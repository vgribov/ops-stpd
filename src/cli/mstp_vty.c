/*
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 * Copyright (C) 2015-2016 Hewlett Packard Enterprise Development LP
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
/****************************************************************************
 *    File               : mstp_vty.c
 *    Description        : MSTP Protocol CLI Commands
 ******************************************************************************/
#include <sys/un.h>
#include <sys/wait.h>
#include <pwd.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "vtysh/lib/version.h"
#include "getopt.h"
#include "vtysh/memory.h"
#include "vtysh/vtysh.h"
#include "vtysh/vector.h"
#include "vtysh/vtysh_user.h"
#include "vtysh/vtysh_utils.h"
#include "vswitch-idl.h"
#include "ovsdb-idl.h"
#include "smap.h"
#include "openvswitch/vlog.h"
#include "openswitch-idl.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"
#include "vtysh/utils/ovsdb_vtysh_utils.h"
#include "mstp_vty.h"
#include "vtysh_ovsdb_mstp_context.h"
#include "ops-utils.h"

extern struct ovsdb_idl *idl;
const struct shash_node **sort_interface(const struct shash *sh);

VLOG_DEFINE_THIS_MODULE(vtysh_mstp_cli);

/*-----------------------------------------------------------------------------
 | Function:        mstp_print_port_statistics
 | Responsibility:  Displays port statistics
 | Parameters:
 |      cist_port:  mstp common instance port row
 | Return:
 ------------------------------------------------------------------------------
 */
static void
mstp_print_port_statistics(const struct ovsrec_mstp_common_instance_port *cist_port) {

    if(!cist_port) {
        VLOG_DBG("Invalid common instance port row %s: %d\n", __FILE__, __LINE__);
        return;
    }

    vty_out(vty, "Bpdus sent %d, received %d%s",
            smap_get_int(&cist_port->mstp_statistics, MSTP_TX_BPDU, 0),
            smap_get_int(&cist_port->mstp_statistics, MSTP_RX_BPDU, 0),
            VTY_NEWLINE);
}

/*-----------------------------------------------------------------------------
 | Function:        compare_nodes_by_vlan_id_in_numerical
 | Responsibility:  Utility API to compare VLAN ID
 ------------------------------------------------------------------------------
 */
int
compare_nodes_by_vlan_id_in_numerical(const void *a_, const void *b_)
{
    const struct shash_node *const *a = a_;
    const struct shash_node *const *b = b_;
    uint i1=0,i2=0;

    if(!a && !b) {
        VLOG_DBG("Invalid argument %s: %d\n", __FILE__, __LINE__);
        return -2;
    }
    sscanf((*a)->name,"%d",&i1);
    sscanf((*b)->name,"%d",&i2);

    if (i1 == i2)
        return 0;
    else if (i1 < i2)
        return -1;
    else
        return 1;
}

/*-----------------------------------------------------------------------------
 | Function:        mstp_util_get_mstid_for_vlanID
 | Responsibility:  Utility API to get the instance ID to which the VLAN belongs
 | Parameters:
 |      vlan_id:    VLAN ID
 |      bridge_row: bridge row pointer
 | Return:
 |      InstId:     Returns MSTP instance ID,
 |                  MSTP_INVALID_ID If no instance mapped
 ------------------------------------------------------------------------------
 */
int64_t
mstp_util_get_mstid_for_vlanID(int64_t vlan_id,
        const struct ovsrec_bridge *bridge_row) {

    int i = 0, j = 0;

    if (!bridge_row) {
        VLOG_DBG("Invalid arguments for mstp_util_get_mstid_for_vlanID %s: %d\n",
                __FILE__, __LINE__);
        return e_vtysh_error;
    }
    /* Loop for all instance in bridge table */
    for (i=0; i < bridge_row->n_mstp_instances; i++) {
        /* Loop for all vlans in one MST instance table */
        for (j=0; j<bridge_row->value_mstp_instances[i]->n_vlans; j++) {
            /* Return the instance ID if the VLAN exist in the instance*/
            if(vlan_id == bridge_row->value_mstp_instances[i]->vlans[j]->id) {
                return bridge_row->key_mstp_instances[i];
            }
        }
    }
    return MSTP_INVALID_ID;
}

/*-----------------------------------------------------------------------------
 | Function:        mstp_util_sort_vlan_id
 | Responsibility:  Utility API sort VLAN ID
 ------------------------------------------------------------------------------
 */
const struct shash_node **
mstp_util_sort_vlan_id(const struct shash *sh)
{
    if (shash_is_empty(sh)) {
        return NULL;
    }
    else {
        const struct shash_node **nodes;
        struct shash_node *node;

        size_t i, n;
        n = shash_count(sh);
        nodes = xmalloc(n * sizeof *nodes);
        if(!nodes) {
            VLOG_DBG("Memory allocation failed %s: %d%s",
                    __FILE__, __LINE__, VTY_NEWLINE);
            return NULL;
        }
        i = 0;
        SHASH_FOR_EACH (node, sh) {
            nodes[i++] = node;
        }
        ovs_assert(i == n);

        qsort(nodes, n, sizeof *nodes, compare_nodes_by_vlan_id_in_numerical);
        return nodes;
    }
}


/*-----------------------------------------------------------------------------
 | Function:        cli_show_spanning_tree_detailed_config
 | Responsibility:  Displays the spanning-tree related global configurations
 | Parameters:
 | Return:
 |      Return : e_vtysh_ok on success else e_vtysh_error
 ------------------------------------------------------------------------------
 */
static int
cli_show_spanning_tree_detailed_config(const struct ovsrec_mstp_common_instance *cist_row) {
    const struct ovsrec_mstp_common_instance_port *cist_port;
    int64_t current_time = (int64_t)time(NULL);
    struct shash sorted_port_id;
    const struct shash_node **cist_port_nodes = NULL;
    int64_t count = 0, i = 0;
    char root_mac[OPS_MAC_STR_SIZE] = {0};
    int priority = 0, sys_id = 0;


    cist_row = ovsrec_mstp_common_instance_first (idl);
    if (!cist_row) {
        vty_out(vty, "No MSTP common instance record found%s", VTY_NEWLINE);
        return e_vtysh_error;
    }

    vty_out(vty, "%s%-30s: %s%s", VTY_NEWLINE, "Topology change flag",
            (!(cist_row->topology_unstable) ||
            (*cist_row->topology_unstable == true)?"False": "True"),
            VTY_NEWLINE);

    vty_out(vty, "%-30s: %ld%s", "Number of topology changes",
            (cist_row->topology_change_count)?*cist_row->topology_change_count:0,
            VTY_NEWLINE);

    vty_out(vty, "%-30s: %ld seconds ago%s",
            "Last topology change occurred",
            (current_time - (int64_t)((cist_row->time_since_top_change)?*cist_row->time_since_top_change:0)),
            VTY_NEWLINE);

    vty_out(vty, "%-10s %-13s %-2ld, %-20s %-2ld %s", "Timers:",
            "Hello expiry",
            (cist_row->hello_expiry_time)?*cist_row->hello_expiry_time:0,
            "Forward delay expiry",
            (cist_row->forward_delay_expiry_time)?*cist_row->forward_delay_expiry_time:0,
            VTY_NEWLINE);

    /* Create the CIST port shash list */
    shash_init(&sorted_port_id);
    OVSREC_MSTP_COMMON_INSTANCE_PORT_FOR_EACH(cist_port, idl) {
        if(!cist_port->port) {
            VLOG_DBG("NO CIST Port found %s: %d%s", __FILE__, __LINE__, VTY_NEWLINE);
            continue;
        }
        if ( NULL == shash_add(&sorted_port_id, cist_port->port->name, (void *)cist_port)) {
            shash_destroy(&sorted_port_id);
            return e_vtysh_ok;
        }
    }

    cist_port_nodes = sort_interface(&sorted_port_id);
    if (!cist_port_nodes) {
        shash_destroy(&sorted_port_id);
        return e_vtysh_ok;
    }
    count = shash_count(&sorted_port_id);

    for(i=0; i<count; i++) {
        cist_port = (const struct ovsrec_mstp_common_instance_port *)cist_port_nodes[i]->data;
        vty_out(vty, "%sPort %s %s", VTY_NEWLINE, cist_port->port->name, VTY_NEWLINE);

        if(cist_port->designated_root) {
            memset(root_mac, 0, sizeof(root_mac));
            priority = 0;
            sscanf(cist_port->designated_root, "%d.%d.%s", &priority, &sys_id, root_mac);
        }
        vty_out(vty, "%-43s:%2d %s %s %s", "Designated root has priority", priority,
                    "Address:", root_mac, VTY_NEWLINE);

        if(cist_port->designated_bridge) {
            memset(root_mac, 0, sizeof(root_mac));
            priority = 0;
            sscanf(cist_port->designated_bridge, "%d.%d.%s", &priority, &sys_id, root_mac);
        }
        vty_out(vty, "%-43s:%2d %s %s %s", "Designated bridge has priority", priority,
                    "Address:", root_mac, VTY_NEWLINE);

        vty_out(vty, "%-43s:%s %s", "Designated port",
                     cist_port->designated_port, VTY_NEWLINE);

        vty_out(vty, "%-43s:%2ld%s", "Number of transitions to forwarding state",
                    (cist_port->fwd_transition_count)?*cist_port->fwd_transition_count:(int64_t)0,
                     VTY_NEWLINE);
        mstp_print_port_statistics(cist_port);
    }
    shash_destroy(&sorted_port_id);
    free(cist_port_nodes);
    return e_vtysh_ok;
}

/*-----------------------------------------------------------------------------
 | Function:        cli_show_spanning_tree_config
 | Responsibility:  Displays the spanning-tree related global configurations
 | Parameters:
 | Return:
 |      Return : e_vtysh_ok on success else e_vtysh_error
 ------------------------------------------------------------------------------
 */
static int
cli_show_spanning_tree_config(bool detail) {
    const struct ovsrec_mstp_common_instance_port *cist_port;
    const struct ovsrec_mstp_common_instance *cist_row;
    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_system *system_row = NULL;
    struct shash sorted_port_id;
    const struct shash_node **cist_port_nodes = NULL;
    int64_t count = 0, i = 0;
    char root_mac[OPS_MAC_STR_SIZE] = {0};
    int priority = 0, sys_id = 0;

    /* Get the current time to calculate the last topology change */
    system_row = ovsrec_system_first(idl);
    if (!system_row) {
        vty_out(vty, "No record found%s", VTY_NEWLINE);
        return e_vtysh_error;
    }

    bridge_row = ovsrec_bridge_first(idl);
    if (!bridge_row) {
        vty_out(vty, "No record found%s", VTY_NEWLINE);
        return e_vtysh_error;
    }

    if (!(bridge_row->mstp_enable) ||
            (*bridge_row->mstp_enable == DEF_ADMIN_STATUS)) {
        vty_out(vty, "Spanning-tree is disabled%s", VTY_NEWLINE);
        return e_vtysh_ok;
    }

    cist_row = ovsrec_mstp_common_instance_first (idl);
    if (!cist_row) {
        vty_out(vty, "No MSTP common instance record found%s", VTY_NEWLINE);
        return e_vtysh_error;
    }

    if(cist_row->designated_root) {
        memset(root_mac, 0, sizeof(root_mac));
        sscanf(cist_row->designated_root, "%d.%d.%s", &priority, &sys_id, root_mac);
    }

    vty_out(vty, "%s%s", "MST0", VTY_NEWLINE);
    vty_out(vty, "  %s%s", "Spanning tree status: Enabled", VTY_NEWLINE);
    vty_out(vty, "  %-10s %-10s: %-20d%s", "Root ID", "Priority",
                    priority, VTY_NEWLINE);

    vty_out(vty, "  %22s: %-20s%s", "MAC-Address", root_mac, VTY_NEWLINE);

    if (VTYSH_STR_EQ(system_row->system_mac, root_mac)) {
        vty_out(vty, "  %34s%s", "This bridge is the root", VTY_NEWLINE);
    }
    vty_out(vty, "  %34s%ld  %s%ld  %s%ld%s",
            "Hello time(in seconds):", *cist_row->hello_time,
            "Max Age(in seconds):", *cist_row->max_age,
            "Forward Delay(in seconds):", *cist_row->forward_delay,
            VTY_NEWLINE);

    vty_out(vty, "%s  %-10s %-10s: %-20ld%s", VTY_NEWLINE, "Bridge ID",
            "Priority", ((*cist_row->priority) * MSTP_BRIDGE_PRIORITY_MULTIPLIER),
            VTY_NEWLINE);
    vty_out(vty, "  %22s: %-20s%s", "MAC-Address",
            system_row->system_mac, VTY_NEWLINE);
    vty_out(vty, "  %34s%ld  %s%ld  %s%ld%s",
            "Hello time(in seconds):", *cist_row->hello_time,
            "Max Age(in seconds):", *cist_row->max_age,
            "Forward Delay(in seconds):", *cist_row->forward_delay,
            VTY_NEWLINE);

    vty_out(vty, "%s%-12s %-14s %-10s %-7s %-10s %s%s", VTY_NEWLINE,
            "Port", "Role", "State", "Cost", "Priority", "Type", VTY_NEWLINE);
    vty_out(vty, "%s %s%s",
            "------------ --------------",
            "---------- ------- ---------- ----------", VTY_NEWLINE);

    /* Create the CIST port shash list */
    shash_init(&sorted_port_id);
    OVSREC_MSTP_COMMON_INSTANCE_PORT_FOR_EACH(cist_port, idl) {
        if(!cist_port->port) {
            VLOG_DBG("NO CIST Port found %s: %d%s", __FILE__, __LINE__, VTY_NEWLINE);
            continue;
        }
        if( NULL == shash_add(&sorted_port_id, cist_port->port->name, (void *)cist_port)) {
            shash_destroy(&sorted_port_id);
            return e_vtysh_ok;
        }
    }
    cist_port_nodes = sort_interface(&sorted_port_id);
    if (!cist_port_nodes) {
        shash_destroy(&sorted_port_id);
        return e_vtysh_ok;
    }

    count = shash_count(&sorted_port_id);

    for(i=0; i<count; i++) {
        cist_port = (const struct ovsrec_mstp_common_instance_port *)cist_port_nodes[i]->data;
        vty_out(vty, "%-12s %-14s %-10s %-7ld %-10ld %s%s",
                cist_port->port->name, cist_port->port_role,
                cist_port->port_state, *cist_port->admin_path_cost,
                ((*cist_port->port_priority) * MSTP_PORT_PRIORITY_MULTIPLIER),
                cist_port->link_type, VTY_NEWLINE);
    }

    if(detail) {
        cli_show_spanning_tree_detailed_config(cist_row);
    }
    shash_destroy(&sorted_port_id);
    free(cist_port_nodes);

    return e_vtysh_ok;
}

/*-----------------------------------------------------------------------------
 | Function:        cli_show_mstp_config
 | Responsibility:  Displays MSTPe related global configurations
 | Parameters:
 | Return:
 |      Return : e_vtysh_ok on success else e_vtysh_error
 ------------------------------------------------------------------------------
 */
static int
cli_show_mstp_config() {
    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_mstp_instance *mstp_row = NULL;
    int i = 0, j = 0;
    struct shash sorted_vlan_id;
    char str[15] = {0};
    const struct shash_node **vlan_nodes = NULL;

    bridge_row = ovsrec_bridge_first(idl);
    if (!bridge_row) {
        vty_out(vty, "No record found.%s", VTY_NEWLINE);
        return e_vtysh_error;
    }

    if (!(bridge_row->mstp_enable) ||
            (*bridge_row->mstp_enable == DEF_ADMIN_STATUS)) {
        vty_out(vty, "Spanning-tree is disabled%s", VTY_NEWLINE);
        return e_vtysh_ok;
    }

    vty_out(vty, "%s%s", "MST configuration information", VTY_NEWLINE);
    vty_out(vty, "   %-20s : %-15s%s", "MST config ID",
            smap_get(&bridge_row->other_config, MSTP_CONFIG_NAME), VTY_NEWLINE);
    vty_out(vty, "   %-20s : %-15d%s", "MST config revision",
            atoi(smap_get(&bridge_row->other_config, MSTP_CONFIG_REV)),
            VTY_NEWLINE);
    vty_out(vty, "   %-20s : %-15s%s", "MST config digest",
            smap_get(&bridge_row->status, MSTP_CONFIG_DIGEST), VTY_NEWLINE);
    vty_out(vty, "   %-20s : %-15ld%s", "Number of instances",
            bridge_row->n_mstp_instances, VTY_NEWLINE);

    vty_out(vty, "%s%-15s %-18s%s", VTY_NEWLINE, "Instance ID",
            "Member VLANs", VTY_NEWLINE);
    vty_out(vty, "--------------- ----------------------------------%s",
            VTY_NEWLINE);

    /* Loop for all instance in bridge table */
    for (i=0; i < bridge_row->n_mstp_instances; i++) {
        shash_init(&sorted_vlan_id);
        memset(str, 0, 15);
        mstp_row = bridge_row->value_mstp_instances[i];

        /* Create the vlan shash list */
        for (j=0; j<mstp_row->n_vlans; j++) {
            sprintf(str, "%ld", mstp_row->vlans[j]->id);
            if ( NULL == shash_add(&sorted_vlan_id, str, (void *)mstp_row->vlans[j])) {
                shash_destroy(&sorted_vlan_id);
                return e_vtysh_ok;
            }
        }

        /* Get the sorted list of vlans from shash */
        vlan_nodes = mstp_util_sort_vlan_id(&sorted_vlan_id);
        if(!vlan_nodes) {
            shash_destroy(&sorted_vlan_id);
            return e_vtysh_ok;
        }

        /* Loop for all vlans in one MST instance table */
        vty_out(vty,"%-15ld %ld", bridge_row->key_mstp_instances[i],
                ((const struct ovsrec_vlan *)vlan_nodes[0]->data)->id);
        for (j=1; j<mstp_row->n_vlans; j++) {
            vty_out(vty, ",%ld", ((const struct ovsrec_vlan *)vlan_nodes[j]->data)->id);
        }
        vty_out(vty, "%s", VTY_NEWLINE);
        shash_destroy(&sorted_vlan_id);
        free(vlan_nodes);
        vlan_nodes = NULL;
    }
    return e_vtysh_ok;
}

/*-----------------------------------------------------------------------------
 | Function:        mstp_show_common_instance_info
 | Responsibility:  Displays MSTP common instance configurations
 | Parameters:
 | Return:
 |      Return : e_vtysh_ok on success else e_vtysh_error
 ------------------------------------------------------------------------------
 */
static int
mstp_show_common_instance_info(
        const struct ovsrec_mstp_common_instance *cist_row) {

    const struct ovsrec_mstp_common_instance_port *cist_port = NULL;
    const struct ovsrec_system *system_row = NULL;
    int j = 0;
    struct shash sorted_vlan_id;
    const struct shash_node **vlan_nodes = NULL;
    const struct shash_node **cist_port_nodes = NULL;
    struct shash sorted_port_id;
    char str[15] = {0};
    int64_t count = 0;
    char root_mac[OPS_MAC_STR_SIZE] = {0};
    int priority = 0, sys_id = 0;

    system_row = ovsrec_system_first(idl);
    if (!system_row) {
        vty_out(vty, "No record found%s", VTY_NEWLINE);
        return e_vtysh_error;
    }

    /* Create the vlan shash list */
    shash_init(&sorted_vlan_id);
    for (j=0; j<cist_row->n_vlans; j++) {
        sprintf(str, "%ld", cist_row->vlans[j]->id);
        if( NULL == shash_add(&sorted_vlan_id, str, (void *)cist_row->vlans[j])) {
            shash_destroy(&sorted_vlan_id);
            return e_vtysh_ok;
        }
    }

    /* Get the sorted list of vlans from shash */
    vlan_nodes = mstp_util_sort_vlan_id(&sorted_vlan_id);
    shash_destroy(&sorted_vlan_id);

    /* common instance table details */
    vty_out(vty, "%-14s %s%s  ", "#### MST0", VTY_NEWLINE, "Vlans mapped:");
    if (cist_row->vlans) {
        vty_out(vty, "%ld", ((const struct ovsrec_vlan *)vlan_nodes[0]->data)->id);
        for (j=1; j<cist_row->n_vlans; j++) {
            vty_out(vty, ",%ld", ((const struct ovsrec_vlan *)vlan_nodes[j]->data)->id);
        }
    }
    vty_out(vty, "%s", VTY_NEWLINE);
    vty_out(vty, "%-14s %s:%-20s %s:%ld%s", "Bridge", "Address",
            system_row->system_mac, "priority",
            ((*cist_row->priority) * MSTP_BRIDGE_PRIORITY_MULTIPLIER),
            VTY_NEWLINE);
    if(cist_row->designated_root) {
        memset(root_mac, 0, sizeof(root_mac));
        sscanf(cist_row->designated_root, "%d.%d.%s", &priority, &sys_id, root_mac);
        if (VTYSH_STR_EQ(system_row->system_mac, root_mac)) {
            vty_out(vty, "%-14s%s", "Root", VTY_NEWLINE);
        }
    }


    if(cist_row->regional_root) {
        memset(root_mac, 0, sizeof(root_mac));
        sscanf(cist_row->regional_root, "%d.%d.%s", &priority, &sys_id, root_mac);
        if (VTYSH_STR_EQ(system_row->system_mac, root_mac)) {
            vty_out(vty, "%-14s%s", "Regional Root", VTY_NEWLINE);
        }
    }


    vty_out(vty, "%-14s %s:%2ld  %s:%2ld  %s:%2ld  %s:%2ld%s", "Operational",
            "Hello time(in seconds)",
            (cist_row->oper_hello_time)?*cist_row->oper_hello_time:DEF_HELLO_TIME,
            "Forward delay(in seconds)",
            (cist_row->oper_forward_delay)?*cist_row->oper_forward_delay:DEF_FORWARD_DELAY,
            "Max-age(in seconds)",
            (cist_row->oper_max_age)?*cist_row->oper_max_age:DEF_MAX_AGE,
            "txHoldCount(in pps)",
            (cist_row->oper_tx_hold_count)?*cist_row->oper_tx_hold_count:DEF_HOLD_COUNT,
            VTY_NEWLINE);
    vty_out(vty, "%-14s %s:%2ld  %s:%2ld  %s:%2ld  %s:%2ld%s", "Configured",
            "Hello time(in seconds)",
            (cist_row->hello_time)?*cist_row->hello_time:DEF_HELLO_TIME,
            "Forward delay(in seconds)",
            (cist_row->forward_delay)?*cist_row->forward_delay:DEF_FORWARD_DELAY,
            "Max-age(in seconds)",
            (cist_row->max_age)?*cist_row->max_age:DEF_MAX_AGE,
            "txHoldCount(in pps)",
            (cist_row->tx_hold_count)?*cist_row->tx_hold_count:DEF_HOLD_COUNT,
            VTY_NEWLINE);

    vty_out(vty, "%s%-14s %-14s %-10s %-10s %-10s %s%s", VTY_NEWLINE,
            "Port", "Role", "State", "Cost", "Priority", "Type", VTY_NEWLINE);
    vty_out(vty, "%s %s%s",
            "-------------- --------------",
            "---------- ---------- ---------- ----------",
            VTY_NEWLINE);

    /* Create the CIST port shash list */
    shash_init(&sorted_port_id);
    OVSREC_MSTP_COMMON_INSTANCE_PORT_FOR_EACH(cist_port, idl) {
        if(!cist_port->port) {
            VLOG_DBG("NO CIST Port found %s: %d%s", __FILE__, __LINE__, VTY_NEWLINE);
            continue;
        }
        if ( NULL == shash_add(&sorted_port_id, cist_port->port->name, (void *)cist_port)) {
            shash_destroy(&sorted_port_id);
            return e_vtysh_ok;
        }
    }

    cist_port_nodes = sort_interface(&sorted_port_id);
    if (!cist_port_nodes) {
        shash_destroy(&sorted_port_id);
        return e_vtysh_ok;
    }
    count = shash_count(&sorted_port_id);

    for(j=0; j<count; j++) {
        cist_port = (const struct ovsrec_mstp_common_instance_port *)cist_port_nodes[j]->data;
        vty_out(vty, "%-14s %-14s %-10s %-10ld %-10ld %s%s",
                cist_port->port->name, cist_port->port_role,
                cist_port->port_state, *cist_port->admin_path_cost,
                ((*cist_port->port_priority) * MSTP_PORT_PRIORITY_MULTIPLIER),
                cist_port->link_type, VTY_NEWLINE);
    }
    shash_destroy(&sorted_port_id);
    free(cist_port_nodes);
    free(vlan_nodes);
    return e_vtysh_ok;
}

/*-----------------------------------------------------------------------------
 | Function:        mstp_show_common_instance_port_info
 | Responsibility:  Displays MSTP common instance port configurations
 | Parameters:
 | Return:
 |      Return : e_vtysh_ok on success else e_vtysh_error
 ------------------------------------------------------------------------------
 */
static int
mstp_show_common_instance_port_info(
        const struct ovsrec_mstp_common_instance *cist_row,
        const struct ovsrec_mstp_common_instance_port *cist_port) {

    const struct ovsrec_system *system_row = NULL;
    char root_mac[OPS_MAC_STR_SIZE] = {0};
    int priority = 0, sys_id = 0;

    system_row = ovsrec_system_first(idl);
    if (!system_row) {
        vty_out(vty, "No record found%s", VTY_NEWLINE);
        return e_vtysh_error;
    }

    vty_out(vty, "%sPort %s%s", VTY_NEWLINE, cist_port->port->name, VTY_NEWLINE);

    if(cist_port->designated_root) {
        memset(root_mac, 0, sizeof(root_mac));
        sscanf(cist_port->designated_root, "%d.%d.%s", &priority, &sys_id, root_mac);
    }

    vty_out(vty, "%-35s: %s%s", "Designated root address",
                 root_mac, VTY_NEWLINE);

    if(cist_port->cist_regional_root_id) {
        memset(root_mac, 0, sizeof(root_mac));
        sscanf(cist_port->cist_regional_root_id, "%d.%d.%s", &priority, &sys_id, root_mac);
    }

    vty_out(vty, "%-35s: %s%s", "Designated regional root address",
                 root_mac, VTY_NEWLINE);
    vty_out(vty, "%-35s: %s%s", "Designated bridge address",
                 cist_port->designated_bridge, VTY_NEWLINE);

    vty_out(vty, "%-10s %s %ld sec, %s:%ld, %s:%ld%s", "Timers:",
                 "Message expires in",
                 (cist_row->hello_expiry_time)?*cist_row->hello_expiry_time:0,
                 "Forward delay expiry",
                 (cist_row->forward_delay_expiry_time)?*cist_row->forward_delay_expiry_time:0,
                 "Forward transitions",
                 (cist_row->forward_delay_expiry_time)?*cist_row->forward_delay_expiry_time:0,
                 VTY_NEWLINE);

    mstp_print_port_statistics(cist_port);
    return e_vtysh_ok;
}



/*-----------------------------------------------------------------------------
 | Function:        mstp_show_instance_info
 | Responsibility:  Displays MSTP instance configurations
 | Parameters:
 | Return:
 |      Return : e_vtysh_ok on success else e_vtysh_error
 ------------------------------------------------------------------------------
 */
static int
mstp_show_instance_info(const struct ovsrec_mstp_common_instance *cist_row,
                   int64_t inst_id, const struct ovsrec_mstp_instance *mstp_row) {
    const struct ovsrec_system *system_row = NULL;
    const struct ovsrec_mstp_instance_port *mstp_port = NULL;
    int j = 0;
    struct shash sorted_vlan_id;
    char str[15] = {0};
    const struct shash_node **vlan_nodes = NULL;
    const struct shash_node **mstp_port_nodes = NULL;
    struct shash sorted_port_id;
    char root_mac[OPS_MAC_STR_SIZE] = {0};
    int priority = 0, sys_id = 0;

    if (!cist_row) {
        VLOG_DBG("Invalid arguments for mstp_show_instance_info %s: %d\n",
                __FILE__, __LINE__);
        return e_vtysh_error;
    }

    system_row = ovsrec_system_first(idl);
    if (!system_row) {
        vty_out(vty, "No record found.%s", VTY_NEWLINE);
        return e_vtysh_error;
    }

    /* Create the vlan shash list */
    shash_init(&sorted_vlan_id);
    for (j=0; j<mstp_row->n_vlans; j++) {
        sprintf(str, "%ld", mstp_row->vlans[j]->id);
        if (NULL == shash_add(&sorted_vlan_id, str, (void *)mstp_row->vlans[j])) {
            shash_destroy(&sorted_vlan_id);
            return e_vtysh_ok;
        }
    }

    /* Get the sorted list of vlans from shash */
    vlan_nodes = mstp_util_sort_vlan_id(&sorted_vlan_id);
    if(!vlan_nodes) {
        shash_destroy(&sorted_vlan_id);
        return e_vtysh_ok;
    }

    vty_out(vty, "%s%s%ld%s%s  ", VTY_NEWLINE, "#### MST",
           inst_id, VTY_NEWLINE, "Vlans mapped:");
    if (mstp_row->vlans) {
        vty_out(vty, "%ld", ((const struct ovsrec_vlan *)vlan_nodes[0]->data)->id);
        for (j=1; j<mstp_row->n_vlans; j++) {
            vty_out(vty, ",%ld", ((const struct ovsrec_vlan *)vlan_nodes[j]->data)->id);
        }
    }
    vty_out(vty, "%s", VTY_NEWLINE);
    vty_out(vty, "%-14s %s:%-20s %s:%ld%s", "Bridge", "Address",
            system_row->system_mac, "Priority",
            ((*mstp_row->priority) * MSTP_BRIDGE_PRIORITY_MULTIPLIER),
            VTY_NEWLINE);
    if(mstp_row->designated_root) {
        memset(root_mac, 0, sizeof(root_mac));
        priority = 0;
        sscanf(mstp_row->designated_root, "%d.%d.%s", &priority, &sys_id, root_mac);
    }

    vty_out(vty, "%-14s Address:%-20s Priority:%ld%s", "Root",
            root_mac,
            (mstp_row->root_priority)?*mstp_row->root_priority:(DEF_BRIDGE_PRIORITY * MSTP_BRIDGE_PRIORITY_MULTIPLIER),
            VTY_NEWLINE);

    vty_out(vty, "%19s:%ld, Cost:%ld, Rem Hops:%ld%s", "Port",
            (mstp_row->root_port)?*mstp_row->root_port:(int64_t)0,
            (mstp_row->root_path_cost)?*mstp_row->root_path_cost:DEF_MSTP_COST,
            (cist_row->remaining_hops)?*cist_row->remaining_hops:(int64_t)0,
            VTY_NEWLINE);

    vty_out(vty, "%s%-14s %-14s %-10s %-7s %-10s %s%s", VTY_NEWLINE,
            "Port", "Role", "State", "Cost", "Priority", "Type",
            VTY_NEWLINE);
    vty_out(vty, "%s %s%s",
            "-------------- --------------",
            "---------- ------- ---------- ----------",
            VTY_NEWLINE);

    shash_init(&sorted_port_id);
    for (j=0; j < mstp_row->n_mstp_instance_ports; j++) {
        mstp_port = mstp_row->mstp_instance_ports[j];
        if(NULL == shash_add(&sorted_port_id, mstp_port->port->name, (void *)mstp_port)) {
            shash_destroy(&sorted_port_id);
            return e_vtysh_ok;
        }
    }

    mstp_port_nodes = sort_interface(&sorted_port_id);
    if (!mstp_port_nodes) {
        shash_destroy(&sorted_port_id);
        return e_vtysh_ok;
    }

    for (j=0; j < mstp_row->n_mstp_instance_ports; j++) {
        mstp_port = (const struct ovsrec_mstp_instance_port *)mstp_port_nodes[j]->data;
        if(!mstp_port) {
            assert(0);
            return e_vtysh_error;
        }
        if (mstp_port->port) {
            vty_out(vty, "%-14s %-14s %-10s %-7ld %-10ld %s%s",
                    mstp_port->port->name, mstp_port->port_role,
                    mstp_port->port_state,
                    (mstp_port->admin_path_cost)?*mstp_port->admin_path_cost:DEF_MSTP_COST,
                    ((*mstp_port->port_priority) * MSTP_PORT_PRIORITY_MULTIPLIER),
                    DEF_LINK_TYPE, VTY_NEWLINE);
        }
    }
    shash_destroy(&sorted_vlan_id);
    shash_destroy(&sorted_port_id);
    free(mstp_port_nodes);
    free(vlan_nodes);
    return e_vtysh_ok;
}

/*-----------------------------------------------------------------------------
 | Function:        cli_show_mst_interface
 | Responsibility:  Displays mst configuration for a particular interface
 | Parameters:
 | Return:
 |      Return : e_vtysh_ok on success else e_vtysh_error
 ------------------------------------------------------------------------------
 */
static int
cli_show_mst_interface(int inst_id, const char *if_name, bool detail) {

    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_mstp_instance *mstp_row = NULL;
    const struct ovsrec_mstp_instance_port *mstp_port_row = NULL;
    const struct ovsrec_mstp_common_instance_port *cist_port = NULL;
    const struct ovsrec_mstp_common_instance *cist_row = NULL;
    int i = 0;
    struct shash sorted_vlan_id;
    char str[15] = {0};
    const struct shash_node **vlan_nodes = NULL;

    cist_row = ovsrec_mstp_common_instance_first (idl);
    if (!cist_row) {
        vty_out(vty, "No MSTP common instance record found%s", VTY_NEWLINE);
        return e_vtysh_error;
    }

    /* Get the MSTP row from bridge table*/
    bridge_row = ovsrec_bridge_first(idl);
    if (bridge_row) {
        /* Loop for all instance in bridge table */
        for (i=0; i < bridge_row->n_mstp_instances; i++) {
            if(inst_id == bridge_row->key_mstp_instances[i]) {
                mstp_row = bridge_row->value_mstp_instances[i];
                break;
            }
        }
    }
    if(!mstp_row) {
        vty_out(vty, "Invalid InstanceId%s", VTY_NEWLINE);
        return e_vtysh_error;
    }

    /* Find the MSTP instance port entry matching with the port index */
    if( if_name != NULL) {
        for (i=0; i < mstp_row->n_mstp_instance_ports; i++) {
            if(!mstp_row->mstp_instance_ports[i]) {
                vty_out(vty, "No MSTP port record found%s", VTY_NEWLINE);
                assert(0);
                return e_vtysh_error;
            }
            if (mstp_row->mstp_instance_ports[i]->port) {
                if (VTYSH_STR_EQ(mstp_row->mstp_instance_ports[i]->port->name,
                                                         if_name)) {
                    mstp_port_row = mstp_row->mstp_instance_ports[i];
                    break;
                }
            }
        }
        OVSREC_MSTP_COMMON_INSTANCE_PORT_FOR_EACH(cist_port, idl) {
            if (cist_port->port) {
                if (VTYSH_STR_EQ(cist_port->port->name, if_name)) {
                     break;
                }
            }
        }
    }
    if ((!mstp_port_row) || (!cist_port)) {
        vty_out(vty, "No MSTP instance port found with this port index%s",
                VTY_NEWLINE);
    }

    vty_out(vty, "Port %s%s", if_name, VTY_NEWLINE);

    vty_out(vty, "Port Type : %-17sPort Guard  : %-15s%s",
            (cist_port->admin_edge_port_disable)?"admin-edge":"admin-network",
            (cist_port->loop_guard_disable)?"enable":"disable", VTY_NEWLINE);

    vty_out(vty, "Link Type : %-17sBPDU Filter : %-15s%s", cist_port->link_type,
            (cist_port->bpdu_filter_disable) ? STATUS_ENABLE: STATUS_DISABLE,
            VTY_NEWLINE);

    vty_out(vty, "Boundary  : %-17sBPDU Guard  : %-15s%s", "internal",
            (cist_port->bpdu_guard_disable) ? STATUS_ENABLE: STATUS_DISABLE,
            VTY_NEWLINE);

    mstp_print_port_statistics(cist_port);

    if(detail) {
        vty_out(vty, "%s%-14s %-14s %-10s %-10s %-10s %s%s", VTY_NEWLINE,
                "Instance", "Role", "State", "Cost", "Priority", "Vlans mapped", VTY_NEWLINE);
        vty_out(vty, "%s %s%s", "-------------- --------------",
                "---------- ---------- ---------- ----------", VTY_NEWLINE);
        vty_out(vty, "%-14d %-14s %-10s %-10ld %-10ld", inst_id,
                mstp_port_row->port_role, mstp_port_row->port_state,
                *mstp_port_row->admin_path_cost,
                ((*mstp_port_row->port_priority) * MSTP_PORT_PRIORITY_MULTIPLIER));

        /* Vlans Mapped */
        if (mstp_row->vlans) {

            /* Create the vlan shash list */
            shash_init(&sorted_vlan_id);
            for (i=0; i<mstp_row->n_vlans; i++) {
                sprintf(str, "%ld", mstp_row->vlans[i]->id);
                if (NULL == shash_add(&sorted_vlan_id, str, (void *)mstp_row->vlans[i])) {
                    shash_destroy(&sorted_vlan_id);
                    return e_vtysh_ok;
                }
            }

            /* Get the sorted list of vlans from shash */
            vlan_nodes = mstp_util_sort_vlan_id(&sorted_vlan_id);
            if(!vlan_nodes) {
                shash_destroy(&sorted_vlan_id);
                return e_vtysh_ok;
            }

            vty_out(vty, " %ld", ((const struct ovsrec_vlan *)vlan_nodes[0]->data)->id);
            for (i=1; i<mstp_row->n_vlans; i++) {
                vty_out(vty, ",%ld", ((const struct ovsrec_vlan *)vlan_nodes[i]->data)->id);
            }
            vty_out(vty, "%s", VTY_NEWLINE);
            shash_destroy(&sorted_vlan_id);
            free(vlan_nodes);
        }
    }
    else {
        mstp_show_common_instance_port_info(cist_row, cist_port);
    }

    return e_vtysh_ok;
}

/*-----------------------------------------------------------------------------
 | Function:        cli_show_mst
 | Responsibility:  Displays MSTI and CIST configurations
 | Parameters:
 | Return:
 |      Return : e_vtysh_ok on success else e_vtysh_error
 ------------------------------------------------------------------------------
 */
static int
cli_show_mst(int inst_id, bool detail_flag) {
    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_mstp_common_instance *cist_row = NULL;
    const struct ovsrec_mstp_common_instance_port *cist_port_row = NULL;
    const struct ovsrec_mstp_instance *mstp_row = NULL;

    bridge_row = ovsrec_bridge_first(idl);
    if (!bridge_row) {
        vty_out(vty, "No record found.%s", VTY_NEWLINE);
        return e_vtysh_error;
    }

    if (!(bridge_row->mstp_enable) ||
            (*bridge_row->mstp_enable == DEF_ADMIN_STATUS)) {
        vty_out(vty, "Spanning-tree is disabled%s", VTY_NEWLINE);
        return e_vtysh_ok;
    }

    cist_row = ovsrec_mstp_common_instance_first (idl);
    if (!cist_row) {
        vty_out(vty, "No MSTP common instance record found.%s", VTY_NEWLINE);
        return e_vtysh_error;
    }

    if (inst_id != MSTP_INVALID_ID) {
        /* check the MST instance exist */
        for (int i=0; i < bridge_row->n_mstp_instances; i++) {
            if(inst_id == bridge_row->key_mstp_instances[i]) {
                mstp_row = bridge_row->value_mstp_instances[i];
            }
        }

        /* MSTP instance not exist */
        if(!mstp_row) {
            vty_out(vty, "No MSTP instance record found%s", VTY_NEWLINE);
            return e_vtysh_ok;
        }

        /* Display MST instance data specific for specific instanceID */
        mstp_show_instance_info(cist_row, inst_id, mstp_row);
    }

    /* Display MST instance data for all instance including CIST*/
    else {
        /* Display common instance data */
        mstp_show_common_instance_info(cist_row);

        /* Loop for all instance in bridge table */
        for (int i=0; i < bridge_row->n_mstp_instances; i++) {
            mstp_row = bridge_row->value_mstp_instances[i];
            if (!mstp_row) {
                assert(0);
                return e_vtysh_error;
            }
            vty_out(vty, "%s", VTY_NEWLINE);
            mstp_show_instance_info(cist_row, bridge_row->key_mstp_instances[i], mstp_row);
        }
    }

    /* Display common instance ports data */
    if(detail_flag) {
        OVSREC_MSTP_COMMON_INSTANCE_PORT_FOR_EACH(cist_port_row, idl) {
            if(!cist_port_row->port) {
                VLOG_DBG("NO CIST Port found %s: %d%s", __FILE__, __LINE__, VTY_NEWLINE);
                continue;
            }
            mstp_show_common_instance_port_info(cist_row, cist_port_row);
        }
    }

    return e_vtysh_ok;
}

/*-----------------------------------------------------------------------------
 | Function:        cli_show_mst
 | Responsibility:  Displays running-config for MSTP module(config-level)
 | Parameters:
 | Return:
 |      Return : e_vtysh_ok on success else e_vtysh_error
 ------------------------------------------------------------------------------
 */
static int
cli_show_mstp_global_config() {
    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_system *system_row = NULL;
    const struct ovsrec_mstp_common_instance *cist_row = NULL;
    const struct ovsrec_mstp_instance *mstp_row = NULL;
    const char *data = NULL;
    int i = 0, j = 0;
    struct shash sorted_vlan_id;
    char str[15] = {0};
    const struct shash_node **vlan_nodes = NULL;

    system_row = ovsrec_system_first(idl);
    if (!system_row) {
        return e_vtysh_error;
    }

    /* Bridge configs */
    bridge_row = ovsrec_bridge_first(idl);
    if (bridge_row) {
        if (bridge_row->mstp_enable &&
                (*bridge_row->mstp_enable != DEF_ADMIN_STATUS)) {
            vty_out(vty, "spanning-tree%s", VTY_NEWLINE);
        }

        data = smap_get(&bridge_row->other_config, MSTP_CONFIG_NAME);
        if (data && (!VTYSH_STR_EQ(data, system_row->system_mac))) {
            vty_out(vty, "spanning-tree config-name %s%s", data, VTY_NEWLINE);
        }

        data = smap_get(&bridge_row->other_config, MSTP_CONFIG_REV);
        if (data && (atoi(DEF_CONFIG_REV) != atoi(data))) {
            vty_out(vty, "spanning-tree config-revision %d%s",
                    atoi(data), VTY_NEWLINE);
        }

        /* Loop for all instance in bridge table */
        for (i=0; i < bridge_row->n_mstp_instances; i++) {
            mstp_row = bridge_row->value_mstp_instances[i];
            if(!mstp_row) {
                assert(0);
                return e_vtysh_error;
            }

            /* Create the vlan shash list */
            shash_init(&sorted_vlan_id);
            memset(str, 0, 15);
            for (j=0; j<mstp_row->n_vlans; j++) {
                sprintf(str, "%ld", mstp_row->vlans[j]->id);
                if (NULL == shash_add(&sorted_vlan_id, str, (void *)mstp_row->vlans[j])) {
                    shash_destroy(&sorted_vlan_id);
                    return e_vtysh_ok;
                }
            }

            /* Get the sorted list of vlans from shash */
            vlan_nodes = mstp_util_sort_vlan_id(&sorted_vlan_id);
            if(!vlan_nodes) {
                shash_destroy(&sorted_vlan_id);
                return e_vtysh_ok;
            }

            /* Loop for all vlans in one MST instance table */
            for (j=0; j<mstp_row->n_vlans; j++) {
                vty_out(vty, "spanning-tree instance %ld vlan %ld%s",
                    bridge_row->key_mstp_instances[i],
                    ((const struct ovsrec_vlan *)vlan_nodes[j]->data)->id,
                    VTY_NEWLINE);
            }

            if (mstp_row->priority &&
                    (*mstp_row->priority != DEF_BRIDGE_PRIORITY)) {
                vty_out(vty, "spanning-tree instance %ld priority %ld%s",
                bridge_row->key_mstp_instances[i],
                *mstp_row->priority, VTY_NEWLINE);
            }
            shash_destroy(&sorted_vlan_id);
            free(vlan_nodes);
            vlan_nodes = NULL;
        }
    }

    /* CIST configs */
    cist_row = ovsrec_mstp_common_instance_first (idl);
    if (cist_row) {
        if (cist_row->priority &&
                *cist_row->priority != DEF_BRIDGE_PRIORITY) {
            vty_out(vty, "spanning-tree priority %ld%s",
                    *cist_row->priority, VTY_NEWLINE);
        }
        if (cist_row->hello_time &&
                *cist_row->hello_time != DEF_HELLO_TIME) {
            vty_out(vty, "spanning-tree hello-time %ld%s",
                       *cist_row->hello_time, VTY_NEWLINE);
        }
        if (cist_row->forward_delay &&
                *cist_row->forward_delay != DEF_FORWARD_DELAY) {
            vty_out(vty, "spanning-tree forward-delay %ld%s",
                               *cist_row->forward_delay, VTY_NEWLINE);
        }
        if (cist_row->max_age && *cist_row->max_age != DEF_MAX_AGE) {
            vty_out(vty, "spanning-tree max-age %ld%s",
                                *cist_row->max_age, VTY_NEWLINE);
        }
        if (cist_row->max_hop_count &&
                *cist_row->max_hop_count != DEF_MAX_HOPS) {
            vty_out(vty, "spanning-tree max-hops %ld%s",
                                *cist_row->max_hop_count, VTY_NEWLINE);
        }
        if (cist_row->tx_hold_count &&
                *cist_row->tx_hold_count != DEF_HOLD_COUNT) {
            vty_out(vty, "spanning-tree transmit-hold-count %ld%s",
                                *cist_row->tx_hold_count, VTY_NEWLINE);
        }
    }
    return e_vtysh_ok;
}

/*-----------------------------------------------------------------------------
 | Function:        cli_show_mst
 | Responsibility:  Displays running-config for MSTP module(Port-level)
 | Parameters:
 | Return:
 |      Return : e_vtysh_ok on success else e_vtysh_error
 ------------------------------------------------------------------------------
 */
static int
cli_show_mstp_intf_config() {
    const struct ovsrec_mstp_common_instance *cist_row = NULL;
    const struct ovsrec_mstp_common_instance_port *cist_port_row = NULL;
    const struct ovsrec_mstp_instance_port *mstp_port_row = NULL;
    const struct ovsrec_mstp_instance *mstp_row = NULL;
    const struct ovsrec_bridge *bridge_row = NULL;
    int i = 0, j = 0, k = 0;
    bool if_print = true;
    struct shash sorted_port_id;
    const struct shash_node **cist_port_nodes = NULL;

    bridge_row = ovsrec_bridge_first(idl);
    if (!bridge_row) {
        return e_vtysh_ok;
    }
    cist_row = ovsrec_mstp_common_instance_first (idl);
    if (!cist_row) {
        return e_vtysh_ok;
    }

    /* Create the CIST port shash list */
    shash_init(&sorted_port_id);
    OVSREC_MSTP_COMMON_INSTANCE_PORT_FOR_EACH(cist_port_row, idl) {
        if(!cist_port_row->port) {
            VLOG_DBG("NO CIST Port found %s: %d%s", __FILE__, __LINE__, VTY_NEWLINE);
            continue;
        }
        if (NULL == shash_add(&sorted_port_id, cist_port_row->port->name, (void *)cist_port_row)) {
            shash_destroy(&sorted_port_id);
            return e_vtysh_ok;
        }
    }

    cist_port_nodes = sort_interface(&sorted_port_id);
    if (!cist_port_nodes) {
        shash_destroy(&sorted_port_id);
        return e_vtysh_ok;
    }

    /* CIST port configs */
    for (i=0; i < cist_row->n_mstp_common_instance_ports; i++) {
        cist_port_row = (const struct ovsrec_mstp_common_instance_port *)cist_port_nodes[i]->data;
        if(!cist_port_row) {
            shash_destroy(&sorted_port_id);
            free(cist_port_nodes);
            assert(0);
            return e_vtysh_error;
        }
        if_print = true;

        if (cist_port_row->loop_guard_disable &&
                *cist_port_row->loop_guard_disable != DEF_BPDU_STATUS) {
            if (if_print) {
                vty_out(vty, "%s %s%s", "interface", cist_port_row->port->name,
                                                                VTY_NEWLINE);
                if_print = false;
            }
            vty_out(vty,  "%4s%s%s", "", "spanning-tree loop-guard enable",
                                                            VTY_NEWLINE);
        }
        if (cist_port_row->root_guard_disable &&
                *cist_port_row->root_guard_disable != DEF_BPDU_STATUS) {
            if (if_print) {
                vty_out(vty, "%s %s%s", "interface", cist_port_row->port->name,
                                                                VTY_NEWLINE);
                if_print = false;
            }
            vty_out(vty, "%4s%s%s", "", "spanning-tree root-guard enable",
                                                            VTY_NEWLINE);
        }
        if (cist_port_row->bpdu_guard_disable &&
                *cist_port_row->bpdu_guard_disable != DEF_BPDU_STATUS) {
            if (if_print) {
                vty_out(vty, "%s %s%s", "interface", cist_port_row->port->name,
                                                                VTY_NEWLINE);
                if_print = false;
            }
            vty_out(vty, "%4s%s%s", "", "spanning-tree bpdu-guard enable",
                                                        VTY_NEWLINE);
        }
        if (cist_port_row->bpdu_filter_disable &&
                *cist_port_row->bpdu_filter_disable != DEF_BPDU_STATUS) {
            if (if_print) {
                vty_out(vty, "%s %s%s", "interface", cist_port_row->port->name,
                                                                VTY_NEWLINE);
                if_print = false;
            }
            vty_out(vty, "%4s%s%s", "", "spanning-tree bpdu-filter enable",
                                                        VTY_NEWLINE);
        }
        if (cist_port_row->admin_edge_port_disable &&
                *cist_port_row->admin_edge_port_disable != DEF_ADMIN_EDGE) {
            if (if_print) {
                vty_out(vty, "%s %s%s", "interface", cist_port_row->port->name,
                                                                VTY_NEWLINE);
                if_print = false;
            }
            vty_out(vty, "%4s%s%s", "", "spanning-tree port-type admin-edge",
                                                        VTY_NEWLINE);
        }
        if (cist_port_row->admin_path_cost &&
                *cist_port_row->admin_path_cost != DEF_MSTP_COST) {
            if (if_print) {
                vty_out(vty, "%s %s%s", "interface", cist_port_row->port->name,
                                                                VTY_NEWLINE);
                if_print = false;
            }
            vty_out(vty, "%4s%s %ld%s", "", "spanning-tree cost",
                    *cist_port_row->admin_path_cost, VTY_NEWLINE);
        }
        if (cist_port_row->port_priority &&
                *cist_port_row->port_priority != DEF_MSTP_PORT_PRIORITY) {
            if (if_print) {
                vty_out(vty, "%s %s%s", "interface", cist_port_row->port->name,
                                                                VTY_NEWLINE);
                if_print = false;
            }
            vty_out(vty, "%4s%s %ld%s", "", "spanning-tree port-priority",
                                 *cist_port_row->port_priority, VTY_NEWLINE);
        }

        for (j=0; j < bridge_row->n_mstp_instances; j++) {
            mstp_row = bridge_row->value_mstp_instances[j];

            /* MST instance commands if port name matches */
            if(!mstp_row) {
                assert(0);
                return e_vtysh_error;
            }
            /* Loop for all ports in the instance table */
            for (k=0; k<mstp_row->n_mstp_instance_ports; k++) {
                mstp_port_row = mstp_row->mstp_instance_ports[k];
                if((!mstp_port_row) ||
                   (!VTYSH_STR_EQ(cist_port_row->port->name, mstp_port_row->port->name))) {
                    continue;
                }
                if (mstp_port_row->port_priority &&
                        (*mstp_port_row->port_priority != DEF_MSTP_PORT_PRIORITY)) {
                    if (if_print) {
                        vty_out(vty, "%s %s%s", "interface", cist_port_row->port->name,
                                VTY_NEWLINE);
                        if_print = false;
                    }
                    vty_out(vty, "%4s%s %ld %s %ld%s", "",
                            "spanning-tree instance",
                            bridge_row->key_mstp_instances[j], "port-priority",
                            *mstp_port_row->port_priority, VTY_NEWLINE);
                }
                if (mstp_port_row->admin_path_cost &&
                        (*mstp_port_row->admin_path_cost != DEF_MSTP_COST)) {
                    if (if_print) {
                        vty_out(vty, "%s %s%s", "interface", cist_port_row->port->name,
                                VTY_NEWLINE);
                        if_print = false;
                    }
                    vty_out(vty, "%4s%s %ld %s %ld%s", "",
                            "spanning-tree instance",
                            bridge_row->key_mstp_instances[j], "cost",
                            *mstp_port_row->admin_path_cost, VTY_NEWLINE);
                }
            }
        }
    }
    shash_destroy(&sorted_port_id);
    free(cist_port_nodes);
    return e_vtysh_ok;
}

/*-----------------------------------------------------------------------------
 | Function:        cli_show_mst
 | Responsibility:  Displays running-config for MSTP module
 | Parameters:
 | Return:
 ------------------------------------------------------------------------------
 */
void
cli_show_mstp_running_config() {

    vty_out (vty, "!%s", VTY_NEWLINE);
    /* Global configuration of MSTP, in config context */
    cli_show_mstp_global_config();

    /* Inerface level configuration of MSTP */
    cli_show_mstp_intf_config();
}

/*-----------------------------------------------------------------------------
 | Function:        mstp_cli_set_string_cist_port_table
 | Responsibility:  Sets the common instance port table config paramters
 | Parameters:
 |      if_name:    Interface nameh
 |      key:        Common instance port column name
 |      value:      Value to be set for the corresponding CIST port column
 | Return:
 |      CMD_SUCCESS:Config executed successfully.
 |      CMD_OVSDB_FAILURE - DB failure.
 ------------------------------------------------------------------------------
 */
static int
mstp_cli_set_string_cist_port_table (const char *if_name, const char *key,
                                     const int64_t value) {

    struct ovsdb_idl_txn *txn = NULL;
    const struct ovsrec_mstp_common_instance_port *cist_port_row = NULL;

    if((!if_name) || (!key)) {
        VLOG_DBG("Invalid Input %s: %d%s", __FILE__, __LINE__, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    START_DB_TXN(txn);
    OVSREC_MSTP_COMMON_INSTANCE_PORT_FOR_EACH(cist_port_row, idl) {
        if(!cist_port_row->port) {
            VLOG_DBG("NO CIST Port found %s: %d%s", __FILE__, __LINE__, VTY_NEWLINE);
            continue;
        }
        if (VTYSH_STR_EQ(cist_port_row->port->name, if_name)) {
            break;
        }
    }

    if (!cist_port_row) {
        ERRONEOUS_DB_TXN(txn, "No record found");
    }

    if (VTYSH_STR_EQ(key, MSTP_PORT_PRIORITY)) {
        ovsrec_mstp_common_instance_port_set_port_priority(cist_port_row,
                                                           &value, 1);
    }
    else if (VTYSH_STR_EQ(key, MSTP_PORT_COST)) {
        ovsrec_mstp_common_instance_port_set_admin_path_cost(cist_port_row,
                                                             &value, 1);
    }

    /* End of transaction. */
    END_DB_TXN(txn);
}

/*-----------------------------------------------------------------------------
 | Function:        mstp_cli_set_cist_port_table
 | Responsibility:  Sets the common instance port table config paramters
 | Parameters:
 |      if_name:    Interface nameh
 |      key:        Common instance port column name
 |      value:      Value to be set for the corresponding CIST port column
 | Return:
 |      CMD_SUCCESS:Config executed successfully.
 |      CMD_OVSDB_FAILURE - DB failure.
 ------------------------------------------------------------------------------
 */
static int
mstp_cli_set_cist_port_table (const char *if_name, const char *key,
                              const bool value) {

    struct ovsdb_idl_txn *txn = NULL;
    const struct ovsrec_mstp_common_instance_port *cist_port_row = NULL;

    START_DB_TXN(txn);

    OVSREC_MSTP_COMMON_INSTANCE_PORT_FOR_EACH(cist_port_row, idl) {
        if(!cist_port_row->port) {
            VLOG_DBG("NO CIST Port found %s: %d%s", __FILE__, __LINE__, VTY_NEWLINE);
            continue;
        }
        if (VTYSH_STR_EQ(cist_port_row->port->name, if_name)) {
            break;
        }
    }

    if (!cist_port_row) {
        ERRONEOUS_DB_TXN(txn, "No record found");
    }

    if (VTYSH_STR_EQ(key, MSTP_ADMIN_EDGE)) {
        ovsrec_mstp_common_instance_port_set_admin_edge_port_disable(
                cist_port_row, &value, 1);
    }
    else if (VTYSH_STR_EQ(key, MSTP_BPDU_GUARD)) {
        ovsrec_mstp_common_instance_port_set_bpdu_guard_disable(cist_port_row,
                                                                    &value, 1);
    }
    else if (VTYSH_STR_EQ(key, MSTP_BPDU_FILTER)) {
        ovsrec_mstp_common_instance_port_set_bpdu_filter_disable(cist_port_row,
                                                                    &value, 1);
    }
    else if (VTYSH_STR_EQ(key, MSTP_ROOT_GUARD)) {
        ovsrec_mstp_common_instance_port_set_root_guard_disable(cist_port_row,
                                                                    &value, 1);
    }
    else if (VTYSH_STR_EQ(key, MSTP_LOOP_GUARD)) {
        ovsrec_mstp_common_instance_port_set_loop_guard_disable(cist_port_row,
                                                                    &value, 1);
    }

    /* End of transaction. */
    END_DB_TXN(txn);
}

/*-----------------------------------------------------------------------------
 | Function:        mstp_cli_set_cist_table
 | Responsibility:  Sets the common instance table config paramters
 | Parameters:
 |      key:        Common instance column name
 |      value:      Value to be set for the corresponding CIST column
 | Return:
 |      CMD_SUCCESS:Config executed successfully.
 |      CMD_OVSDB_FAILURE - DB failure.
 ------------------------------------------------------------------------------
 */
static int
mstp_cli_set_cist_table (const char *key, int64_t value) {
    struct ovsdb_idl_txn *txn = NULL;
    const struct ovsrec_mstp_common_instance *cist_row = NULL;

    START_DB_TXN(txn);

    cist_row = ovsrec_mstp_common_instance_first (idl);
    if (!cist_row) {
        ERRONEOUS_DB_TXN(txn, "No MSTP common instance record found");
    }

    if (VTYSH_STR_EQ(key, MSTP_BRIDGE_PRIORITY)) {
        ovsrec_mstp_common_instance_set_priority(cist_row, &value, 1);
    }
    else if (VTYSH_STR_EQ(key, MSTP_HELLO_TIME)) {
        ovsrec_mstp_common_instance_set_hello_time(cist_row, &value, 1);
    }
    else if (VTYSH_STR_EQ(key, MSTP_FORWARD_DELAY)) {
        ovsrec_mstp_common_instance_set_forward_delay(cist_row, &value, 1);
    }
    else if (VTYSH_STR_EQ(key, MSTP_MAX_HOP_COUNT)) {
        ovsrec_mstp_common_instance_set_max_hop_count(cist_row, &value, 1);
    }
    else if (VTYSH_STR_EQ(key, MSTP_MAX_AGE)) {
        ovsrec_mstp_common_instance_set_max_age(cist_row, &value, 1);
    }
    else if (VTYSH_STR_EQ(key, MSTP_TX_HOLD_COUNT)) {
        ovsrec_mstp_common_instance_set_tx_hold_count(cist_row, &value, 1);
    }

    END_DB_TXN(txn);
}

/*-----------------------------------------------------------------------------
 | Function:        mstp_cli_set_bridge_table
 | Responsibility:  Sets the bridge table config paramters, related to MSTP
 | Parameters:
 |      key:        Bridge column namee
 |      value:      Value to be set for the corresponding bridge column
 | Return:
 |      CMD_SUCCESS:Config executed successfully.
 |      CMD_OVSDB_FAILURE - DB failure.
 ------------------------------------------------------------------------------
 */
static int
mstp_cli_set_bridge_table (const char *key, const char *value) {
    const struct ovsrec_bridge *bridge_row = NULL;
    struct ovsdb_idl_txn *txn = NULL;
    struct smap smap = SMAP_INITIALIZER(&smap);
    bool mstp_enable = false;

    if (!(key && value)) {
        VLOG_DBG("Invalid arguments for mstp_cli_set_bridge_table %s: %d\n",
                __FILE__, __LINE__);
        return e_vtysh_error;
    }
    START_DB_TXN(txn);

    bridge_row = ovsrec_bridge_first(idl);
    if (!bridge_row) {
        ERRONEOUS_DB_TXN(txn, "No record found");
    }

    if (VTYSH_STR_EQ(key, MSTP_ADMIN_STATUS)) {
        mstp_enable = (VTYSH_STR_EQ(value, STATUS_ENABLE))?true:false;
        ovsrec_bridge_set_mstp_enable(bridge_row, &mstp_enable, 1);
    }
    else if((VTYSH_STR_EQ(key, MSTP_CONFIG_NAME)) ||
            (VTYSH_STR_EQ(key, MSTP_CONFIG_REV))) {
        smap_clone(&smap, &bridge_row->other_config);
        smap_replace(&smap, key , value);

        ovsrec_bridge_set_other_config(bridge_row, &smap);
        smap_destroy(&smap);
    }
    END_DB_TXN(txn);
}

/*-----------------------------------------------------------------------------
 | Function:        mstp_cli_set_mst_inst
 | Responsibility:  Sets the MSTP instance table config paramters
 | Parameters:
 |      key:        MSTP instance column name
 |      value:      Value to be set for the corresponding MSTP instance column
 | Return:
 |      CMD_SUCCESS:Config executed successfully.
 |      CMD_OVSDB_FAILURE - DB failure.
 ------------------------------------------------------------------------------
 */
static int
mstp_cli_set_mst_inst(const char *if_name,const char *key,
                  const int64_t instid, const int64_t value) {
    struct ovsdb_idl_txn *txn = NULL;
    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_mstp_instance *mstp_row = NULL;
    const struct ovsrec_mstp_instance_port *mstp_port_row = NULL;
    int i = 0;

    if (!key) {
        VLOG_DBG("Invalid arguments for mstp_cli_set_mst_inst %s: %d\n",
                __FILE__, __LINE__);
        return e_vtysh_error;
    }

    START_DB_TXN(txn);

    if (!MSTP_VALID_MSTID(instid)) {
        ERRONEOUS_DB_TXN(txn, "Invalid InstanceID");
    }

    bridge_row = ovsrec_bridge_first(idl);
    if (!bridge_row) {
        ERRONEOUS_DB_TXN(txn, "No record found");
    }

    /* Find the MSTP instance entry matching with the instid */
    for (i=0; i < bridge_row->n_mstp_instances; i++) {
        if (bridge_row->key_mstp_instances[i] == instid) {
            mstp_row = bridge_row->value_mstp_instances[i];
            break;
        }
    }

    /* Instance not created */
    if (!mstp_row) {
        ERRONEOUS_DB_TXN(txn,
                "No MSTP instance found with this ID");
    }

    if(VTYSH_STR_EQ(key, MSTP_BRIDGE_PRIORITY)) {
        ovsrec_mstp_instance_set_priority(mstp_row, &value, 1);

        /* End of transaction. */
        END_DB_TXN(txn);
    }

    /* Find the MSTP instance port entry matching with the port index */
    if( if_name != NULL) {
        for (i=0; i < mstp_row->n_mstp_instance_ports; i++) {
            if(!mstp_row->mstp_instance_ports[i]) {
                assert(0);
                ERRONEOUS_DB_TXN(txn, "No MSTP port record found");
            }
            if (VTYSH_STR_EQ(mstp_row->mstp_instance_ports[i]->port->name,
                                                    if_name)) {
                mstp_port_row = mstp_row->mstp_instance_ports[i];
                break;
            }
        }
        if (!mstp_port_row) {
            ERRONEOUS_DB_TXN(txn,
                    "No MSTP instance port found with this port index");
        }

        if(VTYSH_STR_EQ(key, MSTP_PORT_COST)) {
            ovsrec_mstp_instance_port_set_admin_path_cost(mstp_port_row, &value, 1);
        }
        else if(VTYSH_STR_EQ(key, MSTP_PORT_PRIORITY)) {
            ovsrec_mstp_instance_port_set_port_priority(mstp_port_row, &value, 1);
        }
    }

    /* End of transaction. */
    END_DB_TXN(txn);
}

/*-----------------------------------------------------------------------------
 | Function:        mstp_update_cist_vlans
 | Responsibility:  Remove vlan from CIST table
 | Parameters:
 |     vlanid:     VLAN ID
 ------------------------------------------------------------------------------
 */
static void
mstp_update_cist_vlans(const struct ovsrec_vlan *vlan_row, bool operation) {

    const struct ovsrec_mstp_common_instance *cist_row = NULL;
    struct ovsrec_vlan **vlans = NULL;
    int i = 0, j = 0;

    cist_row = ovsrec_mstp_common_instance_first(idl);
    if (!cist_row) {
        vty_out(vty, "No MSTP common instance record found%s", VTY_NEWLINE);
        return;
    }
    int n_vlans =
        (operation == true)?(cist_row->n_vlans + 1):(cist_row->n_vlans-1);

    vlans = xcalloc(n_vlans, sizeof *cist_row->vlans);
    if (!vlans) {
        vty_out(vty, "Memory allocation failed%s", VTY_NEWLINE);
        return;
    }

    /* Add the incoming vlan to the common instance table */
    if(operation == true) {
        for (i = 0; i < cist_row->n_vlans; i++) {
            vlans[i] = cist_row->vlans[i];
        }
        vlans[cist_row->n_vlans] = (struct ovsrec_vlan *)vlan_row;
    }
    /* Remove the incoming vlan from the common instance table */
    else {
        for (j = 0,i = 0; i < cist_row->n_vlans; i++) {
            if(vlan_row->id != cist_row->vlans[i]->id) {
                vlans[j++] = cist_row->vlans[i];
            }
        }
    }
    ovsrec_mstp_common_instance_set_vlans(cist_row, vlans, n_vlans);
    free(vlans);
}


/*-----------------------------------------------------------------------------
 | Function:        mstp_cli_inst_vlan_map
 | Responsibility:  Sets the MSTP instance table config paramters
 | Parameters:
 |     instid:     MSTP instance ID
 |     vlanid:     VLAN ID
 |     operation:  MSTP_REMOVE_VLAN_FROM_INSTANCE - Remove vlan from instance
 |                 MSTP_REMOVE_INSTANCE - Remove a complete instance
 | Return:
 |      CMD_SUCCESS:Config executed successfully.
 |      CMD_OVSDB_FAILURE - DB failure.
 ------------------------------------------------------------------------------
 */
static int
mstp_cli_remove_inst_vlan_map(const int64_t instid, const char *vlanid) {

    struct ovsdb_idl_txn *txn = NULL;
    const struct ovsrec_mstp_instance *mstp_inst_row = NULL;
    struct ovsrec_mstp_instance **mstp_info = NULL;
    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_vlan *vlan_row = NULL;
    struct ovsrec_vlan **vlans = NULL;
    int64_t mstp_old_inst_id = 0, *instId_list = NULL;
    int i = 0, j = 0, k = 0;

    int vlan_id =(vlanid)? atoi(vlanid):MSTP_INVALID_ID;

    START_DB_TXN(txn);
    if (!MSTP_VALID_MSTID(instid)) {
        ERRONEOUS_DB_TXN(txn, "Invalid InstanceID");
    }

    bridge_row = ovsrec_bridge_first(idl);
    if (!bridge_row) {
        ERRONEOUS_DB_TXN(txn, "No record found");
    }

    if (vlanid) {
        OVSREC_VLAN_FOR_EACH(vlan_row, idl) {
            if (vlan_id == vlan_row->id) {
                break;
            }
        }
        if (!vlan_row) {
            ERRONEOUS_DB_TXN(txn, "Invalid vlan ID");
        }

        /* Check if the vlan is already mapped to another instance */
        mstp_old_inst_id =
            mstp_util_get_mstid_for_vlanID(vlan_row->id, bridge_row);
        if ((mstp_old_inst_id != MSTP_INVALID_ID) &&
                (mstp_old_inst_id != instid)) {
            ERRONEOUS_DB_TXN(txn,
                    "This VLAN is not mapped to This instance");
        }
    }

    /* Check if any column with the same instid already exist */
    for (i=0; i < bridge_row->n_mstp_instances; i++) {
        if(!(bridge_row->value_mstp_instances[i])) {
            ERRONEOUS_DB_TXN(txn, "No record found");
        }
        if (bridge_row->key_mstp_instances[i] == instid) {
            mstp_inst_row = bridge_row->value_mstp_instances[i];
            break;
        }
    }

    /* MSTP instance not found with the incoming instID */
    if(!mstp_inst_row) {
        ERRONEOUS_DB_TXN(txn,
                "No MSTP instance found with this ID");
    }

    /* Removing a VLAN from existing instance */
    if(vlanid) {
        if(mstp_inst_row->n_vlans == 1) {
            ERRONEOUS_DB_TXN(txn,
                 "The request results in MSTP instance with no VLANs assigned");
        }
        /* Push the complete vlan list to MSTP instance table,
         * except the removed one */
        vlans =
            xcalloc(mstp_inst_row->n_vlans - 1, sizeof *mstp_inst_row->vlans);
        if (!vlans) {
            ERRONEOUS_DB_TXN(txn, "Memory allocation failed");
        }
        for (j=0, i = 0; i < mstp_inst_row->n_vlans; i++) {
            if(vlan_id != mstp_inst_row->vlans[i]->id) {
                vlans[j++] = mstp_inst_row->vlans[i];
            }
        }
        ovsrec_mstp_instance_set_vlans(mstp_inst_row, vlans,
                mstp_inst_row->n_vlans - 1);

        /* Add vlan to CIST*/
        mstp_update_cist_vlans(vlan_row, true);
        free(vlans);
    }

    /* Removing a complete MSTP instance */
    else {
        instId_list = xcalloc(bridge_row->n_mstp_instances -1, sizeof(int64_t));
        if (!instId_list) {
            ERRONEOUS_DB_TXN(txn, "Memory allocation failed");
        }
        mstp_info = xcalloc(bridge_row->n_mstp_instances - 1,
                            sizeof *bridge_row->value_mstp_instances);
        if (!mstp_info) {
            ERRONEOUS_DB_TXN(txn, "Memory allocation failed");
        }
        for (j=0, i = 0; i < bridge_row->n_mstp_instances; i++) {
            if (bridge_row->key_mstp_instances[i] != instid) {
                instId_list[j] = bridge_row->key_mstp_instances[i];
                mstp_info[j++] = bridge_row->value_mstp_instances[i];
            }
            else {
                /* All mapped vlans from the deleted instance need to move to CIST*/
                mstp_inst_row = bridge_row->value_mstp_instances[i];
                for (k=0; k<mstp_inst_row->n_vlans; k++) {
                    mstp_update_cist_vlans(mstp_inst_row->vlans[k], true);
                }
            }
        }

        /* Push the complete MSTP table into the bridge table */
        ovsrec_bridge_set_mstp_instances(bridge_row, instId_list,
                mstp_info, bridge_row->n_mstp_instances - 1);
        free(mstp_info);
        free(instId_list);
    }
    END_DB_TXN(txn);
}
/*-----------------------------------------------------------------------------
 | Function:        sort_mstp_instances
 | Responsibility:  sort MSTP instance pointers in ascending order
 | Parameters:
 |     instid:     MSTP instance ID
 |     vlanid:     VLAN ID
 ------------------------------------------------------------------------------
 */
static void
mstp_instances_sort(int64_t *instId_list,
        struct ovsrec_mstp_instance **mstp_info, int no_of_inst) {
    int i=0, j=0;
    struct ovsrec_mstp_instance *mstp_row = NULL;
    int64_t inst_id = 0;

    for (i = 0; i<no_of_inst; i++) {
        for (j=i+1; j<no_of_inst; j++) {
            if(instId_list[i] > instId_list[j]) {

                /* swap the instance ID */
                inst_id = instId_list[i];
                instId_list[i] = instId_list[j];
                instId_list[j] = inst_id;

                /* swap the UUID pointer of the instance*/
                mstp_row = mstp_info[i];
                mstp_info[i] = mstp_info[j];
                mstp_info[j] = mstp_row;
            }
        }
    }
}

/*-----------------------------------------------------------------------------
 | Function:        mstp_cli_inst_vlan_map
 | Responsibility:  Add new MSTP instance and vlans to existing instance
 | Parameters:
 |     instid:     MSTP instance ID
 |     vlanid:     VLAN ID
 | Return:
 |      CMD_SUCCESS:Config executed successfully.
 |      CMD_OVSDB_FAILURE - DB failure.
 ------------------------------------------------------------------------------
 */
static int
mstp_cli_add_inst_vlan_map(const int64_t instid, const char *vlanid) {

    struct ovsdb_idl_txn *txn = NULL;
    const struct ovsrec_mstp_instance *mstp_inst_row = NULL;
    struct ovsrec_mstp_instance *mstp_row=NULL, **mstp_info = NULL;
    struct ovsrec_mstp_instance_port *mstp_inst_port_row = NULL;
    struct ovsrec_mstp_instance_port **mstp_inst_port_info = NULL;
    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_vlan *vlan_row = NULL;
    struct ovsrec_vlan **vlans = NULL;
    int64_t mstp_old_inst_id = 0, *instId_list = NULL;
    int i = 0, j = 0;
    int64_t port_priority = DEF_MSTP_PORT_PRIORITY;
    int64_t priority = DEF_BRIDGE_PRIORITY;
    int64_t admin_path_cost = DEF_MSTP_COST;

    int vlan_id =(vlanid)? atoi(vlanid):MSTP_INVALID_ID;

    START_DB_TXN(txn);
    if (!MSTP_VALID_MSTID(instid)) {
        ERRONEOUS_DB_TXN(txn, "Invalid InstanceID");
    }

    bridge_row = ovsrec_bridge_first(idl);
    if (!bridge_row) {
        ERRONEOUS_DB_TXN(txn, "No record found");
    }

    if (vlanid) {
        OVSREC_VLAN_FOR_EACH(vlan_row, idl) {
            if (vlan_id == vlan_row->id) {
                break;
            }
        }
        if (!vlan_row) {
            ERRONEOUS_DB_TXN(txn, "Invalid vlan ID");
        }

        /* Check if the vlan is already mapped to another instance */
        mstp_old_inst_id =
            mstp_util_get_mstid_for_vlanID(vlan_row->id, bridge_row);
        if (mstp_old_inst_id != MSTP_INVALID_ID) {
            vty_out(vty, "This VLAN is already mapped to %ld instance%s",
                        mstp_old_inst_id, VTY_NEWLINE);
            ABORT_DB_TXN(txn, "NO Record found");
        }
    }

    /* Check if any column with the same instid already exist */
    for (i=0; i < bridge_row->n_mstp_instances; i++) {
        if(!(bridge_row->value_mstp_instances[i])) {
            ERRONEOUS_DB_TXN(txn, "No record found");
        }
        if (bridge_row->key_mstp_instances[i] == instid) {
            mstp_inst_row = bridge_row->value_mstp_instances[i];
            break;
        }
    }

    /* MSTP instance not found with the incoming instID */
    if(mstp_inst_row) {
        /* Push the complete vlan list to MSTP instance table
         * including the new vlan*/
        vlans =
            xcalloc(mstp_inst_row->n_vlans + 1, sizeof *mstp_inst_row->vlans);
        if (!vlans) {
            ERRONEOUS_DB_TXN(txn, "Memory allocation failed");
        }
        for (i = 0; i < mstp_inst_row->n_vlans; i++) {
            vlans[i] = mstp_inst_row->vlans[i];
        }
        vlans[mstp_inst_row->n_vlans] = (struct ovsrec_vlan *)vlan_row;

        ovsrec_mstp_instance_set_vlans(mstp_inst_row, vlans,
                mstp_inst_row->n_vlans + 1);

        free(vlans);
    }
    else {
        /* Create s MSTP instance row with the incoming data */
        mstp_row = ovsrec_mstp_instance_insert(txn);
        if (!mstp_row) {
            ERRONEOUS_DB_TXN(txn, "Memory allocation failed");
        }

        ovsrec_mstp_instance_set_vlans(mstp_row,
                (struct ovsrec_vlan **)&vlan_row, 1);
        ovsrec_mstp_instance_set_priority(mstp_row,
                &priority, 1);

        /* Add CSTI instance for all ports to the CIST table */
        mstp_inst_port_info =
            xcalloc((bridge_row->n_ports - 1),
                    sizeof *mstp_row->mstp_instance_ports);

        if (!mstp_inst_port_info) {
            ERRONEOUS_DB_TXN(txn, "Memory allocation failed");
        }

        for (i = 0, j = 0; i < bridge_row->n_ports; i++) {

            /* "bridge_normal" is not really a port, ignore it */
            if(VTYSH_STR_EQ(bridge_row->ports[i]->name, DEFAULT_BRIDGE_NAME)) {
                continue;
            }

            /* Create MSTI port table */
            mstp_inst_port_row = ovsrec_mstp_instance_port_insert(txn);
            if (!mstp_inst_port_row) {
                ERRONEOUS_DB_TXN(txn, "Memory allocation failed");
            }

            /* FILL the default values for CIST_port entry */
            ovsrec_mstp_instance_port_set_port_state(mstp_inst_port_row,
                                                     MSTP_STATE_BLOCK);
            ovsrec_mstp_instance_port_set_port_role( mstp_inst_port_row,
                                                      MSTP_ROLE_DISABLE);
            ovsrec_mstp_instance_port_set_port_priority(mstp_inst_port_row,
                                                        &port_priority, 1 );
            ovsrec_mstp_instance_port_set_admin_path_cost(mstp_inst_port_row,
                                                        &admin_path_cost, 1);
            ovsrec_mstp_instance_port_set_port(mstp_inst_port_row,
                                               bridge_row->ports[i]);
            mstp_inst_port_info[j++] = mstp_inst_port_row;
        }

        ovsrec_mstp_instance_set_mstp_instance_ports(mstp_row,
                    mstp_inst_port_info, (bridge_row->n_ports - 1));

        /* Append the MSTP new instance to the existing list */
        mstp_info = xcalloc(bridge_row->n_mstp_instances + 1,
                sizeof *bridge_row->value_mstp_instances);
        if (!mstp_info) {
            ERRONEOUS_DB_TXN(txn, "Memory allocation failed");
        }
        instId_list = xcalloc(bridge_row->n_mstp_instances + 1,
                        sizeof *bridge_row->key_mstp_instances);
        if (!instId_list) {
            ERRONEOUS_DB_TXN(txn, "Memory allocation failed");
        }
        for (i = 0; i < bridge_row->n_mstp_instances; i++) {
            instId_list[i] = bridge_row->key_mstp_instances[i];
            mstp_info[i] = bridge_row->value_mstp_instances[i];
        }
        instId_list[bridge_row->n_mstp_instances] = instid;
        mstp_info[bridge_row->n_mstp_instances] = mstp_row;

        /* Sort the MSTP instance list */
        mstp_instances_sort(instId_list, mstp_info, bridge_row->n_mstp_instances+1);

        /* Push the complete MSTP table into the bridge table */
        ovsrec_bridge_set_mstp_instances(bridge_row, instId_list,
                mstp_info, bridge_row->n_mstp_instances + 1);
        free(mstp_info);
        free(mstp_inst_port_info);
        free(instId_list);
    }

    /* Remove vlan from CIST*/
    mstp_update_cist_vlans(vlan_row, false);

    /* End of transaction. */
    END_DB_TXN(txn);
}

#if 0
/*-----------------------------------------------------------------------------
 | Function:        mstp_cli_set_mist_port_state
 | Responsibility:  Sets the MSTP instance port table port state paramters
 | Parameters:
 |      key:        MSTP instance column name
 |      value:      Value to be set for the corresponding MSTP instance column
 | Return:
 |      CMD_SUCCESS:Config executed successfully.
 |      CMD_OVSDB_FAILURE - DB failure.
 ------------------------------------------------------------------------------
 */
static int
mstp_cli_set_mist_port_state(const char *if_name, const int64_t instid,
                                     const char *port_state) {
    struct ovsdb_idl_txn *txn = NULL;
    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_mstp_instance *mstp_row = NULL;
    const struct ovsrec_mstp_instance_port *mstp_port_row = NULL;
    int i = 0;

    if (!(port_state && if_name)) {
        VLOG_DBG("Invalid arguments for mstp_cli_set_mst_inst %s: %d\n",
                __FILE__, __LINE__);
        return e_vtysh_error;
    }

    START_DB_TXN(txn);

    if (!MSTP_VALID_MSTID(instid)) {
        ERRONEOUS_DB_TXN(txn, "Invalid InstanceID");
    }

    bridge_row = ovsrec_bridge_first(idl);
    if (!bridge_row) {
        ERRONEOUS_DB_TXN(txn, "No record found");
    }

    /* Find the MSTP instance entry matching with the instid */
    for (i=0; i < bridge_row->n_mstp_instances; i++) {
        if (bridge_row->key_mstp_instances[i] == instid) {
            mstp_row = bridge_row->value_mstp_instances[i];
            break;
        }
    }

    /* Instance not created */
    if (!mstp_row) {
        ERRONEOUS_DB_TXN(txn,
                "No MSTP instance found with this ID");
    }

    /* Find the MSTP instance port entry matching with the port index */
    for (i=0; i < mstp_row->n_mstp_instance_ports; i++) {
        if(!mstp_row->mstp_instance_ports[i]) {
            assert(0);
            ERRONEOUS_DB_TXN(txn, "No MSTP port record found");
        }
        if (VTYSH_STR_EQ(mstp_row->mstp_instance_ports[i]->port->name,
                                                if_name)) {
            mstp_port_row = mstp_row->mstp_instance_ports[i];
            break;
        }
    }

    if (!mstp_port_row) {
        ERRONEOUS_DB_TXN(txn,
                "No MSTP instance port found with this port index");
    }

    if (VTYSH_STR_EQ(port_state, MSTP_STATE_DISABLE)) {
        ovsrec_mstp_instance_port_set_port_state(mstp_port_row, port_state);
    }
    else if (VTYSH_STR_EQ(port_state, MSTP_STATE_BLOCK)) {
        ovsrec_mstp_instance_port_set_port_state(mstp_port_row, port_state);

    }
    else if (VTYSH_STR_EQ(port_state, MSTP_STATE_LEARN)) {
        ovsrec_mstp_instance_port_set_port_state(mstp_port_row, port_state);

    }
    else if (VTYSH_STR_EQ(port_state, MSTP_STATE_FORWARD)) {
        ovsrec_mstp_instance_port_set_port_state(mstp_port_row, port_state);
    }
    else {
       ERRONEOUS_DB_TXN(txn,
                    "invalid port state");;
    }

    /* End of transaction. */
    END_DB_TXN(txn);
}

/*-----------------------------------------------------------------------------
 | Function:        mstp_cli_set_cist_port_state
 | Responsibility:  Sets the MSTP cist port table port state paramters
 | Parameters:
 |      key:        MSTP instance column name
 |      value:      Value to be set for the corresponding MSTP instance column
 | Return:
 |      CMD_SUCCESS:Config executed successfully.
 |      CMD_OVSDB_FAILURE - DB failure.
 ------------------------------------------------------------------------------
 */
static int
mstp_cli_set_cist_port_state(const char *if_name, const char *port_state) {
    struct ovsdb_idl_txn *txn = NULL;
    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_mstp_common_instance *cist_row = NULL;
    const struct ovsrec_mstp_common_instance_port *cist_port_row = NULL;
    int i = 0;

    if (!(port_state && if_name)) {
        VLOG_DBG("Invalid arguments for mstp_cli_set_cist_port_state %s: %d\n",
                __FILE__, __LINE__);
        return e_vtysh_error;
    }

    START_DB_TXN(txn);

    bridge_row = ovsrec_bridge_first(idl);
    if (!bridge_row) {
        ERRONEOUS_DB_TXN(txn, "No record found");
    }

    if (!bridge_row->mstp_common_instance) {
            ERRONEOUS_DB_TXN(txn,
                    "No CIST instance found");
    }

    cist_row = bridge_row->mstp_common_instance;

    /* Find the MSTP instance port entry matching with the port index */

    for (i=0; i < cist_row->n_mstp_common_instance_ports; i++) {
        if(!cist_row->mstp_common_instance_ports[i]) {
            ERRONEOUS_DB_TXN(txn, "No CIST port record found");
        }
        if (VTYSH_STR_EQ(cist_row->mstp_common_instance_ports[i]->port->name,
                                                if_name)) {
            cist_port_row = cist_row->mstp_common_instance_ports[i];
            break;
        }
    }

    if (!cist_port_row) {
        ERRONEOUS_DB_TXN(txn,
                "No cist port found with this port index");
    }

    if (VTYSH_STR_EQ(port_state, MSTP_STATE_DISABLE)) {
        ovsrec_mstp_common_instance_port_set_port_state(cist_port_row, port_state);
    }
    else if (VTYSH_STR_EQ(port_state, MSTP_STATE_BLOCK)) {
        ovsrec_mstp_common_instance_port_set_port_state(cist_port_row, port_state);

    }
    else if (VTYSH_STR_EQ(port_state, MSTP_STATE_LEARN)) {
        ovsrec_mstp_common_instance_port_set_port_state(cist_port_row, port_state);

    }
    else if (VTYSH_STR_EQ(port_state, MSTP_STATE_FORWARD)) {
        ovsrec_mstp_common_instance_port_set_port_state(cist_port_row, port_state);
    }
    else {
       ERRONEOUS_DB_TXN(txn,
                    "invalid port state");;
    }

    /* End of transaction. */
    END_DB_TXN(txn);
}
#endif

DEFUN(cli_mstp_func,
      cli_mstp_func_cmd,
      "spanning-tree",
      SPAN_TREE) {

    mstp_cli_set_bridge_table (MSTP_ADMIN_STATUS,
            STATUS_ENABLE);
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_func,
      cli_no_mstp_func_cmd,
      "no spanning-tree",
      NO_STR
      SPAN_TREE) {
    mstp_cli_set_bridge_table(MSTP_ADMIN_STATUS, STATUS_DISABLE);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_config_name,
      cli_mstp_config_name_cmd,
      "spanning-tree config-name WORD",
      SPAN_TREE
      "Set the MST region configuration name\n"
      "Specify the configuration name (maximum 32 characters) (Default: System MAC)\n") {

    if (strlen(argv[0]) > MSTP_MAX_CONFIG_NAME_LEN) {
        vty_out(vty, "Config-name string length exceeded.%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    mstp_cli_set_bridge_table(MSTP_CONFIG_NAME, argv[0]);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_config_rev,
      cli_mstp_config_rev_cmd,
      "spanning-tree config-revision <1-65535>",
      SPAN_TREE
      "Set the MST region configuration revision number\n"
      "Enter an integer number (Default: 0)\n") {

    mstp_cli_set_bridge_table(MSTP_CONFIG_REV, argv[0]);
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_config_name,
      cli_no_mstp_config_name_cmd,
      "no spanning-tree config-name {WORD}",
      NO_STR
      SPAN_TREE
      "Set the MST region configuration name\n"
      "Specify the configuration name (maximum 32 characters) (Default: System MAC)\n") {

    const struct ovsrec_system *system_row;
    system_row = ovsrec_system_first(idl);

    if(!system_row) {
        return CMD_OVSDB_FAILURE;
    }

    mstp_cli_set_bridge_table(MSTP_CONFIG_NAME, system_row->system_mac);
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_config_rev,
      cli_no_mstp_config_rev_cmd,
      "no spanning-tree config-revision {<1-65535>}",
      NO_STR
      SPAN_TREE
      "Set the MST region configuration revision number\n"
      "Enter an integer number (Default: 0)\n") {

    mstp_cli_set_bridge_table(MSTP_CONFIG_REV, DEF_CONFIG_REV);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_inst_vlanid,
      cli_mstp_inst_vlanid_cmd,
      "spanning-tree instance <1-64> vlan VLANID",
      SPAN_TREE
      MST_INST
      "Enter an integer number\n"
      VLAN_STR
      "VLAN to add or to remove from the MST instance\n") {
    mstp_cli_add_inst_vlan_map (atoi(argv[0]), argv[1]);
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_inst_vlanid,
      cli_no_mstp_inst_vlanid_cmd,
      "no spanning-tree instance <1-64> vlan VLANID",
      NO_STR
      SPAN_TREE
      MST_INST
      "Enter an integer number\n"
      VLAN_STR
      "VLAN to add or to remove from the MST instance\n") {
    mstp_cli_remove_inst_vlan_map (atoi(argv[0]), argv[1]);
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_inst,
      cli_no_mstp_inst_cmd,
      "no spanning-tree instance <1-64>",
      NO_STR
      SPAN_TREE
      MST_INST
      "Enter an integer number\n") {
    mstp_cli_remove_inst_vlan_map (atoi(argv[0]), NULL);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_port_type,
      cli_mstp_port_type_cmd,
      "spanning-tree port-type (admin-edge | admin-network)",
      SPAN_TREE
      "Type of port\n"
      "Set as administrative edge port\n"
      "Set as administrative network port (Default)\n") {

    const bool value = (VTYSH_STR_EQ(argv[0], "admin-edge"))?true:false;
    mstp_cli_set_cist_port_table( vty->index, MSTP_ADMIN_EDGE, value);
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_port_type_admin,
      cli_no_mstp_port_type_admin_cmd,
      "no spanning-tree port-type (admin-edge | admin-network)",
      NO_STR
      SPAN_TREE
      "Type of port\n"
      "Set as administrative edge port\n"
      "Set as administrative network port (Default)\n") {

    mstp_cli_set_cist_port_table(vty->index, MSTP_ADMIN_EDGE, DEF_ADMIN_EDGE);
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_port_type,
      cli_no_mstp_port_type_cmd,
      "no spanning-tree port-type",
      NO_STR
      SPAN_TREE
      "Type of port (Default: Network port)\n") {

    mstp_cli_set_cist_port_table(vty->index, MSTP_ADMIN_EDGE, DEF_ADMIN_EDGE);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_bpdu,
      cli_mstp_bpdu_cmd,
      "spanning-tree (bpdu-guard | root-guard | loop-guard | bpdu-filter)",
      SPAN_TREE
      BPDU_GUARD
      ROOT_GUARD
      LOOP_GUARD
      BPDU_FILTER) {

    mstp_cli_set_cist_port_table(vty->index, argv[0], true);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_bpdu_enable,
      cli_mstp_bpdu_enable_cmd,
      "spanning-tree (bpdu-guard | root-guard | loop-guard | bpdu-filter) (enable | disable)",
      SPAN_TREE
      BPDU_GUARD
      ROOT_GUARD
      LOOP_GUARD
      BPDU_FILTER
      "Enable feature for this port\n"
      "Disable feature for this port (Default)\n") {

    const bool value = (VTYSH_STR_EQ(argv[1], "enable"))?true:false;
    mstp_cli_set_cist_port_table( vty->index, argv[0], value);
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_bpdu_enable,
      cli_no_mstp_bpdu_enable_cmd,
      "no spanning-tree (bpdu-guard | root-guard | loop-guard | bpdu-filter) (enable | disable)",
      NO_STR
      SPAN_TREE
      BPDU_GUARD
      ROOT_GUARD
      LOOP_GUARD
      BPDU_FILTER
      "Enable feature for this port\n"
      "Disable feature for this port (Default)\n") {

    mstp_cli_set_cist_port_table(vty->index, argv[0], DEF_BPDU_STATUS);
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_bpdu,
      cli_no_mstp_bpdu_cmd,
      "no spanning-tree (bpdu-guard | root-guard | loop-guard | bpdu-filter)",
      NO_STR
      SPAN_TREE
      BPDU_GUARD
      ROOT_GUARD
      LOOP_GUARD
      BPDU_FILTER) {

    mstp_cli_set_cist_port_table(vty->index, argv[0], DEF_BPDU_STATUS);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_port_priority,
      cli_mstp_port_priority_cmd,
      "spanning-tree port-priority <0-15>",
      SPAN_TREE
      PORT_PRIORITY
      "Enter an integer number (Default: 8)\n") {

    mstp_cli_set_string_cist_port_table(vty->index, MSTP_PORT_PRIORITY, atoi(argv[0]));
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_port_priority,
      cli_no_mstp_port_priority_cmd,
      "no spanning-tree port-priority {<0-15>}",
      NO_STR
      SPAN_TREE
      PORT_PRIORITY
      "Enter an integer number (Default: 8)\n") {

    mstp_cli_set_string_cist_port_table(vty->index, MSTP_PORT_PRIORITY, DEF_MSTP_PORT_PRIORITY);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_cost,
      cli_mstp_cost_cmd,
      "spanning-tree cost <0-200000000>",
      SPAN_TREE
      "Specify a standard to use when calculating the default pathcost"
      "Enter an integer number (Default: 0)\n") {

    mstp_cli_set_string_cist_port_table(vty->index, MSTP_PORT_COST, atoi(argv[0]));
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_cost,
      cli_no_mstp_cost_cmd,
      "no spanning-tree cost {<0-200000000>}",
      NO_STR
      SPAN_TREE
      "Specify a standard to use when calculating the default pathcost"
      "Enter an integer number (Default: 0)\n") {

    mstp_cli_set_string_cist_port_table(vty->index, MSTP_PORT_COST, DEF_MSTP_COST);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_bridge_priority,
      cli_mstp_bridge_priority_cmd,
      "spanning-tree priority <0-15>",
      SPAN_TREE
      BRIDGE_PRIORITY
      "Enter an integer number (Default: 8)\n") {

    mstp_cli_set_cist_table( MSTP_BRIDGE_PRIORITY, atoi(argv[0]));
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_bridge_priority,
      cli_no_mstp_bridge_priority_cmd,
      "no spanning-tree priority {<0-15>}",
      NO_STR
      SPAN_TREE
      BRIDGE_PRIORITY
      "Enter an integer number (Default: 8)\n") {

    mstp_cli_set_cist_table( MSTP_BRIDGE_PRIORITY, DEF_BRIDGE_PRIORITY);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_inst_priority,
      cli_mstp_inst_priority_cmd,
      "spanning-tree instance <1-64> priority <0-15>",
      SPAN_TREE
      MST_INST
      "Enter an integer number\n"
      INST_PRIORITY
      "Enter an integer number (Default: 8)\n") {

    mstp_cli_set_mst_inst(NULL, MSTP_BRIDGE_PRIORITY, atoi(argv[0]), atoi(argv[1]));
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_inst_priority,
      cli_no_mstp_inst_priority_cmd,
      "no spanning-tree instance <1-64> priority {<0-15>}",
      NO_STR
      SPAN_TREE
      MST_INST
      "Enter an integer number\n"
      INST_PRIORITY
      "Enter an integer number (Default: 8)\n") {

    mstp_cli_set_mst_inst(NULL, MSTP_BRIDGE_PRIORITY, atoi(argv[0]),
                        DEF_BRIDGE_PRIORITY);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_inst_cost,
      cli_mstp_inst_cost_cmd,
      "spanning-tree instance <1-64> cost <0-200000000>",
      SPAN_TREE
      MST_INST
      "Enter an integer number\n"
      "Specify a standard to use when calculating the default pathcost"
      "Enter an integer number (Default: 0)\n") {

    mstp_cli_set_mst_inst(vty->index, MSTP_PORT_COST, atoi(argv[0]), atoi(argv[1]));
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_inst_cost,
      cli_no_mstp_inst_cost_cmd,
      "no spanning-tree instance <1-64> cost {<0-200000000>}",
      NO_STR
      SPAN_TREE
      MST_INST
      "Enter an integer number\n"
      "Specify a standard to use when calculating the default pathcost"
      "Enter an integer number (Default: 0)\n") {

    mstp_cli_set_mst_inst(vty->index, MSTP_PORT_COST, atoi(argv[0]),
                                                  DEF_MSTP_COST);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_inst_port_priority,
      cli_mstp_inst_port_priority_cmd,
      "spanning-tree instance <1-64> port-priority <0-15>",
      SPAN_TREE
      MST_INST
      "Enter an integer number\n"
      PORT_PRIORITY
      "Enter an integer number (Default: 8)\n") {

    mstp_cli_set_mst_inst(vty->index, MSTP_PORT_PRIORITY, atoi(argv[0]),
                                                      atoi(argv[1]));
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_inst_port_priority,
      cli_no_mstp_inst_port_priority_cmd,
      "no spanning-tree instance <1-64> port-priority {<0-15>}",
      NO_STR
      SPAN_TREE
      MST_INST
      "Enter an integer number\n"
      PORT_PRIORITY
      "Enter an integer number (Default: 8)\n") {

    mstp_cli_set_mst_inst(vty->index, MSTP_PORT_PRIORITY, atoi(argv[0]),
                                      DEF_MSTP_PORT_PRIORITY);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_hello,
      cli_mstp_hello_cmd,
      "spanning-tree hello-time <2-10>",
      SPAN_TREE
      "Set message transmission interval in seconds on the port\n"
      "Enter an integer number (Default: 2)\n") {

    mstp_cli_set_cist_table( MSTP_HELLO_TIME, atoi(argv[0]));
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_hello,
      cli_no_mstp_hello_cmd,
      "no spanning-tree hello-time {<2-10>}",
      NO_STR
      SPAN_TREE
      "Set message transmission interval in seconds on the port\n"
      "Enter an integer number (Default: 2)\n") {

    mstp_cli_set_cist_table( MSTP_HELLO_TIME, DEF_HELLO_TIME);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_forward_delay,
      cli_mstp_forward_delay_cmd,
      "spanning-tree forward-delay <4-30>",
      SPAN_TREE
      FORWARD_DELAY
      "Enter an integer number (Default: 15)\n") {

    mstp_cli_set_cist_table( MSTP_FORWARD_DELAY, atoi(argv[0]));
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_forward_delay,
      cli_no_mstp_forward_delay_cmd,
      "no spanning-tree forward-delay {<4-30>}",
      NO_STR
      SPAN_TREE
      FORWARD_DELAY
      "Enter an integer number (Default: 15)\n") {

    mstp_cli_set_cist_table( MSTP_FORWARD_DELAY, DEF_FORWARD_DELAY);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_max_hops,
      cli_mstp_max_hops_cmd,
      "spanning-tree max-hops <1-40>",
      SPAN_TREE
      MAX_HOPS
      "Enter an integer number (Default: 20)\n") {

    mstp_cli_set_cist_table( MSTP_MAX_HOP_COUNT, atoi(argv[0]));
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_max_hops,
      cli_no_mstp_max_hops_cmd,
      "no spanning-tree max-hops {<1-40>}",
      NO_STR
      SPAN_TREE
      MAX_HOPS
      "Enter an integer number (Default: 20)\n") {

    mstp_cli_set_cist_table( MSTP_MAX_HOP_COUNT, DEF_MAX_HOPS);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_max_age,
      cli_mstp_max_age_cmd,
      "spanning-tree max-age <6-40>",
      SPAN_TREE
      "Set maximum age of received STP information before it is discarded\n"
      "Enter an integer number (Default: 20)\n") {

    mstp_cli_set_cist_table( MSTP_MAX_AGE, atoi(argv[0]));
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_max_age,
      cli_no_mstp_max_age_cmd,
      "no spanning-tree max-age {<6-40>}",
      NO_STR
      SPAN_TREE
      "Set maximum age of received STP information before it is discarded\n"
      "Enter an integer number (Default: 20)\n") {

    mstp_cli_set_cist_table( MSTP_MAX_AGE, DEF_MAX_AGE);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_transmit_hold_count,
      cli_mstp_transmit_hold_count_cmd,
      "spanning-tree transmit-hold-count <1-10>",
      SPAN_TREE
      "Sets the transmit hold count performance parameter in pps\n"
      "Enter an integer number (Default: 6)\n") {

    mstp_cli_set_cist_table( MSTP_TX_HOLD_COUNT, atoi(argv[0]));
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_transmit_hold_count,
      cli_no_mstp_transmit_hold_count_cmd,
      "no spanning-tree transmit-hold-count {<1-10>}",
      NO_STR
      SPAN_TREE
      "Sets the transmit hold count performance parameter\n"
      "Enter an integer number (Default: 6)\n") {

    mstp_cli_set_cist_table( MSTP_TX_HOLD_COUNT, DEF_HOLD_COUNT);
    return CMD_SUCCESS;
}

#if 0
DEFUN_HIDDEN(cli_mstp_inst_port_state,
      cli_mstp_inst_port_state_cmd,
      "spanning-tree instance <1-64> port-state (Disabled | Blocking | Learning | Forwarding)",
      SPAN_TREE
      MST_INST
      "Enter an integer number\n"
      "Set port state\n"
      "Disabled\n"
      "Blocking\n"
      "Learning\n"
      "Forwarding\n") {

    mstp_cli_set_mist_port_state(vty->index, atoi(argv[0]), argv[1]);
    return CMD_SUCCESS;
}

DEFUN_HIDDEN(cli_mstp_port_state,
      cli_mstp_port_state_cmd,
      "spanning-tree port-state (Disabled | Blocking | Learning | Forwarding)",
      SPAN_TREE
      "Set port state\n"
      "Disabled\n"
      "Blocking\n"
      "Learning\n"
      "Forwarding\n") {

    mstp_cli_set_cist_port_state(vty->index, argv[0]);
    return CMD_SUCCESS;
}
#endif

/* MSTP Show commands*/
DEFUN(show_spanning_tree,
      show_spanning_tree_cmd,
      "show spanning-tree {detail}",
      SHOW_STR
      SPAN_TREE) {

    bool detail = (argv[0])? true: false;

    cli_show_spanning_tree_config(detail);
    vty_out(vty, "%s", VTY_NEWLINE);
    return CMD_SUCCESS;
}

DEFUN(show_mstp_config,
      show_mstp_config_cmd,
      "show spanning-tree mst-config",
      SHOW_STR
      SPAN_TREE
      "Show multiple spanning tree region configuration.\n") {
    cli_show_mstp_config();
    vty_out(vty, "%s", VTY_NEWLINE);
    return CMD_SUCCESS;
}

DEFUN(show_running_config_mstp,
      show_running_config_mstp_cmd,
      "show running-config spanning-tree",
      SHOW_STR
      "Current running configuration\n"
      SPAN_TREE) {
    cli_show_mstp_running_config();
    return CMD_SUCCESS;
}
DEFUN(show_spanning_mst,
      show_spanning_mst_cmd,
      "show spanning-tree mst {detail}",
      SHOW_STR
      SPAN_TREE
      MST_INST
      "Detailed spanning-tree\n") {

    bool detail = (argv[0])? true: false;

    cli_show_mst(MSTP_INVALID_ID, detail);
    vty_out(vty, "%s", VTY_NEWLINE);
    return CMD_SUCCESS;
}

DEFUN(show_spanning_mst_inst,
      show_spanning_mst_inst_cmd,
      "show spanning-tree mst <1-64> {detail}",
      SHOW_STR
      SPAN_TREE
      MST_INST
      "Enter an instance number\n"
      "Detailed spanning-tree\n") {

    bool detail = (argv[1])? true: false;

    cli_show_mst(atoi(argv[0]), detail);
    vty_out(vty, "%s", VTY_NEWLINE);
    return CMD_SUCCESS;
}

DEFUN(show_spanning_mst_inst_intf,
      show_spanning_mst_inst_intf_cmd,
      "show spanning-tree mst <1-64> interface IFNAME {detail}",
      SHOW_STR
      SPAN_TREE
      MST_INST
      "Enter an instance number\n"
      "interface string\n"
      "interface name string\n"
      "Detailed spanning-tree\n") {

    bool detail = (argv[2])? true: false;

    cli_show_mst_interface(atoi(argv[0]), argv[1], detail);
    vty_out(vty, "%s", VTY_NEWLINE);
    return CMD_SUCCESS;
}

/*-----------------------------------------------------------------------------
 | Function:        cli_pre_init
 | Responsibility:  Initialize ops-mstpd cli node.
 | Parameters:
 | Return:
 ------------------------------------------------------------------------------
 */
void
cli_pre_init() {

    ovsdb_idl_add_column(idl, &ovsrec_bridge_col_mstp_instances);
    ovsdb_idl_add_column(idl, &ovsrec_bridge_col_mstp_common_instance);
    ovsdb_idl_add_column(idl, &ovsrec_bridge_col_mstp_enable);
    ovsdb_idl_add_column(idl, &ovsrec_bridge_col_other_config);
    ovsdb_idl_add_column(idl, &ovsrec_bridge_col_status);

    ovsdb_idl_add_table(idl, &ovsrec_table_mstp_instance);
    ovsdb_idl_add_table(idl, &ovsrec_table_mstp_instance_port);
    ovsdb_idl_add_table(idl, &ovsrec_table_mstp_common_instance);
    ovsdb_idl_add_table(idl, &ovsrec_table_mstp_common_instance_port);

    /* MSTP Instance Table. */
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_topology_unstable);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_time_since_top_change);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_hardware_grp_id);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_designated_root);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_root_port);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_priority);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_mstp_instance_ports);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_bridge_identifier);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_root_path_cost);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_topology_change_count);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_vlans);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_root_priority);

    /* mstp instance port table */
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_port_col_designated_bridge);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_port_col_port_role);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_port_col_designated_root);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_port_col_port_priority);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_port_col_admin_path_cost);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_port_col_designated_bridge_priority);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_port_col_port_state);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_port_col_designated_root_priority);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_port_col_designated_cost);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_port_col_port);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_port_col_designated_port);

    /* mstp common instance table */
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_remaining_hops);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_topology_unstable);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_mstp_common_instance_ports);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_forward_delay_expiry_time);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_regional_root);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_oper_tx_hold_count);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_max_age);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_max_hop_count);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_designated_root);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_priority);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_root_path_cost);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_root_port);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_root_priority);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_hello_time);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_cist_path_cost);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_oper_max_age);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_oper_hello_time);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_topology_change_count);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_vlans);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_bridge_identifier);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_time_since_top_change);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_hardware_grp_id);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_hello_expiry_time);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_oper_forward_delay);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_forward_delay);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_tx_hold_count);

    /* mstp common instance port table */
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_fwd_transition_count);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_port_role);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_protocol_migration_enable);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_bpdu_filter_disable);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_admin_edge_port_disable);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_port_path_cost);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_port);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_designated_port);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_root_guard_disable);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_designated_bridge);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_designated_path_cost);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_designated_root);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_bpdu_guard_disable);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_mstp_statistics);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_port_hello_time);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_link_type);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_admin_path_cost);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_cist_path_cost);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_port_priority);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_bpdus_rx_enable);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_loop_guard_disable);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_bpdus_tx_enable);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_cist_regional_root_id);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_restricted_port_tcn_disable);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_oper_edge_port);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_restricted_port_role_disable);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_port_col_port_state);
}

/*-----------------------------------------------------------------------------
 | Function:        cli_post_init
 | Responsibility:  Initialize ops-mstpd cli element.
 | Parameters:
 | Return:
 ------------------------------------------------------------------------------
 */
void cli_post_init(void) {

    vtysh_ret_val retval = e_vtysh_error;

    /* Bridge Table Config */
    install_element(CONFIG_NODE, &cli_mstp_func_cmd);
    install_element(CONFIG_NODE, &cli_no_mstp_func_cmd);
    install_element(CONFIG_NODE, &cli_mstp_config_name_cmd);
    install_element(CONFIG_NODE, &cli_mstp_config_rev_cmd);
    install_element(CONFIG_NODE, &cli_no_mstp_config_rev_cmd);
    install_element(CONFIG_NODE, &cli_no_mstp_config_name_cmd);

    /* CIST table config */
    install_element(CONFIG_NODE, &cli_mstp_hello_cmd);
    install_element(CONFIG_NODE, &cli_mstp_forward_delay_cmd);
    install_element(CONFIG_NODE, &cli_mstp_max_age_cmd);
    install_element(CONFIG_NODE, &cli_mstp_max_hops_cmd);
    install_element(CONFIG_NODE, &cli_no_mstp_hello_cmd);
    install_element(CONFIG_NODE, &cli_mstp_transmit_hold_count_cmd);
    install_element(CONFIG_NODE, &cli_no_mstp_forward_delay_cmd);
    install_element(CONFIG_NODE, &cli_no_mstp_max_age_cmd);
    install_element(CONFIG_NODE, &cli_no_mstp_max_hops_cmd);
    install_element(CONFIG_NODE, &cli_no_mstp_transmit_hold_count_cmd);
    install_element(CONFIG_NODE, &cli_mstp_bridge_priority_cmd);
    install_element(CONFIG_NODE, &cli_no_mstp_bridge_priority_cmd);

    /* CIST port table config*/
    install_element(INTERFACE_NODE, &cli_mstp_bpdu_enable_cmd);
    install_element(INTERFACE_NODE, &cli_mstp_bpdu_cmd);
    install_element(INTERFACE_NODE, &cli_no_mstp_bpdu_cmd);
    install_element(INTERFACE_NODE, &cli_no_mstp_bpdu_enable_cmd);
    install_element(INTERFACE_NODE, &cli_mstp_port_type_cmd);
    install_element(INTERFACE_NODE, &cli_no_mstp_port_type_admin_cmd);
    install_element(INTERFACE_NODE, &cli_no_mstp_port_type_cmd);
    install_element(INTERFACE_NODE, &cli_mstp_port_priority_cmd);
    install_element(INTERFACE_NODE, &cli_no_mstp_port_priority_cmd);
    install_element(INTERFACE_NODE, &cli_mstp_cost_cmd);
    install_element(INTERFACE_NODE, &cli_no_mstp_cost_cmd);

    /* MSTP Inst Table */
    install_element(CONFIG_NODE, &cli_mstp_inst_vlanid_cmd);
    install_element(CONFIG_NODE, &cli_no_mstp_inst_vlanid_cmd);
    install_element(CONFIG_NODE, &cli_no_mstp_inst_cmd);
    install_element(CONFIG_NODE, &cli_mstp_inst_priority_cmd);
    install_element(CONFIG_NODE, &cli_no_mstp_inst_priority_cmd);

    /* MSTP Inst port Table */
    install_element(INTERFACE_NODE, &cli_mstp_inst_port_priority_cmd);
    install_element(INTERFACE_NODE, &cli_no_mstp_inst_port_priority_cmd);
    install_element(INTERFACE_NODE, &cli_mstp_inst_cost_cmd);
    install_element(INTERFACE_NODE, &cli_no_mstp_inst_cost_cmd);
    #if 0
    install_element(INTERFACE_NODE, &cli_mstp_inst_port_state_cmd);
    install_element(INTERFACE_NODE, &cli_mstp_port_state_cmd);
    #endif

    /* show commands */
    install_element(ENABLE_NODE, &show_spanning_tree_cmd);
    install_element(ENABLE_NODE, &show_spanning_mst_cmd);
    install_element(ENABLE_NODE, &show_spanning_mst_inst_cmd);
    install_element(ENABLE_NODE, &show_spanning_mst_inst_intf_cmd);
    install_element(ENABLE_NODE, &show_mstp_config_cmd);
    install_element(ENABLE_NODE, &show_running_config_mstp_cmd);

    retval = install_show_run_config_subcontext(e_vtysh_config_context,
                            e_vtysh_config_context_mstp,
                            &vtysh_config_context_mstp_clientcallback,
                            NULL, NULL);

    if(e_vtysh_ok != retval)
    {
        vtysh_ovsdb_config_logmsg(VTYSH_OVSDB_CONFIG_ERR,
                "MSTP context unable to add config callback");
        assert(0);
    }

    retval = install_show_run_config_subcontext(e_vtysh_interface_context,
                            e_vtysh_interface_context_mstp,
                            &vtysh_intf_context_mstp_clientcallback,
                            NULL, NULL);

    if(e_vtysh_ok != retval)
    {
        vtysh_ovsdb_config_logmsg(VTYSH_OVSDB_CONFIG_ERR,
                "MSTP context unable to add config callback");
        assert(0);
    }
}
