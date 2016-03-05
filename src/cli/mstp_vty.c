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
#include "mstp_vty.h"
#include "vtysh_ovsdb_mstp_context.h"

extern struct ovsdb_idl *idl;
bool init_required = true;

VLOG_DEFINE_THIS_MODULE(vtysh_mstp_cli);

/*-----------------------------------------------------------------------------
 | Function:        mstp_util_add_default_ports_to_cist
 | Responsibility:  Add all L2 VLANs to common instance table
 | Parameters:
 | Return:
 |      CMD_SUCCESS - Config executed successfully.
 |      CMD_OVSDB_FAILURE - DB failure.
 ------------------------------------------------------------------------------
 */
static int
mstp_util_add_default_ports_to_cist() {

    struct ovsrec_mstp_common_instance_port *cist_port_row = NULL;
    struct ovsrec_mstp_common_instance_port **cist_port_info = NULL;
    struct ovsdb_idl_txn *txn = NULL;
    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_mstp_common_instance *cist_row = NULL;
    int64_t i = 0, j = 0;

    int64_t cist_hello_time = DEF_HELLO_TIME;
    int64_t cist_port_priority = DEF_MSTP_PORT_PRIORITY;
    int64_t admin_path_cost = 0;
    struct ovsrec_vlan **vlans = NULL;

    START_DB_TXN(txn);

    bridge_row = ovsrec_bridge_first(idl);
    if (!bridge_row) {
        ERRONEOUS_DB_TXN(txn, "No record found");
    }

    cist_row = ovsrec_mstp_common_instance_first (idl);
    if (!cist_row) {
        ERRONEOUS_DB_TXN(txn, "No MSTP common instance record found");
    }

    /* Add CIST port entry for all ports to the CIST table */
    cist_port_info =
            xcalloc((bridge_row->n_ports - 1),
            sizeof *cist_row->mstp_common_instance_ports);
    if(!cist_port_info) {
        ERRONEOUS_DB_TXN(txn, "NO MSTP common instance port record found");
    }

    for (i = 0, j = 0; i < bridge_row->n_ports; i++) {

        /* "bridge_normal" is not really a port, ignore it */
        if(VTYSH_STR_EQ(bridge_row->ports[i]->name, DEFAULT_BRIDGE_NAME)) {
            continue;
        }

        /* create CIST_port entry */
        cist_port_row = ovsrec_mstp_common_instance_port_insert(txn);
        if (!cist_port_row) {
            vty_out(vty, "Memory allocation failed%s", VTY_NEWLINE);
            break;
        }
        /* FILL the default values for CIST_port entry */
        ovsrec_mstp_common_instance_port_set_port( cist_port_row,
                                                      bridge_row->ports[i]);
        ovsrec_mstp_common_instance_port_set_port_state( cist_port_row,
                                                      MSTP_STATE_BLOCK);
        ovsrec_mstp_common_instance_port_set_port_role( cist_port_row,
                                                      MSTP_ROLE_DISABLE);
        ovsrec_mstp_common_instance_port_set_admin_path_cost( cist_port_row,
                                                      &admin_path_cost, 1);
        ovsrec_mstp_common_instance_port_set_port_priority( cist_port_row,
                                                      &cist_port_priority, 1);
        ovsrec_mstp_common_instance_port_set_link_type( cist_port_row,
                                                      DEF_LINK_TYPE);
        ovsrec_mstp_common_instance_port_set_port_hello_time( cist_port_row,
                                                      &cist_hello_time, 1);
        cist_port_info[j++] = cist_port_row;
    }

    ovsrec_mstp_common_instance_set_mstp_common_instance_ports (cist_row,
                                    cist_port_info, bridge_row->n_ports - 1);
    vlans = xcalloc(bridge_row->n_vlans, sizeof *bridge_row->vlans);
    if (!vlans) {
        ERRONEOUS_DB_TXN(txn, "Memory allocation failed");
    }
    for (i = 0; i < bridge_row->n_vlans; i++) {
        vlans[i] = bridge_row->vlans[i];
    }

    ovsrec_mstp_common_instance_set_vlans(cist_row, vlans, bridge_row->n_vlans);
    free(vlans);
    free(cist_port_info);
    END_DB_TXN(txn);
}

/*-----------------------------------------------------------------------------
 | Function:        mstp_util_set_defaults
 | Responsibility:  Set default values for MSTP instance table & instance port
 | Parameters:
 | Return:
 |      CMD_SUCCESS:Config executed successfully.
 |      CMD_OVSDB_FAILURE - DB failure.
 ------------------------------------------------------------------------------
 */
static int
mstp_util_set_defaults() {

    const struct ovsrec_mstp_common_instance *cist_row = NULL;
    const struct ovsrec_system *system_row = NULL;
    const int64_t cist_top_change_count = 0;
    struct ovsdb_idl_txn *txn = NULL;
    time_t cist_time_since_top_change;
    const int64_t cist_priority = DEF_BRIDGE_PRIORITY;
    const int64_t hello_time = DEF_HELLO_TIME;
    const int64_t fwd_delay = DEF_FORWARD_DELAY;
    const int64_t max_age = DEF_MAX_AGE;
    const int64_t max_hops = DEF_MAX_HOPS;
    const int64_t tx_hold_cnt = DEF_HOLD_COUNT;
    const struct ovsrec_bridge *bridge_row = NULL;
    struct smap smap = SMAP_INITIALIZER(&smap);

    START_DB_TXN(txn);

    system_row = ovsrec_system_first(idl);
    if (!system_row) {
        ERRONEOUS_DB_TXN(txn, "No record found.");
    }

    bridge_row = ovsrec_bridge_first(idl);
    if (!bridge_row) {
        ERRONEOUS_DB_TXN(txn, "No record found");
    }

    time(&cist_time_since_top_change);
    smap_clone(&smap, &bridge_row->other_config);

    /* If config name is NULL, Set the system mac as config-name */
    if (!smap_get(&bridge_row->other_config, MSTP_CONFIG_NAME)) {
        smap_replace (&smap, MSTP_CONFIG_NAME, system_row->system_mac);
    }

    /* If config revision number is NULL, Set the system mac as config-name */
    if (!smap_get(&bridge_row->other_config, MSTP_CONFIG_REV)) {
        smap_replace (&smap, MSTP_CONFIG_REV, DEF_CONFIG_REV);
    }

    ovsrec_bridge_set_other_config(bridge_row, &smap);
    smap_destroy(&smap);

    cist_row = ovsrec_mstp_common_instance_first (idl);
    if (!cist_row) {

        /* Crate a CIST instance */
        cist_row = ovsrec_mstp_common_instance_insert(txn);
        if (!cist_row) {
            ERRONEOUS_DB_TXN(txn, "Memory allocation failed");
        }
        /* updating the default values to the CIST table */
        ovsrec_mstp_common_instance_set_hello_time(cist_row, &hello_time, 1);
        ovsrec_mstp_common_instance_set_priority(cist_row, &cist_priority, 1);
        ovsrec_mstp_common_instance_set_forward_delay(cist_row, &fwd_delay,1);
        ovsrec_mstp_common_instance_set_max_age(cist_row, &max_age, 1);
        ovsrec_mstp_common_instance_set_max_hop_count(cist_row, &max_hops, 1);
        ovsrec_mstp_common_instance_set_tx_hold_count(cist_row, &tx_hold_cnt,1);
        ovsrec_mstp_common_instance_set_regional_root(cist_row,
                                                      system_row->system_mac);
        ovsrec_mstp_common_instance_set_bridge_identifier(cist_row,
                                                      system_row->system_mac);
        ovsrec_mstp_common_instance_set_top_change_cnt(cist_row,
                                                     &cist_top_change_count, 1);
        ovsrec_mstp_common_instance_set_time_since_top_change(cist_row,
                                     (int64_t *)&cist_time_since_top_change, 1);

        /* Add the CIST instance to bridge table */
        ovsrec_bridge_set_mstp_common_instance(bridge_row, cist_row);
    }

    END_DB_TXN(txn);
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
 | Function:        cli_show_spanning_tree_config
 | Responsibility:  Displays the spanning-tree related global configurations
 | Parameters:
 | Return:
 |      Return : e_vtysh_ok on success else e_vtysh_error
 ------------------------------------------------------------------------------
 */
static int
cli_show_spanning_tree_config() {
    const struct ovsrec_mstp_common_instance_port *cist_port;
    const struct ovsrec_mstp_common_instance *cist_row;
    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_system *system_row = NULL;

    /* Get the current time to calculate the last topology change */
    time_t cur_time;
    time(&cur_time);

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

    cist_row = ovsrec_mstp_common_instance_first (idl);
    if (!cist_row) {
        vty_out(vty, "No MSTP common instance record found%s", VTY_NEWLINE);
        return e_vtysh_error;
    }

    if ((bridge_row->mstp_enable) &&
            (*bridge_row->mstp_enable != DEF_ADMIN_STATUS)) {
        vty_out(vty, "%s%s", "MST0", VTY_NEWLINE);
        vty_out(vty, "  %s%s", "Spanning tree status: Enabled", VTY_NEWLINE);
        vty_out(vty, "  %-10s %-10s: %-20ld%s", "Root ID", "Priority",
                                             *cist_row->priority, VTY_NEWLINE);
        vty_out(vty, "  %22s: %-20s%s", "MAC-Address",
                                          system_row->system_mac, VTY_NEWLINE);
        if (VTYSH_STR_EQ(system_row->system_mac, cist_row->regional_root)) {
            vty_out(vty, "  %34s%s", "This bridge is the root", VTY_NEWLINE);
        }
        vty_out(vty, "  %34s%ld  %s%ld  %s%ld%s",
                "Hello time(in seconds):", *cist_row->hello_time,
                "Max Age(in seconds):", *cist_row->max_age,
                "Forward Delay(in seconds):", *cist_row->forward_delay,
                VTY_NEWLINE);

        vty_out(vty, "%s  %-10s %-10s: %-20ld%s", VTY_NEWLINE, "Bridge ID",
                     "Priority", *cist_row->priority, VTY_NEWLINE);
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
        OVSREC_MSTP_COMMON_INSTANCE_PORT_FOR_EACH(cist_port, idl) {
            vty_out(vty, "%-12s %-14s %-10s %-7ld %-10ld %s%s",
                    cist_port->port->name, cist_port->port_role,
                    cist_port->port_state, *cist_port->admin_path_cost,
                    *cist_port->port_priority, cist_port->link_type,
                    VTY_NEWLINE);
        }
    }
    else {
        vty_out(vty, "Spanning-tree is disabled%s", VTY_NEWLINE);
    }
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
    int i = 0, j = 0;

    bridge_row = ovsrec_bridge_first(idl);
    if (!bridge_row) {
        vty_out(vty, "No record found.%s", VTY_NEWLINE);
        return e_vtysh_error;
    }

    if ((bridge_row->mstp_enable) &&
            (*bridge_row->mstp_enable != DEF_ADMIN_STATUS)) {
        vty_out(vty, "%s%s", "MST configuration information", VTY_NEWLINE);
        vty_out(vty, "   %-20s : %-15s%s", "MST config ID",
            smap_get(&bridge_row->other_config, MSTP_CONFIG_NAME), VTY_NEWLINE);
        vty_out(vty, "   %-20s : %-15d %s", "MST config revision",
                atoi(smap_get(&bridge_row->other_config, MSTP_CONFIG_REV)),
                VTY_NEWLINE);
        /*vty_out(vty, "   %-30s : %-15s %s", "MST Configuration Digest",
          smap_get(&bridge_row->other_config, MSTP_CONFIG_DIGEST), VTY_NEWLINE);*/
        vty_out(vty, "   %-20s : %-15ld %s", "Number of instances",
                bridge_row->n_mstp_instances, VTY_NEWLINE);

        vty_out(vty, "%s%-15s %-18s%s", VTY_NEWLINE, "Instance ID",
                                        "Member VLANs", VTY_NEWLINE);
        vty_out(vty, "--------------- ----------------------------------%s",
                                                                VTY_NEWLINE);

        /* Loop for all instance in bridge table */
        for (i=0; i < bridge_row->n_mstp_instances; i++) {
            /* Loop for all vlans in one MST instance table */
            vty_out(vty,"%-15ld %ld", bridge_row->key_mstp_instances[i],
                        bridge_row->value_mstp_instances[i]->vlans[0]->id);
            for (j=1; j<bridge_row->value_mstp_instances[i]->n_vlans; j++) {
                        vty_out(vty, ",%ld",
                        bridge_row->value_mstp_instances[i]->vlans[j]->id );
            }
            vty_out(vty, "%s", VTY_NEWLINE);
        }
    }
    else {
        vty_out(vty, "Spanning-tree is disabled%s", VTY_NEWLINE);
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

    system_row = ovsrec_system_first(idl);
    if (!system_row) {
        vty_out(vty, "No record found%s", VTY_NEWLINE);
        return e_vtysh_error;
    }

    /* common instance table details */
    vty_out(vty, "%-14s %s%s  ", "#### MST0", VTY_NEWLINE, "vlans mapped:");
    if (cist_row->vlans) {
        vty_out(vty, "%ld", cist_row->vlans[0]->id);
        for (j=1; j<cist_row->n_vlans; j++) {
            vty_out(vty, ",%ld", cist_row->vlans[j]->id);
        }
    }
    vty_out(vty, "%s", VTY_NEWLINE);
    vty_out(vty, "%-14s %s:%-15s    %s:%ld%s", "Bridge", "address",
            system_row->system_mac, "priority", *cist_row->priority,
            VTY_NEWLINE);
    if (VTYSH_STR_EQ(system_row->system_mac, cist_row->regional_root)) {
        vty_out(vty, "%-14s %s%s", "Root", "this switch for the CIST",
                VTY_NEWLINE);
    }
    if (VTYSH_STR_EQ(system_row->system_mac, cist_row->designated_root)) {
        vty_out(vty, "%-14s %s%s", "Regional Root", "this switch", VTY_NEWLINE);
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

    vty_out(vty, "%s%-14s %-14s %-10s %-7s %-10s %s%s", VTY_NEWLINE,
            "Port", "Role", "State", "Cost", "Priority", "Type", VTY_NEWLINE);
    vty_out(vty, "%s %s%s",
            "-------------- --------------",
            "---------- ------- ---------- ----------",
            VTY_NEWLINE);
    OVSREC_MSTP_COMMON_INSTANCE_PORT_FOR_EACH(cist_port, idl) {
        vty_out(vty, "%-14s %-14s %-10s %-7ld %-10ld %s%s",
                cist_port->port->name, cist_port->port_role,
                cist_port->port_state, *cist_port->admin_path_cost,
                *cist_port->port_priority, cist_port->link_type,
                VTY_NEWLINE);
    }
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
                   const struct ovsrec_bridge *bridge_row) {
    const struct ovsrec_system *system_row = NULL;
    const struct ovsrec_mstp_instance *mstp_row = NULL;
    const struct ovsrec_mstp_instance_port *mstp_port = NULL;
    int j = 0, i = 0;

    if (!(cist_row && bridge_row)) {
        VLOG_DBG("Invalid arguments for mstp_show_instance_info %s: %d\n",
                __FILE__, __LINE__);
        return e_vtysh_error;
    }

    system_row = ovsrec_system_first(idl);
    if (!system_row) {
        vty_out(vty, "No record found.%s", VTY_NEWLINE);
        return e_vtysh_error;
    }

    /* Loop for all instance in bridge table */
    for (i=0; i < bridge_row->n_mstp_instances; i++) {
        mstp_row = bridge_row->value_mstp_instances[i];
        if (!mstp_row) {
            assert(0);
            return e_vtysh_error;
        }

        vty_out(vty, "%s%s%ld%s%s  ", VTY_NEWLINE, "#### MST",
                bridge_row->key_mstp_instances[i], VTY_NEWLINE, "vlans mapped:");
        if (mstp_row->vlans) {
            vty_out(vty, "%ld", mstp_row->vlans[0]->id);
            for (j=1; j<mstp_row->n_vlans; j++) {
                vty_out(vty, ",%ld", mstp_row->vlans[j]->id);
            }
        }
        vty_out(vty, "%s", VTY_NEWLINE);
        vty_out(vty, "%-14s %s:%-18s %s:%ld%s", "Bridge", "address",
                system_row->system_mac, "priority",
                (mstp_row->priority)?*mstp_row->priority:DEF_BRIDGE_PRIORITY,
                VTY_NEWLINE);

        vty_out(vty, "%-14s address:%-18s priority:%ld%s", "Root",
                (mstp_row->designated_root)?:system_row->system_mac,
                (mstp_row->root_priority)?*mstp_row->root_priority:DEF_BRIDGE_PRIORITY,
                VTY_NEWLINE);

        vty_out(vty, "%19s:%ld, Cost:%ld, Rem Hops:%ld%s", "Port",
                (mstp_row->root_port)?*mstp_row->root_port:(int64_t)0,
                (mstp_row->root_path_cost)?*mstp_row->root_path_cost:DEF_MSTP_COST,
                (cist_row->remaining_hops)?*cist_row->remaining_hops:(int64_t)0,
                VTY_NEWLINE);

        vty_out(vty, "%s%-14s %-14s %-10s %-7s %-10s %s%s",VTY_NEWLINE,
                "Port", "Role", "State", "Cost", "Priority", "Type",
                VTY_NEWLINE);
        vty_out(vty, "%s %s%s",
                "-------------- --------------",
                "---------- ------- ---------- ----------",
                VTY_NEWLINE);
        for (j=0; j < mstp_row->n_mstp_instance_ports; j++) {
            mstp_port = mstp_row->mstp_instance_ports[j];
            if(!mstp_port) {
                assert(0);
                return e_vtysh_error;
            }
            vty_out(vty, "%-14s %-14s %-10s %-7ld %-10ld %s%s",
                    mstp_port->port->name, mstp_port->port_role,
                    mstp_port->port_state,
                    (mstp_port->admin_path_cost)?*mstp_port->admin_path_cost:DEF_MSTP_COST,
                    *mstp_port->port_priority, "p2p", VTY_NEWLINE);
        }
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
cli_show_mst() {
    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_mstp_common_instance *cist_row = NULL;

    bridge_row = ovsrec_bridge_first(idl);
    if (!bridge_row) {
        vty_out(vty, "No record found.%s", VTY_NEWLINE);
        return e_vtysh_error;
    }

    if (*bridge_row->mstp_enable != DEF_ADMIN_STATUS) {
        cist_row = ovsrec_mstp_common_instance_first (idl);
        if (!cist_row) {
            vty_out(vty, "No MSTP common instance record found.%s", VTY_NEWLINE);
            return e_vtysh_error;
        }
        mstp_show_common_instance_info(cist_row);
        mstp_show_instance_info(cist_row, bridge_row);
    }
    else {
        vty_out(vty, "Spanning-tree is disabled%s", VTY_NEWLINE);
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

            /* Loop for all vlans in one MST instance table */
            for (j=0; j<mstp_row->n_vlans; j++) {
                vty_out(vty, "spanning-tree instance %ld vlan %ld%s",
                    bridge_row->key_mstp_instances[i], mstp_row->vlans[j]->id,
                    VTY_NEWLINE);
            }

            if (mstp_row->priority &&
                    (*mstp_row->priority != DEF_BRIDGE_PRIORITY)) {
                vty_out(vty, "spanning-tree instance %ld priority %ld%s",
                bridge_row->key_mstp_instances[i],
                *mstp_row->priority, VTY_NEWLINE);
            }
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

    bridge_row = ovsrec_bridge_first(idl);
    if (!bridge_row) {
        return e_vtysh_ok;
    }
    cist_row = ovsrec_mstp_common_instance_first (idl);
    if (!cist_row) {
        return e_vtysh_ok;
    }

    /* CIST port configs */
    for (i=0; i < cist_row->n_mstp_common_instance_ports; i++) {
        cist_port_row = cist_row->mstp_common_instance_ports[i];
        if(!cist_port_row) {
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
        for (j=0; j < bridge_row->n_mstp_instances; j++) {
            mstp_row = bridge_row->value_mstp_instances[j];

            /* MST instance commands if port name matches */
            if(!mstp_row) {
                continue;
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

    /* TODO This part of initialization need to move to MSTP daemon */
    if (VTYSH_STR_EQ(key, MSTP_ADMIN_STATUS)) {
        mstp_enable = (VTYSH_STR_EQ(value, STATUS_ENABLE))?true:false;

        /* Set the default config-name at the time of enable spanning-tree */
        if((mstp_enable == true) && (init_required == true)) {
            mstp_util_set_defaults();
            mstp_util_add_default_ports_to_cist();
            init_required = false;
        }
    }

    START_DB_TXN(txn);

    bridge_row = ovsrec_bridge_first(idl);
    if (!bridge_row) {
        ERRONEOUS_DB_TXN(txn, "No record found");
    }

    if (VTYSH_STR_EQ(key, MSTP_ADMIN_STATUS)) {
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

    if (!(key && if_name)) {
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
    }

    if(VTYSH_STR_EQ(key, MSTP_PORT_COST)) {
        ovsrec_mstp_instance_port_set_admin_path_cost(mstp_port_row, &value, 1);
    }
    else if(VTYSH_STR_EQ(key, MSTP_PORT_PRIORITY)) {
        ovsrec_mstp_instance_port_set_port_priority(mstp_port_row, &value, 1);
    }

    /* End of transaction. */
    END_DB_TXN(txn);
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
    int i = 0, j = 0;

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

        /* Push the complete MSTP table into the bridge table */
        ovsrec_bridge_set_mstp_instances(bridge_row, instId_list,
                mstp_info, bridge_row->n_mstp_instances + 1);
        free(mstp_info);
        free(mstp_inst_port_info);
        free(instId_list);
    }

    /* End of transaction. */
    END_DB_TXN(txn);
}

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
      "Specify the configuration name (maximum 32 characters)\n") {

    if (strlen(argv[0]) > MSTP_MAX_CONFIG_NAME_LEN) {
        vty_out(vty, "Config-name string length exceeded.%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    mstp_cli_set_bridge_table(MSTP_CONFIG_NAME, argv[0]);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_config_rev,
      cli_mstp_config_rev_cmd,
      "spanning-tree config-revision <1-40>",
      SPAN_TREE
      "Set the MST region configuration revision number(Default: 0)\n"
      "Enter an integer number\n") {

    mstp_cli_set_bridge_table(MSTP_CONFIG_REV, argv[0]);
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_config_name,
      cli_no_mstp_config_name_cmd,
      "no spanning-tree config-name [WORD]",
      NO_STR
      SPAN_TREE
      "Set the MST region configuration name\n"
      "Specify the configuration name (maximum 32 characters)\n") {

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
      "no spanning-tree config-revision [<1-40>]",
      NO_STR
      SPAN_TREE
      "Set the MST region configuration revision number(Default: 0)\n"
      "Enter an integer number\n") {

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
      "Set as administrative network port\n") {

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
      "Set as administrative network port\n") {

    mstp_cli_set_cist_port_table(vty->index, MSTP_ADMIN_EDGE, DEF_ADMIN_EDGE);
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_port_type,
      cli_no_mstp_port_type_cmd,
      "no spanning-tree port-type",
      NO_STR
      SPAN_TREE
      "Type of port\n") {

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
      "Disable feature for this port\n") {

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
      "Disable feature for this port\n") {

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

DEFUN(cli_mstp_bridge_priority,
      cli_mstp_bridge_priority_cmd,
      "spanning-tree priority <0-15>",
      SPAN_TREE
      BRIDGE_PRIORITY
      "Enter an integer number\n") {

    mstp_cli_set_cist_table( MSTP_BRIDGE_PRIORITY, atoi(argv[0]));
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_bridge_priority,
      cli_no_mstp_bridge_priority_cmd,
      "no spanning-tree priority [<0-15>]",
      NO_STR
      SPAN_TREE
      BRIDGE_PRIORITY
      "Enter an integer number\n") {

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
      "Enter an integer number\n") {

    mstp_cli_set_mst_inst(NULL, MSTP_BRIDGE_PRIORITY, atoi(argv[0]), atoi(argv[1]));
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_inst_priority,
      cli_no_mstp_inst_priority_cmd,
      "no spanning-tree instance <1-64> priority [<0-15>]",
      NO_STR
      SPAN_TREE
      MST_INST
      "Enter an integer number\n"
      INST_PRIORITY
      "Enter an integer number\n") {

    mstp_cli_set_mst_inst(NULL, MSTP_BRIDGE_PRIORITY, atoi(argv[0]),
                        DEF_BRIDGE_PRIORITY);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_inst_cost,
      cli_mstp_inst_cost_cmd,
      "spanning-tree instance <1-64> cost <1-200000000>",
      SPAN_TREE
      MST_INST
      "Enter an integer number\n"
      "Specify a standard to use when calculating the default pathcost"
      "Enter an integer number\n") {

    mstp_cli_set_mst_inst(vty->index, MSTP_PORT_COST, atoi(argv[0]), atoi(argv[1]));
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_inst_cost,
      cli_no_mstp_inst_cost_cmd,
      "no spanning-tree instance <1-64> cost [<1-200000000>]",
      NO_STR
      SPAN_TREE
      MST_INST
      "Enter an integer number\n"
      "Specify a standard to use when calculating the default pathcost"
      "Enter an integer number\n") {

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
      "Enter an integer number\n") {

    mstp_cli_set_mst_inst(vty->index, MSTP_PORT_PRIORITY, atoi(argv[0]),
                                                      atoi(argv[1]));
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_inst_port_priority,
      cli_no_mstp_inst_port_priority_cmd,
      "no spanning-tree instance <1-64> port-priority [<0-15>]",
      SPAN_TREE
      MST_INST
      "Enter an integer number\n"
      PORT_PRIORITY
      "Enter an integer number\n") {

    mstp_cli_set_mst_inst(vty->index, MSTP_PORT_PRIORITY, atoi(argv[0]),
                                      DEF_MSTP_PORT_PRIORITY);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_hello,
      cli_mstp_hello_cmd,
      "spanning-tree hello-time <2-10>",
      SPAN_TREE
      "Set message transmission interval in seconds on the port\n"
      "Enter an integer number\n") {

    mstp_cli_set_cist_table( MSTP_HELLO_TIME, atoi(argv[0]));
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_hello,
      cli_no_mstp_hello_cmd,
      "no spanning-tree hello-time [<2-10>]",
      NO_STR
      SPAN_TREE
      "Set message transmission interval in seconds on the port\n"
      "Enter an integer number\n") {

    mstp_cli_set_cist_table( MSTP_HELLO_TIME, DEF_HELLO_TIME);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_forward_delay,
      cli_mstp_forward_delay_cmd,
      "spanning-tree forward-delay <4-30>",
      SPAN_TREE
      FORWARD_DELAY
      "Enter an integer number\n") {

    mstp_cli_set_cist_table( MSTP_FORWARD_DELAY, atoi(argv[0]));
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_forward_delay,
      cli_no_mstp_forward_delay_cmd,
      "no spanning-tree forward-delay [<4-30>]",
      NO_STR
      SPAN_TREE
      FORWARD_DELAY
      "Enter an integer number\n") {

    mstp_cli_set_cist_table( MSTP_FORWARD_DELAY, DEF_FORWARD_DELAY);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_max_hops,
      cli_mstp_max_hops_cmd,
      "spanning-tree max-hops <1-40>",
      SPAN_TREE
      MAX_HOPS
      "Enter an integer number\n") {

    mstp_cli_set_cist_table( MSTP_MAX_HOP_COUNT, atoi(argv[0]));
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_max_hops,
      cli_no_mstp_max_hops_cmd,
      "no spanning-tree max-hops [<1-40>]",
      NO_STR
      SPAN_TREE
      MAX_HOPS
      "Enter an integer number\n") {

    mstp_cli_set_cist_table( MSTP_MAX_HOP_COUNT, DEF_MAX_HOPS);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_max_age,
      cli_mstp_max_age_cmd,
      "spanning-tree max-age <6-40>",
      SPAN_TREE
      "Set maximum age of received STP information before it is discarded\n"
      "Enter an integer number\n") {

    mstp_cli_set_cist_table( MSTP_MAX_AGE, atoi(argv[0]));
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_max_age,
      cli_no_mstp_max_age_cmd,
      "no spanning-tree max-age [<6-40>]",
      NO_STR
      SPAN_TREE
      "Set maximum age of received STP information before it is discarded\n"
      "Enter an integer number\n") {

    mstp_cli_set_cist_table( MSTP_MAX_AGE, DEF_MAX_AGE);
    return CMD_SUCCESS;
}

DEFUN(cli_mstp_transmit_hold_count,
      cli_mstp_transmit_hold_count_cmd,
      "spanning-tree transmit-hold-count <1-10>",
      SPAN_TREE
      "Sets the transmit hold count performance parameter in pps\n"
      "Enter an integer number\n") {

    mstp_cli_set_cist_table( MSTP_TX_HOLD_COUNT, atoi(argv[0]));
    return CMD_SUCCESS;
}

DEFUN(cli_no_mstp_transmit_hold_count,
      cli_no_mstp_transmit_hold_count_cmd,
      "no spanning-tree transmit-hold-count [<1-10>]",
      NO_STR
      SPAN_TREE
      "Sets the transmit hold count performance parameter\n"
      "Enter an integer number\n") {

    mstp_cli_set_cist_table( MSTP_TX_HOLD_COUNT, DEF_HOLD_COUNT);
    return CMD_SUCCESS;
}

/* MSTP Show commands*/
DEFUN(show_spanning_tree,
      show_spanning_tree_cmd,
      "show spanning-tree",
      SHOW_STR
      SPAN_TREE) {
    cli_show_spanning_tree_config();
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
      "Show the switch running configuration.\n"
      SPAN_TREE) {
    cli_show_mstp_running_config();
    return CMD_SUCCESS;
}

DEFUN(show_spanning_mst,
      show_spanning_mst_cmd,
      "show spanning-tree mst",
      SHOW_STR
      SPAN_TREE
      MST_INST) {
    cli_show_mst();
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

    ovsdb_idl_add_table(idl, &ovsrec_table_mstp_instance);
    ovsdb_idl_add_table(idl, &ovsrec_table_mstp_instance_port);
    ovsdb_idl_add_table(idl, &ovsrec_table_mstp_common_instance);
    ovsdb_idl_add_table(idl, &ovsrec_table_mstp_common_instance_port);

    /* MSTP Instance Table. */
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_topology_change_disable);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_time_since_top_change);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_hardware_grp_id);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_designated_root);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_root_port);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_priority);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_mstp_instance_ports);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_bridge_identifier);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_root_path_cost);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_instance_col_top_change_cnt);
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
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_top_change_cnt);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_vlans);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_bridge_identifier);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_time_since_top_change);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_hardware_grp_id);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_hello_expiry_time);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_oper_forward_delay);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_forward_delay);
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_tx_hold_count);

    /* mstp common instance port table */
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

    /* show commands */
    install_element(ENABLE_NODE, &show_spanning_tree_cmd);
    install_element(ENABLE_NODE, &show_spanning_mst_cmd);
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
