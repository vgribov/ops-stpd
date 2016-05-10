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
/******************************************************************************
 *    File               : vtysh_ovsdb_mstp_context.c
 *    Description        : MSTP Protocol show running config API
 ******************************************************************************/
#include "vtysh/vty.h"
#include "vtysh/vector.h"
#include "vswitch-idl.h"
#include "openswitch-idl.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"
#include "vtysh_ovsdb_mstp_context.h"
#include "mstp_vty.h"

/*-----------------------------------------------------------------------------
 | Function:        vtysh_ovsdb_parse_mstp_global_config
 | Responsibility:  Client callback routine for show running-config
 |                  displays the global commands for MSTP
 | Parameters:
 |      p_private:  void type object typecast to required
 | Return:
 |      e_vtysh_ok on success else e_vtysh_error
 ------------------------------------------------------------------------------
 */
static int
vtysh_ovsdb_parse_mstp_global_config(vtysh_ovsdb_cbmsg_ptr p_msg) {
    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_system *system_row = NULL;
    const struct ovsrec_mstp_common_instance *cist_row = NULL;
    const struct ovsrec_mstp_instance *mstp_row = NULL;
    const char *data = NULL;
    size_t i = 0, j = 0;

    system_row = ovsrec_system_first(p_msg->idl);
    if (!system_row) {
        return e_vtysh_error;
    }

    /* Bridge configs */
    bridge_row = ovsrec_bridge_first(p_msg->idl);
    if (bridge_row) {
        if (bridge_row->mstp_enable &&
                (*bridge_row->mstp_enable != DEF_ADMIN_STATUS)) {
            vtysh_ovsdb_cli_print(p_msg, "spanning-tree");
        }

        data = smap_get(&bridge_row->other_config, MSTP_CONFIG_NAME);
        if (data && (!VTYSH_STR_EQ(data, system_row->system_mac))) {
            vtysh_ovsdb_cli_print(p_msg, "spanning-tree config-name %s",
                                                                data);
        }

        data = smap_get(&bridge_row->other_config, MSTP_CONFIG_REV);
        if (data && (atoi(DEF_CONFIG_REV) != atoi(data))) {
            vtysh_ovsdb_cli_print(p_msg, "spanning-tree config-revision %d",
                                                      atoi(data));
        }

        /* Loop for all instance in bridge table */
        for (i=0; i < bridge_row->n_mstp_instances; i++) {
            mstp_row = bridge_row->value_mstp_instances[i];
            if(!mstp_row) {
                continue;
            }

            /* Loop for all vlans in one MST instance table */
            for (j=0; j<mstp_row->n_vlans; j++) {
                vtysh_ovsdb_cli_print(p_msg, "spanning-tree instance %ld vlan %ld",
                    bridge_row->key_mstp_instances[i], mstp_row->vlans[j]->id );
            }

            if (mstp_row->priority &&
                    (*mstp_row->priority != DEF_BRIDGE_PRIORITY)) {
                vtysh_ovsdb_cli_print(p_msg,
                        "spanning-tree instance %ld priority %ld",
                        bridge_row->key_mstp_instances[i],
                        *mstp_row->priority);
            }
        }
    }

    /* CIST configs */
    cist_row = ovsrec_mstp_common_instance_first (p_msg->idl);
    if (cist_row) {
        if (cist_row->priority &&
                *cist_row->priority != DEF_BRIDGE_PRIORITY) {
            vtysh_ovsdb_cli_print(p_msg, "spanning-tree priority %ld",
                                         *cist_row->priority);
        }
        if (cist_row->hello_time &&
                *cist_row->hello_time != DEF_HELLO_TIME) {
            vtysh_ovsdb_cli_print(p_msg, "spanning-tree hello-time %ld",
                                         *cist_row->hello_time);
        }
        if (cist_row->forward_delay &&
                *cist_row->forward_delay != DEF_FORWARD_DELAY) {
            vtysh_ovsdb_cli_print(p_msg, "spanning-tree forward-delay %ld",
                                         *cist_row->forward_delay);
        }
        if (cist_row->max_age && *cist_row->max_age != DEF_MAX_AGE) {
            vtysh_ovsdb_cli_print(p_msg, "spanning-tree max-age %ld",
                                         *cist_row->max_age);
        }
        if (cist_row->max_hop_count &&
                *cist_row->max_hop_count != DEF_MAX_HOPS) {
            vtysh_ovsdb_cli_print(p_msg, "spanning-tree max-hops %ld",
                                         *cist_row->max_hop_count);
        }
        if (cist_row->tx_hold_count &&
                *cist_row->tx_hold_count != DEF_HOLD_COUNT) {
            vtysh_ovsdb_cli_print(p_msg, "spanning-tree transmit-hold-count %ld",
                                         *cist_row->tx_hold_count);
        }
    }
    return e_vtysh_ok;
}
/*-----------------------------------------------------------------------------
 | Function:        vtysh_ovsdb_parse_mstp_intf_config
 | Responsibility:  Client callback routine for show running-config
 |                  displays the commands configured on interface
 | Parameters:
 |      p_private:  void type object typecast to required
 | Return:
 |      e_vtysh_ok on success else e_vtysh_error
 ------------------------------------------------------------------------------
 */
static int
vtysh_ovsdb_parse_mstp_intf_config(vtysh_ovsdb_cbmsg_ptr p_msg) {
    const struct ovsrec_mstp_common_instance_port *cist_port = NULL;
    const struct ovsrec_interface *ifrow = NULL;
    const struct ovsrec_mstp_instance *mstp_row = NULL;
    const struct ovsrec_mstp_instance_port *mstp_port_row = NULL;
    const struct ovsrec_bridge *bridge_row = NULL;
    int i = 0, j = 0;

    ifrow = (struct ovsrec_interface *)p_msg->feature_row;

    OVSREC_MSTP_COMMON_INSTANCE_PORT_FOR_EACH(cist_port, p_msg->idl) {
        if(!cist_port->port) {
            continue;
        }
        if (VTYSH_STR_EQ(cist_port->port->name, ifrow->name)) {
            if (cist_port->loop_guard_disable &&
                    *cist_port->loop_guard_disable != DEF_BPDU_STATUS) {
                vtysh_ovsdb_cli_print(p_msg, "%4s%s", "",
                            "spanning-tree loop-guard enable");
            }
            if (cist_port->root_guard_disable &&
                    *cist_port->root_guard_disable != DEF_BPDU_STATUS) {
                vtysh_ovsdb_cli_print(p_msg, "%4s%s", "",
                             "spanning-tree root-guard enable");
            }
            if (cist_port->bpdu_guard_disable &&
                    *cist_port->bpdu_guard_disable != DEF_BPDU_STATUS) {
                vtysh_ovsdb_cli_print(p_msg, "%4s%s", "",
                             "spanning-tree bpdu-guard enable");
            }
            if (cist_port->bpdu_filter_disable &&
                    *cist_port->bpdu_filter_disable != DEF_BPDU_STATUS) {
                vtysh_ovsdb_cli_print(p_msg, "%4s%s", "",
                             "spanning-tree bpdu-filter enable");
            }
            if (cist_port->admin_edge_port_disable &&
                  *cist_port->admin_edge_port_disable != DEF_ADMIN_EDGE) {
                vtysh_ovsdb_cli_print(p_msg, "%4s%s", "",
                          "spanning-tree port-type admin-edge");
            }
            if (cist_port->port_priority &&
                    *cist_port->port_priority != DEF_MSTP_PORT_PRIORITY) {
                vtysh_ovsdb_cli_print(p_msg, "%4s%s %ld", "",
                        "spanning-tree port-priority", *cist_port->port_priority);
            }
            if (cist_port->admin_path_cost &&
                    *cist_port->admin_path_cost != DEF_MSTP_COST) {
                vtysh_ovsdb_cli_print(p_msg, "%4s%s %ld", "",
                        "spanning-tree cost", *cist_port->admin_path_cost);
            }
        }
    }

    bridge_row = ovsrec_bridge_first(p_msg->idl);
    if (bridge_row) {
        return e_vtysh_ok;
    }

    /* Loop for all instance in bridge table */
    for (i=0; i < bridge_row->n_mstp_instances; i++) {
        mstp_row = bridge_row->value_mstp_instances[i];

        /* Loop for all ports in the MSTP instance table */
        for (j=0; j<mstp_row->n_mstp_instance_ports; j++) {
            mstp_port_row = mstp_row->mstp_instance_ports[j];
            if (VTYSH_STR_EQ(mstp_port_row->port->name, ifrow->name)) {
                if (mstp_port_row->port_priority &&
                   (*mstp_port_row->port_priority != DEF_MSTP_PORT_PRIORITY)) {
                    vtysh_ovsdb_cli_print(p_msg, "%4s%s %ld %s %ld", "",
                            "spanning-tree instance",
                            bridge_row->key_mstp_instances[i],
                            "port-priority",
                            *mstp_port_row->port_priority);
                }
                if (mstp_port_row->admin_path_cost &&
                        (*mstp_port_row->admin_path_cost != DEF_MSTP_COST)) {
                    vtysh_ovsdb_cli_print(p_msg, "%4s%s%ld %s %ld", "",
                            "spanning-tree instance",
                            bridge_row->key_mstp_instances[i],
                            "cost",
                            *mstp_port_row->admin_path_cost);
                }
            }
        }
    }
    return e_vtysh_ok;
}

/*-----------------------------------------------------------------------------
 | Function:        vtysh_config_context_mstp_clientcallback
 | Responsibility:  Registers the client callback routines for config_context
 | Parameters:
 | Return:
 ------------------------------------------------------------------------------
 */
vtysh_ret_val vtysh_config_context_mstp_clientcallback(void *p_private) {
    vtysh_ovsdb_cbmsg_ptr p_msg = (vtysh_ovsdb_cbmsg *)p_private;

    vtysh_ovsdb_parse_mstp_global_config(p_msg);
    return e_vtysh_ok;
}

/*-----------------------------------------------------------------------------
 | Function:        vtysh_config_context_mstp_clientcallback
 | Responsibility:  Registers the client callback routines for interface_context
 | Parameters:
 | Return:
 ------------------------------------------------------------------------------
 */
vtysh_ret_val vtysh_intf_context_mstp_clientcallback(void *p_private) {
    vtysh_ovsdb_cbmsg_ptr p_msg = (vtysh_ovsdb_cbmsg *)p_private;

    vtysh_ovsdb_parse_mstp_intf_config(p_msg);
    return e_vtysh_ok;
}
