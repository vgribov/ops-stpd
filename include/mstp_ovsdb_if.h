/*
 * (c) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
#ifndef __MSTP_OVSDB_IF__H__
#define __MSTP_OVSDB_IF__H__

#include <dynamic-string.h>
#include <vswitch-idl.h>
#include "mstp_fsm.h"


extern bool exiting;
#define FULL_DUPLEX 1
#define HALF_DUPLEX 2

/**************************************************************************//**
 * mstpd daemon's main OVS interface function.
 *
 * @param arg pointer to ovs-appctl server struct.
 *
 *****************************************************************************/

/*************************************************************************//**
 * @ingroup mstpd_ovsdb_if
 * @brief mstpd's internal data strucuture to store per interface data.
 * ****************************************************************************/
struct iface_data {
    char                *name;              /*!< Name of the interface */
    char                *mac_in_use;        /*!< Mac in use for the interface */
    unsigned int        link_speed;         /*!< Operarational link speed of the interface */
    struct port_data    *port_datap;        /*!< Pointer to associated port's port_data */
    int                 lport_id;           /*!< Allocated index for interface */

    /* MSTPDU send/receive related. */
    int                 pdu_sockfd;         /*!< Socket FD for MSTPDU rx/tx */
    bool                pdu_registered;     /*!< Indicates if port is registered to receive MSTPDU */
    enum ovsrec_interface_link_state_e link_state; /*!< operational link state */
    enum ovsrec_interface_duplex_e duplex;  /*!< operational link duplex */

};

struct mstp_cist_data {
    VID_MAP *vlan_data;
    uint32_t priority;
    MSTP_BRIDGE_IDENTIFIER_t bridge_id;
    uint32_t hello_time;
    uint32_t forward_delay;
    uint32_t max_age;
    uint32_t max_hop_count;
    uint32_t tx_hold_count;
    PORT_MAP *port_data;
};

struct mstp_cist_port_data {
    uint32_t port;
    uint32_t port_priority;
    uint32_t admin_path_cost;
    bool admin_edge_port;
    bool bpdus_rx_enable;
    bool bpdus_tx_enable;
    bool restricted_port_role_disable;
    bool restricted_port_tcn_disable;
    bool bpdu_guard;
    bool loop_guard;
    bool root_guard;
    bool bpdu_filter;
};

struct vlan_data {
    uint32_t vlan_id;
    char *name;
};

struct mstp_instance_data {
    uint32_t mstid;
    char *name;
};

/******************************************************************************
 * Datastructures which has to act as interface between OVSDB and MSTP
 * protocol thread.
 * ***************************************************************************/

typedef struct mstp_global_config {
    bool admin_status;
    char config_name[MSTP_MAX_CONFIG_NAME_LEN];
    uint32_t config_revision;
    char config_digest[100];
} mstp_global_config;

typedef struct mstp_msti_config {
    uint16_t mstid;
    uint16_t n_vlans;
    VID_MAP vlans;
    uint32_t priority;
} mstp_msti_config;

typedef struct mstp_msti_port_config {
    uint16_t port;
    uint16_t mstid;
    uint32_t priority;
    uint32_t path_cost;
} mstp_msti_port_config;

typedef struct mstp_msti_stat_info {
    uint16_t mstid;
    uint16_t hardware_grp_id;
    MAC_ADDRESS designated_root;
    uint32_t root_path_cost;
    uint32_t root_priority;
    uint16_t root_port;
    uint32_t time_since_top_change;
    uint16_t top_change_cnt;
    bool topology_change_disable;
} mstp_msti_stat_info;

typedef struct mstp_cist_config {
    VID_MAP vlans;
    uint32_t priority;
    MSTP_BRIDGE_IDENTIFIER_t bridge_id;
    uint16_t hello_time;
    uint16_t forward_delay;
    uint16_t max_age;
    uint16_t max_hop_count;
    uint16_t tx_hold_count;
} mstp_cist_config;

typedef struct mstp_cist_stat_info {
    uint16_t hardware_grp_id;
    MAC_ADDRESS designated_root;
    uint32_t root_path_cost;
    uint32_t root_priority;
    uint16_t root_port;
    MAC_ADDRESS regional_root;
    uint16_t cist_path_cost;
    uint16_t remaining_hops;
    uint32_t oper_hello_time;
    uint32_t oper_forward_delay;
    uint32_t oper_max_age;
    uint32_t hello_expiry_time;
    uint32_t forward_delay_expiry_time;
    uint32_t time_since_top_change;
    uint32_t oper_tx_hold_count;
    uint16_t top_change_cnt;
} mstp_cist_stat_info;

typedef struct mstp_cist_port_config {
    uint16_t port;
    uint16_t port_priority;
    uint32_t admin_path_cost;
    bool admin_edge_port_disable;
    bool bpdus_rx_enable;
    bool bpdus_tx_enable;
    bool restricted_port_role_disable;
    bool restricted_port_tcn_disable;
    bool bpdu_guard_disable;
    bool loop_guard_disable;
    bool root_guard_disable;
    bool bpdu_filter_disable;
} mstp_cist_port_config;

typedef struct mstp_cist_port_stat_info {
    uint16_t port;
    uint16_t port_role;
    uint16_t port_state;
    MAC_ADDRESS designated_root;
    uint16_t link_type;
    bool oper_edge_port;
    MAC_ADDRESS cist_regional_root_id;
    uint16_t cist_path_cost;
    uint16_t port_path_cost;
    uint16_t designated_path_cost;
    MAC_ADDRESS designated_bridge;
    uint16_t designated_port;
    uint32_t port_hello_time;
    bool protocol_migration_enable;
} mstp_cist_port_stat_info;

typedef struct mstp_statistics {
    uint32_t mstp_BPDUs_Tx;
    uint32_t mstp_BPDUs_Rx;
} mstp_statistics;

typedef struct mstp_msti_port_stat_info {
    uint16_t mstid;
    uint16_t port;
    uint16_t port_role;
    uint16_t port_state;
    MAC_ADDRESS designated_root;
    uint16_t designated_root_priority;
    uint16_t designated_cost;
    MAC_ADDRESS designated_bridge;
    uint16_t designated_bridge_priority;
    uint16_t designated_port;
} mstp_msti_port_stat_info;


extern void *mstpd_ovs_main_thread(void *arg);
// Utility functions
extern struct iface_data *find_iface_data_by_index(int index);
extern const char * intf_get_mac_addr(uint16_t lport);
extern const char* system_get_mac_addr(void);
extern void update_mstp_tx_counters();
extern int mstp_cist_config_update();
extern int mstp_cist_port_config_update();
extern int mstp_msti_update_config();
extern int mstp_msti_port_update_config();
extern int mstp_global_config_update();
extern void clear_mstp_global_config();
extern void clear_mstp_cist_config();
extern void clear_mstp_cist_port_config();
extern void clear_mstp_msti_config();
extern void clear_mstp_msti_port_config();
extern void mstp_config_reinit();
extern void mstp_util_set_cist_port_table_bool (const char *if_name, const char *key,const bool value);
extern void mstp_util_set_cist_table_value (const char *key, int64_t value);
extern void mstp_util_set_cist_table_string (const char *key, const char *string);
extern void mstp_util_set_cist_port_table_value (const char *if_name, const char *key, int64_t value);
extern void mstp_util_set_cist_port_table_string (const char *if_name, const char *key, char *string);
extern void mstp_util_set_msti_table_string (const char *key, const char *string, int mstid);
extern void mstp_util_set_msti_table_value (const char *key, int64_t value, int mstid);
extern void mstp_util_set_msti_port_table_value (const char *key, int64_t value, int mstid, int lport);
extern void mstp_util_set_msti_port_table_string (const char *key, char *string, int mstid, int lport);
extern void handle_vlan_add_in_mstp_config(int vlan);
extern void handle_vlan_delete_in_mstp_config(int vlan);
extern void update_port_entry_in_cist_mstp_instances(char *name, int operation);
extern void update_port_entry_in_msti_mstp_instances(char *name, int operation);
extern void update_mstp_on_lport_add(int lport);
extern bool is_lport_down(int lport);
extern bool is_lport_up(int lport);
extern void disable_logical_port(int lport);
extern void enable_logical_port(int lport);
extern void enable_or_disable_port(int lport,bool enable);
#endif /* __MSTP_OVSDB_IF__H__ */
