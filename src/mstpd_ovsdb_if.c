/*
 * (c) Copyright 2016 Hewlett Packard Enterprise Development LP
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
/************************************************************************//**
 * @ingroup stpd
 *
 * @file
 * Source for stpd OVSDB access interface.
 *
 ***************************************************************************/

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include <config.h>
#include <command-line.h>
#include <compiler.h>
#include <daemon.h>
#include <dirs.h>
#include <dynamic-string.h>
#include <fatal-signal.h>
#include <ovsdb-idl.h>
#include <poll-loop.h>
#include <unixctl.h>
#include <util.h>
#include <openvswitch/vconn.h>
#include <openvswitch/vlog.h>
#include <vswitch-idl.h>
#include <openswitch-idl.h>
#include <hash.h>
#include <shash.h>
#include <net/if.h>
#include <assert.h>

#include "mstp_ovsdb_if.h"
#include "mstp_cmn.h"
#include "mqueue.h"
#include "mstp_inlines.h"
#include "mstp_fsm.h"


VLOG_DEFINE_THIS_MODULE(mstpd_ovsdb_if);

/* To serialize updates to OVSDB.  Both MSTP and OVS
 * interface threads calls to update OVSDB states. */
pthread_mutex_t ovsdb_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Scale OVS interface speed number (bps) down to
 *  * that used by MSTP state machine (Mbps). */
#define MEGA_BITS_PER_SEC  1000000
#define INTF_TO_MSTP_LINK_SPEED(s)    ((s)/MEGA_BITS_PER_SEC)

struct ovsdb_idl *idl;           /*!< Session handle for OVSDB IDL session. */
static unsigned int idl_seqno;
static int system_configured = false;
extern bool exiting;
char admin_status[10];
struct mstp_cist_data *cist_data;
VID_MAP cist_vlan_list;
static int n_cist_vlans = 0;
bool cist_added = false;
void util_add_default_ports_to_cist();
void util_mstp_set_defaults();
void util_mstp_init_config();

struct mstp_global_config mstp_global_conf;
struct mstp_cist_config mstp_cist_conf;


PORT_MAP l2ports;
uint16_t n_l2ports = 1; /*bridge_normal will be set by default*/

MSTI_MAP mstp_instance_map;
uint16_t n_msti = 0;

/**
 * A hash map of daemon's internal data for all the interfaces maintained by
 * mstpd.
 */
static struct shash all_interfaces = SHASH_INITIALIZER(&all_interfaces);

/**
 * A hash map of daemon's internal data for all the ports maintained by mstpd.
 **/
static struct shash all_ports = SHASH_INITIALIZER(&all_ports);


/* Mapping of all the VLANs. */
static struct shash all_vlans = SHASH_INITIALIZER(&all_vlans);

/* Mapping of all the MSTP Instances. */
static struct shash all_mstp_instances = SHASH_INITIALIZER(&all_mstp_instances);

/*************************************************************************//**
 * @ingroup mstpd_ovsdb_if
 *  * @brief mstpd's internal data structure to store per port data.
 *   ****************************************************************************/
struct port_data {
    char                *name;              /*!< Name of the port */
    char                *vlan_mode;            /*!< Vlan mode information */
};


/*********************************
 *
 * Pool definitions
 *
 *********************************/
#define BITS_PER_BYTE           8

#define IS_AVAILABLE(a, idx)  ((a[idx/BITS_PER_BYTE] & (1 << (idx % BITS_PER_BYTE))) == 0)

#define CLEAR(a, idx)   a[idx/BITS_PER_BYTE] &= ~(1 << (idx % BITS_PER_BYTE))
#define SET(a, idx)     a[idx/BITS_PER_BYTE] |= (1 << (idx % BITS_PER_BYTE))

#define POOL(name, size)     unsigned char name[size/BITS_PER_BYTE+1]

int allocate_next(unsigned char *pool, int size);
void allocate_reserved_id(unsigned char *pool);
static void free_index(unsigned char *pool, int idx);

POOL(port_index, MAX_ENTRIES_IN_POOL);

struct iface_data *idp_lookup[MAX_ENTRIES_IN_POOL+1];
struct mstp_cist_port_config *cist_port_lookup[MAX_ENTRIES_IN_POOL+1];
struct mstp_msti_config *msti_lookup[MSTP_INSTANCES_MAX+1];
struct mstp_msti_port_config *msti_port_lookup[MSTP_INSTANCES_MAX+1][MAX_ENTRIES_IN_POOL+1];

/**********************************************************************
 * Pool implementation: this is diferrent from the LAG pool manager.
 * This is currently only used for allocating interface indexes.
 **********************************************************************/
int
allocate_next(unsigned char *pool, int size)
{
    int idx = 0;

    while (pool[idx] == 0xff && (idx * BITS_PER_BYTE) < size) {
        idx++;
    }

    if ((idx * BITS_PER_BYTE) < size) {
        idx *= BITS_PER_BYTE;

        while (idx < size && !IS_AVAILABLE(pool, idx)) {
            idx++;
        }

        if (idx < size && IS_AVAILABLE(pool, idx)) {
            SET(pool, idx);
            return idx;
        }
    }

    return -1;
} /* allocate_next */

/**PROC+**********************************************************************
 * Name:     allocate_reserved_id
 *
 * Purpose:   to allocate id for interfaces
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/

void
allocate_reserved_id(unsigned char *pool)
{
    int idx = 0;
    if (IS_AVAILABLE(pool, idx)) {
            SET(pool, idx);
    }

} /* allocate_next */

/**PROC+**********************************************************************
 * Name:     free_index
 *
 * Purpose:   to free id for interfaces
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/


static void
free_index(unsigned char *pool, int idx)
{
    CLEAR(pool, idx);
} /* free_index */

/**PROC+**********************************************************************
 * Name:     alloc_msg
 *
 * Purpose:   to allocate memory for message
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/


static void *
alloc_msg(int size)
{
    void *msg;

    msg = xzalloc(size);

    if (msg == NULL) {
        VLOG_ERR("%s: malloc failed.",__FUNCTION__);
    }

    return msg;
} /* alloc_msg */
/**PROC+**********************************************************************
 * Name:     find_iface_data_by_index
 *
 * Purpose:   To find Interface data based on index
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/


struct iface_data *
find_iface_data_by_index(int index)
{
    struct iface_data *idp;
    if (idp_lookup[index] != NULL)
    {
        idp = idp_lookup[index];
        return idp;
    }
    return NULL;
} /* find_iface_data_by_index */
/**PROC+**********************************************************************
 * Name:     find_iface_data_by_name
 *
 * Purpose:   To find Interface data based on name
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/


struct iface_data *
find_iface_data_by_name(char *name)
{
    struct iface_data *idp;
    struct shash_node *sh_node;
    SHASH_FOR_EACH(sh_node, &all_interfaces) {
        idp = sh_node->data;
        if (idp) {
            if ( strcmp(idp->name,name) == 0 ) {
                return idp;
            }
        }
    }
    return NULL;
}


/* Create a connection to the OVSDB at db_path and create a dB cache
 * for this daemon. */
void
mstpd_ovsdb_init(const char *db_path)
{
    /* Initialize IDL through a new connection to the dB. */
    idl = ovsdb_idl_create(db_path, &ovsrec_idl_class, false, true);
    idl_seqno = ovsdb_idl_get_seqno(idl);
    ovsdb_idl_set_lock(idl, "ops_stpd");

    /* Choose some OVSDB tables and columns to cache. */
    ovsdb_idl_add_table(idl, &ovsrec_table_system);
    ovsdb_idl_add_table(idl, &ovsrec_table_subsystem);

    /* Monitor the following columns, marking them read-only. */
    ovsdb_idl_add_column(idl, &ovsrec_system_col_cur_cfg);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_other_config);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_system_mac);
    ovsdb_idl_add_column(idl, &ovsrec_subsystem_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_subsystem_col_other_info);

    ovsdb_idl_add_table(idl, &ovsrec_table_vlan);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_id);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_name);


    /* Mark the following columns write-only. */
    ovsdb_idl_add_table(idl, &ovsrec_table_interface);
    ovsdb_idl_add_column(idl, &ovsrec_interface_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_interface_col_type);
    ovsdb_idl_add_column(idl, &ovsrec_interface_col_duplex);
    ovsdb_idl_add_column(idl, &ovsrec_interface_col_link_state);
    ovsdb_idl_add_column(idl, &ovsrec_interface_col_link_speed);
    ovsdb_idl_add_column(idl, &ovsrec_interface_col_hw_intf_info);
    ovsdb_idl_add_column(idl, &ovsrec_interface_col_other_config);
    ovsdb_idl_add_column(idl, &ovsrec_interface_col_admin_state);
    ovsdb_idl_add_column(idl, &ovsrec_interface_col_user_config);
    //TBD
    ovsdb_idl_add_table(idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(idl, &ovsrec_bridge_col_other_config);
    ovsdb_idl_add_column(idl, &ovsrec_bridge_col_ports);
    ovsdb_idl_add_column(idl, &ovsrec_bridge_col_status);

    ovsdb_idl_add_table(idl, &ovsrec_table_port);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_tag);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_vlan_mode);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_admin);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_hw_config);

    ovsdb_idl_add_column(idl, &ovsrec_bridge_col_mstp_instances);
    ovsdb_idl_add_column(idl, &ovsrec_bridge_col_mstp_common_instance);
    ovsdb_idl_add_column(idl, &ovsrec_bridge_col_mstp_enable);

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
    ovsdb_idl_add_column(idl, &ovsrec_mstp_common_instance_col_tx_hold_count);
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
} /* mstpd_ovsdb_init */

/**PROC+****************************************************************
 * Name:      mstpd_ovsdb_exit
 *
 * Purpose:  Destroy IDL
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/


void
mstpd_ovsdb_exit(void)
{
    ovsdb_idl_destroy(idl);
} /* mstpd_ovsdb_exit */

/**PROC+****************************************************************
 * Name:      mstpd_chk_for_system_configured
 *
 * Purpose:  Check if System is configured.
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/


static inline void
mstpd_chk_for_system_configured(void)
{
    const struct ovsrec_system *sys = NULL;

    if (system_configured) {
        /* Nothing to do if we're already configured. */
        return;
    }

    sys = ovsrec_system_first(idl);
    if (sys && sys->cur_cfg > (int64_t)0) {
        /* Setting zeroth bit of the pool, since we don't want portindex as 0 */
        allocate_reserved_id(port_index);
        system_configured = true;
    }

} /* mstpd_chk_for_system_configured */
/**PROC+****************************************************************
 * Name:    send_mstp_global_config_update
 *
 * Purpose:  Send MSTP update to daemon.
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/


static void send_mstp_global_config_update(struct mstp_global_config *global_config)
{
    int msgSize = 0;
    mstpd_message *msg;
    struct mstp_global_config *event = NULL;
    if (global_config == NULL)
    {
        return;
    }
    msgSize = sizeof(mstp_global_config)+sizeof(mstpd_message);
    msg = (mstpd_message *)alloc_msg(msgSize);
    if (NULL == msg){
        VLOG_ERR("Out of memory for MSTP timer message.");
        return;
    }
    if (msg != NULL) {
        msg->msg_type = e_mstpd_global_config;
        event = (mstp_global_config *)(msg+1);
        memcpy(event,global_config,sizeof(mstp_global_config));
        mstpd_send_event(msg);
    }
}
/**PROC+****************************************************************
 * Name:    send_mstp_cist_config_update
 *
 * Purpose:  Send MSTP update to daemon.
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

static void send_mstp_cist_config_update(struct mstp_cist_config *cist_config)
{
    int msgSize = 0;
    mstpd_message *msg;
    struct mstp_cist_config *event = NULL;
    if (cist_config == NULL)
    {
        return;
    }
    msgSize = sizeof(mstp_cist_config)+sizeof(mstpd_message);
    msg = (mstpd_message *)alloc_msg(msgSize);
    if (NULL == msg){
        VLOG_ERR("Out of memory for MSTP timer message.");
        return;
    }
    if (msg != NULL) {
        msg->msg_type = e_mstpd_cist_config;
        event = (mstp_cist_config *)(msg+1);
        memcpy(event,cist_config,sizeof(mstp_cist_config));
        mstpd_send_event(msg);
    }
}
/**PROC+****************************************************************
 * Name:    send_mstp_cist_port_config_update
 *
 * Purpose:  Send MSTP update to daemon.
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

static void send_mstp_cist_port_config_update(struct mstp_cist_port_config *cist_port_config)
{
    int msgSize = 0;
    mstpd_message *msg;
    struct mstp_cist_port_config *event = NULL;
    if (cist_port_config == NULL)
    {
        return;
    }
    msgSize = sizeof(mstp_cist_port_config)+sizeof(mstpd_message);
    msg = (mstpd_message *)alloc_msg(msgSize);
    if (NULL == msg){
        VLOG_ERR("Out of memory for MSTP timer message.");
        return;
    }
    if (msg != NULL) {
        msg->msg_type = e_mstpd_cist_port_config;
        event = (mstp_cist_port_config *)(msg+1);
        memcpy(event,cist_port_config,sizeof(mstp_cist_port_config));
        mstpd_send_event(msg);
    }
}
/**PROC+****************************************************************
 * Name:    send_mstp_msti_config_update
 *
 * Purpose:  Send MSTP update to daemon.
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

static void send_mstp_msti_config_update(struct mstp_msti_config *msti_config)
{
    int msgSize = 0;
    mstpd_message *msg;
    struct mstp_msti_config *event = NULL;
    if (msti_config == NULL)
    {
        return;
    }
    msgSize = sizeof(mstp_msti_config)+sizeof(mstpd_message);
    msg = (mstpd_message *)alloc_msg(msgSize);
    if (NULL == msg){
        VLOG_ERR("Out of memory for MSTP timer message.");
        return;
    }
    if (msg != NULL) {
        msg->msg_type = e_mstpd_msti_config;
        event = (mstp_msti_config *)(msg+1);
        memcpy(event,msti_config,sizeof(mstp_msti_config));
        mstpd_send_event(msg);
    }
}
/**PROC+****************************************************************
 * Name:    send_mstp_msti_port_config_update
 *
 * Purpose:  Send MSTP update to daemon.
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

static void send_mstp_msti_port_config_update(struct mstp_msti_port_config *msti_port_config)
{
    int msgSize = 0;
    mstpd_message *msg;
    struct mstp_msti_port_config *event = NULL;
    if (msti_port_config == NULL)
    {
        return;
    }
    msgSize = sizeof(mstp_msti_port_config)+sizeof(mstpd_message);
    msg = (mstpd_message *)alloc_msg(msgSize);
    if (NULL == msg){
        VLOG_ERR("Out of memory for MSTP timer message.");
        return;
    }
    if (msg != NULL) {
        msg->msg_type = e_mstpd_msti_port_config;
        event = (mstp_msti_port_config *)(msg+1);
        memcpy(event,msti_port_config,sizeof(mstp_msti_port_config));
        mstpd_send_event(msg);
    }
}
/**PROC+****************************************************************
 * Name:    send_mstp_msti_config_delete
 *
 * Purpose:  Send MSTP update to daemon.
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

static void send_mstp_msti_config_delete(struct mstp_msti_config_delete *msti_config_delete)
{
    int msgSize = 0;
    mstpd_message *msg;
    struct mstp_msti_config_delete *event = NULL;
    if (msti_config_delete == NULL)
    {
        return;
    }
    msgSize = sizeof(mstp_msti_config_delete)+sizeof(mstpd_message);
    msg = (mstpd_message *)alloc_msg(msgSize);
    if (NULL == msg){
        VLOG_ERR("Out of memory for MSTP timer message.");
        return;
    }
    if (msg != NULL) {
        msg->msg_type = e_mstpd_msti_config_delete;
        event = (mstp_msti_config_delete *)(msg+1);
        memcpy(event,msti_config_delete,sizeof(mstp_msti_config_delete));
        mstpd_send_event(msg);
    }
}

/**PROC+****************************************************************
 * Name:    send_interface_add_msg
 *
 * Purpose:  Send Interface update to daemon.
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

void
send_interface_add_msg(struct iface_data *info_ptr)
{
    int msgSize = 0;
    mstpd_message *msg;
    mstp_lport_add *event;
    msgSize = sizeof(mstp_lport_add)+sizeof(mstpd_message);
    msg = (mstpd_message *)alloc_msg(msgSize);
    if (NULL == msg) {
        VLOG_ERR("Out of memory for MSTP timer message.");
        return;
    }

    if (msg != NULL) {
	    msg->msg_type = e_mstpd_lport_add;
        event = ( mstp_lport_add *)(msg+1);
        event->lportname = info_ptr->name;
        mstpd_send_event(msg);
    }
} /* send_interface_add_msg */
/**PROC+****************************************************************
 * Name:    send_vlan_add_msg
 *
 * Purpose:  Send VLAN update to daemon.
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

static void
send_vlan_add_msg(uint32_t vid)
{
    VLOG_DBG("VLAN add send event : %d", vid);
    int msgSize = 0;
    mstpd_message *msg;
    mstp_vlan_add *event;
    msgSize = sizeof(mstp_vlan_add)+sizeof(mstpd_message);
    msg = (mstpd_message *)alloc_msg(msgSize);
    if(NULL == msg) {
        VLOG_ERR("Out of memory for MSTP VLAN Add Message");
        return;
    }
    if(msg != NULL) {
        msg->msg_type = e_mstpd_vlan_add;
        event = (mstp_vlan_add *)(msg+1);
        event->vid = vid;
        mstpd_send_event(msg);
    }
}

/**PROC+****************************************************************
 * Name:    send_vlan_delete_msg
 *
 * Purpose:  Send VLAN update to daemon.
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

static void
send_vlan_delete_msg(uint32_t vid)
{
    VLOG_DBG("VLAN delete send event : %d", vid);
    int msgSize = 0;
    mstpd_message *msg;
    mstp_vlan_delete *event;
    msgSize = sizeof(mstp_vlan_delete)+sizeof(mstpd_message);
    msg = (mstpd_message *)alloc_msg(msgSize);
    if(NULL == msg) {
        VLOG_ERR("Out of memory for MSTP VLAN Delete Message");
        return;
    }
    if(msg != NULL) {
        msg->msg_type = e_mstpd_vlan_delete;
        event = (mstp_vlan_delete *)(msg+1);
        event->vid = vid;
        mstpd_send_event(msg);
    }
}
/**PROC+****************************************************************
 * Name:    send_l2port_add_msg
 *
 * Purpose:  Send L2port update to daemon.
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

static void
send_l2port_add_msg(uint32_t lport)
{
    VLOG_DBG("L2port add send event : %d", lport);
    int msgSize = 0;
    mstpd_message *msg;
    mstp_lport_add *event;
    msgSize = sizeof(mstp_lport_add)+sizeof(mstpd_message);
    msg = (mstpd_message *)alloc_msg(msgSize);
    if(NULL == msg) {
        VLOG_ERR("Out of memory for MSTP L2port Add Message");
        return;
    }
    if(msg != NULL) {
        msg->msg_type = e_mstpd_lport_add;
        event = (mstp_lport_add *)(msg+1);
        event->lportindex = lport;
        mstpd_send_event(msg);
    }
}
/**PROC+****************************************************************
 * Name:    send_l2port_delete_msg
 *
 * Purpose:  Send L2port update to daemon.
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

static void
send_l2port_delete_msg(uint32_t lport)
{
    VLOG_DBG("L2port delete send event : %d", lport);
    int msgSize = 0;
    mstpd_message *msg;
    mstp_lport_delete *event;
    msgSize = sizeof(mstp_lport_delete)+sizeof(mstpd_message);
    msg = (mstpd_message *)alloc_msg(msgSize);
    if(NULL == msg) {
        VLOG_ERR("Out of memory for MSTP L2port Add Message");
        return;
    }
    if(msg != NULL) {
        msg->msg_type = e_mstpd_lport_delete;
        event = (mstp_lport_delete *)(msg+1);
        event->lportindex = lport;
        mstpd_send_event(msg);
    }
}

/**PROC+****************************************************************
 * Name:    send_admin_status_change_msg
 *
 * Purpose:  Send Admin status update to daemon.
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

static void
send_admin_status_change_msg(bool status)
{
    VLOG_DBG("MSTP_DBG Admin status Change");
    int msgSize = 0;
    mstpd_message *msg;
    mstp_admin_status *event;
    msgSize = sizeof(mstp_admin_status)+sizeof(mstpd_message);
    msg = (mstpd_message *)alloc_msg(msgSize);
    if (NULL == msg) {
        VLOG_ERR("Out of memory for MSTP timer message.");
        return;
    }

    if (msg != NULL) {
        msg->msg_type = e_mstpd_admin_status;
        event = ( mstp_admin_status *)(msg+1);
        event->status = status;
        mstpd_send_event(msg);
    }
} /* send_admin_status_change_msg */

/**PROC+****************************************************************
 * Name:    del_old_interface
 *
 * Purpose:  Delete Interface from local cache
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

static void
del_old_interface(struct shash_node *sh_node)
{
    if (sh_node) {
        struct iface_data *idp = sh_node->data;
        free(idp->name);
        free_index(port_index, idp->lport_id);
        idp_lookup[idp->lport_id] = NULL;
        free(idp);
        shash_delete(&all_interfaces, sh_node);
    }
} /* del_old_interface */

/**
 * Adds a new interface to daemon's internal data structures.
 *
 * Allocates a new iface_data entry. Parses the ifrow and
 * copies data into new iface_data entry.
 * Adds the new iface_data entry into all_interfaces shash map.
 * @param ifrow pointer to interface configuration row in IDL cache.
 */
static void
add_new_interface(const struct ovsrec_interface *ifrow)
{
    struct iface_data *idp = NULL;

    /* Allocate structure to save state information for this interface. */
    idp = xzalloc(sizeof *idp);

    if (!shash_add_once(&all_interfaces, ifrow->name, idp)) {
        VLOG_WARN("Interface %s specified twice", ifrow->name);
        free(idp);
    } else {

        /* Save the interface name. */
        idp->name = xstrdup(ifrow->name);

        /* Allocate interface index. */
        idp->lport_id = allocate_next(port_index, MAX_ENTRIES_IN_POOL);
        if (idp->lport_id <= 0) {
            VLOG_ERR("Invalid interface index=%d", idp->lport_id);
        }
        else {
            VLOG_DBG("New Interface LPORT INDEX : %d",idp->lport_id);
        }

        idp->duplex = HALF_DUPLEX;
        if (ifrow->duplex) {
            if (!strcmp(ifrow->duplex, OVSREC_INTERFACE_DUPLEX_FULL)) {
                idp->duplex = FULL_DUPLEX;
            }
        }
        idp->link_speed = 0;
        if (ifrow->n_link_speed > 0) {
            /* There should only be one speed. */
            idp->link_speed = INTF_TO_MSTP_LINK_SPEED(ifrow->link_speed[0]);
        }

        idp->link_state = INTERFACE_LINK_STATE_DOWN;
        if (ifrow->link_state) {
            if (!strcmp(ifrow->link_state, OVSREC_INTERFACE_LINK_STATE_UP)) {
                idp->link_state = INTERFACE_LINK_STATE_UP;
            }
        }
        idp_lookup[idp->lport_id] = idp;
        VLOG_DBG("Created local data for interface %s", ifrow->name);
    }
} /* add_new_interface */

/**PROC+****************************************************************
 * Name:    send_link_state_change_msg
 *
 * Purpose:  Send link state update to daemon
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/


static void
send_link_state_change_msg(struct iface_data *info_ptr)
{
    int msgSize = 0;
    mstpd_message *msg;
    mstp_lport_state_change *event;
    msgSize = sizeof(mstp_lport_state_change)+sizeof(mstpd_message);
    msg = (mstpd_message *)alloc_msg(msgSize);
    if (NULL == msg) {
        VLOG_ERR("Out of memory for MSTP timer message.");
        return;
    }

    if (msg != NULL) {
	    msg->msg_type = ((info_ptr->link_state == INTERFACE_LINK_STATE_UP) ?
                         e_mstpd_lport_up :
                         e_mstpd_lport_down);
        event = ( mstp_lport_state_change *)(msg+1);
        event->lportname = info_ptr->name;
        event->lportindex = info_ptr->lport_id;
        mstpd_send_event(msg);
    }
} /* send_link_state_change_msg */

/**PROC+****************************************************************
 * Name:    update_interface_cache
 *
 * Purpose:  Update local cache for interface
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/
static int
update_interface_cache(void)
{

    VLOG_DBG("Update Interface cache");
    struct shash sh_idl_interfaces;
    const struct ovsrec_interface *ifrow;
    struct shash_node *sh_node, *sh_next;
    int rc = 0;
    /* Collect all the interfaces in the DB. */
    shash_init(&sh_idl_interfaces);
    OVSREC_INTERFACE_FOR_EACH(ifrow, idl) {
        if (!shash_add_once(&sh_idl_interfaces, ifrow->name, ifrow)) {
            VLOG_DBG("interface %s specified twice", ifrow->name);
        }
    }

    /* Delete old interfaces. */
    SHASH_FOR_EACH_SAFE(sh_node, sh_next, &all_interfaces) {
        struct iface_data *idp =
            shash_find_data(&sh_idl_interfaces, sh_node->name);
        if (!idp) {
            VLOG_DBG("Found a deleted interface %s", sh_node->name);
            del_old_interface(sh_node);
        }
    }

    /* Add new interfaces. */
    SHASH_FOR_EACH(sh_node, &sh_idl_interfaces) {
        struct iface_data *idp =
            shash_find_data(&all_interfaces, sh_node->name);
        if (!idp) {
            VLOG_DBG("Found an added interface %s", sh_node->name);
            add_new_interface(sh_node->data);
            rc++;
        }
    }
    /* Check for changes in the interface row entries. */
    SHASH_FOR_EACH(sh_node, &all_interfaces) {
        struct iface_data *idp = sh_node->data;
        const struct ovsrec_interface *ifrow =
            shash_find_data(&sh_idl_interfaces, sh_node->name);

        /* Check for changes to row. */
        if (OVSREC_IDL_IS_ROW_INSERTED(ifrow, idl_seqno) ||
            OVSREC_IDL_IS_ROW_MODIFIED(ifrow, idl_seqno)) {
            enum ovsrec_interface_link_state_e new_link_state;
            new_link_state = INTERFACE_LINK_STATE_DOWN;
            if (ifrow->link_state ) {
                if (!(strcmp(ifrow->link_state, OVSREC_INTERFACE_LINK_STATE_UP))) {
                    new_link_state = INTERFACE_LINK_STATE_UP;
                }
            }

            if ((new_link_state != idp->link_state)) {
                idp->link_state = new_link_state;
                VLOG_DBG("Interface %s link state changed in DB: "
                         " new_link=%s ",
                         ifrow->name,
                         (idp->link_state == INTERFACE_LINK_STATE_UP ? "up" : "down"));
                send_link_state_change_msg(idp);

            }
        }
    }
    /* Destroy the shash of the IDL interfaces. */
    shash_destroy(&sh_idl_interfaces);
    return rc;

}
/**PROC+****************************************************************
 * Name:    update_l2port_cache
 *
 * Purpose:  Update local cache for interface
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/


static int update_l2port_cache(void)
{
    VLOG_DBG("Update L2 Port Cache");
    const struct ovsrec_bridge *bridge_row = NULL;
    struct iface_data *idp = NULL;
    PORT_MAP temp_ports;
    int rc = 0;
    int i = 0;
    bridge_row = ovsrec_bridge_first(idl);
    if(n_l2ports != bridge_row->n_ports)
    {
        clear_port_map(&temp_ports);
        VLOG_DBG("Update L2 Port Cache : NO of ports changed");
        for (i=0; i < bridge_row->n_ports ; i++)
        {
            idp = find_iface_data_by_name(bridge_row->ports[i]->name);
            if (idp != NULL && (strcmp(idp->name,"bridge_normal")!= 0))
            {
                set_port(&temp_ports,idp->lport_id);
            }
        }
        VLOG_DBG("Update L2 Port Cache : new ports set");
        if (!are_portmaps_equal(&l2ports,&temp_ports))
        {
            VLOG_DBG("Update L2 Port Cache : Change in port map");
            PORT_MAP addPortMap;
            PORT_MAP delPortMap;

            /*---------------------------------------------------------------------
             * Find L2 PORTs that are being Deleted.
             *---------------------------------------------------------------------*/
            copy_port_map(&temp_ports, &delPortMap);
            bit_inverse_port_map(&delPortMap);
            bit_and_port_maps(&l2ports, &delPortMap);

            /*---------------------------------------------------------------------
             * Find L2 ports that are being added.
             *---------------------------------------------------------------------*/
            copy_port_map(&l2ports, &addPortMap);
            bit_inverse_port_map(&addPortMap);
            bit_and_port_maps(&temp_ports, &addPortMap);

            if(are_any_ports_set(&delPortMap))
            {
                VLOG_DBG("Update L2 Port Cache : Removal of ports");
                uint16_t lport = 0;
                for(lport = find_first_port_set(&delPortMap);
                        lport <= MAX_LPORTS;
                        lport = find_next_port_set(&delPortMap, lport))
                {
                    int j = 0;
                    free(cist_port_lookup[lport]);
                    cist_port_lookup[lport] = NULL;
                    for(j = 1; j <= MSTP_INSTANCES_MAX; j++)
                    {
                        if (msti_port_lookup[j][lport])
                        {
                            free(msti_port_lookup[j][lport]);
                            msti_port_lookup[j][lport] = NULL;
                        }
                    }
                    send_l2port_delete_msg(lport);
                }
            }
            if(are_any_ports_set(&addPortMap))
            {
                VLOG_DBG("Update L2 Port Cache : Addition of ports");
                uint16_t lport = 0;
                for(lport = find_first_port_set(&addPortMap);
                        lport <= MAX_LPORTS;
                        lport = find_next_port_set(&addPortMap, lport))
                {
                    rc++;
                    send_l2port_add_msg(lport);
                }
            }
            copy_port_map(&temp_ports,&l2ports);
            n_l2ports = bridge_row->n_ports;
        }
    }
    return rc;
}

/**PROC+****************************************************************
 * Name:    add_new_vlan
 *
 * Purpose:  Update local cache for VLAN
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

static void
add_new_vlan(struct shash_node *sh_node)
{
    VLOG_DBG("Add VLAN Cache");
    struct vlan_data *new_vlan = NULL;
    const struct ovsrec_vlan *vlan_row = sh_node->data;

    /* Allocate structure to save state information for this VLAN. */
    new_vlan = xzalloc(sizeof(struct vlan_data));

    if (!shash_add_once(&all_vlans, vlan_row->name, new_vlan)) {
        VLOG_WARN("VLAN %d specified twice", (int)vlan_row->id);
        free(new_vlan);
    } else {
        VLOG_DBG("Add VLAN Cache should send an update");

        new_vlan->vlan_id = vlan_row->id;
        new_vlan->name = xstrdup(vlan_row->name);
        send_vlan_add_msg(new_vlan->vlan_id);

        VLOG_DBG("Created local data for VLAN %d", (int)vlan_row->id);
    }
} /* add_new_vlan */
/**PROC+****************************************************************
 * Name:    del_old__vlan
 *
 * Purpose:  Update local cache for VLAN
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/


static void
del_old_vlan(struct shash_node *sh_node)
{
    if (sh_node) {
        VLOG_DBG("Delete VLAN Cache should send an update");
        struct vlan_data *vl = sh_node->data;
        send_vlan_delete_msg(vl->vlan_id);
        free(vl->name);
        free(vl);
        shash_delete(&all_vlans, sh_node);
    }

} /* del_old_vlan */
/**PROC+****************************************************************
 * Name:    update_vlan_cache
 *
 * Purpose:  Update local cache for VLAN
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/


static int
update_vlan_cache(void)
{
    VLOG_DBG("Update VLAN Cache");
    struct vlan_data *new_vlan;
    struct shash sh_idl_vlans;
    const struct ovsrec_vlan *row;
    struct shash_node *sh_node, *sh_next;
    int rc = 0;

    /* Collect all the VLANs in the DB. */
    shash_init(&sh_idl_vlans);
    OVSREC_VLAN_FOR_EACH(row, idl) {
        if (!shash_add_once(&sh_idl_vlans, row->name, row)) {
            VLOG_DBG("VLAN %s (%d) specified twice", row->name, (int)row->id);
        }
    }

    /* Delete old VLANs. */
    SHASH_FOR_EACH_SAFE(sh_node, sh_next, &all_vlans) {
        new_vlan = shash_find_data(&sh_idl_vlans, sh_node->name);
        if (!new_vlan) {
            VLOG_DBG("Found a deleted VLAN %s", sh_node->name);
            del_old_vlan(sh_node);
        }
    }

    /* Add new VLANs. */
    SHASH_FOR_EACH(sh_node, &sh_idl_vlans) {
        new_vlan = shash_find_data(&all_vlans, sh_node->name);
        if (!new_vlan) {
            VLOG_DBG("Found an added VLAN %s", sh_node->name);
            add_new_vlan(sh_node);
        }
    }

    /* Destroy the shash of the IDL vlans */
    shash_destroy(&sh_idl_vlans);

    return rc;

} /* update_vlan_cache */

/**PROC+***********************************************************
 * Name:    mstpd_reconfigure
 *
 * Purpose:  Reconfigure MSTP
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/


static int
mstpd_reconfigure(void)
{
    int rc = 0;
    unsigned int new_idl_seqno = ovsdb_idl_get_seqno(idl);

    if (new_idl_seqno == idl_seqno) {
        /* There was no change in the DB. */
        return 0;
    }
    VLOG_DBG("MSTP Old IDL : %d, New IDL : %d",idl_seqno,new_idl_seqno);

    /* Update mstpd's Interfaces table cache. */
    if (update_interface_cache()) {
        rc++;
    }
    if (update_l2port_cache()) {
        rc++;
    }

    if (update_vlan_cache()) {
        rc++;
    }
    if (mstp_cist_config_update()) {
        rc++;
    }

    if (mstp_cist_port_config_update()) {
        rc++;
    }

    if (mstp_msti_update_config()) {
        rc++;
    }

    if (mstp_msti_port_update_config()) {
        rc++;
    }

    if (mstp_global_config_update()) {
        rc++;
    }
    /* Update IDL sequence # after we've handled everything. */
    idl_seqno = new_idl_seqno;

    return rc;

} /* mstpd_reconfigure */

/***
 * @ingroup mstpd
 * @{
 */
void
mstpd_run(void)
{
    struct ovsdb_idl_txn *txn;

    MSTP_OVSDB_LOCK;

    /* Process a batch of messages from OVSDB. */
    ovsdb_idl_run(idl);
    if (ovsdb_idl_is_lock_contended(idl)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_ERR_RL(&rl, "Another mstpd process is running, "
                    "disabling this process until it goes away");
        MSTP_OVSDB_UNLOCK;
        return;
    } else if (!ovsdb_idl_has_lock(idl)) {
        MSTP_OVSDB_UNLOCK;
        return;
    }
    /* Update the local configuration and push any changes to the DB. */
    mstpd_chk_for_system_configured();

    if (system_configured) {
        if(!cist_added)
        {
            util_mstp_set_defaults();
            util_add_default_ports_to_cist();
            util_mstp_init_config();
            cist_added = true;
        }

       txn = ovsdb_idl_txn_create(idl);
        if (mstpd_reconfigure()) {
            /* Some OVSDB write needs to happen. */
            ovsdb_idl_txn_commit_block(txn);
        }
        ovsdb_idl_txn_destroy(txn);
    }

    MSTP_OVSDB_UNLOCK;

    return;
} /* mstpd_run */

void
mstpd_wait(void)
{
    ovsdb_idl_wait(idl);
} /* mstpd_wait */

/**********************************************************************/
/*                        OVS Main Thread                             */
/**********************************************************************/
/**
 * Cleanup function at daemon shutdown time.
 */
static void
mstpd_exit(void)
{
    mstpd_ovsdb_exit();
    VLOG_DBG("mstpd OVSDB thread exiting...");
} /* mstpd_exit */

/**
 * @details
 * mstpd daemon's main OVS interface function.  Repeat loop that
 * calls run, wait, poll_block, etc. functions for mstpd.
 *
 * @param arg pointer to ovs-appctl server struct.
 */
void *
mstpd_ovs_main_thread(void *arg)
{

    struct unixctl_server *appctl;

    /* Detach thread to avoid memory leak upon exit. */
    pthread_detach(pthread_self());

    appctl = (struct unixctl_server *)arg;
    clear_port_map(&l2ports);
    clearBitmap(&mstp_instance_map.map[0],MSTP_INSTANCES_MAX);

    exiting = false;
    while (!exiting) {
        mstpd_run();
        unixctl_server_run(appctl);

        mstpd_wait();
        unixctl_server_wait(appctl);
        if (exiting) {
            poll_immediate_wake();
        } else {
            poll_block();
        }
    }

    mstpd_exit();
    unixctl_server_destroy(appctl);

    /* OPS_TODO -- need to tell main loop to exit... */

    return NULL;

} /* mstpd_ovs_main_thread */

/**PROC+***********************************************************
 * Name:    intf_get_mac_addr
 *
 * Purpose: Get MAC address for interface
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

const char* intf_get_mac_addr(uint16_t lport)
{
    const struct ovsrec_interface *ifrow = NULL;
    struct iface_data *idp = NULL;
    const char *mac = NULL;
    MSTP_OVSDB_LOCK;
    assert((lport != 0) && (lport <= MAX_LPORTS));

    idp = find_iface_data_by_index(lport);
    if (idp == NULL)
    {
        assert(false);
    }
    OVSREC_INTERFACE_FOR_EACH(ifrow, idl)
    {
        if(strcmp(ifrow->name,idp->name)==0)
        {
            mac = smap_get(&ifrow->hw_intf_info,"mac_addr");
            VLOG_DBG("Util name : %s, mac: %s ",ifrow->name,mac);
            MSTP_OVSDB_UNLOCK;
            return mac;
        }
    }
    MSTP_OVSDB_UNLOCK;
    return NULL;
}

/**PROC+***********************************************************
 * Name:    system_get_mac_addr
 *
 * Purpose: Get MAC address for System
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

const char* system_get_mac_addr(void)
{
    const struct ovsrec_system *system = NULL;
    const char *mac = NULL;
    MSTP_OVSDB_LOCK;
    system = ovsrec_system_first(idl);
    mac = xstrdup(system->system_mac);
    MSTP_OVSDB_UNLOCK;
    return mac;
}

/**PROC+***********************************************************
 * Name:    update_mstp_tx_counters
 *
 * Purpose: update Tx counters for MSTP
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

void update_mstp_tx_counters()
{
    const struct ovsrec_bridge *bridge_row = NULL;
    struct ovsdb_idl_txn *txn = NULL;
    struct smap smap = SMAP_INITIALIZER(&smap);
    int value = 0;
    const char *temp = NULL;
    char count[5]={0};

    MSTP_OVSDB_LOCK;
    txn = ovsdb_idl_txn_create(idl);

    bridge_row = ovsrec_bridge_first(idl);
    if (!bridge_row) {
        VLOG_ERR("no bridge record found\n");
    }
    temp = smap_get(&bridge_row->other_config,"mstp_tx_bpdus");
    if(temp)
    {
        value = atoi(temp);
    }
    else
    {
        value = 0;
    }
    value++;
    sprintf(count,"%d",value);
    smap_clone(&smap, &bridge_row->other_config);
    smap_replace(&smap, "mstp_tx_bpdus" , count);

    ovsrec_bridge_set_other_config(bridge_row, &smap);
    smap_destroy(&smap);
    ovsdb_idl_txn_commit_block(txn);
    ovsdb_idl_txn_destroy(txn);
    MSTP_OVSDB_UNLOCK;
}
/**PROC+***********************************************************
 * Name:    mstp_global_config_update
 *
 * Purpose: Update MSTP config to protocol thread
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

int mstp_global_config_update(void) {
    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_system *system_row = NULL;
    const char *mstp_config_name = NULL;
    const char *mstp_config_revision = NULL;
    bool config_change = FALSE;

    bridge_row = ovsrec_bridge_first(idl);
    system_row = ovsrec_system_first(idl);
    mstp_config_revision = smap_get(&bridge_row->other_config,MSTP_CONFIG_REV);
    if (!mstp_config_revision)
    {
        mstp_config_revision = DEF_CONFIG_REV;
    }
    if ( mstp_global_conf.config_revision != atoi(mstp_config_revision)) {
        mstp_global_conf.config_revision = atoi(mstp_config_revision);
        config_change = TRUE;
    }
    mstp_config_name = smap_get(&bridge_row->other_config,MSTP_CONFIG_NAME);
    if (!mstp_config_name)
    {
        mstp_config_name = xstrdup(system_row->system_mac);
    }
    if (strcmp(mstp_global_conf.config_name,mstp_config_name)!= 0) {
        strcpy(mstp_global_conf.config_name,mstp_config_name);
        config_change = TRUE;
    }
    if(config_change)
    {
        send_mstp_global_config_update(&mstp_global_conf);
    }
    VLOG_DBG("MSTP Admin status Change: reconfigure : mstp_global_conf.admin_status : %d , *bridge_row->mstp_enable : %d",
               mstp_global_conf.admin_status, *bridge_row->mstp_enable);
    if (mstp_global_conf.admin_status != *bridge_row->mstp_enable) {
        mstp_global_conf.admin_status = *bridge_row->mstp_enable;
        VLOG_DBG("MSTP Admin status Change: reconfigure 1");
        send_admin_status_change_msg(mstp_global_conf.admin_status);
    }
    return 1;
}
/**PROC+***********************************************************
 * Name:    mstp_cist_config_update
 *
 * Purpose: Update MSTP config to protocol thread
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

int mstp_cist_config_update(void) {
    const struct ovsrec_mstp_common_instance *cist_row = NULL;
    const struct ovsrec_vlan *vlan_row = NULL;
    bool config_change = FALSE;
    struct mstp_cist_config *cist_conf = NULL;
    int i = 0;

    cist_row = ovsrec_mstp_common_instance_first(idl);
    if (!cist_row)
    {
        VLOG_DBG("MSTP CIST doesnot exist");
        return 0;
    }
    if (n_cist_vlans != cist_row->n_vlans)
    {
        clear_vid_map(&cist_vlan_list);
        for (i = 0; i < cist_row->n_vlans; i++) {
            if (cist_row->vlans[i]) {
            vlan_row = cist_row->vlans[i];
            }
            set_vid(&cist_vlan_list,vlan_row->id);
        }
        n_cist_vlans = cist_row->n_vlans;
        config_change = TRUE;
    }
    if (mstp_cist_conf.priority != *cist_row->priority) {
        mstp_cist_conf.priority = *cist_row->priority;
        config_change = TRUE;
    }
    if (mstp_cist_conf.hello_time != *cist_row->hello_time) {
        mstp_cist_conf.hello_time = *cist_row->hello_time;
        config_change = TRUE;
    }
    if (mstp_cist_conf.forward_delay != *cist_row->forward_delay) {
        mstp_cist_conf.forward_delay = *cist_row->forward_delay;
        config_change = TRUE;
    }
    if (mstp_cist_conf.max_age != *cist_row->max_age) {
        mstp_cist_conf.max_age= *cist_row->max_age;
        config_change = TRUE;
    }
    if (mstp_cist_conf.max_hop_count != *cist_row->max_hop_count) {
        mstp_cist_conf.max_hop_count = *cist_row->max_hop_count;
        config_change = TRUE;
    }
    if (mstp_cist_conf.tx_hold_count != *cist_row->tx_hold_count) {
        mstp_cist_conf.tx_hold_count = *cist_row->tx_hold_count;
        config_change = TRUE;
    }
    if (config_change == TRUE)
    {
        cist_conf = &mstp_cist_conf;
        send_mstp_cist_config_update(cist_conf);
    }
    return 1;
}
/**PROC+***********************************************************
 * Name:    mstp_cist_port_config_update
 *
 * Purpose: Update MSTP config to protocol thread
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

int mstp_cist_port_config_update(void) {
    const struct ovsrec_mstp_common_instance_port *cist_port_row = NULL;
    struct iface_data *idp = NULL;
    bool config_change = FALSE;
    OVSREC_MSTP_COMMON_INSTANCE_PORT_FOR_EACH(cist_port_row,idl)
    {
        if(cist_port_row)
        {
            uint32_t lport = 0;
            if (!cist_port_row->port)
            {
                continue;
            }
            idp = find_iface_data_by_name(cist_port_row->port->name);
            if(!idp)
            {
                return 0;
            }
            lport = idp->lport_id;
            VLOG_DBG("cist port config update : %d",lport);
            if(!cist_port_lookup[lport])
            {
                struct mstp_cist_port_config *cist_port = NULL;
                cist_port = xzalloc(sizeof(mstp_cist_port_config));
                cist_port->port_priority = *cist_port_row->port_priority;
                cist_port->admin_path_cost = *cist_port_row->admin_path_cost;
                cist_port->bpdus_rx_enable = *cist_port_row->bpdus_rx_enable;
                cist_port->bpdus_tx_enable = *cist_port_row->bpdus_tx_enable;
                cist_port->admin_edge_port_disable = *cist_port_row->admin_edge_port_disable;
                cist_port->bpdu_guard_disable = *cist_port_row->bpdu_guard_disable;
                cist_port->restricted_port_role_disable = *cist_port_row->restricted_port_role_disable;
                cist_port->restricted_port_tcn_disable = *cist_port_row->restricted_port_tcn_disable;
                cist_port->root_guard_disable = *cist_port_row->root_guard_disable;
                cist_port->loop_guard_disable = *cist_port_row->loop_guard_disable;
                cist_port->bpdu_filter_disable = *cist_port_row->bpdu_filter_disable;
                cist_port->port = lport;
                cist_port_lookup[lport] = cist_port;
                send_mstp_cist_port_config_update(cist_port);
            }
            else {
                struct mstp_cist_port_config *cist_port = cist_port_lookup[lport];
                cist_port->port = lport;
                if (cist_port->port_priority != *cist_port_row->port_priority)
                {
                    cist_port->port_priority = *cist_port_row->port_priority;
                    config_change = TRUE;
                }
                if (cist_port->admin_path_cost != *cist_port_row->admin_path_cost)
                {
                    cist_port->admin_path_cost = *cist_port_row->admin_path_cost;
                    config_change = TRUE;
                }
                if (cist_port->bpdus_rx_enable != *cist_port_row->bpdus_rx_enable)
                {
                    cist_port->bpdus_rx_enable = *cist_port_row->bpdus_rx_enable;
                    config_change = TRUE;
                }
                if (cist_port->bpdus_tx_enable != *cist_port_row->bpdus_tx_enable)
                {
                    cist_port->bpdus_tx_enable = *cist_port_row->bpdus_tx_enable;
                    config_change = TRUE;
                }
                if (cist_port->admin_edge_port_disable != *cist_port_row->admin_edge_port_disable)
                {
                    cist_port->admin_edge_port_disable = *cist_port_row->admin_edge_port_disable;
                    config_change = TRUE;
                }
                if (cist_port->bpdu_guard_disable != *cist_port_row->bpdu_guard_disable)
                {
                    cist_port->bpdu_guard_disable = *cist_port_row->bpdu_guard_disable;
                    config_change = TRUE;
                }
                if (cist_port->restricted_port_role_disable != *cist_port_row->restricted_port_role_disable)
                {
                    cist_port->restricted_port_role_disable = *cist_port_row->restricted_port_role_disable;
                    config_change = TRUE;
                }
                if (cist_port->restricted_port_tcn_disable != *cist_port_row->restricted_port_tcn_disable)
                {
                    cist_port->restricted_port_tcn_disable = *cist_port_row->restricted_port_tcn_disable;
                    config_change = TRUE;
                }
                if (cist_port->root_guard_disable != *cist_port_row->root_guard_disable)
                {
                    cist_port->root_guard_disable = *cist_port_row->root_guard_disable;
                    config_change = TRUE;
                }
                if (cist_port->loop_guard_disable != *cist_port_row->loop_guard_disable)
                {
                    cist_port->loop_guard_disable = *cist_port_row->loop_guard_disable;
                    config_change = TRUE;
                }
                if (cist_port->bpdu_filter_disable != *cist_port_row->bpdu_filter_disable)
                {
                    cist_port->bpdu_filter_disable = *cist_port_row->bpdu_filter_disable;
                    config_change = TRUE;
                }
                if(config_change)
                {
                    send_mstp_cist_port_config_update(cist_port);
                }
            }
        }
    }
    return 1;
}
/**PROC+***********************************************************
 * Name:    delete_msti_cache
 *
 * Purpose: Update MSTP config to protocol thread
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

void delete_msti_cache(uint16_t mstid) {
    int i = 0;
    if(msti_lookup[mstid])
    {
        free(msti_lookup[mstid]);
        msti_lookup[mstid] = NULL;
    }
    for (i = 0; i <= MAX_ENTRIES_IN_POOL; i++) {
        if(msti_port_lookup[mstid][i])
        {
            free(msti_port_lookup[mstid][i]);
            msti_port_lookup[mstid][i] = NULL;
        }
    }
}
/**PROC+***********************************************************
 * Name:    mstp_msti_update_config
 *
 * Purpose: Update MSTP config to protocol thread
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

int mstp_msti_update_config(void)
{
    const struct ovsrec_mstp_instance *msti_row = NULL;
    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_vlan *vlan_row = NULL;
    MSTI_MAP msti_map;
    bool config_change = FALSE;
    int i = 0;
    bridge_row = ovsrec_bridge_first(idl);
    clearBitmap(&msti_map.map[0],MSTP_INSTANCES_MAX);
    for (i = 0; i < bridge_row->n_mstp_instances; i++)
    {
        uint16_t mstid = bridge_row->key_mstp_instances[i];
        msti_row = bridge_row->value_mstp_instances[i];
        setBit(&msti_map.map[0],mstid,MSTP_INSTANCES_MAX);
        if(!msti_lookup[mstid])
        {
            struct mstp_msti_config *msti_data = NULL;
            msti_data = xzalloc(sizeof(mstp_msti_config));
            clear_vid_map(&msti_data->vlans);
            for (i = 0; i < msti_row->n_vlans; i++) {
                vlan_row = msti_row->vlans[i];
                set_vid(&msti_data->vlans,vlan_row->id);
            }
            msti_data->n_vlans = msti_row->n_vlans;
            if(msti_data->priority != *msti_row->priority)
            {
                msti_data->priority = *msti_row->priority;
            }
            msti_data->mstid = mstid;
            msti_lookup[mstid] = msti_data;
            send_mstp_msti_config_update(msti_data);
        }
        else
        {
            struct mstp_msti_config *msti_data = NULL;
            msti_data = msti_lookup[mstid];
            if(msti_data->n_vlans != msti_row->n_vlans)
            {
                clear_vid_map(&msti_data->vlans);
                for (i = 0; i < msti_row->n_vlans; i++) {
                    vlan_row = msti_row->vlans[i];
                    set_vid(&msti_data->vlans,vlan_row->id);
                }
                msti_data->n_vlans = msti_row->n_vlans;
                config_change = TRUE;
            }
            if(msti_data->priority != *msti_row->priority)
            {
                msti_data->priority = *msti_row->priority;
                config_change = TRUE;
            }
            if (config_change)
            {
                send_mstp_msti_config_update(msti_data);
            }
        }

    }
    if(!areBitmapsEqual(&mstp_instance_map.map[0],&msti_map.map[0],MSTP_INSTANCES_MAX))
    {
        VLOG_DBG("Update MSTI Cache : Change in MSTI MAP");
        MSTI_MAP addMstiMap;
        MSTI_MAP delMstiMap;

        /*---------------------------------------------------------------------
         * Find MSTIs that are being Deleted.
         *---------------------------------------------------------------------*/
        copyBitmap(&msti_map.map[0], &delMstiMap.map[0],MSTP_INSTANCES_MAX);
        bitInverseBitmap(&delMstiMap.map[0],MSTP_INSTANCES_MAX);
        bitAndBitmaps(&mstp_instance_map.map[0], &delMstiMap.map[0] ,MSTP_INSTANCES_MAX);

        /*---------------------------------------------------------------------
         * Find MSTIs that are being Added.
         *---------------------------------------------------------------------*/
        copyBitmap(&mstp_instance_map.map[0], &addMstiMap.map[0],MSTP_INSTANCES_MAX);
        bitInverseBitmap(&addMstiMap.map[0],MSTP_INSTANCES_MAX);
        bitAndBitmaps(&msti_map.map[0], &addMstiMap.map[0],MSTP_INSTANCES_MAX);

        if(areAnyBitsSetInBitmap(&delMstiMap.map[0],MSTP_INSTANCES_MAX))
        {
            VLOG_DBG("Update MSTP MSTI Cache : Removal of Instances");
            uint16_t mstid = 0;
            for(mstid = findFirstBitSet(&delMstiMap.map[0],MSTP_INSTANCES_MAX);
                    mstid <= MSTP_INSTANCES_MAX;
                    mstid = findNextBitSet(&delMstiMap.map[0], mstid,MSTP_INSTANCES_MAX))
            {
                struct mstp_msti_config_delete msti_config_delete;
                delete_msti_cache(mstid);
                msti_config_delete.mstid = mstid;
                send_mstp_msti_config_delete(&msti_config_delete);
            }
        }
        copyBitmap(&msti_map.map[0],&mstp_instance_map.map[0],MSTP_INSTANCES_MAX);
    }
    return 1;
}
/**PROC+***********************************************************
 * Name:    mstp_msti_port_update_config
 *
 * Purpose: Update MSTP config to protocol thread
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

int mstp_msti_port_update_config(void)
{
    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_mstp_instance *mstp_inst = NULL;
    const struct ovsrec_mstp_instance_port *mstp_inst_port = NULL;
    int i = 0, j = 0;
    struct iface_data *idp = NULL;
    bool config_change = FALSE;

    bridge_row = ovsrec_bridge_first(idl);
    for(i = 0; i < bridge_row->n_mstp_instances; i++)
    {
        int mstid = 0;
        mstid = bridge_row->key_mstp_instances[i];
        mstp_inst = bridge_row->value_mstp_instances[i];
        if (mstp_inst)
        {
            for (j = 0; j < mstp_inst->n_mstp_instance_ports; j++)
            {
                int lport = 0;
                mstp_inst_port = mstp_inst->mstp_instance_ports[j];
                if (!mstp_inst_port->port)
                {
                    continue;
                }
                idp = find_iface_data_by_name(mstp_inst_port->port->name);
                if(!idp)
                {
                    return 0;
                }
                lport = idp->lport_id;
                if (!msti_port_lookup[mstid][lport])
                {
                    struct mstp_msti_port_config *msti_port = NULL;
                    msti_port = xzalloc(sizeof(struct mstp_msti_port_config));
                    msti_port->priority = *mstp_inst_port->port_priority;
                    msti_port->path_cost = *mstp_inst_port->admin_path_cost;
                    msti_port->port = lport;
                    msti_port->mstid = mstid;
                    send_mstp_msti_port_config_update(msti_port);
                    msti_port_lookup[mstid][lport] = msti_port;
                }
                else
                {
                    struct mstp_msti_port_config *msti_port = msti_port_lookup[mstid][lport];
                    if (msti_port->priority != *mstp_inst_port->port_priority)
                    {
                        msti_port->priority = *mstp_inst_port->port_priority;
                        config_change = TRUE;
                    }
                    if (msti_port->path_cost != *mstp_inst_port->admin_path_cost)
                    {
                        msti_port->path_cost = *mstp_inst_port->admin_path_cost;
                        config_change = TRUE;
                    }
                    if(config_change)
                    {
                        send_mstp_msti_port_config_update(msti_port);
                    }
                }
            }
        }
    }
    return 1;
}
/**PROC+***********************************************************
 * Name:    util_mstp_init_config
 *
 * Purpose: Initialize MSTP Bridge and CIST Config
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/
void
util_mstp_init_config() {
    memset(&mstp_global_conf,0,sizeof(mstp_global_config));
    memset(&mstp_cist_conf,0,sizeof(mstp_cist_config));
}
/**PROC+***********************************************************
 * Name:    clear_mstp_global_config
 *
 * Purpose: Clear MSTP Bridge Config
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/
void clear_mstp_global_config() {
    memset(&mstp_global_conf, 0, sizeof(mstp_global_config));
}
/**PROC+***********************************************************
 * Name:    clear_mstp_cist_config
 *
 * Purpose: Clear MSTP CIST Config
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/
void clear_mstp_cist_config() {
    memset(&mstp_cist_conf, 0, sizeof(mstp_cist_config));
}

/**PROC+***********************************************************
 * Name:    clear_mstp_cist_port_config
 *
 * Purpose: Clear MSTP CIST PORT Config
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

void clear_mstp_cist_port_config() {
    int i = 0;
    for (i = 0; i <= MAX_ENTRIES_IN_POOL; i++)
    {
        if(cist_port_lookup[i])
        {
            free(cist_port_lookup[i]);
            cist_port_lookup[i] = NULL;
        }
    }
}
/**PROC+***********************************************************
 * Name:    clear_mstp_msti_config
 *
 * Purpose: Clear MSTP MSTI Config
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

void clear_mstp_msti_config() {
    int i = 0;
    for(i = 0; i <= MSTP_INSTANCES_MAX; i++)
    {
        if(msti_lookup[i])
        {
            free(msti_lookup[i]);
            msti_lookup[i] = NULL;
        }
    }
}
/**PROC+***********************************************************
 * Name:    clear_mstp_msti_port_config
 *
 * Purpose: Clear MSTP MSTI PORT Config
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

void clear_mstp_msti_port_config() {
    int i = 0,j = 0;
    for (i= 0; i <= MSTP_INSTANCES_MAX; i++) {
        for(j = 0; j <= MAX_ENTRIES_IN_POOL; j++) {
            if(msti_port_lookup[i][j])
            {
                free(msti_port_lookup[i][j]);
                msti_port_lookup[i][j] = NULL;
            }
        }
    }
}
/**PROC+***********************************************************
 * Name:    mstp_config_reinit
 *
 * Purpose: Re-initialize the MSTP Config
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

void
mstp_config_reinit() {
    MSTP_OVSDB_LOCK;
    clear_mstp_global_config();
    clear_mstp_cist_config();
    clear_mstp_cist_port_config();
    clear_mstp_msti_config();
    clear_mstp_msti_port_config();
    mstp_cist_config_update();
    mstp_cist_port_config_update();
    mstp_msti_update_config();
    mstp_msti_port_update_config();
    mstp_global_config_update();
    MSTP_OVSDB_UNLOCK;
}
/**PROC+***********************************************************
 * Name:    util_add_default_ports_to_cist
 *
 * Purpose: Add L2ports to the CIST at the time of INIT.
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/
void
util_add_default_ports_to_cist() {
    struct ovsrec_mstp_common_instance_port *cist_port_row = NULL;
    struct ovsrec_mstp_common_instance_port **cist_port_info = NULL;
    struct ovsdb_idl_txn *txn = NULL;
    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_mstp_common_instance *cist_row = NULL;
    int64_t i = 0,j = 0;

    int64_t cist_hello_time = DEF_HELLO_TIME;
    int64_t cist_port_priority = DEF_MSTP_PORT_PRIORITY;
    int64_t admin_path_cost = 0;
    bool bpdus_rx_enable = false;
    bool bpdus_tx_enable = false;
    bool admin_edge_port_disable = false;
    bool bpdu_guard_disable = false;
    bool restricted_port_role_disable = false;
    bool restricted_port_tcn_disable = false;
    bool root_guard_disable = false;
    bool loop_guard_disable = false;
    bool bpdu_filter_disable = false;


    txn = ovsdb_idl_txn_create(idl);

    bridge_row = ovsrec_bridge_first(idl);
    if (!bridge_row) {
        VLOG_DBG("no bridge record found");
        ovsdb_idl_txn_commit_block(txn);
        ovsdb_idl_txn_destroy(txn);
    }

    cist_row = ovsrec_mstp_common_instance_first (idl);
    if (!cist_row) {
        VLOG_DBG("no MSTP common instance record found");
        ovsdb_idl_txn_commit_block(txn);
        ovsdb_idl_txn_destroy(txn);
    }

    /* Add CIST port entry for all ports to the CIST table */
    cist_port_info = xmalloc(sizeof *cist_row->mstp_common_instance_ports * bridge_row->n_ports-1);

    for (i = 0,j =0 ; i < bridge_row->n_ports; i++) {
        /* create CIST_port entry */
        if (strcmp(bridge_row->ports[i]->name,"bridge_normal") == 0) {
            continue;
        }
        cist_port_row = ovsrec_mstp_common_instance_port_insert(txn);

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
        ovsrec_mstp_common_instance_port_set_bpdus_rx_enable( cist_port_row, &bpdus_rx_enable, 1);
        ovsrec_mstp_common_instance_port_set_bpdus_tx_enable( cist_port_row, &bpdus_tx_enable, 1);
        ovsrec_mstp_common_instance_port_set_admin_edge_port_disable( cist_port_row, &admin_edge_port_disable, 1);
        ovsrec_mstp_common_instance_port_set_bpdu_guard_disable( cist_port_row, &bpdu_guard_disable, 1);
        ovsrec_mstp_common_instance_port_set_root_guard_disable( cist_port_row, &root_guard_disable, 1);
        ovsrec_mstp_common_instance_port_set_loop_guard_disable( cist_port_row, &loop_guard_disable, 1);
        ovsrec_mstp_common_instance_port_set_bpdu_filter_disable( cist_port_row, &bpdu_filter_disable, 1);
        ovsrec_mstp_common_instance_port_set_restricted_port_role_disable( cist_port_row, &restricted_port_role_disable, 1);
        ovsrec_mstp_common_instance_port_set_restricted_port_tcn_disable( cist_port_row, &restricted_port_tcn_disable, 1);
        cist_port_info[j++] = cist_port_row;
    }
    ovsrec_mstp_common_instance_set_mstp_common_instance_ports (cist_row,
                cist_port_info, bridge_row->n_ports-1);
    free(cist_port_info);
    ovsdb_idl_txn_commit_block(txn);
    ovsdb_idl_txn_destroy(txn);
}
/**PROC+***********************************************************
 * Name:    util_mstp_set_defaults
 *
 * Purpose: Add Defaults to the CIST at the time of INIT.
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

void
util_mstp_set_defaults() {

    const struct ovsrec_bridge *bridge_row = NULL;
    struct ovsrec_vlan **vlans = NULL;
    struct smap smap = SMAP_INITIALIZER(&smap);
    struct ovsdb_idl_txn *txn = NULL;
    const struct ovsrec_mstp_common_instance *cist_row = NULL;
    const struct ovsrec_system *system_row = NULL;
    const int64_t cist_top_change_count = 0;
    time_t cist_time_since_top_change;
    const int64_t cist_priority = DEF_BRIDGE_PRIORITY;
    const int64_t hello_time = DEF_HELLO_TIME;
    const int64_t fwd_delay = DEF_FORWARD_DELAY;
    const int64_t max_age = DEF_MAX_AGE;
    const int64_t max_hops = DEF_MAX_HOPS;
    const int64_t tx_hold_cnt = DEF_HOLD_COUNT;
    bool mstp_status = DEF_ADMIN_STATUS;
    int i = 0;

    txn = ovsdb_idl_txn_create(idl);

    bridge_row = ovsrec_bridge_first(idl);

    system_row = ovsrec_system_first(idl);
    if (!system_row) {
        VLOG_DBG("no system record found");
        return;
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
    if (!bridge_row->mstp_enable)
    {
        ovsrec_bridge_set_mstp_enable(bridge_row, &mstp_status, 1);
    }
    smap_destroy(&smap);


    cist_row = ovsrec_mstp_common_instance_first (idl);
    if (!cist_row) {

        /* Crate a CIST instance */
        cist_row = ovsrec_mstp_common_instance_insert(txn);
        vlans = xcalloc(bridge_row->n_vlans, sizeof *bridge_row->vlans);
        if (!vlans) {
            ovsdb_idl_txn_destroy(txn);
            return;
        }
        for (i = 0; i < bridge_row->n_vlans; i++) {
            vlans[i] = bridge_row->vlans[i];
        }
        ovsrec_mstp_common_instance_set_vlans(cist_row, vlans, bridge_row->n_vlans);

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
        ovsrec_mstp_common_instance_set_topology_change_count(cist_row,
                &cist_top_change_count, 1);
        ovsrec_mstp_common_instance_set_time_since_top_change(cist_row,
                (int64_t *)&cist_time_since_top_change, 1);

        /* Add the CIST instance to bridge table */
        ovsrec_bridge_set_mstp_common_instance(bridge_row, cist_row);
    }
    ovsdb_idl_txn_commit_block(txn);
    ovsdb_idl_txn_destroy(txn);
    if (!vlans)
    {
        free(vlans);
    }
    return;
}
/**PROC+***********************************************************
 * Name:    mstp_util_set_cist_port_table_bool
 *
 * Purpose: Sets a boolean value into CIST port Table
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

void
mstp_util_set_cist_port_table_bool (const char *if_name, const char *key,
        const bool value) {
    const struct ovsrec_mstp_common_instance_port *cist_port_row = NULL;

    OVSREC_MSTP_COMMON_INSTANCE_PORT_FOR_EACH(cist_port_row, idl) {
        if (strcmp(cist_port_row->port->name, if_name) == 0) {
            break;
        }
    }

    if (!cist_port_row) {
        return;
    }

    if (strcmp(key, MSTP_OPER_EDGE) == 0) {
        ovsrec_mstp_common_instance_port_set_oper_edge_port(
                cist_port_row, &value, 1);
    }
}

/**PROC+***********************************************************
 * Name:    mstp_util_set_cist_table_value
 *
 * Purpose: Sets a integer value into CIST port Table
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

void
mstp_util_set_cist_table_value (const char *key, int64_t value) {
    const struct ovsrec_mstp_common_instance *cist_row = NULL;

    cist_row = ovsrec_mstp_common_instance_first (idl);
    if (!cist_row) {
        return;
    }

    if (strcmp(key, ROOT_PATH_COST) == 0) {
        ovsrec_mstp_common_instance_set_root_path_cost(cist_row, &value, 1);
    }
    else if (strcmp(key, ROOT_PRIORITY) == 0) {
        ovsrec_mstp_common_instance_set_root_priority(cist_row, &value, 1);
    }
    else if (strcmp(key, CIST_PATH_POST) == 0) {
        ovsrec_mstp_common_instance_set_cist_path_cost(cist_row, &value, 1);
    }
    else if (strcmp(key, REMAINING_HOPS) == 0) {
        ovsrec_mstp_common_instance_set_remaining_hops(cist_row, &value, 1);
    }
    else if (strcmp(key, OPER_HELLO_TIME) == 0) {
        ovsrec_mstp_common_instance_set_oper_hello_time(cist_row, &value, 1);
    }
    else if (strcmp(key, OPER_FORWARD_DELAY) == 0) {
        ovsrec_mstp_common_instance_set_oper_forward_delay(cist_row, &value, 1);
    }
    else if (strcmp(key, OPER_MAX_AGE) == 0) {
        ovsrec_mstp_common_instance_set_oper_max_age(cist_row, &value, 1);
    }
    else if (strcmp(key, HELLO_EXPIRY_TIME) == 0) {
        ovsrec_mstp_common_instance_set_hello_expiry_time(cist_row, &value, 1);
    }
    else if (strcmp(key, FORWARD_DELAY_EXP_TIME) == 0) {
        ovsrec_mstp_common_instance_set_forward_delay_expiry_time(cist_row, &value, 1);
    }
    else if (strcmp(key, TIME_SINCE_TOP_CHANGE) == 0) {
        ovsrec_mstp_common_instance_set_time_since_top_change(cist_row, &value, 1);
    }
    else if (strcmp(key, OPER_TX_HOLD_COUNT) == 0) {
        ovsrec_mstp_common_instance_set_oper_tx_hold_count(cist_row, &value, 1);
    }
    else if (strcmp(key, TOP_CHANGE_CNT) == 0) {
        ovsrec_mstp_common_instance_set_topology_change_count(cist_row, &value, 1);
    }
}

/**PROC+***********************************************************
 * Name:    mstp_util_set_cist_table_string
 *
 * Purpose: Sets a string into CIST port Table
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/
void
mstp_util_set_cist_table_string (const char *key, const char *string) {
    const struct ovsrec_mstp_common_instance *cist_row = NULL;

    cist_row = ovsrec_mstp_common_instance_first (idl);
    if (!cist_row) {
        return;
    }
    if (strcmp(key, DESIGNATED_ROOT) == 0) {
        ovsrec_mstp_common_instance_set_designated_root(cist_row, string);
    }
    else if (strcmp(key, REGIONAL_ROOT) == 0) {
        ovsrec_mstp_common_instance_set_regional_root(cist_row, string);
    }
    else if (strcmp(key, ROOT_PORT) == 0) {
        ovsrec_mstp_common_instance_set_root_port(cist_row, string);
    }
}
/**PROC+***********************************************************
 * Name:    mstp_util_set_cist_port_table_value
 *
 * Purpose: Sets a integer value into CIST port Table
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/
void
mstp_util_set_cist_port_table_value (const char *if_name, const char *key,
        int64_t value) {
    const struct ovsrec_mstp_common_instance_port *cist_port_row = NULL;

    OVSREC_MSTP_COMMON_INSTANCE_PORT_FOR_EACH(cist_port_row, idl) {
        if (strcmp(cist_port_row->port->name, if_name) == 0) {
            break;
        }
    }

    if (!cist_port_row) {
        return;
    }

    if (strcmp(key, CIST_PATH_COST) == 0) {
        ovsrec_mstp_common_instance_port_set_cist_path_cost(cist_port_row, &value, 1);
    }
    else if (strcmp(key, PORT_PATH_COST) == 0) {
        ovsrec_mstp_common_instance_port_set_port_path_cost(cist_port_row, &value, 1);
    }
    else if (strcmp(key, DESIGNATED_PATH_COST) == 0) {
        ovsrec_mstp_common_instance_port_set_designated_path_cost(cist_port_row, &value, 1);
    }
    else if (strcmp(key, PORT_HELLO_TIME) == 0) {
        ovsrec_mstp_common_instance_port_set_port_hello_time(cist_port_row, &value, 1);
    }
}
/**PROC+***********************************************************
 * Name:    mstp_util_set_cist_port_table_string
 *
 * Purpose: Sets a string into CIST port Table
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/
void
mstp_util_set_cist_port_table_string (const char *if_name, const char *key,
        char *string) {
    const struct ovsrec_mstp_common_instance_port *cist_port_row = NULL;

    OVSREC_MSTP_COMMON_INSTANCE_PORT_FOR_EACH(cist_port_row, idl) {
        if (strcmp(cist_port_row->port->name, if_name) == 0) {
            break;
        }
    }

    if (!cist_port_row) {
         return;
    }

    if (strcmp(key, PORT_ROLE) == 0) {
        ovsrec_mstp_common_instance_port_set_port_role(cist_port_row, string);
    }
    else if (strcmp(key, PORT_STATE) == 0) {
        ovsrec_mstp_common_instance_port_set_port_state(cist_port_row, string);
    }
    else if (strcmp(key, LINK_TYPE) == 0) {
        ovsrec_mstp_common_instance_port_set_link_type(cist_port_row, string);
    }
    else if (strcmp(key, DESIGNATED_PORT) == 0) {
        ovsrec_mstp_common_instance_port_set_designated_port(cist_port_row, string);
    }
    else if (strcmp(key, DESIGNATED_ROOT) == 0) {
        ovsrec_mstp_common_instance_port_set_designated_root(cist_port_row, string);
    }
    else if (strcmp(key, CIST_REGIONAL_ROOT_ID) == 0) {
        ovsrec_mstp_common_instance_port_set_cist_regional_root_id(cist_port_row, string);
    }
    else if (strcmp(key, DESIGNATED_BRIDGE) == 0) {
        ovsrec_mstp_common_instance_port_set_designated_bridge(cist_port_row, string);
    }
    else if (strcmp(key, "flush_mac") == 0) {
#if 0
        bool value = (strcmp(string,"enable") == 0)?TRUE:FALSE;
        ovsrec_mstp_common_instance_port_set_flush_macaddress(cist_port_row, &value, 1);
#endif /*0*/
    }
}

/**PROC+***********************************************************
 * Name:    mstp_util_set_msti_table_string
 *
 * Purpose: Sets a string into MSTI Table
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

void
mstp_util_set_msti_table_string (const char *key, const char *string, int mstid) {
    const struct ovsrec_mstp_instance *msti_row = NULL;
    const struct ovsrec_bridge *bridge_row = NULL;
    int  i = 0;
    bridge_row = ovsrec_bridge_first(idl);
    for (i = 0; i < bridge_row->n_mstp_instances; i++)
    {
        int id = bridge_row->key_mstp_instances[i];
        if (id == mstid) {
            msti_row = bridge_row->value_mstp_instances[i];
            break;
        }
    }

    if (!msti_row) {
         return;
    }
    if (strcmp(key, DESIGNATED_ROOT) == 0) {
        ovsrec_mstp_instance_set_designated_root(msti_row, string);
    }
    else if (strcmp(key, ROOT_PORT) == 0) {
        ovsrec_mstp_instance_set_root_port(msti_row, string);
    }
    else if (strcmp(key, BRIDGE_IDENTIFIER) == 0) {
        ovsrec_mstp_instance_set_bridge_identifier(msti_row, string);
    }
    else if (strcmp(key, TOPOLOGY_CHANGE) == 0) {
        bool value = (strcmp(string,"enable") == 0)?TRUE:FALSE;
        ovsrec_mstp_instance_set_topology_unstable(msti_row, &value, 1);
    }
}
/**PROC+***********************************************************
 * Name:    mstp_util_set_msti_table_value
 *
 * Purpose: Sets a value into MSTI Table
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

void
mstp_util_set_msti_table_value (const char *key, int64_t value, int mstid) {
    const struct ovsrec_mstp_instance *msti_row = NULL;
    const struct ovsrec_bridge *bridge_row = NULL;
    int  i = 0;
    bridge_row = ovsrec_bridge_first(idl);
    for (i = 0; i < bridge_row->n_mstp_instances; i++)
    {
        int id = bridge_row->key_mstp_instances[i];
        if (id == mstid) {
            msti_row = bridge_row->value_mstp_instances[i];
            break;
        }
    }

    if (!msti_row) {
         return;
    }
    if (strcmp(key, ROOT_PATH_COST) == 0) {
        ovsrec_mstp_instance_set_root_path_cost(msti_row, &value, 1);
    }
    else if (strcmp(key, ROOT_PRIORITY) == 0) {
        ovsrec_mstp_instance_set_root_priority(msti_row, &value, 1);
    }
    else if (strcmp(key, TIME_SINCE_TOP_CHANGE) == 0) {
        ovsrec_mstp_instance_set_time_since_top_change(msti_row, &value, 1);
    }
    else if (strcmp(key, TOP_CHANGE_CNT) == 0) {
        ovsrec_mstp_instance_set_topology_change_count(msti_row, &value, 1);
    }
}

/**PROC+***********************************************************
 * Name:    mstp_util_set_msti_port_table_value
 *
 * Purpose: Sets a value into MSTI Port Table
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/
void
mstp_util_set_msti_port_table_value (const char *key, int64_t value, int mstid, int lport) {
    const struct ovsrec_mstp_instance *msti_row = NULL;
    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_mstp_instance_port *msti_port_row = NULL;
    struct iface_data *idp = NULL;
    int  i = 0, j = 0;
    bridge_row = ovsrec_bridge_first(idl);
    for (i = 0; i < bridge_row->n_mstp_instances; i++)
    {
        int id = bridge_row->key_mstp_instances[i];
        if (id == mstid) {
            msti_row = bridge_row->value_mstp_instances[i];
            for (j = 0; j < msti_row->n_mstp_instance_ports; j++)
            {
                idp = find_iface_data_by_name(msti_row->mstp_instance_ports[j]->port->name);
                if(!idp)
                {
                    return;
                }
                if(lport == idp->lport_id) {
                    msti_port_row = msti_row->mstp_instance_ports[j];
                    break;
                }
            }
        }
    }

    if (!msti_port_row) {
         return;
    }
    if (strcmp(key, DESIGNATED_ROOT_PRIORITY) == 0) {
        ovsrec_mstp_instance_port_set_designated_root_priority(msti_port_row, &value, 1);
    }
    else if (strcmp(key, DESIGNATED_COST) == 0) {
        ovsrec_mstp_instance_port_set_designated_cost(msti_port_row, &value, 1);
    }
    else if (strcmp(key, DESIGNATED_BRIDGE_PRIORITY) == 0) {
        ovsrec_mstp_instance_port_set_designated_bridge_priority(msti_port_row, &value, 1);
    }
}
/**PROC+***********************************************************
 * Name:    mstp_util_set_msti_port_table_string
 *
 * Purpose: Sets a string into MSTI Port Table
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/
void
mstp_util_set_msti_port_table_string (const char *key, char *string, int mstid, int lport) {
    const struct ovsrec_mstp_instance *msti_row = NULL;
    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_mstp_instance_port *msti_port_row = NULL;
    struct iface_data *idp = NULL;
    int  i = 0, j = 0;
    bridge_row = ovsrec_bridge_first(idl);
    for (i = 0; i < bridge_row->n_mstp_instances; i++)
    {
        int id = bridge_row->key_mstp_instances[i];
        if (id == mstid) {
            msti_row =  bridge_row->value_mstp_instances[i];
            for (j = 0; j < msti_row->n_mstp_instance_ports; j++)
            {
                idp = find_iface_data_by_name(msti_row->mstp_instance_ports[j]->port->name);
                if(!idp)
                {
                    return;
                }
                if(lport == idp->lport_id) {
                    msti_port_row = msti_row->mstp_instance_ports[j];
                    break;
                }
            }
        }
    }

    if (!msti_port_row) {
         return;
    }
    if (strcmp(key, PORT_ROLE) == 0) {
        ovsrec_mstp_instance_port_set_port_role(msti_port_row, string);
    }
    else if (strcmp(key, PORT_STATE) == 0) {
        ovsrec_mstp_instance_port_set_port_state(msti_port_row, string);
    }
    else if (strcmp(key, DESIGNATED_ROOT) == 0) {
        ovsrec_mstp_instance_port_set_designated_root(msti_port_row, string);
    }
    else if (strcmp(key, DESIGNATED_BRIDGE) == 0) {
        ovsrec_mstp_instance_port_set_designated_bridge(msti_port_row, string);
    }
    else if (strcmp(key, DESIGNATED_PORT) == 0) {
        ovsrec_mstp_instance_port_set_designated_port(msti_port_row, string);
    }
    else if (strcmp(key, "flush_mac") == 0) {
#if 0
        bool value = (strcmp(string,"enable") == 0)?TRUE:FALSE;
        ovsrec_mstp_instance_port_set_flush_macaddress(msti_port_row, &value, 1);
#endif /*0*/
    }
}
/**PROC+***********************************************************
 * Name:    mstp_convertPortRoleEnumToString
 *
 * Purpose: Converts Enum into Port Role String
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/
void mstp_convertPortRoleEnumToString(MSTP_PORT_ROLE_t role,char *string)
{
    if(role == MSTP_PORT_ROLE_ROOT) {
        strcpy(string,MSTP_ROLE_ROOT);
    }
    else if (role == MSTP_PORT_ROLE_ALTERNATE) {
        strcpy(string,MSTP_ROLE_ALTERNATE);
    }
    else if (role == MSTP_PORT_ROLE_DESIGNATED) {
        strcpy(string,MSTP_ROLE_DESIGNATE);
    }
    else if (role == MSTP_PORT_ROLE_BACKUP) {
        strcpy(string,MSTP_ROLE_BACKUP);
    }
    else if (role == MSTP_PORT_ROLE_DISABLED) {
        strcpy(string,MSTP_ROLE_DISABLE);
    }
    else if (role == MSTP_PORT_ROLE_MASTER) {
        strcpy(string,MSTP_ROLE_MASTER);
    }
}

/**PROC+***********************************************************
 * Name:    handle_vlan_add_in_mstp_config
 *
 * Purpose: Update DB on a VLAN ADD to the Bridge
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

void handle_vlan_add_in_mstp_config(int vlan)
{
    struct ovsdb_idl_txn *txn = NULL;
    const struct ovsrec_mstp_common_instance *cist_row = NULL;
    const struct ovsrec_vlan *vlan_row = NULL;
    struct ovsrec_vlan **vlans = NULL;
    int i = 0;
    MSTP_OVSDB_LOCK;
    txn = ovsdb_idl_txn_create(idl);
    if (vlan) {
        OVSREC_VLAN_FOR_EACH(vlan_row, idl) {
            if (vlan == vlan_row->id) {
                break;
            }
        }
        if (!vlan_row) {
            ovsdb_idl_txn_commit_block(txn);
            ovsdb_idl_txn_destroy(txn);
        }
    }
    cist_row = ovsrec_mstp_common_instance_first(idl);
    /* MSTP instance not found with the incoming instID */
    if(cist_row) {
        /* Push the complete vlan list to MSTP instance table
         * including the new vlan*/
        vlans =
            xcalloc(cist_row->n_vlans + 1, sizeof *cist_row->vlans);
        if (!vlans) {
            ovsdb_idl_txn_commit_block(txn);
            ovsdb_idl_txn_destroy(txn);
        }
        for (i = 0; i < cist_row->n_vlans; i++) {
            vlans[i] = cist_row->vlans[i];
        }
        vlans[cist_row->n_vlans] = (struct ovsrec_vlan *)vlan_row;
        ovsrec_mstp_common_instance_set_vlans(cist_row, vlans,
                cist_row->n_vlans + 1);
    }
    ovsdb_idl_txn_commit_block(txn);
    ovsdb_idl_txn_destroy(txn);
    if (!vlans)
    {
        free(vlans);
    }
    MSTP_OVSDB_UNLOCK;
}
/**PROC+***********************************************************
 * Name:    handle_vlan_delete_in_mstp_config
 *
 * Purpose: Update DB on a VLAN Delete to the Bridge
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

void handle_vlan_delete_in_mstp_config(int vlan)
{
    struct ovsdb_idl_txn *txn = NULL;
    const struct ovsrec_mstp_common_instance *cist_row = NULL;
    const struct ovsrec_mstp_instance *msti_row = NULL;
    struct ovsrec_vlan **vlans = NULL;
    int i = 0,j = 0;
    MSTP_OVSDB_LOCK;
    cist_row = ovsrec_mstp_common_instance_first(idl);
    if(cist_row) {
        /* Push the complete vlan list to MSTP Common instance table
         * including the new vlan*/
        if (cist_row->n_vlans) {
            txn = ovsdb_idl_txn_create(idl);
            vlans =
                xcalloc(cist_row->n_vlans - 1, sizeof *cist_row->vlans);
            if (!vlans) {
                ovsdb_idl_txn_commit_block(txn);
                ovsdb_idl_txn_destroy(txn);
            }
            for (j=0, i = 0; i < cist_row->n_vlans; i++) {
                if(vlan != cist_row->vlans[i]->id) {
                    vlans[j++] = cist_row->vlans[i];
                }
            }
            ovsrec_mstp_common_instance_set_vlans(cist_row, vlans,
                    cist_row->n_vlans - 1);
            ovsdb_idl_txn_commit_block(txn);
            ovsdb_idl_txn_destroy(txn);
            free(vlans);
        }
    }
    OVSREC_MSTP_INSTANCE_FOR_EACH(msti_row,idl) {
        if(msti_row) {
            /* Push the complete vlan list to MSTP instance table
             * including the new vlan*/
            if (msti_row->n_vlans) {
                txn = ovsdb_idl_txn_create(idl);
                vlans =
                    xcalloc(msti_row->n_vlans - 1, sizeof *msti_row->vlans);
                if (!vlans) {
                    ovsdb_idl_txn_commit_block(txn);
                    ovsdb_idl_txn_destroy(txn);
                }
                for (j=0, i = 0; i < msti_row->n_vlans; i++) {
                    if(vlan != msti_row->vlans[i]->id) {
                        vlans[j++] = msti_row->vlans[i];
                    }
                }
                ovsrec_mstp_instance_set_vlans(msti_row, vlans,
                        msti_row->n_vlans - 1);
                ovsdb_idl_txn_commit_block(txn);
                ovsdb_idl_txn_destroy(txn);
                free(vlans);
            }
        }

    }
    MSTP_OVSDB_UNLOCK;
}
/**PROC+***********************************************************
 * Name:    update_port_entry_in_cist_mstp_instances
 *
 * Purpose: Update CIST DB on a L2port ADD/MODIFY to the Bridge
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/
void update_port_entry_in_cist_mstp_instances(char *name, int operation){
    struct ovsdb_idl_txn *txn = NULL;
    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_mstp_common_instance *cist_row = NULL;
    const struct ovsrec_mstp_common_instance_port *cist_port_row = NULL;
    struct ovsrec_mstp_common_instance_port **cist_port_info = NULL, *cist_port_add = NULL;
    int64_t cist_hello_time = DEF_HELLO_TIME;
    int64_t cist_port_priority = DEF_MSTP_PORT_PRIORITY;
    int64_t admin_path_cost = 0;
    bool bpdus_rx_enable = false;
    bool bpdus_tx_enable = false;
    bool admin_edge_port_disable = false;
    bool bpdu_guard_disable = false;
    bool restricted_port_role_disable = false;
    bool restricted_port_tcn_disable = false;
    bool root_guard_disable = false;
    bool loop_guard_disable = false;
    bool bpdu_filter_disable = false;
    int  i = 0, j = 0;
    MSTP_OVSDB_LOCK;
    txn = ovsdb_idl_txn_create(idl);
    bridge_row = ovsrec_bridge_first(idl);
    cist_row = ovsrec_mstp_common_instance_first(idl);
    if (strcmp(name,DEFAULT_BRIDGE_NAME) == 0)
    {
        ovsdb_idl_txn_destroy(txn);
        MSTP_OVSDB_UNLOCK;
        return;
    }
    OVSREC_MSTP_COMMON_INSTANCE_PORT_FOR_EACH(cist_port_row,idl)
    {
        if(!cist_port_row->port && operation == e_mstpd_lport_delete)
        {
            break;
        }
        if(strcmp(cist_port_row->port->name,name)== 0)
        {
            break;
        }
    }
    if (operation == e_mstpd_lport_add && !cist_port_row) {
        cist_port_add = ovsrec_mstp_common_instance_port_insert(txn);
        /* FILL the default values for CIST_port entry */
        for (i = 0; i < bridge_row->n_ports; i++)
        {
            if(strcmp(bridge_row->ports[i]->name,name) == 0)
            {
                break;
            }
        }
        if (!bridge_row->ports[i])
        {
            ovsdb_idl_txn_destroy(txn);
            MSTP_OVSDB_UNLOCK;
            STP_ASSERT(0);
            return;
        }
        ovsrec_mstp_common_instance_port_set_port( cist_port_add,
                bridge_row->ports[i]);
        ovsrec_mstp_common_instance_port_set_port_state( cist_port_add,
                MSTP_STATE_BLOCK);
        ovsrec_mstp_common_instance_port_set_port_role( cist_port_add,
                MSTP_ROLE_DISABLE);
        ovsrec_mstp_common_instance_port_set_admin_path_cost( cist_port_add,
                &admin_path_cost, 1);
        ovsrec_mstp_common_instance_port_set_port_priority( cist_port_add,
                &cist_port_priority, 1);
        ovsrec_mstp_common_instance_port_set_link_type( cist_port_add,
                DEF_LINK_TYPE);
        ovsrec_mstp_common_instance_port_set_port_hello_time( cist_port_add,
                &cist_hello_time, 1);
        ovsrec_mstp_common_instance_port_set_bpdus_rx_enable( cist_port_add, &bpdus_rx_enable, 1);
        ovsrec_mstp_common_instance_port_set_bpdus_tx_enable( cist_port_add, &bpdus_tx_enable, 1);
        ovsrec_mstp_common_instance_port_set_admin_edge_port_disable( cist_port_add, &admin_edge_port_disable, 1);
        ovsrec_mstp_common_instance_port_set_bpdu_guard_disable( cist_port_add, &bpdu_guard_disable, 1);
        ovsrec_mstp_common_instance_port_set_root_guard_disable( cist_port_add, &root_guard_disable, 1);
        ovsrec_mstp_common_instance_port_set_loop_guard_disable( cist_port_add, &loop_guard_disable, 1);
        ovsrec_mstp_common_instance_port_set_bpdu_filter_disable( cist_port_add, &bpdu_filter_disable, 1);
        ovsrec_mstp_common_instance_port_set_restricted_port_role_disable( cist_port_add, &restricted_port_role_disable, 1);
        ovsrec_mstp_common_instance_port_set_restricted_port_tcn_disable( cist_port_add, &restricted_port_tcn_disable, 1);
        cist_port_info =
            xcalloc((cist_row->n_mstp_common_instance_ports + 1),
                    sizeof *cist_row->mstp_common_instance_ports);
        if(!cist_port_info) {
            ovsdb_idl_txn_commit_block(txn);
            ovsdb_idl_txn_destroy(txn);
        }

        for (i = 0; i < cist_row->n_mstp_common_instance_ports; i++) {
            cist_port_info[i] = cist_row->mstp_common_instance_ports[i];
        }
        cist_port_info[cist_row->n_mstp_common_instance_ports] = cist_port_add;
        ovsrec_mstp_common_instance_set_mstp_common_instance_ports (cist_row,
                cist_port_info, cist_row->n_mstp_common_instance_ports+1 );
    }
    else if (operation == e_mstpd_lport_delete) {
        if(!cist_port_row) {
            ovsdb_idl_txn_destroy(txn);
            MSTP_OVSDB_UNLOCK;
            return;
        }
        cist_port_info =
            xcalloc((cist_row->n_mstp_common_instance_ports - 1),
                    sizeof *cist_row->mstp_common_instance_ports);
        if(!cist_port_info) {
            ovsdb_idl_txn_commit_block(txn);
            ovsdb_idl_txn_destroy(txn);
        }

        for (i = 0,j = 0; i < cist_row->n_mstp_common_instance_ports; i++) {
            if(cist_row->mstp_common_instance_ports[i]->port && strcmp(cist_row->mstp_common_instance_ports[i]->port->name,name) != 0)
            {
                cist_port_info[j++] = cist_row->mstp_common_instance_ports[i];
            }
        }
        ovsrec_mstp_common_instance_set_mstp_common_instance_ports (cist_row,
                cist_port_info, cist_row->n_mstp_common_instance_ports - 1 );
    }
    ovsdb_idl_txn_commit_block(txn);
    ovsdb_idl_txn_destroy(txn);
    free(cist_port_info);
    MSTP_OVSDB_UNLOCK;
}
/**PROC+***********************************************************
 * Name:    update_port_entry_in_msti_mstp_instances
 *
 * Purpose: Update MSTI DB on a L2port ADD/MODIFY to the Bridge
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

void update_port_entry_in_msti_mstp_instances(char *name,int operation) {
    struct ovsdb_idl_txn *txn = NULL;
    const struct ovsrec_bridge *bridge_row = NULL;
    const struct ovsrec_mstp_instance *msti_row = NULL;
    const struct ovsrec_mstp_instance_port *msti_port_row = NULL;
    struct ovsrec_mstp_instance_port **msti_port_info = NULL, *msti_port_add = NULL;
    int64_t cist_port_priority = DEF_MSTP_PORT_PRIORITY;
    int64_t admin_path_cost = 0;
    int i = 0, j= 0, k = 0;
    MSTP_OVSDB_LOCK;
    txn = ovsdb_idl_txn_create(idl);
    bridge_row = ovsrec_bridge_first(idl);
    if (strcmp(name,DEFAULT_BRIDGE_NAME) == 0)
    {
        ovsdb_idl_txn_destroy(txn);
        MSTP_OVSDB_UNLOCK;
        return;
    }
    for ( i = 0; i < bridge_row->n_mstp_instances ; i++)
    {
        msti_row = bridge_row->value_mstp_instances[i];
        for (j = 0; j < msti_row->n_mstp_instance_ports; j++)
        {
            if (!msti_row->mstp_instance_ports[i]->port && operation == e_mstpd_lport_delete)
            {
                msti_port_row = msti_row->mstp_instance_ports[i];
                break;
            }
            if (strcmp(msti_row->mstp_instance_ports[i]->port->name,name) == 0)
            {
                msti_port_row = msti_row->mstp_instance_ports[j];
                break;
            }
        }
        if ((operation == e_mstpd_lport_add) && msti_port_row)
        {
            ovsdb_idl_txn_destroy(txn);
            MSTP_OVSDB_UNLOCK;
            return;
        }
        if ((operation == e_mstpd_lport_add) && !msti_port_row)
        {
            msti_port_add = ovsrec_mstp_instance_port_insert(txn);
            for (k = 0; k < bridge_row->n_ports; k++)
            {
                if(strcmp(bridge_row->ports[k]->name,name) == 0)
                {
                    break;
                }
            }
            if (!bridge_row->ports[k])
            {
                ovsdb_idl_txn_destroy(txn);
                MSTP_OVSDB_UNLOCK;
                STP_ASSERT(0);
                return;
            }
            /* FILL the default values for CIST_port entry */
            ovsrec_mstp_instance_port_set_port( msti_port_add,
                    bridge_row->ports[k]);
            ovsrec_mstp_instance_port_set_port_state( msti_port_add,
                    MSTP_STATE_BLOCK);
            ovsrec_mstp_instance_port_set_port_role( msti_port_add,
                    MSTP_ROLE_DISABLE);
            ovsrec_mstp_instance_port_set_admin_path_cost( msti_port_add,
                    &admin_path_cost, 1);
            ovsrec_mstp_instance_port_set_port_priority( msti_port_add,
                    &cist_port_priority, 1);
            msti_port_info =
                xcalloc((msti_row->n_mstp_instance_ports + 1),
                        sizeof *msti_row->mstp_instance_ports);
            if(!msti_port_info) {
                ovsdb_idl_txn_destroy(txn);
                MSTP_OVSDB_UNLOCK;
                return;
            }

            for (k = 0; k < msti_row->n_mstp_instance_ports; k++) {
                msti_port_info[k] = msti_row->mstp_instance_ports[k];
            }
            msti_port_info[msti_row->n_mstp_instance_ports] = msti_port_add;
            ovsrec_mstp_instance_set_mstp_instance_ports (msti_row,
                    msti_port_info, msti_row->n_mstp_instance_ports+1 );
            free(msti_port_info);
        }
        else if (operation == e_mstpd_lport_delete)
        {
            if (!msti_port_row)
            {
                ovsdb_idl_txn_destroy(txn);
                MSTP_OVSDB_UNLOCK;
                return;
            }
            msti_port_info =
                xcalloc((msti_row->n_mstp_instance_ports - 1),
                        sizeof *msti_row->mstp_instance_ports);
            if(!msti_port_info) {
                ovsdb_idl_txn_destroy(txn);
                MSTP_OVSDB_UNLOCK;
                return;
            }

            for (k = 0,j =0; k < msti_row->n_mstp_instance_ports; k++) {
                if(msti_row->mstp_instance_ports[i]->port && strcmp(msti_row->mstp_instance_ports[i]->port->name,name) != 0)
                {
                    msti_port_info[j++] = msti_row->mstp_instance_ports[k];
                }
            }
            ovsrec_mstp_instance_set_mstp_instance_ports (msti_row,
                    msti_port_info, msti_row->n_mstp_instance_ports - 1);
            free(msti_port_info);
        }
    }
    ovsdb_idl_txn_commit_block(txn);
    ovsdb_idl_txn_destroy(txn);
    MSTP_OVSDB_UNLOCK;
}
/**PROC+***********************************************************
 * Name:    is_lport_down
 *
 * Purpose:  to check if a lport link state is down
 *
 * Params:    none
 *
 * Returns:   TRUE/FALSE
 *
 **PROC-*****************************************************************/
bool is_lport_down(int lport)
{
    struct iface_data *idp = NULL;
    idp = find_iface_data_by_index(lport);
    if (idp->link_state == INTERFACE_LINK_STATE_UP)
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}
/**PROC+***********************************************************
 * Name:    is_lport_up
 *
 * Purpose:  to check if a lport link state is up
 *
 * Params:    none
 *
 * Returns:   TRUE/FALSE
 *
 **PROC-*****************************************************************/

bool is_lport_up(int lport)
{
    struct iface_data *idp = NULL;
    idp = find_iface_data_by_index(lport);
    if (idp->link_state == INTERFACE_LINK_STATE_DOWN)
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}
/**PROC+***********************************************************
 * Name:    disable_logical_port
 *
 * Purpose:  to set a port row to admin status to down.
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

void disable_logical_port(int lport)
{
    struct ovsdb_idl_txn *txn = NULL;
    struct iface_data *idp = NULL;
    const struct ovsrec_port *port_row = NULL;
    txn = ovsdb_idl_txn_create(idl);
    idp = find_iface_data_by_index(lport);
    MSTP_OVSDB_LOCK;
    OVSREC_PORT_FOR_EACH(port_row,idl)
    {
        if(strcmp(port_row->name,idp->name)==0)
        {
            ovsrec_port_set_admin(port_row,"down");
        }
    }
    ovsdb_idl_txn_commit_block(txn);
    ovsdb_idl_txn_destroy(txn);
    MSTP_OVSDB_UNLOCK;
}
/**PROC+***********************************************************
 * Name:   enable_logical_port
 *
 * Purpose:  to set a port row to admin status to up.
 *
 * Params:    none
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/

void enable_logical_port(int lport)
{
    struct ovsdb_idl_txn *txn = NULL;
    struct iface_data *idp = NULL;
    const struct ovsrec_port *port_row = NULL;
    txn = ovsdb_idl_txn_create(idl);
    idp = find_iface_data_by_index(lport);
    MSTP_OVSDB_LOCK;
    OVSREC_PORT_FOR_EACH(port_row,idl)
    {
        if(strcmp(port_row->name,idp->name)==0)
        {
            ovsrec_port_set_admin(port_row,"up");
        }
    }
    ovsdb_idl_txn_commit_block(txn);
    ovsdb_idl_txn_destroy(txn);
    MSTP_OVSDB_UNLOCK;
}

/**PROC+***********************************************************
 * Name:    enable_or_disable_port
 *
 * Purpose:  to set a port row to admin status to up or down.
 *
 * Params:    lport - port to be enabled / disabled
 *            enable - operation to be performed
 *
 * Returns:   none
 *
 **PROC-*****************************************************************/
void enable_or_disable_port(int lport,bool enable)
{
    struct ovsdb_idl_txn *txn = NULL;
    struct iface_data *idp = NULL;
    const struct ovsrec_port *port_row = NULL;
    txn = ovsdb_idl_txn_create(idl);
    idp = find_iface_data_by_index(lport);
    MSTP_OVSDB_LOCK;
    OVSREC_PORT_FOR_EACH(port_row,idl)
    {
        if(strcmp(port_row->name,idp->name)==0)
        {
            if(enable)
                ovsrec_port_set_admin(port_row,"up");
            else
                ovsrec_port_set_admin(port_row,"down");
        }
    }
    ovsdb_idl_txn_commit_block(txn);
    ovsdb_idl_txn_destroy(txn);
    MSTP_OVSDB_UNLOCK;
}
