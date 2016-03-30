/*
 * (c) Copyright 2015 Hewlett Packard Enterprise Development LP
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

#ifndef __MSTP_CMN_H__
#define __MSTP_CMN_H__
#include "mstp_fsm.h"
typedef enum mstpd_message_type_enum {
    e_mstpd_timer=1,
    e_mstpd_lport_up,
    e_mstpd_lport_down,
    e_mstpd_rx_bpdu,
    e_mstpd_lport_add,
    e_mstpd_lport_delete,
    e_mstpd_admin_status,
    e_mstpd_vlan_add,
    e_mstpd_vlan_delete,
    e_mstpd_msti_config_update,
    e_mstpd_global_config,
    e_mstpd_cist_config,
    e_mstpd_cist_port_config,
    e_mstpd_msti_config,
    e_mstpd_msti_port_config,
    e_mstpd_msti_config_delete
} mstpd_message_type;

typedef struct mstp_lport_state_change {
    char *lportname;
    int lportindex;
} mstp_lport_state_change;

typedef struct mstp_lport_add {
    char *lportname;
    int lportindex;
} mstp_lport_add;

typedef struct mstp_lport_delete {
    char *lportname;
    int lportindex;
} mstp_lport_delete;

typedef struct mstp_vlan_add {
    char *name;
    int vid;
} mstp_vlan_add;

typedef struct mstp_vlan_delete {
    char *name;
    int vid;
} mstp_vlan_delete;

typedef struct mstp_admin_status {
    bool status;
} mstp_admin_status;

typedef struct mstp_pkt_recv {
    uint32_t logicalport;
    void *msg;
} mstp_pkt_recv;

typedef struct mstp_config_update {
    void *msg;
} mstp_config_update;

typedef struct mstp_msti_config_delete {
    int mstid;
} mstp_msti_config_delete;

typedef struct mstpd_message_struct
{
    mstpd_message_type msg_type;
    void *msg;

} mstpd_message;

extern int mstpd_send_event(mstpd_message *pmsg);
extern mstpd_message* mstpd_wait_for_next_event(void);
extern void mstpd_event_free(mstpd_message *pmsg);
extern void mstp_processLportUpEvent(mstpd_message *msg);
extern void mstp_processLportDownEvent(mstpd_message *msg);
extern void update_mstp_global_config(mstpd_message *msg);
extern void update_mstp_cist_config(mstpd_message *msg);
extern void update_mstp_cist_port_config(mstpd_message *msg);
extern void update_mstp_msti_config(mstpd_message *msg);
extern void update_mstp_msti_port_config(mstpd_message *msg);
extern void delete_mstp_msti_config(mstpd_message *msg);
#endif  // __MSTP_CMN_H__
