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

#ifndef _MSTP_H_
#define _MSTP_H_

#include <unixctl.h>
#include <sys/types.h>
#include <dynamic-string.h>

void mstpd_ovsdb_init(const char *db_path);
void mstpd_ovsdb_exit(void);
void mstpd_cist_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED);
void mstpd_cist_data_dump(struct ds *ds, int argc, const char *argv[]);
void mstpd_cist_port_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED);
void mstpd_cist_port_data_dump(struct ds *ds, int argc, const char *argv[]);
void mstpd_msti_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED);
void mstpd_msti_data_dump(struct ds *ds, int argc, const char *argv[]);
void mstpd_msti_port_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED);
void mstpd_msti_port_data_dump(struct ds *ds, int argc, const char *argv[]);
void mstpd_daemon_cist_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED);
void mstpd_daemon_cist_data_dump(struct ds *ds, int argc, const char *argv[]);
void mstpd_daemon_cist_port_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED);
void mstpd_daemon_cist_port_data_dump(struct ds *ds, int argc, const char *argv[]);
void mstpd_daemon_msti_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED);
void mstpd_daemon_msti_data_dump(struct ds *ds, int argc, const char *argv[]);
void mstpd_daemon_msti_port_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED);
void mstpd_daemon_msti_port_data_dump(struct ds *ds, int argc, const char *argv[]);
void mstpd_daemon_comm_port_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED);
void mstpd_daemon_comm_port_data_dump(struct ds *ds, int argc, const char *argv[]);
void mstpd_daemon_debug_sm_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED);
void mstpd_daemon_debug_sm_data_dump(struct ds *ds, int argc, const char *argv[]);
void mstpd_daemon_digest_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED);
void mstpd_daemon_digest_data_dump(struct ds *ds, int argc, const char *argv[]);

void *mstpd_rx_pdu_thread(void *data);
int register_stp_mcast_addr(int ifindex);
void deregister_stp_mcast_addr(int ifindex);
void *mstpd_protocol_thread(void *arg);
int mmstp_init(u_long);
#endif /* _MSTP_H_ */
