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

#include <sys/types.h>
#include <dynamic-string.h>

extern void mstpd_ovsdb_init(const char *db_path);
extern void mstpd_ovsdb_exit(void);
extern void mstpd_debug_dump(struct ds *ds, int argc, const char *argv[]);

extern void *mstpd_rx_pdu_thread(void *data);
extern int register_stp_mcast_addr(int ifindex);
extern void deregister_stp_mcast_addr(int ifindex);
extern void *mstpd_protocol_thread(void *arg);
extern int mmstp_init(u_long);
#endif /* _MSTP_H_ */
