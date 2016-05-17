/* Copyright (C) 2015 Hewlett-Packard Development Company, L.P.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SWITCHD_STP_H
#define SWITCHD_STP_H 1

#include <netinet/in.h>
#include "hmap.h"
#include "vswitch-idl.h"
#include "dynamic-string.h"
#include "reconfigure-blocks.h"

#define SWITCHD_STP_PLUGIN_NAME "STP"
#define MSTP_CIST 0
#define MSTP_DEFAULT_STG_GROUP 1
#define MSTP_INST_MIN 1
#define MSTP_INST_MAX 64
#define MSTP_INST_VALID(v)  ((v)>=MSTP_INST_MIN && (v)<=MSTP_INST_MAX)
#define MSTP_CIST_INST_VALID(v)  ((v)>=MSTP_CIST && (v)<=MSTP_INST_MAX)
#define MSTP_STR_EQ(s1, s2) ((strlen((s1)) == strlen((s2))) && (!strncmp((s1), (s2), strlen((s2)))))

struct stp_blk_params{
    struct ovsdb_idl *idl;   /* OVSDB IDL handler */
    const struct ovsrec_bridge *cfg;
};

union mstp_cfg {
        const struct ovsrec_mstp_instance *msti_cfg;
        const struct ovsrec_mstp_common_instance *cist_cfg;
};

union mstp_port_cfg {
        const struct ovsrec_mstp_instance_port *msti_port_cfg;
        const struct ovsrec_mstp_common_instance_port *cist_port_cfg;
};


typedef enum mstp_instance_port_state {
    MSTP_INST_PORT_STATE_DISABLED = 0,
    MSTP_INST_PORT_STATE_BLOCKED,
    MSTP_INST_PORT_STATE_LEARNING,
    MSTP_INST_PORT_STATE_FORWARDING,
    MSTP_INST_PORT_STATE_INVALID,
}mstp_instance_port_state_t;

struct mstp_instance_port_interfaces {
    struct hmap_node hmap_node;  /* Element in struct mstp_instance_port "interfaces" hmap. */
    char *name;
    int stp_state;
};

struct mstp_instance_port {
    struct hmap_node hmap_node; /* Element in struct mstp_instance's "ports" hmap. */
    char *name;
    int stp_state;
    union  mstp_port_cfg cfg;
    struct hmap interfaces;
    int nb_interfaces;
};

struct mstp_instance_vlan {
    struct hmap_node hmap_node;  /* In struct mstp_instance's "vlans" hmap. */
    char *name;
    int vid;
};

struct mstp_instance {
    struct hmap_node node;
    int instance_id;
    struct hmap vlans;
    int nb_vlans;
    struct hmap ports;
    int nb_ports;
    union  mstp_cfg cfg;
    int hw_stg_id;
};

void mstp_cist_and_instance_port_interfaces_add(
                       struct mstp_instance_port *mstp_port,
                       const struct ovsrec_interface *ifconfig);
void mstp_cist_and_instance_port_interfaces_delete(
                                   struct mstp_instance *msti,
                                   struct mstp_instance_port *mstp_port,
                                   struct mstp_instance_port_interfaces *pintf);
bool mstp_cist_and_instance_add_del_instance_port_interfaces(
                                  struct mstp_instance *msti,
                                  struct mstp_instance_port *mstp_port);

void mstp_cist_and_instance_vlan_add(const struct stp_blk_params *br,
                                            struct mstp_instance *msti,
                                           const struct ovsrec_vlan *vlan_cfg);
void mstp_cist_and_instance_vlan_delete(const struct stp_blk_params *br,
                                              struct mstp_instance *msti,
                                              struct mstp_instance_vlan *vlan);
void mstp_cist_and_instance_set_port_state(const struct stp_blk_params *br,
                                                 struct mstp_instance *msti,
                                         struct mstp_instance_port *mstp_port);
void mstp_cist_and_instance_port_delete(const struct stp_blk_params *br,
                                              struct mstp_instance *msti,
                                              struct mstp_instance_port *port);
void mstp_instance_add_del_vlans(const struct stp_blk_params *br,
                                       struct mstp_instance *msti);

void mstp_instance_port_add(const struct stp_blk_params *br,
                                 struct mstp_instance *msti,
                        const struct ovsrec_mstp_instance_port *inst_port_cfg);

void mstp_instance_add_del_ports(const struct stp_blk_params *br,
                                       struct mstp_instance *msti);
void mstp_instance_create(const struct stp_blk_params *br, int inst_id,
                              const struct ovsrec_mstp_instance *msti_cfg);
void mstp_instance_delete(const struct stp_blk_params* br,
                              struct mstp_instance *msti);
void mstp_instance_update(struct stp_blk_params *br_blk_params,
                          struct mstp_instance *msti);
void mstp_add_del_instances(const struct stp_blk_params *br);
void mstp_cist_port_add(const struct stp_blk_params *br,
                            struct mstp_instance *msti,
                 const struct ovsrec_mstp_common_instance_port *cist_port_cfg);
void mstp_cist_configure_ports(const struct stp_blk_params *br,
                                 struct mstp_instance *msti);
void mstp_cist_add_del_vlans(const struct stp_blk_params *br,
                                  struct mstp_instance *msti);
void mstp_cist_create(const struct stp_blk_params *br,
                      const struct ovsrec_mstp_common_instance *msti_cist_cfg);
void mstp_cist_update(const struct stp_blk_params *br_blk_params);
void mstp_update_instances(struct stp_blk_params *br_blk_params);
void stp_reconfigure(struct blk_params*);
void stp_plugin_dump_data(struct ds *ds, int argc, const char *argv[]);

#endif /* switchd_stp.h */
