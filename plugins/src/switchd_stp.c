/* Copyright (C) 2016 Hewlett-Packard Development Company, L.P.
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

/* @file switchd_stp.c
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "hash.h"
#include "hmap.h"
#include "shash.h"
#include "vswitch-idl.h"
#include "openswitch-idl.h"
#include "ofproto/ofproto.h"
#include "openvswitch/vlog.h"
#include "plugin-extensions.h"
#include "asic-plugin.h"
#include "switchd_stp.h"

VLOG_DEFINE_THIS_MODULE(switchd_stp);

#define INSTANCE_STRING_LEN 10

struct hmap all_mstp_instances = HMAP_INITIALIZER(&all_mstp_instances);
static struct asic_plugin_interface *p_asic_plugin_interface = NULL;
const char *port_state_str[] = {"Disabled", "Blocking", "Learning",
                                "Forwarding", "Invalid"};

/*------------------------------------------------------------------------------
| Function:  get_asic_plugin_interface
| Description: get the asic plugin interface object
| Parameters[in]:
| Parameters[out]: port_state:- object conatins port state enum mstp_instance_port_state
| Return: True if valid port state else false.
-----------------------------------------------------------------------------*/
struct asic_plugin_interface *
get_asic_plugin_interface(void)
{
    struct plugin_extension_interface *p_extension;

    /* check asic plugin exists */
    if (p_asic_plugin_interface) {
        return p_asic_plugin_interface;
    }

    if (!find_plugin_extension(ASIC_PLUGIN_INTERFACE_NAME,
                               ASIC_PLUGIN_INTERFACE_MAJOR,
                               ASIC_PLUGIN_INTERFACE_MINOR,
                              &p_extension)) {
       if (NULL != p_extension) {
           p_asic_plugin_interface = p_extension->plugin_interface;
           return p_asic_plugin_interface;
       }
       else {
           return NULL;
       }
    }
    else {
        return NULL;
    }
}

/*------------------------------------------------------------------------------
| Function:  get_port_state_from_string
| Description: get the port state
| Parameters[in]: portstate_str: string  contains port name
| Parameters[out]: port_state:- object conatins port state enum mstp_instance_port_state
| Return: True if valid port state else false.
-----------------------------------------------------------------------------*/
bool
get_port_state_from_string(const char *portstate_str, int *port_state)
{
    bool retval = false;

    if (!portstate_str || !port_state) {
        VLOG_DBG("%s: invalid param", __FUNCTION__);
        return retval;
    }

    VLOG_DBG("%s: entry port state %s", __FUNCTION__, portstate_str);
    if (!strcmp(portstate_str,
                OVSREC_MSTP_COMMON_INSTANCE_PORT_PORT_STATE_BLOCKING)) {
        *port_state = MSTP_INST_PORT_STATE_BLOCKED;
        retval = true;
    } else if (!strcmp(portstate_str,
                       OVSREC_MSTP_INSTANCE_PORT_PORT_STATE_DISABLED)) {
        *port_state = MSTP_INST_PORT_STATE_DISABLED;
        retval = true;
    } else if (!strcmp(portstate_str,
                       OVSREC_MSTP_INSTANCE_PORT_PORT_STATE_LEARNING)) {
        *port_state = MSTP_INST_PORT_STATE_LEARNING;
        retval = true;
    } else if (!strcmp(portstate_str,
                       OVSREC_MSTP_INSTANCE_PORT_PORT_STATE_FORWARDING)) {
        *port_state = MSTP_INST_PORT_STATE_FORWARDING;
        retval = true;
    } else {
        *port_state = MSTP_INST_PORT_STATE_INVALID;
        retval = false;
    }

    VLOG_DBG("%s: exit port state val %d retval %d",
             __FUNCTION__, *port_state, retval);
    return retval;
}

/*------------------------------------------------------------------------------
| Function:  mstp_inform_stp_global_port_state
| Description:  validates to inform stp port state globally
| Parameters[in]: blk params :-object contains idl, ofproro, bridge cfg
| Parameters[in]: mstp_instance object
| Parameters[in]: mstp_instance_port object
| Parameters[out]: None
| Return:  True if it's single instance,
|                  multi instance: port blocked in all mstp instances
-----------------------------------------------------------------------------*/
bool
mstp_inform_stp_global_port_state(const struct stp_blk_params *br,
                                        struct mstp_instance *msti,
                                        struct mstp_instance_port *mstp_port)
{
    int msti_count = 0;
    int port_state;
    bool block_all_msti = false;
    const char *data = NULL;
    const struct ovsrec_port *port_cfg = NULL;

    if (!br || !msti || !mstp_port) {
        VLOG_DBG("%s: invalid param", __FUNCTION__);
        return false;
    }

    msti_count = br->cfg->n_mstp_instances;
    port_state = mstp_port->stp_state;

    /* check for single instance, CIST only */
    if (msti_count == 0) {
        if ((MSTP_INST_PORT_STATE_BLOCKED == port_state) ||
            (MSTP_INST_PORT_STATE_FORWARDING == port_state)) {
            return true;
        }
        else {
            return false;
        }
    }

    /* get the port row config */
    if (msti->instance_id == MSTP_CIST) {
        port_cfg = mstp_port->cfg.cist_port_cfg->port;
    }
    else {
        port_cfg = mstp_port->cfg.msti_port_cfg->port;
    }

    /* get block_all_mstp key value from port row hw_config column */
    data = smap_get(&port_cfg->hw_config, "block_all_mstp");
    if (data && (MSTP_STR_EQ(data, "true"))) {
        block_all_msti = true;
    }
    else {
        if(data && (MSTP_STR_EQ(data, "false"))) {
           block_all_msti = false;
        }
    }

    if(block_all_msti && (MSTP_INST_PORT_STATE_BLOCKED == port_state)) {
        return true;
    }

    if ((!block_all_msti) && (MSTP_INST_PORT_STATE_FORWARDING == port_state)) {
        return true;
    }

    return false;
}

/*-----------------------------------------------------------------------------
| Function:  mstp_cist_and_instance_vlan_add
| Description:  Add vlan to cist or msti
| Parameters[in]: blk params :-object contains idl, ofproro, bridge cfg
| Parameters[in]: mstp_instance object
| Parameters[in]: ovsrec_vlan object
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/
void
mstp_cist_and_instance_vlan_add(const struct stp_blk_params *br,
                                       struct mstp_instance *msti,
                                       const struct ovsrec_vlan *vlan_cfg )
{
    struct mstp_instance_vlan *new_vlan = NULL;
    struct asic_plugin_interface *p_asic_interface = NULL;

    if (!br || !msti || !vlan_cfg) {
        VLOG_DBG("%s: invalid param", __FUNCTION__);
        return;
    }

    VLOG_DBG("%s: entry inst %d", __FUNCTION__, msti->instance_id);

    /* Allocate structure to save state information for this VLAN. */
    new_vlan = xzalloc(sizeof(struct mstp_instance_vlan));
    if (!new_vlan) {
        VLOG_ERR("%s: Failed to allocate memory for vlan %ld in instance %d",
                  __FUNCTION__, vlan_cfg->id, msti->instance_id);
        return;
    }

    hmap_insert(&msti->vlans, &new_vlan->hmap_node,
                hash_string(vlan_cfg->name, 0));

    new_vlan->vid = (int)vlan_cfg->id;
    new_vlan->name = xstrdup(vlan_cfg->name);
    msti->nb_vlans++;
    VLOG_DBG("%s:  add vlan %d to stg %d", __FUNCTION__, new_vlan->vid,
                                              msti->hw_stg_id);

    p_asic_interface = get_asic_plugin_interface();
    if(p_asic_interface) {
        p_asic_interface->add_stg_vlan(msti->hw_stg_id, new_vlan->vid);
    }
    else {
        VLOG_ERR("%s: unable to find asic plugin interface",__FUNCTION__);
    }
}

/*-----------------------------------------------------------------------------
| Function:  mstp_cist_and_instance_vlan_delete
| Description: delete vlan from cist or msti
| Parameters[in]: blk params :-object contains idl, ofproro, bridge cfg
| Parameters[in]: mstp_instance object
| Parameters[in]: mstp_instance_vlan object
| Parameters[out]: None
| Return:
-----------------------------------------------------------------------------*/
void
mstp_cist_and_instance_vlan_delete(const struct stp_blk_params *br,
                                         struct mstp_instance *msti,
                                         struct mstp_instance_vlan *vlan)
{
    int vid;
    struct asic_plugin_interface *p_asic_interface = NULL;

    if (!br || !msti || !vlan) {
        VLOG_DBG("%s: invalid param", __FUNCTION__);
        return;
    }

    VLOG_DBG("%s:entry vlan %d inst %d", __FUNCTION__, vlan->vid,
                                          msti->instance_id);
    vid = vlan->vid;
    hmap_remove(&msti->vlans, &vlan->hmap_node);
    free(vlan->name);
    free(vlan);
    msti->nb_vlans--;
    VLOG_DBG("%s:  remove vlan %d to stg %d", __FUNCTION__, vid,
                                              msti->hw_stg_id);

    p_asic_interface = get_asic_plugin_interface();
    if(p_asic_interface) {
        p_asic_interface->remove_stg_vlan(msti->hw_stg_id, vid);
    }
    else {
        VLOG_ERR("%s: unable to find asic plugin interface",__FUNCTION__);
    }
}

/*-----------------------------------------------------------------------------
| Function: mstp_cist_and_instance_vlan_lookup
| Description: find vlan in cist/mst
| Parameters[in]: mstp_instance object
| Parameters[in]: vlan name
| Parameters[out]: None
| Return: mstp_instance_vlan object
-----------------------------------------------------------------------------*/
static struct mstp_instance_vlan *
mstp_cist_and_instance_vlan_lookup(const struct mstp_instance *msti,
                                          const char *name)
{
    struct mstp_instance_vlan *vlan;

    if (!msti || !name) {
        VLOG_DBG("%s: invalid param", __FUNCTION__);
        return NULL;
    }

    VLOG_DBG("%s: entry inst %d vlan name %s", __FUNCTION__,
                                             msti->instance_id, name);

    HMAP_FOR_EACH_WITH_HASH (vlan, hmap_node, hash_string(name, 0),
                             &msti->vlans) {
        if (!strcmp(vlan->name, name)) {
            return vlan;
        }
    }
    return NULL;
}

/*-----------------------------------------------------------------------------
| Function: mstp_instance_add_del_vlans
| Description: add or delete vlan in mstp instance
| Parameters[in]: blk params :-object contains idl, ofproro, bridge cfg
| Parameters[in]: mstp_instance object
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/
void
mstp_instance_add_del_vlans(const struct stp_blk_params *br,
                                  struct mstp_instance *msti)
{
    size_t i;
    struct mstp_instance_vlan *vlan, *next;
    struct shash sh_idl_vlans;
    struct shash_node *sh_node;

    if (!msti || !br) {
        VLOG_DBG("%s: invalid param", __FUNCTION__);
        return;
    }
    VLOG_DBG("%s: entry inst %d", __FUNCTION__, msti->instance_id);

    /* Collect all Instance VLANs present in the DB. */
    shash_init(&sh_idl_vlans);
    for (i = 0; i < msti->cfg.msti_cfg->n_vlans; i++) {
        const char *name = msti->cfg.msti_cfg->vlans[i]->name;
        if (!shash_add_once(&sh_idl_vlans, name,
                            msti->cfg.msti_cfg->vlans[i])) {
            VLOG_WARN("%s:instance id %d: %s specified twice as msti VLAN",
                      __FUNCTION__, msti->instance_id, name);
        }
    }

    /* Delete old Instance VLANs. */
    HMAP_FOR_EACH_SAFE (vlan, next, hmap_node, &msti->vlans) {
        const struct ovsrec_vlan *vlan_cfg;

        vlan_cfg = shash_find_data(&sh_idl_vlans, vlan->name);
        if (!vlan_cfg) {
            VLOG_DBG("%s:Found a deleted vlan %s in msti %d", __FUNCTION__,
                     vlan->name, msti->instance_id);
            mstp_cist_and_instance_vlan_delete(br, msti, vlan);
        }
    }

    /* Add new VLANs. */
    SHASH_FOR_EACH (sh_node, &sh_idl_vlans) {
        vlan = mstp_cist_and_instance_vlan_lookup(msti, sh_node->name);
        if (!vlan) {
            VLOG_DBG("%s:Found an added vlan %s in msti %d", __FUNCTION__,
                     sh_node->name, msti->instance_id);
            mstp_cist_and_instance_vlan_add(br, msti, sh_node->data);
        }
    }

    /* Destroy the shash of the IDL vlans */
    shash_destroy(&sh_idl_vlans);

}

/*------------------------------------------------------------------------------
| Function:  mstp_cist_and_instance_set_port_state
| Description:  set port state in cist/msti
| Parameters[in]: blk params :-object contains idl, ofproro, bridge cfg
| Parameters[in]: mstp_instance object
| Parameters[in]: mstp_instance_port object
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/
void
mstp_cist_and_instance_set_port_state(const struct stp_blk_params *br,
                                            struct mstp_instance *msti,
                                          struct mstp_instance_port *mstp_port)
{
    struct asic_plugin_interface *p_asic_interface = NULL;
    bool inform_stp_state = false;

    if (!msti || !br || !mstp_port) {
        VLOG_DBG("%s: invalid param", __FUNCTION__);
        return;
    }

    inform_stp_state = mstp_inform_stp_global_port_state(br, msti, mstp_port);
    VLOG_DBG("%s: stg %d port name %s state %d inform_state %s", __FUNCTION__,
             msti->hw_stg_id, mstp_port->name, mstp_port->stp_state,
             ((inform_stp_state)?"true":"false"));

    p_asic_interface = get_asic_plugin_interface();
    if(p_asic_interface) {
        p_asic_interface->set_stg_port_state(mstp_port->name, msti->hw_stg_id,
                                             mstp_port->stp_state,
                                             inform_stp_state);
    }
    else {
        VLOG_ERR("%s: unable to find asic plugin interface",__FUNCTION__);
    }
}

/*------------------------------------------------------------------------------
| Function:   mstp_instance_port_add
| Description: add port to msti
| Parameters[in]: blk params :-object contains idl, ofproro, bridge cfg
| Parameters[in]: mstp_instance_object
| Parameters[in]:  ovsrec_mstp_instance_port object
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/
void
mstp_instance_port_add(const struct stp_blk_params *br,
                            struct mstp_instance *msti,
                         const struct ovsrec_mstp_instance_port *inst_port_cfg)
{
        struct mstp_instance_port *new_port = NULL;
        bool retval = false;
        int port_state;

        if (!msti || !br || !inst_port_cfg) {
            VLOG_DBG("%s: invalid param", __FUNCTION__);
            return;
        }

        VLOG_DBG("%s: entry inst %d", __FUNCTION__, msti->instance_id);

        /* Allocate structure to save state information for this port. */
        new_port = xzalloc(sizeof(struct mstp_instance_port));
        if (!new_port) {
           VLOG_ERR("%s: Failed to allocate memory for port %s in instance %d",
                    __FUNCTION__, inst_port_cfg->port->name, msti->instance_id);
           return;
        }

        hmap_insert(&msti->ports, &new_port->hmap_node,
                    hash_string(inst_port_cfg->port->name, 0));

        new_port->name = xstrdup(inst_port_cfg->port->name);

        retval = get_port_state_from_string(inst_port_cfg->port_state,
                                            &port_state);
        if(false == retval) {
            VLOG_DBG("%s:invalid inst id %d port %s state %s", __FUNCTION__,
                     msti->instance_id, new_port->name, inst_port_cfg->port_state);
            new_port->stp_state = MSTP_INST_PORT_STATE_INVALID;;
            new_port->cfg.msti_port_cfg = inst_port_cfg;
            return;
        }
        new_port->stp_state = port_state;
        new_port->cfg.msti_port_cfg = inst_port_cfg;
        msti->nb_ports++;
        mstp_cist_and_instance_set_port_state(br, msti, new_port);
}

/*-----------------------------------------------------------------------------
| Function:  mstp_cist_and_instance_port_delete
| Description: delete port from cist/msti
| Parameters[in]: blk params :-object contains idl, ofproro, bridge cfg
| Parameters[in]: mstp_instance object
| Parameters[in]: mstp_instance_port object
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/
void
mstp_cist_and_instance_port_delete(const struct stp_blk_params *br,
                                         struct mstp_instance *msti,
                                         struct mstp_instance_port *port)
{


    if (!msti || !br || !port) {
        VLOG_DBG("%s: invalid param", __FUNCTION__);
        return;
    }
    VLOG_DBG("%s: entry inst %d port name %s", __FUNCTION__, msti->instance_id,
             port->name);

    if (port) {
        hmap_remove(&msti->ports, &port->hmap_node);
        free(port->name);
        free(port);
        msti->nb_ports--;
    }

}

/*-----------------------------------------------------------------------------
| Function:  mstp_cist_and_instance_port_lookup
| Description: find port in cist/msti
| Parameters[in]:mstp_instance object
| Parameters[in]: port name
| Parameters[out]: None
| Return:
-----------------------------------------------------------------------------*/
static struct mstp_instance_port *
mstp_cist_and_instance_port_lookup(const struct mstp_instance *msti,
                                          const char *name)
{
    struct mstp_instance_port *port;

    if (!msti || !name) {
        VLOG_DBG("%s: invalid param", __FUNCTION__);
        return NULL;
    }
    VLOG_DBG("%s: inst %d port name %s", __FUNCTION__,
             msti->instance_id, name);

    HMAP_FOR_EACH_WITH_HASH (port, hmap_node, hash_string(name, 0),
                             &msti->ports) {
        if (!strcmp(port->name, name)) {
            return port;
        }
    }
    return NULL;
}

/*------------------------------------------------------------------------------
| Function:  mstp_instance_add_del_ports
| Description: add/del ports from msti
| Parameters[in]: blk params :-object contains idl, ofproro, bridge cfg
| Parameters[in]: mstp_instance object
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/
void
mstp_instance_add_del_ports(const struct stp_blk_params *br,
                                  struct mstp_instance *msti)
{
    size_t i;
    struct mstp_instance_port *inst_port, *next;
    struct shash sh_idl_ports;
    struct shash_node *sh_node;

    if (!msti || !br) {
        VLOG_DBG("%s: invalid param", __FUNCTION__);
        return;
    }

    VLOG_DBG("%s: inst %d", __FUNCTION__, msti->instance_id);

    /* Collect all Instance Ports present in the DB. */
    shash_init(&sh_idl_ports);
    for (i = 0; i < msti->cfg.msti_cfg->n_mstp_instance_ports; i++) {
        const char *name = msti->cfg.msti_cfg->mstp_instance_ports[i]->port->name;
        if (!shash_add_once(&sh_idl_ports, name,
                            msti->cfg.msti_cfg->mstp_instance_ports[i])) {
            VLOG_WARN("mstp instance id %d: %s specified twice as msti port",
                      msti->instance_id, name);
        }
    }

    /* Delete old Instance Ports. */
    HMAP_FOR_EACH_SAFE (inst_port, next, hmap_node, &msti->ports) {
        const struct ovsrec_mstp_instance_port *port_cfg;

        port_cfg = shash_find_data(&sh_idl_ports, inst_port->name);
        if (!port_cfg) {
            VLOG_DBG("Found a deleted Port %s in instance %d",
                     inst_port->name, msti->instance_id);
            mstp_cist_and_instance_port_delete(br, msti, inst_port);
        }
    }

    /* Add new instance ports. */
    SHASH_FOR_EACH (sh_node, &sh_idl_ports) {
        inst_port = mstp_cist_and_instance_port_lookup(msti, sh_node->name);
        if (!inst_port) {
            VLOG_DBG("Found an added Port %s for instance %d",
                     sh_node->name, msti->instance_id);
            mstp_instance_port_add(br, msti, sh_node->data);
        }
    }

    /* Destroy the shash of the IDL ports */
    shash_destroy(&sh_idl_ports);

}

/*-----------------------------------------------------------------------------
| Function:  mstp_instance_create
| Description:  create new mstp instance  object
| Parameters[in]: blk params :-object contains idl, ofproro, bridge cfg
| Parameters[in]: inst_id : instance id
| Parameters[in]: ovsrec_mstp_instance object
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/
void
mstp_instance_create(const struct stp_blk_params *br, int inst_id,
                         const struct ovsrec_mstp_instance *msti_cfg)
{
    struct mstp_instance *msti;
    int stg;
    char inst_id_string[INSTANCE_STRING_LEN] = "";
    struct asic_plugin_interface *p_asic_interface = NULL;

    if (!msti_cfg || !br) {
        VLOG_DBG("%s: invalid param", __FUNCTION__);
        return;
    }

    VLOG_DBG("%s: instid %d", __FUNCTION__, inst_id);

    if (false == MSTP_INST_VALID(inst_id)) {
        VLOG_DBG("%s: invalid instance id %d", __FUNCTION__, inst_id);
        return;
    }

    p_asic_interface = get_asic_plugin_interface();
    if(!p_asic_interface) {
        VLOG_ERR("%s: unable to find asic plugin interface",__FUNCTION__);
        return;
    }

    msti = xzalloc(sizeof *msti);
    if (!msti) {
        VLOG_ERR("%s: Failed to allocate memory for instance id %d",
                 __FUNCTION__, inst_id);
        return;
    }

    msti->instance_id = inst_id;
    msti->cfg.msti_cfg= msti_cfg;
    hmap_init(&msti->vlans);
    hmap_init(&msti->ports);
    snprintf(inst_id_string, sizeof(inst_id_string), "mist%d", inst_id);
    hmap_insert(&all_mstp_instances, &msti->node, hash_string(inst_id_string, 0));

    p_asic_interface->create_stg(&stg);

    msti->hw_stg_id = stg;
    msti->nb_vlans = 0;
    msti->nb_ports = 0;
    /* msti_cfg->hardware_grp_id = stg; */
    VLOG_DBG("%s: created stg %d", __FUNCTION__, msti->hw_stg_id);

    mstp_instance_add_del_vlans(br, msti);
    mstp_instance_add_del_ports(br, msti);
}

/*-----------------------------------------------------------------------------
| Function:  mstp_instance_delete
| Description: delete instance from msti
| Parameters[in]: blk params :-object contains idl, ofproro, bridge cfg
| Parameters[in]: mstp_instance object
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/
void
mstp_instance_delete(const struct stp_blk_params* br,
                         struct mstp_instance *msti)
{
    struct asic_plugin_interface *p_asic_interface = NULL;

    if (!msti || !br) {
        VLOG_DBG("%s: invalid param", __FUNCTION__);
        return;
    }

    VLOG_DBG("%s: inst %d", __FUNCTION__, msti->instance_id);

    p_asic_interface = get_asic_plugin_interface();
    if(!p_asic_interface) {
        VLOG_ERR("%s: unable to find asic plugin interface",__FUNCTION__);
        return;
    }

    if (msti) {
        hmap_remove(&all_mstp_instances, &msti->node);
        hmap_destroy(&msti->vlans);
        hmap_destroy(&msti->ports);
        free(msti);

        VLOG_DBG("%s: delete stg %d", __FUNCTION__, msti->hw_stg_id);
        p_asic_interface->delete_stg(msti->hw_stg_id);
    }

}

/*-----------------------------------------------------------------------------
| Function:  mstp_instance_update
| Description: updates port state in msti
| Parameters[in]: blk params :-object contains idl, ofproro, bridge cfg
| Parameters[in]: mstp_instance object
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/
void
mstp_instance_update(struct stp_blk_params *br_blk_params,
                          struct mstp_instance *msti)
{
    struct mstp_instance_port *inst_port;
    int new_port_state;
    bool retval;
    const  struct ovsrec_mstp_instance *p_mist_row;

    if (!msti || !br_blk_params) {
        VLOG_DBG("%s: invalid param", __FUNCTION__);
        return;
    }

    p_mist_row = msti->cfg.msti_cfg;

    if (!p_mist_row) {
        VLOG_DBG("%s: invalid mist cfg row", __FUNCTION__);
        return;
    }

    VLOG_DBG("%s: entry inst id %d", __FUNCTION__, msti->instance_id);

    /* Check for changes in the vlan row entries. */
    /* check if any vlans added or deleted */
    mstp_instance_add_del_vlans(br_blk_params, msti);

    /* Check for changes in the port row entries. */
    HMAP_FOR_EACH (inst_port, hmap_node, &msti->ports) {
        const struct ovsrec_mstp_instance_port *inst_port_row =
                                                inst_port->cfg.msti_port_cfg;

        // Check for port state changes.
        retval =  get_port_state_from_string(inst_port_row->port_state,
                                             &new_port_state);
        if (false == retval) {
            VLOG_DBG("%s:-invalid port state", __FUNCTION__);
            continue;
        }

        if(new_port_state != inst_port->stp_state) {
            VLOG_DBG("%s: Set mstp instance %d port %s state to %s",
                     __FUNCTION__,
                     msti->instance_id, inst_port->name,
                     inst_port_row->port_state);
            inst_port->stp_state = new_port_state;
            mstp_cist_and_instance_set_port_state(br_blk_params,
                                                  msti, inst_port);
        }
        else {
            VLOG_DBG("%s: No chnage in mstp instance %d port %s state" ,
                     __FUNCTION__,
                     msti->instance_id, inst_port->name);
        }
    }

}

/*-----------------------------------------------------------------------------
| Function:  mstp_cist_and_instance_lookup
| Description: find instance in mstp_instances data
| Parameters[in]: inst_id:- instance
| Parameters[out]: None
| Return: mstp_instance object
-----------------------------------------------------------------------------*/
static struct mstp_instance *
mstp_cist_and_instance_lookup(int inst_id)
{
    struct mstp_instance *msti;
    char inst_id_string[INSTANCE_STRING_LEN] = "";

    if (false == MSTP_CIST_INST_VALID(inst_id)) {
        VLOG_DBG("%s: invalid instance id %d", __FUNCTION__, inst_id);
        return NULL;
    }
    if (MSTP_CIST == inst_id) {
        snprintf(inst_id_string, sizeof(inst_id_string), "cist");
    }
    else {
        snprintf(inst_id_string, sizeof(inst_id_string), "mist%d", inst_id);
    }
    HMAP_FOR_EACH_WITH_HASH (msti, node, hash_string(inst_id_string, 0),
                             &all_mstp_instances) {
        if (inst_id == msti->instance_id) {
            return msti;
        }
    }
    return NULL;
}

/*-----------------------------------------------------------------------------
| Function:  mstp_add_del_instances
| Description: add/del instances from msti
| Parameters[in]: blk params :-object contains idl, ofproro, bridge cfg
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/
void
mstp_add_del_instances(const struct stp_blk_params *br)
{
    struct mstp_instance *msti, *next_msti;
    struct shash new_msti;
    const struct ovsrec_bridge *bridge_row = br->cfg;
    size_t i;

    if (!br) {
        VLOG_DBG("%s: invalid param", __FUNCTION__);
        return;
    }

    VLOG_DBG("%s: entry", __FUNCTION__);

    /* Collect new instance  id's */
    shash_init(&new_msti);

    for (i = 0; i < bridge_row->n_mstp_instances; i++) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        const struct ovsrec_mstp_instance *msti_cfg =
                                   bridge_row->value_mstp_instances[i];
        int inst_id = bridge_row->key_mstp_instances[i];
        char inst_id_string[INSTANCE_STRING_LEN];

        snprintf(inst_id_string, sizeof(inst_id_string), "%d", inst_id);
        if (!shash_add_once(&new_msti, inst_id_string, msti_cfg)) {
            VLOG_WARN_RL(&rl, "inst id %s specified twice", inst_id_string);
        }
    }

    /* Get rid of deleted instid's */
    HMAP_FOR_EACH_SAFE (msti, next_msti, node, &all_mstp_instances) {
        char inst_id_string[INSTANCE_STRING_LEN];
        if (msti->instance_id != MSTP_CIST) {
            snprintf(inst_id_string, sizeof(inst_id_string), "%d",
                     msti->instance_id);
            msti->cfg.msti_cfg = shash_find_data(&new_msti, inst_id_string);
            if (!msti->cfg.msti_cfg) {
                VLOG_DBG("found deleted instance %d",msti->instance_id);
                mstp_instance_delete(br, msti);
            }
        }
    }

    /* Add new instances. */
    for (i = 0; i < bridge_row->n_mstp_instances; i++) {
        int inst_id = bridge_row->key_mstp_instances[i];
        const struct ovsrec_mstp_instance *msti_cfg =
                     bridge_row->value_mstp_instances[i];
        struct mstp_instance *msti = mstp_cist_and_instance_lookup(inst_id);
        if (!msti) {
            VLOG_DBG("Found added instance %d", inst_id);
            mstp_instance_create(br, inst_id, msti_cfg);
        }
    }

    shash_destroy(&new_msti);
}


/*-----------------------------------------------------------------------------
| Function:   mstp_cist_port_add
| Description: add port to cist
| Parameters[in]: blk params :-object contains idl, ofproro, bridge cfg
| Parameters[in]: mstp_instance object
| Parameters[in]: ovsrec_mstp_common_instance_port object
| Parameters[out]: None
| Return:
-----------------------------------------------------------------------------*/
void
mstp_cist_port_add(const struct stp_blk_params *br, struct mstp_instance *msti,
                 const struct ovsrec_mstp_common_instance_port *cist_port_cfg )
{
    struct mstp_instance_port *new_port = NULL;
    bool retval = false;
    int port_state;

    if (!msti || !br || !cist_port_cfg) {
        VLOG_DBG("%s: invalid param", __FUNCTION__);
        return;
    }

    VLOG_DBG("%s: entry inst %d", __FUNCTION__, msti->instance_id);

        /* Allocate structure to save state information for this port. */
        new_port = xzalloc(sizeof(struct mstp_instance_port));
        if (!new_port) {
           VLOG_ERR("%s: Failed to allocate memory for port %s in instance %d",
                    __FUNCTION__, cist_port_cfg->port->name, msti->instance_id);
           return;
        }

        hmap_insert(&msti->ports, &new_port->hmap_node,
                    hash_string(cist_port_cfg->port->name, 0));

        new_port->name = xstrdup(cist_port_cfg->port->name);

        retval = get_port_state_from_string(cist_port_cfg->port_state,
                                            &port_state);
        if (false == retval) {
            VLOG_DBG("%s:invalid CIST port %s state %s", __FUNCTION__,
                     new_port->name, cist_port_cfg->port_state);
            new_port->stp_state = MSTP_INST_PORT_STATE_INVALID;;
            new_port->cfg.cist_port_cfg = cist_port_cfg;
            return;
        }

        new_port->stp_state = port_state;
        new_port->cfg.cist_port_cfg = cist_port_cfg;
        msti->nb_ports++;
        mstp_cist_and_instance_set_port_state(br, msti, new_port);
}

/*-----------------------------------------------------------------------------
| Function:  mstp_cist_configure_ports
| Description: add/del / updateports in cist
| Parameters[in]: blk params :-object contains idl, ofproro, bridge cfg
| Parameters[in]: mstp_instance object
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/
void
mstp_cist_configure_ports(const struct stp_blk_params *br,
                             struct mstp_instance *msti)
{
    size_t i;
    struct mstp_instance_port *inst_port, *next;
    struct shash sh_idl_ports;
    struct shash_node *sh_node;
    int new_port_state;
    bool retval;

    if (!msti || !br) {
        VLOG_DBG("%s: invalid param", __FUNCTION__);
        return;
    }

    VLOG_DBG("%s: entry inst %d", __FUNCTION__, msti->instance_id);

    /* Collect all Instance Ports present in the DB. */
    shash_init(&sh_idl_ports);
    for (i = 0; i < msti->cfg.cist_cfg->n_mstp_common_instance_ports; i++) {
        const char *name =
                    msti->cfg.cist_cfg->mstp_common_instance_ports[i]->port->name;
        if (!shash_add_once(&sh_idl_ports, name,
                          msti->cfg.cist_cfg->mstp_common_instance_ports[i])) {
            VLOG_WARN("instance id %d: %s specified twice as CIST Port",
                      msti->instance_id, name);
        }
    }

    /* Delete old Instance Ports. */
    HMAP_FOR_EACH_SAFE (inst_port, next, hmap_node, &msti->ports) {
        const struct ovsrec_mstp_common_instance_port *port_cfg;

        port_cfg = shash_find_data(&sh_idl_ports, inst_port->name);
        if (!port_cfg) {
            VLOG_DBG("Found a deleted Port %s in CIST", inst_port->name);
            mstp_cist_and_instance_port_delete(br, msti, inst_port);
        }
    }

    /* Add new Instance ports. */
    SHASH_FOR_EACH (sh_node, &sh_idl_ports) {
        inst_port = mstp_cist_and_instance_port_lookup(msti, sh_node->name);
        if (!inst_port) {
            VLOG_DBG("Found an added Port %s in CIST", sh_node->name);
            mstp_cist_port_add(br, msti, sh_node->data);
        }
    }

    inst_port = NULL;
    /* Check for changes in the port row entries. */
    HMAP_FOR_EACH (inst_port, hmap_node, &msti->ports) {
        const struct ovsrec_mstp_common_instance_port *inst_port_row =
                                                 inst_port->cfg.cist_port_cfg;

        // Check for port state changes.
        retval =  get_port_state_from_string(inst_port_row->port_state,
                                             &new_port_state);
        if (false == retval) {
            VLOG_DBG("%s:- invalid port state", __FUNCTION__);
            return;
        }

        if(new_port_state != inst_port->stp_state) {
            VLOG_DBG("%s:Set CIST port state to %s", __FUNCTION__,
                     inst_port_row->port_state);
            inst_port->stp_state = new_port_state;
            mstp_cist_and_instance_set_port_state(br,
                                                  msti, inst_port);
        }
        else {
            VLOG_DBG("%s: No change in CIST port %s state" , __FUNCTION__,
                     inst_port->name);
         }
    }

    /* Destroy the shash of the IDL ports */
    shash_destroy(&sh_idl_ports);

}

/*-----------------------------------------------------------------------------
| Function:  mstp_cist_add_del_vlans
| Description: add/del vlans in cist
| Parameters[in]: blk params :-object contains idl, ofproro, bridge cfg
| Parameters[in]: mstp_instance object
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/
void
mstp_cist_add_del_vlans(const struct stp_blk_params *br,
                             struct mstp_instance *msti)
{
    size_t i;
    struct mstp_instance_vlan *vlan, *next;
    struct shash sh_idl_vlans;
    struct shash_node *sh_node;

    if (!msti || !br) {
        VLOG_DBG("%s: invalid param", __FUNCTION__);
        return;
    }

    VLOG_DBG("%s: entry inst %d", __FUNCTION__, msti->instance_id);

    /* Collect all Instance VLANs present in the DB. */
    shash_init(&sh_idl_vlans);
    for (i = 0; i < msti->cfg.cist_cfg->n_vlans; i++) {
        const char *name = msti->cfg.cist_cfg->vlans[i]->name;
        if (!shash_add_once(&sh_idl_vlans, name,
                            msti->cfg.cist_cfg->vlans[i])) {
            VLOG_WARN("%s: %s specified twice as cist VLAN",
                      __FUNCTION__, name);
        }
    }

    /* Delete old Instance VLANs. */
    HMAP_FOR_EACH_SAFE (vlan, next, hmap_node, &msti->vlans) {
        const struct ovsrec_vlan *vlan_cfg;

        vlan_cfg = shash_find_data(&sh_idl_vlans, vlan->name);
        if (!vlan_cfg) {
            VLOG_DBG("%s:Found a deleted VLAN in CIST%s",
                     __FUNCTION__, vlan->name);
            mstp_cist_and_instance_vlan_delete(br, msti, vlan);
        }
    }

    /* Add new VLANs. */
    SHASH_FOR_EACH (sh_node, &sh_idl_vlans) {
        vlan = mstp_cist_and_instance_vlan_lookup(msti, sh_node->name);
        if (!vlan) {
            VLOG_DBG("%s:Found an added VLAN in CIST%s",
                      __FUNCTION__, sh_node->name);
            mstp_cist_and_instance_vlan_add(br, msti, sh_node->data);
        }
    }

    /* Destroy the shash of the IDL vlans */
    shash_destroy(&sh_idl_vlans);
}


/*-----------------------------------------------------------------------------
| Function:  mstp_cist_create
| Description: create cist instance
| Parameters[in]: blk params :-object contains idl, ofproro, bridge cfg
| Parameters[in]:  ovsrec_mstp_common_instance object
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/
void
mstp_cist_create(const struct stp_blk_params *br,
                    const struct ovsrec_mstp_common_instance *msti_cist_cfg)
{
    struct mstp_instance *msti;
    char inst_id_string[INSTANCE_STRING_LEN] = "";

    if (!msti_cist_cfg || !br) {
        VLOG_DBG("%s: invalid param", __FUNCTION__);
        return;
    }
    VLOG_DBG("%s: entry", __FUNCTION__);

    msti = xzalloc(sizeof *msti);
    if (!msti) {
        VLOG_ERR("%s: Failed to allocate memory for CIST", __FUNCTION__);
        return;
    }

    msti->instance_id = MSTP_CIST;
    msti->cfg.cist_cfg= msti_cist_cfg;
    hmap_init(&msti->vlans);
    hmap_init(&msti->ports);
    snprintf(inst_id_string, sizeof(inst_id_string), "cist");
    hmap_insert(&all_mstp_instances, &msti->node, hash_string(inst_id_string, 0));

    msti->hw_stg_id = MSTP_DEFAULT_STG_GROUP;
    msti->nb_vlans = 0;
    msti->nb_ports = 0;
    mstp_cist_add_del_vlans(br, msti);
    mstp_cist_configure_ports(br, msti);
}

/*-----------------------------------------------------------------------------
| Function:  mstp_cist_update
| Description: check vlans, ports add/deleted -updated in cist
| Parameters[in]: blk params :-object contains idl, ofproro, bridge cfg
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/
void
mstp_cist_update(const struct stp_blk_params *br)
{
    struct mstp_instance *msti;
    const struct ovsrec_mstp_common_instance *msti_cist_cfg;

    if (!br) {
        VLOG_DBG("%s: invalid bridge param", __FUNCTION__);
        return;
    }

    if (!br->cfg) {
        VLOG_DBG("%s: invalid bridge config param", __FUNCTION__);
        return;
    }
    VLOG_DBG("%s: entry", __FUNCTION__);

    msti_cist_cfg = br->cfg->mstp_common_instance;
    if (!msti_cist_cfg) {
        VLOG_DBG("%s: invalid mstp common instance config  param",
                 __FUNCTION__);
        return;
    }

    msti = mstp_cist_and_instance_lookup(MSTP_CIST);
    if (!msti) {
        const struct ovsrec_mstp_common_instance *msti_cist_cfg =
                                                br->cfg->mstp_common_instance;
        VLOG_DBG("%s:Creating CIST", __FUNCTION__);
        mstp_cist_create(br, msti_cist_cfg);
        return;
    }
    else {
        /* update  CIST vlans and ports */
        /* check if any vlans added or deleted */
        mstp_cist_add_del_vlans(br, msti);

        /* check if any l2 ports added or deleted  or updated*/
        mstp_cist_configure_ports(br, msti);
    }

}

/*-----------------------------------------------------------------------------
| Function:   mstp_update_instances
| Description:  update port states and vlans  in msti
| Parameters[in]: blk params :-object contains idl, ofproro, bridge cfg
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/
void
mstp_update_instances(struct stp_blk_params* br_blk_param)
{
       struct mstp_instance *msti, *next_msti;

     if(!br_blk_param || !br_blk_param->idl
        || !br_blk_param->cfg) {
        VLOG_DBG("invalid blk param object");
        return;
    }

    VLOG_DBG("%s:- entry", __FUNCTION__);

    /* Get rid of deleted instid's */
    HMAP_FOR_EACH_SAFE (msti, next_msti, node, &all_mstp_instances) {
        if (msti->instance_id != MSTP_CIST) {
            mstp_instance_update(br_blk_param, msti);
        }
    }
}

/*-----------------------------------------------------------------------------
| Function:  stp_reconfigure
| Description: checks for vlans,ports added/deleted in msti/cist
| Parameters[in]: blk params :-object contains idl, ofproro, bridge cfg
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/
void
stp_reconfigure(struct blk_params* br_blk_param)
{
    struct stp_blk_params blk_param;

    if(!br_blk_param || !br_blk_param->idl) {
        VLOG_DBG("%s: invalid blk param object", __FUNCTION__);
        return;
    }
    VLOG_DBG("%s: entry", __FUNCTION__);

    blk_param.idl = br_blk_param->idl;
    blk_param.cfg = ovsrec_bridge_first(br_blk_param->idl);
    mstp_cist_update(&blk_param);
    mstp_add_del_instances(&blk_param);
    mstp_update_instances(&blk_param);
}

/*-----------------------------------------------------------------------------
| Function:   mstp_instance_dump_data
| Description:  update port states and vlans  in msti
| Parameters[in]: blk params :-object contains idl, ofproro, bridge cfg
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/
void
mstp_instance_dump_data(struct ds *ds, struct mstp_instance *msti)
{
    struct mstp_instance_vlan *vlan;
    struct mstp_instance_port *port;


     if(!msti || !ds) {
        VLOG_ERR("%s: invalid param object", __FUNCTION__);
        return;
    }


    /* display instance data*/
    ds_put_format(ds, "Instance %d:\n", msti->instance_id);
    ds_put_format(ds, "Instance hw stg id %d:\n", msti->hw_stg_id);
    ds_put_format(ds, "Instance vlan count %d:\n", msti->nb_vlans);
    ds_put_format(ds, "Instance port count %d:\n", msti->nb_ports);
    HMAP_FOR_EACH (vlan, hmap_node, &msti->vlans) {
        ds_put_format(ds, "vlan id %d:\n", vlan->vid);
    }

    HMAP_FOR_EACH (port, hmap_node, &msti->ports) {
        ds_put_format(ds, "port %s state %s:\n", port->name,
                      port_state_str[port->stp_state]);
    }
    ds_put_format(ds, "\n");
}

/*-----------------------------------------------------------------------------
| Function:  stp_plugin_dump_data
| Description:dumps stp plugin instance data
| Parameters[in]: None
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/
void
stp_plugin_dump_data(struct ds *ds, int argc, const char *argv[])
{
    struct mstp_instance *msti, *next_msti;

    if (argc > 1) {
        int inst_id = strtol(argv[1], NULL, 10);
        msti = mstp_cist_and_instance_lookup(inst_id);
        if (NULL == msti) {
            ds_put_format(ds, "instance %s not configured\n", argv[1]);
            return;
        }
        mstp_instance_dump_data(ds, msti);
    }
    else {
       /* parse the instance id */
        HMAP_FOR_EACH_SAFE (msti, next_msti, node, &all_mstp_instances) {
                 mstp_instance_dump_data(ds, msti);
        }
    }
}
