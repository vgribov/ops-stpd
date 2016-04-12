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

/**********************************************************************************
 *    File               : mstpd_debug.c
 *    Description        : MSTP Protocol Debug Related Commands
 **********************************************************************************/

#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>

#include <util.h>
#include <daemon.h>
#include <dirs.h>
#include <unixctl.h>
#include <fatal-signal.h>
#include <command-line.h>
#include <vswitch-idl.h>
#include <openvswitch/vlog.h>
#include <assert.h>
#include "mstp_fsm.h"
#include "mstp_recv.h"
#include "mstp_inlines.h"
#include "mstp_ovsdb_if.h"
VLOG_DEFINE_THIS_MODULE(mstpd_debug);

/** ======================================================================= **
 *                                                                           *
 *     Global Variable Declarations                                          *
 *                                                                           *
 ** ======================================================================= **/

MSTP_SM_MAP   mstp_debugSMs;
PORT_MAP      mstp_debugPorts;
MSTP_MSTI_MAP mstp_debugMstis;
bool         mstp_debugCist;
bool         mstp_debugSmCallSm;
bool         mstp_debugTx;
bool         mstp_debugRx;
bool         mstp_debugBpduPrint;
bool         mstp_debugDynConfig;
bool         mstp_debugFlush;
bool         mstp_debugPortStatus;
bool         mstp_debugMisc;
bool         mstp_debugLog;
uint32_t      mstp_debugRxBpduCnt;
uint32_t      mstp_debugTxBpduCnt;

/*Below globals are used by user mode command 'debug mstp'*/

/*'debug mstp packet'*/
PORT_MAP      mstp_debugPktEnabledPorts; /*This is used by debug mstp pkt port <p>*/
MSTP_MSTI_MAP mstp_debugPktEnabledInstances[MAX_LPORTS + 1]; /*this is used by
                                                        debug mstp port <p>
                                                        [instance <i | cst>]*/
PORT_MAP      mstp_debugPktEnabledForCist;

/*'debug mstp events'*/
MSTP_MSTI_MAP mstp_debugEventInstances; /*Instances for which 'debug mstp event
                                          instances <i | cts> has been enabled */
bool         mstp_debugEventCist;
/** ======================================================================= **
 *                                                                           *
 *     Global Functions (externed)                                           *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_validateStrYesNo
 *
 * Purpose:   This is helper function used to verify whether string contains
 *            'y' or 'n' option
 *
 * Params:    optYesNoStr -> pointer to the string containing option
 *
 * Returns:   TRUE if option is 'y', FALSE if option is 'n', -1 otherwise
 *
 * Globals:   none
 **PROC-**********************************************************************/
int
mstp_validateStrYesNo(char *optYesNoStr)
{
   int res;

   STP_ASSERT(optYesNoStr);

   if(!strcmp(optYesNoStr,"y"))
      res = TRUE;
   else if(!strcmp(optYesNoStr,"n"))
      res = FALSE;
   else
      res = -1;

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_validateStrSmName
 *
 * Purpose:   This is helper function used to verify whether string contains
 *            valid MSTP state machine (SM) name
 *
 * Params:    smNameStr -> pointer to the string containing SM name
 *
 * Returns:   integer identifying SM if name is valid, -1 otherwise
 *
 * Globals:   none
 **PROC-**********************************************************************/
int
mstp_validateStrSmName(char *smNameStr)
{
   int smType;

   STP_ASSERT(smNameStr);

   if(!strcmp(smNameStr,"pim"))
      smType =  MSTP_PIM;
   else if(!strcmp(smNameStr,"prs"))
      smType =  MSTP_PRS;
   else if(!strcmp(smNameStr,"prt"))
      smType =  MSTP_PRT;
   else if(!strcmp(smNameStr,"prx"))
      smType =  MSTP_PRX;
   else if(!strcmp(smNameStr,"pst"))
      smType =  MSTP_PST;
   else if(!strcmp(smNameStr,"tcm"))
      smType =  MSTP_TCM;
   else if(!strcmp(smNameStr,"ppm"))
      smType =  MSTP_PPM;
   else if(!strcmp(smNameStr,"ptx"))
      smType =  MSTP_PTX;
   else if(!strcmp(smNameStr,"pti"))
      smType =  MSTP_PTI;
   else if(!strcmp(smNameStr,"bdm"))
      smType =  MSTP_BDM;
   else
      smType = -1;

   return smType;
}
/**PROC+**********************************************************************
 * Name:      mstpd_daemon_debug_sm_data_dump
 *
 * Purpose:   This is helper function used to configure VLOGs to a Statemachine
 *
 * Globals:   none
 **PROC-**********************************************************************/

void mstpd_daemon_debug_sm_data_dump(struct ds *ds, int argc, const char *argv[])
{
    int smType = mstp_validateStrSmName((char *)argv[1]);
    int opt = mstp_validateStrYesNo((char *)argv[2]);

    if(smType < 0)
        ds_put_format(ds,"wrong SM name %s\n", argv[1]);
    else if(opt < 0)
        ds_put_format(ds, "wrong option %s\n",argv[2]);
    else
    {
        opt ? setBit(mstp_debugSMs.sm_map, smType, MSTP_SM_MAX_BIT) :
            clrBit(mstp_debugSMs.sm_map, smType, MSTP_SM_MAX_BIT);
        ds_put_format(ds, "SM '%s' - debug is %s\n", argv[2], opt? "ON" : "OFF");
    }
}

/**PROC+**********************************************************************
 * Name:      mstpd_daemon_debug_sm_unixctl_list
 *
 * Purpose:   This is helper function used to configure VLOGs to a Statemachine
 *
 * Globals:   none
 **PROC-**********************************************************************/


void mstpd_daemon_debug_sm_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    mstpd_daemon_debug_sm_data_dump(&ds, argc, argv);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}


/**PROC+**********************************************************************
 * Name:      mstp_dbgBpduPrint
 *
 * Purpose:   print out the contents of STP BPDU
 *
 * Params:    pkt -> pointer to the packet buffer containing BPDU
 *
 * Returns:   none
 *
 * Globals:   none
 **PROC-**********************************************************************/
void
mstp_dbgBpduPrint(MSTP_RX_PDU *pkt)
{
   MSTP_BPDU_TYPE_t  bpduType = 0;

   assert(pkt);
   bpduType = mstp_getBpduType(pkt);
   if(bpduType == MSTP_BPDU_TYPE_MSTP)
   {
      MSTP_MST_BPDU_t *bpdu = (MSTP_MST_BPDU_t *)(pkt->data);
      int              len  = MSTP_MSTI_CFG_MSGS_SIZE(bpdu);
      uint16_t          msgAge = 0 ;
      uint16_t          maxAge = 0;
      uint16_t          helloTime = 0;
      uint16_t          fwdDelay = 0;

      MSTP_PRINTF("CIST Root=   0x%.4x;0x%.2x%.2x%.2x%.2x%.2x%.2x; EPC= %d",
                  getShortFromPacket(&bpdu->cistRootId.priority),
                  bpdu->cistRootId.mac_address[0],
                  bpdu->cistRootId.mac_address[1],
                  bpdu->cistRootId.mac_address[2],
                  bpdu->cistRootId.mac_address[3],
                  bpdu->cistRootId.mac_address[4],
                  bpdu->cistRootId.mac_address[5],
                  getLongFromPacket(&bpdu->cistExtPathCost));

      MSTP_PRINTF("CIST RRoot= 0x%.4x;0x%.2x%.2x%.2x%.2x%.2x%.2x; IPC= %d",
                  getShortFromPacket(&bpdu->cistRgnRootId.priority),
                  bpdu->cistRgnRootId.mac_address[0],
                  bpdu->cistRgnRootId.mac_address[1],
                  bpdu->cistRgnRootId.mac_address[2],
                  bpdu->cistRgnRootId.mac_address[3],
                  bpdu->cistRgnRootId.mac_address[4],
                  bpdu->cistRgnRootId.mac_address[5],
                  getLongFromPacket(&bpdu->cistIntRootPathCost));

      MSTP_PRINTF("CIST Bridge=0x%.4x;0x%.2x%.2x%.2x%.2x%.2x%.2x; PortId=0x%.2x;",
                  getShortFromPacket(&bpdu->cistBridgeId.priority),
                  bpdu->cistBridgeId.mac_address[0],
                  bpdu->cistBridgeId.mac_address[1],
                  bpdu->cistBridgeId.mac_address[2],
                  bpdu->cistBridgeId.mac_address[3],
                  bpdu->cistBridgeId.mac_address[4],
                  bpdu->cistBridgeId.mac_address[5],
                  getShortFromPacket(&bpdu->cistPortId));

      msgAge    = getShortFromPacket(&bpdu->msgAge);
      maxAge    = getShortFromPacket(&bpdu->maxAge);
      helloTime = getShortFromPacket(&bpdu->helloTime);
      fwdDelay  = getShortFromPacket(&bpdu->fwdDelay);
      MSTP_PRINTF("CIST Times: msgAge=%d;maxAge=%d;hTime=%d;fDelay=%d",
                  msgAge >> 8, maxAge >> 8, helloTime >> 8, fwdDelay >> 8);

      if(len)
      {
         MSTP_MSTI_CONFIG_MSG_t *mstiMsg;
         char                   *end;

         assert(len/sizeof(MSTP_MSTI_CONFIG_MSG_t) <= 64);

         mstiMsg = (MSTP_MSTI_CONFIG_MSG_t *)bpdu->mstiConfigMsgs;
         end     = (char*)mstiMsg + len;
         while((char*)mstiMsg < end)
         {
            MSTID_t mstid = MSTP_GET_BRIDGE_SYS_ID(mstiMsg->mstiRgnRootId);
            if(isBitSet(mstp_debugMstis.map, mstid, MSTP_MSTID_MAX))
            {
               MSTP_PRINTF("MSTI %-2d:", mstid);
               MSTP_PRINTF("MSTI flags=0x%.2x", mstiMsg->mstiFlags);
               MSTP_PRINTF("MSTI RRoot=0x%.4x;0x%.2x%.2x%.2x%.2x%.2x%.2x;",
                           getShortFromPacket(&mstiMsg->mstiRgnRootId.priority),
                           mstiMsg->mstiRgnRootId.mac_address[0],
                           mstiMsg->mstiRgnRootId.mac_address[1],
                           mstiMsg->mstiRgnRootId.mac_address[2],
                           mstiMsg->mstiRgnRootId.mac_address[3],
                           mstiMsg->mstiRgnRootId.mac_address[4],
                           mstiMsg->mstiRgnRootId.mac_address[5]);
               MSTP_PRINTF("MSTI IPC  = %d",
                           getLongFromPacket(&mstiMsg->mstiIntRootPathCost));
               MSTP_PRINTF("MSTI BPri = %d", mstiMsg->mstiBridgePriority);
               MSTP_PRINTF("MSTI PPri = %d", mstiMsg->mstiPortPriority);
               MSTP_PRINTF("MSTI RHops= %d", mstiMsg->mstiRemainingHops);
            }
            mstiMsg++;
         }
      }
   }
}


/**PROC+**********************************************************************
 * Name:      mstpd_cist_data_dump
 *
 * Purpose:   This is helper function used to dump OVSDB CIST Data
 *
 * Globals:   none
 **PROC-**********************************************************************/
void mstpd_cist_data_dump(struct ds *ds, int argc, const char *argv[])
{
    VID_t vid = 0;
    ds_put_format(ds, "MSTP CIST Config OVSDB info: \n");
    ds_put_format(ds, "MSTP VLANs: ");
    for (vid = find_first_vid_set(&mstp_cist_conf.vlans);vid < MAX_VLAN_ID; vid = find_next_vid(&mstp_cist_conf.vlans,vid))
    {
        ds_put_format(ds, "%d", vid);
    }
    ds_put_format(ds, "\n");
    ds_put_format(ds, "MSTP CIST Priority %d\n", mstp_cist_conf.priority);
    ds_put_format(ds, "MSTP CIST Hello Time %d\n",  mstp_cist_conf.hello_time);
    ds_put_format(ds, "MSTP CIST Forward Delay %d\n", mstp_cist_conf.forward_delay);
    ds_put_format(ds, "MSTP CIST Max Age %d\n", mstp_cist_conf.max_age);
    ds_put_format(ds, "MSTP CIST Max Hop Count %d\n", mstp_cist_conf.max_hop_count);
    ds_put_format(ds, "MSTP CIST Tx Hold Count %d\n", mstp_cist_conf.tx_hold_count);
}

/**PROC+**********************************************************************
 * Name:      mstpd_cist_unixctl_list
 *
 * Purpose:   This is helper function used to dump OVSDB CIST Data
 *
 * Globals:   none
 **PROC-**********************************************************************/
void mstpd_cist_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    mstpd_cist_data_dump(&ds, argc, argv);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

/**PROC+**********************************************************************
 * Name:      mstpd_cist_port_data_dump
 *
 * Purpose:   This is helper function used to dump OVSDB CIST Port Data
 *
 * Globals:   none
 **PROC-**********************************************************************/

void mstpd_cist_port_data_dump(struct ds *ds, int argc, const char *argv[])
{
    LPORT_t lport = 0;
    if (argc > 1)
    {
        struct iface_data *idp = NULL;
        char *name = (char *)argv[1];
        idp = find_iface_data_by_name(name);
        lport = idp->lport_id;
        ds_put_format(ds,"MSTP CIST Lport : %d\n",lport);
        struct mstp_cist_port_config *cist_port = cist_port_lookup[lport];
        if (!cist_port)
        {
            ds_put_format(ds,"MSTP CIST PORT doesnot exist\n");
            return;
        }
        ds_put_format(ds,"MSTP CIST PORT Priority : %d\n",cist_port->port_priority);
        ds_put_format(ds,"MSTP CIST PORT Admin Path Cost : %d\n",cist_port->admin_path_cost);
        ds_put_format(ds,"MSTP CIST PORT Admin Edge port : %d\n",cist_port->admin_edge_port_disable);
        ds_put_format(ds,"MSTP CIST PORT BPDUS RX Enable : %d\n",cist_port->bpdus_rx_enable);
        ds_put_format(ds,"MSTP CIST PORT BPDUS TX Enable : %d\n",cist_port->bpdus_tx_enable);
        ds_put_format(ds,"MSTP CIST PORT Restricted Port Role : %d\n",cist_port->restricted_port_role_disable);
        ds_put_format(ds,"MSTP CIST PORT Restricted Port Tcn : %d\n",cist_port->restricted_port_tcn_disable);
        ds_put_format(ds,"MSTP CIST PORT BPDU Guard : %d\n",cist_port->bpdu_guard_disable);
        ds_put_format(ds,"MSTP CIST PORT LOOP Guard : %d\n",cist_port->loop_guard_disable);
        ds_put_format(ds,"MSTP CIST PORT ROOT Guard : %d\n",cist_port->root_guard_disable);
        ds_put_format(ds,"MSTP CIST PORT BPDU Filter : %d\n",cist_port->bpdu_filter_disable);
    }
    else
    {
        ds_put_format(ds,"Enter a Port Number");
    }
}


/**PROC+**********************************************************************
 * Name:      mstpd_cist_port_unixctl_list
 *
 * Purpose:   This is helper function used to dump OVSDB CIST Port Data
 *
 * Globals:   none
 **PROC-**********************************************************************/


void mstpd_cist_port_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    mstpd_cist_port_data_dump(&ds, argc, argv);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}


/**PROC+**********************************************************************
 * Name:      mstpd_msti_data_dump
 *
 * Purpose:   This is helper function used to dump OVSDB MSTI Data
 *
 * Globals:   none
 **PROC-**********************************************************************/


void mstpd_msti_data_dump(struct ds *ds, int argc, const char *argv[])
{
    if (argc > 1)
    {
        uint16_t mstid = atoi(argv[1]);
        VID_t vid = 0;
        struct mstp_msti_config *msti_data = msti_lookup[mstid];
        if (!msti_data)
        {
            ds_put_format(ds, "MSTI DATA is not found");
            return;
        }
        ds_put_format(ds, "MSTP MSTI Config OVSDB info: \n");
        ds_put_format(ds, "MSTP MSTI VLANs: ");
        for (vid = find_first_vid_set(&msti_data->vlans);vid < MAX_VLAN_ID; vid = find_next_vid(&msti_data->vlans,vid))
        {
            ds_put_format(ds, "%d", vid);
        }
        ds_put_format(ds, "\n");
        ds_put_format(ds, "MSTP MSTI Priority %d\n", msti_data->priority);
    }
    else
    {
        ds_put_format(ds, "ENTER MSTI ID \n");
    }
}

/**PROC+**********************************************************************
 * Name:      mstpd_msti_unixctl_list
 *
 * Purpose:   This is helper function used to dump OVSDB MSTI Data
 *
 * Globals:   none
 **PROC-**********************************************************************/


void mstpd_msti_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    mstpd_msti_data_dump(&ds, argc, argv);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}
/**PROC+**********************************************************************
 * Name:      mstpd_msti_port_data_dump
 *
 * Purpose:   This is helper function used to dump OVSDB MSTI Port Data
 *
 * Globals:   none
 **PROC-**********************************************************************/


void mstpd_msti_port_data_dump(struct ds *ds, int argc, const char *argv[])
{
    LPORT_t lport = 0;
    uint16_t mstid = 0;
    if (argc > 1)
    {
        struct iface_data *idp = NULL;
        char *name = (char *)argv[2];
        idp = find_iface_data_by_name(name);
        lport = idp->lport_id;
        mstid = atoi(argv[1]);
        ds_put_format(ds,"MSTP MSTI Lport : %d\n",lport);
        struct mstp_msti_port_config *msti_port = msti_port_lookup[mstid][lport];
        if (!msti_port)
        {
            ds_put_format(ds,"MSTP MSTI PORT doesnot exist\n");
            return;
        }
        ds_put_format(ds,"MSTP CIST PORT Priority : %d\n",msti_port->priority);
        ds_put_format(ds,"MSTP CIST PORT Admin Path Cost : %d\n",msti_port->path_cost);
    }
    else
    {
        ds_put_format(ds,"Enter a Port Number");
    }
}


/**PROC+**********************************************************************
 * Name:      mstpd_msti_port_unixctl_list
 *
 * Purpose:   This is helper function used to dump OVSDB MSTI Port Data
 *
 * Globals:   none
 **PROC-**********************************************************************/

void mstpd_msti_port_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    mstpd_msti_port_data_dump(&ds, argc, argv);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}
