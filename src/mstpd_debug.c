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
