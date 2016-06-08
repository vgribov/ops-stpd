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
 *    File               : mstpd_recv.c
 *    Description        : MSTP Protocol Packet Receive Related Routines
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
#include <eventlog.h>

#include "mstp_fsm.h"
#include "mstp_recv.h"
#include "mstp_inlines.h"
#include "mstp_ovsdb_if.h"

VLOG_DEFINE_THIS_MODULE(mstpd_recv);
/** ======================================================================= **
 *                                                                           *
 *     Global Functions (externed)                                           *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_DecodeBpdu
 *
 * Purpose:   Decodes a BPDU from another Spanning Tree Bridge
 *
 * Params:    pkt - pointer to pkt
 *
 * Returns:   MSTP pkt type
 *
 * Globals:   mstp_CB
 *
 **PROC-**********************************************************************/
MSTP_PKT_TYPE_t mstp_decodeBpdu(MSTP_RX_PDU *pkt)
{
   MSTP_COMM_PORT_INFO_t  *commPortPtr;
   ENET_HDR               *enet_hdr;
   LPORT_t                 lport;

   lport = GET_PKT_LOGICAL_PORT(pkt);
   STP_ASSERT(IS_VALID_LPORT(lport));

   /*---------------------------------------------------------------------
    * Check if MSTP port's data is allocated.
    * NOTE: It is possible to hit a race condition when BPDU may come
    *       on port that gone short after the BPDU was received, e.g. such
    *       port has joined a trunk while BPDU for this port was queued
    *       on the MSTP receive ring.
    *---------------------------------------------------------------------*/
   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   if(commPortPtr== NULL) {
      return(MSTP_INVALID_PKT);
   }

   /*----------------------------------------------------------------------
    * Drop the BPDU for port if configured.
    *----------------------------------------------------------------------*/
   if(commPortPtr->dropBpdu)
   {
      return MSTP_INVALID_PKT;
   }

   /*----------------------------------------------------------------------
    * Store BPDU source address for future reference
    * (e.g. during Errant BPDU traps generation)
    *----------------------------------------------------------------------*/
   enet_hdr = (ENET_HDR *)(pkt->data);
   MAC_ADDR_COPY(enet_hdr->src,commPortPtr->bpduSrcMac);
   /*---------------------------------------------------------------------
    * Check to see if BPDU-Protection or BPDU-Filter options are applied
    * to the port and set msg's operation field accordingly.
    * NOTE: The order of checks done below is critical:
    *       - BPDU-Protection takes precedence over BPDU-Filter and
    *         normal port's behavior
    *       - BPDU-Filter takes precedence over normal port's behavior
    *---------------------------------------------------------------------*/

   if(MSTP_COMM_PORT_IS_BPDU_PROTECTED(lport))
      return(MSTP_UNAUTHORIZED_BPDU_DATA_PKT);

   if(MSTP_COMM_IS_BPDU_FILTER(lport))
      return(MSTP_ERRANT_PROTOCOL_DATA_PKT);

   return(MSTP_PROTOCOL_DATA_PKT);
}
/**PROC+**********************************************************************
 * Name:      mstp_protocolData
 *
 * Purpose:   This function validates received BPDUs and calls PRX SM
 *            if BPDU is valid
 *
 *
 * Params:    msg  -> pointer to incoming MSG that carries
 *                    received BPDU packet.
 *
 * Returns:   none
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
void
mstp_protocolData(MSTP_RX_PDU *pkt)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr;
   LPORT_t                lport;
   bool                   edgePort;

   STP_ASSERT(pkt);

   /*------------------------------------------------------------------------
    * validate the port received
    *------------------------------------------------------------------------*/
   lport = GET_PKT_LOGICAL_PORT(pkt);
   STP_ASSERT(IS_VALID_LPORT(lport));

   /*------------------------------------------------------------------------
    * check for the race condition case. It is possible to get this function
    * called in the middle of the disabling protocol code path executed
    * by the session task (dynamic configuration change).
    *------------------------------------------------------------------------*/
   if(MSTP_ENABLED == FALSE)
   {
      return;
   }

   /*------------------------------------------------------------------------
    * check if MSTP port's data is allocated.
    * NOTE: It is possible to hit a race condition when the message we are
    *       processing contains BPDU that was received on a port that has
    *       already gone, e.g. such port has joined a trunk while the message
    *       was queued for the MSTP Protocol thread.
    *------------------------------------------------------------------------*/
   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   if(commPortPtr == NULL)
   {
      return;
   }

   /*------------------------------------------------------------------------
    * validate the received BPDU
    *------------------------------------------------------------------------*/
   if(!mstp_validateBpdu(pkt))
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      /* update statistics counter */
      STP_ASSERT(cistPortPtr);
      cistPortPtr->dbgCnts.invalidBpduCnt++;
      cistPortPtr->dbgCnts.invalidBpduCntLastUpdated = time(NULL);

      log_event("MSTP_BAD_BPDU",
          EV_KV("config_parameter", "%s", "wrong Protocol ID and version"),
          EV_KV("port", "%d", lport));
      return;
   }

   /* count number of processed BPDUs */
   mstp_CB.prBpduCnt++;
   mstp_CB.rxBpduCnt++;
   commPortPtr->dbxRxCnt++;
   MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_RCVD_BPDU);

   edgePort = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                        MSTP_PORT_ADMIN_EDGE_PORT);
   if(edgePort)
   {
      char        portName[PORTNAME_LEN];

      intf_get_port_name(lport, portName);
      VLOG_DBG("BPDU received on admin edge port %s",portName);
      log_event("MSTP_BPDU_RECVD_ON_EDGE_PORT",
          EV_KV("port", "%s", portName));
   }

   /*------------------------------------------------------------------------
    * Stop any BPDU transmissions on the Bridge while we are processing
    * BPDU
    * NOTE: Any single received BPDU that changes the CIST Root
    *       Identifier, CIST External Root Path Cost, or CIST Regional
    *       Root associated with MSTIs should be processed in their
    *       entirety, or not at all, before encoding BPDUs for
    *       transmission. This recommendation is made to minimize the
    *       number of BPDUs to be transmitted following receipt of a
    *       BPDU carrying new information. It is not required
    *       for correctness and has not therefore been incorporated into
    *       the state machines.
    *       (802.1Q-REV/D5.0 13.31)
    *------------------------------------------------------------------------*/
   mstp_preventTxOnBridge();

   /*------------------------------------------------------------------------
    * kick the Port Receive state machine
    *------------------------------------------------------------------------*/
   mstp_prxSm(pkt, lport);

   /*------------------------------------------------------------------------
    * Inform DB about port state changes, if any
    *------------------------------------------------------------------------*/
   mstp_informDBOnPortStateChange(0);

   /*------------------------------------------------------------------------
    * When we done with processing of the BPDU initiate transmission of
    * pending information on the Bridge, if any
    *------------------------------------------------------------------------*/
   mstp_doPendingTxOnBridge();

}
/**PROC+**********************************************************************
 * Name:      mstp_errantProtocolData
 *
 * Purpose:   Handles an errant BPDU received, one that wasn't expected.
 *            Count it per-port.  If SNMP Trap generation is enabled and
 *            it is time, send a trap.
 *
 * Params:    msg  -> pointer to incoming MSG that carries
 *                    received BPDU packet.
 *            source -> reason for the trap
 *
 * Returns:   none
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
void
mstp_errantProtocolData(MSTP_RX_PDU *pkt, TRAP_SOURCE_TYPE_e source)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr;
   LPORT_t                lport;

   STP_ASSERT(pkt);

   /*------------------------------------------------------------------------
    * validate the port received
    *------------------------------------------------------------------------*/
   lport = GET_PKT_LOGICAL_PORT(pkt);
   STP_ASSERT(IS_VALID_LPORT(lport));

   /*------------------------------------------------------------------------
    * check for the race condition case. It is possible to get this function
    * called in the middle of the disabling protocol code path executed
    * by the session task (dynamic configuration change).
    *------------------------------------------------------------------------*/
   if(MSTP_ENABLED == FALSE)
   {
      return;
   }

   /*------------------------------------------------------------------------
    * check if MSTP port's data is allocated.
    * NOTE: It is possible to hit a race condition when the message we are
    *       processing contains BPDU that was received on a port that has
    *       already gone, e.g. such port has joined a trunk while the message
    *       was queued for the MSTP Protocol thread.
    *------------------------------------------------------------------------*/
   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   if(commPortPtr == NULL)
   {
      return;
   }

   /*------------------------------------------------------------------------
    * Store trapSource for use during trap generation
    *------------------------------------------------------------------------*/
   commPortPtr->trapSource = source;

   /*------------------------------------------------------------------------
    * Augment Errant Bpdu Count
    *------------------------------------------------------------------------*/
   STP_ASSERT(MSTP_CIST_PORT_PTR(lport));
   MSTP_CIST_PORT_PTR(lport)->dbgCnts.errantBpduCnt++;
   MSTP_CIST_PORT_PTR(lport)->dbgCnts.errantBpduCntLastUpdated =
                                                         time(NULL);
   /*------------------------------------------------------------------------
    * Store port state at time of event for sending trap
    *------------------------------------------------------------------------*/
   if(commPortPtr->trapPortState == 0)
      commPortPtr->trapPortState = mstp_dot1dStpPortState(lport);

#if OPS_MSTP_TODO
   /*------------------------------------------------------------------------
    * MSTP_ERRANT_BPDU_HOLD_TIME seconds between traps
    *------------------------------------------------------------------------*/
   mstp_triggerTrap(lport, MSTP_ERRANT_BPDU_HOLD_TIME, FALSE);
#endif /*OPS_MSTP_TODO*/
}

/**PROC+**********************************************************************
 * Name:      mstp_processUnauthorizedBpdu
 *
 * Purpose:   Handles a BPDU received on a BPDU
 *            protected port. Count it and shut down port. If
 *            SNMP Trap generation is enabled and it is time,
 *            send a trap.
 *
 * Params:    msg  -> pointer to incoming MSG that carries
 *                    received BPDU packet.
 *            source -> reason for the trap.
 *
 * Returns:   none
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
void
mstp_processUnauthorizedBpdu(MSTP_RX_PDU *pkt, TRAP_SOURCE_TYPE_e source)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr;
   LPORT_t                lport;
   char                   lport_name[PORTNAME_LEN];
   char                   logStr[30];

   STP_ASSERT(pkt);

   /*------------------------------------------------------------------------
    * validate the port received
    *------------------------------------------------------------------------*/
   lport = GET_PKT_LOGICAL_PORT(pkt);
   STP_ASSERT(IS_VALID_LPORT(lport));

   /*------------------------------------------------------------------------
    * check for the race condition case. It is possible to get this function
    * called in the middle of the disabling protocol code path executed
    * by the session task (dynamic configuration change).
    *------------------------------------------------------------------------*/
   if(MSTP_ENABLED == FALSE)
   {
      return;
   }

   /*------------------------------------------------------------------------
    * check if MSTP port's data is allocated.
    * NOTE: It is possible to hit a race condition when the message we are
    *       processing contains BPDU that was received on a port that has
    *       already gone, e.g. such port has joined a trunk while the message
    *       was queued for the MSTP Protocol thread.
    *------------------------------------------------------------------------*/
   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   if(commPortPtr == NULL)
   {
      return;
   }
   if(commPortPtr->inBpduError == FALSE)
   {
      if(!is_lport_down(lport))
      {

            disable_logical_port(lport);
         /*------------------------------------------------------------------
          * Log message that we are disabling port.
          *------------------------------------------------------------------*/
         intf_get_port_name(lport,lport_name);
         if(commPortPtr->reEnableTimer > 0)
            snprintf(logStr,sizeof(logStr),"for %d seconds ",
                     commPortPtr->reEnableTimer);
         else
            logStr[0] = '\0';
         VLOG_DBG("port %s disabled %s- BPDU received on protected port.",lport_name,logStr);
         log_event("MSTP_ERROR_DISABLED_PORT",
             EV_KV("port", "%s", lport_name),
             EV_KV("sec", "%s", logStr));
      }

      /*---------------------------------------------------------------------
       * Store trapSource for use during trap generation
       *---------------------------------------------------------------------*/
      commPortPtr->trapSource = source;

      /*---------------------------------------------------------------------
       * Store port state at time of event for sending trap
       *---------------------------------------------------------------------*/
      commPortPtr->trapPortState = mstp_dot1dStpPortState(lport);
      commPortPtr->inBpduError = TRUE;

      /*---------------------------------------------------------------------
       * Augment Errant Bpdu Count
       *---------------------------------------------------------------------*/
      STP_ASSERT(MSTP_CIST_PORT_PTR(lport));
      MSTP_CIST_PORT_PTR(lport)->dbgCnts.errantBpduCnt++;
      MSTP_CIST_PORT_PTR(lport)->dbgCnts.errantBpduCntLastUpdated =
                                                         time(NULL);
#ifdef OPS_MSTP_TODO
      /*---------------------------------------------------------------------
       * Enforce a 2 x HELLO TIME delay, to allow for topology to settle
       * since we disable port for Bpdu Protection and possibly could impede
       * the ability for SNMP trap to get to trap monitor
       *---------------------------------------------------------------------*/
      mstp_triggerTrap(lport, 2 * mstp_Bridge.HelloTime, TRUE);
#endif /*OPS_MSTP_TODO*/
   }

}
