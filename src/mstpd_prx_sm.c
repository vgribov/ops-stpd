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
 *    File               : mstpd_prx_sm.c
 *    Description        : MSTP Protocol Port Receive State Machine
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

VLOG_DEFINE_THIS_MODULE(mstpd_prx_sm);
/*---------------------------------------------------------------------------
 * Local functions prototypes (forward declarations)
 *---------------------------------------------------------------------------*/
static void mstp_prxSmGeneralCond(LPORT_t lport);
static bool mstp_prxSmDiscardCond(MSTP_RX_PDU *pkt, LPORT_t lport);
static bool mstp_prxSmReceiveCond(MSTP_RX_PDU *pkt, LPORT_t lport);
static void mstp_prxSmDiscardAct(LPORT_t lport);
static void mstp_prxSmReceiveAct(MSTP_RX_PDU *pkt, LPORT_t lport);

/** ======================================================================= **
 *                                                                           *
 *     Global Functions (externed)                                           *
 *                                                                           *
 ** ======================================================================= **/
/**PROC+**********************************************************************
 * Name:      mstp_prxSm
 *
 * Purpose:   The entry point to the Port Receive (PRX) state machine,
 *            which is responsible for receiving BPDUs.
 *           (802.1Q-REV/D5.0 13.28)
 *
 * Params:    pkt   -> pointer to the packet buffer with received BPDU in
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_prxSm(MSTP_RX_PDU *pkt, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = NULL;
   bool                  next        = FALSE;/* This variable is used to
                                               * indicate that the state
                                               * change processing
                                               * is still required */
   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   mstp_prxSmGeneralCond(lport);
   do
   {
      switch(commPortPtr->prxState)
      {
         case MSTP_PRX_STATE_DISCARD:
            next = mstp_prxSmDiscardCond(pkt, lport);
            break;
         case MSTP_PRX_STATE_RECEIVE:
            next = mstp_prxSmReceiveCond(pkt, lport);
            break;
         default:
            STP_ASSERT(0);
            break;
      }
   }
   while (next == TRUE);

   /*------------------------------------------------------------------------
    * when exit the state for PRX SM must be 'DISCARD' || 'RECEIVE'
    *------------------------------------------------------------------------*/
   STP_ASSERT(commPortPtr->prxState == MSTP_PRX_STATE_DISCARD ||
          commPortPtr->prxState == MSTP_PRX_STATE_RECEIVE);

}
/** ======================================================================= **
 *                                                                           *
 *     Static (local to this file) Functions                                 *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_prxSmGeneralCond
 *
 * Purpose:   Check for the conditions to transition to the next state
 *
 * Params:    lport -> logical port number a BPDU was received on
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
static void
mstp_prxSmGeneralCond(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr    = MSTP_COMM_PORT_PTR(lport);
   uint8_t                 MigrateTime    = mstp_Bridge.MigrateTime;
   uint8_t                 edgeDelayWhile = 0;
   bool                  rcvdBpdu       = FALSE;
   bool                  portEnabled    = FALSE;

   /*------------------------------------------------------------------------
    * collect state exit conditions information
    *------------------------------------------------------------------------*/
   edgeDelayWhile = commPortPtr->edgeDelayWhile;
   rcvdBpdu = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                        MSTP_PORT_RCVD_BPDU);
   portEnabled = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                           MSTP_PORT_PORT_ENABLED);

   /*------------------------------------------------------------------------
    * check for condition to transition to the 'DISCARD' state
    *------------------------------------------------------------------------*/
   if((MSTP_BEGIN == TRUE) ||
      ((rcvdBpdu || (edgeDelayWhile != MigrateTime)) && !portEnabled))
   {/* 'BEGIN" ||
     * (('rcvdBpdu' || ('edgeDelayWhile' != 'MigrateTime')) && '!portEnabled')
     */
      MSTP_SM_ST_PRINTF1(MSTP_PRX, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                         "PRX:", MSTP_PRX_STATE_s[commPortPtr->prxState],
                         MSTP_PRX_STATE_s[MSTP_PRX_STATE_DISCARD], lport);
      commPortPtr->prxState = MSTP_PRX_STATE_DISCARD;
      mstp_prxSmDiscardAct(lport);
   }
}
/**PROC+**********************************************************************
 * Name:      mstp_prxSmDiscardCond
 *
 * Purpose:   Check for the conditions to transition to the next state
 *            The current state is 'DISCARD'.
 *
 * Params:    pkt   -> pointer to the packet buffer with received BPDU in
 *            lport -> logical port number a BPDU was received on
 *
 * Returns:   TRUE, indicating that the state has been changed
 *            and the immediate check for the exit conditions from this
 *            new state is required; FALSE otherwise.
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
static bool
mstp_prxSmDiscardCond(MSTP_RX_PDU *pkt, LPORT_t lport)
{
   bool                   res         = FALSE;
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr && (commPortPtr->prxState == MSTP_PRX_STATE_DISCARD));

   if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_RCVD_BPDU) &&
      MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_PORT_ENABLED))
   {/* 'rcvdBpdu' && 'portEnabled' */

      /*---------------------------------------------------------------------
       * condition for transition to the 'RECEIVE' state
       *---------------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF1(MSTP_PRX, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                         "PRX:", MSTP_PRX_STATE_s[commPortPtr->prxState],
                         MSTP_PRX_STATE_s[MSTP_PRX_STATE_RECEIVE], lport);
      commPortPtr->prxState = MSTP_PRX_STATE_RECEIVE;
      mstp_prxSmReceiveAct(pkt, lport);
      res = TRUE;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prxSmReceiveCond
 *
 * Purpose:   Check for the conditions to transition to the next state
 *            The current state is 'RECEIVE'.
 *
 * Params:    pkt   -> pointer to the packet buffer with received BPDU in
 *            lport -> logical port number a BPDU was received on
 *
 * Returns:   TRUE, indicating that the state has been changed (re-entered)
 *            and the immediate check for the exit conditions from this new
 *            state is required; FALSE otherwise.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_prxSmReceiveCond(MSTP_RX_PDU *pkt, LPORT_t lport)
{
   bool                   res         = FALSE;
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);
   bool                  rcvdAnyMsg  = mstp_rcvdAnyMsgCondition(lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(commPortPtr && (commPortPtr->prxState == MSTP_PRX_STATE_RECEIVE));

   if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_RCVD_BPDU) &&
      MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_PORT_ENABLED) &&
      !rcvdAnyMsg)
   {/* 'rcvdBpdu' && 'portEnabled' && '!rcvdAnyMsg' */

      /*---------------------------------------------------------------------
       * condition for transition (re-enter) to the 'RECEIVE' state
       *---------------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF1(MSTP_PRX, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                         "PRX:", MSTP_PRX_STATE_s[commPortPtr->prxState],
                         MSTP_PRX_STATE_s[MSTP_PRX_STATE_RECEIVE], lport);
      commPortPtr->prxState = MSTP_PRX_STATE_RECEIVE;
      mstp_prxSmReceiveAct(pkt, lport);
      res = TRUE;
   }

   return res;
}
/**PROC+**********************************************************************
 * Name:      mstp_prxSmDiscardAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'DISCARD' state
 *            ('rcvdBpdu' = 'rcvdRSTP' = 'rcvdSTP' = FALSE;
 *             clearAllRcvdMsgs();
 *             'edgeDelayWhile' = 'MigrateTime';)
 *
 * Params:    lport -> logical port number
 *
 * Returns:   mstp_Bridge
 *
 * Globals:
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_prxSmDiscardAct(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr);

   MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_RCVD_BPDU);
   MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_RCVD_RSTP);
   MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_RCVD_STP);
   mstp_clearAllRcvdMsgs(lport);
   commPortPtr->edgeDelayWhile = mstp_Bridge.MigrateTime;

   if(MSTP_BEGIN == FALSE)
   {
      /*------------------------------------------------------------------------
       * kick Bridge Detection state machine (per-Port)
       *------------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF(MSTP_PRX, MSTP_PER_PORT_SM_CALL_SM_FMT,
                             "PRX:", "DISCARD", "BDM:", lport);
      mstp_bdmSm(lport);

      /*---------------------------------------------------------------------
       * kick Port Protocol Migration state machine (per-Port)
       *---------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF(MSTP_PRX, MSTP_PER_PORT_SM_CALL_SM_FMT,
                             "PRX:", "DISCARD", "PPM:", lport);
      mstp_ppmSm(lport);
   }
}
/**PROC+**********************************************************************
 * Name:      mstp_prxSmReceiveAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'RECEIVE' state
 *            (updtBPDUVersion();
 *             'rcvdInternal' = fromSameRegion();
 *             setRcvdMsgs();
 *             'operEdge' = 'rcvdBpdu' = FALSE;
 *             'edgeDelayWhile' = 'MigrateTime';)
 *
 * Params:    pkt   -> pointer to the packet buffer with received BPDU in
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_prxSmReceiveAct(MSTP_RX_PDU *pkt, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t  *commPortPtr = MSTP_COMM_PORT_PTR(lport);
   MSTID_t                 mstid;
   MSTP_CIST_PORT_INFO_t  *cistPortPtr   = NULL;
   MSTP_MSTI_PORT_INFO_t  *mstiPortPtr   = NULL;
   bool                   loopGuardEnabled = FALSE;

   STP_ASSERT(pkt);
   STP_ASSERT(IS_VALID_LPORT(lport));

   /*------------------------------------------------------------------------
    * 'mstp_updtBPDUVersion' function sets either the 'rcvdRSTP' or the
    * 'rcvdSTP' flag to reflect the type of the BPDU for use by the Protocol
    * Migration machine.
    *------------------------------------------------------------------------*/
   mstp_updtBPDUVersion(pkt, lport);

   /*------------------------------------------------------------------------
    * set the 'rcvdInternal' flag if the received BPDU conveys an MST
    * Configuration Identifier that matches that held for this Bridge,
    * clear that flag otherwise.
    *------------------------------------------------------------------------*/
   if(mstp_fromSameRegion(pkt, lport))
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_RCVD_INTERNAL);
   else
      MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_RCVD_INTERNAL);

   /*------------------------------------------------------------------------
    * set 'rcvdMsg' flag for the CIST, and additionally for each MSTI in the
    * received BPDU, if the 'rcvdBPDU' is internal.
    *------------------------------------------------------------------------*/
   mstp_setRcvdMsgs(pkt, lport);

   /*------------------------------------------------------------------------
    * clear 'operEdge' flag
    *------------------------------------------------------------------------*/
   MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_OPER_EDGE);

   /*------------------------------------------------------------------------
    * clear 'rcvdBpdu' flag
    *------------------------------------------------------------------------*/
   MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_RCVD_BPDU);

   /*------------------------------------------------------------------------
    * Check if Loop guard is enabled for port.
    * Reset the inconsistent state for CIST/MSTI.
    *------------------------------------------------------------------------*/
   if(MSTP_COMM_PORT_IS_LOOP_GUARD_PROTECTED(lport))
   {
      loopGuardEnabled = TRUE;
   }

   cistPortPtr = MSTP_CIST_PORT_PTR(lport);

   if(cistPortPtr &&
      cistPortPtr->loopInconsistent &&
      loopGuardEnabled)
   {
      /*----------------------------------------------
       * Reset the inconsistent state of CIST to FALSE
       * as we have received a BPDU.
       *---------------------------------------------*/
      char   portName[PORTNAME_LEN];

      intf_get_port_name(lport, portName);
      cistPortPtr->loopInconsistent = FALSE;

      VLOG_DBG("port %s moved out of inconsistent state for %s",portName,"CIST");
      log_event("MSTP_OUT_INCONSISTENT",
          EV_KV("port", "%s", portName),
          EV_KV("proto", "%s", "CIST"));

   }

   /*------------------------------------------------------------------------
    * 'edgeDelayWhile' = 'MigrateTime'
    * NOTE: In our implementation the "edgeDelayWhile" timer may expire
    *           prematurely - faster then in 3 seconds interval as specified
    *           by the standard. The 'edgeDelayWhile' timer state is being
    *           controlled by two state machines:
    *           - PTI (Port Timers State Machine)
    *           - PRX (Port Receive State Machine)
    *          These state machines are not synchronized to each other.
    *          The PTI is driven by local switch's 1 second timer ticks,
    *          decrementing all MSTP timer counters down on every timer tick
    *          event. The PRX is driven by external BPDU TX process, which
    *          suppose to send BPDUs in 2 second intervals (by default), the
    *          PRX restarts the "edgeDelayWhile" timer to the next 3 seconds
    *          on every BPDU receive event.
    *          Since PTI and PRX run asynchronously the actual 'edgeDelayWhile'
    *          time interval varies in a range of 2.xx-3.00 seconds, depending
    *          on how timer tick and the BPDU receive events correlate (pretty
    *          much random correlation), and if external BPDU TX process exceeds
    *          the .xx fraction the 'edgeDelayWhile' timer may expire too early.
    *          So we are adding an extra second here to align the 'local timer',
    *          'local receive' and 'remote transmit' tasks to the 3.xx-4
    *          seconds interval to escape premature expiration of the
    *          'edgeDelayWhile' timer in fragile bridges environment.
    *------------------------------------------------------------------------*/
   commPortPtr->edgeDelayWhile = mstp_Bridge.MigrateTime + 1;
   /*------------------------------------------------------------------------
    * kick Bridge Detection state machine (per-Port)
    *------------------------------------------------------------------------*/
   MSTP_SM_CALL_SM_PRINTF(MSTP_PRX, MSTP_PER_PORT_SM_CALL_SM_FMT,
           "PRX:", "RECEIVE", "BDM:", lport);
   mstp_bdmSm(lport);

   /*------------------------------------------------------------------------
    * clear 'rcvdBpdu' flag
    *------------------------------------------------------------------------*/
   MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_RCVD_BPDU);

   /*------------------------------------------------------------------------
    *     * kick Port Protocol Migration state machine (per-Port)
    *------------------------------------------------------------------------*/
   MSTP_SM_CALL_SM_PRINTF(MSTP_PRX, MSTP_PER_PORT_SM_CALL_SM_FMT,
           "PRX:", "RECEIVE", "PPM:", lport);
   mstp_ppmSm(lport);

   /*------------------------------------------------------------------------
    * kick Port Information state machine for the CIST (per-Tree per-Port)
    *------------------------------------------------------------------------*/
   MSTP_SM_CALL_SM_PRINTF(MSTP_PRX, MSTP_PER_PORT_SM_CALL_SM_FMT,
                          "PRX:", "RECEIVE", "PIM:", lport);

   STP_ASSERT(MSTP_CIST_PORT_PTR(lport));
   STP_ASSERT(MSTP_CIST_PORT_IS_BIT_SET(MSTP_CIST_PORT_PTR(lport)->bitMap,
                                    MSTP_CIST_PORT_RCVD_MSG));
   mstp_pimSm(pkt, MSTP_CISTID, lport);

   /*------------------------------------------------------------------------
    * kick appropriate state machines for every MSTI found in BPDU,
    * if such MSTI is configured on the Bridge
    *------------------------------------------------------------------------*/
   if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_RCVD_INTERNAL))
   {
      MSTP_MSTI_CONFIG_MSG_t *mstiCfgMsgPtr = NULL;
      while((mstiCfgMsgPtr = mstp_findNextMstiCfgMsgInBpdu(pkt, mstiCfgMsgPtr)))
      {
         mstid = MSTP_GET_BRIDGE_SYS_ID_FROM_PKT(mstiCfgMsgPtr->mstiRgnRootId);
         if(MSTP_VALID_MSTID(mstid) && MSTP_MSTI_VALID(mstid))
         {
            /*----------------------------------------------
             * Reset the inconsistent state of MST instance
             * to FALSE as we have received a BPDU.
             *----------------------------------------------*/
            mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
            if (mstiPortPtr &&
                mstiPortPtr->loopInconsistent &&
                loopGuardEnabled)
            {
               char   portName[PORTNAME_LEN];
               char   mstiName[8];

               intf_get_port_name(lport, portName);
               snprintf(mstiName, sizeof(mstiName), "MSTI %d", mstid);
               mstiPortPtr->loopInconsistent = FALSE;

               VLOG_DBG("port %s moved out of inconsistent state for %s",portName,mstiName);
               log_event("MSTP_OUT_INCONSISTENT",
                   EV_KV("port", "%s", portName),
                   EV_KV("proto", "%s", mstiName));
            }

            /*---------------------------------------------------------------
             * kick Port Information state machine (per-Tree per-Port)
             *---------------------------------------------------------------*/
            MSTP_SM_CALL_SM_PRINTF(MSTP_PRX, MSTP_PER_PORT_SM_CALL_SM_FMT,
                                   "PRX:", "RECEIVE", "PIM:", lport);
            mstp_pimSm(pkt, mstid, lport);
        }
      }
   }
}
