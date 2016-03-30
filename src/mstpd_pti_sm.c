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
 *    File               : mstpd_pti_sm.c
 *    Description        : MSTP Protocol Port Timer State Machine
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
#include "mstp_inlines.h"
#include "mstp_ovsdb_if.h"

VLOG_DEFINE_THIS_MODULE(mstpd_pti_sm);
/*--------------------------------------------------------------------------
 * Local functions prototypes (forward declarations)
 *--------------------------------------------------------------------------*/
static void mstp_ptiSmGeneralCond(LPORT_t lport);
static bool mstp_ptiSmOneSecondCond(LPORT_t lport);
static bool mstp_ptiSmTickCond(LPORT_t lport);
static void mstp_ptiSmOneSecondAct(LPORT_t lport);
static void mstp_ptiSmTickAct(LPORT_t lport);

/** ======================================================================= **
 *                                                                           *
 *     Global Functions (externed)                                           *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_ptiSm
 *
 * Purpose:   The entry point to the Port Timers (PTI) state machine.
 *            The PTI SM for a given Port is responsible for decrementing
 *            the timer variables for the CIST and all MSTIs for that Port
 *            with granularity of a one second.
 *            (802.1Q-REV/D5.0 13.27; 802.1D-2004 17.22;)
 *
 * Params:    lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_ptiSm(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = NULL;
   bool                  next        = FALSE;/* This variable is used to
                                               * indicate that the state
                                               * change processing
                                               * is still required */
   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   if(MSTP_BEGIN == FALSE)
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_TICK);

   mstp_ptiSmGeneralCond(lport);
   do
   {
      switch(commPortPtr->ptiState)
      {
         case MSTP_PTI_STATE_ONE_SECOND:
            next = mstp_ptiSmOneSecondCond(lport);
            break;
         case MSTP_PTI_STATE_TICK:
            next = mstp_ptiSmTickCond(lport);
            break;
         default:
            STP_ASSERT(0);
            break;
      }
   }
   while (next == TRUE);

   /*------------------------------------------------------------------------
    * when exit the state for PTI SM must be 'ONE_SECOND'
    *------------------------------------------------------------------------*/
   STP_ASSERT(commPortPtr->ptiState == MSTP_PTI_STATE_ONE_SECOND);

}

/** ======================================================================= **
 *                                                                           *
 *     Static (local to this file) Functions                                 *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_ptiSmGeneralCond
 *
 * Purpose:   Check for the conditions to transition to the next state
 *
 * Params:    lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
static void
mstp_ptiSmGeneralCond(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr  = MSTP_COMM_PORT_PTR(lport);

   /*------------------------------------------------------------------------
    * check for condition to transition to the 'ONE_SECOND' state
    *------------------------------------------------------------------------*/
   if(MSTP_BEGIN == TRUE)
   {
      if(commPortPtr->ptiState != MSTP_PTI_STATE_ONE_SECOND)
      {/* reset to the initial state */
         MSTP_SM_ST_PRINTF1(MSTP_PTI, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PTI:", MSTP_PTI_STATE_s[commPortPtr->ptiState],
                            MSTP_PTI_STATE_s[MSTP_PTI_STATE_ONE_SECOND],
                            lport);
         commPortPtr->ptiState = MSTP_PTI_STATE_ONE_SECOND;
         mstp_ptiSmOneSecondAct(lport);
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_ptiSmOneSecondCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'ONE_SECOND'
 *
 * Params:    lport -> logical port number
 *
 * Returns:   TRUE, indicating that the state has been changed to the 'TICK'
 *            and the immediate check for the exit conditions from this state
 *            is required; FALSE otherwise.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_ptiSmOneSecondCond(LPORT_t lport)
{
   bool                   res = FALSE;
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr && (commPortPtr->ptiState == MSTP_PTI_STATE_ONE_SECOND));

   if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_TICK))
   {
      /*---------------------------------------------------------------------
       * condition for transition to the 'TICK' state
       *---------------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF1(MSTP_PTI, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                         "PTI:", MSTP_PTI_STATE_s[commPortPtr->ptiState],
                         MSTP_PTI_STATE_s[MSTP_PTI_STATE_TICK], lport);
      commPortPtr->ptiState = MSTP_PTI_STATE_TICK;
      mstp_ptiSmTickAct(lport);
      res = TRUE;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_ptiSmTickCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'TICK'
 *
 * Params:    lport -> logical port number
 *
 * Returns:   FALSE, indicating that no immediate check for the exit conditions
 *            from the new state is required.
 *
 * Globals:
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_ptiSmTickCond(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(commPortPtr && (commPortPtr->ptiState == MSTP_PTI_STATE_TICK));

   /*------------------------------------------------------------------------
    * transition to the 'ONE_SECOND' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF1(MSTP_PTI, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                      "PTI:", MSTP_PTI_STATE_s[commPortPtr->ptiState],
                      MSTP_PTI_STATE_s[MSTP_PTI_STATE_ONE_SECOND], lport);
   commPortPtr->ptiState = MSTP_PTI_STATE_ONE_SECOND;
   mstp_ptiSmOneSecondAct(lport);

   return FALSE;
}

/**PROC+**********************************************************************
 * Name:      mstp_ptiSmOneSecondAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'ONE_SECOND' state
 *            ('tick' = FALSE;)
 *
 * Params:    lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_ptiSmOneSecondAct(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr);

   MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_TICK);
}

/**PROC+**********************************************************************
 * Name:      mstp_ptiSmTickAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'TICK' state
 *            (dec(helloWhen); dec(tcWhile); dec(fdWhile);
 *             dec(rcvdInfoWhile); dec(rrWhile);
 *             dec(rbWhile);dec(mdelayWhile); dec(edgeDelayWhile);
 *             dec(txCount);)
 *
 * Params:    lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_ptiSmTickAct(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);
   MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);
   bool                  call_prtSm  = FALSE;
   bool                  portEnabled = FALSE;
   MSTID_t                mstid = 0;
   bool                  loopGuardEnabled = FALSE;

   STP_ASSERT(commPortPtr);
   STP_ASSERT(cistPortPtr);

   portEnabled = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                        MSTP_PORT_PORT_ENABLED);

   if(MSTP_COMM_PORT_IS_LOOP_GUARD_PROTECTED(lport))
   {
      loopGuardEnabled = TRUE;
   }

   /*------------------------------------------------------------------------
    * The Port should be transitioned to some state on PRT SM before timers
    * become active
    *------------------------------------------------------------------------*/
   STP_ASSERT(cistPortPtr->prtState != MSTP_PRT_STATE_UNKNOWN);

   /*------------------------------------------------------------------------
    * update common CIST and MSTIs State Machine Timers
    *------------------------------------------------------------------------*/

   if(commPortPtr->edgeDelayWhile)
   {
      commPortPtr->edgeDelayWhile--;
      if(commPortPtr->edgeDelayWhile == 0)
      {/* Edge Delay Timer has expired */
         /*------------------------------------------------------------------
          * kick Bridge Detection state machine (per-Port)
          *------------------------------------------------------------------*/
         MSTP_SM_CALL_SM_PRINTF(MSTP_PTI,MSTP_PER_PORT_SM_CALL_SM_FMT,
                                "PTI:", "TICK", "BDM:", lport);
         mstp_bdmSm(lport);
      }
   }

   if(commPortPtr->helloWhen)
   {
      commPortPtr->helloWhen--;
      if(commPortPtr->helloWhen == 0)
      {/* Transmit Timer has expired */
         if(portEnabled)
         {
            /*---------------------------------------------------------------
             * kick Port Transmit state machine (per-Port)
             *---------------------------------------------------------------*/
            MSTP_SM_CALL_SM_PRINTF(MSTP_PTI,MSTP_PER_PORT_SM_CALL_SM_FMT,
                                   "PTI:", "TICK", "PTX:", lport);
            mstp_ptxSm(lport);
         }

      }
   }

   if(commPortPtr->mdelayWhile)
   {
      commPortPtr->mdelayWhile--;
      if(commPortPtr->mdelayWhile == 0)
      {/* Migration Timer has expired */
         if(portEnabled)
         {
            /*---------------------------------------------------------------
             * kick Port Protocol Migration state machine (per-Port)
             *---------------------------------------------------------------*/
            MSTP_SM_CALL_SM_PRINTF(MSTP_PTI,MSTP_PER_PORT_SM_CALL_SM_FMT,
                                   "PTI:", "TICK", "PPM:", lport);
            mstp_ppmSm(lport);
         }
      }
   }

   if(commPortPtr->txCount)
      commPortPtr->txCount--;

   /*------------------------------------------------------------------------
    * update CIST's State Machine Timers
    *------------------------------------------------------------------------*/

   if(cistPortPtr->tcWhile)
   {
       cistPortPtr->tcWhile--;
       if(cistPortPtr->tcWhile == 0)
       {
           mstp_util_set_msti_table_string(TOPOLOGY_CHANGE,"disable",mstid);
       }
   }

   if(cistPortPtr->fdWhile &&
      (cistPortPtr->prtState != MSTP_PRT_STATE_DISABLED_PORT))
   {
      cistPortPtr->fdWhile--;
      if(cistPortPtr->fdWhile == 0)
         call_prtSm = TRUE;
   }

   if(cistPortPtr->rrWhile)
   {
      cistPortPtr->rrWhile--;
      if(cistPortPtr->rrWhile == 0)
         call_prtSm = TRUE;
   }

   if(cistPortPtr->rbWhile)
   {
      cistPortPtr->rbWhile--;
      if(cistPortPtr->rbWhile == 0)
         call_prtSm = TRUE;
   }

   if(call_prtSm)
   {/* one (or may be all) of Role Timers has expired */
      /*------------------------------------------------------------------
       * kick Port Role Transitions state machine for the CIST
       *------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF(MSTP_PTI,MSTP_PER_PORT_SM_CALL_SM_FMT,
                             "PTI:", "TICK", "PRT:", lport);
      mstp_prtSm(MSTP_CISTID, lport);
   }

   if(cistPortPtr->rcvdInfoWhile)
   {
      cistPortPtr->rcvdInfoWhile--;
      if(cistPortPtr->rcvdInfoWhile == 0)
      {/* aging timer has expired */
         if((commPortPtr->rcvdSelfSentPkt == FALSE) &&
            ((cistPortPtr->role == MSTP_PORT_ROLE_ROOT) ||
             (cistPortPtr->role == MSTP_PORT_ROLE_ALTERNATE) ||
             (cistPortPtr->role == MSTP_PORT_ROLE_BACKUP)))
         {
            char                     portName[PORTNAME_LEN];
            char                     dsnBridgeName[20];
            MSTP_BRIDGE_IDENTIFIER_t dsnBridgeId =
                                         cistPortPtr->portPriority.dsnBridgeID;

            /* Update statistics counter */
            cistPortPtr->dbgCnts.starvedBpduCnt++;
            cistPortPtr->dbgCnts.starvedBpduCntLastUpdated =
                                                         time(NULL);
            /* log RMON event */
            intf_get_port_name(lport, portName);
            snprintf(dsnBridgeName, sizeof(dsnBridgeName),
                     "%d:%02x%02x%02x-%02x%02x%02x",
                     MSTP_GET_BRIDGE_PRIORITY(dsnBridgeId),
                     PRINT_MAC_ADDR(dsnBridgeId.mac_address));
            VLOG_DBG("%s starved for %s on port %s from %s","CIST","a BPDU Rx",portName,dsnBridgeName);
            if(loopGuardEnabled)
            {
               cistPortPtr->loopInconsistent = TRUE;

               VLOG_DBG("bpdu loss- port %s moved to inconsistent state for %s", portName,
                     "CIST");
#if OPS_MSTP_TODO
               /*send a trap*/
               mstp_sendLoopGuardInconsistencyTrap(MSTP_CISTID,lport);
#endif /*OPS_MSTP_TODO*/
            }
         }

         if(cistPortPtr->loopInconsistent == FALSE ||
            cistPortPtr->role == MSTP_PORT_ROLE_ROOT)
         {
            /*------------------------------------------------------------------
             * kick Port Information state machine for the CIST
             *------------------------------------------------------------------*/
            MSTP_SM_CALL_SM_PRINTF(MSTP_PTI,MSTP_PER_PORT_SM_CALL_SM_FMT,
                  "PTI:", "TICK", "PIM:", lport);
            mstp_pimSm(NULL, MSTP_CISTID, lport);
         }
      }
   }

   /*------------------------------------------------------------------------
    * update MSTI's State Machine Timers (for every active tree)
    *------------------------------------------------------------------------*/

   for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_MSTID_MAX; mstid++)
   {
      if(MSTP_MSTI_VALID(mstid))
      {
         MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

         STP_ASSERT(mstiPortPtr);

         if(mstiPortPtr)
         {
            call_prtSm = FALSE;

            if(mstiPortPtr->tcWhile)
            {
               mstiPortPtr->tcWhile--;
               if(mstiPortPtr->tcWhile == 0)
               {
                   mstp_util_set_msti_table_string(TOPOLOGY_CHANGE,"disable",mstid);
               }
            }

            if(mstiPortPtr->fdWhile &&
               (mstiPortPtr->prtState != MSTP_PRT_STATE_DISABLED_PORT))
            {
               mstiPortPtr->fdWhile--;
               if(mstiPortPtr->fdWhile == 0)
                  call_prtSm = TRUE;
            }

            if(mstiPortPtr->rrWhile)
            {
               mstiPortPtr->rrWhile--;
               if(mstiPortPtr->rrWhile == 0)
                  call_prtSm = TRUE;
            }

            if(mstiPortPtr->rbWhile)
            {
               mstiPortPtr->rbWhile--;
               if(mstiPortPtr->rbWhile == 0)
                  call_prtSm = TRUE;
            }

            if(call_prtSm)
            {/* one (or may be all) of Role Timers has expired */
               /*------------------------------------------------------------
                * kick Port Role Transitions state machine for the MSTI
                *------------------------------------------------------------*/
               MSTP_SM_CALL_SM_PRINTF(MSTP_PTI,MSTP_PER_PORT_SM_CALL_SM_FMT,
                                      "PTI:", "TICK", "PRT:", lport);
               mstp_prtSm(mstid, lport);
            }

            if(mstiPortPtr->rcvdInfoWhile)
            {
               mstiPortPtr->rcvdInfoWhile--;
               if(mstiPortPtr->rcvdInfoWhile == 0)
               {/* aging timer has expired */
                  if((commPortPtr->rcvdSelfSentPkt == FALSE) &&
                        ((mstiPortPtr->role == MSTP_PORT_ROLE_ROOT) ||
                         (mstiPortPtr->role == MSTP_PORT_ROLE_ALTERNATE) ||
                         (mstiPortPtr->role == MSTP_PORT_ROLE_BACKUP)))
                  {
                     char                     portName[PORTNAME_LEN];
                     char                     mstiName[8];
                     char                     dsnBridgeName[20];
                     MSTP_BRIDGE_IDENTIFIER_t dsnBridgeId =
                        mstiPortPtr->portPriority.dsnBridgeID;

                     /* Update statistics counter */
                     mstiPortPtr->dbgCnts.starvedMsgCnt++;
                     mstiPortPtr->dbgCnts.starvedMsgCntLastUpdated =
                        time(NULL);
                     /* log RMON event */
                     intf_get_port_name(lport, portName);
                     snprintf(mstiName, sizeof(mstiName), "MSTI %d",mstid);
                     snprintf(dsnBridgeName, sizeof(dsnBridgeName),
                           "%d:%02x%02x%02x-%02x%02x%02x",
                           MSTP_GET_BRIDGE_PRIORITY(dsnBridgeId),
                           PRINT_MAC_ADDR(dsnBridgeId.mac_address));
                     VLOG_DBG("%s starved for %s on port %s from %s",
                           mstiName, "an MSTI Msg Rx", portName,
                           dsnBridgeName);
                     if(loopGuardEnabled)
                     {
                        mstiPortPtr->loopInconsistent = TRUE;

                        VLOG_DBG("bpdu loss- port %s moved to inconsistent state for %s",
                              portName, mstiName);
#ifdef OPS_MSTP_TODO
                        /*send a trap*/
                        mstp_sendLoopGuardInconsistencyTrap(mstid, lport);
#endif /*OPS_MSTP_TODO*/
                     }
                  }

                  if((mstiPortPtr->loopInconsistent == FALSE) ||
                     (mstiPortPtr->role == MSTP_PORT_ROLE_ROOT))
                  {
                     /*---------------------------------------------------------
                      * kick Port Information state machine for the MSTI
                      *---------------------------------------------------------*/
                     MSTP_SM_CALL_SM_PRINTF(MSTP_PTI,MSTP_PER_PORT_SM_CALL_SM_FMT,
                           "PTI:", "TICK", "PIM:", lport);
                     mstp_pimSm(NULL, mstid, lport);
                  }
               }
            }
         }
      }
   }
}
