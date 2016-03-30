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
 *    File               : mstpd_pim_sm.c
 *    Description        : MSTP Protocol Port Information State Machine Entry point
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

VLOG_DEFINE_THIS_MODULE(mstpd_pim_sm);
/*---------------------------------------------------------------------------
 * Local functions prototypes (forward declarations)
 *---------------------------------------------------------------------------*/
static void mstp_pimSmGeneralCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_pimSmDisabledCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_pimSmAgedCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_pimSmUpdateCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_pimSmCurrentCond(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport);
static bool mstp_pimSmReceiveCond(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport);
static bool mstp_pimSmSuperiorDesignatedCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_pimSmRepeatedDesignatedCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_pimSmInferiorDesignatedCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_pimSmNotDesignatedCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_pimSmOtherCond(MSTID_t mstid, LPORT_t lport);

static void mstp_pimSmDisabledAct(MSTID_t mstid, LPORT_t lport);
static void mstp_pimSmAgedAct(MSTID_t mstid, LPORT_t lport);
static void mstp_pimSmUpdateAct(MSTID_t mstid, LPORT_t lport);
static void mstp_pimSmReceiveAct(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport);
static void mstp_pimSmSuperiorDesignatedAct(MSTP_RX_PDU *pkt, MSTID_t mstid,
                                             LPORT_t lport);
static void mstp_pimSmRepeatedDesignatedAct(MSTP_RX_PDU *pkt, MSTID_t mstid,
                                            LPORT_t lport);
static void mstp_pimSmInferiorDesignatedAct(MSTP_RX_PDU *pkt, MSTID_t mstid,
                                            LPORT_t lport);
static void mstp_pimSmNotDesignatedAct(MSTP_RX_PDU *pkt, MSTID_t mstid,
                                       LPORT_t lport);
static void mstp_pimSmOtherAct(MSTID_t mstid, LPORT_t lport);
static void  mstp_syncMstiPortsWithCist(LPORT_t lport);


/** ======================================================================= **
 *                                                                           *
 *     Global Functions (externed)                                           *
 *                                                                           *
 ** ======================================================================= **/
/**PROC+**********************************************************************
 * Name:      mstp_pimSm
 *
 * Purpose:   The entry point to the Port Information (PIM) state machine.
 *            NOTE: The Port Information state machine is responsible for
 *                  recording the Spanning Tree information currently in use
 *                  by the CIST or a given MSTI for a given Port, ageing that
 *                  information out if it was derived from an incoming BPDU,
 *                  and recording the origin of the information in the 'infoIs'
 *                  variable. The 'selected' variable is cleared and 'reselect'
 *                  set to signal to the Port Role Selection machine that port
 *                  roles need to be recomputed. The 'infoIs' and 'portPriority'
 *                  variables from all ports are used in that computation and,
 *                  together with 'portTimes', determine new values of
 *                  'designatedPriority' and 'designatedTimes'. The 'selected'
 *                  variable is set by the Port Role Selection machine once the
 *                  computation is complete.
 *           (802.1Q-REV/D5.0 13.32)
 *
 * Params:    pkt   -> pointer to the packet buffer with received BPDU in
 *                     (can be NULL when this SM is being initialized, e.g.
 *                     after enabling protocol on the tree via configuration
 *                     request or at the boot time)
 *            mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:
 *
 **PROC-**********************************************************************/
void
mstp_pimSm(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport)
{
   bool             next     = FALSE;/* This variable is used to indicate
                                       * that the state change processing is
                                       * still required */
   MSTP_PIM_STATE_t *statePtr = NULL;

   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(MSTP_INSTANCE_IS_VALID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));

   statePtr = mstp_utilPimStatePtr(mstid, lport);
   STP_ASSERT(statePtr);

   /* Check for global (external) conditions that may affect the
    * the current PIM SM state */
   mstp_pimSmGeneralCond(mstid, lport);

   /* Run PIM State Machine */
   do
   {
      switch(*statePtr)
      {
         case MSTP_PIM_STATE_DISABLED:
            next = mstp_pimSmDisabledCond(mstid, lport);
            break;
         case MSTP_PIM_STATE_AGED:
            next = mstp_pimSmAgedCond(mstid, lport);
            break;
         case MSTP_PIM_STATE_UPDATE:
            next = mstp_pimSmUpdateCond(mstid, lport);
            break;
         case MSTP_PIM_STATE_CURRENT:
            next = mstp_pimSmCurrentCond(pkt, mstid, lport);
            break;
         case MSTP_PIM_STATE_RECEIVE:
            next = mstp_pimSmReceiveCond(pkt, mstid, lport);
            break;
         case MSTP_PIM_STATE_SUPERIOR_DESIGNATED:
            next = mstp_pimSmSuperiorDesignatedCond(mstid, lport);
            break;
         case MSTP_PIM_STATE_REPEATED_DESIGNATED:
            next = mstp_pimSmRepeatedDesignatedCond(mstid, lport);
            break;
         case MSTP_PIM_STATE_INFERIOR_DESIGNATED:
            next = mstp_pimSmInferiorDesignatedCond(mstid, lport);
            break;
         case MSTP_PIM_STATE_NOT_DESIGNATED:
            next = mstp_pimSmNotDesignatedCond(mstid, lport);
            break;
         case MSTP_PIM_STATE_OTHER:
            next = mstp_pimSmOtherCond(mstid, lport);
            break;
         default:
            STP_ASSERT(0);
            break;
      }
   }
   while (next == TRUE);

   /*------------------------------------------------------------------------
    * when exit the state for PIM SM must be 'CURRENT' || 'DISABLED'
    * NOTE: 'AGED' state could be the legal final state for an MSTI's port
    *       located on the boundary of a MST region
    *------------------------------------------------------------------------*/
   STP_ASSERT(*statePtr == MSTP_PIM_STATE_CURRENT ||
          *statePtr == MSTP_PIM_STATE_DISABLED ||
          (mstid != MSTP_CISTID ? *statePtr == MSTP_PIM_STATE_AGED : FALSE));
}
/** ======================================================================= **
 *                                                                           *
 *     Static (local to this file) Functions                                 *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_pimSmGeneralCond
 *
 * Purpose:   Check for the conditions to transition to the next state
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_pimSmGeneralCond(MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = NULL;
   MSTP_PIM_STATE_t      *statePtr    = NULL;
   MSTP_INFO_IS_t         infoIs      = MSTP_INFO_IS_UNKNOWN;

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);
   statePtr = mstp_utilPimStatePtr(mstid, lport);
   STP_ASSERT(statePtr);

   /*------------------------------------------------------------------------
    * collect state change conditions information
    *------------------------------------------------------------------------*/
   STP_ASSERT((mstid == MSTP_CISTID) ? (MSTP_CIST_PORT_PTR(lport) != NULL) :
                                   (MSTP_MSTI_PORT_PTR(mstid, lport) != NULL));
   infoIs = (mstid == MSTP_CISTID) ? MSTP_CIST_PORT_PTR(lport)->infoIs :
                                     MSTP_MSTI_PORT_PTR(mstid, lport)->infoIs;

   /*------------------------------------------------------------------------
    * check for conditions to transition to the 'DISABLED' state
    *------------------------------------------------------------------------*/
   if((!MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_PORT_ENABLED)
       && (infoIs != MSTP_INFO_IS_DISABLED)) || (MSTP_BEGIN == TRUE))
   {/*(!portEnabled && (infoIs != Disabled)) || BEGIN*/
      if(*statePtr != MSTP_PIM_STATE_DISABLED)
      {
         MSTP_SM_ST_PRINTF(MSTP_PIM,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PIM:",MSTP_PIM_STATE_s[*statePtr],
                           MSTP_PIM_STATE_s[MSTP_PIM_STATE_DISABLED],
                           mstid, lport);
         *statePtr = MSTP_PIM_STATE_DISABLED;
         mstp_pimSmDisabledAct(mstid, lport);
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_pimSmDisabledCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'DISABLED'.
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   TRUE, indicating that the state has been changed (or re-entered)
 *            and the immediate check for the exit conditions from this state
 *            is required; FALSE otherwise.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_pimSmDisabledCond(MSTID_t mstid, LPORT_t lport)
{
   bool                   res         = FALSE;
   bool                   rcvdMsg     = FALSE;
   MSTP_PIM_STATE_t      *statePtr    = NULL;
   MSTP_COMM_PORT_INFO_t *commPortPtr = NULL;

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);
   statePtr = mstp_utilPimStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PIM_STATE_DISABLED));

   /*------------------------------------------------------------------------
    * collect state exit conditions information
    *------------------------------------------------------------------------*/
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      rcvdMsg  = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                           MSTP_CIST_PORT_RCVD_MSG);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      rcvdMsg  = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                           MSTP_MSTI_PORT_RCVD_MSG);
   }

   /*------------------------------------------------------------------------
    * check for conditions to transition to the next state
    *------------------------------------------------------------------------*/
   if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_PORT_ENABLED))
   {/* 'portEnabled' */

      /*---------------------------------------------------------------------
       * condition for transition to the 'AGED' state
       *---------------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF(MSTP_PIM,
                        MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                        "PIM:",MSTP_PIM_STATE_s[*statePtr],
                        MSTP_PIM_STATE_s[MSTP_PIM_STATE_AGED],
                        mstid, lport);
      *statePtr = MSTP_PIM_STATE_AGED;
      mstp_pimSmAgedAct(mstid, lport);
      res = FALSE;
   }
   else if(rcvdMsg)
   {
      if(*statePtr != MSTP_PIM_STATE_DISABLED)
      {
         /*---------------------------------------------------------------
          * condition for transition (re-enter) to the 'DISABLED' state
          *---------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PIM,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PIM:", MSTP_PIM_STATE_s[*statePtr],
                           MSTP_PIM_STATE_s[MSTP_PIM_STATE_DISABLED],
                           mstid, lport);
         *statePtr = MSTP_PIM_STATE_DISABLED;
         mstp_pimSmDisabledAct(mstid, lport);
         res = TRUE;
      }
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_pimSmAgedCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'AGED'.
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   TRUE, indicating that the state has been changed to the 'UPDATE'
 *            and the immediate check for the exit conditions from this state
 *            is required; FALSE otherwise.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_pimSmAgedCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = FALSE;
   bool              selected = FALSE;
   bool              updtInfo = FALSE;
   MSTP_PIM_STATE_t *statePtr = NULL;

   statePtr = mstp_utilPimStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PIM_STATE_AGED));

   /*------------------------------------------------------------------------
    * collect state exit conditions information
    *------------------------------------------------------------------------*/
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      selected = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                           MSTP_CIST_PORT_SELECTED);
      updtInfo = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                           MSTP_CIST_PORT_UPDT_INFO);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      selected = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                           MSTP_MSTI_PORT_SELECTED);
      updtInfo = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                           MSTP_MSTI_PORT_UPDT_INFO);
   }

   /*------------------------------------------------------------------------
    * check for conditions to transition to the next state
    *------------------------------------------------------------------------*/
   if(selected && updtInfo)
   {/* 'selected' && 'updtInfo' */

      /*---------------------------------------------------------------------
       * condition for transition to the 'UPDATE' state
       *---------------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF(MSTP_PIM,
                        MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                        "PIM:", MSTP_PIM_STATE_s[*statePtr],
                        MSTP_PIM_STATE_s[MSTP_PIM_STATE_UPDATE], mstid, lport);
      *statePtr = MSTP_PIM_STATE_UPDATE;
      mstp_pimSmUpdateAct(mstid, lport);
      res = TRUE;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_pimSmUpdateCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'UPDATE'.
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   FALSE, indicating that no immediate check for the exit conditions
 *            from the new state is required.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_pimSmUpdateCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = FALSE;
   MSTP_PIM_STATE_t *statePtr = NULL;

   /*------------------------------------------------------------------------
    * transition to the 'CURRENT' state unconditionally
    *------------------------------------------------------------------------*/
   statePtr = mstp_utilPimStatePtr(mstid, lport);
   STP_ASSERT(statePtr && *statePtr == MSTP_PIM_STATE_UPDATE);
   MSTP_SM_ST_PRINTF(MSTP_PIM,MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PIM:", MSTP_PIM_STATE_s[*statePtr],
                     MSTP_PIM_STATE_s[MSTP_PIM_STATE_CURRENT], mstid, lport);
   *statePtr = MSTP_PIM_STATE_CURRENT;

   /*------------------------------------------------------------------------
    * there are no actions to perform when entering the 'CURRENT' state
    *------------------------------------------------------------------------*/

   return res;
}
/**PROC+**********************************************************************
 * Name:      mstp_pimSmCurrentCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'CURRENT'.
 *
 * Params:    pkt   -> pointer to the packet buffer with received BPDU in
 *            mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   TRUE, indicating that the state has been changed to the 'UPDATE'
 *            and the immediate check for the exit conditions from this state
 *            is required; FALSE otherwise.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_pimSmCurrentCond(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport)
{
   bool                   res           = FALSE;
   bool                   rcvdCistMsg   = FALSE;
   bool                   updtCistInfo  = FALSE;
   bool                   rcvdMstiMsg   = FALSE;
   bool                   updtMstiInfo  = FALSE;
   bool                   rcvdXstMsg    = FALSE;
   bool                   updtXstInfo   = FALSE;
   bool                   selected      = FALSE;
   bool                   updtInfo      = FALSE;
   uint8_t                 rcvdInfoWhile = 0;
   MSTP_COMM_PORT_INFO_t *commPortPtr   = NULL;
   MSTP_CIST_PORT_INFO_t *cistPortPtr   = NULL;
   MSTP_PIM_STATE_t      *statePtr      = NULL;
   MSTP_INFO_IS_t         infoIs;

   statePtr = mstp_utilPimStatePtr(mstid, lport);
   STP_ASSERT(statePtr && *statePtr == MSTP_PIM_STATE_CURRENT);

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   cistPortPtr = MSTP_CIST_PORT_PTR(lport);
   STP_ASSERT(cistPortPtr);

   /*------------------------------------------------------------------------
    * collect state change conditions information
    * NOTES:
    *  1). 'rcvdCistMsg' is TRUE for a given Port if and only if 'rcvdMsg'
    *      is TRUE for the CIST for that Port;
    *  2). 'rcvdMstiMsg' is TRUE for a given Port and MSTI if and only
    *      if 'rcvdMsg' is FALSE for the CIST for that Port and 'rcvdMsg'
    *      is TRUE for the MSTI for that Port;
    *  3). 'updtCistInfo' is TRUE for a given Port if and only if
    *      'updtInfo' is TRUE for the CIST for that Port;
    *  4). 'updtMstiInfo' is TRUE for a given Port and MSTI if and only if
    *      'updtInfo' is TRUE for the MSTI for that Port or 'updtInfo' is
    *      TRUE for the CIST for that Port.
    *  5)  The dependency of 'rcvdMstiMsg' and 'updtMstiInfo' on CIST
    *      variables for the Port reflects the fact that MSTIs exist in a
    *      context of CST parameters. The state machines ensure that the
    *      CIST parameters from received BPDUs are processed and updated
    *      prior to processing MSTI information.
    *  (802.1Q-REV/D5.0 13.25.12; 13.25.13; 13.25.16; 13.25.17)
    *------------------------------------------------------------------------*/

   rcvdCistMsg  = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                            MSTP_CIST_PORT_RCVD_MSG);
   updtCistInfo = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                            MSTP_CIST_PORT_UPDT_INFO);

   if(mstid == MSTP_CISTID)
   {
      selected =
         MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                   MSTP_CIST_PORT_SELECTED);
      updtInfo =
         MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                   MSTP_CIST_PORT_UPDT_INFO);
      rcvdInfoWhile = cistPortPtr->rcvdInfoWhile;
      infoIs        = cistPortPtr->infoIs;
      rcvdXstMsg    = rcvdCistMsg;
      updtXstInfo   = updtCistInfo;
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      rcvdMstiMsg = ((rcvdCistMsg == FALSE) &&
                     MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                               MSTP_MSTI_PORT_RCVD_MSG));
      updtMstiInfo =
         (MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                   MSTP_MSTI_PORT_UPDT_INFO) || updtCistInfo);
      selected =
         MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                   MSTP_MSTI_PORT_SELECTED);
      updtInfo =
         MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                   MSTP_MSTI_PORT_UPDT_INFO);
      rcvdInfoWhile = mstiPortPtr->rcvdInfoWhile;
      infoIs        = mstiPortPtr->infoIs;
      rcvdXstMsg    = rcvdMstiMsg;
      updtXstInfo   = updtMstiInfo;
   }


   /*------------------------------------------------------------------------
    * check for conditions to transition to the next state
    *------------------------------------------------------------------------*/
   if(selected && updtInfo)
   {/* 'selected' && 'updtInfo' */

      /*---------------------------------------------------------------------
       * condition for transition to the 'UPDATE' state
       *---------------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF(MSTP_PIM,
                        MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                        "PIM:", MSTP_PIM_STATE_s[*statePtr],
                        MSTP_PIM_STATE_s[MSTP_PIM_STATE_UPDATE], mstid, lport);
      *statePtr = MSTP_PIM_STATE_UPDATE;
      mstp_pimSmUpdateAct(mstid, lport);
      res = TRUE;
   }
   else if((infoIs == MSTP_INFO_IS_RECEIVED) &&
           (rcvdInfoWhile == 0) &&
           (!updtInfo && !rcvdXstMsg))
   {/* ('infoIs' == Received) && ('rcvdInfoWhile' == 0) &&
     * '!updtInfo' && '!rcvdXstMsg' */

      /*---------------------------------------------------------------------
       * condition for transition to the 'AGED' state
       *---------------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF(MSTP_PIM,
                        MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                        "PIM:", MSTP_PIM_STATE_s[*statePtr],
                        MSTP_PIM_STATE_s[MSTP_PIM_STATE_AGED], mstid, lport);
      *statePtr = MSTP_PIM_STATE_AGED;

      /* Perform state enter action */
      mstp_pimSmAgedAct(mstid, lport);
      res = FALSE;
   }
   else if(rcvdXstMsg && !updtXstInfo && pkt)
   {/* 'rcvdXstMsg' && '!updtXstInfo' */

      /*---------------------------------------------------------------------
       * condition for transition to the 'RECEIVE' state
       *---------------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF(MSTP_PIM,
                        MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                        "PIM:", MSTP_PIM_STATE_s[*statePtr],
                        MSTP_PIM_STATE_s[MSTP_PIM_STATE_RECEIVE],
                        mstid, lport);
      *statePtr = MSTP_PIM_STATE_RECEIVE;
      mstp_pimSmReceiveAct(pkt, mstid, lport);
      res = TRUE;
   }
   else
   {/* no change in state */
      MSTP_SM_ST_PRINTF(MSTP_PIM,
                        "PIM: CURRENT state not changed MST=%d,  lport=%d",
                        mstid, lport);
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_pimSmReceiveCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'RECEIVE'.
 *
 * Params:    pkt   -> pointer to the packet buffer with received BPDU in
 *            mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   TRUE, indicating that the state has been changed and the
 *            immediate check for the exit conditions from this state
 *            is required; FALSE otherwise
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_pimSmReceiveCond(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport)
{
   bool              res      = FALSE;
   MSTP_PIM_STATE_t *statePtr = NULL;
   MSTP_RCVD_INFO_t  rcvdInfo = MSTP_RCVD_INFO_UNKNOWN;

   statePtr = mstp_utilPimStatePtr(mstid, lport);
   STP_ASSERT(statePtr && *statePtr == MSTP_PIM_STATE_RECEIVE);

   /*------------------------------------------------------------------------
    * collect state change conditions information
    *------------------------------------------------------------------------*/
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      rcvdInfo = cistPortPtr->rcvdInfo;
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      rcvdInfo = mstiPortPtr->rcvdInfo;
   }

   /*------------------------------------------------------------------------
    * check for conditions to transition to the next state
    *------------------------------------------------------------------------*/
   switch(rcvdInfo)
   {
      case MSTP_RCVD_INFO_SUPERIOR_DESIGNATED:
         /*------------------------------------------------------------------
          * condition for transition to the 'SUPERIOR_DESIGNATED' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PIM,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PIM:", MSTP_PIM_STATE_s[*statePtr],
                           MSTP_PIM_STATE_s[MSTP_PIM_STATE_SUPERIOR_DESIGNATED],
                           mstid, lport);
         *statePtr = MSTP_PIM_STATE_SUPERIOR_DESIGNATED;
         mstp_pimSmSuperiorDesignatedAct(pkt, mstid, lport);
         res = TRUE;
         break;
      case MSTP_RCVD_INFO_REPEATED_DESIGNATED:
         /*------------------------------------------------------------------
          * condition for transition to the 'REPEATED_DESIGNATED' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PIM,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PIM:", MSTP_PIM_STATE_s[*statePtr],
                           MSTP_PIM_STATE_s[MSTP_PIM_STATE_REPEATED_DESIGNATED],
                           mstid, lport);
         *statePtr = MSTP_PIM_STATE_REPEATED_DESIGNATED;
         mstp_pimSmRepeatedDesignatedAct(pkt, mstid, lport);
         res = TRUE;
         break;
      case MSTP_RCVD_INFO_INFERIOR_DESIGNATED:
         /*------------------------------------------------------------------
          * condition for transition to the 'INFERIOR_DESIGNATED' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PIM,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PIM:", MSTP_PIM_STATE_s[*statePtr],
                           MSTP_PIM_STATE_s[MSTP_PIM_STATE_INFERIOR_DESIGNATED],
                           mstid, lport);
         *statePtr = MSTP_PIM_STATE_INFERIOR_DESIGNATED;
         mstp_pimSmInferiorDesignatedAct(pkt, mstid, lport);
         res = TRUE;
         break;
      case MSTP_RCVD_INFO_INFERIOR_ROOT_ALTERNATE:
         /*------------------------------------------------------------------
          * condition for transition to the 'NOT_DESIGNATED' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PIM,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PIM:", MSTP_PIM_STATE_s[*statePtr],
                           MSTP_PIM_STATE_s[MSTP_PIM_STATE_NOT_DESIGNATED],
                           mstid, lport);
         *statePtr = MSTP_PIM_STATE_NOT_DESIGNATED;
         mstp_pimSmNotDesignatedAct(pkt, mstid, lport);
         res = TRUE;
         break;
      case MSTP_RCVD_INFO_OTHER:
         /*------------------------------------------------------------------
          * condition for transition to the 'OTHER' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PIM,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PIM:", MSTP_PIM_STATE_s[*statePtr],
                           MSTP_PIM_STATE_s[MSTP_PIM_STATE_OTHER],
                           mstid, lport);
         *statePtr = MSTP_PIM_STATE_OTHER;
         mstp_pimSmOtherAct(mstid, lport);
         res = TRUE;
         break;
      default:
         /*------------------------------------------------------------------
          * wow, something is really wrong!
          *------------------------------------------------------------------*/
         STP_ASSERT(0);
         break;
   }

   return res;
}
/**PROC+**********************************************************************
 * Name:      mstp_pimSmSuperiorDesignatedCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'SUPERIOR_DESIGNATED'.
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   TRUE, indicating that the state has been changed and the
 *            immediate check for the exit conditions from this state
 *            is required
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_pimSmSuperiorDesignatedCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PIM_STATE_t *statePtr = NULL;

   statePtr = mstp_utilPimStatePtr(mstid, lport);
   STP_ASSERT(statePtr && *statePtr == MSTP_PIM_STATE_SUPERIOR_DESIGNATED);

   /*------------------------------------------------------------------------
    * transition to the 'CURRENT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PIM,MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PIM:", MSTP_PIM_STATE_s[*statePtr],
                     MSTP_PIM_STATE_s[MSTP_PIM_STATE_CURRENT],
                     mstid, lport);
   *statePtr = MSTP_PIM_STATE_CURRENT;

   /*------------------------------------------------------------------------
    * there are no actions to perform when enter the 'CURRENT' state
    *------------------------------------------------------------------------*/

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_pimSmRepeatedDesignatedCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'REPEATED_DESIGNATED'.
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   TRUE, indicating that the state has been changed and the
 *            immediate check for the exit conditions from this state
 *            is required
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_pimSmRepeatedDesignatedCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PIM_STATE_t *statePtr = NULL;

   statePtr = mstp_utilPimStatePtr(mstid, lport);
   STP_ASSERT(statePtr && *statePtr == MSTP_PIM_STATE_REPEATED_DESIGNATED);

   /*------------------------------------------------------------------------
    * transition to the 'CURRENT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PIM,MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PIM:", MSTP_PIM_STATE_s[*statePtr],
                     MSTP_PIM_STATE_s[MSTP_PIM_STATE_CURRENT],
                     mstid, lport);
   *statePtr = MSTP_PIM_STATE_CURRENT;

   /*------------------------------------------------------------------------
    * there are no actions to perform when enter the 'CURRENT' state
    *------------------------------------------------------------------------*/

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_pimSmInferiorDesignatedCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'INFERIOR_DESIGNATED'.
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   FALSE, indicating that no immediate check for the exit conditions
 *            from the new state is required.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_pimSmInferiorDesignatedCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = FALSE;
   MSTP_PIM_STATE_t *statePtr = NULL;

   statePtr = mstp_utilPimStatePtr(mstid, lport);
   STP_ASSERT(statePtr && *statePtr == MSTP_PIM_STATE_INFERIOR_DESIGNATED);

   /*------------------------------------------------------------------------
    * transition to the 'CURRENT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PIM,MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PIM:", MSTP_PIM_STATE_s[*statePtr],
                     MSTP_PIM_STATE_s[MSTP_PIM_STATE_CURRENT],
                     mstid, lport);
   *statePtr = MSTP_PIM_STATE_CURRENT;

   /*------------------------------------------------------------------------
    * there are no actions to perform when enter the 'CURRENT' state
    *------------------------------------------------------------------------*/

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_pimSmNotDesignatedCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'NOT_DESIGNATED'.
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   FALSE, indicating that no immediate check for the exit conditions
 *            from the new state is required.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_pimSmNotDesignatedCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = FALSE;
   MSTP_PIM_STATE_t *statePtr = NULL;

   statePtr = mstp_utilPimStatePtr(mstid, lport);
   STP_ASSERT(statePtr && *statePtr == MSTP_PIM_STATE_NOT_DESIGNATED);

   /*------------------------------------------------------------------------
    * transition to the 'CURRENT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PIM,MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PIM:", MSTP_PIM_STATE_s[*statePtr],
                     MSTP_PIM_STATE_s[MSTP_PIM_STATE_CURRENT],
                     mstid, lport);
   *statePtr = MSTP_PIM_STATE_CURRENT;

   /*------------------------------------------------------------------------
    * there are no actions to perform when enter the 'CURRENT' state
    *------------------------------------------------------------------------*/

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_pimSmOtherCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'OTHER'.
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   FALSE, indicating that no immediate check for the exit conditions
 *            from the new state is required.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_pimSmOtherCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = FALSE;
   MSTP_PIM_STATE_t *statePtr = NULL;

   statePtr = mstp_utilPimStatePtr(mstid, lport);
   STP_ASSERT(statePtr && *statePtr == MSTP_PIM_STATE_OTHER);

   /*------------------------------------------------------------------------
    * transition to the 'CURRENT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PIM,MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PIM:", MSTP_PIM_STATE_s[*statePtr],
                     MSTP_PIM_STATE_s[MSTP_PIM_STATE_CURRENT], mstid, lport);
   *statePtr = MSTP_PIM_STATE_CURRENT;

   /*------------------------------------------------------------------------
    * there are no actions to perform when enter the 'CURRENT' state
    *------------------------------------------------------------------------*/

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_pimSmDisabledAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'DISABLED' state.
 *            ('rcvdMsg' = FALSE;
 *             'proposing' = 'proposed' = 'agree' = 'agreed' = FALSE;
 *             'rcvdInfoWhile' = 0;
 *             'infoIs' = 'Disabled'; 'reselect' = TRUE; 'selected' = FALSE;)
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   mstp_Bridge
 *
 * Globals:
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_pimSmDisabledAct(MSTID_t mstid, LPORT_t lport)
{
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_RCVD_MSG);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_PROPOSING);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_PROPOSED);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_AGREE);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_AGREED);
      cistPortPtr->rcvdInfoWhile = 0;
      cistPortPtr->infoIs = MSTP_INFO_IS_DISABLED;
      MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_RESELECT);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_SELECTED);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RCVD_MSG);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_PROPOSING);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_PROPOSED);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_AGREE);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_AGREED);
      mstiPortPtr->rcvdInfoWhile = 0;
      mstiPortPtr->infoIs = MSTP_INFO_IS_DISABLED;
      MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RESELECT);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SELECTED);
   }

   if(MSTP_BEGIN == FALSE)
   {
      /*---------------------------------------------------------------------
       * kick Port Role Selection state machine (per-Tree)
       *---------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF(MSTP_PIM, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                             "PIM:", "DISABLED", "PRS:", mstid, lport);
      mstp_prsSm(mstid);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_pimSmAgedAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'AGED' state.
 *            ('infoIs' = 'Aged';
 *             'reselect' = TRUE; 'selected' = FALSE;)
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   mstp_Bridge
 *
 * Globals:
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_pimSmAgedAct(MSTID_t mstid, LPORT_t lport)
{

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      cistPortPtr->infoIs = MSTP_INFO_IS_AGED;
      MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_RESELECT);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_SELECTED);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      mstiPortPtr->infoIs = MSTP_INFO_IS_AGED;
      MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RESELECT);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SELECTED);
   }

   if(MSTP_BEGIN == FALSE)
   {
      /*---------------------------------------------------------------------
       * NOTE: The call for 'mstp_syncMstiPortsWithCist' below is
       *           a workaround to 802.1Q-REV/D5.0 design.
       *           See 'mstp_syncMstiPortsWithCist' function header
       *           description for more explanation.
       *---------------------------------------------------------------------*/
      if(mstid == MSTP_CISTID)
      {
         MSTP_BRIDGE_IDENTIFIER_t rgnRootID = MSTP_CIST_ROOT_PRIORITY.rgnRootID;
         MSTP_COMM_PORT_INFO_t   *commPortPtr = MSTP_COMM_PORT_PTR(lport);

         STP_ASSERT(commPortPtr);

         /*------------------------------------------------------------------
          * kick Port Role Selection state machine
          *------------------------------------------------------------------*/
         MSTP_SM_CALL_SM_PRINTF(MSTP_PIM, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                             "PIM:", "AGED", "PRS:", mstid, lport);
         mstp_prsSm(mstid);
         if(MSTP_IS_THIS_BRIDGE_RROOT(MSTP_CISTID) ||
            (MSTP_BRIDGE_ID_EQUAL(rgnRootID,
                                  MSTP_CIST_ROOT_PRIORITY.rgnRootID) == FALSE) ||
            (MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                       MSTP_PORT_RCVD_INTERNAL) == FALSE))
         {/* This Bridge is the MST Regional Root or MST Regional Root has been
           * changed or this 'aged' CIST port is located on the boundary of the
           * MST Region. In all these cases we want to enforce the state and role
           * of this port for all MSTIs to be in sync with the current state and
           * role of this port set for the CIST */
             mstp_syncMstiPortsWithCist(lport);
         }
      }
      else
      {
         /*------------------------------------------------------------------
          * kick Port Role Selection state machine
          *------------------------------------------------------------------*/
         MSTP_SM_CALL_SM_PRINTF(MSTP_PIM, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                                "PIM:", "AGED", "PRS:", mstid, lport);
         mstp_prsSm(mstid);
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_pimSmUpdateAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'UPDATE' state.
 *            ('proposing' = 'proposed' = FALSE;
 *             'agreed' = 'agreed' && betterorsameInfo('Mine');
 *             'synced' = 'synced' && 'agreed';
 *             'portPriority' = 'designatedPriority';
 *             'portTimes' = 'designatedTimes';
 *             'updtInfo' = FALSE;
 *             'infoIs' = 'Mine';
 *             'newInfoXst' = TRUE;)
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   mstp_Bridge
 *
 * Globals:
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_pimSmUpdateAct(MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);
      bool                  agreed      = FALSE;
      bool                  synced      = FALSE;

      STP_ASSERT(cistPortPtr);

      STP_ASSERT((cistPortPtr->selectedRole == MSTP_PORT_ROLE_DESIGNATED) ||
             (cistPortPtr->loopInconsistent &&
             (cistPortPtr->selectedRole == MSTP_PORT_ROLE_ALTERNATE)));

      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_PROPOSING);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_PROPOSED);

      agreed = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                         MSTP_CIST_PORT_AGREED);
      if(agreed && !mstp_betterOrSameInfo(mstid, lport, MSTP_INFO_IS_MINE))
      {
         MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_AGREED);
         agreed = FALSE;
      }
      if(agreed && commPortPtr->rcvdSelfSentPkt)
      {/* If port had experienced (and may be still experiencing) a loop-back
        * condition we clear 'agreed' flag for such port to enforce it go
        * through the proposal/agreement handshake with the neighbor for
        * the Role and State to be in. If loop condition still exists it
        * will be detected during handshake phase.
        * NOTE: agreed' port may immediately transition to the forwarding
        *       state; we don't want it for the loop-backed port as every
        *       transition to forwarding triggers topology change event ... */
         MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_AGREED);
         agreed = FALSE;
      }

      synced = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                         MSTP_CIST_PORT_SYNCED);
      if(synced && !agreed)
      {
         MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_SYNCED);
         synced = FALSE;
      }

      cistPortPtr->portPriority = cistPortPtr->designatedPriority;
      cistPortPtr->portTimes.fwdDelay = cistPortPtr->designatedTimes.fwdDelay;
      cistPortPtr->portTimes.maxAge = cistPortPtr->designatedTimes.maxAge;
      cistPortPtr->portTimes.messageAge =
                                     cistPortPtr->designatedTimes.messageAge;
      cistPortPtr->portTimes.hops = cistPortPtr->designatedTimes.hops;
      if(!MSTP_IS_THIS_BRIDGE_CIST_ROOT)
      {
         /*-------------------------------------------------------------------
          * get the 'Hello Time' propagated by the CIST Root Bridge on to this
          * Bridge's Root Port. If this Bridge is the Root then it will itself
          * propagate 'Hello Time' to the other Bridges via Designated ports.
          *-------------------------------------------------------------------*/
         STP_ASSERT(MSTP_CIST_ROOT_HELLO_TIME);
         cistPortPtr->portTimes.helloTime = MSTP_CIST_ROOT_HELLO_TIME;
      }
      else
         cistPortPtr->portTimes.helloTime = commPortPtr->HelloTime;

      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_UPDT_INFO);
      cistPortPtr->infoIs = MSTP_INFO_IS_MINE;
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
      bool                  agreed      = FALSE;
      bool                  synced      = FALSE;

      STP_ASSERT(mstiPortPtr);

      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_PROPOSING);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_PROPOSED);

      agreed = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                         MSTP_MSTI_PORT_AGREED);
      if(agreed && !mstp_betterOrSameInfo(mstid, lport, MSTP_INFO_IS_MINE))
      {
         MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_AGREED);
         agreed = FALSE;
      }
      if(agreed && commPortPtr->rcvdSelfSentPkt)
      {/* If port had experienced (and may be still experiencing) a loop-back
        * condition we clear 'agreed' flag for such port enforcing it go
        * through the proposal/agreement handshake with its neighbour for
        * the Role and State to be in. If loop condition still exists it
        * will be detected during handshake phase.
        * NOTE: agreed' port may immediately transition to the forwarding
        *       state; we don't want it for the loop-backed port as every
        *       transition to forwarding triggers topology change event ... */
         MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_AGREED);
         agreed = FALSE;
      }

      synced = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                         MSTP_MSTI_PORT_SYNCED);
      if(synced && !agreed)
      {
         MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SYNCED);
         synced = FALSE;
      }

      mstiPortPtr->portPriority = mstiPortPtr->designatedPriority;
      mstiPortPtr->portTimes = mstiPortPtr->designatedTimes;
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_UPDT_INFO);
      mstiPortPtr->infoIs = MSTP_INFO_IS_MINE;
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO_MSTI);
   }

   if(MSTP_BEGIN == FALSE)
   {
      /*---------------------------------------------------------------------
       * kick Port Role Transition state machine
       *---------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF(MSTP_PIM, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                             "PIM:", "UPDATE", "PRT:", mstid, lport);
      mstp_prtSm(mstid, lport);
      /*---------------------------------------------------------------------
       * kick Port Transmit state machine
       *---------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF(MSTP_PIM, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                             "PIM:", "UPDATE", "PTX:", mstid, lport);
      mstp_ptxSm(lport);
   }
}
/**PROC+**********************************************************************
 * Name:      mstp_pimSmReceiveAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'RECEIVE' state.
 *            ('rcvdInfo' = rcvInfo(); recordMastered();)
 *
 * Params:    pkt   -> pointer to the packet buffer with received BPDU in
 *            mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   mstp_Bridge
 *
 * Globals:
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_pimSmReceiveAct(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport)
{
   MSTP_RCVD_INFO_t rcvdInfo  = MSTP_RCVD_INFO_UNKNOWN;

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(pkt);
   STP_ASSERT((mstid == MSTP_CISTID) ? (MSTP_CIST_PORT_PTR(lport) != NULL) :
                                   (MSTP_MSTI_PORT_PTR(mstid, lport) != NULL));

   /* NOTE: This function sets 'rcvdTcn' and sets 'rcvdTc' for
    * each and every MSTI if a TCN BPDU has been received */
   rcvdInfo = mstp_rcvInfo(pkt, mstid, lport);

   if(mstid == MSTP_CISTID)
      MSTP_CIST_PORT_PTR(lport)->rcvdInfo = rcvdInfo;
   else
      MSTP_MSTI_PORT_PTR(mstid, lport)->rcvdInfo = rcvdInfo;

   mstp_recordMastered(pkt, mstid, lport);
}

/**PROC+**********************************************************************
 * Name:      mstp_pimSmSuperiorDesignatedAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'SUPERIOR_DESIGNATED' state.
 *            ('infoInternal' = 'rcvdInternal';
 *             'agreed' = 'proposing' = FALSE;
 *             recordProposal();
 *             setTcFlags();
 *             'agree' = 'agree' && betterorsameInfo('Received');
 *             recordAgreement();
 *             'synced' = 'synced' && 'agreed';
 *             recordPriority();
 *             recordTimes();
 *             updtRcvdInfoWhile();
 *             'infoIs' = 'Received';
 *             'reselect' = TRUE;
 *             'selected' = FALSE;
 *             'rcvdMsg' = FALSE;)
 *
 * Params:    pkt   -> pointer to the packet buffer with received BPDU in
 *            mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   mstp_Bridge
 *
 * Globals:
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_pimSmSuperiorDesignatedAct(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = NULL;
   bool                  agree       = FALSE;
   bool                  agreed      = FALSE;
   bool                  synced      = FALSE;

   STP_ASSERT(pkt);
   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_RCVD_INTERNAL))
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_INFO_INTERNAL);
   else
      MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_INFO_INTERNAL);

   /*
    * This is an explicite case to ensure that we set the timers properly
    * for the ports, when we are either the Root Port or Alternate Port.
    * This is a case where the timers are changed the upstream switch and
    * is communicate the current switch thru the BPDUs received, but did not
    * cause the Port Role or State to change.
    */
   if(mstid == MSTP_CISTID)
   {/* The CIST */
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);

      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_AGREED);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_PROPOSING);
      /* NOTE: this function updates the 'proposed' flag */
      mstp_recordProposal(pkt, mstid, lport);
      /* update 'TC flags' according to the information in the received BDPU */
      mstp_setTcFlags(pkt, mstid, lport);

      agree = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                        MSTP_CIST_PORT_AGREE);
      if(agree && !mstp_betterOrSameInfo(mstid, lport, MSTP_INFO_IS_RECEIVED))
      {
         MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_AGREE);
      }

      /* NOTE: this function updates the 'agreed' and 'proposing' flags */
      mstp_recordAgreement(pkt, mstid, lport);
      agreed = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                         MSTP_CIST_PORT_AGREED);

      synced = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                         MSTP_CIST_PORT_SYNCED);
      if(synced && !agreed)
      {
         MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_SYNCED);
         synced = FALSE;
      }

      mstp_recordPriority(mstid, lport);
      mstp_recordTimes(mstid, lport);
      /* compute new value for the 'rcvdInfoWhile' variable */
      mstp_updtRcvdInfoWhile(mstid, lport);
      cistPortPtr->infoIs = MSTP_INFO_IS_RECEIVED;
      MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_RESELECT);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_SELECTED);
   }
   else
   {/* An MSTI */
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      STP_ASSERT(MSTP_COMM_PORT_IS_BIT_SET(MSTP_COMM_PORT_PTR(lport)->bitMap,
                                       MSTP_PORT_RCVD_INTERNAL));

      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_AGREED);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_PROPOSING);
      /* NOTE: this function updates the 'proposed' flag */
      mstp_recordProposal(pkt, mstid, lport);
      /* update 'TC flags' according to the information in the received BDPU */
      mstp_setTcFlags(pkt, mstid, lport);

      agree  = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                         MSTP_MSTI_PORT_AGREE);
      if(agree && !mstp_betterOrSameInfo(mstid, lport,MSTP_INFO_IS_RECEIVED))
      {
         MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_AGREE);
      }
      /* NOTE: this function updates the 'agreed' and 'proposing' flags */
      mstp_recordAgreement(pkt, mstid, lport);
      agreed = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                         MSTP_MSTI_PORT_AGREED);

      synced = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                         MSTP_MSTI_PORT_SYNCED);
      if(synced && !agreed)
      {
         MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SYNCED);
         synced = FALSE;
      }

      mstp_recordPriority(mstid, lport);
      mstp_recordTimes(mstid, lport);
      /* compute new value for the 'rcvdInfoWhile' variable */
      mstp_updtRcvdInfoWhile(mstid, lport);
      mstiPortPtr->infoIs = MSTP_INFO_IS_RECEIVED;
      MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RESELECT);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SELECTED);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RCVD_MSG);
   }

   if(MSTP_BEGIN == FALSE)
   {
      /*---------------------------------------------------------------------
       * NOTE: The call for 'mstp_syncMstiPortsWithCist' below is
       *           a workaround to 802.1Q-REV/D5.0 design. See function header
       *           description for explanation.
       *---------------------------------------------------------------------*/
      if(mstid == MSTP_CISTID)
      {
         MSTP_BRIDGE_IDENTIFIER_t rgnRootID = MSTP_CIST_ROOT_PRIORITY.rgnRootID;

         /*------------------------------------------------------------------
          * kick Port Role Selection state machine for the CIST
          *------------------------------------------------------------------*/
         MSTP_SM_CALL_SM_PRINTF(MSTP_PIM, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                             "PIM:", "SUPERIOR_DSGN", "PRS:", mstid, lport);
         mstp_prsSm(mstid);
         if(!MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                       MSTP_PORT_RCVD_INTERNAL) ||
            (MSTP_BRIDGE_ID_EQUAL(rgnRootID,
                                  MSTP_CIST_ROOT_PRIORITY.rgnRootID) == FALSE))
         {/* The CIST Root(or Alternate) port is either located on the boundary
           * of the MST region OR the boundary of the MST region has been changed
           * so that this CIST port become internal to the MST region.
           * In all cases we need to synchronize this port's CIST role with its
           * role for all the MSTIs */
            mstp_syncMstiPortsWithCist(lport);
         }

         MSTP_CIST_PORT_CLR_BIT(MSTP_CIST_PORT_PTR(lport)->bitMap,
                                MSTP_CIST_PORT_RCVD_MSG);
      }
      else
      {
         /*------------------------------------------------------------------
          * kick Port Role Selection state machine the MSTI
          *------------------------------------------------------------------*/
         MSTP_SM_CALL_SM_PRINTF(MSTP_PIM, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                                "PIM:", "SUPERIOR_DSGN", "PRS:", mstid, lport);
         mstp_prsSm(mstid);
      }

      /*---------------------------------------------------------------------
       * kick Topology Change state machine (per-Tree per-Port)
       *---------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF(MSTP_PRX, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                             "PIM:", "SUPERIOR_DSGN", "TCM:", mstid, lport);
      mstp_tcmSm(mstid, lport);
   }
}
/**PROC+**********************************************************************
 * Name:      mstp_pimSmRepeatedDesignatedAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'REPEATED_DESIGNATED' state.
 *            ('infoInternal' = 'rcvdInternal';
 *             recordProposal();
 *             setTcFlags();
 *             recordAgreement();
 *             updtRcvdInfoWhile();
 *             'rcvdMsg' = FALSE;)
 *
 * Params:    pkt   -> pointer to the packet buffer with received BPDU in
 *            mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   mstp_Bridge
 *
 * Globals:
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_pimSmRepeatedDesignatedAct(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr);

   if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_RCVD_INTERNAL))
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_INFO_INTERNAL);
   else
      MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_INFO_INTERNAL);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);

      /* NOTE: this function updates the 'proposed' flag */
      mstp_recordProposal(pkt, mstid, lport);
      /* update 'TC flags' according to the information in the received BDPU */
      mstp_setTcFlags(pkt, mstid, lport);
      /* NOTE: this function updates the 'agreed' and 'proposing' flags */
      mstp_recordAgreement(pkt, mstid, lport);
      /* compute new value for the 'rcvdInfoWhile' variable */
      mstp_updtRcvdInfoWhile(mstid, lport);

      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_RCVD_MSG);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);

      /* NOTE: this function updates the 'proposed' flag */
      mstp_recordProposal(pkt, mstid, lport);
      /* update 'TC flags' according to the information in the received BDPU */
      mstp_setTcFlags(pkt, mstid, lport);
      /* NOTE: this function updates the 'agreed' and 'proposing' flags */
      mstp_recordAgreement(pkt, mstid, lport);
      /* compute new value for the 'rcvdInfoWhile' variable */
      mstp_updtRcvdInfoWhile(mstid, lport);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RCVD_MSG);
   }

   if(MSTP_BEGIN == FALSE)
   {
      /*---------------------------------------------------------------------
       * kick Port Role Transitions state machine (per-Tree per-Port)
       *---------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF(MSTP_PIM, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                             "PIM:", "REPEATED_DSGN", "PRT:", mstid, lport);
      mstp_prtSm(mstid, lport);

      /*---------------------------------------------------------------------
       * kick Topology Change state machine (per-Tree per-Port)
       *---------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF(MSTP_PRX, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                             "PIM:", "REPEATED_DSGN", "TCM:", mstid, lport);
      mstp_tcmSm(mstid, lport);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_pimSmInferiorDesignatedAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'INFERIOR_DESIGNATED' state.
 *            (recordDispute();
 *             'rcvdMsg' = FALSE;)
 *
 * Params:    pkt   -> pointer to the packet buffer with received BPDU in
 *            mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   mstp_Bridge
 *
 * Globals:
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_pimSmInferiorDesignatedAct(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport)
{
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      mstp_recordDispute(pkt, mstid, lport);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_RCVD_MSG);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      mstp_recordDispute(pkt, mstid, lport);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RCVD_MSG);
   }

   /*------------------------------------------------------------------------
    * kick Port Role Transitions state machine (per-Tree per-Port)
    *------------------------------------------------------------------------*/
   MSTP_SM_CALL_SM_PRINTF(MSTP_PIM, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                          "PIM:", "ROOT", "PRT:", mstid, lport);
   mstp_prtSm(mstid, lport);

   if (MSTP_BEGIN == FALSE)
   {
      if (mstid == MSTP_CISTID)
      {
         MSTP_COMM_PORT_INFO_t *commPortPtr  = NULL;

         commPortPtr = MSTP_COMM_PORT_PTR(lport);
         STP_ASSERT(commPortPtr);
         if(!MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                          MSTP_PORT_RCVD_INTERNAL))
         {/* The CIST Root(or Alternate) port is either located on the boundary
           * of the MST region OR the boundary of the MST region has been changed
           * so that this CIST port become internal to the MST region.
           * In all cases we need to synchronize this port's CIST role with its
           * role for all the MSTIs */
            mstp_syncMstiPortsWithCist(lport);
         }
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_pimSmNotDesignatedAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'NOT_DESIGNATED' state.
 *            (recordAgreement();
 *             setTcFlags();
 *             'rcvdMsg' = FALSE;)
 *
 * Params:    pkt   -> pointer to the packet buffer with received BPDU in
 *            mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   mstp_Bridge
 *
 * Globals:
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_pimSmNotDesignatedAct(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport)
{
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      /* NOTE: this function updates the 'agreed' and 'proposing' flags */
      mstp_recordAgreement(pkt, mstid, lport);
      /* update 'TC flags' according to the information in the received BDPU */
      mstp_setTcFlags(pkt, mstid, lport);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_RCVD_MSG);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      /* NOTE: this function updates the 'agreed' and 'proposing' flags */
      mstp_recordAgreement(pkt, mstid, lport);
      /* update 'TC flags' according to the information in the received BDPU */
      mstp_setTcFlags(pkt, mstid, lport);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RCVD_MSG);
   }

   /*------------------------------------------------------------------------
    * kick Port Role Transitions state machine (per-Tree per-Port)
    *------------------------------------------------------------------------*/
   MSTP_SM_CALL_SM_PRINTF(MSTP_PIM, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                          "PIM:", "NOT_DSGN", "PRT:", mstid, lport);
   mstp_prtSm(mstid, lport);

   if (MSTP_BEGIN == FALSE)
   {
      if (mstid == MSTP_CISTID)
      {
         MSTP_COMM_PORT_INFO_t *commPortPtr  = NULL;

         commPortPtr = MSTP_COMM_PORT_PTR(lport);
         STP_ASSERT(commPortPtr);
         if(!MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                          MSTP_PORT_RCVD_INTERNAL))
         {/* The CIST Root(or Alternate) port is either located on the boundary
           * of the MST region OR the boundary of the MST region has been changed
           * so that this CIST port become internal to the MST region.
           * In all cases we need to synchronize this port's CIST role with its
           * role for all the MSTIs */
            mstp_syncMstiPortsWithCist(lport);
         }
      }
   }

   /*------------------------------------------------------------------------
    * kick Topology Change state machine (per-Tree per-Port)
    *------------------------------------------------------------------------*/
   MSTP_SM_CALL_SM_PRINTF(MSTP_PRX, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                          "PIM:", "NOT_DSGN", "TCM:", mstid, lport);
   mstp_tcmSm(mstid, lport);
}
/**PROC+**********************************************************************
 * Name:      mstp_pimSmOtherAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'OTHER' state.
 *            ('rcvdMsg' = FALSE)
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   mstp_Bridge
 *
 * Globals:
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_pimSmOtherAct(MSTID_t mstid, LPORT_t lport)
{
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_RCVD_MSG);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RCVD_MSG);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_syncMstiPortsWithCist
 *
 * Purpose:   Update logical port role for all MSTIs to keep it in sync with
 *            the current state of that port on the CIST. This function
 *            called from 'mstp_pimSmAgedAct' or
 *            'mstp_pimSmSuperiorDesignatedAct' routines.
 *            NOTE: The MSTIs (unlike the CIST) use the additional port
 *                      role - Master Port. A Master Port provides connectivity
 *                      from a Region to a CIST Root that lies outside the
 *                      Region. At the Boundary of a Region, if the CIST Port
 *                      Role is Root Port the MSTI Port Role will be Master
 *                      Port, and if the CIST Port Role is Designated Port,
 *                      Alternate Port, Backup Port, or Disabled Port, each
 *                      MSTI's Port Role will be the same (see Master Port
 *                      definition and it's functionality description at
 *                      802.1Q-REV/D5.0 13.4 e); 13.12 e); 13.13 f); 13.24.15);
 *
 *                         As per standard description, the only place where
 *                      MSTI's port role is being set with respect to the
 *                      current port role for the CIST is PRS SM's function
 *                      'mstp_updtRolesMsti'.
 *                         As per design, for any given MSTI its PRS SM is
 *                      being called by PIM SM whenever a Bridge located
 *                      IN THE SAME Region sends BPDU with superior MSTI
 *                      configuration information or port's current information
 *                      stored from the previously received superior message is
 *                      aged out. The MSTIs information carried in BPDUs sent
 *                      by a Bridge located in different Region is being
 *                      ingnored by the MSTIs on the receiving Bridge. So we
 *                      have a chance do not recognize that there are conditions
 *                      for an MSTI port to become Master Port or Alternate Port
 *                      (or change role back from it to some other) because
 *                      of the selected role change for this port for the CIST.
 *                         This function is an effort to fix the situation and
 *                      have all MSTIs ports to be in sync with the CIST port
 *                      located at the boundary of a Region.
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
mstp_syncMstiPortsWithCist(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr;
   MSTID_t                mstid;

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(IS_VALID_LPORT(lport));
   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_MSTID_MAX; mstid++)
   {
      if(MSTP_MSTI_VALID(mstid))
      {
         MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid,lport);

         STP_ASSERT(mstiPortPtr);
         MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RESELECT);
         MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SELECTED);
         mstp_prsSm(mstid);
      }
   }
}
