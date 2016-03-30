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
 *    File               : mstpd_pst_sm.c
 *    Description        : MSTP Protocol Port State Transition State Machine
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

VLOG_DEFINE_THIS_MODULE(mstpd_pst_sm);
/*---------------------------------------------------------------------------
 * Local functions prototypes (forward declarations)
 *---------------------------------------------------------------------------*/
static void mstp_pstSmGeneralCond(MSTID_t mstid, LPORT_t lport);
static void mstp_pstSmDiscardingCond(MSTID_t mstid, LPORT_t lport);
static void mstp_pstSmLearningCond(MSTID_t mstid, LPORT_t lport);
static void mstp_pstSmForwardingCond(MSTID_t mstid, LPORT_t lport);

static void mstp_pstSmDiscardingAct(MSTID_t mstid, LPORT_t lport);
static void mstp_pstSmLearningAct(MSTID_t mstid, LPORT_t lport);
static void mstp_pstSmForwardingAct(MSTID_t mstid, LPORT_t lport);

/** ======================================================================= **
 *                                                                           *
 *     Global Functions (externed)                                           *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_pstSm
 *
 * Purpose:   The entry point to the Port State Transitions state machine.
 *           (802.1Q-REV/D5.0 13.35)
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:
 *
 **PROC-**********************************************************************/
void
mstp_pstSm(MSTID_t mstid, LPORT_t lport)
{
   MSTP_PST_STATE_t *statePtr = NULL;

   STP_ASSERT(mstid <= MSTP_MSTID_MAX);
   STP_ASSERT(MSTP_INSTANCE_IS_VALID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      statePtr = &cistPortPtr->pstState;
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      statePtr = &mstiPortPtr->pstState;
   }

   mstp_pstSmGeneralCond(mstid, lport);
   switch(*statePtr)
   {
      case MSTP_PST_STATE_DISCARDING:
         mstp_pstSmDiscardingCond(mstid, lport);
         break;
      case MSTP_PST_STATE_LEARNING:
         mstp_pstSmLearningCond(mstid, lport);
         break;
      case MSTP_PST_STATE_FORWARDING:
         mstp_pstSmForwardingCond(mstid, lport);
         break;
      default:
         STP_ASSERT(0);
         break;
   }

   /*------------------------------------------------------------------------
    * when exit the state for PST SM must be 'DISCARDING' || 'LEARNING' ||
    * 'FORWARDING'
    *------------------------------------------------------------------------*/
   STP_ASSERT(*statePtr == MSTP_PST_STATE_DISCARDING ||
          *statePtr == MSTP_PST_STATE_LEARNING   ||
          *statePtr == MSTP_PST_STATE_FORWARDING);

}

/** ======================================================================= **
 *                                                                           *
 *     Static (local to this file) Functions                                 *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_pstSmGeneralCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *
 * Params:    mstid -> MST Instance Idetifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_pstSmGeneralCond(MSTID_t mstid, LPORT_t lport)
{
   /*------------------------------------------------------------------------
    * check for conditions to transition to the 'DISCARDING' state
    *------------------------------------------------------------------------*/
   if(MSTP_BEGIN == TRUE)
   {
      MSTP_PST_STATE_t *statePtr;

      if(mstid == MSTP_CISTID)
      {
         MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

         STP_ASSERT(cistPortPtr);
         statePtr = &cistPortPtr->pstState;
      }
      else
      {
         MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

         STP_ASSERT(mstiPortPtr);
         statePtr = &mstiPortPtr->pstState;
      }

      /*---------------------------------------------------------------------
       * check for conditions to transition to the 'DISCARDING' state
       *---------------------------------------------------------------------*/
      if(*statePtr != MSTP_PST_STATE_DISCARDING)
      {
         MSTP_SM_ST_PRINTF(MSTP_PST,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PST:", MSTP_PST_STATE_s[*statePtr],
                           MSTP_PST_STATE_s[MSTP_PST_STATE_DISCARDING],
                           mstid, lport);
         *statePtr = MSTP_PST_STATE_DISCARDING;
         mstp_pstSmDiscardingAct(mstid, lport);
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_pstSmDiscardingCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'DISCARDING'.
 *
 * Params:    mstid -> MST Instance Idetifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_pstSmDiscardingCond(MSTID_t mstid, LPORT_t lport)
{
   bool             learn    = FALSE;
   MSTP_PST_STATE_t *statePtr = NULL;

   /*------------------------------------------------------------------------
    * collect state exit conditions information
    *------------------------------------------------------------------------*/
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      statePtr = &cistPortPtr->pstState;
      learn = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                        MSTP_CIST_PORT_LEARN);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      statePtr = &mstiPortPtr->pstState;
      learn = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                        MSTP_MSTI_PORT_LEARN);
   }

   STP_ASSERT(*statePtr == MSTP_PST_STATE_DISCARDING);

   /*------------------------------------------------------------------------
    * check for conditions to transition to the 'LEARNING' state
    *------------------------------------------------------------------------*/
   if(learn)
   {
      MSTP_SM_ST_PRINTF(MSTP_PST,
                        MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                        "PST:", MSTP_PST_STATE_s[*statePtr],
                        MSTP_PST_STATE_s[MSTP_PST_STATE_LEARNING],
                        mstid, lport);
      *statePtr = MSTP_PST_STATE_LEARNING;
      mstp_pstSmLearningAct(mstid, lport);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_pstSmLearningCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'LEARNING'.
 *
 * Params:    mstid -> MST Instance Idetifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   none.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_pstSmLearningCond(MSTID_t mstid, LPORT_t lport)
{
   bool             learn    = FALSE;
   bool             forward  = FALSE;
   MSTP_PST_STATE_t *statePtr = NULL;

   /*------------------------------------------------------------------------
    * collect state exit conditions information
    *------------------------------------------------------------------------*/
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);

      statePtr = &cistPortPtr->pstState;
      learn = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                        MSTP_CIST_PORT_LEARN);
      forward = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                          MSTP_CIST_PORT_FORWARD);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);

      statePtr = &mstiPortPtr->pstState;
      learn = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                        MSTP_MSTI_PORT_LEARN);
      forward = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                          MSTP_MSTI_PORT_FORWARD);
   }

   STP_ASSERT(*statePtr == MSTP_PST_STATE_LEARNING);

   /*------------------------------------------------------------------------
    * check for conditions to transition to the next state
    *------------------------------------------------------------------------*/
   if(forward)
   {/* 'forward' */
      /*---------------------------------------------------------------------
       * condition for transition to the 'FORWARDING' state
       *---------------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF(MSTP_PST,
                        MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                        "PST:", MSTP_PST_STATE_s[*statePtr],
                        MSTP_PST_STATE_s[MSTP_PST_STATE_FORWARDING],
                        mstid, lport);
      *statePtr = MSTP_PST_STATE_FORWARDING;
      mstp_pstSmForwardingAct(mstid, lport);
   }
   else if(!learn)
   {/* !'learn' */
      /*---------------------------------------------------------------------
       * condition for transition to the 'DISCARDING' state
       *---------------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF(MSTP_PST,
                        MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                        "PST:", MSTP_PST_STATE_s[*statePtr],
                        MSTP_PST_STATE_s[MSTP_PST_STATE_DISCARDING],
                        mstid, lport);
      *statePtr = MSTP_PST_STATE_DISCARDING;
      mstp_pstSmDiscardingAct(mstid, lport);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_pstSmForwardingCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'FORWARDING.
 *
 * Params:    mstid -> MST Instance Idetifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   TRUE, indicating that the state has been changed
 *            and the immediate check for the exit conditions from this state
 *            is required; FALSE otherwise.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_pstSmForwardingCond(MSTID_t mstid, LPORT_t lport)
{
   bool             forward  = FALSE;
   MSTP_PST_STATE_t *statePtr = NULL;

   /*------------------------------------------------------------------------
    * collect state exit conditions information
    *------------------------------------------------------------------------*/
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);

      statePtr = &cistPortPtr->pstState;
      forward = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                          MSTP_CIST_PORT_FORWARD);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);

      statePtr = &mstiPortPtr->pstState;
      forward = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                          MSTP_MSTI_PORT_FORWARD);
   }

   STP_ASSERT(*statePtr == MSTP_PST_STATE_FORWARDING);

   /*------------------------------------------------------------------------
    * check for conditions to transition to the 'DISCARDING' state
    *------------------------------------------------------------------------*/
   if(!forward)
   {/* !'forward' */
      MSTP_SM_ST_PRINTF(MSTP_PST,
                        MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                        "PST:", MSTP_PST_STATE_s[*statePtr],
                        MSTP_PST_STATE_s[MSTP_PST_STATE_DISCARDING],
                        mstid, lport);
      *statePtr = MSTP_PST_STATE_DISCARDING;
      mstp_pstSmDiscardingAct(mstid, lport);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_pstSmDiscardingAct
 *
 * Purpose:   Execute actions that are necessary when entering to the
 *            'DISCARDING' state.
 *            (disableLearning();
 *             'learning' = FALSE;
 *             disableForwarding();
 *             'forwarding' = FALSE;)
 *
 * Params:    mstid -> MST Instance Idetifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_pstSmDiscardingAct(MSTID_t mstid, LPORT_t lport)
{
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);

      mstp_disableLearning(mstid, lport);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_LEARNING);
      mstp_disableForwarding(mstid, lport);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_FORWARDING);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);

      mstp_disableLearning(mstid, lport);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_LEARNING);
      mstp_disableForwarding(mstid, lport);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_FORWARDING);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_pstSmLearningAct
 *
 * Purpose:   Execute actions that are necessary when entering to the
 *            'LEARNING' state.
 *            (enableLearning(); 'learning' = TRUE;)
 *
 * Params:    mstid -> MST Instance Idetifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_pstSmLearningAct(MSTID_t mstid, LPORT_t lport)
{

   STP_ASSERT(MSTP_BEGIN == FALSE);

   mstp_enableLearning(mstid, lport);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);

      MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_LEARNING);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);

      MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_LEARNING);
   }

   /*------------------------------------------------------------------------
    * kick Topology Change state machine  (per-Tree per-Port)
    *------------------------------------------------------------------------*/
   MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                           "PST:", "LEARNING", "TCM:", mstid, lport);
   mstp_tcmSm(mstid, lport);
}

/**PROC+**********************************************************************
 * Name:      mstp_pstSmForwardingAct
 *
 * Purpose:   Execute actions that are necessary when entering to the
 *            'FORWARDING' state.
 *            (enableForwarding(); forwarding = TRUE;)
 *
 * Params:    mstid -> MST Instance Idetifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_pstSmForwardingAct(MSTID_t mstid, LPORT_t lport)
{
   STP_ASSERT(MSTP_BEGIN == FALSE);

   mstp_enableForwarding(mstid, lport);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);

      MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_FORWARDING);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);

      MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_FORWARDING);
   }

   /*------------------------------------------------------------------------
    * kick Topology Change state machine  (per-Tree per-Port)
    *------------------------------------------------------------------------*/
   MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                           "PST:", "FORWARDING", "TCM:", mstid, lport);
   mstp_tcmSm(mstid, lport);
}
