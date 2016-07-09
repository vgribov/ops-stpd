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
 *    File               : mstpd_tcm_sm.c
 *    Description        : MSTP Protocol Topology Change State Machine Entry point
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

VLOG_DEFINE_THIS_MODULE(mstpd_tcm_sm);
/*---------------------------------------------------------------------------
 * Local functions prototypes (forward declarations)
 *---------------------------------------------------------------------------*/
static void mstp_tcmSmGeneralCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_tcmSmInactiveCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_tcmSmLearningCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_tcmSmDetectedCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_tcmSmActiveCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_tcmSmNotifiedTcnCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_tcmSmNotifiedTcCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_tcmSmPropagatingCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_tcmSmAcknowledgedCond(MSTID_t mstid, LPORT_t lport);

static void mstp_tcmSmInactiveAct(MSTID_t mstid, LPORT_t lport);
static void mstp_tcmSmLearningAct(MSTID_t mstid, LPORT_t lport);
static void mstp_tcmSmDetectedAct(MSTID_t mstid, LPORT_t lport);
static void mstp_tcmSmNotifiedTcnAct(MSTID_t mstid, LPORT_t lport);
static void mstp_tcmSmNotifiedTcAct(MSTID_t mstid, LPORT_t lport);
static void mstp_tcmSmPropagatingAct(MSTID_t mstid, LPORT_t lport);
static void mstp_tcmSmAcknowledgedAct(MSTID_t mstid, LPORT_t lport);

/** ======================================================================= **
 *                                                                           *
 *     Global Functions (externed)                                           *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_tcmSm
 *
 * Purpose:   The entry point to the Topology Change state machine.
 *            (802.1Q-REV/D5.0 13.36)
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_CB, mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_tcmSm(MSTID_t mstid, LPORT_t lport)
{
   MSTP_TCM_STATE_t *statePtr = NULL;
   bool             next     = FALSE;/* This variable is used to indicate
                                       * that the state change processing
                                       * is still required */
   STP_ASSERT(mstid == MSTP_CISTID || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(MSTP_INSTANCE_IS_VALID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));

   statePtr = mstp_utilTcmStatePtr(mstid, lport);
   STP_ASSERT(statePtr);
   mstp_tcmSmGeneralCond(mstid, lport);
   do
   {
      switch(*statePtr)
      {
         case MSTP_TCM_STATE_INACTIVE:
            next = mstp_tcmSmInactiveCond(mstid, lport);
            break;
         case MSTP_TCM_STATE_LEARNING:
            next = mstp_tcmSmLearningCond(mstid, lport);
            break;
         case MSTP_TCM_STATE_DETECTED:
            next = mstp_tcmSmDetectedCond(mstid, lport);
            break;
         case MSTP_TCM_STATE_ACTIVE:
            next = mstp_tcmSmActiveCond(mstid, lport);
            break;
         case MSTP_TCM_STATE_NOTIFIED_TCN:
            next = mstp_tcmSmNotifiedTcnCond(mstid, lport);
            break;
         case MSTP_TCM_STATE_NOTIFIED_TC:
            next = mstp_tcmSmNotifiedTcCond(mstid, lport);
            break;
         case MSTP_TCM_STATE_PROPAGATING:
            next = mstp_tcmSmPropagatingCond(mstid, lport);
            break;
         case MSTP_TCM_STATE_ACKNOWLEDGED:
            next = mstp_tcmSmAcknowledgedCond(mstid, lport);
            break;
         default:
            STP_ASSERT(0);
            break;
      }
   }
   while (next == TRUE);

   /*------------------------------------------------------------------------
    * when exit the state for TCM SM must be
    * 'INACTIVE' || 'LEARNING' || 'ACTIVE'
    *------------------------------------------------------------------------*/
   STP_ASSERT(*statePtr == MSTP_TCM_STATE_INACTIVE ||
          *statePtr == MSTP_TCM_STATE_LEARNING ||
          *statePtr == MSTP_TCM_STATE_ACTIVE);

}

/** ======================================================================= **
 *                                                                           *
 *     Static (local to this file) Functions                                 *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_tcmSmGeneralCond
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
mstp_tcmSmGeneralCond(MSTID_t mstid, LPORT_t lport)
{
   /*------------------------------------------------------------------------
    * check for conditions to transition to the 'INIT' state
    *------------------------------------------------------------------------*/
   if(MSTP_BEGIN == TRUE)
   {
      MSTP_TCM_STATE_t *statePtr;

      if(mstid == MSTP_CISTID)
      {
         MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

         STP_ASSERT(cistPortPtr);
         statePtr = &cistPortPtr->tcmState;
      }
      else
      {
         MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

         STP_ASSERT(mstiPortPtr);
         statePtr = &mstiPortPtr->tcmState;
      }

      if(*statePtr != MSTP_TCM_STATE_INACTIVE)
      {
         /*------------------------------------------------------------------
          * condition for transition to the 'INACTIVE' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_TCM,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "TCM:", MSTP_TCM_STATE_s[*statePtr],
                           MSTP_TCM_STATE_s[MSTP_TCM_STATE_INACTIVE], mstid,
                           lport);
         *statePtr = MSTP_TCM_STATE_INACTIVE;
         mstp_tcmSmInactiveAct(mstid, lport);
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_tcmSmInactiveCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'INACTIVE'.
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
static bool
mstp_tcmSmInactiveCond(MSTID_t mstid, LPORT_t lport)
{
   bool                          res         = FALSE;
   bool                  learn       = FALSE;
   bool                  fdbFlush    = FALSE;
   MSTP_COMM_PORT_INFO_t *commPortPtr = NULL;
   MSTP_TCM_STATE_t      *statePtr    = NULL;

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   /*------------------------------------------------------------------------
    * collect state exit conditions information
    *------------------------------------------------------------------------*/
   fdbFlush = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                        MSTP_PORT_FDB_FLUSH);
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      statePtr = &cistPortPtr->tcmState;
      learn = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                        MSTP_CIST_PORT_LEARN);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      statePtr = &mstiPortPtr->tcmState;
      learn = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                        MSTP_MSTI_PORT_LEARN);
   }

   STP_ASSERT(*statePtr == MSTP_TCM_STATE_INACTIVE);

   /*------------------------------------------------------------------------
    * check for conditions to transition to the 'LEARNING' state
    *------------------------------------------------------------------------*/
   if(learn && !fdbFlush)
   {/* 'learn' && '!fdbflush' */
      MSTP_SM_ST_PRINTF(MSTP_TCM,
                        MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                        "TCM:", MSTP_TCM_STATE_s[*statePtr],
                        MSTP_TCM_STATE_s[MSTP_TCM_STATE_LEARNING], mstid,
                        lport);
      *statePtr = MSTP_TCM_STATE_LEARNING;
      mstp_tcmSmLearningAct(mstid, lport);
      res = TRUE;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_tcmSmLearningCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'LEARNING'.
 *
 * Params:    mstid -> MST Instance Idetifier (the CIST or an MSTI)
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
mstp_tcmSmLearningCond(MSTID_t mstid, LPORT_t lport)
{
   bool                         res         = FALSE;
   bool                         operEdge    = FALSE;
   bool                         rcvdTc      = FALSE;
   bool                         rcvdTcn     = FALSE;
   bool                         rcvdTcAck   = FALSE;
   bool                         forward     = FALSE;
   bool                         learn       = FALSE;
   bool                         learning    = FALSE;
   bool                         tcProp      = FALSE;
   MSTP_PORT_ROLE_t              role        = MSTP_PORT_ROLE_DISABLED;
   MSTP_TCM_STATE_t *statePtr    = NULL;
   MSTP_COMM_PORT_INFO_t        *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(commPortPtr);

   /*------------------------------------------------------------------------
    * collect state exit conditions information
    *------------------------------------------------------------------------*/
   operEdge =
      MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_OPER_EDGE);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      statePtr = &cistPortPtr->tcmState;
      rcvdTcn =
         MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_RCVD_TCN);
      rcvdTcAck =
         MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_RCVD_TC_ACK);
      rcvdTc =
         MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap, MSTP_CIST_PORT_RCVD_TC);
      forward =
         MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap, MSTP_CIST_PORT_FORWARD);
      tcProp  =
         MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap, MSTP_CIST_PORT_TC_PROP);
      role = cistPortPtr->role;
      learn = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                        MSTP_CIST_PORT_LEARN);
      learning = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                           MSTP_CIST_PORT_LEARNING);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      statePtr = &mstiPortPtr->tcmState;
      rcvdTc =
         MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RCVD_TC);
      forward =
         MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap, MSTP_MSTI_PORT_FORWARD);
      tcProp  =
         MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap, MSTP_MSTI_PORT_TC_PROP);
      role = mstiPortPtr->role;
      learn = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                        MSTP_MSTI_PORT_LEARN);
      learning = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                           MSTP_MSTI_PORT_LEARNING);
   }

   STP_ASSERT(*statePtr == MSTP_TCM_STATE_LEARNING);

   /*------------------------------------------------------------------------
    * check for conditions to transition to the next state
    *------------------------------------------------------------------------*/
   if(((role == MSTP_PORT_ROLE_ROOT) || (role == MSTP_PORT_ROLE_DESIGNATED) ||
       (role == MSTP_PORT_ROLE_MASTER)) &&
      forward && !operEdge)
   {/* (('role' == 'RootPort') ||
     *  ('role' == 'DesignatedPort') ||
     *  ('role' == 'MasterPort')) &&
     *  'forward' && !'operEdge' */

      /*---------------------------------------------------------------------
       * condition for transition to the 'DETECTED' state
       *---------------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF(MSTP_TCM,
                        MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                        "TCM:", MSTP_TCM_STATE_s[*statePtr],
                        MSTP_TCM_STATE_s[MSTP_TCM_STATE_DETECTED],
                        mstid, lport);
      *statePtr = MSTP_TCM_STATE_DETECTED;
      mstp_tcmSmDetectedAct(mstid, lport);
      res = TRUE;
   }
   else
   if(rcvdTc ||rcvdTcn ||rcvdTcAck ||tcProp)
   {/* 'rcvdTc' ||'rcvdTcn' ||'rcvdTcAck' || 'tcProp' */

      /*---------------------------------------------------------------------
       * condition for transition (re-enter) to the 'LEARNING' state
       * NOTE: 'rcvdTcn' and 'rcvdTcAck' conditions make sense only
       *       for the CIST
       *---------------------------------------------------------------------*/
      STP_ASSERT((rcvdTcn || rcvdTcAck) ? (mstid == MSTP_CISTID) : TRUE);
      MSTP_SM_ST_PRINTF(MSTP_TCM,
                        MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                        "TCM:", MSTP_TCM_STATE_s[*statePtr],
                        MSTP_TCM_STATE_s[MSTP_TCM_STATE_LEARNING],
                        mstid, lport);
      *statePtr = MSTP_TCM_STATE_LEARNING;
      mstp_tcmSmLearningAct(mstid, lport);
      res = FALSE;
   }
   else if((role != MSTP_PORT_ROLE_ROOT) &&
           (role != MSTP_PORT_ROLE_DESIGNATED) &&
           (role != MSTP_PORT_ROLE_MASTER) &&
           !(learn || learning))
   {/* ('role' != 'RootPort') &&
     * ('role' != 'DesignatedPort')
     * ('role' != 'MasterPort') &&
     * !('learn' || 'learning') &&
     * !('rcvdTc' || 'rcvdTcn' || 'rcvdTcAck' || 'tcProp') */

      /*---------------------------------------------------------------------
       * condition for transition to the 'INACTIVE' state
       *---------------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF(MSTP_TCM,
                        MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                        "TCM:", MSTP_TCM_STATE_s[*statePtr],
                        MSTP_TCM_STATE_s[MSTP_TCM_STATE_INACTIVE],
                        mstid, lport);
      *statePtr = MSTP_TCM_STATE_INACTIVE;
      mstp_tcmSmInactiveAct(mstid, lport);
      res = FALSE;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_tcmSmDetectedCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'DETECTED'.
 *
 * Params:    mstid -> MST Instance Idetifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   TRUE, indicating that the state has been changed
 *            and the immediate check for the exit conditions from this state
 *            is required.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_tcmSmDetectedCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_TCM_STATE_t *statePtr = NULL;

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      statePtr = &cistPortPtr->tcmState;
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      statePtr = &mstiPortPtr->tcmState;
   }

   STP_ASSERT(*statePtr == MSTP_TCM_STATE_DETECTED);

   /*------------------------------------------------------------------------
    * transition to the 'ACTIVE' state unconditionally
    * NOTE: there are no actions to perform when entering this state
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_TCM, MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "TCM:", MSTP_TCM_STATE_s[*statePtr],
                     MSTP_TCM_STATE_s[MSTP_TCM_STATE_ACTIVE], mstid, lport);
   *statePtr = MSTP_TCM_STATE_ACTIVE;

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_tcmSmActiveCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'ACTIVE'.
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
static bool
mstp_tcmSmActiveCond(MSTID_t mstid, LPORT_t lport)
{
   bool                  res         = FALSE;
   bool                  operEdge    = FALSE;
   bool                  rcvdTc      = FALSE;
   bool                  rcvdTcn     = FALSE;
   bool                  rcvdTcAck   = FALSE;
   bool                  tcProp      = FALSE;
   MSTP_PORT_ROLE_t       role        = MSTP_PORT_ROLE_UNKNOWN;
   MSTP_TCM_STATE_t      *statePtr    = NULL;
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr);

   /*------------------------------------------------------------------------
    * collect state exit conditions information
    *------------------------------------------------------------------------*/
   operEdge =
      MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_OPER_EDGE);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      statePtr = &cistPortPtr->tcmState;
      rcvdTcn =
         MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_RCVD_TCN);
      rcvdTcAck =
         MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_RCVD_TC_ACK);
      rcvdTc =
         MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap, MSTP_CIST_PORT_RCVD_TC);
      tcProp  =
         MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap, MSTP_CIST_PORT_TC_PROP);
      role = cistPortPtr->role;
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      statePtr = &mstiPortPtr->tcmState;
      rcvdTc =
         MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RCVD_TC);
      tcProp  =
         MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap, MSTP_MSTI_PORT_TC_PROP);
      role = mstiPortPtr->role;
   }

   STP_ASSERT(*statePtr == MSTP_TCM_STATE_ACTIVE);

   /*------------------------------------------------------------------------
    * check for conditions to transition to the next state
    *------------------------------------------------------------------------*/
   if(((role != MSTP_PORT_ROLE_ROOT) && (role != MSTP_PORT_ROLE_DESIGNATED) &&
       (role != MSTP_PORT_ROLE_MASTER)) || operEdge)
   {/* (('role' != 'RootPort') &&
     * ('role' != 'DesignatedPort') &&
     *  ('role' != 'MasterPort')) || 'operEdge' */

      /*---------------------------------------------------------------------
       * condition for transition to the 'LEARNING' state
       *---------------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF(MSTP_TCM,
                        MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                        "TCM:", MSTP_TCM_STATE_s[*statePtr],
                        MSTP_TCM_STATE_s[MSTP_TCM_STATE_LEARNING], mstid, lport);
      *statePtr = MSTP_TCM_STATE_LEARNING;
      mstp_tcmSmLearningAct(mstid, lport);
      res = TRUE;
   }
   else if(rcvdTcn)
   {/* 'rcvdTcn' */

      /*---------------------------------------------------------------------
       * condition for transition to the 'NOTIFIED_TCN' state
       * NOTE: 'rcvdTcn' condition make sense only for the CIST
       *---------------------------------------------------------------------*/
      STP_ASSERT(mstid == MSTP_CISTID);
      MSTP_SM_ST_PRINTF(MSTP_TCM,
                        MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                        "TCM:", MSTP_TCM_STATE_s[*statePtr],
                        MSTP_TCM_STATE_s[MSTP_TCM_STATE_NOTIFIED_TCN],
                        mstid, lport);
      *statePtr = MSTP_TCM_STATE_NOTIFIED_TCN;
      mstp_tcmSmNotifiedTcnAct(mstid, lport);
      res = TRUE;
   }
   else if(rcvdTc)
   {/* 'rcvdTc' */

      /*---------------------------------------------------------------------
       * condition for transition to the 'NOTIFIED_TC' state
       *---------------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF(MSTP_TCM,
                        MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                        "TCM:", MSTP_TCM_STATE_s[*statePtr],
                        MSTP_TCM_STATE_s[MSTP_TCM_STATE_NOTIFIED_TC],
                        mstid, lport);
      *statePtr = MSTP_TCM_STATE_NOTIFIED_TC;
      mstp_tcmSmNotifiedTcAct(mstid, lport);
      res = TRUE;
   }
   else if(tcProp && !operEdge)
   {/* 'tcProp' && '!operEdge' */

      /*---------------------------------------------------------------------
       * condition for transition to the 'PROPAGATING' state
       *---------------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF(MSTP_TCM,
                        MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                        "TCM:", MSTP_TCM_STATE_s[*statePtr],
                        MSTP_TCM_STATE_s[MSTP_TCM_STATE_PROPAGATING],
                        mstid, lport);
      *statePtr = MSTP_TCM_STATE_PROPAGATING;
      mstp_tcmSmPropagatingAct(mstid, lport);
      res = TRUE;
   }
   else if(rcvdTcAck)
   {/* 'rcvdTcAck' */

      /*---------------------------------------------------------------------
       * condition for transition to the 'ACKNOWLEDGED' state
       * NOTE: 'rcvdTcAck' condition make sense only for the CIST
       *---------------------------------------------------------------------*/
      STP_ASSERT(mstid == MSTP_CISTID);
      MSTP_SM_ST_PRINTF(MSTP_TCM,
                        MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                        "TCM:", MSTP_TCM_STATE_s[*statePtr],
                        MSTP_TCM_STATE_s[MSTP_TCM_STATE_ACKNOWLEDGED],
                        mstid, lport);
      *statePtr = MSTP_TCM_STATE_ACKNOWLEDGED;
      mstp_tcmSmAcknowledgedAct(mstid, lport);
      res = TRUE;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_tcmSmNotifiedTcnCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'NOTIFIED_TCN'.
 *
 * Params:    mstid -> MST Instance Idetifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   TRUE, indicating that the state has been changed
 *            and the immediate check for the exit conditions from this state
 *            is required.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_tcmSmNotifiedTcnCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res = TRUE;
   MSTP_TCM_STATE_t *statePtr = NULL;

   /*------------------------------------------------------------------------
    * transition to the 'NOTIFIED_TC' state unconditionally
    *------------------------------------------------------------------------*/
   statePtr = mstp_utilTcmStatePtr(mstid, lport);
   STP_ASSERT(statePtr && *statePtr == MSTP_TCM_STATE_NOTIFIED_TCN);
   MSTP_SM_ST_PRINTF(MSTP_TCM, MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "TCM:", MSTP_TCM_STATE_s[*statePtr],
                     MSTP_TCM_STATE_s[MSTP_TCM_STATE_NOTIFIED_TC],
                     mstid, lport);
   *statePtr = MSTP_TCM_STATE_NOTIFIED_TC;
   mstp_tcmSmNotifiedTcAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_tcmSmNotifiedTcCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'NOTIFIED_TC'.
 *
 * Params:    mstid -> MST Instance Idetifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   TRUE, indicating that the state has been changed
 *            and the immediate check for the exit conditions from this state
 *            is required.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_tcmSmNotifiedTcCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res = TRUE;
   MSTP_TCM_STATE_t *statePtr = NULL;

   /*------------------------------------------------------------------------
    * transition to the 'ACTIVE' state unconditionally
    * NOTE: there are no actions to perform when entering this state
    *------------------------------------------------------------------------*/
   statePtr = mstp_utilTcmStatePtr(mstid, lport);
   STP_ASSERT(statePtr && *statePtr == MSTP_TCM_STATE_NOTIFIED_TC);
   MSTP_SM_ST_PRINTF(MSTP_TCM, MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "TCM:", MSTP_TCM_STATE_s[*statePtr],
                     MSTP_TCM_STATE_s[MSTP_TCM_STATE_ACTIVE],
                     mstid, lport);
   *statePtr = MSTP_TCM_STATE_ACTIVE;

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_tcmSmPropagatingCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'PROPAGATING'.
 *
 * Params:    mstid -> MST Instance Idetifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   TRUE, indicating that the state has been changed
 *            and the immediate check for the exit conditions from this state
 *            is required.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_tcmSmPropagatingCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res = TRUE;
   MSTP_TCM_STATE_t *statePtr = NULL;

   /*------------------------------------------------------------------------
    * transition to the 'ACTIVE' state unconditionally
    * NOTE: there are no actions to perform when entering this state
    *------------------------------------------------------------------------*/
   statePtr = mstp_utilTcmStatePtr(mstid, lport);
   STP_ASSERT(statePtr && *statePtr == MSTP_TCM_STATE_PROPAGATING);
   MSTP_SM_ST_PRINTF(MSTP_TCM, MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "TCM:", MSTP_TCM_STATE_s[*statePtr],
                     MSTP_TCM_STATE_s[MSTP_TCM_STATE_ACTIVE],
                     mstid, lport);
   *statePtr = MSTP_TCM_STATE_ACTIVE;

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_tcmSmAcknowledgedCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'ACKNOWLEDGED'.
 *
 * Params:    mstid -> MST Instance Idetifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   TRUE, indicating that the state has been changed
 *            and the immediate check for the exit conditions from this state
 *            is required.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_tcmSmAcknowledgedCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res = TRUE;
   MSTP_TCM_STATE_t *statePtr = NULL;

   /*------------------------------------------------------------------------
    * transition to the 'ACTIVE' state unconditionally
    * NOTE: there are no actions to perform when entering this state
    *------------------------------------------------------------------------*/
   statePtr = mstp_utilTcmStatePtr(mstid, lport);
   STP_ASSERT(statePtr && *statePtr == MSTP_TCM_STATE_ACKNOWLEDGED);
   MSTP_SM_ST_PRINTF(MSTP_TCM, MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "TCM:", MSTP_TCM_STATE_s[*statePtr],
                     MSTP_TCM_STATE_s[MSTP_TCM_STATE_ACTIVE], mstid, lport);
   *statePtr = MSTP_TCM_STATE_ACTIVE;

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_tcmSmInactiveAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'INIT' state.
 *            ('fdbFlush' = TRUE;
 *             'tcWhile' = 0;
 *             if (cist) tcAck = FALSE;)
 *
 *            NOTE1:'fdbFlush' is a boolean. Set by the topology change state
 *                  machine to instruct the filtering database to remove all
 *                  entries for this Port, immediately if 'rstpVersion'
 *                  (17.20.11) is TRUE, or by rapid ageing (17.19.1) if
 *                  'stpVersion' (17.20.12) is TRUE. Reset by the filtering
 *                  database once the entries are removed if 'rstpVersion' is
 *                  TRUE, and immediately if 'stpVersion' is TRUE.
 *                  (802.1D-2004 17.19.7)
 *            NOTE2:In addition to the definition of 'fdbFlush' contained in
 *                  IEEE Std 802.1D, setting the 'fdbFlush' variable does not
 *                  result in flushing of filtering database entries in the
 *                  case that the Port is an Edge Port
 *                  (i.e., 'operEdge' is TRUE).
 *                  (802.1Q-REV/D5.0 13.24 s))
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
mstp_tcmSmInactiveAct(MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = NULL;

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   if(!MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_OPER_EDGE))
   {/* do MAC Address flushing on 'nonEdge' port only
     * (see NOTE2 in function header) */

      /* NOTE: rather than use 'fdbFlush' variable to communicate with
       *           Address Manager we do immediate flushing, that can be
       *           changed later after discussion with appropriate people */
      mstp_flush(mstid, lport);
      MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_FDB_FLUSH);
   }

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      cistPortPtr->tcWhile = 0;
      MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_TC_ACK);
      /* NOTE: we need to clear 'rcvdTcn' flag as it is possible to have
       *           this flag stuck on the disconnected port (e.g. a port just
       *           connected to STP (802.1d) device had received a TCN BPDU
       *           while not yet being in the Learning state and right after
       *           that the port was disconnected) */
      MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_RCVD_TCN);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      mstiPortPtr->tcWhile = 0;
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_tcmSmLearningAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'LEARNING' state.
 *            (if ('cist') {'rcvdTc' = 'rcvdTcn' = 'rcvdTcAck' = FALSE;}
 *             'rcvdTc' = 'tcProp' = FALSE;)
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
mstp_tcmSmLearningAct(MSTID_t mstid, LPORT_t lport)
{
   if(mstid == MSTP_CISTID)
   {
      MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(commPortPtr);
      STP_ASSERT(cistPortPtr);

      MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_RCVD_TCN);
      MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_RCVD_TC_ACK);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_RCVD_TC);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_TC_PROP);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);

      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RCVD_TC);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_TC_PROP);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_tcmSmDetectedAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'DETECTED' state.
 *            (newTcWhile(); setTcPropTree();
 *             'newInfoXst' = TRUE)
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
mstp_tcmSmDetectedAct(MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(commPortPtr);
   VLOG_DBG("MSTP TCM Detected");
   mstp_newTcWhile(mstid, lport);
   mstp_setTcPropTree(mstid, lport);
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO);
      /* increment detected topology changes counter for this port */
      cistPortPtr->dbgCnts.tcDetectCnt++;
      cistPortPtr->dbgCnts.tcDetectCntLastUpdated = time(NULL);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO_MSTI);
      /* increment detected topology changes counter for this port */
      mstiPortPtr->dbgCnts.tcDetectCnt++;
      mstiPortPtr->dbgCnts.tcDetectCntLastUpdated = time(NULL);
   }

      /*---------------------------------------------------------------------
       * kick Port Transmit state machine (per-Port)
       *---------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF(MSTP_TCM, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                             "TCM:", "DETECTED", "PTX:", mstid, lport);
      mstp_ptxSm(lport);
}

/**PROC+**********************************************************************
 * Name:      mstp_tcmSmNotifiedTcnAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'NOTIFIED_TCN' state.
 *            (newTcWhile();)
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
mstp_tcmSmNotifiedTcnAct(MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = NULL;

   STP_ASSERT(MSTP_BEGIN == FALSE);
   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   if (!commPortPtr)
   {
        STP_ASSERT(0);
   }
   STP_ASSERT((mstid == MSTP_CISTID) ?
          MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,MSTP_PORT_RCVD_TCN) :
          !MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,MSTP_PORT_RCVD_TCN));

   VLOG_DBG("MSTP TCM Notified");
   mstp_newTcWhile(mstid, lport);
}

/**PROC+**********************************************************************
 * Name:      mstp_tcmSmNotifiedTcAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'NOTIFIED_TC' state.
 *            (if ('cist') 'rcvdTcn' = FALSE;
 *             'rcvdTc' = FALSE;
 *             if ('cist' && ('role' == 'DesignatedPort')) 'tcAck' = TRUE;
 *             setTcPropTree();)
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
mstp_tcmSmNotifiedTcAct(MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = NULL;

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);

      MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_RCVD_TCN);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_RCVD_TC);
      if(cistPortPtr->role == MSTP_PORT_ROLE_DESIGNATED)
         MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_TC_ACK);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RCVD_TC);
   }

   mstp_setTcPropTree(mstid, lport);
}

/**PROC+**********************************************************************
 * Name:      mstp_tcmSmPropagatingAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'PROPAGATING' state.
 *            (newTcWhile();
 *             'fdbFlush' = TRUE;
 *             'tcProp' = FALSE;)
 *
 *            NOTE1:'fdbFlush' is a boolean. Set by the topology change state
 *                  machine to instruct the filtering database to remove all
 *                  entries for this Port, immediately if 'rstpVersion'
 *                  (17.20.11) is TRUE, or by rapid ageing (17.19.1) if
 *                  'stpVersion' (17.20.12) is TRUE. Reset by the filtering
 *                  database once the entries are removed if 'rstpVersion' is
 *                  TRUE, and immediately if 'stpVersion' is TRUE.
 *                  (802.1D-2004 17.19.7)
 *            NOTE2:In addition to the definition of 'fdbFlush' contained in
 *                  IEEE Std 802.1D, setting the 'fdbFlush' variable does not
 *                  result in flushing of filtering database entries in the
 *                  case that the Port is an Edge Port
 *                  (i.e., 'operEdge' is TRUE).
 *                  (802.1Q-REV/D5.0 13.24 s))
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
mstp_tcmSmPropagatingAct(MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(commPortPtr);

   VLOG_DBG("MSTP TCM Propagating");
   mstp_newTcWhile(mstid, lport);
   if(!MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_OPER_EDGE))
   {/* do MAC Address flushing on 'nonEdge' port only */

      /* NOTE: rather than use 'fdbFlush' variable to communicate with
       *           Address Manager we do immediate flushing, that can be
       *           changed later after discussion with appropriate people */
      mstp_flush(mstid, lport);
      MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_FDB_FLUSH);
   }

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_TC_PROP);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_TC_PROP);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_tcmSmAcknowledgedAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'ACKNOWLEDGED' state.
 *            ('tcWhile' = 0; 'rcvdTcAck' = FALSE;)
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
mstp_tcmSmAcknowledgedAct(MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      cistPortPtr->tcWhile = 0;
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      mstiPortPtr->tcWhile = 0;
   }

   MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_RCVD_TC_ACK);
}
