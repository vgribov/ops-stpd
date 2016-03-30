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

/************************************************************************//**
 * @ingroup ops-stpd
 ***************************************************************************/
/**********************************************************************************
 *    File               : mstpd_bdm_sm.c
 *    Description        : MSTP Protocol Bridge Detection State Machine Entry point
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

VLOG_DEFINE_THIS_MODULE(mstpd_bdm_sm);
/*---------------------------------------------------------------------------
 * Local functions prototypes (forward declarations)
 *---------------------------------------------------------------------------*/
static void mstp_bdmSmGeneralCond(LPORT_t lport);
static void mstp_bdmSmEdgeCond(LPORT_t lport);
static void mstp_bdmSmNotEdgeCond(LPORT_t lport);

static void mstp_bdmSmEdgeAct(LPORT_t lport);
static void mstp_bdmSmNotEdgeAct(LPORT_t lport);

/** ======================================================================= **
 *                                                                           *
 *     Global Functions (externed)                                           *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_bdmSm
 *
 * Purpose:   Bridge Detection state machine.
 *            (802.1Q-REV/D5.0 13.30; 802.1D-2004 17.25)
 *
 * Params:    lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
void
mstp_bdmSm(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr;

   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   mstp_bdmSmGeneralCond(lport);
   switch(commPortPtr->bdmState)
   {
      case MSTP_BDM_STATE_EDGE:
         mstp_bdmSmEdgeCond(lport);
         break;
      case MSTP_BDM_STATE_NOT_EDGE:
         mstp_bdmSmNotEdgeCond(lport);
         break;
      default:
         STP_ASSERT(0);
   }

   /*------------------------------------------------------------------------
    * when exit the state for BDM SM must be 'EDGE' || 'NOT_EDGE'
    *------------------------------------------------------------------------*/
   STP_ASSERT(commPortPtr->bdmState == MSTP_BDM_STATE_EDGE ||
          commPortPtr->bdmState == MSTP_BDM_STATE_NOT_EDGE);

}

/** ======================================================================= **
 *                                                                           *
 *     Static (local to this file) Functions                                 *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_bdmSmGeneralCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
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
mstp_bdmSmGeneralCond(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr);

   /*------------------------------------------------------------------------
    * check for conditions to transition to the 'EDGE' or 'NOT_EDGE' state
    *------------------------------------------------------------------------*/
   if(MSTP_BEGIN == TRUE)
   {
      if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                   MSTP_PORT_ADMIN_EDGE_PORT))
      {/* 'BEGIN' && 'AdminEdge' */
         MSTP_SM_ST_PRINTF1(MSTP_BDM, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                            "BDM:",MSTP_BDM_STATE_s[commPortPtr->bdmState],
                            MSTP_BDM_STATE_s[MSTP_BDM_STATE_EDGE], lport);
         commPortPtr->bdmState = MSTP_BDM_STATE_EDGE;
         mstp_bdmSmEdgeAct(lport);
      }
      else
      {/* 'BEGIN' && '!AdminEdge' */
         MSTP_SM_ST_PRINTF1(MSTP_BDM, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                            "BDM:",MSTP_BDM_STATE_s[commPortPtr->bdmState],
                            MSTP_BDM_STATE_s[MSTP_BDM_STATE_NOT_EDGE], lport);
         commPortPtr->bdmState = MSTP_BDM_STATE_NOT_EDGE;
         mstp_bdmSmNotEdgeAct(lport);
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_bdmSmEdgeCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'EDGE'
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
mstp_bdmSmEdgeCond(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr && (commPortPtr->bdmState == MSTP_BDM_STATE_EDGE));

   /*------------------------------------------------------------------------
    * check for conditions to transition to the next state
    *------------------------------------------------------------------------*/
   if((!MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                  MSTP_PORT_PORT_ENABLED) &&
       !MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                  MSTP_PORT_ADMIN_EDGE_PORT)) ||
      !MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                 MSTP_PORT_OPER_EDGE))
   {/* ('!portEnabled' && '!AdminEdge') || '!operEdge' */
      MSTP_SM_ST_PRINTF1(MSTP_BDM, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                         "BDM:",MSTP_BDM_STATE_s[commPortPtr->bdmState],
                         MSTP_BDM_STATE_s[MSTP_BDM_STATE_NOT_EDGE], lport);
      commPortPtr->bdmState = MSTP_BDM_STATE_NOT_EDGE;
      mstp_bdmSmNotEdgeAct(lport);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_bdmSmNotEdgeCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'NOT_EDGE'
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
mstp_bdmSmNotEdgeCond(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr    = MSTP_COMM_PORT_PTR(lport);
   MSTP_CIST_PORT_INFO_t *cistPortPtr    = MSTP_CIST_PORT_PTR(lport);
   bool                  portEnabled    = FALSE;
   bool                  AdminEdge      = FALSE;
   bool                  AutoEdge       = FALSE;
   bool                  sendRstp       = FALSE;
   bool                  proposing      = FALSE;
   uint8_t                edgeDelayWhile = 0;

   STP_ASSERT(commPortPtr && (commPortPtr->bdmState == MSTP_BDM_STATE_NOT_EDGE));
   STP_ASSERT(cistPortPtr);

   edgeDelayWhile = commPortPtr->edgeDelayWhile;
   portEnabled    = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                              MSTP_PORT_PORT_ENABLED);
   AdminEdge      = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                              MSTP_PORT_ADMIN_EDGE_PORT);
   AutoEdge       = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                              MSTP_PORT_AUTO_EDGE);
   sendRstp       = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                              MSTP_PORT_SEND_RSTP);
   proposing      = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                              MSTP_CIST_PORT_PROPOSING);

   /*------------------------------------------------------------------------
    * check for conditions to transition to the next state
    *------------------------------------------------------------------------*/
   if((!portEnabled && AdminEdge) ||
      ((edgeDelayWhile == 0) && AutoEdge && sendRstp && proposing))
   {
      MSTP_SM_ST_PRINTF1(MSTP_BDM, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                         "BDM:",MSTP_BDM_STATE_s[commPortPtr->bdmState],
                         MSTP_BDM_STATE_s[MSTP_BDM_STATE_EDGE], lport);
      commPortPtr->bdmState = MSTP_BDM_STATE_EDGE;
      mstp_bdmSmEdgeAct(lport);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_bdmSmEdgeAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'EDGE' state.
 *            ('operEdgePort' = 'TRUE';)
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
mstp_bdmSmEdgeAct(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr);
   MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_OPER_EDGE);

   mstp_updatePortOperEdgeState(MSTP_CISTID, lport, TRUE);

   if(MSTP_BEGIN == FALSE)
   {
      MSTID_t mstid;

      /*---------------------------------------------------------------------
       * kick Port Role Transitions state machine (per-Tree per-Port)
       * for the CIST
       *---------------------------------------------------------------------*/
      mstid = MSTP_CISTID;
      MSTP_SM_CALL_SM_PRINTF(MSTP_PIM, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                             "BDM:", "EDGE", "PRT:", mstid, lport);
      mstp_prtSm(mstid, lport);

      /*------------------------------------------------------------------
       * kick Topology Change state machine (per-Tree per-Port)
       *------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                              "BDM:", "EDGE", "TCM:", mstid, lport);
      mstp_tcmSm(mstid, lport);

      /*---------------------------------------------------------------------
       * kick Port Role Transitions and Topology Change state machines for
       * each enabled MSTI (both SMs are per-Tree per-Port)
       *---------------------------------------------------------------------*/
      for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
      {
         if(MSTP_MSTI_VALID(mstid))
         {
            STP_ASSERT(MSTP_MSTI_PORT_PTR(mstid, lport));
            MSTP_SM_CALL_SM_PRINTF(MSTP_PIM,
                                   MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                                   "BDM:", "EDGE", "PRT:", mstid, lport);
            mstp_prtSm(mstid, lport);
            MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                                    "BDM:", "EDGE", "TCM:", mstid, lport);
            mstp_tcmSm(mstid, lport);
         }
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_bdmSmNotEdgeAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'NOT_EDGE' state.
 *            ('operEdgePort' = 'FALSE';)
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
mstp_bdmSmNotEdgeAct(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr);
   MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_OPER_EDGE);

   mstp_updatePortOperEdgeState(MSTP_CISTID, lport, FALSE);

   if(MSTP_BEGIN == FALSE)
   {
      MSTID_t mstid;

      mstid = MSTP_CISTID;

      /*---------------------------------------------------------------------
       * kick Port Role Transitions state machine (per-Tree per-Port)
       * for the CIST
       *---------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF(MSTP_PIM, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                             "BDM:", "NOT_EDGE", "PRT:", mstid, lport);
      mstp_prtSm(mstid, lport);

      /*------------------------------------------------------------------
       * kick Topology Change state machine (per-Tree per-Port)
       * for the CIST
       *------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                              "BDM:", "NOT_EDGE", "TCM:", mstid, lport);
      mstp_tcmSm(mstid, lport);

      /*---------------------------------------------------------------------
       * kick Port Role Transitions and Topology Change state machines for
       * each enabled MSTI (both SMs are per-Tree per-Port)
       *---------------------------------------------------------------------*/
      for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
      {
         if(MSTP_MSTI_VALID(mstid))
         {
            STP_ASSERT(MSTP_MSTI_PORT_PTR(mstid, lport));
            MSTP_SM_CALL_SM_PRINTF(MSTP_PIM,
                                   MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                                   "BDM:", "NOT_EDGE", "PRT:", mstid, lport);
            mstp_prtSm(mstid, lport);
            MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                                    "BDM:", "NOT_EDGE", "TCM:", mstid, lport);
            mstp_tcmSm(mstid, lport);
         }
      }
   }
}
