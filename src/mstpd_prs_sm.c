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
 *    File               : mstpd_prs_sm.c
 *    Description        : MSTP Protocol Port Role Selection State Machine
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
VLOG_DEFINE_THIS_MODULE(mstpd_prs_sm);

/*---------------------------------------------------------------------------
 * Local functions prototypes (forward declarations)
 *---------------------------------------------------------------------------*/
static void mstp_prsSmGeneralCond(MSTID_t mstid);
static bool mstp_prsSmInitTreeCond(MSTID_t mstid);
static bool mstp_prsSmRoleSelectionCond(MSTID_t mstid);

static void mstp_prsSmInitTreeAct(MSTID_t mstid);
static void mstp_prsSmRoleSelectionAct(MSTID_t mstid);

/** ======================================================================= **
 *                                                                           *
 *     Global Functions (externed)                                           *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_prsSm
 *
 * Purpose:   The entry point to the Port Role Selection state machine.
 *           (802.1Q-REV/D5.0 13.33)
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *
 * Returns:   none
 *
 * Globals:
 *
 **PROC-**********************************************************************/
void
mstp_prsSm(MSTID_t mstid)
{
   bool              next     = FALSE;/* This variable is used to indicate that
                                       * the state change processing is still
                                       * required */
   MSTP_PRS_STATE_t *statePtr = (mstid == MSTP_CISTID) ?
                                &(MSTP_CIST_INFO.prsState) :
                                &(MSTP_MSTI_INFO(mstid)->prsState);

   STP_ASSERT(mstid <= MSTP_MSTID_MAX);
   STP_ASSERT(MSTP_INSTANCE_IS_VALID(mstid));

   mstp_prsSmGeneralCond(mstid);
   do
   {
      switch(*statePtr)
      {
         case MSTP_PRS_STATE_INIT_TREE:
            next = mstp_prsSmInitTreeCond(mstid);
            break;
         case MSTP_PRS_STATE_ROLE_SELECTION:
            next = mstp_prsSmRoleSelectionCond(mstid);
            break;
         default:
            STP_ASSERT(0);
            break;
      }
   }
   while (next == TRUE);

   /*------------------------------------------------------------------------
    * when exit the state for PRS SM must be 'ROLE_SELECTION'
    *------------------------------------------------------------------------*/
   STP_ASSERT(*statePtr == MSTP_PRS_STATE_ROLE_SELECTION);

}

/** ======================================================================= **
 *                                                                           *
 *     Static (local to this file) Functions                                 *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_prsSmGeneralCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_prsSmGeneralCond(MSTID_t mstid)
{
   if(MSTP_BEGIN == TRUE)
   {
      MSTP_PRS_STATE_t *statePtr = (mstid == MSTP_CISTID) ?
                                   &(MSTP_CIST_INFO.prsState) :
                                   &(MSTP_MSTI_INFO(mstid)->prsState);

      /*---------------------------------------------------------------------
       * check for conditions to transition to the 'INIT_TREE' state
       *---------------------------------------------------------------------*/
      if(*statePtr != MSTP_PRS_STATE_INIT_TREE)
      {
         MSTP_SM_ST_PRINTF2(MSTP_PRS, MSTP_PER_TREE_SM_STATE_TRANSITION_FMT,
                            "PRS:", MSTP_PRS_STATE_s[*statePtr],
                            MSTP_PRS_STATE_s[MSTP_PRS_STATE_INIT_TREE],
                            mstid);
         *statePtr = MSTP_PRS_STATE_INIT_TREE;
         mstp_prsSmInitTreeAct(mstid);
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_prsSmInitTreeCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'INIT_TREE'
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *
 * Returns:   FALSE, indicating that no immediate check for the exit conditions
 *            from the new state is required.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_prsSmInitTreeCond(MSTID_t mstid)
{
   bool              res = FALSE;
   MSTP_PRS_STATE_t *statePtr = (mstid == MSTP_CISTID) ?
                            &(MSTP_CIST_INFO.prsState) :
                            &(MSTP_MSTI_INFO(mstid)->prsState);

   /*------------------------------------------------------------------------
    * transition to the 'ROLE_SELECTION' state unconditionally
    *------------------------------------------------------------------------*/
   STP_ASSERT(*statePtr == MSTP_PRS_STATE_INIT_TREE);
   MSTP_SM_ST_PRINTF2(MSTP_PRS, MSTP_PER_TREE_SM_STATE_TRANSITION_FMT,
                      "PRS:", MSTP_PRS_STATE_s[*statePtr],
                      MSTP_PRS_STATE_s[MSTP_PRS_STATE_ROLE_SELECTION], mstid);
   *statePtr = MSTP_PRS_STATE_ROLE_SELECTION;
   mstp_prsSmRoleSelectionAct(mstid);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prsSmRoleSelectionCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'ROLE_SELECTION'
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *
 * Returns:   FALSE, indicating that no immediate check for the exit conditions
 *            from the new state is required.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_prsSmRoleSelectionCond(MSTID_t mstid)
{
   bool              res      = FALSE;
   bool             reselect = FALSE;
   LPORT_t           lport;
   MSTP_PRS_STATE_t *statePtr = (mstid == MSTP_CISTID) ?
                                &(MSTP_CIST_INFO.prsState) :
                                &(MSTP_MSTI_INFO(mstid)->prsState);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(*statePtr == MSTP_PRS_STATE_ROLE_SELECTION);

   /*------------------------------------------------------------------------
    * collect state exit conditions information
    *------------------------------------------------------------------------*/
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr;

      for(lport = 1 ; lport <= MAX_LPORTS; lport++)
      {
         cistPortPtr = MSTP_CIST_PORT_PTR(lport);
         if (cistPortPtr && MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                                      MSTP_CIST_PORT_RESELECT))
         {
            reselect = TRUE;
            break;
         }
      }
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr;

      for(lport = 1 ; lport <= MAX_LPORTS; lport++)
      {
         mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
         if (mstiPortPtr && MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                                      MSTP_MSTI_PORT_RESELECT))
         {
            reselect = TRUE;
            break;
         }
      }
   }

   /*------------------------------------------------------------------------
    * check for condition to transition (re-enter) to the 'ROLE_SELECTION'
    * state
    *------------------------------------------------------------------------*/
   if(reselect)
   {/* reselect1 || reselect2 || ... reselectN */
      MSTP_SM_ST_PRINTF2(MSTP_PRS, MSTP_PER_TREE_SM_STATE_TRANSITION_FMT,
                         "PRS:", MSTP_PRS_STATE_s[*statePtr],
                         MSTP_PRS_STATE_s[MSTP_PRS_STATE_ROLE_SELECTION],mstid);
      *statePtr = MSTP_PRS_STATE_ROLE_SELECTION;
      mstp_prsSmRoleSelectionAct(mstid);
      res = FALSE;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prsSmInitTreeAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'INIT_TREE' state.
 *            (updtRolesDisabledTree();)
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *
 * Returns:   none
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_prsSmInitTreeAct(MSTID_t mstid)
{
   mstp_updtRolesDisabledTree(mstid);
}

/**PROC+**********************************************************************
 * Name:      mstp_prsSmRoleSelectionAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'ROLE_SELECTION' state.
 *            (clearReselectTree(); updtRolesTree(); setSelectedTree();)
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *
 * Returns:   none
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_prsSmRoleSelectionAct(MSTID_t mstid)
{
   LPORT_t                lport = 0;
   LPORT_t                lportRoot;
   MSTP_COMM_PORT_INFO_t *commPortPtr = NULL;

   mstp_clearReselectTree(mstid);
   mstp_updtRolesTree(mstid);
   mstp_setSelectedTree(mstid);

   lportRoot = (mstid == MSTP_CISTID) ?
                MSTP_GET_PORT_NUM(MSTP_CIST_ROOT_PORT_ID):
                MSTP_GET_PORT_NUM(MSTP_MSTI_ROOT_PORT_ID(mstid));

   /*------------------------------------------------------------------------
    * First, update info for the Root Port. This order is critical as during
    * the Root Port update we may schedule appropriate updates for all other
    * ports.
    * NOTE: 'lportRoot' MUST be '0' if this Bridge is the Root of the tree
    *------------------------------------------------------------------------*/
   if(lportRoot != 0)
   {/* This Bridge is not the Root of the tree */
      STP_ASSERT(IS_VALID_LPORT(lportRoot));
      STP_ASSERT(MSTP_COMM_PORT_PTR(lportRoot));

      /*---------------------------------------------------------------------
       * kick Port Information state machine (per-Tree per-Port)
       *---------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF1(MSTP_PRS,
                              MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                              "PRS:", "ROLE_SELECTION", "PIM:",
                              mstid, lportRoot);
      mstp_pimSm(NULL, mstid, lportRoot);

      /*--------------------------------------------------------------------
       * kick Port Role Transitions state machine (per-Tree per-Port)
       *--------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF1(MSTP_PRS,
                              MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                              "PRS:", "ROLE_SELECTION", "PRT:",
                              mstid, lportRoot);
      mstp_prtSm(mstid, lportRoot);
   }

   /*------------------------------------------------------------------------
    * Proceed with all ports but Root Port.
    *------------------------------------------------------------------------*/
   for(lport = 1; lport <= MAX_LPORTS; lport++)
   {
      if(lport == lportRoot)
         continue;

      commPortPtr = MSTP_COMM_PORT_PTR(lport);
      if(commPortPtr != NULL)
      {

         /*------------------------------------------------------------------
          * kick Port Information state machine (per-Tree per-Port)
          *------------------------------------------------------------------*/
         MSTP_SM_CALL_SM_PRINTF1(MSTP_PRS,
                                 MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                                 "PRS:", "ROLE_SELECTION", "PIM:",
                                 mstid, lport);
         mstp_pimSm(NULL, mstid, lport);
         /*------------------------------------------------------------------
          * kick Port Role Transitions state machine (per-Tree per-Port)
          *------------------------------------------------------------------*/
         MSTP_SM_CALL_SM_PRINTF1(MSTP_PRS,
                                 MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                                 "PRS:", "ROLE_SELECTION", "PRT:",
                                 mstid, lport);
         mstp_prtSm(mstid, lport);
      }
   }

   /*------------------------------------------------------------------------
    * Call PRT SM for the Root Port one more time after scheduled updates
    * for all other ports have been completed, we may have changes in global
    * conditions (such as 'allSynced' or 'reRooted') that allow this Root Port
    * transition to the Forwarding state immediately
    * NOTE: 'lportRoot' MUST be '0' if this Bridge is the Root of the tree
    *------------------------------------------------------------------------*/
   if(lportRoot != 0)
   {/* This Bridge is not the Root of the tree */
      STP_ASSERT(IS_VALID_LPORT(lportRoot));
      STP_ASSERT(MSTP_COMM_PORT_PTR(lportRoot));

      /*--------------------------------------------------------------------
       * kick Port Role Transitions state machine (per-Tree per-Port)
       *--------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF1(MSTP_PRS,
                              MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                              "PRS:", "ROLE_SELECTION", "PRT:",
                              mstid, lportRoot);
      mstp_prtSm(mstid, lportRoot);
   }
}
