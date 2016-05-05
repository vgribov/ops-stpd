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
 *    File               : mstpd_prt_sm.c
 *    Description        : MSTP Protocol Port Role Transition State Machine
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
VLOG_DEFINE_THIS_MODULE(mstpd_prt_sm);

/*---------------------------------------------------------------------------
 * Local functions prototypes (forward declarations)
 *---------------------------------------------------------------------------*/
static void mstp_prtSmGeneralCond(MSTID_t mstid, LPORT_t lport);

/* Disabled Port */
static bool mstp_prtSmInitPortCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmDisablePortCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmDisabledPortCond(MSTID_t mstid, LPORT_t lport);

static void mstp_prtSmInitPortAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmDisablePortAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmDisabledPortAct(MSTID_t mstid, LPORT_t lport);

/* Master Port */
static bool mstp_prtSmMasterPortCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmMasterProposedCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmMasterAgreedCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmMasterSyncedCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmMasterRetiredCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmMasterForwardCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmMasterLearnCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmMasterDiscardCond(MSTID_t mstid, LPORT_t lport);

static void mstp_prtSmMasterPortAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmMasterProposedAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmMasterAgreedAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmMasterSyncedAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmMasterRetiredAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmMasterForwardAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmMasterLearnAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmMasterDiscardAct(MSTID_t mstid, LPORT_t lport);

/* Root Port */
static bool mstp_prtSmRootPortCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmRootProposedCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmRootAgreedCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmRootSyncedCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmReRootCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmRootForwardCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmRootLearnCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmReRootedCond(MSTID_t mstid, LPORT_t lport);

static void mstp_prtSmRootPortAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmRootProposedAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmRootAgreedAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmRootSyncedAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmReRootAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmRootForwardAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmRootLearnAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmReRootedAct(MSTID_t mstid, LPORT_t lport);

/* Designated Port */
static bool mstp_prtSmDesignatedPortCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmDesignatedProposeCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmDesignatedAgreedCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmDesignatedSyncedCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmDesignatedRetiredCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmDesignatedForwardCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmDesignatedLearnCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmDesignatedDiscardCond(MSTID_t mstid, LPORT_t lport);

static void mstp_prtSmDesignatedPortAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmDesignatedProposeAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmDesignatedAgreedAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmDesignatedSyncedAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmDesignatedRetiredAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmDesignatedForwardAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmDesignatedLearnAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmDesignatedDiscardAct(MSTID_t mstid, LPORT_t lport);

/* Aletrnate and Backup Port */
static bool mstp_prtSmAlternatePortCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmAlternateProposedCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmAlternateAgreedCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmBlockPortCond(MSTID_t mstid, LPORT_t lport);
static bool mstp_prtSmBackupPortCond(MSTID_t mstid, LPORT_t lport);

static void mstp_prtSmAlternatePortAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmAlternateProposedAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmAlternateAgreedAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmBlockPortAct(MSTID_t mstid, LPORT_t lport);
static void mstp_prtSmBackupPortAct(MSTID_t mstid, LPORT_t lport);

/** ======================================================================= **
 *                                                                           *
 *     Global Functions (externed)                                           *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_prtSm
 *
 * Purpose:   The entry point to the Port Role Transitions (PRT) state machine.
 *            (802.1Q-REV/D5.0 13.34)
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
mstp_prtSm(MSTID_t mstid, LPORT_t lport)
{
   bool             next     = FALSE;/* This variable is used to indicate
                                       * that the state change processing is
                                       * still required */
   MSTP_PRT_STATE_t *statePtr = NULL;

   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(MSTP_INSTANCE_IS_VALID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));

   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr);

   MSTP_SM_ST_PRINTF(MSTP_PRT,
                     MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", "ENTER",
                     MSTP_PRT_STATE_s[*statePtr],
                     mstid, lport);

   /* Check global (external) conditions to determine what component of the
    * PRT State Machine to execute, which will be one of the following:
    * - PRT SM for Disabled Port
    * - PRT SM for Master Port
    * - PRT SM for Root Port
    * - PRT SM for Designated Port
    * - PRT SM for Alternate and Backup Port */
   mstp_prtSmGeneralCond(mstid, lport);

   /* Run PRT State Machine */
   do
   {
      switch(*statePtr)
      {
         /* Disabled Port role transitions */
         case MSTP_PRT_STATE_INIT_PORT:
            next = mstp_prtSmInitPortCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_DISABLE_PORT:
            next = mstp_prtSmDisablePortCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_DISABLED_PORT:
            next = mstp_prtSmDisabledPortCond(mstid, lport);
            break;
         /* Master Port role transitions */
         case MSTP_PRT_STATE_MASTER_PORT:
            next = mstp_prtSmMasterPortCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_MASTER_PROPOSED:
            next = mstp_prtSmMasterProposedCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_MASTER_AGREED:
            next = mstp_prtSmMasterAgreedCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_MASTER_SYNCED:
            next = mstp_prtSmMasterSyncedCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_MASTER_RETIRED:
            next = mstp_prtSmMasterRetiredCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_MASTER_FORWARD:
            next = mstp_prtSmMasterForwardCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_MASTER_LEARN:
            next = mstp_prtSmMasterLearnCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_MASTER_DISCARD:
            next = mstp_prtSmMasterDiscardCond(mstid, lport);
            break;
         /* Root Port role transitions */
         case MSTP_PRT_STATE_ROOT_PORT:
            next = mstp_prtSmRootPortCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_ROOT_PROPOSED:
            next = mstp_prtSmRootProposedCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_ROOT_AGREED:
            next = mstp_prtSmRootAgreedCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_ROOT_SYNCED:
            next = mstp_prtSmRootSyncedCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_REROOT:
            next = mstp_prtSmReRootCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_ROOT_FORWARD:
            next = mstp_prtSmRootForwardCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_ROOT_LEARN:
            next = mstp_prtSmRootLearnCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_REROOTED:
            next = mstp_prtSmReRootedCond(mstid, lport);
            break;
         /* Designated Port role transitions */
         case MSTP_PRT_STATE_DESIGNATED_PORT:
            next = mstp_prtSmDesignatedPortCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_DESIGNATED_PROPOSE:
            next = mstp_prtSmDesignatedProposeCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_DESIGNATED_AGREED:
            next = mstp_prtSmDesignatedAgreedCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_DESIGNATED_SYNCED:
            next = mstp_prtSmDesignatedSyncedCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_DESIGNATED_RETIRED:
            next = mstp_prtSmDesignatedRetiredCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_DESIGNATED_FORWARD:
            next = mstp_prtSmDesignatedForwardCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_DESIGNATED_LEARN:
            next = mstp_prtSmDesignatedLearnCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_DESIGNATED_DISCARD:
            next = mstp_prtSmDesignatedDiscardCond(mstid, lport);
            break;
         /* Alternate and Backup Port role transitions */
         case MSTP_PRT_STATE_ALTERNATE_PORT:
            next = mstp_prtSmAlternatePortCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_ALTERNATE_PROPOSED:
            next = mstp_prtSmAlternateProposedCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_ALTERNATE_AGREED:
            next = mstp_prtSmAlternateAgreedCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_BLOCK_PORT:
            next = mstp_prtSmBlockPortCond(mstid, lport);
            break;
         case MSTP_PRT_STATE_BACKUP_PORT:
            next = mstp_prtSmBackupPortCond(mstid, lport);
            break;
         default:
            STP_ASSERT(0);
            break;
      }
   }
   while (next == TRUE);

   /*------------------------------------------------------------------------
    * on exit the state for PRT SM must be one of the following:
    * 'MASTER_PORT' || 'ROOT_PORT' || 'DESIGNATED_PORT' || 'ALTERNATE_PORT' ||
    * 'BLOCK_PORT' || 'DISABLE_PORT' || 'DISABLED_PORT'
    *------------------------------------------------------------------------*/
   STP_ASSERT(*statePtr == MSTP_PRT_STATE_MASTER_PORT     ||
          *statePtr == MSTP_PRT_STATE_ROOT_PORT       ||
          *statePtr == MSTP_PRT_STATE_DESIGNATED_PORT ||
          *statePtr == MSTP_PRT_STATE_ALTERNATE_PORT  ||
          *statePtr == MSTP_PRT_STATE_BLOCK_PORT      ||
          *statePtr == MSTP_PRT_STATE_DISABLE_PORT    ||
          *statePtr == MSTP_PRT_STATE_DISABLED_PORT);
   MSTP_SM_ST_PRINTF(MSTP_PRT,
                     MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", "EXIT",
                     MSTP_PRT_STATE_s[*statePtr],
                     mstid, lport);
}

/** ======================================================================= **
 *                                                                           *
 *     Static (local to this file) Functions                                 *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_prtSmGeneralCond
 *
 * Purpose:   Check for the global (external) conditions to determine what
 *            component of the PRT SM to execute:
 *            - PRT SM for Disabled Port
 *            - PRT SM for Master Port
 *            - PRT SM for Root Port
 *            - PRT SM for Designated Port
 *            - PRT SM for Alternate and Backup Port
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            port  -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_prtSmGeneralCond(MSTID_t mstid, LPORT_t lport)
{
   bool             selected     = FALSE;
   bool             updtInfo     = FALSE;
   MSTP_PORT_ROLE_t  role         = MSTP_PORT_ROLE_DISABLED;
   MSTP_PORT_ROLE_t  selectedRole = MSTP_PORT_ROLE_DISABLED;
   MSTP_PRT_STATE_t *statePtr     = NULL;

   /*------------------------------------------------------------------------
    * collect state transition information
    *------------------------------------------------------------------------*/
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);

      statePtr     = &cistPortPtr->prtState;
      selected     = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                               MSTP_CIST_PORT_SELECTED);
      updtInfo     = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                               MSTP_CIST_PORT_UPDT_INFO);
      role         = cistPortPtr->role;
      selectedRole = cistPortPtr->selectedRole;
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);

      statePtr     = &mstiPortPtr->prtState;
      selected     = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                               MSTP_MSTI_PORT_SELECTED);
      updtInfo     = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                               MSTP_MSTI_PORT_UPDT_INFO);
      role         = mstiPortPtr->role;
      selectedRole = mstiPortPtr->selectedRole;
   }

   /*------------------------------------------------------------------------
    * check for conditions to transition to the next state
    *------------------------------------------------------------------------*/
   if(MSTP_BEGIN == TRUE)
   {/* 'BEGIN' - PRT SM Initialization */
      if(*statePtr != MSTP_PRT_STATE_INIT_PORT)
      {
         /*------------------------------------------------------------------
          * condition for transition to the 'INIT_PORT' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_INIT_PORT],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_INIT_PORT;
         mstp_prtSmInitPortAct(mstid, lport);
      }
   }
   else if((role != selectedRole) && (selected && !updtInfo))
   {/* ('role' != 'selectedRole') && 'selected' && '!updtInfo' */

      if(selectedRole == MSTP_PORT_ROLE_DISABLED)
      {/* ('selectedRole' == 'DisabledPort') &&
        * ('role' != 'selectedRole') && 'selected' && '!updtInfo' */

         /*---------------------------------------------------------------
          * condition for transition to the 'DISABLE_PORT' state
          *---------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_DISABLE_PORT],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_DISABLE_PORT;
         mstp_prtSmDisablePortAct(mstid, lport);
      }
      else if(selectedRole == MSTP_PORT_ROLE_MASTER)
      {/* ('selectedRole' == 'MasterPort') &&
        * ('role' != 'selectedRole') && 'selected' && '!updtInfo' */

         /*---------------------------------------------------------------
          * condition for transition to the 'MASTER_PORT' state
          *---------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_MASTER_PORT],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_MASTER_PORT;
         mstp_prtSmMasterPortAct(mstid, lport);
      }
      else if(selectedRole == MSTP_PORT_ROLE_ROOT)
      {/* ('selectedRole' == 'RootPort') &&
        * ('role' != 'selectedRole') && 'selected' && '!updtInfo' */

         /*---------------------------------------------------------------
          * condition for transition to the 'ROOT_PORT' state
          *---------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_ROOT_PORT],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_ROOT_PORT;
         mstp_prtSmRootPortAct(mstid, lport);
      }
      else if(selectedRole == MSTP_PORT_ROLE_DESIGNATED)
      {/* ('selectedRole' == 'DesignatedPort') &&
        * ('role' != 'selectedRole') && 'selected' && '!updtInfo' */

         /*---------------------------------------------------------------
          * condition for transition to the 'DESIGNATED_PORT' state
          *---------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_DESIGNATED_PORT],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_DESIGNATED_PORT;
         mstp_prtSmDesignatedPortAct(mstid, lport);
      }
      else if((selectedRole == MSTP_PORT_ROLE_ALTERNATE) ||
              (selectedRole == MSTP_PORT_ROLE_BACKUP))
      {/* (('selectedRole' == 'AlternatePort') ||
        *  ('selectedRole' == 'BackupPort')) &&
        * ('role' != 'selectedRole') && 'selected' && '!updtInfo' */

         /*---------------------------------------------------------------
          * condition for transition to the 'BLOCK_PORT' state
          *---------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_BLOCK_PORT],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_BLOCK_PORT;
         mstp_prtSmBlockPortAct(mstid, lport);
      }
      else
         STP_ASSERT(0);
   }
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*
 *                                                                           *
 * Disabled Port State transition and State action routines                  *
 *                                                                           *
 *~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

/**PROC+**********************************************************************
 * Name:      mstp_prtSmInitPortCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'INIT_PORT'.
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
mstp_prtSmInitPortCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   /*------------------------------------------------------------------------
    * transition to the 'DISABLE_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_INIT_PORT));

   MSTP_SM_ST_PRINTF(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_DISABLE_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_DISABLE_PORT;
   mstp_prtSmDisablePortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmDisablePortCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'DISABLE_PORT'.
 *
 * Params:    mstid -> MST Instance Idetifier (the CIST or an MSTI)
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
mstp_prtSmDisablePortCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res        = FALSE;
   bool             selected   = FALSE;
   bool             updtInfo   = FALSE;
   bool             learning   = FALSE;
   bool             forwarding = FALSE;
   MSTP_PRT_STATE_t *statePtr   = NULL;

   /*------------------------------------------------------------------------
    * collect state exit conditions information
    *------------------------------------------------------------------------*/
   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_DISABLE_PORT));
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      selected   = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_SELECTED);
      updtInfo   = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_UPDT_INFO);
      learning   = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_LEARNING);
      forwarding = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_FORWARDING);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      selected   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_SELECTED);
      updtInfo   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_UPDT_INFO);
      learning   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_LEARNING);
      forwarding = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_FORWARDING);
   }

   /*------------------------------------------------------------------------
    * check for condition to transition to the 'DISABLED_PORT' state
    *------------------------------------------------------------------------*/
   if(selected && !updtInfo && !learning && !forwarding)
   {/* 'selected' && '!updtInfo' && '!learning' && '!forwarding' */
      MSTP_SM_ST_PRINTF(MSTP_PRT,
                        MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                        "PRT:", MSTP_PRT_STATE_s[*statePtr],
                        MSTP_PRT_STATE_s[MSTP_PRT_STATE_DISABLED_PORT],
                        mstid, lport);
      *statePtr = MSTP_PRT_STATE_DISABLED_PORT;
      mstp_prtSmDisabledPortAct(mstid, lport);
      res = FALSE;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmDisabledPortCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'DISABLED_PORT'.
 *
 * Params:    mstid -> MST Instance Idetifier (the CIST or an MSTI)
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
mstp_prtSmDisabledPortCond(MSTID_t mstid, LPORT_t lport)
{
   bool                   res         = FALSE;
   bool                  selected    = FALSE;
   bool                  updtInfo    = FALSE;
   bool                  sync        = FALSE;
   bool                  synced      = FALSE;
   bool                  reRoot      = FALSE;
   uint8_t                 fdWhile     = 0;
   uint16_t                MaxAge      = 0;
   MSTP_PRT_STATE_t      *statePtr    = NULL;
   MSTP_COMM_PORT_INFO_t *commPortPtr = NULL;

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   if (!commPortPtr)
   {
        STP_ASSERT(0);
   }

   /*------------------------------------------------------------------------
    * collect state exit conditions information
    *------------------------------------------------------------------------*/
   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_DISABLED_PORT));
   MaxAge = MSTP_CIST_ROOT_TIMES.maxAge;

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      selected = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                           MSTP_CIST_PORT_SELECTED);
      updtInfo = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                           MSTP_CIST_PORT_UPDT_INFO);
      sync     = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                           MSTP_CIST_PORT_SYNC);
      synced   = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                           MSTP_CIST_PORT_SYNCED);
      reRoot   = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                           MSTP_CIST_PORT_RE_ROOT);
      fdWhile  = cistPortPtr->fdWhile;
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      selected = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                           MSTP_MSTI_PORT_SELECTED);
      updtInfo = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                           MSTP_MSTI_PORT_UPDT_INFO);
      sync     = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                           MSTP_MSTI_PORT_SYNC);
      synced   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                           MSTP_MSTI_PORT_SYNCED);
      reRoot   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                           MSTP_MSTI_PORT_RE_ROOT);
      fdWhile  = mstiPortPtr->fdWhile;
   }

   /*------------------------------------------------------------------------
    * check for condition to transition to the next state
    *------------------------------------------------------------------------*/
   if((selected && !updtInfo) &&
      ((fdWhile != MaxAge) || sync || reRoot || !synced))
   {/* 'selected' && !'updtInfo' &&
     * (('fdWhile' != 'MaxAge') || 'sync' || 'reRoot' || !'synced') */

         /*------------------------------------------------------------------
          * condition for transition (re-enter) to the 'DISABLED_PORT' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_DISABLED_PORT],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_DISABLED_PORT;
         mstp_prtSmDisabledPortAct(mstid, lport);
         res = FALSE;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmInitPortAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'INIT_PORT' state.
 *            ('role' = 'DisabledPort';
 *             'learn' = 'forward' = FALSE;
 *             'synced' = FALSE;
 *             'sync' = 'reRoot' = TRUE;
 *             'rrWhile' = 'FwdDelay';
 *             'fdWhile' = 'MaxAge';
 *             'rbWhile' = 0;)
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
mstp_prtSmInitPortAct(MSTID_t mstid, LPORT_t lport)
{
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      cistPortPtr->role = MSTP_PORT_ROLE_DISABLED;
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_LEARN);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_FORWARD);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_SYNCED);
      MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_SYNC);
      MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_RE_ROOT);
      cistPortPtr->rrWhile = MSTP_CIST_ROOT_TIMES.fwdDelay;
      cistPortPtr->fdWhile = MSTP_CIST_ROOT_TIMES.maxAge;
      cistPortPtr->rbWhile = 0;
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      mstiPortPtr->role = MSTP_PORT_ROLE_DISABLED;
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_LEARN);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_FORWARD);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SYNCED);
      MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SYNC);
      MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RE_ROOT);
      mstiPortPtr->rrWhile = MSTP_CIST_ROOT_TIMES.fwdDelay;
      mstiPortPtr->fdWhile = MSTP_CIST_ROOT_TIMES.maxAge;
      mstiPortPtr->rbWhile = 0;
   }

   if(MSTP_BEGIN == FALSE)
   {
      /*------------------------------------------------------------------
       * kick Port State Transitions state machine (per-Tree per-Port)
       *------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                              "PRT:", "INIT_PORT", "PST:", mstid, lport);
      mstp_pstSm(mstid, lport);

      /*---------------------------------------------------------------------
       * kick Topology Change state machine  (per-Tree per-Port)
       *---------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                              "PRT:", "INIT_PORT", "TCM:", mstid, lport);
      mstp_tcmSm(mstid, lport);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmDisablePortAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'DISABLE_PORT' state.
 *            ('role' = 'selectedRole'; 'learn' = 'forward' = FALSE;)
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
mstp_prtSmDisablePortAct(MSTID_t mstid, LPORT_t lport)
{
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      cistPortPtr->role = cistPortPtr->selectedRole;
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_LEARN);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_FORWARD);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      mstiPortPtr->role = mstiPortPtr->selectedRole;
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_LEARN);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_FORWARD);
   }

   if(MSTP_BEGIN == FALSE)
   {
      /*------------------------------------------------------------------
       * kick Port State Transitions state machine (per-Tree per-Port)
       *------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                              "PRT:", "DISABLE_PORT", "PST:", mstid, lport);
      mstp_pstSm(mstid, lport);

      /*------------------------------------------------------------------
       * kick Topology Change state machine (per-Tree per-Port)
       *------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                              "PRT:", "DISABLE_PORT", "TCM:", mstid, lport);
      mstp_tcmSm(mstid, lport);

   }
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmDisabledPortAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'DISABLED_PORT' state.
 *            ('fdWhile = 'MaxAge';
 *             'synced' = TRUE; 'rrWhile' = 0;
 *             'sync' = 'reRoot' = FALSE;)
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
mstp_prtSmDisabledPortAct(MSTID_t mstid, LPORT_t lport)
{
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      cistPortPtr->fdWhile = MSTP_CIST_ROOT_TIMES.maxAge;
      MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_SYNCED);
      cistPortPtr->rrWhile = 0;
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_SYNC);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_RE_ROOT);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      mstiPortPtr->fdWhile = MSTP_CIST_ROOT_TIMES.maxAge;
      MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SYNCED);
      mstiPortPtr->rrWhile = 0;
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SYNC);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RE_ROOT);
   }
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*
 *                                                                           *
 * Master Port State transition and State action routines                    *
 *                                                                           *
 *~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

/**PROC+**********************************************************************
 * Name:      mstp_prtSmMasterPortCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'MASTER_PORT'.
 *
 * Params:    mstid -> MST Instance Idetifier (an MSTI only, never the CIST)
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
mstp_prtSmMasterPortCond(MSTID_t mstid, LPORT_t lport)
{
   bool                   res         = FALSE;
   bool                  selected    = FALSE;
   bool                  updtInfo    = FALSE;
   bool                  sync        = FALSE;
   bool                  synced      = FALSE;
   bool                  learn       = FALSE;
   bool                  learning    = FALSE;
   bool                  forward     = FALSE;
   bool                  forwarding  = FALSE;
   bool                  reRoot      = FALSE;
   bool                  agree       = FALSE;
   bool                  agreed      = FALSE;
   bool                  proposed    = FALSE;
   bool                  disputed    = FALSE;
   bool                  operEdge    = FALSE;
   bool                  allSynced   = TRUE;
   uint8_t                 fdWhile     = 0;
   uint8_t                rrWhile     = 0;
   MSTP_COMM_PORT_INFO_t *commPortPtr = NULL;
   MSTP_MSTI_PORT_INFO_t *mstiPortPtr = NULL;
   MSTP_PRT_STATE_t      *statePtr    = NULL;

   STP_ASSERT(MSTP_VALID_MSTID(mstid));
   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_MASTER_PORT));
   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);
   mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
   STP_ASSERT(mstiPortPtr);

   /*------------------------------------------------------------------------
    * collect state exit conditions information
    *------------------------------------------------------------------------*/
   allSynced  = mstp_AllSyncedCondition(mstid, lport);
   operEdge   = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                          MSTP_PORT_OPER_EDGE);
   selected   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                          MSTP_MSTI_PORT_SELECTED);
   updtInfo   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                          MSTP_MSTI_PORT_UPDT_INFO);
   sync       = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                          MSTP_MSTI_PORT_SYNC);
   synced     = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                          MSTP_MSTI_PORT_SYNCED);
   learn      = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                          MSTP_MSTI_PORT_LEARN);
   learning   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                          MSTP_MSTI_PORT_LEARNING);
   forward    = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                          MSTP_MSTI_PORT_FORWARD);
   forwarding = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                          MSTP_MSTI_PORT_FORWARDING);
   reRoot     = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                          MSTP_MSTI_PORT_RE_ROOT);
   agree      = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                          MSTP_MSTI_PORT_AGREE);
   agreed     = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                          MSTP_MSTI_PORT_AGREED);
   proposed   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                          MSTP_MSTI_PORT_PROPOSED);
   disputed   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                          MSTP_MSTI_PORT_DISPUTED);
   fdWhile    = mstiPortPtr->fdWhile;
   rrWhile    = mstiPortPtr->rrWhile;

   /*------------------------------------------------------------------------
    * check for condition to transition to the next state
    *------------------------------------------------------------------------*/
   if(selected && !updtInfo)
   {/* 'selected' && !'updtInfo' */

      if(proposed && !agree)
      {/* 'selected' && !'updtInfo' &&
        * 'proposed' && '!agree' */

         /*------------------------------------------------------------------
          * condition for transition to the 'MASTER_PROPOSED' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_MASTER_PROPOSED],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_MASTER_PROPOSED;
         mstp_prtSmMasterProposedAct(mstid, lport);
         res = TRUE;
      }
      else
      if((allSynced && !agree) || (proposed && agree))
      {/* 'selected' && !'updtInfo' &&
        * ('allSynced' && '!agree') || ('proposed' && 'agree') */

         /*------------------------------------------------------------------
          * condition for transition to the 'MASTER_AGREED' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_MASTER_AGREED],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_MASTER_AGREED;
         mstp_prtSmMasterAgreedAct(mstid, lport);
         res = TRUE;
      }
      else
      if((!learning && !forwarding && !synced) ||
         (agreed && !synced) || (operEdge && !synced) || (sync && synced))
      {/* 'selected' && !'updtInfo' &&
        * ('!learning' && '!forwarding' && '!synced') ||
        * ('agreed' && '!synced') || ('operEdge' && '!synced') ||
        * ('sync' && 'synced') */

         /*------------------------------------------------------------------
          * condition for transition to the 'MASTER_SYNCED' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_MASTER_SYNCED],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_MASTER_SYNCED;
         mstp_prtSmMasterSyncedAct(mstid, lport);
         res = TRUE;
      }
      else
      if(reRoot && (rrWhile == 0))
      {/* 'selected' && !'updtInfo' &&
        * 'reRoot' && ('rrWhile' == 0) */

         /*------------------------------------------------------------------
          * condition for transition to the 'MASTER_RETIRED' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_MASTER_RETIRED],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_MASTER_RETIRED;
         mstp_prtSmMasterRetiredAct(mstid, lport);
         res = TRUE;
      }
      else
      if(((sync && !synced) || (reRoot && (rrWhile != 0)) || disputed) &&
         !operEdge && (learn || forward))
      {/* 'selected' && !'updtInfo' &&
        * (('sync' && '!synced') ||
        * ('reRoot' && ('rrWhile' != 0)) || 'disputed') &&
        * '!operEdge' && ('learn' || 'forward') */

         /*------------------------------------------------------------------
          * condition for transition to the 'MASTER_DISCARD' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_MASTER_DISCARD],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_MASTER_DISCARD;
         mstp_prtSmMasterDiscardAct(mstid, lport);
         res = TRUE;
      }
      else
      if(((fdWhile == 0) || allSynced) && !learn)
      {/* 'selected' && !'updtInfo' &&
        * (('fdWhile' == 0) || 'allSynced') && '!learn' */

         /*------------------------------------------------------------------
          * condition for transition to the 'MASTER_LEARN' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_MASTER_LEARN],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_MASTER_LEARN;
         mstp_prtSmMasterLearnAct(mstid, lport);
         res = TRUE;
      }
      else
      if(((fdWhile == 0) || allSynced) && (learn && !forward))
      {/* 'selected' && !'updtInfo' &&
        * (('fdWhile' == 0) || 'allSynced') && ('learn' && '!forward')*/

         /*------------------------------------------------------------------
          * condition for transition to the 'MASTER_FORWARD' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_MASTER_FORWARD],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_MASTER_FORWARD;
         mstp_prtSmMasterForwardAct(mstid, lport);
         res = TRUE;
      }
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmMasterProposedCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'MASTER_PROPOSED'.
 *
 * Params:    mstid -> MST Instance Idetifier (an MSTI only, never the CIST)
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
mstp_prtSmMasterProposedCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   STP_ASSERT(MSTP_VALID_MSTID(mstid));
   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_MASTER_PROPOSED));

   /*------------------------------------------------------------------------
    * transition to the 'MASTER_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PRT,
                     MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_MASTER_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_MASTER_PORT;
   mstp_prtSmMasterPortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmMasterAgreedCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'MASTER_AGREED'.
 *
 * Params:    mstid -> MST Instance Idetifier (an MSTI only, never the CIST)
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
mstp_prtSmMasterAgreedCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   STP_ASSERT(MSTP_VALID_MSTID(mstid));
   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_MASTER_AGREED));

   /*------------------------------------------------------------------------
    * transition to the 'MASTER_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PRT,
                     MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_MASTER_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_MASTER_PORT;
   mstp_prtSmMasterPortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmMasterSyncedCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'MASTER_SYNCED'.
 *
 * Params:    mstid -> MST Instance Idetifier (an MSTI only, never the CIST)
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
mstp_prtSmMasterSyncedCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   STP_ASSERT(MSTP_VALID_MSTID(mstid));
   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_MASTER_SYNCED));

   /*------------------------------------------------------------------------
    * transition to the 'MASTER_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PRT,
                     MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_MASTER_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_MASTER_PORT;
   mstp_prtSmMasterPortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmMasterRetiredCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'MASTER_RETIRED'.
 *
 * Params:    mstid -> MST Instance Idetifier (an MSTI only, never the CIST)
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
mstp_prtSmMasterRetiredCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   STP_ASSERT(MSTP_VALID_MSTID(mstid));
   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_MASTER_RETIRED));

   /*------------------------------------------------------------------------
    * transition to the 'MASTER_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PRT,
                     MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_MASTER_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_MASTER_PORT;
   mstp_prtSmMasterPortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmMasterForwardCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'MASTER_FORWARD'.
 *
 * Params:    mstid -> MST Instance Idetifier (an MSTI only, never the CIST)
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
mstp_prtSmMasterForwardCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = FALSE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   STP_ASSERT(MSTP_VALID_MSTID(mstid));
   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_MASTER_FORWARD));

   /*------------------------------------------------------------------------
    * transition to the 'MASTER_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PRT,
                     MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_MASTER_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_MASTER_PORT;
   mstp_prtSmMasterPortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmMasterLearnCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'MASTER_LEARN'.
 *
 * Params:    mstid -> MST Instance Idetifier (an MSTI only, never the CIST)
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
mstp_prtSmMasterLearnCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   STP_ASSERT(MSTP_VALID_MSTID(mstid));
   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_MASTER_LEARN));

   /*------------------------------------------------------------------------
    * transition to the 'MASTER_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PRT,
                     MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_MASTER_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_MASTER_PORT;
   mstp_prtSmMasterPortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmMasterDiscardCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'MASTER_DISCARD'.
 *
 * Params:    mstid -> MST Instance Idetifier (an MSTI only, never the CIST)
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
mstp_prtSmMasterDiscardCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   STP_ASSERT(MSTP_VALID_MSTID(mstid));
   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_MASTER_DISCARD));

   /*------------------------------------------------------------------------
    * transition to the 'MASTER_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PRT,
                     MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_MASTER_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_MASTER_PORT;
   mstp_prtSmMasterPortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmMasterPortAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'MASTER_PORT' state.
 *            ('role' = 'MasterPort';)
 *
 * Params:    mstid -> MST Instance Identifier (an MSTI only, never the CIST)
 *            lport -> logical port number
 *
 * Returns:   mstp_Bridge
 *
 * Globals:
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_prtSmMasterPortAct(MSTID_t mstid, LPORT_t lport)
{
   MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(MSTP_VALID_MSTID(mstid));
   STP_ASSERT(mstiPortPtr);
   STP_ASSERT(mstiPortPtr->selectedRole == MSTP_PORT_ROLE_MASTER);

   mstiPortPtr->role = mstiPortPtr->selectedRole;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmMasterProposedAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'MASTER_PROPOSED' state.
 *            (setSyncTree(); 'proposed' = FALSE;)
 *
 * Params:    mstid -> MST Instance Identifier (an MSTI only, never the CIST)
 *            lport -> logical port number
 *
 * Returns:   mstp_Bridge
 *
 * Globals:
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_prtSmMasterProposedAct(MSTID_t mstid, LPORT_t lport)
{
   MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(MSTP_VALID_MSTID(mstid));
   STP_ASSERT(mstiPortPtr);

   mstp_setSyncTree(mstid);
   MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_PROPOSED);
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmMasterAgreedAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'MASTER_AGREED' state.
 *            ('proposed' = 'sync' = FALSE;
 *             'agree' = TRUE;)
 *
 * Params:    mstid -> MST Instance Identifier (an MSTI only, never the CIST)
 *            lport -> logical port number
 *
 * Returns:   mstp_Bridge
 *
 * Globals:
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_prtSmMasterAgreedAct(MSTID_t mstid, LPORT_t lport)
{
   MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(MSTP_VALID_MSTID(mstid));
   STP_ASSERT(mstiPortPtr);

   MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_PROPOSED);
   MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SYNC);
   MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_AGREE);
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmMasterSyncedAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'MASTER_SYNCED' state.
 *            ('rrWhile' = 0;
 *             'synced' = TRUE;
 *             'sync' = FALSE;)
 *
 * Params:    mstid -> MST Instance Identifier (an MSTI only, never the CIST)
 *            lport -> logical port number
 *
 * Returns:   mstp_Bridge
 *
 * Globals:
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_prtSmMasterSyncedAct(MSTID_t mstid, LPORT_t lport)
{
   MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(MSTP_VALID_MSTID(mstid));
   STP_ASSERT(mstiPortPtr);

   mstiPortPtr->rrWhile = 0;
   MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SYNCED);
   MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SYNC);
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmMasterRetiredAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'MASTER_RETIRED' state.
 *            ('reRoot' = FALSE;)
 *
 * Params:    mstid -> MST Instance Identifier (an MSTI only, never the CIST)
 *            lport -> logical port number
 *
 * Returns:   mstp_Bridge
 *
 * Globals:
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_prtSmMasterRetiredAct(MSTID_t mstid, LPORT_t lport)
{
   MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(MSTP_VALID_MSTID(mstid));
   STP_ASSERT(mstiPortPtr);

   MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RE_ROOT);
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmMasterForwardAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'MASTER_FORWARD' state.
 *            ('forward' = TRUE; 'fdWhile' = 0;
 *             'agreed = 'sendRSTP';)
 *
 * Params:    mstid -> MST Instance Identifier (an MSTI only, never the CIST)
 *            lport -> logical port number
 *
 * Returns:   mstp_Bridge
 *
 * Globals:
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_prtSmMasterForwardAct(MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);
   MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(MSTP_VALID_MSTID(mstid));
   STP_ASSERT(commPortPtr && mstiPortPtr);

   MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_FORWARD);
   mstiPortPtr->fdWhile = 0;
   if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_SEND_RSTP))
      MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_AGREED);
   else
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_AGREED);

   /*------------------------------------------------------------------------
    * Port State Transitions state machine (per-Tree per-Port)
    *------------------------------------------------------------------------*/
   MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                           "PRT:", "MASTER_FORWARD", "PST:", mstid, lport);
   mstp_pstSm(mstid, lport);
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmMasterLearnAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'MASTER_LEARN' state.
 *            ('learn' = TRUE;
 *             'fdWhile' = 'forwardDelay';)
 *
 * Params:    mstid -> MST Instance Identifier (an MSTI only, never the CIST)
 *            lport -> logical port number
 *
 * Returns:   mstp_Bridge
 *
 * Globals:
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_prtSmMasterLearnAct(MSTID_t mstid, LPORT_t lport)
{
   MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(MSTP_VALID_MSTID(mstid));
   STP_ASSERT(mstiPortPtr);

   MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_LEARN);
   mstiPortPtr->fdWhile = mstp_forwardDelayParameter(lport);
   /*------------------------------------------------------------------
    * kick Port State Transitions state machine (per-Tree per-Port)
    *------------------------------------------------------------------*/
   MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                           "PRT:", "MASTER_LEARN", "PST:", mstid, lport);
   mstp_pstSm(mstid, lport);
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmMasterDiscardAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'MASTER_DISCARD' state.
 *            ('learn' = 'forward' = 'disputed' = FALSE;
 *             'fdWhile' = 'forwardDelay';)
 *
 * Params:    mstid -> MST Instance Identifier (an MSTI only, never the CIST)
 *            lport -> logical port number
 *
 * Returns:   mstp_Bridge
 *
 * Globals:
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_prtSmMasterDiscardAct(MSTID_t mstid, LPORT_t lport)
{
   MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(MSTP_VALID_MSTID(mstid));
   STP_ASSERT(mstiPortPtr);

   MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_LEARN);
   MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_FORWARD);
   MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_DISPUTED);
   mstiPortPtr->fdWhile = mstp_forwardDelayParameter(lport);
   /*------------------------------------------------------------------
    * kick Port State Transitions state machine (per-Tree per-Port)
    *------------------------------------------------------------------*/
   MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                           "PRT:", "MASTER_DISCARD", "PST:", mstid, lport);
   mstp_pstSm(mstid, lport);
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*
 *                                                                           *
 * Root Port State transition and State action routines                      *
 *                                                                           *
 *~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

/**PROC+**********************************************************************
 * Name:      mstp_prtSmRootPortCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'ROOT_PORT'.
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
mstp_prtSmRootPortCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res          = FALSE;
   bool             selected     = FALSE;
   bool             updtInfo     = FALSE;
   bool             sync         = FALSE;
   bool             synced       = FALSE;
   bool             learn        = FALSE;
   bool             forward      = FALSE;
   bool             reRoot       = FALSE;
   bool             reRooted     = FALSE;
   bool             agree        = FALSE;
   bool             agreed       = FALSE;
   bool             proposed     = FALSE;
   bool             allSynced    = TRUE;
   uint8_t            ForceVersion = mstp_Bridge.ForceVersion;
   uint32_t           FwdDelay     = MSTP_CIST_ROOT_TIMES.fwdDelay;
   uint8_t            fdWhile      = 0;
   uint8_t            rbWhile      = 0;
   uint8_t            rrWhile      = 0;
   MSTP_PRT_STATE_t *statePtr     = NULL;

   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_ROOT_PORT));

   /*------------------------------------------------------------------------
    * collect state exit conditions information
    *------------------------------------------------------------------------*/
   allSynced = mstp_AllSyncedCondition(mstid, lport);
   reRooted  = mstp_ReRootedCondition(mstid, lport);
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      selected = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                           MSTP_CIST_PORT_SELECTED);
      updtInfo = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                           MSTP_CIST_PORT_UPDT_INFO);
      sync     = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                           MSTP_CIST_PORT_SYNC);
      synced   = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                           MSTP_CIST_PORT_SYNCED);
      learn    = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                           MSTP_CIST_PORT_LEARN);
      forward  = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                           MSTP_CIST_PORT_FORWARD);
      reRoot   = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                           MSTP_CIST_PORT_RE_ROOT);
      agree    = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                           MSTP_CIST_PORT_AGREE);
      agreed   = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                           MSTP_CIST_PORT_AGREED);
      proposed = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                           MSTP_CIST_PORT_PROPOSED);
      fdWhile  = cistPortPtr->fdWhile;
      rbWhile  = cistPortPtr->rbWhile;
      rrWhile  = cistPortPtr->rrWhile;
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      selected = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                           MSTP_MSTI_PORT_SELECTED);
      updtInfo = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                           MSTP_MSTI_PORT_UPDT_INFO);
      sync     = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                           MSTP_MSTI_PORT_SYNC);
      synced   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                           MSTP_MSTI_PORT_SYNCED);
      learn    = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                           MSTP_MSTI_PORT_LEARN);
      forward  = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                           MSTP_MSTI_PORT_FORWARD);
      reRoot   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                           MSTP_MSTI_PORT_RE_ROOT);
      agree    = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                           MSTP_MSTI_PORT_AGREE);
      agreed   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                           MSTP_MSTI_PORT_AGREED);
      proposed = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                           MSTP_MSTI_PORT_PROPOSED);
      fdWhile  = mstiPortPtr->fdWhile;
      rbWhile  = mstiPortPtr->rbWhile;
      rrWhile  = mstiPortPtr->rrWhile;
   }

   /*------------------------------------------------------------------------
    * check for condition to transition to the next state
    *------------------------------------------------------------------------*/
   if(selected && !updtInfo)
   {/* 'selected' && !'updtInfo' */

      if(proposed && !agree)
      {/* 'selected' && !'updtInfo' &&
        * 'proposed' && '!agree' */

         /*------------------------------------------------------------------
          * condition for transition to the 'ROOT_PROPOSED' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_ROOT_PROPOSED],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_ROOT_PROPOSED;
         mstp_prtSmRootProposedAct(mstid, lport);
         res = TRUE;
      }
      else
      if((allSynced && !agree) || (proposed && agree))
      {/* 'selected' && !'updtInfo' &&
        * ('allSynced' && '!agree') || ('proposed' && 'agree') */

         /*------------------------------------------------------------------
          * condition for transition to the 'ROOT_AGREED' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_ROOT_AGREED],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_ROOT_AGREED;
         mstp_prtSmRootAgreedAct(mstid, lport);
         res = TRUE;
      }
      else
      if((agreed && !synced) || (sync && synced))
      {/* 'selected' && !'updtInfo' &&
        * ('agreed' && '!synced') || ('sync' && 'synced') */

         /*------------------------------------------------------------------
          * condition for transition to the 'ROOT_SYNCED' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_ROOT_SYNCED],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_ROOT_SYNCED;
         mstp_prtSmRootSyncedAct(mstid, lport);
         res = TRUE;
      }
      else
      if(!forward && !reRoot)
      {/* 'selected' && !'updtInfo' &&
        * '!forward' && '!reRoot' */

         /*------------------------------------------------------------------
          * condition for transition to the 'REROOT' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_REROOT],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_REROOT;
         mstp_prtSmReRootAct(mstid, lport);
         res = TRUE;
      }
      else
      if(rrWhile != FwdDelay)
      {/* 'selected' && !'updtInfo' &&
        * 'rrWhile' != 'FwdDelay' */

         /*------------------------------------------------------------------
          * condition for transition (re-enter) to the 'ROOT_PORT' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_ROOT_PORT],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_ROOT_PORT;
         mstp_prtSmRootPortAct(mstid, lport);
         res = TRUE;
      }
      else
      if(reRoot && forward)
      {/* 'selected' && !'updtInfo' &&
        * 'reRoot' && 'forward' */

         /*------------------------------------------------------------------
          * condition for transition to the 'REROOTED' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_REROOTED],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_REROOTED;
         mstp_prtSmReRootedAct(mstid, lport);
         res = TRUE;
      }
      else
      if(((fdWhile == 0) || ((reRooted && (rbWhile == 0)) && (ForceVersion >= 2)))
         && !learn)
      {/* 'selected' && !'updtInfo' &&
        * (('fdWhile' == 0) || ('reRooted' && ('rbWhile' == 0)) &&
        * ('rstpVersion')) && '!learn' */

         /*------------------------------------------------------------------
          * condition for transition to the 'ROOT_LEARN' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_ROOT_LEARN],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_ROOT_LEARN;
         mstp_prtSmRootLearnAct(mstid, lport);
         res = TRUE;
      }
      else
      if(((fdWhile == 0) || ((reRooted && (rbWhile == 0)) && (ForceVersion >= 2)))
         && learn && !forward)
      {/* 'selected' && !'updtInfo' &&
        * (('fdWhile' == 0) || ('reRooted' && ('rbWhile' == 0)) &&
        * ('rstpVersion')) && 'learn' && '!forward' */

         /*------------------------------------------------------------------
          * condition for transition to the 'ROOT_FORWARD' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_ROOT_FORWARD],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_ROOT_FORWARD;
         mstp_prtSmRootForwardAct(mstid, lport);
         res = TRUE;
      }
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmRootProposedCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'ROOT_PROPOSED'.
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
mstp_prtSmRootProposedCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_ROOT_PROPOSED));

   /*------------------------------------------------------------------------
    * transition to the 'ROOT_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PRT,
                     MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_ROOT_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_ROOT_PORT;
   mstp_prtSmRootPortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmRootAgreedCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'ROOT_AGREED'.
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
mstp_prtSmRootAgreedCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_ROOT_AGREED));

   /*------------------------------------------------------------------------
    * transition to the 'ROOT_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PRT,
                     MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_ROOT_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_ROOT_PORT;
   mstp_prtSmRootPortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmRootSyncedCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'ROOT_SYNCED'.
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
mstp_prtSmRootSyncedCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_ROOT_SYNCED));

   /*------------------------------------------------------------------------
    * transition to the 'ROOT_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PRT,
                     MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_ROOT_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_ROOT_PORT;
   mstp_prtSmRootPortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmReRootCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'REROOT'.
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
mstp_prtSmReRootCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_REROOT));

   /*------------------------------------------------------------------------
    * transition to the 'ROOT_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PRT,
                     MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_ROOT_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_ROOT_PORT;
   mstp_prtSmRootPortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmRootForwardCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'ROOT_FORWARD'.
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
mstp_prtSmRootForwardCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_ROOT_FORWARD));

   /*------------------------------------------------------------------------
    * transition to the 'ROOT_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PRT,
                     MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_ROOT_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_ROOT_PORT;
   mstp_prtSmRootPortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmRootLearnCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'ROOT_LEARN'.
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
mstp_prtSmRootLearnCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_ROOT_LEARN));

   /*------------------------------------------------------------------------
    * transition to the 'ROOT_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PRT,
                     MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_ROOT_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_ROOT_PORT;
   mstp_prtSmRootPortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmReRootedCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'REROOTED'.
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
mstp_prtSmReRootedCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_REROOTED));

   /*------------------------------------------------------------------------
    * transition to the 'ROOT_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PRT,
                     MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_ROOT_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_ROOT_PORT;
   mstp_prtSmRootPortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmRootPortAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'ROOT_PORT' state.
 *            ('role' = 'RootPort';
 *             'rrWhile' = 'FwdDelay';)
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
mstp_prtSmRootPortAct(MSTID_t mstid, LPORT_t lport)
{
   STP_ASSERT(MSTP_BEGIN == FALSE);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      STP_ASSERT(cistPortPtr->selectedRole == MSTP_PORT_ROLE_ROOT);
      cistPortPtr->role    = cistPortPtr->selectedRole;
      cistPortPtr->rrWhile = MSTP_CIST_ROOT_TIMES.fwdDelay;
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      STP_ASSERT(mstiPortPtr->selectedRole == MSTP_PORT_ROLE_ROOT);
      mstiPortPtr->role    = mstiPortPtr->selectedRole;
      mstiPortPtr->rrWhile = MSTP_CIST_ROOT_TIMES.fwdDelay;
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmRootProposedAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'ROOT_PROPOSED' state.
 *            (setSyncTree(); 'proposed' = FALSE;)
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
mstp_prtSmRootProposedAct(MSTID_t mstid, LPORT_t lport)
{
   STP_ASSERT(MSTP_BEGIN == FALSE);

   mstp_setSyncTree(mstid);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_PROPOSED);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_PROPOSED);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmRootAgreedAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'ROOT_AGREED' state.
 *            ('proposed' = 'sync' = FALSE;
 *             'agree' = TRUE;
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
mstp_prtSmRootAgreedAct(MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(commPortPtr);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_PROPOSED);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_SYNC);
      MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_AGREE);
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_PROPOSED);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SYNC);
      MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_AGREE);
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO_MSTI);
   }
   /*------------------------------------------------------------------------
    * kick Port Transmit state machine (per-Port)
    *------------------------------------------------------------------------*/
   MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                           "PRT:", "ROOT_AGREED", "PTX:", mstid, lport);
   mstp_ptxSm(lport);
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmRootSyncedAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'ROOT_SYNCED' state.
 *            ('synced' = TRUE;
 *             'sync' = FALSE;)
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
mstp_prtSmRootSyncedAct(MSTID_t mstid, LPORT_t lport)
{
   STP_ASSERT(MSTP_BEGIN == FALSE);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_SYNCED);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_SYNC);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SYNCED);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SYNC);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmReRootAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'REROOT' state.
 *            (setReRootTree();)
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
mstp_prtSmReRootAct(MSTID_t mstid, LPORT_t lport)
{
   STP_ASSERT(MSTP_BEGIN == FALSE);
   mstp_setReRootTree(mstid);
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmRootForwardAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'ROOT_FORWARD' state.
 *            ('fdWhile' = 0;
 *             'forward' = TRUE;)
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
mstp_prtSmRootForwardAct(MSTID_t mstid, LPORT_t lport)
{
   STP_ASSERT(MSTP_BEGIN == FALSE);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      cistPortPtr->fdWhile = 0;
      MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_FORWARD);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      mstiPortPtr->fdWhile = 0;
      MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_FORWARD);
   }
   /*------------------------------------------------------------------------
    * Port State Transitions state machine (per-Tree per-Port)
    *------------------------------------------------------------------------*/
   MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                           "PRT:", "ROOT_FORWARD", "PST:", mstid, lport);
   mstp_pstSm(mstid, lport);
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmRootLearnAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'ROOT_LEARN' state.
 *            ('fdWhile' = 'forwardDelay';
 *             'learn' = TRUE;)
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
mstp_prtSmRootLearnAct(MSTID_t mstid, LPORT_t lport)
{
   STP_ASSERT(MSTP_BEGIN == FALSE);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);

      cistPortPtr->fdWhile = mstp_forwardDelayParameter(lport);
      MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_LEARN);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      mstiPortPtr->fdWhile = mstp_forwardDelayParameter(lport);
      MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_LEARN);
   }
   /*------------------------------------------------------------------
    * kick Port State Transitions state machine (per-Tree per-Port)
    *------------------------------------------------------------------*/
   MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                           "PRT:", "ROOT_LEARN", "PST:", mstid, lport);
   mstp_pstSm(mstid, lport);
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmReRootedAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'REROOTED' state.
 *            ('reRoot' = FALSE;)
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
mstp_prtSmReRootedAct(MSTID_t mstid, LPORT_t lport)
{
   STP_ASSERT(MSTP_BEGIN == FALSE);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_RE_ROOT);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RE_ROOT);
   }
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*
 *                                                                           *
 * Designated Port State transition and State action routines                *
 *                                                                           *
 *~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

/**PROC+**********************************************************************
 * Name:      mstp_prtSmDesignatedPortCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'DESIGNATED_PORT'.
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
mstp_prtSmDesignatedPortCond(MSTID_t mstid, LPORT_t lport)
{
   bool                   res          = FALSE;
   bool                  selected     = FALSE;
   bool                  updtInfo     = FALSE;
   bool                  sync         = FALSE;
   bool                  synced       = FALSE;
   bool                  learn        = FALSE;
   bool                  learning     = FALSE;
   bool                  forward      = FALSE;
   bool                  forwarding   = FALSE;
   bool                  reRoot       = FALSE;
   bool                  agree        = FALSE;
   bool                  agreed       = FALSE;
   bool                  proposing    = FALSE;
   bool                  proposed     = FALSE;
   bool                  disputed     = FALSE;
   bool                  allSynced    = TRUE;
   bool                  operEdge     = FALSE;
   uint8_t                 fdWhile      = 0;
   uint8_t                 rrWhile      = 0;
   MSTP_COMM_PORT_INFO_t *commPortPtr  = NULL;
   MSTP_PRT_STATE_t      *statePtr     = NULL;

   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_DESIGNATED_PORT));
   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   /*------------------------------------------------------------------------
    * collect state exit conditions information
    *------------------------------------------------------------------------*/
   allSynced = mstp_AllSyncedCondition(mstid, lport);
   operEdge = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                        MSTP_PORT_OPER_EDGE);
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      selected   = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_SELECTED);
      updtInfo   = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_UPDT_INFO);
      sync       = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_SYNC);
      synced     = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_SYNCED);
      learn      = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_LEARN);
      learning   = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_LEARNING);
      forward    = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_FORWARD);
      forwarding = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_FORWARDING);
      reRoot     = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_RE_ROOT);
      agree      = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_AGREE);
      agreed     = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_AGREED);
      proposing  = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_PROPOSING);
      proposed   = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_PROPOSED);
      disputed   = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_DISPUTED);
      fdWhile    = cistPortPtr->fdWhile;
      rrWhile    = cistPortPtr->rrWhile;
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      selected   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_SELECTED);
      updtInfo   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_UPDT_INFO);
      sync       = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_SYNC);
      synced     = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_SYNCED);
      learn      = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_LEARN);
      learning   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_LEARNING);
      forward    = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_FORWARD);
      forwarding = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_FORWARDING);
      reRoot     = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_RE_ROOT);
      agree      = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_AGREE);
      agreed     = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_AGREED);
      proposing  = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_PROPOSING);
      proposed   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_PROPOSED);
      disputed   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_DISPUTED);
      fdWhile    = mstiPortPtr->fdWhile;
      rrWhile    = mstiPortPtr->rrWhile;
   }

   /*------------------------------------------------------------------------
    * check for condition to transition to the next state
    *------------------------------------------------------------------------*/
   if(selected && !updtInfo)
   {/* 'selected' && !'updtInfo' */

      if(!forward && !agreed && !proposing && !operEdge)
      {/* 'selected' && !'updtInfo' &&
        * '!forward' && '!agreed' && '!proposing' && '!operEdge' */

         /*------------------------------------------------------------------
          * condition for transition to the 'DESIGNATED_PROPOSE' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_DESIGNATED_PROPOSE],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_DESIGNATED_PROPOSE;
         mstp_prtSmDesignatedProposeAct(mstid, lport);
         res = TRUE;
      }
      else
      if(allSynced && (proposed || !agree))
      {/* 'selected' && !'updtInfo' &&
        * 'allSynced' && ('proposed' || '!agree') */

         /*------------------------------------------------------------------
          * condition for transition to the 'DESIGNATED_AGREED' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_DESIGNATED_AGREED],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_DESIGNATED_AGREED;
         mstp_prtSmDesignatedAgreedAct(mstid, lport);
         res = TRUE;
      }
      else
      if((!learning && !forwarding && !synced) ||
         (agreed && !synced) || (operEdge && !synced) || (sync && synced))
      {/* 'selected' && !'updtInfo' &&
        * (!'learning' && !'forwarding' && !'synced') ||
        * ('agreed' && !'synced') || ('operEdge' && '!synced') ||
        * ('sync' && 'synced') */

         /*------------------------------------------------------------------
          * condition for transition to the 'DESIGNATED_SYNCED' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_DESIGNATED_SYNCED],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_DESIGNATED_SYNCED;
         mstp_prtSmDesignatedSyncedAct(mstid, lport);
         res = TRUE;
      }
      else
      if(reRoot && (rrWhile == 0))
      {/* 'selected' && !'updtInfo' &&
        * 'reRoot' && ('rrWhile' == 0) */

         /*------------------------------------------------------------------
          * condition for transition to the 'DESIGNATED_RETIRED' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_DESIGNATED_RETIRED],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_DESIGNATED_RETIRED;
         mstp_prtSmDesignatedRetiredAct(mstid, lport);
         res = TRUE;
      }
      else
      if(((sync && !synced) || (reRoot && (rrWhile != 0)) || disputed) &&
         !operEdge && (learn || forward))
      {/* 'selected' && !'updtInfo' &&
        * (('sync' && '!synced') || ('reRoot' && ('rrWhile' != 0)) ||
        * 'disputed') && !operEdge && (learn || forward) */

         /*------------------------------------------------------------------
          * condition for transition to the 'DESIGNATED_DISCARD' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_DESIGNATED_DISCARD],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_DESIGNATED_DISCARD;
         mstp_prtSmDesignatedDiscardAct(mstid, lport);
         res = TRUE;
      }
      else
      if(((fdWhile == 0) || agreed || operEdge) && ((rrWhile == 0) || !reRoot)
         && !sync && !learn)
      {/* 'selected' && !'updtInfo' &&
        * (('fdWhile' == 0) || 'agreed' || 'operEdge') &&
        * (('rrWhile' == 0) || '!reRoot') &&
        * '!sync' && '!learn' */

         /*------------------------------------------------------------------
          * condition for transition to the 'DESIGNATED_LEARN' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_DESIGNATED_LEARN],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_DESIGNATED_LEARN;
         mstp_prtSmDesignatedLearnAct(mstid, lport);
         res = TRUE;
      }
      else
      if(((fdWhile == 0) || agreed || operEdge) && ((rrWhile == 0) || !reRoot)
         && !sync && (learn && !forward))
      {/* 'selected' && !'updtInfo' &&
        * (('fdWhile' == 0) || 'agreed' || 'operEdge') &&
        * (('rrWhile' == 0) || '!reRoot') &&
        * '!sync' && ('learn' && '!forward') */

         /*------------------------------------------------------------------
          * condition for transition to the 'DESIGNATED_FORWARD' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_DESIGNATED_FORWARD],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_DESIGNATED_FORWARD;
         mstp_prtSmDesignatedForwardAct(mstid, lport);
         res = TRUE;
      }
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmDesignatedProposeCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'DESIGNATED_PROPOSE'.
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
mstp_prtSmDesignatedProposeCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_DESIGNATED_PROPOSE));

   /*------------------------------------------------------------------------
    * transition to the 'DESIGNATED_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PRT,
                     MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_DESIGNATED_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_DESIGNATED_PORT;
   mstp_prtSmDesignatedPortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmDesignatedAgreedCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'DESIGNATED_AGREED'.
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
mstp_prtSmDesignatedAgreedCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_DESIGNATED_AGREED));

   /*------------------------------------------------------------------------
    * transition to the 'DESIGNATED_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PRT,
                     MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_DESIGNATED_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_DESIGNATED_PORT;
   mstp_prtSmDesignatedPortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmDesignatedSyncedCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'DESIGNATED_SYNCED'.
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
mstp_prtSmDesignatedSyncedCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   /*------------------------------------------------------------------------
    * transition to the 'DESIGNATED_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_DESIGNATED_SYNCED));
   MSTP_SM_ST_PRINTF(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_DESIGNATED_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_DESIGNATED_PORT;
   mstp_prtSmDesignatedPortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmDesignatedRetiredCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'DESIGNATED_RETIRED'.
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
mstp_prtSmDesignatedRetiredCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   /*------------------------------------------------------------------------
    * transition to the 'DESIGNATED_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_DESIGNATED_RETIRED));
   MSTP_SM_ST_PRINTF(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_DESIGNATED_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_DESIGNATED_PORT;
   mstp_prtSmDesignatedPortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmDesignatedForwardCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'DESIGNATED_FORWARD'.
 *
 * Params:    mstid -> MST Instance Idetifier (the CIST or an MSTI)
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
mstp_prtSmDesignatedForwardCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = FALSE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   /*------------------------------------------------------------------------
    * transition to the 'DESIGNATED_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_DESIGNATED_FORWARD));
   MSTP_SM_ST_PRINTF(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_DESIGNATED_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_DESIGNATED_PORT;
   mstp_prtSmDesignatedPortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmDesignatedLearnCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'DESIGNATED_LEARN'.
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
mstp_prtSmDesignatedLearnCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_DESIGNATED_LEARN));

   /*------------------------------------------------------------------------
    * transition to the 'DESIGNATED_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PRT,
                     MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_DESIGNATED_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_DESIGNATED_PORT;
   mstp_prtSmDesignatedPortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmDesignatedDiscardCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'DESIGNATED_DISCARD'.
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
mstp_prtSmDesignatedDiscardCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_DESIGNATED_DISCARD));

   /*------------------------------------------------------------------------
    * transition to the 'DESIGNATED_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF(MSTP_PRT,
                     MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_DESIGNATED_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_DESIGNATED_PORT;
   mstp_prtSmDesignatedPortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmDesignatedPortAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'DESIGNATED_PORT' state.
 *            ('role' = 'DesignatedPort';)
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
mstp_prtSmDesignatedPortAct(MSTID_t mstid, LPORT_t lport)
{
   STP_ASSERT(MSTP_BEGIN == FALSE);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      STP_ASSERT(cistPortPtr->selectedRole == MSTP_PORT_ROLE_DESIGNATED);
      cistPortPtr->role = cistPortPtr->selectedRole;
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      STP_ASSERT(mstiPortPtr->selectedRole == MSTP_PORT_ROLE_DESIGNATED);
      mstiPortPtr->role = mstiPortPtr->selectedRole;
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmDesignatedProposeAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'DESIGNATED_PROPOSE' state.
 *            ('proposing' = TRUE;
 *             if(cist) {'edgeDelayWhile' = 'EdgeDelay';}
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
mstp_prtSmDesignatedProposeAct(MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(commPortPtr);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);
      bool                  operPointToPointMAC = FALSE;

      STP_ASSERT(cistPortPtr);
      MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_PROPOSING);

      operPointToPointMAC = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                            MSTP_PORT_OPER_POINT_TO_POINT_MAC);
      commPortPtr->edgeDelayWhile = operPointToPointMAC ?
                                    mstp_Bridge.MigrateTime :
                                    mstp_Bridge.CistInfo.rootTimes.maxAge;
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_PROPOSING);
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO_MSTI);
   }
   /*------------------------------------------------------------------
    * kick Port Transmit state machine (per-Port)
    *------------------------------------------------------------------*/
   MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                           "PRT:", "DESIGNATED_PROPOSE", "PTX:", mstid, lport);
   mstp_ptxSm(lport);
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmDesignatedAgreedAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'DESIGNATED_AGREED' state.
 *            ('proposed' = 'sync' = FALSE;
 *             'agree' = TRUE;
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
mstp_prtSmDesignatedAgreedAct(MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(commPortPtr);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_PROPOSED);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_SYNC);
      MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_AGREE);
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_PROPOSED);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SYNC);
      MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_AGREE);
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO_MSTI);
   }
   /*------------------------------------------------------------------
    * kick Port Transmit state machine (per-Port)
    *------------------------------------------------------------------*/
   MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                           "PRT:", "DESIGNATED_AGREED", "PTX:", mstid, lport);
   mstp_ptxSm(lport);
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmDesignatedSyncedAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'DESIGNATED_SYNCED' state.
 *            ('rrWhile' = 0; 'synced' = TRUE;
 *             'sync' = FALSE;)
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
mstp_prtSmDesignatedSyncedAct(MSTID_t mstid, LPORT_t lport)
{
   STP_ASSERT(MSTP_BEGIN == FALSE);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      cistPortPtr->rrWhile = 0;
      MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_SYNCED);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_SYNC);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      mstiPortPtr->rrWhile = 0;
      MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SYNCED);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SYNC);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmDesignatedRetiredAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'DESIGNATED_RETIRED' state.
 *            ('reRoot' = FALSE;)
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
mstp_prtSmDesignatedRetiredAct(MSTID_t mstid, LPORT_t lport)
{
   STP_ASSERT(MSTP_BEGIN == FALSE);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_RE_ROOT);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RE_ROOT);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmDesignatedForwardAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'DESIGNATED_FORWARD' state.
 *            ('forward' = TRUE;
 *             'fdWhile' = 0;
 *             'agreed' = 'sendRSTP';)
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
mstp_prtSmDesignatedForwardAct(MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(commPortPtr);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_FORWARD);
      cistPortPtr->fdWhile = 0;
      if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_SEND_RSTP))
         MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_AGREED);
      else
         MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_AGREED);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_FORWARD);
      mstiPortPtr->fdWhile = 0;
      if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_SEND_RSTP))
         MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_AGREED);
      else
         MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_AGREED);
   }
   /*------------------------------------------------------------------------
    * Port State Transitions state machine (per-Tree per-Port)
    *------------------------------------------------------------------------*/
   MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                           "PRT:", "DESIGNATED_FORWARD", "PST:", mstid, lport);
   mstp_pstSm(mstid, lport);
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmDesignatedLearnAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'DESIGNATED_LEARN' state.
 *            ('learn' = TRUE;
 *             'fdWhile' = 'forwardDelay';)
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
mstp_prtSmDesignatedLearnAct(MSTID_t mstid, LPORT_t lport)
{
   STP_ASSERT(MSTP_BEGIN == FALSE);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_LEARN);
      cistPortPtr->fdWhile = mstp_forwardDelayParameter(lport);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_LEARN);
      mstiPortPtr->fdWhile = mstp_forwardDelayParameter(lport);
   }
   /*------------------------------------------------------------------
    * kick Port State Transitions state machine (per-Tree per-Port)
    *------------------------------------------------------------------*/
   MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                           "PRT:", "DESIGNATED_LEARN", "PST:", mstid, lport);
   mstp_pstSm(mstid, lport);
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmDesignatedDiscardAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'DESIGNATED_DISCARD' state.
 *            ('learn' = 'forward' = 'disputed' = FALSE;
 *             'fdWhile' = 'forwardDelay';)
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
mstp_prtSmDesignatedDiscardAct(MSTID_t mstid, LPORT_t lport)
{
   STP_ASSERT(MSTP_BEGIN == FALSE);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_LEARN);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_FORWARD);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_DISPUTED);
      cistPortPtr->fdWhile = mstp_forwardDelayParameter(lport);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_LEARN);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_FORWARD);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_DISPUTED);
      mstiPortPtr->fdWhile = mstp_forwardDelayParameter(lport);
   }
   /*------------------------------------------------------------------
    * kick Port State Transitions state machine (per-Tree per-Port)
    *------------------------------------------------------------------*/
   MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                           "PRT:", "DESIGNATED_DISCARD", "PST:", mstid, lport);
   mstp_pstSm(mstid, lport);
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*
 *                                                                           *
 * Alternate and Backup Port State transition and State action routines      *
 *                                                                           *
 *~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

/**PROC+**********************************************************************
 * Name:      mstp_prtSmAlternatePortCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'ALTERNATE_PORT'.
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
mstp_prtSmAlternatePortCond(MSTID_t mstid, LPORT_t lport)
{
   bool                   res          = FALSE;
   bool                  selected     = FALSE;
   bool                  updtInfo     = FALSE;
   bool                  sync         = FALSE;
   bool                  synced       = FALSE;
   bool                  reRoot       = FALSE;
   bool                  agree        = FALSE;
   bool                  proposed     = FALSE;
   bool                  allSynced    = TRUE;
   uint32_t                forwardDelay = 0;
   uint16_t                HelloTime    = 0;
   uint8_t                 fdWhile      = 0;
   uint8_t                 rbWhile      = 0;
   MSTP_PORT_ROLE_t       role         = MSTP_PORT_ROLE_DISABLED;
   MSTP_PRT_STATE_t      *statePtr     = NULL;
   MSTP_COMM_PORT_INFO_t *commPortPtr  = NULL;

   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_ALTERNATE_PORT));
   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   /*------------------------------------------------------------------------
    * collect state exit conditions information
    *------------------------------------------------------------------------*/
   allSynced = mstp_AllSyncedCondition(mstid, lport);
   HelloTime = commPortPtr->HelloTime;
   forwardDelay = mstp_forwardDelayParameter(lport);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      selected   = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_SELECTED);
      updtInfo   = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_UPDT_INFO);
      sync       = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_SYNC);
      synced     = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_SYNCED);
      reRoot     = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_RE_ROOT);
      agree      = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_AGREE);
      proposed   = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_PROPOSED);
      fdWhile    = cistPortPtr->fdWhile;
      rbWhile    = cistPortPtr->rbWhile;
      role       = cistPortPtr->role;
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      selected   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_SELECTED);
      updtInfo   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_UPDT_INFO);
      sync       = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_SYNC);
      synced     = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_SYNCED);
      reRoot     = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_RE_ROOT);
      agree      = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_AGREE);
      proposed   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_PROPOSED);
      fdWhile    = mstiPortPtr->fdWhile;
      rbWhile    = mstiPortPtr->rbWhile;
      role       = mstiPortPtr->role;
   }

   /*------------------------------------------------------------------------
    * check for condition to transition to the next state
    *------------------------------------------------------------------------*/
   if(selected && !updtInfo)
   {/* 'selected' && !'updtInfo' */

      if(proposed && !agree)
      {/* 'selected' && !'updtInfo' &&
        * 'proposed' && '!agree' */

         /*------------------------------------------------------------------
          * condition for transition to the 'ALTERNATE_PROPOSED' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_ALTERNATE_PROPOSED],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_ALTERNATE_PROPOSED;
         mstp_prtSmAlternateProposedAct(mstid, lport);
         res = TRUE;
      }
      else
      if((allSynced && !agree) || (proposed && agree))
      {/* 'selected' && !'updtInfo' &&
        * ('allSynced' && '!agree') || ('proposed' || 'agree') */

         /*------------------------------------------------------------------
          * condition for transition to the 'ALTERNATE_AGREED' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_ALTERNATE_AGREED],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_ALTERNATE_AGREED;
         mstp_prtSmAlternateAgreedAct(mstid, lport);
         res = TRUE;
      }
      else
      if((fdWhile != forwardDelay) || sync || reRoot || !synced)
      {/* 'selected' && !'updtInfo' &&
        * ('fdWhile' != 'forwardDelay') || 'sync' || 'reRoot' || '!synced' */

         /*------------------------------------------------------------------
          * condition for transition (re-enter) to the 'ALTERNATE_PORT' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_ALTERNATE_PORT],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_ALTERNATE_PORT;
         mstp_prtSmAlternatePortAct(mstid, lport);
         res = TRUE;
      }
      else if((rbWhile != 2*HelloTime) && (role == MSTP_PORT_ROLE_BACKUP))
      {/* 'selected' && !'updtInfo' &&
        * ('rbWhile' != 2*'HelloTime') && ('role' == 'BackupPort') */
         /*------------------------------------------------------------------
          * condition for transition to the 'BACKUP_PORT' state
          *------------------------------------------------------------------*/
         MSTP_SM_ST_PRINTF(MSTP_PRT,
                           MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                           "PRT:", MSTP_PRT_STATE_s[*statePtr],
                           MSTP_PRT_STATE_s[MSTP_PRT_STATE_BACKUP_PORT],
                           mstid, lport);
         *statePtr = MSTP_PRT_STATE_BACKUP_PORT;
         mstp_prtSmBackupPortAct(mstid, lport);
         res = TRUE;
      }
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmAlternateProposedCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'ALTERNATE_PROPOSED'.
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
mstp_prtSmAlternateProposedCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   /*------------------------------------------------------------------------
    * transition to the 'ALTERNATE_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_ALTERNATE_PROPOSED));
   MSTP_SM_ST_PRINTF(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_ALTERNATE_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_ALTERNATE_PORT;
   mstp_prtSmAlternatePortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmAlternateAgreedCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'ALTERNATE_AGREED'.
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
mstp_prtSmAlternateAgreedCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   /*------------------------------------------------------------------------
    * transition to the 'ALTERNATE_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_ALTERNATE_AGREED));
   MSTP_SM_ST_PRINTF(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_ALTERNATE_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_ALTERNATE_PORT;
   mstp_prtSmAlternatePortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmBlockPortCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'BLOCK_PORT'.
 *
 * Params:    mstid -> MST Instance Idetifier (the CIST or an MSTI)
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
mstp_prtSmBlockPortCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res        = FALSE;
   bool             selected   = FALSE;
   bool             updtInfo   = FALSE;
   bool             learning   = FALSE;
   bool             forwarding = FALSE;
   MSTP_PRT_STATE_t *statePtr   = NULL;

   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_BLOCK_PORT));

   /*------------------------------------------------------------------------
    * collect state exit conditions information
    *------------------------------------------------------------------------*/
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      selected   = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_SELECTED);
      updtInfo   = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_UPDT_INFO);
      learning   = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_LEARNING);
      forwarding = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_FORWARDING);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      selected   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_SELECTED);
      updtInfo   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_UPDT_INFO);
      learning   = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_LEARNING);
      forwarding = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_FORWARDING);
   }

   /*------------------------------------------------------------------------
    * check for condition to transition to the 'ALTERNATE_PORT' state
    *------------------------------------------------------------------------*/
   if(selected && !updtInfo && !learning && !forwarding)
   {/* 'selected' && '!updtInfo' &&
     * '!learning' && '!forwarding' */
      MSTP_SM_ST_PRINTF(MSTP_PRT,
                        MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                        "PRT:", MSTP_PRT_STATE_s[*statePtr],
                        MSTP_PRT_STATE_s[MSTP_PRT_STATE_ALTERNATE_PORT],
                        mstid, lport);
      *statePtr = MSTP_PRT_STATE_ALTERNATE_PORT;
      mstp_prtSmAlternatePortAct(mstid, lport);
      res = FALSE;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmBackupPortCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'BACKUP_PORT'.
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
mstp_prtSmBackupPortCond(MSTID_t mstid, LPORT_t lport)
{
   bool              res      = TRUE;
   MSTP_PRT_STATE_t *statePtr = NULL;

   /*------------------------------------------------------------------------
    * transition to the 'ALTERNATE_PORT' state unconditionally
    *------------------------------------------------------------------------*/
   statePtr = mstp_utilPrtStatePtr(mstid, lport);
   STP_ASSERT(statePtr && (*statePtr == MSTP_PRT_STATE_BACKUP_PORT));
   MSTP_SM_ST_PRINTF(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT,
                     "PRT:", MSTP_PRT_STATE_s[*statePtr],
                     MSTP_PRT_STATE_s[MSTP_PRT_STATE_ALTERNATE_PORT],
                     mstid, lport);
   *statePtr = MSTP_PRT_STATE_ALTERNATE_PORT;
   mstp_prtSmAlternatePortAct(mstid, lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmAlternatePortAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'ALTERNATE_PORT' state.
 *            ('fdWhile' = 'forwardDelay';
 *             'synced' = TRUE;
 *             'rrWhile' = 0;
 *             'sync' = 'reRoot' = FALSE;)
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
mstp_prtSmAlternatePortAct(MSTID_t mstid, LPORT_t lport)
{
   STP_ASSERT(MSTP_BEGIN == FALSE);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      cistPortPtr->fdWhile = mstp_forwardDelayParameter(lport);
      MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_SYNCED);
      cistPortPtr->rrWhile = 0;
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_SYNC);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_RE_ROOT);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      mstiPortPtr->fdWhile = mstp_forwardDelayParameter(lport);
      MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SYNCED);
      mstiPortPtr->rrWhile = 0;
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SYNC);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RE_ROOT);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmAlternateProposedAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'ALTERNATE_PROPOSED' state.
 *            (setSyncTree();
 *             'proposed' = FALSE;)
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
mstp_prtSmAlternateProposedAct(MSTID_t mstid, LPORT_t lport)
{
   STP_ASSERT(MSTP_BEGIN == FALSE);

   mstp_setSyncTree(mstid);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_PROPOSED);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_PROPOSED);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmAlternateAgreedAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'ALTERNATE_AGREED' state.
 *            ('proposed' = FALSE;
 *             'agree' = TRUE;
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
mstp_prtSmAlternateAgreedAct(MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(commPortPtr);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_PROPOSED);
      MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_AGREE);
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_PROPOSED);
      MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_AGREE);
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO_MSTI);
   }
   /*------------------------------------------------------------------------
    * kick Port Transmit state machine (per-Port)
    *------------------------------------------------------------------------*/
   MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                           "PRT:", "ALTERNATE_AGREED", "PTX:", mstid, lport);
   mstp_ptxSm(lport);
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmBlockPortAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'BLOCK_PORT' state.
 *            ('role' = 'selectedRole'; 'learn' = 'forward' = FALSE;)
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
mstp_prtSmBlockPortAct(MSTID_t mstid, LPORT_t lport)
{
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);

      cistPortPtr->role = cistPortPtr->selectedRole;
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_LEARN);
      MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_FORWARD);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      mstiPortPtr->role = mstiPortPtr->selectedRole;
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_LEARN);
      MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_FORWARD);
   }

   if(MSTP_BEGIN == FALSE)
   {
      /*------------------------------------------------------------------
       * kick Port State Transitions state machine (per-Tree per-Port)
       *------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                              "PRT:", "BLOCK_PORT", "PST:", mstid, lport);
      mstp_pstSm(mstid, lport);

      /*------------------------------------------------------------------
       * kick Topology Change state machine (per-Tree per-Port)
       *------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF1(MSTP_PRT, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                              "PRT:", "BLOCK_PORT", "TCM:", mstid, lport);
      mstp_tcmSm(mstid, lport);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_prtSmBackupPortAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'BACKUP_PORT' state.
 *            ('rbWhile' = 2*'HelloTime';)
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
mstp_prtSmBackupPortAct(MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(commPortPtr);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      cistPortPtr->rbWhile = 2*(commPortPtr->HelloTime);
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      mstiPortPtr->rbWhile = 2*(commPortPtr->HelloTime);
   }
}
