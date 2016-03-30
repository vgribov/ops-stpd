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
 *    File               : mstpd_ppm_sm.c
 *    Description        : MSTP Protocol Port Protocol Migartion State Machine
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

VLOG_DEFINE_THIS_MODULE(mstpd_ppm_sm);
/*---------------------------------------------------------------------------
 * Local functions prototypes (forward declarations)
 *---------------------------------------------------------------------------*/
static void mstp_ppmSmGeneralCond(LPORT_t lport);
static bool mstp_ppmSmCheckingRstpCond(LPORT_t lport);
static bool mstp_ppmSmSelectingStpCond(LPORT_t lport);
static bool mstp_ppmSmSensingCond(LPORT_t lport);

static void mstp_ppmSmCheckingRstpAct(LPORT_t lport);
static void mstp_ppmSmSelectingStpAct(LPORT_t lport);
static void mstp_ppmSmSensingAct(LPORT_t lport);

/** ======================================================================= **
 *                                                                           *
 *     Global Functions (externed)                                           *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_ppmSm
 *
 * Purpose:   The entry point to the Port Protocol Migration (PPM)
 *            state machine.
 *            The PPM SM updates 'sendRSTP' to tell the Port Transmit (PTX)
 *            state machine which BPDU types to transmit, to support
 *            interoperability with the previous versions of the Spanning
 *            Tree Algorithm and Protocol.
 *            (802.1Q-REV/D5.0 13.29; 802.1D-2004 17.24)
 *
 * Params:    lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:
 *
 **PROC-**********************************************************************/
void
mstp_ppmSm(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = NULL;
   bool                  next        = FALSE;/* This variable is used to
                                               * indicate that the state
                                               * change processing is still
                                               * required */
   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);
   VLOG_DBG("MSTP PPM SM for lport : %d", lport);

   mstp_ppmSmGeneralCond(lport);
   VLOG_DBG("MSTP PPM SM for lport : %d", commPortPtr->ppmState);
   do
   {
      switch(commPortPtr->ppmState)
      {
         VLOG_DBG("MSTP PPM State for lport: %d, %d",lport,commPortPtr->ppmState);
         case MSTP_PPM_STATE_CHECKING_RSTP:
            next = mstp_ppmSmCheckingRstpCond(lport);
            VLOG_DBG("MSTP PPM Checking RSTP State next: %d, %d",next,commPortPtr->ppmState);
            break;
         case MSTP_PPM_STATE_SELECTING_STP:
            next = mstp_ppmSmSelectingStpCond(lport);
            VLOG_DBG("MSTP PPM Selecting STP State next: %d, %d",next,commPortPtr->ppmState);
            break;
         case MSTP_PPM_STATE_SENSING:
            next = mstp_ppmSmSensingCond(lport);
            VLOG_DBG("MSTP PPM Sensing State next: %d, %d",next,commPortPtr->ppmState);
            break;
         default:
            STP_ASSERT(0);
            break;
      }
   }
   while (next == TRUE);

   /*------------------------------------------------------------------------
    * when exit the state for PPM SM must be 'CHECKING_RSTP' ||
    * 'SELECTING_STP' || 'SENSING'
    *------------------------------------------------------------------------*/
   STP_ASSERT(commPortPtr->ppmState == MSTP_PPM_STATE_CHECKING_RSTP ||
          commPortPtr->ppmState == MSTP_PPM_STATE_SELECTING_STP ||
          commPortPtr->ppmState == MSTP_PPM_STATE_SENSING);

}

/** ======================================================================= **
 *                                                                           *
 *     Static (local to this file) Functions                                 *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_ppmSmGeneralCond
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
mstp_ppmSmGeneralCond(LPORT_t lport)
{

   /*------------------------------------------------------------------------
    * check for conditions to transition to the 'CHECKING_RSTP' state
    *------------------------------------------------------------------------*/
   if(MSTP_BEGIN == TRUE)
   {
      MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

      STP_ASSERT(commPortPtr);

      if(commPortPtr->ppmState != MSTP_PPM_STATE_CHECKING_RSTP)
      {
         MSTP_SM_ST_PRINTF1(MSTP_PPM,
                            MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                            "PPM:",MSTP_PPM_STATE_s[commPortPtr->ppmState],
                            MSTP_PPM_STATE_s[MSTP_PPM_STATE_CHECKING_RSTP],
                            lport);
         commPortPtr->ppmState = MSTP_PPM_STATE_CHECKING_RSTP;
         mstp_ppmSmCheckingRstpAct(lport);
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_ppmSmCheckingRstpCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'CHECKING_RSTP'
 *
 * Params:    lport -> logical port number
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
mstp_ppmSmCheckingRstpCond(LPORT_t lport)
{
   bool                   res         = FALSE;
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr &&
          (commPortPtr->ppmState == MSTP_PPM_STATE_CHECKING_RSTP));

   /*------------------------------------------------------------------------
    * check for conditions to transition to the next state
    *------------------------------------------------------------------------*/
   if(commPortPtr->mdelayWhile == 0)
   {/* 'mdelayWhile' == 0 */

      /*---------------------------------------------------------------------
       * condition for transition to the 'SENSING' state
       *---------------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF1(MSTP_PPM, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                         "PPM:",MSTP_PPM_STATE_s[commPortPtr->ppmState],
                         MSTP_PPM_STATE_s[MSTP_PPM_STATE_SENSING],lport);
      commPortPtr->ppmState = MSTP_PPM_STATE_SENSING;
      mstp_ppmSmSensingAct(lport);
      res = TRUE;
   }
   else if((commPortPtr->mdelayWhile != mstp_Bridge.MigrateTime) &&
           !MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                      MSTP_PORT_PORT_ENABLED))
   {/* 'mdelayWhile' != 'MigrateTime' && !'portEnabled' */

      /*---------------------------------------------------------------------
       * condition for transition (re-enter) to the 'CHECKING_RSTP' state
       *---------------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF1(MSTP_PPM, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                         "PPM:",MSTP_PPM_STATE_s[commPortPtr->ppmState],
                         MSTP_PPM_STATE_s[MSTP_PPM_STATE_CHECKING_RSTP],lport);
      commPortPtr->ppmState = MSTP_PPM_STATE_CHECKING_RSTP;
      mstp_ppmSmCheckingRstpAct(lport);
      res = TRUE;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_ppmSmSelectingStpCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'SELECTING_STP'
 *
 * Params:    lport -> logical port number
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
mstp_ppmSmSelectingStpCond(LPORT_t lport)
{
   bool                   res         = FALSE;
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr &&
          (commPortPtr->ppmState == MSTP_PPM_STATE_SELECTING_STP));

   /*------------------------------------------------------------------------
    * check for conditions to transition to the next state
    *------------------------------------------------------------------------*/
   if((commPortPtr->mdelayWhile == 0) ||
      !MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_PORT_ENABLED)
      ||
      MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_MCHECK))
   {/* 'mdelayWhile' == 0 || !'portEnabled' || 'mcheck' */

      /*---------------------------------------------------------------------
       * condition for transition to the 'SENSING' state
       *---------------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF1(MSTP_PPM, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                         "PPM:",MSTP_PPM_STATE_s[commPortPtr->ppmState],
                         MSTP_PPM_STATE_s[MSTP_PPM_STATE_SENSING], lport);
      commPortPtr->ppmState = MSTP_PPM_STATE_SENSING;
      mstp_ppmSmSensingAct(lport);
      res = TRUE;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_ppmSmSensingCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'SENSING'
 *
 * Params:    lport -> logical port number
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
mstp_ppmSmSensingCond(LPORT_t lport)
{
   bool                   res         = FALSE;
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr &&
          (commPortPtr->ppmState == MSTP_PPM_STATE_SENSING));

   /*------------------------------------------------------------------------
    * check for conditions to transition to the next state
    *------------------------------------------------------------------------*/
   if(!MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_PORT_ENABLED)
      ||
      MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_MCHECK) ||
      ((mstp_Bridge.ForceVersion >= MSTP_PROTOCOL_VERSION_ID_RST) &&
       !MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_SEND_RSTP) &&
       MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_RCVD_RSTP)))
   {/* !'portEnabled' || 'mcheck' ||
     * ((rstpVersion) && !'sendRSTP' && 'rcvdRSTP') */

      /*---------------------------------------------------------------------
       * condition for transition to the 'CHECKING_RSTP' state
       *---------------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF1(MSTP_PPM, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                         "PPM:",MSTP_PPM_STATE_s[commPortPtr->ppmState],
                         MSTP_PPM_STATE_s[MSTP_PPM_STATE_CHECKING_RSTP], lport);
      commPortPtr->ppmState = MSTP_PPM_STATE_CHECKING_RSTP;
      mstp_ppmSmCheckingRstpAct(lport);
      res = TRUE;
   }
   else if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_SEND_RSTP)
           &&
           MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_RCVD_STP))
   {/* 'sendRSTP' && 'rcvdSTP' */

      /*---------------------------------------------------------------------
       * condition for transition to the 'SELECTING_STP' state
       *---------------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF1(MSTP_PPM, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                         "PPM:",MSTP_PPM_STATE_s[commPortPtr->ppmState],
                         MSTP_PPM_STATE_s[MSTP_PPM_STATE_SELECTING_STP], lport);
      commPortPtr->ppmState = MSTP_PPM_STATE_SELECTING_STP;
      mstp_ppmSmSelectingStpAct(lport);
      res = TRUE;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_ppmSmCheckingRstpAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'CHECKING_RSTP' state.
 *            ('mcheck' = FALSE;
 *             'sendRSTP' = (rstpVersion);
 *             'mdelayWhile' = 'MigrateTime';)
 *            NOTE: (rstpVersion) above means that it is TRUE if Force Protocol
 *                  Version is greater or equal to 2.
 *
 * Params:    lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_ppmSmCheckingRstpAct(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr);

   MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_MCHECK);
   if(mstp_Bridge.ForceVersion >= MSTP_PROTOCOL_VERSION_ID_RST)
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_SEND_RSTP);
   else
      MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_SEND_RSTP);
   commPortPtr->mdelayWhile = mstp_Bridge.MigrateTime;
}

/**PROC+**********************************************************************
 * Name:      mstp_ppmSmSelectingStpAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'SELECTING_STP' state.
 *            ('sendRSTP' = FALSE;
 *             'mdelayWhile' = 'MigrateTime';)
 *
 * Params:    lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_ppmSmSelectingStpAct(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr);

   MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_SEND_RSTP);
   commPortPtr->mdelayWhile = mstp_Bridge.MigrateTime;
}

/**PROC+**********************************************************************
 * Name:      mstp_ppmSmSensingAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'SENSING' state.
 *            ('rcvdRSTP' = 'rcvdSTP' = FALSE;)
 *
 * Params:    lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_ppmSmSensingAct(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr);

   MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_RCVD_RSTP);
   MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_RCVD_STP);
}
