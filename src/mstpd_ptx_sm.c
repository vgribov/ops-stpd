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
 *    File               : mstpd_ptx_sm.c
 *    Description        : MSTP Protocol Port Transmit State Machine
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

VLOG_DEFINE_THIS_MODULE(mstpd_ptx_sm);

/*---------------------------------------------------------------------------
 * Local functions prototypes (forward declarations)
 *---------------------------------------------------------------------------*/
static void mstp_ptxSmGeneralCond(LPORT_t lport);

static bool mstp_ptxSmTransmitInitCond(LPORT_t lport);
static bool mstp_ptxSmTransmitPeriodicCond(LPORT_t lport);
static bool mstp_ptxSmIdleCond(LPORT_t lport);
static bool mstp_ptxSmTransmitConfigCond(LPORT_t lport);
static bool mstp_ptxSmTransmitTcnCond(LPORT_t lport);
static bool mstp_ptxSmTransmitRstpCond(LPORT_t lport);

static void mstp_ptxSmTransmitInitAct(LPORT_t lport);
static void mstp_ptxSmTransmitPeriodicAct(LPORT_t lport);
static void mstp_ptxSmTransmitIdleAct(LPORT_t lport);
static void mstp_ptxSmTransmitConfigAct(LPORT_t lport);
static void mstp_ptxSmTransmitTcnAct(LPORT_t lport);
static void mstp_ptxSmTransmitRstpAct(LPORT_t lport);

/** ======================================================================= **
 *                                                                           *
 *     Global Functions (externed)                                           *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_ptxSm
 *
 * Purpose:   The entry point to the Port Transmit (PTX) state machine.
 *            This state machine is responsible for transmitting BPDUs.
 *            (802.1Q-REV/D5.0 13.31)
 *
 * Params:    lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:
 *
 **PROC-**********************************************************************/
void
mstp_ptxSm(LPORT_t lport)
{
   bool                  next = FALSE;/* This variable is used to indicate
                                        * that the state change processing
                                        * is still required */
   MSTP_COMM_PORT_INFO_t *commPortPtr = NULL;

   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   /*------------------------------------------------------------------------
    * check if this is an attempt to transmit BPDU on a filtered port,
    * if so then skip state machine.
    * NOTE: 'MSTP_BEGIN == TRUE' indicates state machine initialization,
    *       in which case we do not perform any special checks and follow
    *       normal procedure.
    *------------------------------------------------------------------------*/
   if((MSTP_BEGIN == FALSE) && MSTP_COMM_IS_BPDU_FILTER(lport))
         return;

   if(mstp_Bridge.preventTx == TRUE)
   {
      MSTP_SM_ST_PRINTF1(MSTP_PTX,
                         MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                         "PTX:", "TX", "LOCKED", lport);
      return;
   }

   mstp_ptxSmGeneralCond(lport);
   do
   {
      switch(commPortPtr->ptxState)
      {
         case MSTP_PTX_STATE_TRANSMIT_INIT:
            next = mstp_ptxSmTransmitInitCond(lport);
            break;
         case MSTP_PTX_STATE_TRANSMIT_PERIODIC:
            next = mstp_ptxSmTransmitPeriodicCond(lport);
            break;
         case MSTP_PTX_STATE_IDLE:
            next = mstp_ptxSmIdleCond(lport);
            break;
         case MSTP_PTX_STATE_TRANSMIT_CONFIG:
            next = mstp_ptxSmTransmitConfigCond(lport);
            break;
         case MSTP_PTX_STATE_TRANSMIT_TCN:
            next = mstp_ptxSmTransmitTcnCond(lport);
            break;
         case MSTP_PTX_STATE_TRANSMIT_RSTP:
            next = mstp_ptxSmTransmitRstpCond(lport);
            break;
         default:
            STP_ASSERT(0);
            break;
      }
   }
   while (next == TRUE);

   /*------------------------------------------------------------------------
    * when exit the state for PTX SM must be 'IDLE'
    *------------------------------------------------------------------------*/
   STP_ASSERT(commPortPtr->ptxState == MSTP_PTX_STATE_IDLE);

}

/** ======================================================================= **
 *                                                                           *
 *     Static (local to this file) Functions                                 *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_ptxSmGeneralCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *
 * Params:    port -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_ptxSmGeneralCond(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr);

   /*------------------------------------------------------------------------
    * check for conditions to transition to the 'TRANSMIT_INIT' state
    *------------------------------------------------------------------------*/
   if((MSTP_BEGIN == TRUE) ||
      !MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_PORT_ENABLED))
   {
      if(commPortPtr->ptxState != MSTP_PTX_STATE_TRANSMIT_INIT)
      {
         MSTP_SM_ST_PRINTF1(MSTP_PTX, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                            "PTX:",MSTP_PTX_STATE_s[commPortPtr->ptxState],
                            MSTP_PTX_STATE_s[MSTP_PTX_STATE_TRANSMIT_INIT],
                            lport);
         commPortPtr->ptxState = MSTP_PTX_STATE_TRANSMIT_INIT;
         mstp_ptxSmTransmitInitAct(lport);
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_ptxSmTransmitInitCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'TRANSMIT_INIT'.
 *
 * Params:    lport -> logical port number
 *
 * Returns:   FALSE, indicating that no immediate check for the exit conditions
 *            from the new state is required.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_ptxSmTransmitInitCond(LPORT_t lport)
{
   bool                   res         = FALSE;
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr);
   STP_ASSERT(commPortPtr->ptxState == MSTP_PTX_STATE_TRANSMIT_INIT);

   /*------------------------------------------------------------------------
    * transition to the 'IDLE' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF1(MSTP_PTX, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                      "PTX:",MSTP_PTX_STATE_s[commPortPtr->ptxState],
                      MSTP_PTX_STATE_s[MSTP_PTX_STATE_IDLE], lport);
   commPortPtr->ptxState = MSTP_PTX_STATE_IDLE;
   mstp_ptxSmTransmitIdleAct(lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_ptxSmTransmitPeriodicCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'TRANSMIT_PERIODIC'.
 *
 * Params:    lport -> logical port number
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
mstp_ptxSmTransmitPeriodicCond(LPORT_t lport)
{
   bool                   res         = TRUE;
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr);
   STP_ASSERT(commPortPtr->ptxState == MSTP_PTX_STATE_TRANSMIT_PERIODIC);

   /*------------------------------------------------------------------------
    * transition to the 'IDLE' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF1(MSTP_PTX, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                      "PTX:", MSTP_PTX_STATE_s[commPortPtr->ptxState],
                      MSTP_PTX_STATE_s[MSTP_PTX_STATE_IDLE], lport);
   commPortPtr->ptxState = MSTP_PTX_STATE_IDLE;
   mstp_ptxSmTransmitIdleAct(lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_ptxSmIdleCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'IDLE'.
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
mstp_ptxSmIdleCond(LPORT_t lport)
{
   bool                   res         = FALSE;
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr);
   STP_ASSERT(commPortPtr->ptxState == MSTP_PTX_STATE_IDLE);

   /*------------------------------------------------------------------------
    * check for conditions to transition to the next state
    *------------------------------------------------------------------------*/
   if(!mstp_allTransmitReadyCondition(lport))
      return FALSE;

   if(commPortPtr->helloWhen == 0)
   {/* 'helloWhen' == 0 */
      /*---------------------------------------------------------------------
       * condition for transition to the 'TRANSMIT_PERIODIC' state
       *---------------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF1(MSTP_PTX, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                         "PTX:", MSTP_PTX_STATE_s[commPortPtr->ptxState],
                         MSTP_PTX_STATE_s[MSTP_PTX_STATE_TRANSMIT_PERIODIC],
                         lport);
      commPortPtr->ptxState = MSTP_PTX_STATE_TRANSMIT_PERIODIC;
      mstp_ptxSmTransmitPeriodicAct(lport);
      res = TRUE;
   }
   else if(commPortPtr->txCount < mstp_Bridge.TxHoldCount)
   {/* 'helloWhen' != 0 && ('txCount' < 'TxHoldCount') */
      MSTP_CIST_PORT_INFO_t *cistPortPtr        = MSTP_CIST_PORT_PTR(lport);
      bool                  cistRootPort       = FALSE;
      bool                  cistDesignatedPort = FALSE;
      bool                  mstiMasterPort     = FALSE;
      bool                  newInfo            = FALSE;
      bool                  newInfoMsti        = FALSE;
      bool                  sendRSTP           = FALSE;
      MSTID_t                mstid;

      STP_ASSERT(cistPortPtr);

      /*------------------------------------------------------------------
       * collect state exit conditions information.
       * NOTE: 'cistRootPort' is TRUE if the CIST role for the given Port
       *        is 'RootPort' (802.1Q-REV/D5.0 13.25.4)
       *       'cistDesignatedPort' is TRUE if the CIST role for the given
       *        Port is 'DesignatedPort' (802.1Q-REV/D5.0 13.25.5)
       *       'mstiMasterPort is TRUE if the role for any MSTI for the
       *        given Port is 'MasterPort' (802.1Q-REV/D5.0 13.25.10)
       *------------------------------------------------------------------*/
      cistRootPort       = (cistPortPtr->role == MSTP_PORT_ROLE_ROOT);
      cistDesignatedPort = (cistPortPtr->role == MSTP_PORT_ROLE_DESIGNATED);
      for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_MSTID_MAX; mstid++)
      {
         if(MSTP_MSTI_VALID(mstid))
         {
            MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid,
                                                                    lport);
            STP_ASSERT(mstiPortPtr);
            if(mstiPortPtr->role == MSTP_PORT_ROLE_MASTER)
            {
               mstiMasterPort = TRUE;
               break;
            }
         }
      }

      sendRSTP    = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                              MSTP_PORT_SEND_RSTP);
      newInfo     = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                              MSTP_PORT_NEW_INFO);
      newInfoMsti = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                              MSTP_PORT_NEW_INFO_MSTI);

      /*---------------------------------------------------------------------
       * check for conditions to transition to the next state
       *---------------------------------------------------------------------*/
      if(!sendRSTP)
      {/* '!sendRSTP' */
         if(newInfo)
         {/* 'newInfo' */
            if(cistDesignatedPort)
            {/* ('!sendRSTP' && 'newInfo' && cistDesignatedPort &&
              *  ('txCount' < 'TxHoldCount') && ('helloWhen' != 0)) */
               /*---------------------------------------------------------
                * condition for transition to the 'TRANSMIT_CONFIG' state
                *---------------------------------------------------------*/
               MSTP_SM_ST_PRINTF1(MSTP_PTX,
                                  MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                                  "PTX:",MSTP_PTX_STATE_s[commPortPtr->ptxState],
                                  MSTP_PTX_STATE_s[MSTP_PTX_STATE_TRANSMIT_CONFIG],
                                  lport);
               commPortPtr->ptxState = MSTP_PTX_STATE_TRANSMIT_CONFIG;
               mstp_ptxSmTransmitConfigAct(lport);
               res = TRUE;
            }
            else if(cistRootPort)
            {/* ('!sendRSTP' && 'newInfo' && cistRootPort &&
              *  ('txCount' < 'TxHoldCount') && ('helloWhen' != 0)) */
               /*---------------------------------------------------------
                * condition for transition to the 'TRANSMIT_TCN' state
                *---------------------------------------------------------*/
               MSTP_SM_ST_PRINTF1(MSTP_PTX,
                                  MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                                  "PTX:",MSTP_PTX_STATE_s[commPortPtr->ptxState],
                                  MSTP_PTX_STATE_s[MSTP_PTX_STATE_TRANSMIT_TCN],
                                  lport);
               commPortPtr->ptxState = MSTP_PTX_STATE_TRANSMIT_TCN;
               mstp_ptxSmTransmitTcnAct(lport);
               res = TRUE;
            }
         }
      }
      else
      {/* 'sendRSTP' */
         if(newInfo || (newInfoMsti && !mstiMasterPort))
         {/* ('sendRSTP' &&
           *  ('newInfo' || ('newInfoMsti' && '!mstiMasterPort')) &&
           *  ('txCount' < 'TxHoldCount') && ('helloWhen' !=0)) */
            /*------------------------------------------------------------
             * condition for transition to the 'TRANSMIT_RSTP' state
             *------------------------------------------------------------*/
            MSTP_SM_ST_PRINTF1(MSTP_PTX,
                               MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                               "PTX:",MSTP_PTX_STATE_s[commPortPtr->ptxState],
                               MSTP_PTX_STATE_s[MSTP_PTX_STATE_TRANSMIT_RSTP],
                               lport);
            commPortPtr->ptxState = MSTP_PTX_STATE_TRANSMIT_RSTP;
            mstp_ptxSmTransmitRstpAct(lport);
            res = TRUE;
         }
      }
   } /* 'helloWhen' != 0 && ('txCount' < 'TxHoldCount') */
   else
   {
      /*------------------------------------------------------------
       * no conditions to change the state
       *------------------------------------------------------------*/
      MSTP_SM_ST_PRINTF1(MSTP_PTX,
                         MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                         "PTX:",MSTP_PTX_STATE_s[commPortPtr->ptxState],
                         MSTP_PTX_STATE_s[commPortPtr->ptxState],
                         lport);
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_ptxSmTransmitConfigCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'TRANSMIT_CONFIG'.
 *
 * Params:    lport -> logical port number
 *
 * Returns:   FALSE, indicating that no immediate check for the exit conditions
 *            from the new state is required.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_ptxSmTransmitConfigCond(LPORT_t lport)
{
   bool                   res         = FALSE;
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr);
   STP_ASSERT(commPortPtr->ptxState == MSTP_PTX_STATE_TRANSMIT_CONFIG);

   /*------------------------------------------------------------------------
    * transition to the 'IDLE' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF1(MSTP_PTX, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                      "PTX:",MSTP_PTX_STATE_s[commPortPtr->ptxState],
                      MSTP_PTX_STATE_s[MSTP_PTX_STATE_IDLE], lport);
   commPortPtr->ptxState = MSTP_PTX_STATE_IDLE;
   mstp_ptxSmTransmitIdleAct(lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_ptxSmTransmitTcnCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'TRANSMIT_TCN'.
 *
 * Params:    lport -> logical port number
 *
 * Returns:   FALSE, indicating that no immediate check for the exit conditions
 *            from the new state is required.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_ptxSmTransmitTcnCond(LPORT_t lport)
{
   bool                   res         = FALSE;
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr);
   STP_ASSERT(commPortPtr->ptxState == MSTP_PTX_STATE_TRANSMIT_TCN);

   /*------------------------------------------------------------------------
    * transition to the 'IDLE' state unconditionally
    *------------------------------------------------------------------------*/
   MSTP_SM_ST_PRINTF1(MSTP_PTX, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                      "PTX:",MSTP_PTX_STATE_s[commPortPtr->ptxState],
                      MSTP_PTX_STATE_s[MSTP_PTX_STATE_IDLE], lport);
   commPortPtr->ptxState = MSTP_PTX_STATE_IDLE;
   mstp_ptxSmTransmitIdleAct(lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_ptxSmTransmitRstpCond
 *
 * Purpose:   Check for the conditions to transition to the next state.
 *            The current state is 'TRANSMIT_RSTP'.
 *
 * Params:    lport -> logical port number
 *
 * Returns:   FALSE, indicating that no immediate check for the exit conditions
 *            from the new state is required.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_ptxSmTransmitRstpCond(LPORT_t lport)
{
   bool                   res         = FALSE;
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr);

   /*------------------------------------------------------------------------
    * transition to the 'IDLE' state unconditionally
    *------------------------------------------------------------------------*/
   STP_ASSERT(commPortPtr->ptxState == MSTP_PTX_STATE_TRANSMIT_RSTP);
   MSTP_SM_ST_PRINTF1(MSTP_PTX, MSTP_PER_PORT_SM_STATE_TRANSITION_FMT,
                      "PTX:", MSTP_PTX_STATE_s[commPortPtr->ptxState],
                      MSTP_PTX_STATE_s[MSTP_PTX_STATE_IDLE], lport);
   commPortPtr->ptxState = MSTP_PTX_STATE_IDLE;
   mstp_ptxSmTransmitIdleAct(lport);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_ptxSmTransmitInitAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'TRANSMIT_INIT' state.
 *            ('newInfo' = 'newInfoMsti' = TRUE;
 *             'txCount' = 0;)
 *
 * Params:    lport -> logical port number
 *
 * Returns:
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_ptxSmTransmitInitAct(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(commPortPtr);
   MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO);
   MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO_MSTI);
   commPortPtr->txCount = 0;
}

/**PROC+**********************************************************************
 * Name:      mstp_ptxSmTransmitPeriodicAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'TRANSMIT_PERIODIC' state.
 *            ('newInfo' = 'newInfo' ||
 *             ('cistDesignatedPort' || ('cistRootPort' && ('tcWhile' !=0)));
 *
 *            ('newInfoMsti' = 'newInfoMsti' ||
 *             'mstiDesignatedOrTCpropagatingRootPort';)
 *
 * Params:    lport -> logical port number
 *
 * Returns:
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_ptxSmTransmitPeriodicAct(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr        = MSTP_COMM_PORT_PTR(lport);
   MSTP_CIST_PORT_INFO_t *cistPortPtr        = MSTP_CIST_PORT_PTR(lport);
   MSTP_MSTI_PORT_INFO_t *mstiPortPtr        = NULL;
   bool                  cistRootPort       = FALSE;
   bool                  cistDesignatedPort = FALSE;
   bool                  mstiDesignatedOrTCpropagatingRootPort = FALSE;
   bool                  newInfo            = FALSE;
   bool                  newInfoMsti        = FALSE;
   MSTID_t                mstid;

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(commPortPtr);
   STP_ASSERT(cistPortPtr);

   /* 'cistRootPort' is TRUE if the CIST role for the given Port is
    * 'RootPort' (802.1Q-REV/D5.0 13.25.4)*/
   cistRootPort       = (cistPortPtr->role == MSTP_PORT_ROLE_ROOT);

   /* 'cistDesignatedPort' is TRUE if the CIST role for the given Port
    * is 'DesignatedPort' (802.1Q-REV/D5.0 13.25.5) */
   cistDesignatedPort = (cistPortPtr->role == MSTP_PORT_ROLE_DESIGNATED);

   /* 'mstiDesignatedOrTCpropagatingRootPort' is TRUE if the role for
    * any MSTI for the given Port is either:
    *    a) 'DesignatedPort'; or
    *    b) 'RootPort', and the instance for the given MSTI and Port of
    *       the 'tcWhile' timer is not zero.
    *  (802.1Q-REV/D5.0 13.25.9) */
   for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_MSTID_MAX; mstid++)
   {
      if(MSTP_MSTI_VALID(mstid))
      {
         mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

         STP_ASSERT(mstiPortPtr);
         if((mstiPortPtr->role == MSTP_PORT_ROLE_DESIGNATED) ||
            ((mstiPortPtr->role == MSTP_PORT_ROLE_ROOT) &&
             (mstiPortPtr->tcWhile != 0)))
         {
            mstiDesignatedOrTCpropagatingRootPort = TRUE;
            break;
         }
      }
   }

   /*------------------------------------------------------------------------
    * 'newInfo' = 'newInfo' ||
    *  ('cistDesignatedPort' || ('cistRootPort' && ('tcWhile' !=0)));
    *------------------------------------------------------------------------*/
   newInfo = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,MSTP_PORT_NEW_INFO);
   if(!newInfo &&
      (cistDesignatedPort || (cistRootPort && (cistPortPtr->tcWhile !=0))))
   {
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO);
   }

   /*------------------------------------------------------------------------
    * 'newInfoMsti' = 'newInfoMsti' || 'mstiDesignatedOrTCpropagatingRootPort'
    *------------------------------------------------------------------------*/
   newInfoMsti = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                           MSTP_PORT_NEW_INFO_MSTI);
   if(!newInfoMsti && mstiDesignatedOrTCpropagatingRootPort)
   {
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO_MSTI);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_ptxSmTransmitConfigAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'TRANSMIT_CONFIG' state.
 *            ('newInfo' = FALSE;
 *             txConfig();
 *             'txCount' +=1;
 *             'tcAck' = FALSE;)
 *
 * Params:    lport -> logical port number
 *
 * Returns:
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_ptxSmTransmitConfigAct(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(commPortPtr);

   MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO);
   MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO_MSTI);
   mstp_txConfig(lport);
   commPortPtr->txCount +=1;
   MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_TC_ACK);
}

/**PROC+**********************************************************************
 * Name:      mstp_ptxSmTransmitTcnAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'TRANSMIT_TCN' state.
 *            ('newInfo' = FALSE;
 *             txTcn();
 *             'txCount' +=1;)
 *
 * Params:    lport -> logical port number
 *
 * Returns:
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_ptxSmTransmitTcnAct(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(commPortPtr);

   MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO);
   MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO_MSTI);
   mstp_txTcn(lport);
   commPortPtr->txCount +=1;
}

/**PROC+**********************************************************************
 * Name:      mstp_ptxSmTransmitRstpAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'TRANSMIT_RSTP' state.
 *            ('newInfo' = 'newInfoMsti' = FALSE;
 *             txMstp(); '
 *             txCount' +=1;
 *             'tcAck' = FALSE;)
 *
 * Params:    lport -> logical port number
 *
 * Returns:
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_ptxSmTransmitRstpAct(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

   STP_ASSERT(MSTP_BEGIN == FALSE);
   STP_ASSERT(commPortPtr);

   MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO);
   MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_NEW_INFO_MSTI);
   mstp_txMstp(lport);
   commPortPtr->txCount +=1;
   MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_TC_ACK);
}

/**PROC+**********************************************************************
 * Name:      mstp_ptxSmTransmitIdleAct
 *
 * Purpose:   Execute actions that are necessary when entering the
 *            'IDLE' state.
 *            ('helloWhen = HelloTime')
 *
 * Params:    lport -> logical port number
 *
 * Returns:
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_ptxSmTransmitIdleAct(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);
   MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

   STP_ASSERT(commPortPtr);
   STP_ASSERT(cistPortPtr);

   STP_ASSERT(cistPortPtr->portTimes.helloTime >= MSTP_HELLO_MIN_SEC &&
          cistPortPtr->portTimes.helloTime <= MSTP_HELLO_MAX_SEC);
   commPortPtr->helloWhen = cistPortPtr->portTimes.helloTime;
}
