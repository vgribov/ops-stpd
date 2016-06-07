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
 *    File               : mstpd_init.c
 *    Description        : MSTP Protocol Initialization Related Functions
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
#include "mstp_ovsdb_if.h"

VLOG_DEFINE_THIS_MODULE(mstpd_init);
uint8_t Stp_version = 3;
uint8_t Spanning=FALSE;
/** ======================================================================= **
 *                                                                           *
 *     Global Variable Declarations                                          *
 *                                                                           *
 ** ======================================================================= **/
#ifdef MSTP_DEBUG
/*---------------------------------------------------------------------------
 * buffer used for debuging messages passed to the 'debug' task
 *---------------------------------------------------------------------------*/
char mstp_debugBuf[MSTP_DEBUG_BUF_LEN];
#endif /* MSTP_DEBUG */
/*---------------------------------------------------------------------------
 * MSTP Control Block.
 *---------------------------------------------------------------------------*/
MSTP_CB_t mstp_CB;

/*---------------------------------------------------------------------------
 * MST Bridge Operation Information.
 *---------------------------------------------------------------------------*/
MSTP_BRIDGE_INFO_t mstp_Bridge;

/*---------------------------------------------------------------------------
 * VLAN IDs to MST Instance mapping Table.
 *---------------------------------------------------------------------------*/
VID_MAP mstp_MstiVidTable[MSTP_INSTANCES_MAX + 1];

/*---------------------------------------------------------------------------
 * VLAN group number to MST Instance Identifier mapping Table.
 * Used to communicate to IDL that treats a VLAN group as an ordinal
 * number of the slot in VLAN groups table.
 *---------------------------------------------------------------------------*/
MSTID_t mstp_vlanGroupNumToMstIdTable[MSTP_INSTANCES_MAX + 1];

/*---------------------------------------------------------------------------
 * MST Configuration Identifier Digest Signature Key (16 bytes mandatory
 * value as defined in 802.1Q-REV/D5.0 13.7). Used to generate the
 * Configuration Digest - a 16 octet signature of type HMAC-MD5 created
 * from the MST Configuration Table.
 *---------------------------------------------------------------------------*/
const uint8_t mstp_DigestSignatureKey[MSTP_DIGEST_KEY_LEN] =
{
   0x13, 0xAC, 0x06, 0xA6, 0x2E, 0x47, 0xFD, 0x51,
   0xF9, 0x5D, 0x2B, 0xA2, 0x43, 0xCD, 0x03, 0x46
};

/*---------------------------------------------------------------------------
 * Global throttle structure control blocks
 *---------------------------------------------------------------------------*/
struct_handle_t   gMstpStructMem[MSTP_MAX_LOG_THROTTLE_CLIENT];
hash_handle_t     gMstpThrottleHashTbl[MSTP_MAX_LOG_THROTTLE_CLIENT];
throttle_handle_t gMstpInfoThrottle[MSTP_MAX_LOG_THROTTLE_CLIENT];

/*---------------------------------------------------------------------------
 * Local functions prototypes (forward declarations)
 *---------------------------------------------------------------------------*/
static void mstp_clearBridgeGlobalData(void);
static void mstp_initBridgeCistData(bool init);
static void mstp_initBridgeMstiData(int mstid,bool init);
static void mstp_initBridgeTreesData(bool init);
static void mstp_initBridgeGlobalData(bool init);
static void mstp_initControlData(void);

/** ======================================================================= **
 *                                                                           *
 *     Global Functions (externed)                                           *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstpInitialInit
 *
 * Purpose:   MSTP initial initialization
 *
 * Returns:   none
 *
 * Params:    none
 *
 **PROC-**********************************************************************/
void
mstpInitialInit(void)
{
   /* -----------------------------------------------------------------------
    * Sanity check: 64 instances is the theoretical maximum allowed by
    *               MSTP design
    * -----------------------------------------------------------------------*/
   STP_ASSERT(MSTP_INSTANCES_MAX <= 64);

   /* -----------------------------------------------------------------------
    * Initialize MSTP Control Block Data:
    * - initialize MSTP Control Block data held in 'mstp_CB'
    * - create MSTP Control Task
    * - connect to other manager tasks that MSTP is going to communicate to
    * -----------------------------------------------------------------------*/
   mstp_initControlData();

}

/**PROC+**********************************************************************
 * Name:      mstp_initMstiVlanTables
 *
 * Purpose:   Map all VLANs to the CIST in 'mstp_MstiVidTable' and initialize
 *            (zero) 'mstp_MstIdToVlanGroupNumTable', which is used for mapping
 *            MST Instances to the VLAN group numbers maintained in the switchd
 *            code space.
 *            Called when MSTP administrative status become 'enabled'.
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   mstp_MstiVidTable, mstp_MstIdToVlanGroupNumTable
 *
 **PROC-**********************************************************************/
void
mstp_initMstiVlanTables(void)
{

   /*------------------------------------------------------------------------
    * Build initial value for the 'digest' component of the Bridge's MST
    * Configuration Identifier ('digest' reflects the VLAN IDs to MSTIs
    * mapping on the Bridge)
    *------------------------------------------------------------------------*/
   mstp_buildMstConfigurationDigest(mstp_Bridge.MstConfigId.digest);
   /*------------------------------------------------------------------------
    * Initialize (zero) 'mstp_vlanGroupNumToMstIdTable' to indicate there are
    * no VLAN groups yet configured (a VLAN group will be created at the time
    * of an MSTI creation. Number of VLAN groups should be equal to the number
    * of configured MSTIs).
    *------------------------------------------------------------------------*/
   memset(mstp_vlanGroupNumToMstIdTable, 0,
          sizeof(mstp_vlanGroupNumToMstIdTable));
   /*Setting maxVlanGroups to MSTP Instances MAX*/
   mstp_Bridge.maxVlanGroups = MSTP_INSTANCES_MAX;
}

/**PROC+**********************************************************************
 * Name:      mstp_initStateMachines
 *
 * Purpose:   Bring MSTP State Machines to the initial states
 *            Called when MSTP administrative status is set 'enabled' or
 *            when dynamic re-configuration change occured that require
 *            MSTP to be re-initialized
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   mstp_CB, mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
void
mstp_initStateMachines(void)
{
   MSTID_t                mstid;
   LPORT_t                lport;
   MSTP_COMM_PORT_INFO_t *commPortPtr;

   MSTP_MISC_PRINTF("!!!SMs initialization %s", "start");

   /*------------------------------------------------------------------------
    * set all state machines to initial state
    * NOTE: A value of TRUE causes all CIST and MSTI state machines, including
    *       per Port state machines, to transit to their initial state
    *------------------------------------------------------------------------*/
   MSTP_BEGIN = TRUE;

   /*------------------------------------------------------------------------
    * First, initialize PIM SMs as they assign initial value to 'infoIs'
    * variable that is being used later during initialization of the PRS SMs
    * to set appropriate value to the 'selectedRole'.
    *------------------------------------------------------------------------*/
   VLOG_DBG("%s : MSTP PIM SM initialized", __FUNCTION__);
   for(lport = 1 ; lport <= MAX_LPORTS ; lport++)
   {
      commPortPtr = MSTP_COMM_PORT_PTR(lport);
      if(commPortPtr)
      {
         /*------------------------------------------------------------------
          * per-Port per-Tree (the CIST or an MSTI) SMs
          *------------------------------------------------------------------*/
         mstp_pimSm(NULL, MSTP_CISTID, lport);
         for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_MSTID_MAX; mstid++)
         {
            if(MSTP_MSTI_VALID(mstid))
            {
               mstp_pimSm(NULL, mstid, lport);
            }
         }
      }
   }

   /*------------------------------------------------------------------------
    * Second, initialize PRS SMs as they assign initial value to 'selectedRole'
    * variable that is being used later during initialization of the PRT SMs
    * to set appropriate value to the Port's 'role' variable.
    *------------------------------------------------------------------------*/
   VLOG_DBG("%s : MSTP PRS SM initialized", __FUNCTION__);
   mstp_prsSm(MSTP_CISTID);
   for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_MSTID_MAX; mstid++)
   {
      if(MSTP_MSTI_VALID(mstid))
      {
         mstp_prsSm(mstid);
      }
   }

   /*------------------------------------------------------------------------
    * Initialize other per-Port per-Bridge and per-Port per-Tree SMs
    *------------------------------------------------------------------------*/
   VLOG_DBG("%s : MSTP PPM SM initializing", __FUNCTION__);
   for(lport = 1 ; lport <= MAX_LPORTS ; lport++)
   {
      commPortPtr = MSTP_COMM_PORT_PTR(lport);
      if(commPortPtr)
      {
         /*------------------------------------------------------------------
          * per-Port per-Bridge SMs
          *------------------------------------------------------------------*/
         VLOG_DBG("%s : MSTP PPM SM initialized", __FUNCTION__);
         mstp_ppmSm(lport);
         VLOG_DBG("%s : MSTP BDM SM initialized", __FUNCTION__);
         mstp_bdmSm(lport);
         VLOG_DBG("%s : MSTP PRX SM initialized", __FUNCTION__);
         mstp_prxSm(NULL, lport);
         VLOG_DBG("%s : MSTP PTX SM initialized", __FUNCTION__);
         mstp_ptxSm(lport);
         VLOG_DBG("%s : MSTP PTI SM initialized", __FUNCTION__);
         mstp_ptiSm(lport);

         /*------------------------------------------------------------------
          * per-Port per-Tree (the CIST or an MSTI) SMs
          *------------------------------------------------------------------*/
         VLOG_DBG("%s : MSTP PRT SM initialized", __FUNCTION__);
         mstp_prtSm(MSTP_CISTID, lport);
         VLOG_DBG("%s : MSTP PST SM initialized", __FUNCTION__);
         mstp_pstSm(MSTP_CISTID, lport);
         VLOG_DBG("%s : MSTP TCM SM initialized", __FUNCTION__);
         mstp_tcmSm(MSTP_CISTID, lport);

         for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_MSTID_MAX; mstid++)
         {
            if(MSTP_MSTI_VALID(mstid))
            {
               mstp_prtSm(mstid, lport);
               mstp_pstSm(mstid, lport);
               mstp_tcmSm(mstid, lport);
            }
         }
      }
   }

   /*------------------------------------------------------------------------
    * SMs initialization is done
    * NOTE: A value of FALSE allows all state machines to perform transitions
    *       out of their initial state, in accordance with the relevant state
    *       machine definitions.
    *------------------------------------------------------------------------*/
   MSTP_BEGIN = FALSE;

   MSTP_MISC_PRINTF("!!!SMs initialization %s", "end");
}

/**PROC+**********************************************************************
 * Name:      mstp_initProtocolData
 *
 * Purpose:   Initialize MSTP internal data with the data read from
 *            configuration.
 *            Called when MSTP administrative status is set to 'enabled'
 *            or when significant dynamic reconfiguration changes were made
 *            while protocol was running, so MSTP in-memory data structures
 *            need to be re-initialized from config.
 *
 * Params:    init -> boolean that indicates whether MSTP protocol
 *                    initialization or dynamic reconfiguration
 *                    change takes the place.
 *
 * Returns:   none
 *
 * Globals:   mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
void
mstp_initProtocolData(bool init)
{
   STP_ASSERT(MSTP_ENABLED);

   /*------------------------------------------------------------------------
    * initialize global Per-Bridge Variables and State Machine Performance
    * Parameters used by all MSTP trees (the CIST and the MSTIs) from config.
    *------------------------------------------------------------------------*/
   mstp_initBridgeGlobalData(init);

   /*------------------------------------------------------------------------
    * initialize the CIST and the MSTIs specific data from config.
    *------------------------------------------------------------------------*/
   mstp_initBridgeTreesData(init);
}

/**PROC+**********************************************************************
 * Name:      mstp_initMstiPortData
 *
 * Purpose:   Allocate and initialize MSTI port in-memory data structure
 *
 * Params:    mstid -> MST instance identifier
 *            lport -> logical port number
 *            init  -> boolean that indicates whether MSTP protocol
 *                     initialization or dynamic reconfiguration
 *                     change takes the place.
 *
 * Returns:   pointer to the allocated memory space
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
MSTP_MSTI_PORT_INFO_t *
mstp_initMstiPortData(MSTID_t mstid, LPORT_t lport, bool init)
{
   MSTP_MSTI_PORT_INFO_t     *mstiPortPtr;

   STP_ASSERT(IS_VALID_LPORT(lport));
   STP_ASSERT(MSTP_VALID_MSTID(mstid));
   STP_ASSERT(MSTP_MSTI_INFO(mstid));

   /*------------------------------------------------------------------------
    * to facilitate references
    *------------------------------------------------------------------------*/
   mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
   STP_ASSERT(mstiPortPtr);

   /*------------------------------------------------------------------------
    * State Machine Timers (802.1Q-REV/D5.0 13.21), they will be dynamically
    * set to the appropriate values during the run of the SMs.
    *------------------------------------------------------------------------*/
   mstiPortPtr->fdWhile = 0;       /* d) */
   mstiPortPtr->rrWhile = 0;       /* e) */
   mstiPortPtr->rbWhile = 0;       /* f) */
   mstiPortPtr->tcWhile = 0;       /* g) */
   mstiPortPtr->rcvdInfoWhile = 0; /* h) */

   /*------------------------------------------------------------------------
    * Initialize other Per-Port Variables (802.1Q-REV/D5.0 13.24)
    * NOTE: every MSTP State Machine (SM) has an 'initial' state that will
    *       be reached at the time of SM initialization. In that 'initial'
    *       state the variables that SM is responsible for are being
    *       initialized to the appropriate initial values.
    *------------------------------------------------------------------------*/
   mstiPortPtr->infoIs = MSTP_INFO_IS_UNKNOWN;                        /*  x) */
   mstiPortPtr->rcvdInfo = MSTP_RCVD_INFO_UNKNOWN;                    /* ac) */
   mstiPortPtr->role = MSTP_PORT_ROLE_UNKNOWN;                        /* as) */
   mstiPortPtr->selectedRole = MSTP_PORT_ROLE_UNKNOWN;                /* at) */
   mstiPortPtr->designatedPriority = MSTP_MSTI_BRIDGE_PRIORITY(mstid);/* al) */
   mstiPortPtr->designatedPriority.dsnPortID = mstiPortPtr->portId;
   memset((char*)&mstiPortPtr->designatedTimes, 0,
          sizeof(mstiPortPtr->designatedTimes));                      /* am) */
   memset((char*)&mstiPortPtr->msgPriority, 0,
          sizeof(mstiPortPtr->msgPriority));                          /* an) */
   memset((char*)&mstiPortPtr->msgTimes, 0,
          sizeof(mstiPortPtr->msgTimes));                             /* ao) */
   mstiPortPtr->portPriority = MSTP_MSTI_BRIDGE_PRIORITY(mstid);      /* aq) */
   mstiPortPtr->portPriority.dsnPortID = mstiPortPtr->portId;
   memset((char*)&mstiPortPtr->portTimes, 0,
          sizeof(mstiPortPtr->portTimes));                            /* ar) */


    /*------------------------------------------------------------------------
    * Initializing Port Uptime
    *------------------------------------------------------------------------*/
   mstiPortPtr->mstiPort_uptime = time(NULL);

   /*------------------------------------------------------------------------
    * Per-Port State Machines states (802.1Q-REV/D5.0 13.19)
    * NOTE: We do not set here any initial state to the SMs as they will do
    *       it themselves at the time of the SM initialization.
    *------------------------------------------------------------------------*/
   mstiPortPtr->pimState = MSTP_PIM_STATE_UNKNOWN;
   mstiPortPtr->prtState = MSTP_PRT_STATE_UNKNOWN;
   mstiPortPtr->pstState = MSTP_PST_STATE_UNKNOWN;
   mstiPortPtr->tcmState = MSTP_TCM_STATE_UNKNOWN;

   if(init)
   {/* Protocol initialization */
      /*---------------------------------------------------------------------
       * Clear statistics MIB support (RFC1493 MIB)
       *---------------------------------------------------------------------*/
      mstiPortPtr->forwardTransitions = 0;

      /*---------------------------------------------------------------------
       * Clear counters used for debugging/troubleshooting purposes
       *---------------------------------------------------------------------*/
      memset(&mstiPortPtr->dbgCnts, 0, sizeof(mstiPortPtr->dbgCnts));

      /* Clear the history table */
      memset(&mstiPortPtr->portHistory, 0, sizeof(mstiPortPtr->portHistory));
   }

   return mstiPortPtr;
}

/**PROC+**********************************************************************
 * Name:      mstp_initCistPortData
 *
 * Purpose:   Allocate and initialize CIST port in-memory data structures
 *
 * Params:    lport -> logical port number
 *            init  -> boolean that indicates whether MSTP protocol
 *                     initialization or dynamic reconfiguration
 *                     change takes the place.
 *
 * Returns:   pointer to the allocated memory space
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
MSTP_CIST_PORT_INFO_t *
mstp_initCistPortData(LPORT_t lport, bool init)
{
   MSTP_CIST_PORT_INFO_t     *cistPortPtr;
   STP_ASSERT(IS_VALID_LPORT(lport));

   /*------------------------------------------------------------------------
    * to facilitate references
    *------------------------------------------------------------------------*/
   cistPortPtr = MSTP_CIST_PORT_PTR(lport);
   STP_ASSERT(cistPortPtr);

   /*------------------------------------------------------------------------
    * State Machine Timers (802.1Q-REV/D5.0 13.21), they will be dynamically
    * set to the appropriate values during the run of the SMs.
    *------------------------------------------------------------------------*/

   cistPortPtr->fdWhile = 0;       /* d) */
   cistPortPtr->rrWhile = 0;       /* e) */
   cistPortPtr->rbWhile = 0;       /* f) */
   cistPortPtr->tcWhile = 0;       /* g) */
   cistPortPtr->rcvdInfoWhile = 0; /* h) */

   /*------------------------------------------------------------------------
    * Initialize other Per-Port Variables (802.1Q-REV/D5.0 13.24)
    * NOTE: every MSTP State Machine (SM) has an 'initial' state that will
    *       be reached at the time of SM initialization. In that 'initial'
    *       state the variables that SM is responsible for are being
    *       initialized to the appropriate initial values.
    *------------------------------------------------------------------------*/
   cistPortPtr->infoIs   = MSTP_INFO_IS_UNKNOWN;                      /*  x) */
   cistPortPtr->rcvdInfo = MSTP_RCVD_INFO_UNKNOWN;                    /* ac) */
   cistPortPtr->role     = MSTP_PORT_ROLE_UNKNOWN;                    /* as) */
   cistPortPtr->selectedRole = MSTP_PORT_ROLE_UNKNOWN;                /* at) */
   cistPortPtr->designatedPriority = MSTP_CIST_BRIDGE_PRIORITY;       /* al) */
   cistPortPtr->designatedPriority.dsnPortID = cistPortPtr->portId;
   memset((char*)&cistPortPtr->designatedTimes, 0,
          sizeof(cistPortPtr->designatedTimes));                      /* am) */
   memset((char*)&cistPortPtr->msgPriority, 0,
          sizeof(cistPortPtr->msgPriority));                          /* an) */
   memset((char*)&cistPortPtr->msgTimes, 0,
          sizeof(cistPortPtr->msgTimes));                             /* ao) */
   cistPortPtr->portPriority = MSTP_CIST_BRIDGE_PRIORITY;             /* aq) */
   cistPortPtr->portPriority.dsnPortID = cistPortPtr->portId;
   memset((char*)&cistPortPtr->portTimes, 0,
          sizeof(cistPortPtr->portTimes));                            /* ar) */
   STP_ASSERT(MSTP_COMM_PORT_PTR(lport));
   cistPortPtr->portTimes.helloTime = MSTP_COMM_PORT_PTR(lport)->HelloTime;

    /*------------------------------------------------------------------------
    * Initializing Port Uptime
    *------------------------------------------------------------------------*/
   cistPortPtr->cistPort_uptime = time(NULL);

   /*------------------------------------------------------------------------
    * Per-Port State Machines states (802.1Q-REV/D5.0 13.19)
    * NOTE: We do not set here any initial state to the SMs as they will do
    *       it themselves at the time of the SM initialization.
    *------------------------------------------------------------------------*/
   cistPortPtr->pimState = MSTP_PIM_STATE_UNKNOWN;
   cistPortPtr->prtState = MSTP_PRT_STATE_UNKNOWN;
   cistPortPtr->pstState = MSTP_PST_STATE_UNKNOWN;
   cistPortPtr->tcmState = MSTP_TCM_STATE_UNKNOWN;

   if(init)
   {/* Protocol initialization */
      /*---------------------------------------------------------------------
       * Clear statistics MIB support (RFC1493 MIB)
       *---------------------------------------------------------------------*/
      cistPortPtr->forwardTransitions = 0;

      /*---------------------------------------------------------------------
       * Clear counters used for debugging/troubleshooting purposes
       *---------------------------------------------------------------------*/
      memset(&cistPortPtr->dbgCnts, 0, sizeof(cistPortPtr->dbgCnts));
      memset(&cistPortPtr->portHistory, 0, sizeof(cistPortPtr->portHistory));
   }

   return cistPortPtr;
}
/**PROC+**********************************************************************
 * Name:      mstp_initCommonPortData
 *
 * Purpose:   Allocate, if necessary, and initialize in-memory data structure
 *            for the MSTP port (shared by the CIST and the MSTIs)
 *
 * Params:    stpCfgPortPtr -> pointer to the STP port config data
 *            init          -> boolean that indicates whether MSTP protocol
 *                             initialization or dynamic reconfiguration
 *                             change takes the place.
 *
 * Returns:   pointer to the allocated memory space
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
MSTP_COMM_PORT_INFO_t *
mstp_initCommonPortData(LPORT_t lport,bool init)
{
   MSTP_COMM_PORT_INFO_t      *commPortPtr;

   STP_ASSERT(MSTP_ENABLED);

   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   /*------------------------------------------------------------------------
    * Initialize CIST Port Priority (802.1Q-REV/D5.0 13.24.12)
    * Initialize Port's 'HelloTime' parameter (802.1Q-REV/D5.0 13.22 j))
    * Initialize Port's 'restrictedRole' parameter (802.1Q-REV/D5.0 13.25.14)
    * Initialize Port's 'restrictedTcn' parameter (802.1Q-REV/D5.0 13.25.15)
    * Initialize BPDU Filter flag.
    * NOTE: in-memory data structure for the port will be allocated if
    *       it does not exist yet.
    *------------------------------------------------------------------------*/

   /*------------------------------------------------------------------------
    * Clear Per-Port State Machines states
    * NOTE: every MSTP State Machine (SM) has an 'initial' state that will
    *       be entered at the time of a SM initialization. In 'initial'
    *       state every SM sets appropriate variables to the initial values.
    *       Here we mark all SMs as uninitialized by assigning 'unknow' value
    *       to the state. Call for SMs initialization will be done later.
    *------------------------------------------------------------------------*/
   commPortPtr->ptiState = MSTP_PTI_STATE_UNKNOWN;
   commPortPtr->ppmState = MSTP_PPM_STATE_UNKNOWN;
   commPortPtr->prxState = MSTP_PRX_STATE_UNKNOWN;
   commPortPtr->ptxState = MSTP_PTX_STATE_UNKNOWN;
   commPortPtr->bdmState = MSTP_BDM_STATE_UNKNOWN;

   /*------------------------------------------------------------------------
    * Clear State Machine Timers (802.1Q-REV/D5.0 13.21)
    *------------------------------------------------------------------------*/
   commPortPtr->mdelayWhile    = 0; /* a) */
   commPortPtr->helloWhen      = 0; /* b) */
   commPortPtr->edgeDelayWhile = 0; /* c) */



  /*-------------------------------------------------------------------------
   * Clear Per-Port Variables (802.1Q-REV/D5.0)
   *-------------------------------------------------------------------------*/
   commPortPtr->txCount        = 0; /* 13.24 e) */

   /*------------------------------------------------------------------------
    * Clear miscellaneous per-port variables
    *------------------------------------------------------------------------*/
   commPortPtr->trapThrottleTimer = 0;
   commPortPtr->trapPending       = FALSE;
   commPortPtr->trapPortState     = 0;
   commPortPtr->dropBpdu          = FALSE;
   commPortPtr->inBpduError       = FALSE;
   commPortPtr->reEnableTimer     = 0;
   commPortPtr->rcvdSelfSentPkt   = FALSE;

   return commPortPtr;
}

/**PROC+**********************************************************************
 * Name:      mstp_clearBridgeTreesData
 *
 * Purpose:   Clear the data used by the CIST and the MSTIs.
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   none
 *
 **PROC-**********************************************************************/
static void
mstp_clearBridgeTreesData(void)
{
   MSTID_t mstid;
   LPORT_t lport;

   for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
   {
      if(MSTP_MSTI_INFO(mstid))
      {
         for(lport = 1; lport <= MAX_LPORTS; lport++)
         {
             if(MSTP_MSTI_PORT_PTR(mstid,lport))
                 mstp_clearMstiPortData(mstid,lport);
         }
         mstp_clearBridgeMstiData(mstid);
      }
   }

   for(lport = 1; lport <= MAX_LPORTS; lport++)
   {
      if(MSTP_CIST_PORT_PTR(lport))
         mstp_clearCistPortData(lport);
   }
   mstp_clearBridgeCistData();
}

/**PROC+**********************************************************************
 * Name:      mstp_clearBridgeCistData
 *
 * Purpose:   Remove in-memory data structure allocated for the CIST.
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
void
mstp_clearBridgeCistData() {
       /*---------------------------------------------------------------------
       * Clear CIST's VLAN IDs mapping data in the global 'mstp_MstiVidTable'
       *---------------------------------------------------------------------*/
      clear_vid_map(&mstp_MstiVidTable[MSTP_CISTID]);

      /*---------------------------------------------------------------------
       * Clear the CIST data
       *---------------------------------------------------------------------*/
      memset(&MSTP_CIST_INFO, 0, sizeof(MSTP_CIST_INFO));

      MSTP_CIST_VALID = FALSE;
      MSTP_NUM_OF_VALID_TREES--;
}

/**PROC+**********************************************************************
 * Name:      mstp_clearBridgeMstiData
 *
 * Purpose:   Remove in-memory data structure allocated for the MSTI.
 *
 * Params:    mstid -> MST Instance Identifier
 *
 * Returns:   none
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
void
mstp_clearBridgeMstiData(MSTID_t mstid) {
    MSTP_TREE_MSG_t *m;
    if(MSTP_MSTI_INFO(mstid) == NULL)
        return;
    /*---------------------------------------------------------------------
     * VIDs that are removed from the MSTI should be mapped back to
     * the CIST in the global 'mstp_MstiVidTable'.
     *---------------------------------------------------------------------*/
    bit_or_vid_maps(&mstp_MstiVidTable[mstid],
            &mstp_MstiVidTable[MSTP_CISTID]);

    /*---------------------------------------------------------------------
     * Clear MSTI's VIDs mapping data in the global 'mstp_MstiVidTable'
     *---------------------------------------------------------------------*/
    clear_vid_map(&mstp_MstiVidTable[mstid]);
    /*---------------------------------------------------------------------
     * Decrement global counter of valid trees
     *---------------------------------------------------------------------*/
    MSTP_NUM_OF_VALID_TREES--;
    /*--------------------------------------------------------------------
     * If there is a pending message to other subsystems queued by this
     * MSTI we need to remove it from the queue and free memory space,
     * the message is not valid anymore.
     *--------------------------------------------------------------------*/
    m = mstp_findMstiPortStateChgMsg(mstid);
    if(m != NULL)
    {
        remqhere_nodis(&MSTP_TREE_MSGS_QUEUE, &m->link);
        free(m);
    }

    /*---------------------------------------------------------------------
     * Free memory space allocated for the MSTI
     *---------------------------------------------------------------------*/
    free(MSTP_MSTI_INFO(mstid));
    MSTP_MSTI_INFO(mstid) = NULL;

}

/**PROC+**********************************************************************
 * Name:      mstp_clearProtocolData
 *
 * Purpose:   Clear(free) data used by MSTP
 *            Called when administrative status of MSTP is going to be
 *            set to 'disabled'.
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
void
mstp_clearProtocolData(void)
{
    STP_ASSERT(MSTP_ENABLED);
    /*------------------------------------------------------------------------
     * clear the CIST and the MSTIs data
     *------------------------------------------------------------------------*/
    mstp_clearBridgeTreesData();

   /*------------------------------------------------------------------------
    * clear global Per-Bridge Variables and State Machine Performance
    * Parameters used by MSTP trees (the CIST and the MSTIs).
    *------------------------------------------------------------------------*/
   mstp_clearBridgeGlobalData();

}

/**PROC+**********************************************************************
 * Name:      mstp_clearMstiPortData
 *
 * Purpose:   Remove in-memory data structure allocated for the MSTI port.
 *
 * Params:    mstid -> MST instance identifier
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
void
mstp_clearMstiPortData(MSTID_t mstid, LPORT_t lport)
{
   STP_ASSERT(MSTP_VALID_MSTID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));
   STP_ASSERT(MSTP_COMM_PORT_PTR(lport));
   STP_ASSERT(MSTP_MSTI_PORT_PTR(mstid, lport));

   free(MSTP_MSTI_PORT_PTR(mstid, lport));
   MSTP_MSTI_PORT_PTR(mstid, lport) = NULL;

}

/**PROC+**********************************************************************
 * Name:      mstp_clearCistPortData
 *
 * Purpose:   Remove in-memory data structure allocated for the CIST port.
 *            This function gets called when one of the following occured:
 *            1). protocol is administratively disabled
 *            2). IDL informed MSTP that the logical port is being removed
 *               (happens when logical ports leave or change a trunk)
 *
 * Params:    lport        -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
void
mstp_clearCistPortData(LPORT_t lport)
{
   STP_ASSERT(IS_VALID_LPORT(lport));
   STP_ASSERT(MSTP_COMM_PORT_PTR(lport));
   STP_ASSERT(MSTP_CIST_PORT_PTR(lport));

   free(MSTP_CIST_PORT_PTR(lport));
   MSTP_CIST_PORT_PTR(lport) = NULL;
}

/**PROC+**********************************************************************
 * Name:      mstp_clearCommonPortData
 *
 * Purpose:   Remove in-memory data structure allocated for the common MSTP
 *            port (used by the CIST and all the MSTIs)
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
mstp_clearCommonPortData(LPORT_t lport)
{
   STP_ASSERT(IS_VALID_LPORT(lport));
   STP_ASSERT(MSTP_COMM_PORT_PTR(lport));

   MSTP_COMM_CLR_BPDU_FILTER(lport);

   free(MSTP_COMM_PORT_PTR(lport));
   MSTP_COMM_PORT_PTR(lport) = NULL;

}
/**PROC+**********************************************************************
 * Name:      mstp_clearMstpToOthersMessageQueue
 *
 * Purpose:   Remove from the queue all pending MSTP messages to
 *            other subsytems .
 *
 * Returns:   none
 *
 * Params:    none
 *
 **PROC-**********************************************************************/
void
mstp_clearMstpToOthersMessageQueue(void)
{
   MSTP_TREE_MSG_t *m;

   while(qempty(&MSTP_TREE_MSGS_QUEUE) == FALSE)
   {
      m = (MSTP_TREE_MSG_t *) remqhi(&MSTP_TREE_MSGS_QUEUE);
      free(m);
   }
}
/**PROC+**********************************************************************
 * Name:      mstp_updateMstpCBPortMaps
 *
 * Purpose:   Eliminate ports present in 'pmap' from the use by MSTP when
 *            it will propagate ports state change info to DB.
 *            In particular:
 *            1). clear ports from the global port maps 'MSTP_FWD_LPORTS'
 *                and 'MSTP_BLK_LPORTS' - these are used to keep track of
 *                what MSTP have told DB about 'forwarding'/'blocked' ports.
 *            2). clear ports from the port maps of each queued message that
 *                MSTP wants to deliver to DB
 *
 * Params:    pmap -> pointer to the map of logical ports that are being
 *                    removed
 *
 * Returns:   none
 *
 * Globals:   mstp_CB
 *
 **PROC-**********************************************************************/
void
mstp_updateMstpCBPortMaps(LPORT_t lport)
{
   PORT_MAP pmap;
   MSTP_TREE_MSG_t *m;
   PORT_MAP         tmp_pmap;

   clear_port_map(&pmap);
   set_port(&pmap,lport);

   STP_ASSERT(are_any_ports_set(&pmap));

   copy_port_map(&pmap, &tmp_pmap);
   bit_inverse_port_map(&tmp_pmap);

   bit_and_port_maps(&tmp_pmap, &MSTP_FWD_LPORTS);
   bit_and_port_maps(&tmp_pmap, &MSTP_BLK_LPORTS);

   for(m  = (MSTP_TREE_MSG_t *) qfirst_nodis(&MSTP_TREE_MSGS_QUEUE);
       m != (MSTP_TREE_MSG_t *) Q_NULL;
       m  = (MSTP_TREE_MSG_t *) qnext_nodis(&MSTP_TREE_MSGS_QUEUE, &m->link))
   {
      bit_and_port_maps(&tmp_pmap, &m->portsFwd);
      bit_and_port_maps(&tmp_pmap, &m->portsLrn);
      bit_and_port_maps(&tmp_pmap, &m->portsBlk);
      bit_and_port_maps(&tmp_pmap, &m->portsUp);
      bit_and_port_maps(&tmp_pmap, &m->portsDwn);
      bit_and_port_maps(&tmp_pmap, &m->portsMacAddrFlush);
   }
}

/** ======================================================================= **
 *                                                                           *
 *     Static (local to this file) Functions                                 *
 *                                                                           *
 ** ======================================================================= **/


/**PROC+**********************************************************************
 * Name:      mstp_clearBridgeGlobalData
 *
 * Purpose:   Clear global MSTP Bridge parameters.
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   none
 *
 **PROC-**********************************************************************/
static void
mstp_clearBridgeGlobalData(void)
{
   LPORT_t lport;

   STP_ASSERT(MSTP_ENABLED);

   /*------------------------------------------------------------------------
    * Clear MSTP common port data (used by both CIST and MSTIs)
    *------------------------------------------------------------------------*/
   for(lport = 1; lport <= MAX_LPORTS; lport++)
   {
      if(MSTP_COMM_PORT_PTR(lport))
         mstp_clearCommonPortData(lport);
   }

   /*------------------------------------------------------------------------
    * clear global Per-Bridge Variables and State Machine Performance
    * Parameters used by MSTP trees (the CIST and the MSTIs).
    *------------------------------------------------------------------------*/
   MSTP_BEGIN = FALSE;

   /*------------------------------------------------------------------------
    * clear MST Configuration Identifier
    *------------------------------------------------------------------------*/
   mstp_Bridge.MstConfigId.formatSelector = 0;
   memset(mstp_Bridge.MstConfigId.configName, 0,
          sizeof(mstp_Bridge.MstConfigId.configName));
   mstp_Bridge.MstConfigId.revisionLevel = 0;
   memset(mstp_Bridge.MstConfigId.digest, 0,
          sizeof(mstp_Bridge.MstConfigId.digest));

   /*------------------------------------------------------------------------
    * clear global State Machine Performance Parameters
    *------------------------------------------------------------------------*/
   mstp_Bridge.FwdDelay     = 0;
   mstp_Bridge.MigrateTime  = 0;
   mstp_Bridge.TxHoldCount  = 0;
   mstp_Bridge.MaxAge       = 0;
   mstp_Bridge.HelloTime    = 0;
   mstp_Bridge.MaxHops      = 0;

   /*------------------------------------------------------------------------
    * clear misc globals
    *------------------------------------------------------------------------*/
   mstp_Bridge.numOfValidTrees  = 0;
   mstp_Bridge.dynReconfig      = 0;
   mstp_Bridge.defaultPathCosts = path_cost_8021t;

   /*------------------------------------------------------------------------
    * clear BPDU Filtering.
    *------------------------------------------------------------------------*/
   clear_port_map(&mstp_Bridge.bpduFilterLports);

   /*------------------------------------------------------------------------
    * clear BPDU Protection
    *------------------------------------------------------------------------*/
   clear_port_map(&mstp_Bridge.bpduProtectionLports);

   /*------------------------------------------------------------------------
    * clear Loop guard Protection
    *------------------------------------------------------------------------*/
   clear_port_map(&mstp_Bridge.loopGuardLports);

   mstp_Bridge.portReEnableTimeout = 0;

   mstp_Bridge.trap_mask           = 0; /* Traps off by default */

}
/**PROC+**********************************************************************
 * Name:      mstp_initBridgeMstiData
 *
 * Purpose:   Initialize MSTI specific parameters with the values
 *            read from config.
 *            Called when MSTP administrative status is set to 'enabled'
 *            or when significant dynamic reconfiguration changes were made
 *            while protocol was running, so MSTP in-memory data structures
 *            need to be re-initialized from config.
 *
 * Params:    mstiCfgDataPtr -> pointer to MST Instance config data
 *            init           -> boolean that indicates whether MSTP protocol
 *                              initialization or dynamic reconfiguration
 *                              change takes the place.
 *
 * Returns:   none
 *
 * Globals:   none
 *
 **PROC-**********************************************************************/
static void
mstp_initBridgeMstiData(int mstid,bool init)
{
   MSTP_MSTI_BRIDGE_PRI_VECTOR_t *pri_vec;
   MSTP_BRIDGE_IDENTIFIER_t       mstiRootID;
   const char *my_mac = NULL;
   MAC_ADDRESS mac;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(MSTP_VALID_MSTID(mstid));

   /*------------------------------------------------------------------------
    * Set 'BridgeIdentifier' for the MSTI:
    *    - priority,
    *    - sys ID,
    *    - mac address
    * (802.1Q-REV/D5.0 13.23 c))
    * NOTE: 'mstp_hpicfBridgeMSTInstanceUpdate' function below will allocate
    *       in-memory data structure for the MST Instance if it does not
    *       exist yet and allocate and initialize MSTI ports data structures.
    *       In addition:
    *       1). It updates 'priority' component of the 'BridgeIdentifier'
    *           with the value read from config.
    *       2). It updates 'mstp_MstiVidTable' with VLANs mapped to the given
    *           MST Instance.
    *------------------------------------------------------------------------*/
   MSTP_SET_BRIDGE_SYS_ID(MSTP_MSTI_BRIDGE_IDENTIFIER(mstid), mstid);
    /* get the mac address for the port */
   my_mac = system_get_mac_addr();
   sscanf(my_mac,"%02x:%02x:%02x:%02x:%02x:%02x",(unsigned int *)&mac[0],(unsigned int *)&mac[1],(unsigned int *)&mac[2],
           (unsigned int *)&mac[3],(unsigned int *)&mac[4],(unsigned int *)&mac[5]);
   MAC_ADDR_COPY(&mac, MSTP_MSTI_BRIDGE_IDENTIFIER(mstid).mac_address);


   /*------------------------------------------------------------------------
    * Set 'BridgePriority' vector for the MSTI:
    *    - regional Root ID (priority, sys ID and mac address)
    *    - internal Root Path Cost
    *    - designated Bridge ID (priority, sys ID and mac address)
    *    - designated Port ID
    * (802.1Q-REV/D5.0 13.23 d))
    *------------------------------------------------------------------------*/
   pri_vec = &MSTP_MSTI_BRIDGE_PRIORITY(mstid);
   pri_vec->rgnRootID.priority = MSTP_MSTI_BRIDGE_IDENTIFIER(mstid).priority;
   MAC_ADDR_COPY(MSTP_MSTI_BRIDGE_IDENTIFIER(mstid).mac_address,
                 pri_vec->rgnRootID.mac_address);

   pri_vec->intRootPathCost = 0;

   pri_vec->dsnBridgeID.priority = MSTP_MSTI_BRIDGE_IDENTIFIER(mstid).priority;
   MAC_ADDR_COPY(MSTP_MSTI_BRIDGE_IDENTIFIER(mstid).mac_address,
                 pri_vec->dsnBridgeID.mac_address);

   pri_vec->dsnPortID = 0;

   /*------------------------------------------------------------------------
    * Set 'BridgeTimes' for the MSTI
    * (802.1Q-REV/D5.0 13.23 e))
    *------------------------------------------------------------------------*/
   MSTP_MSTI_BRIDGE_TIMES(mstid).hops = mstp_Bridge.MaxHops;

   /*------------------------------------------------------------------------
    * Set 'rootPortID' for the MSTI to zero (will be calculated by protocol)
    * (802.1Q-REV/D5.0 13.23 f))
    *------------------------------------------------------------------------*/
   MSTP_MSTI_ROOT_PORT_ID(mstid) = 0;

   /*------------------------------------------------------------------------
    * Copy current MSTI Regional Root Bridge ID to be used for further check
    * in the Regional Root history changes
    *------------------------------------------------------------------------*/
   mstiRootID = MSTP_MSTI_ROOT_PRIORITY(mstid).rgnRootID;

   /*------------------------------------------------------------------------
    * Set 'rootPriority' vector for the MSTI:
    *    - regional Root ID (priority, sys ID and mac address)
    *    - internal Root Path Cost
    *    - designated Bridge ID (priority, sys ID and mac address)
    *    - designated Port ID
    * (802.1Q-REV/D5.0 13.23 g))
    *------------------------------------------------------------------------*/
   pri_vec = &MSTP_MSTI_ROOT_PRIORITY(mstid);
   pri_vec->rgnRootID.priority = MSTP_MSTI_BRIDGE_IDENTIFIER(mstid).priority;
   MAC_ADDR_COPY(MSTP_MSTI_BRIDGE_IDENTIFIER(mstid).mac_address,
                 pri_vec->rgnRootID.mac_address);

   pri_vec->intRootPathCost = 0;

   pri_vec->dsnBridgeID.priority = MSTP_MSTI_BRIDGE_IDENTIFIER(mstid).priority;
   MAC_ADDR_COPY(MSTP_MSTI_BRIDGE_IDENTIFIER(mstid).mac_address,
                 pri_vec->dsnBridgeID.mac_address);

   pri_vec->dsnPortID = 0;

   /*------------------------------------------------------------------------
    * Set 'rootTimes' for the MSTI
    * (802.1Q-REV/D5.0 13.23 h))
    *------------------------------------------------------------------------*/
   MSTP_MSTI_ROOT_TIMES(mstid) = MSTP_MSTI_BRIDGE_TIMES(mstid);

   /*------------------------------------------------------------------------
    * Per-Instance State Machines states
    *------------------------------------------------------------------------*/
   MSTP_MSTI_INFO(mstid)->prsState = MSTP_PRS_STATE_UNKNOWN;

   if(init)
   {/* Protocol initialization */
      /*---------------------------------------------------------------------
       * Reset MSTI Statistics MIB info
       *---------------------------------------------------------------------*/
      MSTP_MSTI_INFO(mstid)->timeSinceTopologyChange = 0;
      MSTP_MSTI_INFO(mstid)->topologyChangeCnt       = 0;

      /*---------------------------------------------------------------------
       * Reset MSTI Regional Root change history statistics info
       *---------------------------------------------------------------------*/
      MSTP_MSTI_INFO(mstid)->mstiRgnRootChangeCnt = 0;
      memset(MSTP_MSTI_INFO(mstid)->mstiRgnRootHistory, 0,
             sizeof(MSTP_MSTI_INFO(mstid)->mstiRgnRootHistory));

      /*---------------------------------------------------------------------
       * Update first entry in MSTI Root change history to this switch ID
       *---------------------------------------------------------------------*/
      mstp_updateMstiRootHistory(mstid, pri_vec->rgnRootID);
   }
   else
   {/* Protocol dynamic reconfiguration change occurred */
      LPORT_t lport;

      /*----------------------------------------------------------------------
       * Check if the MSTI Regional Root has been changed, if so then update
       * the Regional Root change history for the MSTI.
       *---------------------------------------------------------------------*/
      if(!MSTP_BRIDGE_ID_EQUAL(mstiRootID, pri_vec->rgnRootID))
      {
         mstp_updateMstiRootHistory(mstid, pri_vec->rgnRootID);
         mstp_logNewRootId(mstiRootID, pri_vec->rgnRootID, FALSE, mstid);
      }

      /*---------------------------------------------------------------------
       * Re-read the MSTI ports data from config
       * NOTE: This is the case of dynamic reconfiguration changes. The MSTI
       *       ports in-memory data structures should be already allocated.
       *---------------------------------------------------------------------*/
      for(lport = 1; lport <= MAX_LPORTS; lport++)
      {
         if(MSTP_MSTI_PORT_PTR(mstid, lport))
         {
            STP_ASSERT(IS_VALID_LPORT(lport));
            mstp_initMstiPortData(mstid, lport, FALSE);
         }
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_initBridgeCistData
 *
 * Purpose:   Initialize CIST specific parameters with the values
 *            read from config.
 *            Called when MSTP administrative status is set to 'enabled'
 *            or when significant dynamic reconfiguration changes were made
 *            while protocol was running, so MSTP in-memory data structures
 *            need to be re-initialized from config.
 *
 * Params:    cistCfgDataPtr -> pointer to the CIST config data
 *            init           -> boolean that indicates whether MSTP protocol
 *                              initialization or dynamic reconfiguration
 *                              change takes the place.
 *
 * Returns:   none
 *
 * Globals:   none
 *
 **PROC-**********************************************************************/
static void
mstp_initBridgeCistData(bool init)
{
   MSTP_CIST_BRIDGE_PRI_VECTOR_t *pri_vec;
   MSTP_BRIDGE_IDENTIFIER_t       cstRootID;
   MSTP_BRIDGE_IDENTIFIER_t       istRootID;
   const char *my_mac = NULL;
   MAC_ADDRESS mac;

   STP_ASSERT(MSTP_ENABLED);
   /*------------------------------------------------------------------------
    * Set 'BridgeIdentifier' for the CIST:
    *    - priority,
    *    - sys ID,
    *    - mac address
    * (802.1Q-REV/D5.0 13.23 c))
    * NOTE: 'mstp_hpicfBridgeMSTInstanceUpdate' function below will allocate
    *       and initialize CIST ports data structures if they do not exist
    *       yet. In addition:
    *       1). It updates 'priority' component of the 'BridgeIdentifier'
    *           with the value read from config.
    *       2). It updates 'mstp_MstiVidTable' with VLANs mapped to the CIST.
    *------------------------------------------------------------------------*/
   MSTP_SET_BRIDGE_SYS_ID(MSTP_CIST_BRIDGE_IDENTIFIER, MSTP_CISTID);
   my_mac = system_get_mac_addr();
   sscanf(my_mac,"%02x:%02x:%02x:%02x:%02x:%02x",(unsigned int *)&mac[0],(unsigned int *)&mac[1],(unsigned int *)&mac[2],
           (unsigned int *)&mac[3],(unsigned int *)&mac[4],(unsigned int *)&mac[5]);
   MAC_ADDR_COPY(&mac,
                 MSTP_CIST_BRIDGE_IDENTIFIER.mac_address);

   /*------------------------------------------------------------------------
    * Set 'BridgePriority' vector for the CIST:
    *    - Root ID (priority, sys ID and mac address),
    *    - external Root Path Cost,
    *    - regional Root ID (priority, sys ID and mac address),
    *    - internal Root Path Cost,
    *    - designated Bridge ID (priority, sys ID and mac address),
    *    - designated Port ID
    * (802.1Q-REV/D5.0 13.23 d))
    *------------------------------------------------------------------------*/
   pri_vec = &MSTP_CIST_BRIDGE_PRIORITY;
   pri_vec->rootID.priority = MSTP_CIST_BRIDGE_IDENTIFIER.priority;
   MAC_ADDR_COPY(MSTP_CIST_BRIDGE_IDENTIFIER.mac_address,
                 pri_vec->rootID.mac_address);

   pri_vec->extRootPathCost = 0;

   pri_vec->rgnRootID.priority = MSTP_CIST_BRIDGE_IDENTIFIER.priority;
   MAC_ADDR_COPY(MSTP_CIST_BRIDGE_IDENTIFIER.mac_address,
                 pri_vec->rgnRootID.mac_address);

   pri_vec->intRootPathCost = 0;

   pri_vec->dsnBridgeID.priority = MSTP_CIST_BRIDGE_IDENTIFIER.priority;
   MAC_ADDR_COPY(MSTP_CIST_BRIDGE_IDENTIFIER.mac_address,
                 pri_vec->dsnBridgeID.mac_address);

   pri_vec->dsnPortID = 0;

   /*------------------------------------------------------------------------
    * Set 'BridgeTimes' for the CIST
    * NOTE: 'mstp_Bridge.FwdDelay', 'mstp_Bridge.MaxAge',
    *       'mstp_Bridge.MaxHops' are set in 'mstp_initBridgeGlobalData'
    *       at the time of enabling MSTP.
    * (802.1Q-REV/D5.0 13.23 e))
    *------------------------------------------------------------------------*/
   MSTP_CIST_BRIDGE_TIMES.fwdDelay   = mstp_Bridge.FwdDelay;
   MSTP_CIST_BRIDGE_TIMES.maxAge     = mstp_Bridge.MaxAge;
   MSTP_CIST_BRIDGE_TIMES.messageAge = 0;
   MSTP_CIST_BRIDGE_TIMES.hops       = mstp_Bridge.MaxHops;

   /*------------------------------------------------------------------------
    * Set 'rootPortID' for the CIST to zero (will be calculated by protocol)
    * (802.1Q-REV/D5.0 13.23 f))
    *------------------------------------------------------------------------*/
   MSTP_CIST_ROOT_PORT_ID = 0;

   /*------------------------------------------------------------------------
    * Copy current CST and IST Root Bridge IDs (will be used in further checks
    * for the CST Root and IST Regional Root history changes)
    *------------------------------------------------------------------------*/
   cstRootID = MSTP_CIST_ROOT_PRIORITY.rootID;
   istRootID = MSTP_CIST_ROOT_PRIORITY.rgnRootID;

   /*------------------------------------------------------------------------
    * Set 'rootPriority' vector for the CIST:
    *    - Root ID (priority, sys ID and mac address)
    *    - external Root Path Cost
    *    - regional Root ID (priority, sys ID and mac address)
    *    - internal Root Path Cost
    *    - designated Bridge ID (priority, sys ID and mac address)
    *    - designated Port ID
    * (802.1Q-REV/D5.0 13.23 g))
    *------------------------------------------------------------------------*/
   pri_vec = &MSTP_CIST_ROOT_PRIORITY;
   pri_vec->rootID.priority = MSTP_CIST_BRIDGE_IDENTIFIER.priority;
   MAC_ADDR_COPY(MSTP_CIST_BRIDGE_IDENTIFIER.mac_address,
                 pri_vec->rootID.mac_address);

   pri_vec->extRootPathCost = 0;

   pri_vec->rgnRootID.priority = MSTP_CIST_BRIDGE_IDENTIFIER.priority;
   MAC_ADDR_COPY(MSTP_CIST_BRIDGE_IDENTIFIER.mac_address,
                 pri_vec->rgnRootID.mac_address);

   pri_vec->intRootPathCost = 0;

   pri_vec->dsnBridgeID.priority = MSTP_CIST_BRIDGE_IDENTIFIER.priority;
   MAC_ADDR_COPY(MSTP_CIST_BRIDGE_IDENTIFIER.mac_address,
                 pri_vec->dsnBridgeID.mac_address);

   pri_vec->dsnPortID = 0;

   /*------------------------------------------------------------------------
    * Set 'rootTimes' for the CIST
    * (802.1Q-REV/D5.0 13.23 h))
    *------------------------------------------------------------------------*/
   MSTP_CIST_ROOT_TIMES = MSTP_CIST_BRIDGE_TIMES;

   /*------------------------------------------------------------------------
    * Set 'cistRootHelloTime' to zero. This variable will be set to the
    * 'Hello Time' value propagated by the CIST Root Bridge on to this
    * Bridge's Root Port. If this Bridge will be the CIST Root then this
    * variable should not be used.
    *------------------------------------------------------------------------*/
   MSTP_CIST_ROOT_HELLO_TIME = 0;

   /*------------------------------------------------------------------------
    * Per-Instance State Machines states
    *------------------------------------------------------------------------*/
   MSTP_CIST_INFO.prsState = MSTP_PRS_STATE_UNKNOWN;
   MSTP_CIST_TC_TRAP_CONTROL = FALSE;
   if(init)
   {/* Protocol initialization */
      /*---------------------------------------------------------------------
       * Reset CIST Statistics MIB info
       *---------------------------------------------------------------------*/
      MSTP_CIST_INFO.timeSinceTopologyChange = 0;
      MSTP_CIST_INFO.topologyChangeCnt       = 0;

      /*---------------------------------------------------------------------
       * Clear CST Root change history statistics info
       *---------------------------------------------------------------------*/
      MSTP_CIST_INFO.cstRootChangeCnt = 0;
      memset(MSTP_CIST_INFO.cstRootHistory, 0,
             sizeof(MSTP_CIST_INFO.cstRootHistory));

      /*---------------------------------------------------------------------
       * Update first entry in CST Root change history to this switch ID
       *---------------------------------------------------------------------*/
      mstp_updateCstRootHistory(pri_vec->rootID);

      /*---------------------------------------------------------------------
       * Reset IST Regional Root change history statistics info
       *---------------------------------------------------------------------*/
      MSTP_CIST_INFO.istRgnRootChangeCnt = 0;
      memset(MSTP_CIST_INFO.istRgnRootHistory, 0,
             sizeof(MSTP_CIST_INFO.istRgnRootHistory));

      /*---------------------------------------------------------------------
       * Update first entry in IST Root change history to this switch ID
       *---------------------------------------------------------------------*/
      mstp_updateIstRootHistory(pri_vec->rgnRootID);
   }
   else
   {/* Protocol dynamic reconfiguration change occurred */
      LPORT_t lport;

      /*----------------------------------------------------------------------
       * Check if the CST Root has been changed, if so then update the Root
       * change history for the CST.
       *---------------------------------------------------------------------*/
      if(!MSTP_BRIDGE_ID_EQUAL(cstRootID, pri_vec->rootID))
      {
         mstp_updateCstRootHistory(pri_vec->rootID);
         mstp_logNewRootId(cstRootID, pri_vec->rootID, TRUE, MSTP_CISTID);
      }

      /*----------------------------------------------------------------------
       * Check if the IST Regional Root has been changed, if so then update
       * the Regional Root change history for the IST.
       *---------------------------------------------------------------------*/
      if(!MSTP_BRIDGE_ID_EQUAL(istRootID, pri_vec->rgnRootID))
      {
         mstp_updateIstRootHistory(pri_vec->rgnRootID);
         mstp_logNewRootId(istRootID, pri_vec->rgnRootID, FALSE, MSTP_CISTID);
      }

      /*---------------------------------------------------------------------
       * Re-read the CIST ports data from config
       * NOTE: This is the case of dynamic reconfiguration changes. The CIST
       *       ports in-memory data structures should be already allocated.
       *---------------------------------------------------------------------*/
      for(lport = 1; lport <= MAX_LPORTS; lport++)
      {
         if(MSTP_CIST_PORT_PTR(lport))
         {
            STP_ASSERT(IS_VALID_LPORT(lport));
            mstp_initCistPortData(lport, init);
         }
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_initBridgeTreesData
 *
 * Purpose:   Initialize the CIST and the MST Instances data with the data
 *            read from config
 *            Called when MSTP administrative status is set to 'enabled'
 *            or when significant dynamic reconfiguration changes were made
 *            while protocol was running, so MSTP in-memory data structures
 *            need to be re-initialized from config.
 *
 * Params:    init -> boolean that indicates whether MSTP protocol
 *                    initialization or dynamic reconfiguration
 *                    change takes the place.
 *
 * Returns:   none
 *
 * Globals:   none
 *
 **PROC-**********************************************************************/
static void
mstp_initBridgeTreesData(bool init)
{
   MSTID_t                        mstidx;
   for (mstidx= 0; mstidx <= MSTP_MSTID_MAX ; mstidx++)
   {
       if(mstidx == MSTP_CISTID)
       {
           mstp_initBridgeCistData(init);
       }
       else if((MSTP_MSTI_INFO(mstidx)) && (MSTP_MSTI_INFO(mstidx)->valid == TRUE))
       {
           mstp_initBridgeMstiData(mstidx,init);
       }
   }

}

/**PROC+**********************************************************************
 * Name:      mstp_initBridgeGlobalData
 *
 * Purpose:   Initialize global MSTP Bridge parameters with the values
 *            read from config.
 *            Called when MSTP administrative status is set to 'enabled'
 *            or when significant dynamic reconfiguration changes were made
 *            while protocol was running, so MSTP in-memory data structures
 *            need to be re-initialized from config.
 *
 * Params:    init -> boolean that indicates whether MSTP protocol
 *                    initialization or dynamic reconfiguration
 *                    change takes the place.
 *
 * Returns:   none
 *
 * Globals:   none
 *
 **PROC-**********************************************************************/
static void
mstp_initBridgeGlobalData(bool init)
{
   uint32_t                portIdx;
    /*------------------------------------------------------------------------
    * Initialize global per-Bridge Variables
    *------------------------------------------------------------------------*/
   MSTP_BEGIN = FALSE;

    /*------------------------------------------------------------------------
    * These MSTP Bridge Performance parameters use hardcoded values
    *------------------------------------------------------------------------*/
   mstp_Bridge.TxHoldCount  = MSTP_TX_HOLD_COUNT;
   mstp_Bridge.MigrateTime  = MSTP_MIGRATE_TIME_SEC;

   mstp_Bridge.preventTx    = FALSE;


   /*------------------------------------------------------------------------
    * Initialize global per-Bridge Variables
    *------------------------------------------------------------------------*/
   MSTP_BEGIN = FALSE;
   for (portIdx = 1; IS_VALID_LPORT(portIdx); portIdx++) {
       if(MSTP_COMM_PORT_PTR(portIdx)) {
           mstp_initCommonPortData(portIdx,init);
       }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_initControlData
 *
 * Purpose:   Initialize MSTP Control Data, that is
 *             - initialize MSTP Control Block data
 *             - create MSTP Control Task
 *             - connect to other manager tasks that MSTP is going to
 *               communicate to
 *            Called at the switch boot time only.
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
static void
mstp_initControlData(void)
{
   /*------------------------------------------------------------------------
    * initialize MSTP Control Block data (all to zero)
    *------------------------------------------------------------------------*/
   memset((char *) &mstp_CB, 0, (sizeof (MSTP_CB_t)));

   /*------------------------------------------------------------------------
    * initialize trees change message queue.
    *------------------------------------------------------------------------*/
   inique(&MSTP_TREE_MSGS_QUEUE);
   /* Clear VIDs mapping for all MSTIs */
   memset(mstp_MstiVidTable, 0x00, sizeof(mstp_MstiVidTable));
   /* Map all VIDs to the CIST */
   MSTP_ADD_ALL_VIDS_TO_VIDMAP(&mstp_MstiVidTable[MSTP_CISTID]);
}
