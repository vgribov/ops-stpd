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
 *    File               : mstpd_util.c
 *    Description        : MSTP Protocol Utility Functions
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
#include <eventlog.h>

#include "mstp_ovsdb_if.h"
#include "mstp_inlines.h"
#include "mstp_recv.h"
#include "mstp_fsm.h"
#include "md5.h"

VLOG_DEFINE_THIS_MODULE(mstpd_util);
/*---------------------------------------------------------------------------
 * Local functions prototypes (forward declarations)
 *---------------------------------------------------------------------------*/
static bool    mstp_isMstBpdu(MSTP_RX_PDU *pkt);
static void    mstp_updtMstiRootInfoChg(MSTID_t mstid);
static void    mstp_updtMstiPortStateChgMsg(MSTID_t mstid, LPORT_t lport,
                                            MSTP_ACT_TYPE_t state);
static bool    mstp_isNeighboreBridgeInMyRegion(MSTP_RX_PDU *pkt);
static int     mstp_cistPriorityVectorsCompare
                                           (MSTP_CIST_BRIDGE_PRI_VECTOR_t *v1,
                                            MSTP_CIST_BRIDGE_PRI_VECTOR_t *v2);
static int     mstp_mstiPriorityVectorsCompare
                                           (MSTP_MSTI_BRIDGE_PRI_VECTOR_t *v1,
                                            MSTP_MSTI_BRIDGE_PRI_VECTOR_t *v2);
static MSTP_MSTI_CONFIG_MSG_t *
               mstp_findMstiCfgMsgInBpdu(MSTP_RX_PDU *pkt, MSTID_t mstid);
static bool    mstp_isStpConfigBpdu(MSTP_RX_PDU *pkt);
static bool    mstp_isStpTcnBpdu(MSTP_RX_PDU *pkt);
static bool    mstp_isRstBpdu(MSTP_RX_PDU *pkt);
static bool    mstp_isMstBpdu(MSTP_RX_PDU *pkt);
static bool    mstp_isSelfSentPkt(MSTP_RX_PDU *pkt);
static void    mstp_updtRolesCist(void);
static void    mstp_updtRolesMsti(MSTID_t mstid);
static MSTP_RCVD_INFO_t
               mstp_rcvInfoCist(MSTP_RX_PDU *pkt, LPORT_t lport);
static MSTP_RCVD_INFO_t
               mstp_rcvInfoMsti(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport);
static void    mstp_mstRgnCfgConsistencyCheck(MSTP_MST_BPDU_t *bpdu,
                                              LPORT_t lport);
static bool    mstp_isOldRootPropagation(MSTID_t mstid, LPORT_t lport,
                                         MSTP_MST_BPDU_t *bpdu,
                                         MSTP_MSTI_CONFIG_MSG_t *cfgMsgPtr,
                                         bool bpduSameRgn);
/** ====================================================================== **
 *                                                                          *
 *     Global Functions (externed)                                          *
 *                                                                          *
 ** ====================================================================== **/

/**PROC+**********************************************************************
 * Name:      mstp_clearGlobalMstpDebugInfo
 *
 * Purpose:   clear global MSTP debugging info.
 *            Currently called from 'dev_idle' function (drv_poll.c)
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
mstp_clearGlobalMstpDebugInfo(void)
{
    if(MSTP_ENABLED == FALSE)
        return;

    mstp_CB.prBpduWm = MAX(mstp_CB.prBpduWm, mstp_CB.prBpduCnt);
    mstp_CB.prBpduCnt = 0;
}

/**PROC+****************************************************************
 * Name:      isMstpEnabled
 *
 * Purpose:   Return whether MSTP enabled on the box.
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals: . Spanning, stp_version
 **PROC-*****************************************************************/

bool isMstpEnabled(void)
{
   return MSTP_ENABLED;
}

/**PROC+**********************************************************************
 * Name:      mstp_setDynReconfigChangeFlag
 *
 * Purpose:   Sets MSTP_DYN_RECONFIG_CHANGE flag to indicate that dynamic
 *            reconfiguration change occurred and protocol re-initialization is
 *            required.
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 **PROC-**********************************************************************/
void mstp_setDynReconfigChangeFlag (void)
{
   if (MSTP_ENABLED == TRUE)
   {
      MSTP_DYN_RECONFIG_CHANGE = TRUE;
   }
   return;
}

/**PROC+**********************************************************************
 * Name:      mstp_portAutoDetectParamsSet
 *
 * Purpose:   Set port parameters that depend on the physical characteristics
 *            of the established connection with the peer port.
 *            Called when 'LPORT_UP_indic' event is received, signalling that
 *            the port is physically connected to the wire.
 *            NOTE: if 'useCfgPathCost' for the port is FALSE that means
 *                  this port is configured to use dynamic method of
 *                  selecting a value for the path cost.
 *
 * Params:    lport     -> logical port number
 *            speedDplx -> logical port's speed/duplex information passed.
 *
 * Returns:   none
 *
 * Globals:   none
 *
 **PROC-**********************************************************************/
void
mstp_portAutoDetectParamsSet(LPORT_t lport, SPEED_DPLX* speedDplx)
{
   MSTID_t                mstid;
   MSTP_COMM_PORT_INFO_t *commPortPtr;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   /*------------------------------------------------------------------------
    * Set path cost value for the port
    * NOTE: MESH port is being enforced always have the lowest path cost
    *------------------------------------------------------------------------*/
      {
         uint32_t autoPathCost = mstp_convertLportSpeedToPathCost(speedDplx);

         if(commPortPtr->useCfgPathCost == FALSE)
            commPortPtr->ExternalPortPathCost = autoPathCost;

         STP_ASSERT(MSTP_CIST_PORT_PTR(lport));
         if(MSTP_CIST_PORT_PTR(lport)->useCfgPathCost == FALSE)
            MSTP_CIST_PORT_PTR(lport)->InternalPortPathCost = autoPathCost;

         for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
         {
            if(MSTP_MSTI_VALID(mstid))
            {
               STP_ASSERT(MSTP_MSTI_PORT_PTR(mstid, lport));
               if(MSTP_MSTI_PORT_PTR(mstid, lport)->useCfgPathCost == FALSE)
               {
                  MSTP_MSTI_PORT_PTR(mstid, lport)->InternalPortPathCost =
                                                                  autoPathCost;
               }
            }
         }
      }
   /*------------------------------------------------------------------------
    * Set operational value of the port's Point to Point MAC parameter
    *------------------------------------------------------------------------*/
   if(commPortPtr->adminPointToPointMAC == MSTP_ADMIN_PPMAC_AUTO)
   {
      if(speedDplx->duplex == FULL_DUPLEX)
         MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap,
                                MSTP_PORT_OPER_POINT_TO_POINT_MAC);
      else
         MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap,
                                MSTP_PORT_OPER_POINT_TO_POINT_MAC);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_portAutoPathCostDetect
 *
 * Purpose:   Calculate Path Cost information to be set for the MSTP port
 *            based on the connection speed and duplex mode this port
 *            currently operates with.
 *
 * Params:    lport    -> logical port in question
 *
 * Returns:   Path Cost value that corresponds to the current value of the
 *            port's physical link characteristics.
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_portAutoPathCostDetect(LPORT_t lport)
{
   uint32_t    pathCost;
   SPEED_DPLX speedDplx;

   STP_ASSERT(IS_VALID_LPORT(lport));
   /*------------------------------------------------------------------------
    * NOTE: 'intf_get_lport_speed_duplex' function returns FALSE only if
    *       'lport' is not connected.
    *       For not connected port we return '0' path cost value indicating
    *       that auto speed detection failed. Zero path cost value also
    *       indicates that the logical port is configured to
    *       'auto speed detection mode', i.e. port should calculate the path
    *       cost from the link connection speed rather then use config info.
    *------------------------------------------------------------------------*/
   if(intf_get_lport_speed_duplex(lport, &speedDplx))
      pathCost = mstp_convertLportSpeedToPathCost(&speedDplx);
   else
      pathCost = 0;

   return pathCost;
}

/**PROC+**********************************************************************
 * Name:      mstp_portDuplexModeDetect
 *
 * Purpose:   Find what duplex mode the given logical port currently operates
 *            with.
 *
 * Params:    lport    -> logical port in question
 *
 * Returns:   logical port's current duplex mode.
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
PORT_DUPLEX
mstp_portDuplexModeDetect(LPORT_t lport)
{
   PORT_DUPLEX portDuplex;
   SPEED_DPLX  speedDplx;

   STP_ASSERT(IS_VALID_LPORT(lport));

   /*------------------------------------------------------------------------
    * NOTE: 'intf_get_lport_speed_duplex' function returns FALSE only if
    *       'lport' is not connected.
    *------------------------------------------------------------------------*/
   if(intf_get_lport_speed_duplex(lport, &speedDplx))
      portDuplex = speedDplx.duplex;
   else
      portDuplex = FULL_DUPLEX;

   return portDuplex;
}

/**PROC+**********************************************************************
 * Name:      mstp_isLportFwdOnVlan
 *
 * Purpose:   Return whether logical port is forwarding on the VLAN.
 *
 * Params:    lport -> logical port number
 *            vlan  -> vlan number
 *
 * Returns:   TRUE if 'lport' is in FORWARDING state on the 'vlan',
 *            FALSE otherwise
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
bool
mstp_isLportFwdOnVlan(LPORT_t lport, VID_t vlan)
{
   bool res = FALSE;

   STP_ASSERT(IS_VALID_LPORT(lport));
   STP_ASSERT(IS_VALID_VID(vlan));

   if(MSTP_ENABLED == FALSE)
   {
         res = TRUE;
   }
   else
   {
      MSTID_t mstid;

       /* Find an MST Instance the VLAN is being mapped to */
      if(((mstid = mstp_getMstIdForVlan(vlan)) != MSTP_NO_MSTID) &&
         MSTP_INSTANCE_IS_VALID(mstid))
      {/* Look at MSTI port state */
         if(mstid == MSTP_CISTID)
         {
            MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

            if(cistPortPtr &&
               (cistPortPtr->pstState == MSTP_PST_STATE_FORWARDING))
            {
               res = TRUE;
            }
         }
         else
         {
            MSTP_MSTI_PORT_INFO_t *mstiPortPtr =
                                              MSTP_MSTI_PORT_PTR(mstid, lport);

            if(mstiPortPtr &&
               (mstiPortPtr->pstState == MSTP_PST_STATE_FORWARDING))
            {
               res = TRUE;
            }
         }
      }

   }

   return res;
}
/**PROC+**********************************************************************
 * Name:      mstp_mapMstIdToVlanGroupNum
 *
 * Purpose:   Find a free VLAN group number to be associated with a newly
 *            created Spanning Tree instance.
 *            Called at the time of new MST Instance creation.
 *
 * Params:    mstid -> MST Instance Identifier
 *
 * Returns:   Free VLAN group number (> 0) if available, 0 otherwise
 *
 * Globals:   mstp_CB
 *
 **PROC-**********************************************************************/
VLAN_GROUP_t
mstp_mapMstIdToVlanGroupNum(MSTID_t mstid)
{
   VLAN_GROUP_t vlanGroupNum;
   bool        mapped = FALSE;

   STP_ASSERT(MSTP_VALID_MSTID(mstid));
   STP_ASSERT(MSTP_MSTI_VALID(mstid));
   STP_ASSERT(MSTP_MSTI_INFO(mstid)->vlanGroupNum == 0);
   STP_ASSERT(mstp_Bridge.maxVlanGroups <= MSTP_INSTANCES_MAX);

   for(vlanGroupNum = 1;
       vlanGroupNum <= mstp_Bridge.maxVlanGroups;
       vlanGroupNum++)
   {
      if(mstp_vlanGroupNumToMstIdTable[vlanGroupNum] == 0)
      {
         mstp_vlanGroupNumToMstIdTable[vlanGroupNum] = mstid;
         mapped = TRUE;
         break;
      }
   }

   return (mapped ? vlanGroupNum : 0);
}

/**PROC+**********************************************************************
 * Name:      mstp_unmapMstIdFromVlanGroupNum
 *
 * Purpose:   Mark VLAN group number associated with given MST Instance as
 *            a free to be used by other MSTI.
 *            Called at the time of MST Instance deletion.
 *
 * Params:    mstid -> MST Instance Identifier
 *
 * Returns:   none
 *
 * Globals:   mstp_CB
 *
 **PROC-**********************************************************************/
void
mstp_unmapMstIdFromVlanGroupNum(MSTID_t mstid)
{
   VLAN_GROUP_t vlanGroupNum;

   STP_ASSERT(MSTP_VALID_MSTID(mstid));
   STP_ASSERT(MSTP_MSTI_VALID(mstid));
   STP_ASSERT(MSTP_MSTI_INFO(mstid)->vlanGroupNum != 0);
   STP_ASSERT(mstp_Bridge.maxVlanGroups <= MSTP_INSTANCES_MAX);

   for(vlanGroupNum = 1;
       vlanGroupNum <= mstp_Bridge.maxVlanGroups;
       vlanGroupNum++)
   {
      if(mstp_vlanGroupNumToMstIdTable[vlanGroupNum] == mstid)
      {
         mstp_vlanGroupNumToMstIdTable[vlanGroupNum] = 0;
         break;
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_isThisBridgeRegionalRoot
 *
 * Purpose:   Verify if this Bridge is the Regional Root for a Spanning Tree
 *            instance with the given 'mstid'.
 *
 * Params:    mstid -> MST Instance Identifier.
 *
 * Returns:   TRUE if this Bridge is the Regional Root for a 'mstid',
 *            FALSE otherwise.
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 **PROC-**********************************************************************/
bool
mstp_isThisBridgeRegionalRoot(MSTID_t mstid)
{
   bool res = FALSE;

   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(MSTP_INSTANCE_IS_VALID(mstid));

   if(mstid == MSTP_CISTID)
   {
      if(MSTP_BRIDGE_ID_EQUAL(MSTP_CIST_BRIDGE_IDENTIFIER,
                              MSTP_CIST_ROOT_PRIORITY.rgnRootID))
      {
         res = TRUE;
      }
   }
   else
   {
      if(MSTP_BRIDGE_ID_EQUAL(MSTP_MSTI_BRIDGE_IDENTIFIER(mstid),
                              MSTP_MSTI_ROOT_PRIORITY(mstid).rgnRootID))
      {
         res = TRUE;
      }
   }

   return res;

}

/**PROC+**********************************************************************
 * Name:      mstp_collectNotForwardingPorts
 *
 * Purpose:   Collect all MSTP ports that are not administratively disabled
 *            and currently are set to BLOCKED or LEARNING state. This
 *            function called at the time when administrative status of
 *            the MSTP protocol on the switch is going to be 'disabled'.
 *
 * Params:    pmap -> pointer to the lport map where to store ports that need
 *                    to be FORWARDING.
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 **PROC-**********************************************************************/
void
mstp_collectNotForwardingPorts(PORT_MAP *pmap)
{
   LPORT_t                lport;
   MSTID_t                mstid;
   MSTP_COMM_PORT_INFO_t *commPortPtr;
   MSTP_CIST_PORT_INFO_t *cistPortPtr;
   MSTP_MSTI_PORT_INFO_t *mstiPortPtr;

   STP_ASSERT(pmap);

   /*------------------------------------------------------------------------
    * Collect all MSTP ports that are not in FORWARDING state
    *------------------------------------------------------------------------*/
   clear_port_map(pmap);
   for(lport = 1; lport <= MAX_LPORTS; lport++)
   {
      commPortPtr = MSTP_COMM_PORT_PTR(lport);
      if(commPortPtr &&
         MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_PORT_ENABLED))
      {

         /*------------------------------------------------------------------
          * first, check if port is not FORWARDING on the CIST
          *------------------------------------------------------------------*/
         cistPortPtr = MSTP_CIST_PORT_PTR(lport);
         STP_ASSERT(cistPortPtr);
         if(cistPortPtr->pstState != MSTP_PST_STATE_FORWARDING)
         {
            set_port(pmap, lport);
            continue;
         }

         /*------------------------------------------------------------------
          * second, check if port is not FORWARDING on any MSTI
          *------------------------------------------------------------------*/
         for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
         {
            if(MSTP_MSTI_INFO(mstid))
            {
               mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
               STP_ASSERT(mstiPortPtr);
               if(mstiPortPtr->pstState != MSTP_PST_STATE_FORWARDING)
               {
                  set_port(pmap, lport);
                  break;
               }
            }
         }
      }
   }
}
#if OPS_MSTP_TODO
/**PROC+**********************************************************************
 * Name:      mstp_blockedPortsBackToForward
 *
 * Purpose:   Inform other subsystems that some ports need to be set to the
 *            FORWARDING state. This function called at the time when
 *            administrative status of the MSTP protocol on the switch is going
 *            to be 'disabled', so those MSTP controlled ports that are not
 *            administratively disabled and currently are set BLOCKED or
 *            LEARNING should be restored back to the FORWARDING state
 *            on the switch.
 *
 * Params:    pmap -> pointer to the lport map with the ports that need
 *                    to be FORWARDING.
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_blockedPortsBackToForward(PORT_MAP *pmap)
{
   PORT_MAP tmpPmap;
   STP_ASSERT(pmap);
   STP_ASSERT(are_any_ports_set(pmap));

   /*------------------------------------------------------------------------
    * inform DB about ports state changes
    *------------------------------------------------------------------------*/
   mstp_informDBLportsStateChange(MSTP_NON_STP_BRIDGE, pmap,
                                    MSTP_ACT_ENABLE_FORWARDING);

   mstp_informDBLportsUpDown(MSTP_NON_STP_BRIDGE, pmap, MSTP_ACT_PROPAGATE_UP);

}

#endif /*OPS_MSTP_TODO*/
/**PROC+**********************************************************************
 * Name:      mstp_portEnable
 *
 * Purpose:   This routine called on receipt of LPORT_UP_indic event.
 *            It sets all necessary port data and kicks appropriate state
 *            machines.
 *
 * Params:    lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_portEnable(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr;
   MSTID_t                mstid;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   if(!commPortPtr)
      return;

   if(!MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_PORT_ENABLED))
   {
      MSTP_PORT_STATUS_PRINTF(lport, MSTP_PORT_STATE_FMT, "ENABLE PORT: start",
                              MSTP_ENBL_SYM, lport);
      /*---------------------------------------------------------------------
       * mark port as 'enabled'
       *---------------------------------------------------------------------*/
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_PORT_ENABLED);

      /*---------------------------------------------------------------------
       * It's possible that port was in BpduError and then disabled. If admin
       * then re-enables the interface we should clear BPDU Error flag
       *---------------------------------------------------------------------*/
      commPortPtr->inBpduError = FALSE;

      /*---------------------------------------------------------------------
       * Stop BPDU transmissions on the Bridge until we done with enabling
       * the port, we will do scheduled transmission at the end of this function
       * to minimize the number of BPDUs to be transmitted.
       * NOTE: If a CIST state machine sets 'newInfo', this machine will ensure
       *       that a BPDU is transmitted conveying the new CIST information.
       *       If MST BPDUs can be transmitted through the port this BPDU will
       *       also convey new MSTI information for all MSTIs. If a MSTI state
       *       machine sets 'newInfoMsti', and MST BPDUs can be transmitted
       *       through the port, this machine will ensure that a BPDU is
       *       transmitted conveying information for the CIST and all MSTIs.
       *       (802.1Q-REV/D5.0 13.31
       *---------------------------------------------------------------------*/
      mstp_preventTxOnBridge();

      /*---------------------------------------------------------------------
       * kick Port Receive  state machine (per-Port)
       *---------------------------------------------------------------------*/
      mstp_prxSm(NULL, lport);

      /*---------------------------------------------------------------------
       * kick Port Protocol Migration state machine (per-Port)
       *---------------------------------------------------------------------*/
      mstp_ppmSm(lport);

      /*---------------------------------------------------------------------
       * kick CIST's Port Information state machine (per-Tree per-Port)
       *---------------------------------------------------------------------*/
      mstp_pimSm(NULL, MSTP_CISTID, lport);

      /*---------------------------------------------------------------------
       * kick Port Information state machine for each enabled MSTI
       * (per-Tree per-Port)
       *---------------------------------------------------------------------*/
      for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
      {
         if(MSTP_MSTI_VALID(mstid))
         {
            STP_ASSERT(MSTP_MSTI_PORT_PTR(mstid, lport));
            mstp_pimSm(NULL, mstid, lport);
         }
      }
      /*---------------------------------------------------------------------
       * When we done with port enabling lets initiate transmission of pending
       * information on the Bridge, if any
       *---------------------------------------------------------------------*/
      mstp_doPendingTxOnBridge();

      MSTP_PORT_STATUS_PRINTF(lport, MSTP_PORT_STATE_FMT, "ENABLE PORT: end",
                              MSTP_ENBL_SYM, lport);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_portDisable
 *
 * Purpose:   This routine called on receipt of LPORT_DOWN_indic events
 *            or called by 'mstp_removeLports' function when IDL informs MSTP
 *            that a port leaves or changes a trunk.
 *            It sets all necessary port data and kicks appropriate state
 *            machines.
 *
 * Params:    lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_portDisable(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr;
   MSTID_t                mstid;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   if(!commPortPtr)
   {
      /*---------------------------------------------------------------------
       * It is possible that the port's data structure does not exist.
       *---------------------------------------------------------------------*/
      return;
   }

   if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_PORT_ENABLED))
   {
      /*---------------------------------------------------------------------
       * mark port as 'disabled'
       *---------------------------------------------------------------------*/
      MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap, MSTP_PORT_PORT_ENABLED);
      MSTP_PORT_STATUS_PRINTF(lport, MSTP_PORT_STATE_FMT, "DISABLED PORT",
                              MSTP_DSBL_SYM, lport);

      /*---------------------------------------------------------------------
       * Stop BPDU transmissions on the Bridge until we done with disabling
       * the port, we will do scheduled transmission at the end of this
       * function to minimize the number of BPDUs to be transmitted.
       * NOTE: If a CIST state machine sets 'newInfo', this machine will ensure
       *       that a BPDU is transmitted conveying the new CIST information.
       *       If MST BPDUs can be transmitted through the port this BPDU will
       *       also convey new MSTI information for all MSTIs. If a MSTI state
       *       machine sets 'newInfoMsti', and MST BPDUs can be transmitted
       *       through the port, this machine will ensure that a BPDU is
       *       transmitted conveying information for the CIST and all MSTIs.
       *       (802.1Q-REV/D5.0 13.31
       *---------------------------------------------------------------------*/
      mstp_preventTxOnBridge();

      /*---------------------------------------------------------------------
       * kick CIST's Port Information state machine (per-Tree per-Port)
       *---------------------------------------------------------------------*/
      STP_ASSERT(MSTP_CIST_PORT_PTR(lport));
      mstp_pimSm(NULL, MSTP_CISTID, lport);

      /*---------------------------------------------------------------------
       * kick Port Information state machine for each enabled MSTI
       * (per-Tree per-Port)
       *---------------------------------------------------------------------*/
      for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
      {
         if(MSTP_MSTI_VALID(mstid))
         {
            STP_ASSERT(MSTP_MSTI_PORT_PTR(mstid, lport));
            mstp_pimSm(NULL, mstid, lport);
         }
      }

      /*---------------------------------------------------------------------
       * kick Port Receive state machine (per-Port)
       *---------------------------------------------------------------------*/
      mstp_prxSm(NULL, lport);

      /*---------------------------------------------------------------------
       * kick Port Protocol Migration state machine (per-Port)
       *---------------------------------------------------------------------*/
      mstp_ppmSm(lport);

      /*---------------------------------------------------------------------
       * kick Bridge Detection state machine (per-Port)
       *---------------------------------------------------------------------*/
      mstp_bdmSm(lport);
      /*---------------------------------------------------------------------
       * When we done with port disabling lets initiate transmission of pending
       * information on the Bridge, if any
       *---------------------------------------------------------------------*/
      mstp_doPendingTxOnBridge();
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_enableActiveLogicalPorts
 *
 * Purpose:   Enable for MSTP all logical ports that are in 'UP' state
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_enableActiveLogicalPorts(void)
{
   LPORT_t lport;

   for(lport = 1; lport <= MAX_LPORTS; lport++)
   {
      if(MSTP_COMM_PORT_PTR(lport) && !is_lport_down(lport))
      {
         mstp_portEnable(lport);
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_utilPrtStatePtr
 *
 * Purpose:   This utility function returns pointer to the Port's
 *            Role Transition State variable. Called by Port Role
 *            Transitions State Machine routines.
 *
 * Params:    mstid -> MST Instance Idetifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   Pointer to the state information place holder
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
MSTP_PRT_STATE_t *
mstp_utilPrtStatePtr(MSTID_t mstid, LPORT_t lport)
{
   MSTP_PRT_STATE_t *statePtr = NULL;

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      statePtr = &cistPortPtr->prtState;
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      statePtr = &mstiPortPtr->prtState;
   }

   return statePtr;
}

/**PROC+**********************************************************************
 * Name:      mstp_utilPimStatePtr
 *
 * Purpose:   This utility function returns pointer to the Port's
 *            Information State variable. Called by Port Information
 *            State Machine routines.
 *
 * Params:    mstid -> MST Instance Idetifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   Pointer to the state information place holder
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
MSTP_PIM_STATE_t *
mstp_utilPimStatePtr(MSTID_t mstid, LPORT_t lport)
{
   MSTP_PIM_STATE_t *statePtr = NULL;

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      statePtr = &cistPortPtr->pimState;
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      statePtr = &mstiPortPtr->pimState;
   }

   return statePtr;
}

/**PROC+**********************************************************************
 * Name:      mstp_utilTcmStatePtr
 *
 * Purpose:   This utility function returns pointer to the Port's
 *            Topology Change State variable. Called by Port Topology Change
 *            State Machine routines.
 *
 * Params:    mstid -> MST Instance Idetifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   Pointer to the state information place holder
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
MSTP_TCM_STATE_t *
mstp_utilTcmStatePtr(MSTID_t mstid, LPORT_t lport)
{
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

   return statePtr;
}

/**PROC+**********************************************************************
 * Name:      mstp_findNextMstiCfgMsgInBpdu
 *
 * Purpose:   In the received BPDU search for the location of the next MSTI
 *            Configuration Message starting from location pointed by the
 *            'current'. If 'current' is NULL than find first MSTI Config
 *            Message.
 *
 * Params:    pkt     -> pointer to the packet buffer with BPDU in
 *            current -> pointer to the place in BPDU to start search from
 *
 * Returns:   returns pointer to the location of the next Configuration
 *            Message if found, NULL otherwise.
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
MSTP_MSTI_CONFIG_MSG_t *
mstp_findNextMstiCfgMsgInBpdu(MSTP_RX_PDU *pkt, MSTP_MSTI_CONFIG_MSG_t *current)
{
   MSTP_MST_BPDU_t *bpdu = NULL;
   int              len  = 0;

   /*------------------------------------------------------------------------
    * sanity checks
    *------------------------------------------------------------------------*/
   STP_ASSERT(pkt);
   if(mstp_isMstBpdu(pkt) == FALSE)
   {/* wrong BPDU type */
      STP_ASSERT(0);
      return NULL;
   }
   bpdu = (MSTP_MST_BPDU_t *)(pkt->data);
   len  = MSTP_MSTI_CFG_MSGS_SIZE(bpdu);
   if(len == 0)
      return NULL;

   STP_ASSERT(len/sizeof(MSTP_MSTI_CONFIG_MSG_t) <= 64);

   if(current == NULL)
      current = (MSTP_MSTI_CONFIG_MSG_t *) bpdu->mstiConfigMsgs;
   else
   {
      char *end = (char*)bpdu->mstiConfigMsgs + len;

      STP_ASSERT(((char*)current >= (char*)bpdu->mstiConfigMsgs) &&
             ((char*)current < end));

      current++;
      current = ((char*)current >= end) ? NULL : current;
   }

   return current;
}

/**PROC+**********************************************************************
 * Name:      mstp_disableLearning
 *
 * Purpose:   This procedure causes the Learning Process to stop learning
 *            from the source address of frames received on the Port.
 *            (802.1Q-REV/D5.0 13.26 b); 802.1D-2004 17.21.4)
 *
 * Params:    mstid  -> MST Instance Identifier (the CIST or an MSTI)
 *            lport  -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_disableLearning(MSTID_t mstid, LPORT_t lport)
{
   /*-----------------------------------------------------------------------
    * there are no actions defined to perform on the switch for this case
    *-----------------------------------------------------------------------*/
}

/**PROC+**********************************************************************
 * Name:      mstp_enableLearning
 *
 * Purpose:   This procedure causes the Learning Process to start learning
 *            from frames received on the Port.
 *            (802.1Q-REV/D5.0 13.26 e); 802.1D-2004 17.21.6)
 *
 * Params:    mstid  -> MST Instance Identifier (the CIST or an MSTI)
 *            lport  -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_enableLearning(MSTID_t mstid, LPORT_t lport)
{
   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));

   mstp_updtMstiPortStateChgMsg(mstid, lport, MSTP_ACT_ENABLE_LEARNING);
   MSTP_MSTI_PORT_STATUS_PRINTF(mstid, lport, MSTP_PORT_STATE_ON_TREE_FMT,
                                "<ENABLE LRN>",MSTP_LRN_SYM, mstid, lport);
}

/**PROC+**********************************************************************
 * Name:      mstp_enableForwarding
 *
 * Purpose:   This procedure causes the Forwarding Process to start
 *            forwarding frames through the Port.
 *            (802.1Q-REV/D5.0 13.26 d); 802.1D-2004 17.21.5)
 *            It stores state information of the 'lport' on the given 'mstid'
 *            in global port state changes collector for further distribution
 *            of this information troughout the system.
 *
 * Params:    mstid  -> MST Instance Identifier
 *            lport  -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_enableForwarding(MSTID_t mstid, LPORT_t lport)
{
   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));

   mstp_updtMstiPortStateChgMsg(mstid, lport, MSTP_ACT_ENABLE_FORWARDING);
   MSTP_MSTI_PORT_STATUS_PRINTF(mstid, lport, MSTP_PORT_STATE_ON_TREE_FMT,
                                "<ENABLE FWD>", MSTP_FWD_SYM, mstid, lport);
   if(mstid == MSTP_CISTID)
   {
      STP_ASSERT(MSTP_CIST_PORT_PTR(lport));
      MSTP_CIST_PORT_PTR(lport)->forwardTransitions++;
      MSTP_CIST_PORT_PTR(lport)->forwardTransitionsLastUpdated =
                                                         time(NULL);
   }
   else
   {
      STP_ASSERT(MSTP_MSTI_PORT_PTR(mstid, lport));
      MSTP_MSTI_PORT_PTR(mstid, lport)->forwardTransitions++;
      MSTP_MSTI_PORT_PTR(mstid, lport)->forwardTransitionsLastUpdated =
                                                         time(NULL);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_disableForwarding
 *
 * Purpose:   This procedure causes the Forwarding Process to stop forwarding
 *            frames through the Port.
 *            (802.1Q-REV/D5.0 13.26 b); 802.1D-2004 17.21.3)
 *
 * Params:    mstid  -> MST Instance Identifier (the CIST or an MSTI)
 *            lport  -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_disableForwarding(MSTID_t mstid, LPORT_t lport)
{
   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));

   mstp_updtMstiPortStateChgMsg(mstid, lport, MSTP_ACT_DISABLE_FORWARDING);
   MSTP_MSTI_PORT_STATUS_PRINTF(mstid, lport, MSTP_PORT_STATE_ON_TREE_FMT,
                                "<DISABLE FWD>", MSTP_NO_FWD_SYM, mstid, lport);
}
/**PROC+**********************************************************************
 * Name:      mstp_flush
 *
 * Purpose:   Flushes (i.e., removes) all Dynamic Filtering Entries in the
 *            Filtering Database that contain information learned on the lport
 *            on the given Spanning Tree.
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_flush(MSTID_t mstid, LPORT_t lport)
{
   MSTP_TREE_MSG_t *m;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));

   m = mstp_findMstiPortStateChgMsg(mstid);
   if(m == NULL)
   {
       m = calloc(1, sizeof(MSTP_TREE_MSG_t));
       if (!m)
       {
           STP_ASSERT(0);
           return;
       }
      m->mstid        = mstid;
      m->link.q_flink = NULL;
      m->link.q_blink = NULL;
      insqti_nodis(&MSTP_TREE_MSGS_QUEUE, &m->link);
   }

   set_port(&m->portsMacAddrFlush, lport);
   MSTP_MSTI_PORT_FLUSH_PRINTF(mstid, lport, MSTP_PORT_STATE_ON_TREE_FMT,
                               "<MAC ADDR FLUSH>", MSTP_FLUSH_SYM,
                               mstid, lport);

}
/**PROC+**********************************************************************
 * Name:     mstp_noStpPropagatePortUpState
 *
 * Purpose:  This function propagates the 'Up' event for the 'lport'
 *           throughout the system when administrative state of the MSTP
 *           protocol is set to 'disabled', i.e. switch is not a Spanning Tree
 *           Bridge.
 *
 * Params:   lport  -> logical port number
 *
 * Returns:  none
 *
 * Globals:  mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_noStpPropagatePortUpState(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr;
   STP_ASSERT(MSTP_ENABLED == FALSE);
   STP_ASSERT(IS_VALID_LPORT(lport));
   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   if(!commPortPtr)
   {
        return;
   }
   commPortPtr->adminPointToPointMAC = MSTP_ADMIN_PPMAC_AUTO;
   if(mstp_portDuplexModeDetect(lport) == FULL_DUPLEX)
   {
       MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap,
               MSTP_PORT_OPER_POINT_TO_POINT_MAC);
   }
   else
   {
       MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap,
               MSTP_PORT_OPER_POINT_TO_POINT_MAC);
   }

   mstp_updtMstiPortStateChgMsg(MSTP_NON_STP_BRIDGE, lport,
                                MSTP_ACT_PROPAGATE_UP);
   MSTP_PORT_STATUS_PRINTF(lport, MSTP_PORT_STATE_FMT, "<PORT UP EVT>",
                           MSTP_ENBL_SYM, lport);
}

/**PROC+**********************************************************************
 * Name:     mstp_noStpPropagatePortDownState
 *
 * Purpose:  This function propagates the 'Down' event for the 'lport'
 *           throughout the system when administrative state of the MSTP
 *           protocol is set to 'disabled', i.e. switch is not a Spanning Tree
 *           Bridge.
 *
 * Params:   lport  -> logical port number
 *
 * Returns:  none
 *
 * Globals:  mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_noStpPropagatePortDownState(LPORT_t lport)
{
   STP_ASSERT(MSTP_ENABLED == FALSE);
   STP_ASSERT(IS_VALID_LPORT(lport));

   mstp_updtMstiPortStateChgMsg(MSTP_NON_STP_BRIDGE, lport,
                                MSTP_ACT_PROPAGATE_DOWN);
   MSTP_PORT_STATUS_PRINTF(lport, MSTP_PORT_STATE_FMT,
                           "<PORT DOWN EVT>", MSTP_DSBL_SYM, lport);
}

/**PROC+**********************************************************************
 * Name:     mstp_rcvdAnyMsgCondition
 *
 * Purpose:  Check if 'rcvdMsg' condition is met for a given Port.
 *           (802.1Q-REV/D5.0 13.25.11)
 *
 * Params:   lport  -> logical port number
 *
 * Returns:  TRUE for a given Port if 'rcvdMsg' is TRUE for the CIST or any
 *           MSTI for that Port, FALSE otherwise.
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
bool
mstp_rcvdAnyMsgCondition(LPORT_t lport)
{
   bool                   res = FALSE;
   MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

   STP_ASSERT(cistPortPtr);
   if(MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap, MSTP_CIST_PORT_RCVD_MSG))
   {
      res = TRUE;
   }
   else
   {
      MSTID_t mstid;

      for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
      {
         if(MSTP_MSTI_VALID(mstid))
         {
            MSTP_MSTI_PORT_INFO_t *mstiPortPtr =
                                              MSTP_MSTI_PORT_PTR(mstid, lport);

            STP_ASSERT(mstiPortPtr);
            if(mstiPortPtr &&
               MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                         MSTP_MSTI_PORT_RCVD_MSG))
            {
               res = TRUE;
               break;
            }
         }
      }
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:     mstp_isOldRootPropagation
 *
 * Purpose:  Check if received BPDU contains the obsolete Root Information
 *           for the given instance of spanning tree, if so then set
 *           Message Age and/or Remaining hops in port's message priority
 *           vector to their extreme values in order to speed up aging of
 *           the stale information
 *
 * Params:   mstid     -> MST Instance ID (the CIST or an MSTI)
 *           lport     -> logical port number
 *           bpdu      -> received BPDU
 *           cfgMsgPtr -> MSTI configuration Message
 *
 * Returns:   TRUE if Root Information in the received packet is obsolete
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 **PROC-**********************************************************************/
static bool
mstp_isOldRootPropagation(MSTID_t mstid, LPORT_t lport, MSTP_MST_BPDU_t *bpdu,
                          MSTP_MSTI_CONFIG_MSG_t *cfgMsgPtr, bool bpduSameRgn)
{
   bool res = FALSE;

   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));
   STP_ASSERT((mstid == MSTP_CISTID) ? (bpdu != NULL) : (cfgMsgPtr != NULL));

   if(mstid == MSTP_CISTID)
   {/* BPDU is being processed by the CIST (instance 0) */
      MSTP_CIST_PORT_INFO_t *cistPortPtr = NULL;
      MSTP_CIST_MSG_TIMES_t *msgTimesPtr = NULL;

      cistPortPtr = MSTP_CIST_PORT_PTR(lport);
      STP_ASSERT(cistPortPtr);
      msgTimesPtr = &cistPortPtr->msgTimes;
      if(bpduSameRgn)
      {/* BPDU comes from a Bridge located within same region */
         if(MAC_ADDRS_EQUAL(bpdu->cistRgnRootId.mac_address,
                            MSTP_CIST_BRIDGE_IDENTIFIER.mac_address))
         {
            if(getShortFromPacket(&bpdu->cistRgnRootId.priority) !=
               MSTP_CIST_BRIDGE_IDENTIFIER.priority)
            {/* Received BPDU points to this switch as being the Regional Root
              * Bridge while this Bridge's priority is different from what is
              * in BPDU */
               msgTimesPtr->hops = 0;
               res = TRUE;
            }
            else
            if(!MAC_ADDRS_EQUAL(bpdu->cistRootId.mac_address,
                                MSTP_CIST_ROOT_PRIORITY.rootID.mac_address))
            {/* Received BPDU points to this switch as being the Regional Root
              * Bridge while the CIST Root Bridge known on this switch is
              * different from what is in BPDU
              * NOTE1: within the Region the Regional Root Bridge tells others
              *       who is the CIST Root Bridge
              * NOTE2: the CIST Root Bridge located within region is the
              *        Regional Root Bridge at the same time */
               msgTimesPtr->messageAge = msgTimesPtr->maxAge;
               msgTimesPtr->hops = 0;
               res = TRUE;
            }
         }
      }
      else
      {/* BPDU comes from a Bridge located outside of this Bridge's region */
         if(MAC_ADDRS_EQUAL(bpdu->cistRootId.mac_address,
                            MSTP_CIST_BRIDGE_IDENTIFIER.mac_address) &&
            (getShortFromPacket(&bpdu->cistRootId.priority) !=
             MSTP_CIST_BRIDGE_IDENTIFIER.priority))
         {/* Received BPDU points to this switch as being the CIST Root
           * Bridge while this Bridge's priority is different from what is
           * in BPDU */
            msgTimesPtr->messageAge = msgTimesPtr->maxAge;
            res = TRUE;
         }
      }
   }
   else
   {/* MSTI Configuration Message located inside of the received BPDU is being
     * processed by MST Instance */
      STP_ASSERT(bpduSameRgn);
      if(MAC_ADDRS_EQUAL(cfgMsgPtr->mstiRgnRootId.mac_address,
                         MSTP_MSTI_BRIDGE_IDENTIFIER(mstid).mac_address) &&
         (getShortFromPacket(&cfgMsgPtr->mstiRgnRootId.priority) !=
          MSTP_MSTI_BRIDGE_IDENTIFIER(mstid).priority))
      {/* Received message points to this switch as being the Regional Root
        * Bridge while this Bridge's priority is different from what is
        * in the message */
         MSTP_MSTI_PORT_INFO_t *mstiPortPtr = NULL;
         MSTP_MSTI_MSG_TIMES_t *msgTimesPtr = NULL;

         mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
         STP_ASSERT(mstiPortPtr);
         msgTimesPtr = &mstiPortPtr->msgTimes;
         msgTimesPtr->hops = 0;
         res = TRUE;
      }
   }

   return res;
}
/**PROC+**********************************************************************
 * Name:     mstp_preventTxOnBridge
 *
 * Purpose:  Postpone any BPDU transmissions on the Bridge (for all ports
 *           for all Trees). We use global 'preventTx' bool variable
 *           to indicate whether or not BPDU transmission is allowed on
 *           this Bridge. This function is a counterpart to the
 *           'mstp_doPendingTxOnBridge' function.
 *
 * Params:   none
 *
 * Returns:  none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_preventTxOnBridge(void)
{
   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(mstp_Bridge.preventTx == FALSE);
   mstp_Bridge.preventTx = TRUE;
}

/**PROC+**********************************************************************
 * Name:     mstp_doPendingTxOnBridge
 *
 * Purpose:  Call PTX SM for all ports that have pending BDPU transmissions.
 *           This function is a counterpart to the 'mstp_preventTxOnBridge'
 *           function.
 *
 * Params:   none
 *
 * Returns:  none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_doPendingTxOnBridge(void)
{
   LPORT_t                lport;
   MSTP_COMM_PORT_INFO_t *commPortPtr;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(mstp_Bridge.preventTx == TRUE);

   mstp_Bridge.preventTx = FALSE;

   for(lport = 1; lport <= MAX_LPORTS; lport++)
   {
      commPortPtr = MSTP_COMM_PORT_PTR(lport);
      if(commPortPtr)
      {
         if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                      MSTP_PORT_NEW_INFO) ||
            MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                      MSTP_PORT_NEW_INFO_MSTI))
         {
            mstp_ptxSm(lport);
         }
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_buildMstConfigurationDigest
 *
 * Purpose:   This function creates the HMAC-MD5 Configuration Digest
 *            from the content of MST Configuration Table.
 *            NOTE: For the purposes of calculating the Configuration Digest,
 *                  the MST Configuration Table (see picture below) is
 *                  considered to contain 4096 consecutive two octet elements,
 *                  where each element of the table (with the exception of the
 *                  first and last) contains an MSTID value encoded as a binary
 *                  number, with the first octet being most significant. The
 *                  first element of the table contains the value 0, the second
 *                  element the MSTID value corresponding to VID 1, the third
 *                  element the MSTID value corresponding to VID 2, and so on,
 *                  with the next to last element of the table containing the
 *                  MSTID value corresponding to VID 4094, and the last element
 *                  containing the value 0.
 *                  (802.1Q-REV/D5.0 13.7)
 *
 *            |<- 2 octets ->|
 *            +---------------+ - MST Configuration Table
 *            |  0x0000       |
 *            +---------------+
 *            +---------------+
 *            |  MSTID value  | <- vid 1
 *            +---------------+
 *            .................
 *            +---------------+
 *            |  MSTID value  | <- vid 4094
 *            +---------------+
 *            +---------------+
 *            |  0x0000       |
 *            +---------------+
 *
 * Params:    resDigest -> points to the place where to store the result
 *                         (configuration digest).
 *
 * Returns:   none
 *
 * Globals:   mstp_DigestSignatureKey
 *
 **PROC-**********************************************************************/
void
mstp_buildMstConfigurationDigest(uint8_t *resDigest)
{
   uint8_t   digest[MSTP_DIGEST_SIZE]; /* 16 bytes */
   char     digest_str[200] = {0};
   char temp[10]= {0};
   MSTID_t *mstCfgTable;
   VID_t    vid;
   MSTID_t  mstid;
   int      mstCfgTableSize;
   uint32_t i = 0;
   const struct ovsrec_bridge *bridge_row = NULL;
   struct ovsdb_idl_txn *txn = NULL;
   struct smap smap = SMAP_INITIALIZER(&smap);
   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(resDigest);
   STP_ASSERT(MSTP_DIGEST_SIZE == 16);
   MSTP_OVSDB_LOCK;
   txn = ovsdb_idl_txn_create(idl);
   bridge_row = ovsrec_bridge_first(idl);

   /*------------------------------------------------------------------------
    * allocate buffer big enough to accomodate MST Configuration Table.
    *------------------------------------------------------------------------*/
   STP_ASSERT(sizeof(MSTID_t) == MSTP_MST_CFG_ELEM_SIZE);
   mstCfgTableSize = MSTP_MST_CFG_TBL_SIZE * MSTP_MST_CFG_ELEM_SIZE;
   mstCfgTable = (MSTID_t *) calloc(1, mstCfgTableSize);
   if (!mstCfgTable)
   {
       ovsdb_idl_txn_destroy(txn);
       MSTP_OVSDB_UNLOCK;
       STP_ASSERT(0);
       return;
   }


   /*------------------------------------------------------------------------
    * build contents of the MST Configuration Table
    *------------------------------------------------------------------------*/
   for(vid = MSTP_MST_CFG_TBL_FIRST_VID_IDX;
       vid <= MSTP_MST_CFG_TBL_LAST_VID_IDX; vid++)
   {
          if((mstid = mstp_getMstIdForVid(vid)) != MSTP_NO_MSTID)
          {
               {
		   /* MSTP digest is calculated only on Primary/Normal VLAN*/
                   mstCfgTable[vid] = htons(mstid);
	       }

          }
   }

   /*------------------------------------------------------------------------
    * calculate the digest value
    * NOTE: 'hmac_md5_calc' always returns 16 bytes digest value
    *------------------------------------------------------------------------*/
   memset(digest, 0, sizeof(digest));
   hmac_md5((unsigned char*) mstCfgTable, mstCfgTableSize,
                 (uint8_t*)mstp_DigestSignatureKey, MSTP_DIGEST_KEY_LEN, digest);
   for(i=0; i< MSTP_DIGEST_SIZE; i++)
   {
      snprintf(temp,10,"%.2X",digest[i]);
      strncat(digest_str,temp,10);
   }
   smap_clone(&smap, &bridge_row->status);
   smap_replace(&smap, "mstp_config_digest" , digest_str);
   ovsrec_bridge_set_status(bridge_row, &smap);
   VLOG_DBG("Config Digest : %s",digest_str);

   /*------------------------------------------------------------------------
    * copy result
    *------------------------------------------------------------------------*/
   memcpy(resDigest, digest, sizeof(digest));

   /*------------------------------------------------------------------------
    * free memory used
    *------------------------------------------------------------------------*/
   free(mstCfgTable);
   ovsdb_idl_txn_commit_block(txn);
   ovsdb_idl_txn_destroy(txn);
   smap_destroy(&smap);
   MSTP_OVSDB_UNLOCK;
}

/**PROC+**********************************************************************
 * Name:      mstp_getMyMstConfigurationId
 *
 * Purpose:   This function returns MST Configuration Identification information
 *            configured for this Bridge.
 *
 * Params:    mstCfgId  -> pointer to the place holder to where put the result
 *
 * Returns:   none
 *
 * Globals:   mstp_CB, mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_getMyMstConfigurationId(MSTP_MST_CONFIGURATION_ID_t *mstCfgId)
{
   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(mstCfgId);

   mstCfgId->formatSelector = mstp_Bridge.MstConfigId.formatSelector;
   memcpy(mstCfgId->configName, mstp_Bridge.MstConfigId.configName,
          MSTP_MST_CONFIG_NAME_LEN);
   mstCfgId->revisionLevel = mstp_Bridge.MstConfigId.revisionLevel;
   memcpy(mstCfgId->digest, mstp_Bridge.MstConfigId.digest, MSTP_DIGEST_SIZE);
}

/**PROC+**********************************************************************
 * Name:      mstp_getConfigurationDigestStr
 *
 * Purpose:   This function returns MST Configuration Digest hexadecimal value
 *            being represented as the text string
 *            (e.g. "0xAC36177F50283CD4B83821D8AB26DE62")
 *
 * Params:    buf    -> pointer to the buffer where put the result
 *            bufLen -> the length of the result buffer
 *
 * Returns:   none
 *
 * Globals:   mstp_CB, mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
void
mstp_getMstConfigurationDigestStr(char *buf, int bufLen)
{
   uint8_t *dgPtr;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(buf);
   STP_ASSERT(MSTP_DIGEST_SIZE == 16);
   STP_ASSERT(bufLen >= 2 + MSTP_DIGEST_SIZE*2 + 1);
   dgPtr = mstp_Bridge.MstConfigId.digest;
   memset(buf, 0, bufLen);
   sprintf(buf,
           "0x%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X",
           dgPtr[0], dgPtr[1], dgPtr[2], dgPtr[3], dgPtr[4], dgPtr[5], dgPtr[6],
           dgPtr[7], dgPtr[8], dgPtr[9], dgPtr[10],dgPtr[11],dgPtr[12],
           dgPtr[13],dgPtr[14],dgPtr[15]);

}

/**PROC+**********************************************************************
 * Name:      mstp_getMstIdForVlan
 *
 * Purpose:   This function returns MST Instance Identifier to which given
 *            'vlan' is mapped to.
 *
 * Params:    vlan  -> VLAN number in question
 *
 * Returns:   MST Instance Identifier the given 'vlan' is mapped to
 *
 * Globals:   mstp_MstiVlanTable
 *
 * Constraints:
 **PROC-**********************************************************************/
MSTID_t
mstp_getMstIdForVlan(VID_t vlan)
{
   MSTID_t mstid = MSTP_NO_MSTID;
   VID_t   vid = 0;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(IS_VALID_VID(vid));
   if(IS_VALID_VID(vid))
      mstid = mstp_getMstIdForVid(vid);

   return mstid;
}

/**PROC+**********************************************************************
 * Name:      mstp_validateBpdu
 *
 * Purpose:   Validation of received BPDUs
 *            (802.1Q-REV/D5.0 14.4)
 *
 * Params:    pkt -> pointer to the packet buffer with BPDU in
 *
 * Returns:   TRUE if BPDU is valid, FALSE otherwise
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
bool
mstp_validateBpdu(MSTP_RX_PDU *pkt)
{
   bool res = FALSE;

   STP_ASSERT(pkt);

   /*------------------------------------------------------------------------
    * perform test 14.4 e)
    *------------------------------------------------------------------------*/
   if(mstp_isMstBpdu(pkt))
   {
      res = TRUE;
   }
   /*------------------------------------------------------------------------
    * perform tests 14.4 c)-d)
    *------------------------------------------------------------------------*/
   else if(mstp_isRstBpdu(pkt))
   {
      res = TRUE;
   }
   /*------------------------------------------------------------------------
    * perform test 14.4 a)
    *------------------------------------------------------------------------*/
   else if(mstp_isStpConfigBpdu(pkt))
   {
      res = TRUE;
   }
   /*------------------------------------------------------------------------
    * perform test 14.4 b)
    *------------------------------------------------------------------------*/
   else if(mstp_isStpTcnBpdu(pkt))
   {
      res = TRUE;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_betterOrSameInfo
 *
 * Purpose:   Returns TRUE if, for a given Port and Tree (CIST, or MSTI),
 *            either
 *            a) The procedure's parameter 'newInfoIs' is 'Received',
 *               and 'infoIs' is 'Received' and the 'msgPriority' vector
 *               is better than or the same as the 'portPriority'
 *               vector; or,
 *            b) The procedure's parameter 'newInfoIs' is 'Mine',
 *               and 'infoIs' is 'Mine' and the 'designatedPriority' vector
 *               is better than or the same as the 'portPriority'
 *               vector.
 *            Returns False otherwise.
 *            NOTE: This procedure is not invoked (in the case of a MSTI) if
 *                  the received BPDU carrying the MSTI information was
 *                  received from another MST Region. In that event, the
 *                  Port Receive Machine (using setRcvdMsgs()) does not set
 *                  'rcvdMsg' for any MSTI, and the Port Information Machine's
 *                  SUPERIOR_DESIGNATED state is not entered.
 *            Called from Port Information (PIM) state machine.
 *            (802.1Q-REV/D5.0 13.26 g); 13.26.1)
 *
 * Params:    mstid     -> MST Instance Identifier (the CIST or an MSTI)
 *            lport     -> logical port number
 *            newInfoIs -> the new origin/state of the port's STP information
 *                         to be held in 'infoIs' variable
 *
 * Returns:   TRUE or FALSE (see above description)
 *
 * Globals:   mstp_CB
 *
 **PROC-**********************************************************************/
bool
mstp_betterOrSameInfo(MSTID_t mstid, LPORT_t lport, MSTP_INFO_IS_t newInfoIs)
{
   bool           res = FALSE;
   MSTP_INFO_IS_t infoIs;

   STP_ASSERT(IS_VALID_LPORT(lport));
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT((newInfoIs == MSTP_INFO_IS_RECEIVED) ||
          (newInfoIs == MSTP_INFO_IS_MINE));

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t         *cistPortPtr     = NULL;
      MSTP_CIST_BRIDGE_PRI_VECTOR_t *firstPriVecPtr  = NULL;
      MSTP_CIST_BRIDGE_PRI_VECTOR_t *secondPriVecPtr = NULL;

      cistPortPtr   = MSTP_CIST_PORT_PTR(lport);
      STP_ASSERT(cistPortPtr);
      infoIs        = cistPortPtr->infoIs;

      if((newInfoIs == MSTP_INFO_IS_RECEIVED) &&
         (infoIs == MSTP_INFO_IS_RECEIVED))
      {/* Check if 'msgPriority' vector is better than or same as
        * 'portPriority' vector */
         firstPriVecPtr  = &cistPortPtr->msgPriority;
         secondPriVecPtr = &cistPortPtr->portPriority;
         res = !(mstp_cistPriorityVectorsCompare(firstPriVecPtr,
                                                 secondPriVecPtr) > 0);
      }
      else if((newInfoIs == MSTP_INFO_IS_MINE) &&
              (infoIs == MSTP_INFO_IS_MINE))
      {/* Check if 'designatedPriority' vector is better than or same as
        * 'portPriority' vector */
         firstPriVecPtr  = &cistPortPtr->designatedPriority;
         secondPriVecPtr = &cistPortPtr->portPriority;
         res = !(mstp_cistPriorityVectorsCompare(firstPriVecPtr,
                                                 secondPriVecPtr) > 0);
      }
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t         *mstiPortPtr     = NULL;
      MSTP_MSTI_BRIDGE_PRI_VECTOR_t *firstPriVecPtr  = NULL;
      MSTP_MSTI_BRIDGE_PRI_VECTOR_t *secondPriVecPtr = NULL;

      mstiPortPtr   = MSTP_MSTI_PORT_PTR(mstid, lport);
      STP_ASSERT(mstiPortPtr);
      infoIs        = mstiPortPtr->infoIs;

      if((newInfoIs == MSTP_INFO_IS_RECEIVED) &&
         (infoIs == MSTP_INFO_IS_RECEIVED))
      {/* Check if 'msgPriority' vector is better than or same as
        * 'portPriority' vector */

         /* On receive this function should be called only for an MSTI port
          * located inside of MST Region */
         STP_ASSERT(MSTP_COMM_PORT_PTR(lport) &&
                MSTP_COMM_PORT_IS_BIT_SET(MSTP_COMM_PORT_PTR(lport)->bitMap,
                                          MSTP_PORT_RCVD_INTERNAL));

         firstPriVecPtr  = &mstiPortPtr->msgPriority;
         secondPriVecPtr = &mstiPortPtr->portPriority;
         res = !(mstp_mstiPriorityVectorsCompare(firstPriVecPtr,
                                                 secondPriVecPtr) > 0);
      }
      else if((newInfoIs == MSTP_INFO_IS_MINE) &&
              (infoIs == MSTP_INFO_IS_MINE))
      {/* Check if 'designatedPriority' vector is better than or same as
        * 'portPriority' vector */
         firstPriVecPtr  = &mstiPortPtr->designatedPriority;
         secondPriVecPtr = &mstiPortPtr->portPriority;
         res = !(mstp_mstiPriorityVectorsCompare(firstPriVecPtr,
                                                 secondPriVecPtr) > 0);
      }
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_clearAllRcvdMsgs
 *
 * Purpose:   Clears 'rcvdMsg' for the CIST and all MSTIs, for this Port.
 *            (802.1Q-REV/D5.0 13.26.2)
 *            Called from Port Receive (PRX) state machine.
 *
 * Params:    lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_CB, mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_clearAllRcvdMsgs(LPORT_t lport)
{
   MSTID_t mstid;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(IS_VALID_LPORT(lport));

   /*------------------------------------------------------------------------
    * clear 'rcvdMsg' flag for the CIST for this port
    *------------------------------------------------------------------------*/
   if(MSTP_CIST_PORT_PTR(lport))
   {
      MSTP_CIST_PORT_CLR_BIT(MSTP_CIST_PORT_PTR(lport)->bitMap,
                             MSTP_CIST_PORT_RCVD_MSG);
   }

   /*------------------------------------------------------------------------
    * clear 'rcvdMsg' flag for all MSTIs for this port
    *------------------------------------------------------------------------*/
   for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_MSTID_MAX; mstid++)
   {
      if(MSTP_MSTI_VALID(mstid) && MSTP_MSTI_PORT_PTR(mstid, lport))
      {
         MSTP_MSTI_PORT_CLR_BIT(MSTP_MSTI_PORT_PTR(mstid, lport)->bitMap,
                                MSTP_MSTI_PORT_RCVD_MSG);
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_updtBPDUVersion
 *
 * Purpose:   Sets 'rcvdSTP' TRUE if the BPDU received is a version 0 or
 *            version 1 TCN or a Config BPDU.
 *            Sets 'rcvdRSTP' TRUE if the received BPDU is a RSTP BPDU or a
 *            MST BPDU.
 *            (802.1Q-REV-D5.0 13.26.21)
 *            Called from Port Receive (PRX) state machine.
 *
 * Params:    pkt   -> pointer to the packet buffer with received BPDU in
 *            lport -> logical port number the BPDU came on
 *
 * Returns:   none
 *
 * Globals:   mstp_CB, mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_updtBPDUVersion(MSTP_RX_PDU *pkt, LPORT_t lport)
{
   MSTP_BPDU_COMMON_HEADER_t *bpdu        = NULL;
   MSTP_COMM_PORT_INFO_t     *commPortPtr = NULL;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(pkt);
   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   bpdu = (MSTP_BPDU_COMMON_HEADER_t *)(pkt->data);

   if((bpdu->protocolVersionId < MSTP_PROTOCOL_VERSION_ID_RST) &&
      ((bpdu->bpduType == MSTP_BPDU_TYPE_STP_TCN) ||
       (bpdu->bpduType == MSTP_BPDU_TYPE_STP_CONFIG)))
   {/* version is 0 or 1 and BPDU is TCN or Config BPDU */
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_RCVD_STP);
   }
   else if((bpdu->protocolVersionId >= MSTP_PROTOCOL_VERSION_ID_RST) &&
           (bpdu->bpduType == MSTP_BPDU_TYPE_RST))
   {/* received BPDU is a RSTP or a MST BPDU */
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_RCVD_RSTP);
   }
   else
      STP_ASSERT(0);
}

/**PROC+**********************************************************************
 * Name:      mstp_clearReselectTree
 *
 * Purpose:   Clears 'reselect' for the tree (the CIST or a given MSTI) for
 *            all Ports of the Bridge.
 *            (802.1Q-REV/D5.0 13.26 h); 13.26.3)
 *            Called from Port Role Selection (PRS) state machine.
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *
 * Returns:   none
 *
 * Globals:   mstp_CB, mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_clearReselectTree(MSTID_t mstid)
{

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));

   if(MSTP_ENABLED)
   {
      if(mstid == MSTP_CISTID)
      {/* clear 'reselect' flag for the CIST for all ports */
         LPORT_t                lport;
         MSTP_CIST_PORT_INFO_t *cistPortPtr;

         for(lport = 1; lport <= MAX_LPORTS; lport++)
         {
            cistPortPtr = MSTP_CIST_PORT_PTR(lport);
            if(cistPortPtr)
            {
               MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap,
                                      MSTP_CIST_PORT_RESELECT);
            }
         }
      }
      else
      {/* clear 'reselect' flag for the given MSTI for all ports */
         LPORT_t                lport;
         MSTP_MSTI_PORT_INFO_t *mstiPortPtr;

         for(lport = 1; lport <= MAX_LPORTS; lport++)
         {
            mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
            if(mstiPortPtr)
            {
               MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap,
                                      MSTP_MSTI_PORT_RESELECT);
            }
         }
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_fromSameRegion
 *
 * Purpose:   Returns TRUE if 'rcvdRSTP' is TRUE, and the received BPDU
 *            conveys an MST Configuration Identifier that matches that held
 *            for the Bridge. Returns FALSE otherwise.
 *            (802.1Q-REV/D5.0 13.26.4)
 *            Called from Port Receive (PRX) state machine.
 *
 * Params:    pkt   -> pointer to the packet buffer with BPDU in
 *            lport -> logical port number a BPDU was received on
 *
 * Returns:   TRUE if received BPDU was originated by a Bridge that belongs
 *            to the same MST Region that this Bridge, FALSE otherwise.
 *
 * Globals:   mstp_CB, mstp_Bridge
 *
 **PROC-**********************************************************************/
bool
mstp_fromSameRegion(MSTP_RX_PDU *pkt, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = NULL;
   bool                   res         = FALSE;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(pkt);
   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   /* When Force Protocol Version parameter of the MSTP Bridge is set to STP or
    * RSTP such Bridge must emulate behaviour of one of these earlier versions
    * of protocol on all Bridge's ports, i.e. operate as a single spanning tree
    * (SST) Bridge. By definition, any SST Bridge is unaware of MST Regions, so
    * all received BPDUs are treated as being from a different MST Region.
    * (802.1Q-REV/D5.0 13.6.2 c)) */
   if((mstp_Bridge.ForceVersion == MSTP_PROTOCOL_VERSION_ID_STP) ||
      (mstp_Bridge.ForceVersion == MSTP_PROTOCOL_VERSION_ID_RST))
   {
      return FALSE;
   }

   if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_RCVD_RSTP) &&
      (mstp_isMstBpdu(pkt) == TRUE) &&
      (mstp_isNeighboreBridgeInMyRegion(pkt) == TRUE))
   {
      res = TRUE;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_newTcWhile
 *
 * Purpose:   If the value of 'tcWhile' is zero and 'sendRSTP' is TRUE,
 *            this procedure sets the value of 'tcWhile' to 'HelloTime' plus
 *            one second and sets either 'newInfo' TRUE for the CIST,
 *            or 'newInfoMsti' TRUE for a given MSTI. The value of 'HelloTime'
 *            is taken from the CIST's 'portTimes' parameter (13.24.13) for
 *            this Port. If the value of 'tcWhile' is zero and 'sendRSTP' is
 *            FALSE, this procedure sets the value of 'tcWhile' to the sum
 *            of the Max Age and Forward Delay components of 'rootTimes' and
 *            does not change the value of either 'newInfo' or 'newInfoMsti'.
 *            Otherwise the procedure takes no action.
 *            (802.1Q-REV/D5.0 13.26 i); 13.26.5).
 *            Called from Topology Change (TCM) state machine.
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_newTcWhile(MSTID_t mstid, LPORT_t lport)
{
   uint16_t tcWhileVal = 0;
   struct ovsdb_idl_txn *txn = NULL;
   MSTP_OVSDB_LOCK;
   txn = ovsdb_idl_txn_create(idl);
   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(IS_VALID_LPORT(lport));
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(MSTP_INSTANCE_IS_VALID(mstid));
   STP_ASSERT(MSTP_COMM_PORT_PTR(lport));
   STP_ASSERT((mstid == MSTP_CISTID) ? (MSTP_CIST_PORT_PTR(lport) != NULL) :
                                   (MSTP_MSTI_PORT_PTR(mstid, lport) != NULL));

   /*------------------------------------------------------------------------
    * Get current value of the 'tcWhile' timer
    *------------------------------------------------------------------------*/
   tcWhileVal = (mstid == MSTP_CISTID) ?
                 MSTP_CIST_PORT_PTR(lport)->tcWhile :
                 MSTP_MSTI_PORT_PTR(mstid, lport)->tcWhile;

   /*------------------------------------------------------------------------
    * If current value of the 'tcWhile' timer is zero than compute a new value
    * and apply it to the port for the given Tree (the CIST or an MSTI)
    *------------------------------------------------------------------------*/
   if(tcWhileVal == 0)
   {
      if(MSTP_COMM_PORT_IS_BIT_SET(MSTP_COMM_PORT_PTR(lport)->bitMap,
                                   MSTP_PORT_SEND_RSTP))
      {/* 'tcWhile' is zero and 'sendRSTP' is TRUE,
        * set the value of 'tcWhile' to 'HelloTime' plus one second and
        * set either 'newInfo' TRUE for the CIST, or 'newInfoMsti' TRUE
        * for a given MSTI */

         /* The value of 'HelloTime' is taken from the CIST's 'portTimes'
          * parameter for this Port.*/
         tcWhileVal = MSTP_CIST_PORT_PTR(lport)->portTimes.helloTime + 1;
         MSTP_COMM_PORT_SET_BIT(MSTP_COMM_PORT_PTR(lport)->bitMap,
                                (mstid == MSTP_CISTID) ?
                                 MSTP_PORT_NEW_INFO :
                                 MSTP_PORT_NEW_INFO_MSTI);
      }
      else
      {/* 'tcWhile' is zero and 'sendRSTP' is FALSE,
        * set the value of 'tcWhile' to the sum of the Max Age and
        * Forward Delay components of 'rootTimes' and do not change
        * the value of either 'newInfo' or 'newInfoMsti' */
         tcWhileVal = MSTP_CIST_ROOT_TIMES.maxAge +
                      MSTP_CIST_ROOT_TIMES.fwdDelay;
      }

      /*---------------------------------------------------------------------
       * Apply new value of 'tcWhile' timer to the given port for the given
       * Tree and update Topology Change Count and Time Since Topology Change
       * statistics MIB objects.
       * NOTE1: Time Since Topology Change - count in seconds of the time
       *        elapsed since tcWhile was last non-zero for any Port
       *        for the given MSTI.
       *       (802.1Q-REV/D5.0 12.8.1.2.3 c))
       * NOTE2: Topology Change Count - count of the times 'tcWhile' has been
       *        non-zero for any Port for the given MSTI since the Bridge was
       *        powered on or initialized.
       *       (802.1Q-REV/D5.0 12.8.1.2.3 d))
       *---------------------------------------------------------------------*/
      if(mstid == MSTP_CISTID)
      {
         MSTP_CIST_PORT_PTR(lport)->tcWhile = tcWhileVal;
         MSTP_CIST_INFO.topologyChangeCnt++;
         mstp_util_set_cist_table_value(TOP_CHANGE_CNT,MSTP_CIST_INFO.topologyChangeCnt);
         MSTP_CIST_INFO.timeSinceTopologyChange = time(NULL);
         mstp_util_set_cist_table_value(TIME_SINCE_TOP_CHANGE,MSTP_CIST_INFO.timeSinceTopologyChange);
      }
      else
      {
         MSTP_MSTI_PORT_PTR(mstid, lport)->tcWhile = tcWhileVal;
         mstp_util_set_msti_table_string(TOPOLOGY_CHANGE,"enable",mstid);
         MSTP_MSTI_INFO(mstid)->topologyChangeCnt++;
         mstp_util_set_msti_table_value(TOP_CHANGE_CNT,MSTP_MSTI_INFO(mstid)->topologyChangeCnt,mstid);
         MSTP_MSTI_INFO(mstid)->timeSinceTopologyChange =
                                                  time(NULL);
         mstp_util_set_msti_table_value(TIME_SINCE_TOP_CHANGE,MSTP_MSTI_INFO(mstid)->timeSinceTopologyChange,mstid);
      }
   }
   ovsdb_idl_txn_commit_block(txn);
   ovsdb_idl_txn_destroy(txn);
   MSTP_OVSDB_UNLOCK;
}

/**PROC+**********************************************************************
 * Name:      mstp_rcvInfo
 *
 * Purpose:   Decodes received BPDUs. Sets 'rcvdTcn' and sets 'rcvdTc' for
 *            each and every MSTI if a TCN BPDU has been received, and
 *            extracts the message priority and timer values from the received
 *            BPDU storing them in the 'msgPriority' and 'msgTimes' variables.
 *            Called from Port Information state machine.
 *            (802.1Q-REV/D5.0 13.26 j); 13.26.6)
 *
 * Params:    pkt   -> pointer to the packet buffer with BPDU in
 *            mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   For a given Port and Tree (CIST or MSTI) it returns:
 *            'MSTP_RCVD_INFO_SUPERIOR_DESIGNATED'
 *                - if the received CIST or MSTI message conveys a Designated
 *                  Port Role, and
 *                  1)the message priority ('msgPriority') is superior to the
 *                    Port's port priority vector, or
 *                  2)the message priority is the same as the Port's port
 *                    priority vector, and any of the received timer parameter
 *                    values ('msgTimes') differ from those already held for
 *                    the Port ('portTimes')
 *            or
 *            'MSTP_RCVD_INFO_REPEATED_DESIGNATED'
 *                - if the received CIST or MSTI message conveys a Designated
 *                  Port Role, and
 *                  1) the message priority vector and timer parameters that
 *                     are the same as the Port's port priority vector and
 *                     timer values; and
 *                  2) infoIs is Received
 *            or
 *            'MSTP_RCVD_INFO_INFERIOR_DESIGNATED'
 *                - if the received CIST or MSTI message conveys a Designated
 *                  Port Role.
 *            or
 *            'MSTP_RCVD_INFO_INFERIOR_ROOT_ALTERNATE'
 *                  - if the received CIST or MSTI message conveys a Root Port,
 *                    Alternate Port, or Backup Port Role and a CIST or MSTI
 *                    message priority that is the same as or worse than the
 *                    CIST or MSTI port priority vector.
 *             or
 *            'MSTP_RCVD_INFO_OTHER' otherwise.
 *
 *            NOTE: Configuration BPDU implicitly conveys a Designated Port Role.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
MSTP_RCVD_INFO_t
mstp_rcvInfo(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport)
{
   MSTP_RCVD_INFO_t rcvdInfo;

   STP_ASSERT(pkt);
   STP_ASSERT(mstid == MSTP_CISTID || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));

   /*------------------------------------------------------------------------
    * Check if a TCN BPDU has been received
    *------------------------------------------------------------------------*/
   if((mstid == MSTP_CISTID) && mstp_isStpTcnBpdu(pkt))
   {/* TCN BPDU */
      MSTP_COMM_PORT_INFO_t *commPortPtr;
      MSTID_t                tmpId;

      commPortPtr = MSTP_COMM_PORT_PTR(lport);
      STP_ASSERT(commPortPtr);

      /*---------------------------------------------------------------------
       * set 'rcvdTcn' TRUE
       *---------------------------------------------------------------------*/
      MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_RCVD_TCN);

      /*---------------------------------------------------------------------
       * kick Topology Change state machine (per-Tree per-Port)
       *---------------------------------------------------------------------*/
      MSTP_SM_CALL_SM_PRINTF(MSTP_PRX, MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                             "PIM:", "RECEIVE", "TCM:", mstid, lport);
      mstp_tcmSm(MSTP_CISTID, lport);

      /*---------------------------------------------------------------------
       * set 'rcvdTc' TRUE for each and every MSTI
       *---------------------------------------------------------------------*/
      for(tmpId = MSTP_MSTID_MIN; tmpId <= MSTP_MSTID_MAX; tmpId++)
      {
         if(MSTP_MSTI_VALID(tmpId))
         {
            MSTP_MSTI_PORT_INFO_t *mstiPortPtr =
                                              MSTP_MSTI_PORT_PTR(tmpId, lport);
            STP_ASSERT(mstiPortPtr);
            MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap,MSTP_MSTI_PORT_RCVD_TC);

            /*---------------------------------------------------------------
             * kick Topology Change state machine (per-Tree per-Port)
             *---------------------------------------------------------------*/
            MSTP_SM_CALL_SM_PRINTF(MSTP_PRX,
                                   MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                                   "PIM:", "RECEIVE", "TCM:", tmpId, lport);
            mstp_tcmSm(tmpId, lport);
         }
      }
   }

   /*------------------------------------------------------------------------
    * Extract message priority and timer values from the received BPDU and
    * store them in the 'msgPriority' and 'msgTimes' variables for a given
    * port for a given Tree.
    *------------------------------------------------------------------------*/
   if(mstid == MSTP_CISTID)
      rcvdInfo = mstp_rcvInfoCist(pkt, lport);
   else
      rcvdInfo = mstp_rcvInfoMsti(pkt, mstid, lport);

   return rcvdInfo;
}

/**PROC+**********************************************************************
 * Name:      mstp_rcvInfoCist
 *
 * Purpose:   Helper function called by the 'rcvInfo' function to decode
 *            information in received BPDU with respect to the CIST.
 *
 * Params:    pkt   -> pointer to the packet buffer with BPDU in
 *            lport -> logical port number the BPDU was received on
 *
  * Returns:  'MSTP_RCVD_INFO_SUPERIOR_DESIGNATED'
 *                - if the received CIST message conveys a Designated
 *                  Port Role, and
 *                  1)the message priority ('msgPriority') is superior to the
 *                    Port's port priority vector, or
 *                  2)the message priority is the same as the Port's port
 *                    priority vector, and any of the received timer parameter
 *                    values ('msgTimes') differ from those already held for
 *                    the Port ('portTimes')
 *            or
 *            'MSTP_RCVD_INFO_REPEATED_DESIGNATED'
 *                - if the received CIST message conveys a Designated
 *                  Port Role, and
 *                  1) the message priority vector and timer parameters that
 *                     are the same as the Port's port priority vector and
 *                     timer values; and
 *                  2) 'infoIs' is Received
 *            or
 *            'MSTP_RCVD_INFO_INFERIOR_DESIGNATED'
 *                - if the received CIST message conveys a Designated
 *                  Port Role.
 *            or
 *            'MSTP_RCVD_INFO_INFERIOR_ROOT_ALTERNATE'
 *                  - if the received CIST message conveys a Root Port,
 *                    Alternate Port, or Backup Port Role and a CIST
 *                    message priority that is the same as or worse than the
 *                    CIST port priority vector.
 *             or
 *            'MSTP_RCVD_INFO_OTHER' otherwise.
 *
 *            NOTE: Configuration BPDU implicitly conveys a Designated Port Role.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static MSTP_RCVD_INFO_t
mstp_rcvInfoCist(MSTP_RX_PDU *pkt, LPORT_t lport)
{
   MSTP_MST_BPDU_t             *bpdu           = NULL;
   MSTP_CIST_PORT_INFO_t       *cistPortPtr    = NULL;
   MSTP_CIST_MSG_PRI_VECTOR_t  *msgPriVecPtr   = NULL;
   MSTP_CIST_PORT_PRI_VECTOR_t *portPriVecPtr  = NULL;
   MSTP_CIST_MSG_TIMES_t       *msgTimesPtr    = NULL;
   MSTP_CIST_PORT_TIMES_t      *portTimesPtr   = NULL;
   bool                        bpduSameRgn    = FALSE;
   bool                        bpduTimesEqual = FALSE;
   bool                        rgnRootChanged = FALSE;
   MSTP_BPDU_TYPE_t             bpduType;

   STP_ASSERT(pkt);
   STP_ASSERT(IS_VALID_LPORT(lport));

   /*-------------------------------------------------------------------------
    * CIST specific Per-Port information
    *------------------------------------------------------------------------*/
   STP_ASSERT(MSTP_COMM_PORT_PTR(lport));
   cistPortPtr = MSTP_CIST_PORT_PTR(lport);
   STP_ASSERT(cistPortPtr);

   /* If an 'external' loop has been detected on the port lets ignore all
    * incoming BPDUs and wait for aging out of the 'rcvdInfoWhile' timer on
    * this port, then the 'looped' port will try to negotiate it's state
    * and have a chance to recognize if loop still exists */
   if(MSTP_COMM_PORT_PTR(lport)->rcvdSelfSentPkt && cistPortPtr->rcvdInfoWhile)
      return MSTP_RCVD_INFO_OTHER;

   /*-------------------------------------------------------------------------
    * determine BPDU type
    *------------------------------------------------------------------------*/
   bpduType = mstp_getBpduType(pkt);
   if((bpduType == MSTP_BPDU_TYPE_TCN) || (bpduType == MSTP_BPDU_TYPE_UNKNOWN))
      return MSTP_RCVD_INFO_OTHER;

   /*-------------------------------------------------------------------------
    * determine MST Region the sending Bridge belongs to.
    * NOTE: An STP or RSTP Bridge is always treated by MSTP as being in
    *       an MST Region of its own.
    *------------------------------------------------------------------------*/
   bpduSameRgn = mstp_fromSameRegion(pkt, lport);
   STP_ASSERT(bpduSameRgn ? bpduType == MSTP_BPDU_TYPE_MSTP : TRUE);

   /*-------------------------------------------------------------------------
    * set to the start of BPDU
    *------------------------------------------------------------------------*/
   //bpdu = (MSTP_MST_BPDU_t *)FRAME_PDU(pkt);
   bpdu = (MSTP_MST_BPDU_t *)(pkt->data);

   if(bpduType == MSTP_BPDU_TYPE_MSTP)
   {/* Check for the MST Region misconfiguration error, update statistics info
     * if consistency error has been detected */
      mstp_mstRgnCfgConsistencyCheck(bpdu, lport);
   }

   /*-------------------------------------------------------------------------
    * decode received BPDU, i.e. extract the message priority and timer values
    * from the received BPDU and store them in the 'msgPriority' and 'msgTimes'
    * variables of the receiving port
    *------------------------------------------------------------------------*/

   /* to facilitate further references set pointers to the Port's
    * 'msgPriority', 'msgTimes', 'portPriority', 'portTimes' place holders */
   msgPriVecPtr  = &cistPortPtr->msgPriority;
   msgTimesPtr   = &cistPortPtr->msgTimes;
   portPriVecPtr = &cistPortPtr->portPriority;
   portTimesPtr  = &cistPortPtr->portTimes;

   /*-------------------------------------------------------------------------
    * Update Port's 'msgPriority' variable from the info carried in BPDU,
    * 'msgPriority' consist of:
    *    - rootID           <- CIST Root Identifier
    *    - extRootPathCost  <- CIST external Root Path Cost
    *    - rgnRootID        <- CIST Regional Root Identifier
    *    - intRootPathCost  <- CIST Internal Root Path Cost
    *    - dsnBridgeID      <- CIST Designated Bridge Identifier
    *    - dsnPortID        <- CIST Designated Port Identifier
    *------------------------------------------------------------------------*/
   /* CIST Root Identifier */
   MAC_ADDR_COPY(bpdu->cistRootId.mac_address,
                 msgPriVecPtr->rootID.mac_address);
   msgPriVecPtr->rootID.priority =
                                 getShortFromPacket(&bpdu->cistRootId.priority);

   /* CIST External Root Path Cost */
   msgPriVecPtr->extRootPathCost = getLongFromPacket(&bpdu->cistExtPathCost);

   /*------------------------------------------------------------------------
    * NOTE: If a Configuration Message is received in an RST or ST BPDU,
    *       both the Regional Root Identifier and the Designated Bridge
    *       Identifier are decoded from the single BPDU field used for the
    *       Designated Bridge Parameter (the MST BPDU field in this position
    *       encodes the CIST Regional Root Identifier). An STP or RSTP
    *       Bridge is always treated by MSTP as being in an MST Region of
    *       its own.
    *       (802.1Q-REV/D5.0 13.10)
    *------------------------------------------------------------------------*/

   /* CIST Regional Root Identifier */
   MAC_ADDR_COPY(bpdu->cistRgnRootId.mac_address,
                 msgPriVecPtr->rgnRootID.mac_address);
   msgPriVecPtr->rgnRootID.priority =
                             getShortFromPacket(&bpdu->cistRgnRootId.priority);

   /* CIST Designated Bridge Identifier */
   if(bpduType != MSTP_BPDU_TYPE_MSTP)
   {/* Configuration Message is receved in an RSTP or STP BPDU, therefore
     * both Regional Root Identifier and the Designated Bridge Identifier
     * are decoded from a single BPDU field used for the Designated Bridge
     * Parameter (see note above) */
      STP_ASSERT((bpduType == MSTP_BPDU_TYPE_RSTP) ||
             (bpduType == MSTP_BPDU_TYPE_STP));
      MAC_ADDR_COPY(bpdu->cistRgnRootId.mac_address,
                    msgPriVecPtr->dsnBridgeID.mac_address);
      msgPriVecPtr->dsnBridgeID.priority =
                             getShortFromPacket(&bpdu->cistRgnRootId.priority);
   }
   else
   {
      MAC_ADDR_COPY(bpdu->cistBridgeId.mac_address,
                    msgPriVecPtr->dsnBridgeID.mac_address);
      msgPriVecPtr->dsnBridgeID.priority =
                              getShortFromPacket(&bpdu->cistBridgeId.priority);
   }

   /* CIST Internal Root Path Cost
    * NOTE: If receiving Bridge is not in the same MST Region as sending
    *       Bridge, the Internal Root Path Cost is decoded as 0, as it has
    *       no meaning to the receiving Bridge (802.1Q-REV/D5.0 13.10) */
   msgPriVecPtr->intRootPathCost = bpduSameRgn ?
                                   getLongFromPacket(&bpdu->cistIntRootPathCost):
                                   0;

   /* CIST Designated Port Identifier */
   msgPriVecPtr->dsnPortID = getShortFromPacket(&bpdu->cistPortId);

   /*-------------------------------------------------------------------------
    * Update Port's 'msgTimes' variable from the info carried in BPDU
    * 'msgPriority' consist of:
    *    - messageAge   <- Message Age
    *    - maxAge       <- Max Age
    *    - fwdDelay     <- Forward Delay
    *    - helloTime    <- Hello Time
    *    - hops         <- Remaining Hops
    *------------------------------------------------------------------------*/
   msgTimesPtr->messageAge = getShortFromPacket(&bpdu->msgAge);
   msgTimesPtr->messageAge = (msgTimesPtr->messageAge >> 8);
   msgTimesPtr->maxAge     = getShortFromPacket(&bpdu->maxAge);
   msgTimesPtr->maxAge     = (msgTimesPtr->maxAge >> 8);
   msgTimesPtr->fwdDelay   = getShortFromPacket(&bpdu->fwdDelay);
   msgTimesPtr->fwdDelay   = (msgTimesPtr->fwdDelay >> 8);
   msgTimesPtr->helloTime  = getShortFromPacket(&bpdu->helloTime);
   msgTimesPtr->helloTime  = (msgTimesPtr->helloTime >> 8);
   if(bpduType == MSTP_BPDU_TYPE_MSTP)
   {
      /* NOTE: 'remainingHops' make sense only within an MST Region, so if
       *           MST BPDU is received from a Bridge in a different region
       *           we assign 'remainingHops' to the 'MaxHops' value */
      msgTimesPtr->hops = bpduSameRgn ?
                          bpdu->cistRemainingHops : mstp_Bridge.MaxHops;
   }
   else
   {/* If the BPDU is a ST or RST BPDU without MSTP parameters, 'remainingHops'
     * is set to 'MaxHops' (P802.1Q-REV/D5.0 13.24.10) */
      msgTimesPtr->hops    = mstp_Bridge.MaxHops;
   }

   /*-------------------------------------------------------------------------
    * Set 'bpduTimesEqual' and 'rgnRootChanged' boolean variables used for
    * decision making further in the code
    *------------------------------------------------------------------------*/
   if((msgTimesPtr->fwdDelay   == portTimesPtr->fwdDelay)   &&
      (msgTimesPtr->maxAge     == portTimesPtr->maxAge)     &&
      (msgTimesPtr->messageAge == portTimesPtr->messageAge) &&
      (msgTimesPtr->helloTime  == portTimesPtr->helloTime)  &&
      (bpduSameRgn ?
       msgTimesPtr->hops       == portTimesPtr->hops : TRUE))
   {/* the received timer parameter values are the same as those already held
     * for the Port */
      bpduTimesEqual = TRUE;
   }

   /*-------------------------------------------------------------------------
    * Check if sending Bridge and this receiving Bridge are in agreement
    * about the Regional Root Bridge elected for the MST region this Bridge
    * is in
    *------------------------------------------------------------------------*/
   rgnRootChanged = ((bpduSameRgn &&
                      !MSTP_BRIDGE_ID_EQUAL(cistPortPtr->msgPriority.rgnRootID,
                                            MSTP_CIST_ROOT_PRIORITY.rgnRootID))
                     ||
                     (!bpduSameRgn &&
                     MSTP_BRIDGE_ID_EQUAL(cistPortPtr->msgPriority.rgnRootID,
                                          MSTP_CIST_ROOT_PRIORITY.rgnRootID)));

   /*-------------------------------------------------------------------------
    * Classify the information in received BPDU as to fall into one of the
    * following categories:
    * SuperiorDesignatedInfo
    * or
    * RepeatedDesignatedInfo
    * or
    * InferiorDesignatedInfo
    * or
    * InferiorRootAlternateInfo
    * or
    * OtherInfo
    * NOTE for 'SuperiorDesignatedInfo' determination:
    *       Received information for a spanning tree is considered superior
    *       to, and will replace, that recorded in the receiving Port's
    *       port priority vector if
    *       Case 1) its message priority vector is better,
    *       OR
    *       Case 2) if it was transmitted by the same Designated Bridge and
    *               Designated Port
    *               AND
    *               the message priority vector, timer, or hop count
    *               information differ from those recorded.
    *       (802.1Q-REV/D5.0 13.15)
    *       OR
    *       Case 3) the CIST Regional Root this Bridge knows so far is
    *               different from what is being sent in BPDU from another
    *               Bridge (i.e. rgnRootChanged == TRUE).
    *------------------------------------------------------------------------*/

   if(mstp_isOldRootPropagation(MSTP_CISTID, lport, bpdu, NULL, bpduSameRgn))
      return  MSTP_RCVD_INFO_SUPERIOR_DESIGNATED;

   /* If we see loop-backed BPDU then treat it as a superior msg; it will
    * cause the Port Information SM (caller of this function) enter the
    * SUPER_DESIGNATED state, where it calls the Port Role Selection SM to
    * update Bridge's Port Roles resulting in calculation of the Backup Port
    * Role for this port and the state of this port to be Blocked. The roles
    * and states of other ports will not be affected as the Bridge's own
    * BPDU is being ignored by the Port Role Selection SM procedures. */
   MSTP_COMM_PORT_PTR(lport)->rcvdSelfSentPkt = mstp_isSelfSentPkt(pkt);
   if(MSTP_COMM_PORT_PTR(lport)->rcvdSelfSentPkt)
   {/* Self sent (loop-backed) BPDU, i.e. received message was transmitted
     * by this Bridge on this Port */
      /* Update statistics counter */
      cistPortPtr->dbgCnts.loopBackBpduCnt++;
      cistPortPtr->dbgCnts.loopBackBpduCntLastUpdated = time(NULL);

      return MSTP_RCVD_INFO_SUPERIOR_DESIGNATED;
   }

   STP_ASSERT((bpduType == MSTP_BPDU_TYPE_STP)  ||
          (bpduType == MSTP_BPDU_TYPE_RSTP) ||
          (bpduType == MSTP_BPDU_TYPE_MSTP));

   if((bpduType == MSTP_BPDU_TYPE_STP) ||
      (bpdu->cistFlags & MSTP_CIST_FLAG_PORT_ROLE) == MSTP_BPDU_ROLE_DESIGNATED)
   {/* The received CIST message conveys a Designated Port Role
     * NOTE: A Configuration BPDU implicitly conveys a Designated Port Role */

      if(bpduSameRgn && (cistPortPtr->role == MSTP_PORT_ROLE_DESIGNATED) &&
         !MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                    MSTP_CIST_PORT_PROPOSING) &&
         (msgTimesPtr->hops <= 1))
      {/* NOTE: the receiving port is located beyond of the 'max-hops'
        *           limit specified by the current Regional Root Bridge,
        *           i.e. this port can not be included in the Region so
        *           the Region becomes partitioned. In such case we
        *           ignore received BPDUs in order to keep both split parts
        *           of the Region stable */
         /* Update statistics info */
         cistPortPtr->dbgCnts.exceededHopsBpduCnt++;
         cistPortPtr->dbgCnts.exceededHopsBpduCntLastUpdated =
                                                         time(NULL);
         return MSTP_RCVD_INFO_OTHER;
      }

      /*----------------------------------------------------------------------
       * check for the 'SuperDesignatedInfo' (Case 3)
       *---------------------------------------------------------------------*/
      if(rgnRootChanged)
      {/* The CIST Regional Root has changed */
         return MSTP_RCVD_INFO_SUPERIOR_DESIGNATED;
      }

      /*----------------------------------------------------------------------
       * check for the 'RepeatedDesignatedInfo'
       *---------------------------------------------------------------------*/
      if(!mstp_cistPriorityVectorsCompare(msgPriVecPtr, portPriVecPtr) &&
         (bpduTimesEqual == TRUE) &&
         (cistPortPtr->infoIs == MSTP_INFO_IS_RECEIVED))
      {/* the received CIST message conveys a Designated Port Role, and
        * message priority vector and timer parameters that are the same as
        * the Port's port priority vector and timer values and 'infoIs' is
        * 'Received' */
         return MSTP_RCVD_INFO_REPEATED_DESIGNATED;
      }

      /*----------------------------------------------------------------------
       * check for the 'SuperDesignatedInfo' - Case 1
       *---------------------------------------------------------------------*/
      if(mstp_cistPriorityVectorsCompare(msgPriVecPtr, portPriVecPtr) < 0)
      {/* the message priority vector is strictly better than the Port's
        * port priority vector */
         return MSTP_RCVD_INFO_SUPERIOR_DESIGNATED;
      }

      /*----------------------------------------------------------------------
       * check for the 'SuperDesignatedInfo'  - Case 2
       *---------------------------------------------------------------------*/
      if(MAC_ADDRS_EQUAL(msgPriVecPtr->dsnBridgeID.mac_address,
                         portPriVecPtr->dsnBridgeID.mac_address) &&
         (MSTP_GET_PORT_NUM(msgPriVecPtr->dsnPortID) ==
          MSTP_GET_PORT_NUM(portPriVecPtr->dsnPortID)))
      {/* the message was transmitted by the same Designated Bridge and
        * Designated Port */
         if(mstp_cistPriorityVectorsCompare(msgPriVecPtr, portPriVecPtr) ||
            (bpduTimesEqual == FALSE))
         {/* and the message priority vector, timer, or hop count information
           * differ from those recorded */
            return MSTP_RCVD_INFO_SUPERIOR_DESIGNATED;
         }
      }

      /*----------------------------------------------------------------------
       * if none of the above conditions was met then return
       * 'InferiorDesignatedInfo'
       *---------------------------------------------------------------------*/
      return MSTP_RCVD_INFO_INFERIOR_DESIGNATED;
   }
   else
   if((((bpdu->cistFlags & MSTP_CIST_FLAG_PORT_ROLE) == MSTP_BPDU_ROLE_ROOT)
       ||
       ((bpdu->cistFlags & MSTP_CIST_FLAG_PORT_ROLE) ==
                                         MSTP_BPDU_ROLE_ALTERNATE_OR_BACKUP))
      &&
      !(mstp_cistPriorityVectorsCompare(msgPriVecPtr, portPriVecPtr) < 0))
   {/* The received CIST message conveys a Root Port, Alternate Port, or
     * Backup Port Role AND a CIST message priority that is the same as
     * or worse than the CIST port priority vector */
      return MSTP_RCVD_INFO_INFERIOR_ROOT_ALTERNATE;
   }
   else
   {
      return MSTP_RCVD_INFO_OTHER;
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_rcvInfoMsti
 *
 * Purpose:   Helper function called by the 'rcvInfo' function to decode
 *            information in received BPDU with respect to the given MSTI.
 *
 * Params:    pkt   -> pointer to the packet buffer with BPDU in
 *            lport -> logical port number the BPDU was received on
 *
  * Returns:  'MSTP_RCVD_INFO_SUPERIOR_DESIGNATED'
 *                - if the received MSTI message conveys a Designated
 *                  Port Role, and
 *                  1)the message priority ('msgPriority') is superior to the
 *                    Port's port priority vector, or
 *                  2)the message priority is the same as the Port's port
 *                    priority vector, and any of the received timer parameter
 *                    values ('msgTimes') differ from those already held for
 *                    the Port ('portTimes')
 *            or
 *            'MSTP_RCVD_INFO_REPEATED_DESIGNATED'
 *                - if the received MSTI message conveys a Designated
 *                  Port Role, and
 *                  1) the message priority vector and timer parameters that
 *                     are the same as the Port's port priority vector and
 *                     timer values; and
 *                  2) 'infoIs' is Received
 *            or
 *            'MSTP_RCVD_INFO_INFERIOR_DESIGNATED'
 *                - if the received MSTI message conveys a Designated
 *                  Port Role.
 *            or
 *            'MSTP_RCVD_INFO_INFERIOR_ROOT_ALTERNATE'
 *                  - if the received MSTI message conveys a Root Port,
 *                    Alternate Port, or Backup Port Role and a MSTI
 *                    message priority that is the same as or worse than the
 *                    MSTI port priority vector.
 *             or
 *            'MSTP_RCVD_INFO_OTHER' otherwise.
 *
 *            NOTE: Configuration BPDU implicitly conveys a Designated Port Role.
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
static MSTP_RCVD_INFO_t
mstp_rcvInfoMsti(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport)
{
   MSTP_MST_BPDU_t             *bpdu;
   MSTP_MSTI_PORT_INFO_t       *mstiPortPtr;
   MSTP_BPDU_TYPE_t             bpduType;
   bool                        bpduSameRgn    = FALSE;
   bool                        bpduTimesEqual = FALSE;
   bool                        rgnRootChanged = FALSE;
   MSTP_MSTI_MSG_PRI_VECTOR_t  *msgPriVecPtr;
   MSTP_MSTI_PORT_PRI_VECTOR_t *portPriVecPtr;
   MSTP_MSTI_MSG_TIMES_t       *msgTimesPtr;
   MSTP_MSTI_PORT_TIMES_t      *portTimesPtr;
   MSTP_MSTI_CONFIG_MSG_t      *cfgMsgPtr;
   uint16_t                      priorityVal;

   STP_ASSERT(pkt);
   STP_ASSERT(IS_VALID_LPORT(lport));
   STP_ASSERT(MSTP_VALID_MSTID(mstid));

   /*------------------------------------------------------------------------
    * MSTI specific Per-Port information
    *------------------------------------------------------------------------*/
   STP_ASSERT(MSTP_COMM_PORT_PTR(lport));
   mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
   STP_ASSERT(mstiPortPtr);

   /* If an 'external' loop has been detected on the port lets ignore all
    * incoming BPDUs and wait for aging out of the 'rcvdInfoWhile' timer on
    * this port, then the 'looped' port will try to negotiate it's state
    * and have a chance to recognize if loop still exists */
   if(MSTP_COMM_PORT_PTR(lport)->rcvdSelfSentPkt && mstiPortPtr->rcvdInfoWhile)
      return MSTP_RCVD_INFO_OTHER;

   /*------------------------------------------------------------------------
    * determine BPDU type
    * NOTE: This function should be called only for processing MST BPDUs
    *------------------------------------------------------------------------*/
   bpduType = mstp_getBpduType(pkt);
   STP_ASSERT(bpduType == MSTP_BPDU_TYPE_MSTP);
   if(bpduType != MSTP_BPDU_TYPE_MSTP)
      return MSTP_RCVD_INFO_OTHER;

   /*------------------------------------------------------------------------
    * determine MST Region the sending Bridge belongs to
    * NOTE: This function should not be called for processing MST BPDUs
    *       coming from a Bridge located in different MST Region
    *------------------------------------------------------------------------*/
   bpduSameRgn = mstp_fromSameRegion(pkt, lport);
   STP_ASSERT(bpduSameRgn == TRUE);
   if(bpduSameRgn == FALSE)
      return MSTP_RCVD_INFO_OTHER;

   /*------------------------------------------------------------------------
    * in the receved BPDU search for MSTI Configuration Message parameters
    * applicable to the given MSTI.
    * NOTE: we always should be able to find the info at this point
    *       (since we are in the same MST region with the sender)
    *------------------------------------------------------------------------*/
   cfgMsgPtr = mstp_findMstiCfgMsgInBpdu(pkt, mstid);
   STP_ASSERT(cfgMsgPtr);
   if(cfgMsgPtr == NULL)
      return MSTP_RCVD_INFO_OTHER;

   /*-------------------------------------------------------------------------
    * set to the start of BPDU
    *------------------------------------------------------------------------*/
   bpdu = (MSTP_MST_BPDU_t *)(pkt->data);

   /*-------------------------------------------------------------------------
    * decode received BPDU, i.e. extract the message priority and timer values
    * from the received BPDU and store them in the 'msgPriority' and 'msgTimes'
    * variables of the receiving port
    *------------------------------------------------------------------------*/

   /* to facilitate further references set pointers to the Port's
    * 'msgPriority', 'msgTimes', 'portPriority', 'portTimes' place holders */
   msgPriVecPtr  = &mstiPortPtr->msgPriority;
   msgTimesPtr   = &mstiPortPtr->msgTimes;
   portPriVecPtr = &mstiPortPtr->portPriority;
   portTimesPtr  = &mstiPortPtr->portTimes;

   /*-------------------------------------------------------------------------
    * Update Port's 'msgPriority' variable from the info carried in BPDU,
    * 'msgPriority' consist of:
    *    - rgnRootID        <- MSTI Regional Root Identifier
    *    - intRootPathCost  <- MSTI Internal Root Path Cost
    *    - dsnBridgeID      <- MSTI Designated Bridge Identifier
    *    - dsnPortID        <- MSTI Designated Port Identifier
    *------------------------------------------------------------------------*/

   /* MSTI Regional Root Identifier */
   MAC_ADDR_COPY(cfgMsgPtr->mstiRgnRootId.mac_address,
                 msgPriVecPtr->rgnRootID.mac_address);
   msgPriVecPtr->rgnRootID.priority =
                        getShortFromPacket(&cfgMsgPtr->mstiRgnRootId.priority);

   /* MSTI Internal Root Path Cost */
   msgPriVecPtr->intRootPathCost =
                            getLongFromPacket(&cfgMsgPtr->mstiIntRootPathCost);

   /* MSTI Designated Bridge Identifier
    * NOTE: the 4 most significant bits of the Bridge Identifier constitute
    *       the managable priority component for each MSTI and are separately
    *       encoded (into 1 octet) in MSTI Configuration Messages in the BPDU.
    *       Bits 5 through 8 of Octet 14 convey the value of the Bridge
    *       Identifier Priority for this MSTI. Bits 1 through 4 of Octet 14
    *       shall be transmitted as 0, and ignored on receipt.
    *       (802.1Q-REV/D5.0 14.6.1 d)) */
   MAC_ADDR_COPY(bpdu->cistBridgeId.mac_address,
                 msgPriVecPtr->dsnBridgeID.mac_address);
   priorityVal = (((cfgMsgPtr->mstiBridgePriority & 0xF0) >> 4) * 4096);
   MSTP_SET_BRIDGE_PRIORITY(msgPriVecPtr->dsnBridgeID, priorityVal);
   MSTP_SET_BRIDGE_SYS_ID(msgPriVecPtr->dsnBridgeID, mstid);

   /* MSTI Designated Port Identifier
    * NOTE: Bits 5 through 8 of Octet 15 convey the value of the Port
    *       Identifier Priority for this MSTI. Bits 1 through 4 of Octet
    *       15 shall be transmitted as 0, and ignored on receipt.
    *       (802.1Q-REV/D5.0 14.6.1 e)) */
   msgPriVecPtr->dsnPortID = getShortFromPacket(&bpdu->cistPortId);
   priorityVal = (((cfgMsgPtr->mstiPortPriority & 0xF0) >> 4) * 16);
   MSTP_SET_PORT_PRIORITY(msgPriVecPtr->dsnPortID, priorityVal);

   /*-------------------------------------------------------------------------
    * Update Port's 'msgTimes' variable from the info carried in BPDU
    * 'msgPriority' consist of:
    *    - hops         <- Remaining Hops
    *------------------------------------------------------------------------*/
   msgTimesPtr->hops = cfgMsgPtr->mstiRemainingHops;

   /*-------------------------------------------------------------------------
    * Set 'bpduTimesEqual' and 'rgnRootChanged' bool variables used for
    * decision making further in the code
    *------------------------------------------------------------------------*/
   if(msgTimesPtr->hops == portTimesPtr->hops)
   {/* the received timer parameter values are the same as those already
     * held for the Port */
      bpduTimesEqual = TRUE;
   }

   /* Check if sending Bridge and this receiving Bridge are in agreement
    * about the Regional Root Bridge elected for the MST region this Bridge
    * is in */
   rgnRootChanged = !MSTP_BRIDGE_ID_EQUAL(mstiPortPtr->msgPriority.rgnRootID,
                                          MSTP_MSTI_ROOT_PRIORITY(mstid).rgnRootID);

   /*-------------------------------------------------------------------------
    * Classify the information in received BPDU as to fall into one of the
    * following categories:
    * SuperiorDesignatedInfo
    * or
    * RepeatedDesignatedInfo
    * or
    * InferiorDesignatedInfo
    * or
    * InferiorRootAlternateInfo
    * or
    * OtherInfo
    * NOTE for 'SuperiorDesignatedInfo' determination:
    *       Received information for a spanning tree is considered superior
    *       to, and will replace, that recorded in the receiving Port's
    *       port priority vector if
    *       Case 1) its message priority vector is better,
    *       OR
    *       Case 2) if it was transmitted by the same Designated Bridge and
    *               Designated Port
    *               AND
    *               the message priority vector, timer, or hop count
    *               information differ from those recorded.
    *       (802.1Q-REV/D5.0 13.15)
    *       OR
    *       Case 3) the CIST Regional Root this Bridge knows so far is
    *               different from what is being sent in BPDU from another
    *               Bridge (i.e. rgnRootChanged == TRUE).
    *------------------------------------------------------------------------*/

   STP_ASSERT(bpduSameRgn);
   if(mstp_isOldRootPropagation(mstid, lport, NULL, cfgMsgPtr, TRUE))
      return  MSTP_RCVD_INFO_SUPERIOR_DESIGNATED;

   /* If we see loop-backed BPDU then treat it as a superior msg; it will
    * cause the Port Information SM (caller of this function) enter the
    * SUPER_DESIGNATED state, where it calls the Port Role Selection SM to
    * update Bridge's Port Roles resulting in calculation of the Backup Port
    * Role for this port and the state of this port to be Blocked. The roles
    * and states of other ports will not be affected as the Bridge's own
    * BPDU is being ignored by the Port Role Selection SM procedures. */
   MSTP_COMM_PORT_PTR(lport)->rcvdSelfSentPkt = mstp_isSelfSentPkt(pkt);
   if(MSTP_COMM_PORT_PTR(lport)->rcvdSelfSentPkt)
   {/* Self sent (loop-backed) BPDU, i.e. the received message was transmitted
     * by this Bridge on this Port */
      return MSTP_RCVD_INFO_SUPERIOR_DESIGNATED;
   }

   if((cfgMsgPtr->mstiFlags & MSTP_MSTI_FLAG_PORT_ROLE) ==
                                                     MSTP_BPDU_ROLE_DESIGNATED)
   {/* The received MSTI message conveys a Designated Port Role */

      if(bpduSameRgn && (mstiPortPtr->role == MSTP_PORT_ROLE_DESIGNATED) &&
         !MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                    MSTP_MSTI_PORT_PROPOSING) &&
         (msgTimesPtr->hops <= 1))
      {/* NOTE: the receiving port is located beyond of the 'max-hops'
        *           limit specified by the current Regional Root Bridge,
        *           i.e. this port can not be included in the Region so
        *           the Region becomes partitioned. In such case we
        *           ignore received BPDUs in order to keep both split parts
        *           of the Region stable */
         /* Update statistics info */
         mstiPortPtr->dbgCnts.exceededHopsMsgCnt++;
         mstiPortPtr->dbgCnts.exceededHopsMsgCntLastUpdated =
                                                         time(NULL);
         return MSTP_RCVD_INFO_OTHER;
      }

      /*----------------------------------------------------------------------
       * check for the 'SuperDesignatedInfo' (Case 3)
       *---------------------------------------------------------------------*/
      if(rgnRootChanged == TRUE)
      {/* The MSTI Regional Root has changed */
         return MSTP_RCVD_INFO_SUPERIOR_DESIGNATED;
      }

      /*----------------------------------------------------------------------
       * check for the 'RepeatedDesignatedInfo'
       *---------------------------------------------------------------------*/
      if(!mstp_mstiPriorityVectorsCompare(msgPriVecPtr, portPriVecPtr) &&
         (bpduTimesEqual == TRUE) &&
         (mstiPortPtr->infoIs == MSTP_INFO_IS_RECEIVED))
      {/* the received MSTI message conveys a Designated Port Role, and
        * message priority vector and timer parameters that are the same as
        * the Port's port priority vector and timer values and 'infoIs' is
        * 'Received' */
         return MSTP_RCVD_INFO_REPEATED_DESIGNATED;
      }

      /*----------------------------------------------------------------------
       * check for the 'SuperDesignatedInfo' - Case 1
       *---------------------------------------------------------------------*/
      if(mstp_mstiPriorityVectorsCompare(msgPriVecPtr, portPriVecPtr) < 0)
      {/* the message priority vector is strictly better than the Port's
        * port priority vector */
         return MSTP_RCVD_INFO_SUPERIOR_DESIGNATED;
      }

      /*----------------------------------------------------------------------
       * check for the 'SuperDesignatedInfo'  - Case 2
       *---------------------------------------------------------------------*/
      if(MAC_ADDRS_EQUAL(msgPriVecPtr->dsnBridgeID.mac_address,
                         portPriVecPtr->dsnBridgeID.mac_address) &&
         (MSTP_GET_PORT_NUM(msgPriVecPtr->dsnPortID) ==
          MSTP_GET_PORT_NUM(portPriVecPtr->dsnPortID)))
      {/* the message was  transmitted by the same Designated Bridge and
        *    Designated Port) */
         if(mstp_mstiPriorityVectorsCompare(msgPriVecPtr, portPriVecPtr) ||
            (bpduTimesEqual == FALSE))
         {/* and the message priority vector, timer, or hop count information
           * differ from those recorded */
            return MSTP_RCVD_INFO_SUPERIOR_DESIGNATED;
         }
      }

      /*----------------------------------------------------------------------
       * if none of the above conditions was met then return
       * 'InferiorDesignatedInfo'
       *---------------------------------------------------------------------*/
      return MSTP_RCVD_INFO_INFERIOR_DESIGNATED;
   }
   else
   if((((cfgMsgPtr->mstiFlags & MSTP_MSTI_FLAG_PORT_ROLE) == MSTP_BPDU_ROLE_ROOT)
       ||
       ((cfgMsgPtr->mstiFlags & MSTP_MSTI_FLAG_PORT_ROLE) ==
                                         MSTP_BPDU_ROLE_ALTERNATE_OR_BACKUP))
      &&
      !(mstp_mstiPriorityVectorsCompare(msgPriVecPtr, portPriVecPtr) < 0))
   {/* The received MSTI message conveys a Root Port, Alternate Port, or
     * Backup Port Role AND a MSTI message priority that is the same as
     * or worse than the MSTI port priority vector */
      return MSTP_RCVD_INFO_INFERIOR_ROOT_ALTERNATE;
   }
   else
   {
      return MSTP_RCVD_INFO_OTHER;
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_recordAgreement
 *
 * Purpose:   For the CIST and a given Port,
 *               if 'rstpVersion' is TRUE, 'operPointToPointMAC' is TRUE,
 *               and the received CIST Message has the 'Agreement' flag set,
 *               the CIST 'agreed' flag is set and the CIST 'proposing' flag
 *               is cleared. Otherwise the CIST 'agreed' flag is cleared.
 *               Additionally, if the CIST message was received from a
 *               Bridge in a different MST Region i.e. the 'rcvdInternal'
 *               flag is clear, the 'agreed' and 'proposing' flags for this
 *               Port for all MSTIs are set or cleared to the same value as
 *               the CIST 'agreed' and 'proposing' flags. If the CIST
 *               message was received from a Bridge in the same MST Region,
 *               the MSTI 'agreed' and 'proposing' flags are not changed.
 *            For a given MSTI and Port,
 *               if 'operPointToPointMAC' is TRUE, and:
 *                  a) the message priority vector of the CIST Message
 *                     accompanying the received MSTI Message (i.e. 'received'
 *                     in the same BPDU) has the same CIST Root Identifier,
 *                     CIST External Root Path Cost, and Regional Root
 *                     Identifier as the CIST port priority vector, and
 *                  b) the received MSTI Message has the 'Agreement' flag set,
 *                     the MSTI 'agreed' flag is set and the MSTI 'proposing'
 *                     flag is cleared. Otherwise the MSTI 'agreed' flag is
 *                     cleared.
 *            NOTE: MSTI Messages received from Bridges external to the
 *                  MST Region are discarded and not processed by
 *                  recordAgreeement() function.
 *            (802.1Q-REV/D5.0 13.26 k); 13.26.7)
 *
 * Params:    pkt   -> pointer to the packet buffer with BPDU in
 *            mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_recordAgreement(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr  = NULL;
   MSTP_CIST_PORT_INFO_t *cistPortPtr  = NULL;
   MSTP_MST_BPDU_t       *bpdu         = NULL;
   bool                  rcvdInternal = FALSE;
   bool                  rstpVersion  = FALSE;
   bool                  operPPMAC    = FALSE; /* operPointToPointMAC */

   STP_ASSERT(pkt);
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   cistPortPtr = MSTP_CIST_PORT_PTR(lport);
   STP_ASSERT(cistPortPtr);

   //bpdu = (MSTP_MST_BPDU_t *)FRAME_PDU(pkt);
   bpdu = (MSTP_MST_BPDU_t *)(pkt->data);
   rcvdInternal = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                            MSTP_PORT_RCVD_INTERNAL);
   /* 'rstpVersion' is TRUE if Force Protocol Version is greater than or
    * equal to 2 (2 is associated with RST Protocol Version Identifier) */
   rstpVersion = (mstp_Bridge.ForceVersion >= MSTP_PROTOCOL_VERSION_ID_RST);
   operPPMAC = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                         MSTP_PORT_OPER_POINT_TO_POINT_MAC);

   if(mstid == MSTP_CISTID)
   {/* the CIST */
      bool cistAgreed    = FALSE;
      bool cistProposing = FALSE;

      cistAgreed = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_AGREED);
      cistProposing = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_PROPOSING);
      if(rstpVersion && operPPMAC &&
         (bpdu->cistFlags & MSTP_CIST_FLAG_AGREEMENT))
      {/* 'rstpVersion' is TRUE, 'operPointToPointMAC' is TRUE, and the
        * received CIST Message has the 'Agreement' flag set,
        * we should set the CIST 'agreed' flag and clear the CIST 'proposing'
        * flag */
         MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_AGREED);
         cistAgreed = TRUE;
         MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_PROPOSING);
         cistProposing = FALSE;
      }
      else
      {/* otherwise clear the CIST 'agreed' flag */
         MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_AGREED);
         cistAgreed = FALSE;
      }

      if(!rcvdInternal)
      {/* the CIST message was received from a Bridge in a different
        * MST Region, the 'agreed' and 'proposing' flags for this
        * Port for all MSTIs should be set or cleared to the same value as
        * the CIST 'agreed' and 'proposing' flags */
         MSTID_t tmpId;

         for(tmpId = MSTP_MSTID_MIN; tmpId <= MSTP_MSTID_MAX; tmpId++)
         {
            if(MSTP_MSTI_VALID(tmpId))
            {
               MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(tmpId,
                                                                       lport);
               STP_ASSERT(mstiPortPtr);
               if(cistAgreed)
                  MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap,
                                         MSTP_MSTI_PORT_AGREED);
               else
                  MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap,
                                         MSTP_MSTI_PORT_AGREED);
               if(cistProposing)
                  MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap,
                                         MSTP_MSTI_PORT_PROPOSING);
               else
                  MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap,
                                         MSTP_MSTI_PORT_PROPOSING);
            }
         }
      }
   }
   else
   {/* an MSTI */
      MSTP_MSTI_CONFIG_MSG_t *cfgMsgPtr = mstp_findMstiCfgMsgInBpdu(pkt, mstid);

      STP_ASSERT(rcvdInternal == TRUE);
      STP_ASSERT(cfgMsgPtr);
      if(cfgMsgPtr)
      {
         MSTP_MSTI_PORT_INFO_t       *mstiPortPtr   = NULL;
         MSTP_CIST_MSG_PRI_VECTOR_t  *msgPriVec     = &cistPortPtr->msgPriority;
         MSTP_CIST_PORT_PRI_VECTOR_t *portPriVec    = &cistPortPtr->portPriority;
         bool                        eqMsgPortPrms = FALSE;

         mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
         STP_ASSERT(mstiPortPtr);

         eqMsgPortPrms =
            ((MSTP_BRIDGE_ID_EQUAL(msgPriVec->rootID, portPriVec->rootID)) &&
             (msgPriVec->extRootPathCost == portPriVec->extRootPathCost)   &&
             (MSTP_BRIDGE_ID_EQUAL(msgPriVec->rgnRootID,
                                   portPriVec->rgnRootID)));

         if(operPPMAC && eqMsgPortPrms &&
            (cfgMsgPtr->mstiFlags & MSTP_MSTI_FLAG_AGREEMENT))
         {/* 'operPointToPointMAC' is TRUE, the message priority vector of the
           * CIST Message accompanying the received MSTI Message has the same
           * CIST Root Identifier, CIST External Root Path Cost, and Regional
           * Root Identifier as the CIST port priority vector, and the
           * received MSTI Message has the Agreement flag set */

            /* the MSTI 'agreed' flag should be set and the MSTI 'proposing'
             * flag should be cleared. Otherwise the MSTI 'agreed' flag is
             * cleared.   */
            MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_AGREED);
            MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap,
                                   MSTP_MSTI_PORT_PROPOSING);
         }
         else
         {/* Otherwise the MSTI 'agreed' flag should be cleared.   */
            MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_AGREED);
         }
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_recordDispute
 *
 * Purpose:   For the CIST and a given port, if the CIST message has the
 *            learning flag set:
 *               a) The disputed variable is set; and
 *               b) The agreed variable is cleared.
 *            Additionally, if the CIST message was received from a Bridge
 *            in a different MST region (i.e., if the rcvdInternal flag is
 *            clear), then for all the MSTIs:
 *               c) The disputed variable is set; and
 *               d) The agreed variable is cleared.
 *            For a given MSTI and port, if the received MSTI message has
 *            the learning flag set:
 *               e) The disputed variable is set; and
 *               f) The agreed variable is cleared.+B
 *            (802.1Q-REV/D5.0 13.26 l); 13.26.8)
 *            Called from Port Information (PIM) state machine.
 *
 * Params:    pkt   -> pointer to the packet buffer with BPDU in
 *            mstid -> MST Instance Identifier
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_recordDispute(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr  = NULL;
   bool                  rcvdInternal = FALSE;

   STP_ASSERT(pkt);
   STP_ASSERT(mstid == MSTP_CISTID || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);
   rcvdInternal = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                            MSTP_PORT_RCVD_INTERNAL);

   if(mstid == MSTP_CISTID)
   {/* The CIST */
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);
      //MSTP_MST_BPDU_t       *bpdu        = (MSTP_MST_BPDU_t *)FRAME_PDU(pkt);
      MSTP_MST_BPDU_t       *bpdu        = (MSTP_MST_BPDU_t *)(pkt->data);

      STP_ASSERT(cistPortPtr);
      if(bpdu->cistFlags & MSTP_CIST_FLAG_LEARNING)
      {/* The 'learning' flag is set in the received CIST message */

         /*------------------------------------------------------------------
          * set 'disputed' and clear 'agreed' valrables for the CIST
          *------------------------------------------------------------------*/
         MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_DISPUTED);
         MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_AGREED);
      }

      if(!rcvdInternal)
      {/* The CIST message was received from a Bridge in different
        * MST region */
         MSTP_MSTI_PORT_INFO_t *mstiPortPtr = NULL;
         MSTID_t                tmpId;

         /*------------------------------------------------------------------
          * for all MSTIs set 'disputed' and clear 'agreed' valrables
          *------------------------------------------------------------------*/
         for(tmpId = MSTP_MSTID_MIN; tmpId <= MSTP_MSTID_MAX; tmpId++)
         {
            if(MSTP_MSTI_VALID(tmpId))
            {
               mstiPortPtr = MSTP_MSTI_PORT_PTR(tmpId, lport);
               STP_ASSERT(mstiPortPtr);
               MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap,
                                      MSTP_MSTI_PORT_DISPUTED);
               MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap,
                                      MSTP_MSTI_PORT_AGREED);
            }
         }
      }
   }
   else
   {/* An MSTI */
      MSTP_MSTI_PORT_INFO_t  *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
      MSTP_MSTI_CONFIG_MSG_t *mstiMsgPtr  = NULL;

      STP_ASSERT(mstiPortPtr);
      mstiMsgPtr = mstp_findMstiCfgMsgInBpdu(pkt, mstid);
      STP_ASSERT(mstiMsgPtr);
      if(mstiMsgPtr->mstiFlags & MSTP_MSTI_FLAG_LEARNING)
      {/* The 'learning' flag is set in the received MSTI message */

         /*------------------------------------------------------------------
          * set 'disputed' and clear 'agreed' valrables for the MSTI
          *------------------------------------------------------------------*/
         MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_DISPUTED);
         MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_AGREED);
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_recordMastered
 *
 * Purpose:   For the CIST and a given Port,
 *               if the CIST message was received from a Bridge in a
 *               different MST Region, i.e. the 'rcvdInternal' flag is
 *               clear, the 'mastered' variable for this Port is cleared
 *               for all MSTIs.
 *            For a given MSTI and Port,
 *               if the MSTI message was received on a point to point link
 *               and the MSTI Message has the 'Master' flag set, set the
 *               'mastered' variable for this MSTI. Otherwise reset the
 *               'mastered' variable.
 *            (802.1Q-REV/D5.0 13.26.9)
 *            Called from Port Information (PIM) state machine.
 *
 * Params:    pkt   -> pointer to the packet buffer with BPDU in
 *            mstid -> MST Instance Identifier
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_recordMastered(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = NULL;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(pkt);
   STP_ASSERT(mstid == MSTP_CISTID || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   if(mstid == MSTP_CISTID)
   {/* The CIST */
      if(!MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                    MSTP_PORT_RCVD_INTERNAL))
      {/* the CIST message was received from a Bridge in a different
        * MST Region */
         MSTP_MSTI_PORT_INFO_t *mstiPortPtr = NULL;
         MSTID_t                tmpId;

         /*------------------------------------------------------------------
          * clear 'mastered' variable for this Port for all MSTIs
          *------------------------------------------------------------------*/
         for(tmpId = MSTP_MSTID_MIN; tmpId <= MSTP_MSTID_MAX; tmpId++)
         {
            if(MSTP_MSTI_VALID(tmpId))
            {
               mstiPortPtr = MSTP_MSTI_PORT_PTR(tmpId, lport);
               STP_ASSERT(mstiPortPtr);
               MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap,
                                      MSTP_MSTI_PORT_MASTERED);
            }
         }
      }
   }
   else
   {/* An MSTI */
      MSTP_MSTI_PORT_INFO_t  *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
      MSTP_MSTI_CONFIG_MSG_t *mstiMsgPtr  = mstp_findMstiCfgMsgInBpdu(pkt,
                                                                      mstid);
      STP_ASSERT(mstiPortPtr && mstiMsgPtr);
      if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                   MSTP_PORT_OPER_POINT_TO_POINT_MAC) &&
         (mstiMsgPtr->mstiFlags & MSTP_MSTI_FLAG_MASTER))
      {/* the MSTI Message was received on a point to point link and
        * the 'Master' flag is set, set 'mastered' variable */
         MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_MASTERED);
      }
      else
      {/* otherwise reset the 'mastered' variable */
         MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_MASTERED);
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_recordProposal
 *
 * Purpose:   For the CIST and a given Port,
 *               if the received CIST Message conveys a Designated Port Role,
 *               and has the 'Proposal' flag set, the CIST 'proposed' flag is
 *               set. Otherwise the CIST 'proposed' flag is not changed.
 *               Additionally, if the CIST Message was received from a Bridge
 *               in a different MST Region, i.e. the 'rcvdInternal' flag is
 *               clear, the 'proposed' flags for this Port for all MSTIs are
 *               set or cleared to the same value as the CIST 'proposed' flag.
 *               If the CIST message was received from a Bridge in the same
 *               MST Region, the MSTI 'proposed' flags are not changed.
 *            For a given MSTI and Port,
 *               if the received MSTI Message conveys a Designated Port Role,
 *               and has the 'Proposal' flag set, the MSTI 'proposed' flag is
 *               set. Otherwise the MSTI 'proposed' flag is not changed.
 *            NOTE: MSTI Messages received from Bridges external to the
 *                  MST Region are discarded and not processed by
 *                  recordProposal() function
 *            (802.1Q-REV/D5.0 13.26 m); 13.26.10)
 *            Called from Port Information (PIM) state machine.
 *
 * Params:    pkt   -> pointer to the packet buffer with BPDU in
 *            mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_recordProposal(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr  = NULL;
   MSTP_MST_BPDU_t       *bpdu         = NULL;
   bool                  rcvdInternal = FALSE;

   STP_ASSERT(pkt);
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   //bpdu = (MSTP_MST_BPDU_t *)FRAME_PDU(pkt);
   bpdu = (MSTP_MST_BPDU_t *)(pkt->data);
   rcvdInternal = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                            MSTP_PORT_RCVD_INTERNAL);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr  = MSTP_CIST_PORT_PTR(lport);
      bool                  cistProposed = FALSE;

      STP_ASSERT(cistPortPtr);
      if(((bpdu->cistFlags & MSTP_CIST_FLAG_PORT_ROLE) ==
                                                    MSTP_BPDU_ROLE_DESIGNATED)
         && (bpdu->cistFlags & MSTP_CIST_FLAG_PROPOSAL))
      {/* the received CIST Message conveys a Designated Port Role and has the
        * 'Proposal' flag set, the CIST 'proposed' flag should be set */
         MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_PROPOSED);
         cistProposed = TRUE;
      }

      if(!rcvdInternal)
      {/* the CIST Message was received from a Bridge in a different MST Region,
        * the 'proposed' flags for this Port for all MSTIs should be set or
        * cleared to the same value as the CIST 'proposed' flag */
         MSTP_MSTI_PORT_INFO_t *mstiPortPtr = NULL;
         MSTID_t                tmpId;

         for(tmpId = MSTP_MSTID_MIN; tmpId <= MSTP_MSTID_MAX; tmpId++)
         {
            if(MSTP_MSTI_VALID(tmpId))
            {
               mstiPortPtr = MSTP_MSTI_PORT_PTR(tmpId, lport);
               STP_ASSERT(mstiPortPtr);
               if(cistProposed)
                   MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap,
                                          MSTP_MSTI_PORT_PROPOSED);
               else
                   MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap,
                                          MSTP_MSTI_PORT_PROPOSED);
            }
         }
      }
   }
   else
   {
      MSTP_MSTI_CONFIG_MSG_t *cfgMsgPtr = mstp_findMstiCfgMsgInBpdu(pkt, mstid);

      STP_ASSERT(rcvdInternal == TRUE);
      STP_ASSERT(cfgMsgPtr);
      if(cfgMsgPtr &&
         ((cfgMsgPtr->mstiFlags & MSTP_MSTI_FLAG_PORT_ROLE) ==
                                                     MSTP_BPDU_ROLE_DESIGNATED)
         && (cfgMsgPtr->mstiFlags & MSTP_MSTI_FLAG_PROPOSAL))
      {/* the received MSTI Message conveys a Designated Port Role, and has the
        * 'Proposal' flag set, the MSTI 'proposed' flag should be set */
         MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

         STP_ASSERT(mstiPortPtr);
         MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap,  MSTP_MSTI_PORT_PROPOSED);
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_recordPriority
 *
 * Purpose:   Sets the components of the 'portPriority' variable to the values
 *            of the corresponding 'msgPriority' components.
 *            Called from Port Information (PIM) state machine.
 *            (802.1Q-REV/D5.0 13.26 f); 802.1D-2004 17.21.12)
  *
 * Params:    msti  -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_CB
 *
 **PROC-**********************************************************************/
void
mstp_recordPriority(MSTID_t mstid,  LPORT_t lport)
{
   STP_ASSERT(IS_VALID_LPORT(lport));
   STP_ASSERT(mstid == MSTP_CISTID || MSTP_VALID_MSTID(mstid));

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      cistPortPtr->portPriority = cistPortPtr->msgPriority;
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      mstiPortPtr->portPriority = mstiPortPtr->msgPriority;
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_recordTimes
 *
 * Purpose:   For the CIST and a given Port, sets 'portTimes' Message Age,
 *            Max Age, Forward Delay and remainingHops to the received values
 *            held in 'msgTimes' and 'portTimes' Hello Time to 'msgTimes'
 *            Hello Time if that is greater than the minimum specified in the
 *            Compatibility Range column of Table 17-1 of IEEE Std 802.1D,
 *            and to that minimum otherwise.
 *            For a given MSTI and Port, sets 'portTime' remainingHops to the
 *            received value held in 'msgTimes'.
 *            Called from Port Information (PIM) state machine.
 *            (802.1Q-REV/D5.0 13.26 n); 13.26.11)
 *
 * Params:    msti  -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_CB
 *
 **PROC-**********************************************************************/
void
mstp_recordTimes(MSTID_t mstid,  LPORT_t lport)
{
    struct ovsdb_idl_txn *txn = NULL;
    MSTP_OVSDB_LOCK;
    txn = ovsdb_idl_txn_create(idl);
    STP_ASSERT(IS_VALID_LPORT(lport));
   STP_ASSERT(mstid == MSTP_CISTID || MSTP_VALID_MSTID(mstid));

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      cistPortPtr->portTimes.messageAge = cistPortPtr->msgTimes.messageAge;
      if (cistPortPtr->portTimes.maxAge != cistPortPtr->msgTimes.maxAge) {
          mstp_util_set_cist_table_value(OPER_MAX_AGE, cistPortPtr->msgTimes.maxAge);
          cistPortPtr->portTimes.maxAge     = cistPortPtr->msgTimes.maxAge;
      }
      if (cistPortPtr->portTimes.fwdDelay != cistPortPtr->msgTimes.fwdDelay) {
          mstp_util_set_cist_table_value(OPER_FORWARD_DELAY, cistPortPtr->msgTimes.fwdDelay);
          cistPortPtr->portTimes.fwdDelay   = cistPortPtr->msgTimes.fwdDelay;
      }
      if (cistPortPtr->portTimes.hops != cistPortPtr->msgTimes.hops) {
          mstp_util_set_cist_table_value(REMAINING_HOPS, cistPortPtr->msgTimes.hops);
          cistPortPtr->portTimes.hops       = cistPortPtr->msgTimes.hops;
      }
      if (cistPortPtr->portTimes.helloTime != cistPortPtr->msgTimes.helloTime) {
          char port[20] = {0};
          mstp_util_set_cist_table_value(OPER_HELLO_TIME, cistPortPtr->msgTimes.helloTime);
          intf_get_port_name(lport,port);
          mstp_util_set_cist_port_table_value(port,OPER_HELLO_TIME, cistPortPtr->msgTimes.helloTime);
          cistPortPtr->portTimes.helloTime  = cistPortPtr->msgTimes.helloTime;
      }

      /* Validate 'portTimes' Hello Time ranges
       * NOTE: receive of an invalid 'Hello Time' value of 0 can cause
       *       tight loop between the Port Transmit (PTX) state machine's
       *       TRANSMIT_PERIODIC and IDLE states, and to fail to transmit
       *       BPDUs. */
      if(cistPortPtr->portTimes.helloTime < MSTP_HELLO_MIN_SEC)
         cistPortPtr->portTimes.helloTime = MSTP_HELLO_MIN_SEC;
      else if(cistPortPtr->portTimes.helloTime > MSTP_HELLO_MAX_SEC)
      {/* NOTE: 802.1Q-REV/d5.0 document does not pay attention on
        * this case, the 802.1D/D1 Annex Z.5.1 (and common sense) tell
        * to cover this case also */
         cistPortPtr->portTimes.helloTime = MSTP_HELLO_MAX_SEC;
      }
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      mstiPortPtr->portTimes.hops = mstiPortPtr->msgTimes.hops;
   }
   ovsdb_idl_txn_commit_block(txn);
   ovsdb_idl_txn_destroy(txn);
   MSTP_OVSDB_UNLOCK;
}

/**PROC+**********************************************************************
 * Name:      mstp_setRcvdMsgs
 *
 * Purpose:   Sets 'rcvdMsg' for the CIST, and makes the received CST or
 *            CIST message available to the CIST Port Information state
 *            machine. Additionally and if and only if 'rcvdInternal' is
 *            set, sets 'rcvdMsg' for each and every MSTI for which an
 *            MSTI message is conveyed in the BPDU, and makes available
 *            each MSTI message and the common parts of the CIST message
 *            priority (the CIST Root Identifier, External Root Path Cost,
 *            and Regional Root Identifier) to the Port Information state
 *            machine for that MSTI.
 *            (802.1Q-REV/D5.0 13.26.12)
 *            Called from Port Receive (PRX) state machine.
 *
 * Params:    pkt   -> pointer to the packet buffer with BPDU in
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_setRcvdMsgs(MSTP_RX_PDU *pkt, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr;
   MSTP_CIST_PORT_INFO_t *cistPortPtr;
   MSTID_t                mstid = MSTP_CISTID;
   MSTP_BPDU_TYPE_t       bpduType;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(pkt);
   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   cistPortPtr = MSTP_CIST_PORT_PTR(lport);
   STP_ASSERT(cistPortPtr);

   /*------------------------------------------------------------------------
    * set 'rcvdMsg' TRUE for the CIST
    *------------------------------------------------------------------------*/
   MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_RCVD_MSG);

   /*-------------------------------------------------------------------------
    * determine BPDU type
    *------------------------------------------------------------------------*/
   bpduType = mstp_getBpduType(pkt);

   MSTP_RX_BPDU_CNT++;

   /*------------------------------------------------------------------------
    * update internal statistics counters
    *------------------------------------------------------------------------*/
   if(bpduType == MSTP_BPDU_TYPE_MSTP)
   {
      cistPortPtr->dbgCnts.mstBpduRxCnt++;
      update_mstp_counters(lport, MSTP_RX_BPDU);
      cistPortPtr->dbgCnts.mstBpduRxCntLastUpdated = time(NULL);
   }
   else if(bpduType == MSTP_BPDU_TYPE_RSTP)
   {
      cistPortPtr->dbgCnts.rstBpduRxCnt++;
      cistPortPtr->dbgCnts.rstBpduRxCntLastUpdated = time(NULL);
   }
   else if(bpduType == MSTP_BPDU_TYPE_STP)
   {
      cistPortPtr->dbgCnts.cfgBpduRxCnt++;
      cistPortPtr->dbgCnts.cfgBpduRxCntLastUpdated = time(NULL);
   }
   else if(bpduType == MSTP_BPDU_TYPE_TCN)
   {
      cistPortPtr->dbgCnts.tcnBpduRxCnt++;
      cistPortPtr->dbgCnts.tcnBpduRxCntLastUpdated = time(NULL);
   }

   if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_RCVD_INTERNAL))
   {/* 'rcvdInternal' is set, then set 'rcvdMsg' for each and every MSTI
     * for which an MSTI configuration message is conveyed in the BPDU */
      MSTP_MST_BPDU_t *bpdu = (MSTP_MST_BPDU_t *)(pkt->data);
      int              len;

      STP_ASSERT(bpduType == MSTP_BPDU_TYPE_MSTP);

      /*---------------------------------------------------------------------
       * search for MSTI Configuration Messages conveyed in the BPDU
       *---------------------------------------------------------------------*/
      len = MSTP_MSTI_CFG_MSGS_SIZE(bpdu);
      if(len)
      {
         MSTP_MSTI_CONFIG_MSG_t *mstiMsg;
         char                   *end;

         STP_ASSERT(len/sizeof(MSTP_MSTI_CONFIG_MSG_t) <= 64);

         mstiMsg = (MSTP_MSTI_CONFIG_MSG_t *)bpdu->mstiConfigMsgs;
         end     = (char*)mstiMsg + len;

         while((char*)mstiMsg < end)
         {
            mstid = MSTP_GET_BRIDGE_SYS_ID_FROM_PKT(mstiMsg->mstiRgnRootId);
            if(MSTP_VALID_MSTID(mstid) && MSTP_MSTI_VALID(mstid))
            {
               MSTP_MSTI_PORT_INFO_t *mstiPortPtr =
                                              MSTP_MSTI_PORT_PTR(mstid, lport);
               STP_ASSERT(mstiPortPtr);
               /*------------------------------------------------------------
                * set 'rcvdMsg' TRUE for the MSTI
                *------------------------------------------------------------*/
               MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap,
                                      MSTP_MSTI_PORT_RCVD_MSG);

               /*------------------------------------------------------------
                * update statistics counters
                *------------------------------------------------------------*/
               mstiPortPtr->dbgCnts.mstiMsgRxCnt++;
               mstiPortPtr->dbgCnts.mstiMsgRxCntLastUpdated =
                                                         time(NULL);

            }

            mstiMsg++;
         }
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_setReRootTree
 *
 * Purpose:   This procedure sets 'reRoot' TRUE for this tree
 *            (the CIST or a given MSTI) for all Ports of the Bridge.
 *            (802.1Q-REV/D5.0 13.26 o); 13.26.13)
 *            Called from Port Role Transitions (PRT) state machine.
 *
 * Params:    mstid -> MST Instance Identifier
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_setReRootTree(MSTID_t mstid)
{
   LPORT_t lport;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));

   if(mstid == MSTP_CISTID)
   {/* set 'reRoot' for CIST for all ports */
      MSTP_CIST_PORT_INFO_t *cistPortPtr;

      for(lport = 1; lport <= MAX_LPORTS; lport++)
      {
         cistPortPtr = MSTP_CIST_PORT_PTR(lport);
         if(cistPortPtr)
         {
            MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_RE_ROOT);
         }
      }
   }
   else
   {/* set 'reRoot' for given MSTI for all ports */
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr;

      STP_ASSERT(MSTP_MSTI_VALID(mstid));

      for(lport = 1; lport <= MAX_LPORTS; lport++)
      {
         mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
         if(mstiPortPtr)
         {
            MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RE_ROOT);
         }
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_setSelectedTree
 *
 * Purpose:   Sets 'selected' TRUE for this tree (the CIST or a given MSTI)
 *            for all Ports of the Bridge if 'reselect' is FALSE for all Ports
 *            in this tree. If 'reselect' is TRUE for any Port in this tree,
 *            this procedure takes no action.
 *            (802.1Q-REV/D5.0 13.26 p); 13.26.14)
 *            Called from Port Role Selection (PRS) state machine.
 *
 * Params:    mstid -> MST Instance Identifier
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_setSelectedTree(MSTID_t mstid)
{
   LPORT_t lport;
   bool   reselect = FALSE;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(MSTP_INSTANCE_IS_VALID(mstid));

   if(mstid == MSTP_CISTID)
   {/* set 'selected' for CIST for all ports */
      MSTP_CIST_PORT_INFO_t *cistPortPtr = NULL;

      /* check if 'reselect' is FALSE for all Ports in this tree */
      for(lport = 1; lport <= MAX_LPORTS; lport++)
      {
         if((cistPortPtr = MSTP_CIST_PORT_PTR(lport)))
         {
            reselect = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                                 MSTP_CIST_PORT_RESELECT);
         }

         if(reselect)
            break;
      }

      if(!reselect)
      {/* set 'selected' TRUE for this tree for all ports */
         for(lport = 1; lport <= MAX_LPORTS; lport++)
         {
            if((cistPortPtr = MSTP_CIST_PORT_PTR(lport)))
            {
               MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap,
                                      MSTP_CIST_PORT_SELECTED);
            }
         }
      }
   }
   else
   {/* set 'selected' for given MSTI for all ports */
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = NULL;

      /* check if 'reselect' is FALSE for all Ports in this tree */
      for(lport = 1; lport <= MAX_LPORTS; lport++)
      {
         if((mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport)))
         {
            reselect = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                                 MSTP_MSTI_PORT_RESELECT);
         }

         if(reselect)
            break;
      }

      if(!reselect)
      {/* set 'selected' TRUE for this tree for all ports */
         for(lport = 1; lport <= MAX_LPORTS; lport++)
         {
            if((mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport)))
            {
               MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap,
                                      MSTP_MSTI_PORT_SELECTED);
            }
         }
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_setSyncTree
 *
 * Purpose:   This procedure sets 'sync' TRUE for this tree
 *            (the CIST or a given MSTI) for all Ports of the Bridge.
 *            (802.1Q-REV/D5.0 13.26 q); 13.26.15)
 *            Called from Port Role Transitions (PRT) state machine.
 *
 * Params:    mstid -> MST Instance Identifier
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_setSyncTree(MSTID_t mstid)
{
   LPORT_t lport;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(MSTP_INSTANCE_IS_VALID(mstid));

   if(mstid == MSTP_CISTID)
   {/* set 'sync' for the CIST for all ports */
      MSTP_CIST_PORT_INFO_t *cistPortPtr;

      for(lport = 1; lport <= MAX_LPORTS; lport++)
      {
         if((cistPortPtr = MSTP_CIST_PORT_PTR(lport)))
            MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_SYNC);
      }
   }
   else
   {/* set 'sync' for the given MSTI for all ports */
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr;

      STP_ASSERT(MSTP_MSTI_VALID(mstid));

      for(lport = 1; lport <= MAX_LPORTS; lport++)
      {
         if((mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport)))
            MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_SYNC);
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_setTcFlags
 *
 * Purpose:   For the CIST and a given Port:
 *            a) If the Topology Change Acknowledgment flag is set for the
 *               CIST in the received BPDU, sets 'rcvdTcAck' TRUE.
 *            b) If 'rcvdInternal' is clear and the Topology Change flag is set
 *               for the CIST in the received BPDU, sets 'rcvdTc' TRUE for the
 *               CIST and for each and every MSTI.
 *            c) If 'rcvdInternal' is set, sets 'rcvdTc' for the CIST if the
 *               Topology Change flag is set for the CIST in the received BPDU.
 *            For a given MSTI and Port, sets 'rcvdTc' for this MSTI if the
 *            Topology Change flag is set in the corresponding MSTI message.
 *            (802.1Q-REV/D5.0 13.26 r); 13.26.16)
 *            Called from the Port Information (PIM) state machine.
 *
 * Params:    pkt   -> pointer to the packet buffer with BPDU in
 *            mstid -> MST Instance Identifier
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_setTcFlags(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr  = NULL;
   bool                  rcvdInternal = FALSE;
   char                   portName[PORTNAME_LEN];
   char                   mst_str[10];

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(pkt);
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   rcvdInternal = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                            MSTP_PORT_RCVD_INTERNAL);
   STP_ASSERT(rcvdInternal ? mstp_isMstBpdu(pkt) : TRUE);

   if(mstid == MSTP_CISTID)
   {/* The CIST */
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);
      MSTP_MST_BPDU_t       *bpdu        = (MSTP_MST_BPDU_t *)(pkt->data);

      STP_ASSERT(cistPortPtr);

      if(bpdu->cistFlags & MSTP_CIST_FLAG_TC_ACK)
      {/* The Topology Change Acknowledgment flag is set for the
        * CIST in the received BPDU */

         /*------------------------------------------------------------------
          * set 'rcvdTcAck' TRUE and update received TC ACK flags
          * statistics counter
          *------------------------------------------------------------------*/
         MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_RCVD_TC_ACK);
         cistPortPtr->dbgCnts.tcAckFlagRxCnt++;
         cistPortPtr->dbgCnts.tcAckFlagRxCntLastUpdated = time(NULL);
      }

      if(rcvdInternal)
      {/* The 'rcvdInternal' is set */
         if(bpdu->cistFlags & MSTP_CIST_FLAG_TC)
         {/* And the Topology Change flag is set for the CIST */

            /*---------------------------------------------------------------
             * set 'rcvdTc' TRUE for the CIST and update received TC
             * flags statistics counter
             *---------------------------------------------------------------*/

            MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_RCVD_TC);
            cistPortPtr->dbgCnts.tcFlagRxCnt++;
            cistPortPtr->dbgCnts.tcFlagRxCntLastUpdated = time(NULL);
            mstpUpdateTcHistory(mstid, lport, FALSE);
            intf_get_port_name(lport, portName);
            VLOG_DBG("Topology Change received on port %s for %s from Source MAC %02x%02x%02x-%02x%02x%02x",portName,"CIST",PRINT_MAC_ADDR(commPortPtr->bpduSrcMac));
            log_event("MSTP_TC_RECV",
                EV_KV("port", "%s", portName),
                EV_KV("proto", "%s", "CIST"),
                EV_KV("mac", "%02x:%02x:%02x:%02x:%02x:%02x", PRINT_MAC_ADDR(commPortPtr->bpduSrcMac)));
         }
      }
      else if(bpdu->cistFlags & MSTP_CIST_FLAG_TC)
      {/* The 'rcvdInternal' is clear and the Topology Change flag is set
        * for the CIST in the received BPDU */
         MSTP_MSTI_PORT_INFO_t *mstiPortPtr = NULL;
         MSTID_t                tmpId;

         /*------------------------------------------------------------------
          * set 'rcvdTc' TRUE for the CIST and update received TC flags
          * statistics counter
          *------------------------------------------------------------------*/
         MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap,MSTP_CIST_PORT_RCVD_TC);
         cistPortPtr->dbgCnts.tcFlagRxCnt++;
         cistPortPtr->dbgCnts.tcFlagRxCntLastUpdated = time(NULL);

         mstpUpdateTcHistory(mstid, lport, FALSE);
         intf_get_port_name(lport, portName);
         VLOG_DBG("Topology Change received on port %s for %s from Source MAC %02x%02x%02x-%02x%02x%02x",portName,"CIST",PRINT_MAC_ADDR(commPortPtr->bpduSrcMac));
         log_event("MSTP_TC_RECV",
             EV_KV("port", "%s", portName),
             EV_KV("proto", "%s", "CIST"),
             EV_KV("mac", "%02x:%02x:%02x:%02x:%02x:%02x", PRINT_MAC_ADDR(commPortPtr->bpduSrcMac)));

         /*------------------------------------------------------------------
          * set 'rcvdTc' TRUE for each and every MSTI and update
          * received TC flags statistics counter
          *------------------------------------------------------------------*/
         for(tmpId = MSTP_MSTID_MIN; tmpId <= MSTP_MSTID_MAX; tmpId++)
         {
            if(MSTP_MSTI_VALID(tmpId))
            {
               mstiPortPtr = MSTP_MSTI_PORT_PTR(tmpId, lport);
               STP_ASSERT(mstiPortPtr);
               MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap,
                                      MSTP_MSTI_PORT_RCVD_TC);
               mstiPortPtr->dbgCnts.tcFlagRxCnt++;
               mstiPortPtr->dbgCnts.tcFlagRxCntLastUpdated =
                                                         time(NULL);
               mstpUpdateTcHistory(tmpId, lport, FALSE);
               intf_get_port_name(lport, portName);
               snprintf(mst_str, sizeof(mst_str), "MSTI %d", tmpId);
               VLOG_DBG("Topology Change received on port %s for %s from Source MAC %02x%02x%02x-%02x%02x%02x",portName,mst_str,PRINT_MAC_ADDR(commPortPtr->bpduSrcMac));
               log_event("MSTP_TC_RECV",
                   EV_KV("port", "%s", portName),
                   EV_KV("proto", "%s", mst_str),
                   EV_KV("mac", "%02x:%02x:%02x:%02x:%02x:%02x", PRINT_MAC_ADDR(commPortPtr->bpduSrcMac)));

               /*------------------------------------------------------------
                * kick Topology Change state machine (per-Tree per-Port)
                *------------------------------------------------------------*/
               STP_ASSERT(mstiPortPtr->pimState < MSTP_PIM_STATE_MAX);
               MSTP_SM_CALL_SM_PRINTF(MSTP_PRX,
                                      MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT,
                                      "PIM:",
                                      MSTP_PIM_STATE_s[mstiPortPtr->pimState],
                                      "TCM:", tmpId, lport);
               mstp_tcmSm(tmpId, lport);
            }
         }
      }
   }
   else
   {/* An MSTI */
      MSTP_MSTI_PORT_INFO_t  *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
      MSTP_MSTI_CONFIG_MSG_t *mstiMsgPtr  = NULL;

      STP_ASSERT(mstiPortPtr);
      mstiMsgPtr = mstp_findMstiCfgMsgInBpdu(pkt, mstid);
      STP_ASSERT(mstiMsgPtr);
      if(mstiMsgPtr && (mstiMsgPtr->mstiFlags & MSTP_MSTI_FLAG_TC))
      {/* The Topology Change flag is set in the MSTI message corresponding
        * to the given MSTI */
         /*-------------------------------------------------------------------
          * set 'rcvdTc' TRUE for the MSTI and update received TC flags
          * statistics counter
          *------------------------------------------------------------------*/
         MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_RCVD_TC);
         mstiPortPtr->dbgCnts.tcFlagRxCnt++;
         mstiPortPtr->dbgCnts.tcFlagRxCntLastUpdated = time(NULL);
         mstpUpdateTcHistory(mstid, lport, FALSE);
         intf_get_port_name(lport, portName);
         snprintf(mst_str, sizeof(mst_str), "MSTI %d", mstid);
         VLOG_DBG("Topology Change received on port %s for %s from Source MAC %02x%02x%02x-%02x%02x%02x",portName,mst_str,PRINT_MAC_ADDR(commPortPtr->bpduSrcMac));
         log_event("MSTP_TC_RECV",
             EV_KV("port", "%s", portName),
             EV_KV("proto", "%s", mst_str),
             EV_KV("mac", "%02x:%02x:%02x:%02x:%02x:%02x", PRINT_MAC_ADDR(commPortPtr->bpduSrcMac)));

      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_setTcPropTree
 *
 * Purpose:   If and only if 'restrictedTcn' is FALSE for the Port that
 *            invoked the procedure, sets 'tcProp' TRUE for the given
 *            tree (the CIST or a given MSTI) for all other Ports.
 *            (802.1Q-REV/D5.0 13.26 s); 13.26.17)
 *            Called from Topology Change (TCM) state machine.
 *
 * Params:    mstid -> MST Instance Identifier
 *            lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_setTcPropTree(MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr;
   LPORT_t lp;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(MSTP_INSTANCE_IS_VALID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   if (!commPortPtr)
   {
       STP_ASSERT(0);
   }

   if(MSTP_COMM_PORT_IS_BIT_SET(MSTP_COMM_PORT_PTR(lport)->bitMap,
                                MSTP_PORT_RESTRICTED_TCN))
   {/* 'restrictedTcn' is TRUE for the port, no further actions to perform */
      return;
   }

   /*------------------------------------------------------------------------
    * Set 'selected' TRUE for this tree (the CIST or a given MSTI) for all
    * Ports of the Bridge
    *------------------------------------------------------------------------*/

   if(mstid == MSTP_CISTID)
   {/* set 'tcProp' for CIST ports */
      MSTP_CIST_PORT_INFO_t *cistPortPtr;

      for(lp = 1; lp <= MAX_LPORTS; lp++)
      {
         if(lp == lport)
            continue;

         cistPortPtr = MSTP_CIST_PORT_PTR(lp);
         if(cistPortPtr)
         {
            MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap, MSTP_CIST_PORT_TC_PROP);

           /*------------------------------------------------------------------
            * kick Topology Change state machine  (per-Tree per-Port)
            *----------------------------------------------------------------*/
            mstp_tcmSm(mstid, lp);
         }
      }
   }
   else
   {/* set 'tcProp' for MSTI ports */
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr;

      STP_ASSERT(MSTP_MSTI_VALID(mstid));

      for(lp = 1; lp <= MAX_LPORTS; lp++)
      {
         if(lp == lport)
            continue;

         mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lp);
         if(mstiPortPtr)
         {
            MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap, MSTP_MSTI_PORT_TC_PROP);

           /*------------------------------------------------------------------
            * kick Topology Change state machine  (per-Tree per-Port)
            *----------------------------------------------------------------*/
            mstp_tcmSm(mstid, lp);
         }
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_syncMaster
 *
 * Purpose:   For all MSTIs, for each Port that has 'infoInternal' set:
 *               a) Clears the 'agree', 'agreed', and 'synced' variables;
 *               and
 *               b) Sets the 'sync' variable.
 *            (802.1Q-REV/D5.0 13.26.18)
 *            Called from the updtRolesTree() function
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_syncMaster(void)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr = NULL;
   LPORT_t                lport;

   STP_ASSERT(MSTP_ENABLED);

   for(lport = 1; lport <= MAX_LPORTS; lport++)
   {
      commPortPtr = MSTP_COMM_PORT_PTR(lport);
      if(commPortPtr &&
         MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,MSTP_PORT_INFO_INTERNAL))
      {
         MSTID_t mstid;
         for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
         {
            if(MSTP_MSTI_VALID(mstid))
            {
               MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid,
                                                                       lport);
               STP_ASSERT(mstiPortPtr);
               MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap,
                                      MSTP_MSTI_PORT_AGREE);
               MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap,
                                      MSTP_MSTI_PORT_AGREED);
               MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap,
                                      MSTP_MSTI_PORT_SYNCED);
               MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap,
                                      MSTP_MSTI_PORT_SYNC);
            }
         }
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_txTcn
 *
 * Purpose:   Transmits a Topology Change Notification BPDU
 *            (802.1Q-REV/D5.0 13.26 a); 802.1D-2004 17.21.21;)
 *            Called from Port Transmit (PTX) state machine.
 *
 * Params:    lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge, stp_multicast
 *
 **PROC-**********************************************************************/
void
mstp_txTcn(LPORT_t lport)
{
   MSTP_RX_PDU                   *pkt;
   MSTP_TCN_BPDU_t       *bpdu;
   MSTP_COMM_PORT_INFO_t *commPortPtr;
   MSTP_CIST_PORT_INFO_t *cistPortPtr;
   struct iface_data *idp = NULL;
   const char *my_mac = NULL;
   MAC_ADDRESS mac;
   int rc;



   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(IS_VALID_LPORT(lport));

   /*------------------------------------------------------------------------
    * allocate pkt buffer
    *------------------------------------------------------------------------*/
   if((pkt = (MSTP_RX_PDU *)malloc(sizeof(MSTP_RX_PDU))) == NULL)
   {
      return; /* resources exhaustion */
   }
   /*------------------------------------------------------------------------
    * common Per-Port information
    *------------------------------------------------------------------------*/
   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   if (!commPortPtr)
   {
       STP_ASSERT(0);
   }

   /*------------------------------------------------------------------------
    * CIST specific Per-Port information
    *------------------------------------------------------------------------*/
   cistPortPtr = MSTP_CIST_PORT_PTR(lport);
   STP_ASSERT(cistPortPtr);

   /*------------------------------------------------------------------------
    * initialize (zero) BPDU
    *------------------------------------------------------------------------*/
   bpdu = (MSTP_TCN_BPDU_t *)(pkt->data);
   /* cov-error can be ignored because its safe to write beyond frame[1] */
   /* coverity[overrun-buffer-arg : FALSE] */
   memset((char *)bpdu,0,sizeof(MSTP_TCN_BPDU_t));

   /*------------------------------------------------------------------------
    * fill pkt header
    *------------------------------------------------------------------------*/

   /* destination Multicast address */
   MAC_ADDR_COPY(stp_multicast, bpdu->lsapHdr.dst);

   /* get the mac address for the port */
   my_mac = intf_get_mac_addr(lport);
   sscanf(my_mac,"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]);
   MAC_ADDR_COPY(&mac, bpdu->lsapHdr.src);

   storeShortInPacket(&bpdu->lsapHdr.len, (SNAP + MSTP_STP_TCN_BPDU_LEN_MIN));
   bpdu->lsapHdr.dsap = 0x42;
   bpdu->lsapHdr.ssap = 0x42;
   bpdu->lsapHdr.ctrl = MSTP_LSAP_HDR_CTRL_VAL;

   /*------------------------------------------------------------------------
    * set protocol Id, version and BPDU type
    *------------------------------------------------------------------------*/
   bpdu->protocolId        = MSTP_STP_RST_MST_PROTOCOL_ID;
   bpdu->protocolVersionId = MSTP_PROTOCOL_VERSION_ID_STP;
   bpdu->bpduType          = MSTP_BPDU_TYPE_STP_TCN;

   /*------------------------------------------------------------------------
    * transmit the packet
    *------------------------------------------------------------------------*/
   MSTP_TX_BPDU_CNT++;
   /* update statistics counter */
   cistPortPtr->dbgCnts.tcnBpduTxCnt++;
   cistPortPtr->dbgCnts.tcnBpduTxCntLastUpdated = time(NULL);
   idp = find_iface_data_by_index(lport);

   if (idp == NULL) {
       VLOG_ERR("Failed to find interface data for MSTPDU TX! "
               "lport= %d", lport);
       STP_ASSERT(FALSE);
   }

   if (idp->pdu_registered != TRUE) {
       VLOG_ERR("Trying to send MSTPDU before registering, "
               "port=%s", idp->name);
       STP_ASSERT(FALSE);
   }
   pkt->pktLen = sizeof(uint32_t)+sizeof(MSTP_TCN_BPDU_t);
   rc = sendto(idp->pdu_sockfd, pkt->data, pkt->pktLen, 0, NULL, 0);
   if (rc == -1) {
       VLOG_ERR("Failed to send MSTPDU for interface=%s, rc=%d",
               idp->name, rc);
       STP_ASSERT(FALSE);
   }
   VLOG_DBG("If it is here!! Packet is OUT successfully!!!");


}

/**PROC+**********************************************************************
 * Name:      mstp_txConfig
 *
 * Purpose:   Transmits a Configuration BPDU.
 *            The first four components of the message priority vector
 *            conveyed in the BPDU are set to the value of the CIST Root
 *            Identifier, External Root Path Cost, Bridge Identifier,
 *            and Port Identifier components of the CIST's 'designatedPriority'
 *            parameter for this Port.
 *            The topology change flag is set if ('tcWhile' != 0) for the Port.
 *            The topology change acknowledgement flag is set to the value of
 *            'TcAck' for the Port. The remaining flags are set to zero.
 *            The value of the Message Age, Max Age, and Fwd Delay parameters
 *            conveyed in the BPDU are set to the values held in the CIST's
 *            'designatedTimes' parameter for the Port. The value of the
 *            Hello Time parameter conveyed in the BPDU is set to the value held
 *            in the CIST's 'portTimes' parameter for the Port.
 *            (802.1Q-REV/D5.0 13.26.19)
 *            Called from Port Transmit (PTX) state machine.
 *
 * Params:    lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_CB, mstp_Bridge, stp_multicast
 *
 **PROC-**********************************************************************/
void
mstp_txConfig(LPORT_t lport)
{
   MSTP_RX_PDU                       *pkt          = NULL;
   MSTP_CFG_BPDU_t                   *bpdu         = NULL;
   MSTP_COMM_PORT_INFO_t             *commPortPtr  = NULL;
   MSTP_CIST_PORT_INFO_t             *cistPortPtr  = NULL;
   MSTP_CIST_DESIGNATED_PRI_VECTOR_t *dsnPriVecPtr = NULL;
   MSTP_CIST_DESIGNATED_TIMES_t      *dsnTimesPtr  = NULL;
   const char *my_mac = NULL;
   int rc;
   struct iface_data *idp = NULL;
   MAC_ADDRESS mac;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(IS_VALID_LPORT(lport));

   /*------------------------------------------------------------------------
    * allocate pkt buffer
    *------------------------------------------------------------------------*/
   if((pkt = (MSTP_RX_PDU *)malloc(sizeof(MSTP_RX_PDU))) == NULL)
   {
      return; /* resources exhaustion */
   }
   /*------------------------------------------------------------------------
    * common Per-Port information
    *------------------------------------------------------------------------*/
   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   /*------------------------------------------------------------------------
    * CIST specific Per-Port information
    *------------------------------------------------------------------------*/
   cistPortPtr = MSTP_CIST_PORT_PTR(lport);
   STP_ASSERT(cistPortPtr);
   /*------------------------------------------------------------------------
    * initialize (zero) BPDU
    *------------------------------------------------------------------------*/
   bpdu = (MSTP_CFG_BPDU_t *)(pkt->data);

   /* cov-error can be ignored because its safe to write beyond frame[1] */
   /* coverity[overrun-buffer-arg : FALSE] */
   memset((char *)bpdu, 0, sizeof(MSTP_CFG_BPDU_t));

   /* destination Multicast address */
   MAC_ADDR_COPY(stp_multicast, bpdu->lsapHdr.dst);

   /* get the mac address for the port */
   my_mac = intf_get_mac_addr(lport);
   VLOG_DBG("MSTP Util : 5 : mac : %s", my_mac);
   sscanf(my_mac,"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]);
   MAC_ADDR_COPY(&mac, bpdu->lsapHdr.src);

   storeShortInPacket(&bpdu->lsapHdr.len,
                                        (SNAP + MSTP_STP_CONFIG_BPDU_LEN_MIN));
   bpdu->lsapHdr.dsap = 0x42;
   bpdu->lsapHdr.ssap = 0x42;
   bpdu->lsapHdr.ctrl = MSTP_LSAP_HDR_CTRL_VAL;

   /*------------------------------------------------------------------------
    * set protocol Id, version and BPDU type
    *------------------------------------------------------------------------*/
   bpdu->protocolId        = MSTP_STP_RST_MST_PROTOCOL_ID;
   bpdu->protocolVersionId = MSTP_PROTOCOL_VERSION_ID_STP;
   bpdu->bpduType          = MSTP_BPDU_TYPE_STP_CONFIG;

   /*------------------------------------------------------------------------
    * set message priority vector
    *------------------------------------------------------------------------*/
   dsnPriVecPtr = &cistPortPtr->designatedPriority;

   /* copy CIST Root Identifier */
   MAC_ADDR_COPY(dsnPriVecPtr->rootID.mac_address, bpdu->rootId.mac_address);
   storeShortInPacket(&bpdu->rootId.priority, dsnPriVecPtr->rootID.priority);
   /* copy CIST External Root Path Cost */
   storeLongInPacket(&bpdu->rootPathCost, dsnPriVecPtr->extRootPathCost);
   /* copy CIST Bridge Identifier */
   MAC_ADDR_COPY(dsnPriVecPtr->dsnBridgeID.mac_address,
                 bpdu->bridgeId.mac_address);
   storeShortInPacket(&bpdu->bridgeId.priority,
                                         dsnPriVecPtr->dsnBridgeID.priority);
   /* copy CIST Port Identifier  */
   storeShortInPacket(&bpdu->portId, dsnPriVecPtr->dsnPortID);

   /*------------------------------------------------------------------------
    * set message CIST flags
    *------------------------------------------------------------------------*/
   if(cistPortPtr->tcWhile != 0)
   {/* (tcWhile != 0), set topology change flag for the Port */
      bpdu->flags |= MSTP_CIST_FLAG_TC;
      /* increment propagated TC flags statistics counter */
      cistPortPtr->dbgCnts.tcFlagTxCnt++;
      cistPortPtr->dbgCnts.tcFlagTxCntLastUpdated = time(NULL);
   }

   if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_TC_ACK))
   {/* 'TcAck' is set, set topology change acknowledgement flag for the Port */
      bpdu->flags |= MSTP_CIST_FLAG_TC_ACK;
      /* increment transmitted TC ACK flags statistics counter */
      cistPortPtr->dbgCnts.tcAckFlagTxCnt++;
      cistPortPtr->dbgCnts.tcAckFlagTxCntLastUpdated = time(NULL);
   }
   /*------------------------------------------------------------------------
    * set message times parameters
    * NOTE: times in message are carried in units of 1/256 second
    *       (802.1D-2004 9.2.8)
    *------------------------------------------------------------------------*/
   dsnTimesPtr  = &cistPortPtr->designatedTimes;

   storeShortInPacket(&bpdu->fwdDelay, dsnTimesPtr->fwdDelay << 8);
   storeShortInPacket(&bpdu->maxAge, dsnTimesPtr->maxAge << 8);
   storeShortInPacket(&bpdu->msgAge, dsnTimesPtr->messageAge << 8);
   storeShortInPacket(&bpdu->helloTime, cistPortPtr->portTimes.helloTime << 8);


   MSTP_TX_BPDU_CNT++;
   idp = find_iface_data_by_index(lport);

   if (idp == NULL) {
       VLOG_ERR("Failed to find interface data for MSTPDU TX! "
               "lport= %d", lport);
       STP_ASSERT(FALSE);
   }

   if (idp->pdu_registered != TRUE) {
       VLOG_ERR("Trying to send MSTPDU before registering, "
               "port=%s", idp->name);
       STP_ASSERT(FALSE);
   }
   pkt->pktLen = sizeof(uint32_t)+sizeof(MSTP_CFG_BPDU_t);
   rc = sendto(idp->pdu_sockfd, pkt->data, pkt->pktLen, 0, NULL, 0);
   if (rc == -1) {
       VLOG_ERR("Failed to send LACPDU for interface=%s, rc=%d",
               idp->name, rc);
       STP_ASSERT(FALSE);
   }
   VLOG_DBG("If it is here!! Packet is OUT successfully!!!");

}

/**PROC+**********************************************************************
 * Name:      mstp_txMstp
 *
 * Purpose:   Transmits a MST BPDU, encoded according to the specification
 *            contained in 802.1Q-REV/D5.0 14.6
 *            The first six components of the CIST message priority vector
 *            conveyed in the BPDU are set to the value of the CIST's
 *            'designatedPriority' parameter for this Port. The Port Role
 *            in the BPDU is set to the current value of the 'role' variable
 *            for the transmitting port. The 'Agreement' and 'Proposal' flags
 *            in the BPDU are set to the values of the 'agree' and 'proposing'
 *            variables for the transmitting Port, respectively. The CIST
 *            topology change flag is set if ('tcWhile' != 0) for the Port.
 *            The topology change acknowledge flag in the BPDU is never used
 *            and is set to zero. The 'learning' and 'forwarding' flags in the
 *            BPDU are set to the values of the 'learning' and 'forwarding'
 *            variables for the CIST, respectively. The value of the
 *            Message Age, Max Age, and Fwd Delay parameters conveyed in the
 *            BPDU are set to the values held in the CIST's 'designatedTimes'
 *            parameter for the Port. The value of the Hello Time parameter
 *            conveyed in the BPDU is set to the value held in the CIST's
 *            'portTimes' parameter for the Port. If the value of the
 *            Force Protocol Version parameter is less than 3, no further
 *            parameters are encoded in the BPDU and the protocol version
 *            parameter is set to 2 (denoting a RST BPDU). Otherwise, the
 *            protocol version parameter is set to 3 and the remaining
 *            parameters of the MST BPDU are encoded:
 *               a) The version 3 length.
 *               b) The MST Configuration Identifier parameter of the BPDU is
 *                  set to the value of the 'MstConfigId' variable for the
 *                  Bridge.
 *               c) The CIST Internal Root Path Cost.
 *               d) The CIST Bridge Identifier.
 *               e) The CIST Remaining Hops.
 *               f) The parameters of each MSTI message, encoded in MSTID order.
 *            (802.1Q-REV/D5.0 13.26.20; 14.3.3; 14.6)
 *            Called from Port Transmit (PTX) state machine.
 *
 * Params:    lport -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_CB, mstp_Bridge, stp_multicast
 *
 **PROC-**********************************************************************/
void
mstp_txMstp(LPORT_t lport)
{
   MSTP_RX_PDU                               *pkt              = NULL;
   MSTP_MST_BPDU_t                   *bpdu             = NULL;
   MSTP_MSTI_INFO_t                  *mstiPtr          = NULL;
   MSTP_COMM_PORT_INFO_t             *commPortPtr      = NULL;
   MSTP_CIST_PORT_INFO_t             *cistPortPtr      = NULL;
   MSTP_CIST_DESIGNATED_PRI_VECTOR_t *cistDsnPriVecPtr = NULL;
   MSTP_CIST_DESIGNATED_TIMES_t      *cistDsnTimesPtr  = NULL;
   int                                bpduLen          = 0;
   MSTID_t                            mstid            = MSTP_CISTID;
   const char *my_mac = NULL;
   MAC_ADDRESS mac;
   struct iface_data *idp = NULL;
   int rc= 0;


   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(IS_VALID_LPORT(lport));

   /*------------------------------------------------------------------------
    * common Per-Port information
    *------------------------------------------------------------------------*/
   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   if (!commPortPtr)
   {
       STP_ASSERT(0);
   }


   /*------------------------------------------------------------------------
    * CIST specific Per-Port information
    *------------------------------------------------------------------------*/
   cistPortPtr = MSTP_CIST_PORT_PTR(lport);
   STP_ASSERT(cistPortPtr);

   /*------------------------------------------------------------------------
    * When we have multiple instances it is possible to call this function
    * in effort to transmit MSTI info when CIST port is disabled
    * (happens when MSTP task process 'port down' event).
    *------------------------------------------------------------------------*/
   if(cistPortPtr->role == MSTP_PORT_ROLE_DISABLED)
      return;

   /*------------------------------------------------------------------------
    * allocate pkt buffer
    *------------------------------------------------------------------------*/
   if((pkt = (MSTP_RX_PDU *)malloc(sizeof(MSTP_RX_PDU))) == NULL)
   {
      return; /* resources exhaustion */
   }

   /*------------------------------------------------------------------------
    * initialize (zero) BPDU
    *------------------------------------------------------------------------*/
   bpdu = (MSTP_MST_BPDU_t *)(pkt->data);

   /* cov-error can be ignored because its safe to write beyond frame[1] */
   /* coverity[overrun-buffer-arg : FALSE] */
   memset((char *)bpdu,0,sizeof(MSTP_MST_BPDU_t));

   /*------------------------------------------------------------------------
    * fill pkt header
    *------------------------------------------------------------------------*/

   /* destination Multicast address */
   MAC_ADDR_COPY(stp_multicast, bpdu->lsapHdr.dst);

   /* get the mac address for the port */
   my_mac = intf_get_mac_addr(lport);
   VLOG_DBG("MSTP Util : 5 : mac : %s", my_mac);
   sscanf(my_mac,"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]);
   MAC_ADDR_COPY(&mac, bpdu->lsapHdr.src);

   bpduLen            = SNAP + MSTP_RST_BPDU_LEN_MIN;
   bpdu->lsapHdr.dsap = 0x42;
   bpdu->lsapHdr.ssap = 0x42;
   bpdu->lsapHdr.ctrl = MSTP_LSAP_HDR_CTRL_VAL;

   /*------------------------------------------------------------------------
    * set protocol Id and BPDU type (protocol version will be set further)
    *------------------------------------------------------------------------*/
   bpdu->protocolId = MSTP_STP_RST_MST_PROTOCOL_ID;
   bpdu->bpduType   = MSTP_BPDU_TYPE_MST;

   /*------------------------------------------------------------------------
    * set message priority vector.
    * The first six components of the CIST message priority vector
    * conveyed in the BPDU are set to the value of the CIST's
    * 'designatedPriority' parameter for this Port.
    * NOTE: The CIST Internal Root Path Cost and the CIST Designated Bridge
    *       Identifier are encoded further, if Force Protocol Version parameter
    *       is set 'D_hpicfBridgeRstpProtocolVersion_ieee8021s'.
    *------------------------------------------------------------------------*/
   cistDsnPriVecPtr = &cistPortPtr->designatedPriority;

   /* copy the CIST Root Identifier */
   MAC_ADDR_COPY(cistDsnPriVecPtr->rootID.mac_address,
                 bpdu->cistRootId.mac_address);
   storeShortInPacket(&bpdu->cistRootId.priority,
                      cistDsnPriVecPtr->rootID.priority);

   /* copy the CIST External Root Path Cost */
   storeLongInPacket(&bpdu->cistExtPathCost, cistDsnPriVecPtr->extRootPathCost);

   /* copy the CIST Regional Root Identifier */
   MAC_ADDR_COPY(cistDsnPriVecPtr->rgnRootID.mac_address,
                 bpdu->cistRgnRootId.mac_address);
   storeShortInPacket(&bpdu->cistRgnRootId.priority,
                      cistDsnPriVecPtr->rgnRootID.priority);

   /* copy the CIST Port Identifier:
    * NOTE: Octets 26 and 27 convey the CIST Port Identifier of the
    *       transmitting Bridge Port
    *       (802.1Q-REV/D5.0 14.6 k)) */
   storeShortInPacket(&bpdu->cistPortId, cistPortPtr->portId);

   /*------------------------------------------------------------------------
    * set CIST port role.
    * NOTE: The Port Role in the BPDU should be set to the current value of
    *       the 'role' variable for the transmitting port
    *------------------------------------------------------------------------*/
   switch(cistPortPtr->role)
   {
      case MSTP_PORT_ROLE_ROOT:
         bpdu->cistFlags |= MSTP_BPDU_ROLE_ROOT;
      break;
      case MSTP_PORT_ROLE_DESIGNATED:
         bpdu->cistFlags |= MSTP_BPDU_ROLE_DESIGNATED;
      break;
      case MSTP_PORT_ROLE_ALTERNATE:
      case MSTP_PORT_ROLE_BACKUP:
         bpdu->cistFlags |= MSTP_BPDU_ROLE_ALTERNATE_OR_BACKUP;
      break;
      default:
         STP_ASSERT(0);
      break;
   }

   /*------------------------------------------------------------------------
    * set message flags.
    * NOTE: The 'Agreement' and 'Proposal' flags in the BPDU are set to the
    *       values of the 'agree' and 'proposing' variables for the
    *       transmitting Port, respectively.
    *       The CIST topology change flag is set if ('tcWhile' != 0) for the
    *       Port. The topology change acknowledge flag in the BPDU is never
    *       used and is set to zero. The 'learning' and 'forwarding' flags in
    *       the BPDU are set to the values of the 'learning' and 'forwarding'
    *       variables for the CIST, respectively.
    *------------------------------------------------------------------------*/

   if(MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap, MSTP_CIST_PORT_AGREE))
   {/* 'agree' is set, set 'Agreement' flag */
      bpdu->cistFlags |= MSTP_CIST_FLAG_AGREEMENT;
   }

   if(MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap, MSTP_CIST_PORT_PROPOSING))
   {/* 'proposing' is set, set 'Proposal' flag */
      bpdu->cistFlags |= MSTP_CIST_FLAG_PROPOSAL;
   }

   if(cistPortPtr->tcWhile != 0)
   {/* (tcWhile != 0), set  CIST topology change flag for the Port */
      VLOG_DBG("MSTP tcWhile : %d port : %d", cistPortPtr->tcWhile, lport);
      bpdu->cistFlags |= MSTP_CIST_FLAG_TC;
      /* increment propagated TC flags statistics counter */
      cistPortPtr->dbgCnts.tcFlagTxCnt++;
      cistPortPtr->dbgCnts.tcFlagTxCntLastUpdated = time(NULL);
   }

   if(MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap, MSTP_CIST_PORT_LEARNING))
   {/* set 'learning' flag */
      bpdu->cistFlags |= MSTP_CIST_FLAG_LEARNING;
   }

   if(MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap, MSTP_CIST_PORT_FORWARDING))
   {/* set 'forwarding' flag */
      bpdu->cistFlags |= MSTP_CIST_FLAG_FORWADING;
   }

   /*------------------------------------------------------------------------
    * set message times parameters.
    * The value of the Message Age, Max Age, and Fwd Delay parameters conveyed
    * in the BPDU are set to the values held in the CIST's 'designatedTimes'
    * parameter for the Port. The value of the Hello Time parameter conveyed in
    * the BPDU is set to the value held in the CIST's 'portTimes' parameter for
    * the Port.
    * NOTE: Times in message are carried in units of 1/256 second
    *       (802.1D-2004 9.2.8)
    *------------------------------------------------------------------------*/
   cistDsnTimesPtr = &cistPortPtr->designatedTimes;

   storeShortInPacket(&bpdu->msgAge, cistDsnTimesPtr->messageAge << 8);
   storeShortInPacket(&bpdu->maxAge, cistDsnTimesPtr->maxAge << 8);
   storeShortInPacket(&bpdu->fwdDelay, cistDsnTimesPtr->fwdDelay << 8);
   storeShortInPacket(&bpdu->helloTime, cistPortPtr->portTimes.helloTime << 8);

   /*------------------------------------------------------------------------
    * check the state of Force Protocol Version parameter
    *------------------------------------------------------------------------*/
   if(mstp_Bridge.ForceVersion < MSTP_PROTOCOL_VERSION_ID_MST)
   {/* If the value of the Force Protocol Version parameter is less than 3,
     * no further parameters are encoded in the BPDU and the protocol version
     * parameter is set to 2 (denoting an RST BPDU) */
     bpdu->protocolVersionId = MSTP_PROTOCOL_VERSION_ID_RST;
     /* Update RST BPDUs TX statistics */
     cistPortPtr->dbgCnts.rstBpduTxCnt++;
     cistPortPtr->dbgCnts.rstBpduTxCntLastUpdated = time(NULL);
   }
   else
   {/* Otherwise, the protocol version parameter is set to 3 (denoting an
     * MST BPDU) and the remaining parameters of the MST BPDU are encoded
     * NOTE: we will update the 'version3Length' parameter along the
     *       remained encoding process */
      MSTP_MSTI_CONFIG_MSG_t *mstiMsgPtr  = NULL;
      uint16_t                 version3Len = 0;

      /*---------------------------------------------------------------------
       * update Ethernet frame total length to include the size of the
       * 'version3Length' field.
       *---------------------------------------------------------------------*/
      bpduLen += sizeof(bpdu->version3Length);

      /*---------------------------------------------------------------------
       * the protocol version parameter
       *---------------------------------------------------------------------*/
      bpdu->protocolVersionId = MSTP_PROTOCOL_VERSION_ID_MST;

      /*---------------------------------------------------------------------
       * the MST Configuration Identifier parameter of the BPDU is set
       * to the value of the 'MstConfigId' variable for the Bridge
       *---------------------------------------------------------------------*/
      memcpy(&bpdu->mstConfigurationId, &mstp_Bridge.MstConfigId,
             sizeof(bpdu->mstConfigurationId));
      storeShortInPacket(&bpdu->mstConfigurationId.revisionLevel,
              mstp_Bridge.MstConfigId.revisionLevel);

      version3Len += sizeof(bpdu->mstConfigurationId);

      /*---------------------------------------------------------------------
       * copy the CIST Internal Root Path Cost */
      storeLongInPacket(&bpdu->cistIntRootPathCost,
                        cistDsnPriVecPtr->intRootPathCost);
      version3Len += sizeof(bpdu->cistIntRootPathCost);

      /*---------------------------------------------------------------------
       * copy the CIST Designated Bridge Identifier
       * NOTE: Octets 94 through 101 convey the CIST Bridge Identifier of the
       *       transmitting Bridge. The 12 bit system id extension component
       *       of the CIST Bridge Identifier shall be transmitted as 0.
       *       The behavior on receipt is unspecified if it is non-zero
       *      (802.1Q-REV/D5.0 14.6 t))
       *---------------------------------------------------------------------*/
      STP_ASSERT(MSTP_GET_BRIDGE_SYS_ID(MSTP_CIST_BRIDGE_IDENTIFIER) == 0);
      MAC_ADDR_COPY(cistDsnPriVecPtr->dsnBridgeID.mac_address,
                    bpdu->cistBridgeId.mac_address);
      storeShortInPacket(&bpdu->cistBridgeId.priority,
                         cistDsnPriVecPtr->dsnBridgeID.priority);
      version3Len += sizeof(bpdu->cistBridgeId);

      /*---------------------------------------------------------------------
       * the CIST Remaining Hops
       *---------------------------------------------------------------------*/
      bpdu->cistRemainingHops = cistDsnTimesPtr->hops;
      version3Len += sizeof(bpdu->cistRemainingHops);

      /*---------------------------------------------------------------------
       * The parameters of each MSTI message, encoded in MSTID order:
       * NOTE: No more than 64 MSTIs may be supported, as no more than 64
       *       MSTI Configuration Messages may be encoded in one MST BPDU
       *       (in a standard sized Ethernet frame).
       *---------------------------------------------------------------------*/
      mstiMsgPtr = (MSTP_MSTI_CONFIG_MSG_t *)bpdu->mstiConfigMsgs;
      for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_MSTID_MAX; mstid++)
      {
         /*------------------------------------------------------------------
          * to facilitate references
          *------------------------------------------------------------------*/
         mstiPtr = MSTP_MSTI_INFO(mstid);
         if(mstiPtr)
         {
            MSTP_MSTI_PORT_INFO_t *mstiPortPtr =
                                              MSTP_MSTI_PORT_PTR(mstid, lport);
            STP_ASSERT(mstiPortPtr);

            if((mstiPortPtr->role != MSTP_PORT_ROLE_UNKNOWN) &&
               (mstiPortPtr->role != MSTP_PORT_ROLE_DISABLED))
            {
               MSTP_MSTI_DESIGNATED_PRI_VECTOR_t *mstiDsnPriVecPtr = NULL;
               uint16_t                            priorityVal      = 0;

               /*------------------------------------------------------------
                * clear placeholder for the MSTI Configuration message as it
                * may contain the garbage left from the previous usage
                * of the packet buffer
                *------------------------------------------------------------*/
               memset((char *)mstiMsgPtr, 0, sizeof(MSTP_MSTI_CONFIG_MSG_t));

               /*------------------------------------------------------------
                * to facilitate the reference to 'designatedPriority' content
                *------------------------------------------------------------*/
               mstiDsnPriVecPtr = &mstiPortPtr->designatedPriority;

               /*------------------------------------------------------------
                * MSTI Regional Root Identifier */
               MAC_ADDR_COPY(mstiDsnPriVecPtr->rgnRootID.mac_address,
                             mstiMsgPtr->mstiRgnRootId.mac_address);
               storeShortInPacket(&mstiMsgPtr->mstiRgnRootId.priority,
                                  mstiDsnPriVecPtr->rgnRootID.priority);

               /*------------------------------------------------------------
                * MSTI Internal Root Path Cost */
               storeLongInPacket(&mstiMsgPtr->mstiIntRootPathCost,
                                 mstiDsnPriVecPtr->intRootPathCost);

               /*------------------------------------------------------------
                * MSTI Bridge Priority
                * NOTE: Bits 5 through 8 of Octet 14 convey the value of the
                *       Bridge Identifier Priority for this MSTI. Bits 1
                *       through 4 of Octet 14 shall be transmitted as 0, and
                *       ignored on receipt (802.1Q-REV/D5.0 14.6.1 d)).
                *------------------------------------------------------------*/
               priorityVal =
                           MSTP_GET_BRIDGE_PRIORITY(mstiPtr->BridgeIdentifier);
               mstiMsgPtr->mstiBridgePriority = ((priorityVal / 4096) << 4);

               /*------------------------------------------------------------
                * MSTI Port Priority
                * NOTE: Bits 5 through 8 of Octet 15 convey the value of the
                *       Port Identifier Priority for this MSTI. Bits 1 through
                *       4 of Octet 15 shall be transmitted as 0, and ignored
                *       on receipt (802.1Q-REV/D5.0 14.6.1 e)).
                *------------------------------------------------------------*/
               priorityVal = MSTP_GET_PORT_PRIORITY(mstiPortPtr->portId);
               mstiMsgPtr->mstiPortPriority = ((priorityVal / 16) << 4);

               /*------------------------------------------------------------
                * MSTI Remaning Hops
                *------------------------------------------------------------*/
               mstiMsgPtr->mstiRemainingHops =
                                             mstiPortPtr->designatedTimes.hops;

               /*------------------------------------------------------------
                * set MSTI port role
                *------------------------------------------------------------*/
               switch(mstiPortPtr->role)
               {
                  case MSTP_PORT_ROLE_ROOT:
                     mstiMsgPtr->mstiFlags |= MSTP_BPDU_ROLE_ROOT;
                     break;
                  case MSTP_PORT_ROLE_MASTER:
                     mstiMsgPtr->mstiFlags |= MSTP_BPDU_ROLE_MASTER_PORT;
                     break;
                  case MSTP_PORT_ROLE_DESIGNATED:
                     mstiMsgPtr->mstiFlags |= MSTP_BPDU_ROLE_DESIGNATED;
                     break;
                  case MSTP_PORT_ROLE_ALTERNATE:
                  case MSTP_PORT_ROLE_BACKUP:
                     mstiMsgPtr->mstiFlags |= MSTP_BPDU_ROLE_ALTERNATE_OR_BACKUP;
                     break;
                  default:
                     STP_ASSERT(0);
                     break;
               }

               /*------------------------------------------------------------
                * set other MSTI flags
                *------------------------------------------------------------*/

               if(MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                            MSTP_MSTI_PORT_AGREE))
               {/* 'agree' is set, set 'Agreement' flag */
                  mstiMsgPtr->mstiFlags |= MSTP_MSTI_FLAG_AGREEMENT;
               }

               if(MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                            MSTP_MSTI_PORT_PROPOSING))
               {/* 'proposing' is set, set 'Proposal' flag */
                  mstiMsgPtr->mstiFlags |= MSTP_MSTI_FLAG_PROPOSAL;
               }

               if(mstiPortPtr->tcWhile != 0)
               {/* (tcWhile != 0), set MSTI topology change flag */
                  mstiMsgPtr->mstiFlags |= MSTP_MSTI_FLAG_TC;
                  /* increment propagated TC flags statistics counter */
                  mstiPortPtr->dbgCnts.tcFlagTxCnt++;
                  mstiPortPtr->dbgCnts.tcFlagTxCntLastUpdated =
                                                         time(NULL);
               }

               if(MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                            MSTP_MSTI_PORT_LEARNING))
               {/* 'learning' is set, set 'learning' flag */
                  mstiMsgPtr->mstiFlags |= MSTP_MSTI_FLAG_LEARNING;
               }

               if(MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                            MSTP_MSTI_PORT_FORWARDING))
               {/* 'forwarding' is set, set 'forwarding' flag */
                  mstiMsgPtr->mstiFlags |= MSTP_MSTI_FLAG_FORWADING;
               }

               if(MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                            MSTP_MSTI_PORT_MASTER))
               {/* 'master' variable is set, set 'Master' flag */
                  mstiMsgPtr->mstiFlags |= MSTP_MSTI_FLAG_MASTER;
               }

               version3Len += sizeof(MSTP_MSTI_CONFIG_MSG_t);

               /* update MSTI CFG MSGs TX statistics */
               mstiPortPtr->dbgCnts.mstiMsgTxCnt++;
               mstiPortPtr->dbgCnts.mstiMsgTxCntLastUpdated =
                                                         time(NULL);

               /*------------------------------------------------------------
                * debug trace, if enabled
                *------------------------------------------------------------*/
               mstiMsgPtr++;

            }
         }
      }

      /*---------------------------------------------------------------------
       * set Version 3 Length field of the BPDU
       *---------------------------------------------------------------------*/
      storeShortInPacket(&bpdu->version3Length, version3Len);

      /*---------------------------------------------------------------------
       * update Ethernet frame total length to include MST Configuration Data
       *---------------------------------------------------------------------*/
      bpduLen += version3Len;

      /* Update MST BPDUs TX statistics */
      cistPortPtr->dbgCnts.mstBpduTxCnt++;
      update_mstp_counters(lport, MSTP_TX_BPDU);
      cistPortPtr->dbgCnts.mstBpduTxCntLastUpdated = time(NULL);
   }

   /*------------------------------------------------------------------------
    * convert Ethernet frame length to the network byte order
    *------------------------------------------------------------------------*/
   storeShortInPacket(&bpdu->lsapHdr.len, bpduLen);

   /*------------------------------------------------------------------------
    * set pkt frame
    *------------------------------------------------------------------------*/
   /*------------------------------------------------------------------------
    * debug trace, if enabled
    *------------------------------------------------------------------------*/
   mstid = MSTP_CISTID;

   /*------------------------------------------------------------------------
    * transmit the packet
    *------------------------------------------------------------------------*/
   MSTP_TX_BPDU_CNT++;
   idp = find_iface_data_by_index(lport);

   if (idp == NULL) {
       VLOG_ERR("Failed to find interface data for MSTPDU TX! "
               "lport= %d", lport);
       STP_ASSERT(FALSE);
   }

   if (idp->pdu_registered != TRUE) {
       VLOG_ERR("Trying to send MSTPDU before registering, "
               "port=%s", idp->name);
       STP_ASSERT(FALSE);
   }
   pkt->pktLen = ENET_HDR_SIZ + bpduLen;
   rc = sendto(idp->pdu_sockfd, pkt->data, pkt->pktLen, 0, NULL, 0);
   if (rc == -1) {
       VLOG_ERR("Failed to send MSTPDU for interface=%s, rc=%d",
               idp->name, rc);
       STP_ASSERT(FALSE);
   }
   VLOG_DBG("If it is here!! Packet is OUT successfully!!!");

}

/**PROC+**********************************************************************
 * Name:      mstp_updtRcvdInfoWhile
 *
 * Purpose:   Updates 'rcvdInfoWhile'. The value assigned to 'rcvdInfoWhile'
 *            is three times the Hello Time, if either:
 *               a) Message Age, incremented by 1 second and rounded to the
 *                  nearest whole second, does not exceed Max Age and the
 *                  information was received from a Bridge external to the
 *                  MST Region ('rcvdInternal' FALSE);
 *               or
 *               b) 'remainingHops', decremented by one, is greater than zero
 *                  and the information was received from a Bridge internal
 *                  to the MST Region ('rcvdInternal' TRUE);
 *               and is zero otherwise.
 *            The values of Message Age, Max Age, 'remainingHops', and
 *            Hello Time used in these calculations are taken from the
 *            CIST's 'portTimes' parameter, and are not changed by this
 *            procedure.
 *            (802.1Q-REV/D5.0 13.26.22)
 *            Called from Port Information state machine.
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
mstp_updtRcvdInfoWhile(MSTID_t mstid, LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr   = NULL;
   MSTP_CIST_PORT_INFO_t *cistPortPtr   = NULL;
   MSTP_MSTI_PORT_INFO_t *mstiPortPtr   = NULL;
   bool                  rcvdInternal  = FALSE;
   uint16_t                rcvdInfoWhile = 0;
   uint16_t                messageAge    = 0;
   uint16_t                maxAge        = 0;
   int16_t                  remainingHops = 0;
   uint16_t                helloTime     = 0;

   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(MSTP_INSTANCE_IS_VALID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   cistPortPtr = MSTP_CIST_PORT_PTR(lport);
   STP_ASSERT(cistPortPtr);

   if(mstid != MSTP_CISTID)
   {
      mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
      STP_ASSERT(mstiPortPtr);
   }

   if(commPortPtr->rcvdSelfSentPkt)
   {
      if(mstid == MSTP_CISTID)
      {/* On the 'looped' CIST port let setup aging timer to a random value to
        * minimize the chance for this port to be involved to the Forwarding
        * state negotiation with the peer port in the context of an external
        * loop existence. That random value is a period of time when we ignore
        * all BPDUs coming on the 'looped' port. Doing this we want to escape
        * generation of Topology Changes by this port until external loop has
        * not been resolved */
         uint8_t min = MSTP_HELLO_MAX_SEC;   /* 10 seconds */
         uint8_t max = MSTP_HELLO_MAX_SEC*3; /* 30 seconds */

         cistPortPtr->rcvdInfoWhile = min + (rand() % (1 + max - min));
         STP_ASSERT((cistPortPtr->rcvdInfoWhile >= min) &&
                (cistPortPtr->rcvdInfoWhile <= max));
      }
      else
      {/* On the 'looped' MSTI port let synchronise the 'rcvdInfoWhile' aging
        * timer with the value currently set for the 'looped' CIST port */
         mstiPortPtr->rcvdInfoWhile = cistPortPtr->rcvdInfoWhile;
      }

      return;
   }

   rcvdInternal = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                            MSTP_PORT_RCVD_INTERNAL);
   STP_ASSERT((mstid != MSTP_CISTID) ? (rcvdInternal == TRUE) : true);

   /*------------------------------------------------------------------------
    * The values of Message Age, Max Age and Hello Time are taken from the
    * CIST's 'portTimes' parameter
    * NOTE: the value of 'remainingHops' is taken from the 'portTimes'
    *           parameter associated with given 'mstid', i.e the CIST or MSTI
    *------------------------------------------------------------------------*/
   messageAge    = cistPortPtr->portTimes.messageAge;
   maxAge        = cistPortPtr->portTimes.maxAge;
   helloTime     = cistPortPtr->portTimes.helloTime;
   remainingHops = (mstid == MSTP_CISTID) ? cistPortPtr->portTimes.hops :
                                            mstiPortPtr->portTimes.hops;

   /*------------------------------------------------------------------------
    * Calculate new value for the 'rcvdInfoWhile' variable
    *------------------------------------------------------------------------*/
   messageAge    += 1;
   remainingHops -= 1;

   if(((messageAge <= maxAge) && !rcvdInternal) ||
      ((remainingHops > 0)    &&  rcvdInternal))
   {/* Message Age, incremented by 1 second, does not exceed Max Age and the
     * information was received from a Bridge external to the MST Region
     * OR
     * 'remainingHops', decremented by one, is greater than zero and the
     * information was received from a Bridge internal to the MST Region */

      rcvdInfoWhile = (3 * helloTime);
   }
   else
   {/* and is zero otherwise */
      rcvdInfoWhile = 0;
   }

   /*------------------------------------------------------------------------
    * Apply new value of 'rcvdInfoWhile' to the given port for the given Tree
    * and update statistics counters, if necessary
    *------------------------------------------------------------------------*/
   if(mstid == MSTP_CISTID)
   {
      cistPortPtr->rcvdInfoWhile = rcvdInfoWhile;

      if(!rcvdInternal && (messageAge > maxAge))
      {/* Message Age exceeds Max Age */
         cistPortPtr->dbgCnts.agedBpduCnt++;
         cistPortPtr->dbgCnts.agedBpduCntLastUpdated = time(NULL);
      }

      if(rcvdInternal && (remainingHops <= 0) )
      {/* 'remainingHops' is less than or equal to zero */
         cistPortPtr->dbgCnts.exceededHopsBpduCnt++;
         cistPortPtr->dbgCnts.exceededHopsBpduCntLastUpdated =
                                                         time(NULL);
      }
   }
   else
   {
      mstiPortPtr->rcvdInfoWhile = rcvdInfoWhile;
      if(remainingHops <= 0)
      {/* 'remainingHops' is less than or equal to zero */
         mstiPortPtr->dbgCnts.exceededHopsMsgCnt++;
         mstiPortPtr->dbgCnts.exceededHopsMsgCntLastUpdated =
                                                         time(NULL);
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_updtRolesTree
 *
 * Purpose:   This procedure calculates the Spanning Tree priority
 *            vectors and timer values, for the CIST or a given MSTI.
 *            It also assignes the CIST or MSTI port role for each
 *            Port and updates Port's Port Priority Vector and Spanning
 *            Tree Timer Information.
 *            (802.1Q-REV/D5.0 13.26.23; 13.9; 13.10; 13.11;)
 *            Called from Port Role Selection (PRS) state machine
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *
 * Returns:   none
 *
 * Globals:   mstp_CB, mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_updtRolesTree(MSTID_t mstid)
{
   struct ovsdb_idl_txn *txn = NULL;
   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(mstid == MSTP_CISTID || MSTP_VALID_MSTID(mstid));
   MSTP_OVSDB_LOCK;
   txn = ovsdb_idl_txn_create(idl);
   if(mstid == MSTP_CISTID)
      mstp_updtRolesCist();
   else
      mstp_updtRolesMsti(mstid);
   ovsdb_idl_txn_commit_block(txn);
   ovsdb_idl_txn_destroy(txn);
   MSTP_OVSDB_UNLOCK;
}

/**PROC+**********************************************************************
 * Name:      mstp_updtRolesCist
 *
 * Purpose:   Helper function called by the 'updtRolesTree' function to
 *            calculate the CIST Priority Vectors (13.9, 13.10) and Timer
 *            Values. It also assignes the CIST Port Role for each
 *            Port and updates Port's Port Priority Vector and Spanning
 *            Tree Timer Information.
 *            (802.1Q-REV/D5.0 13.26.23)
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   mstp_CB, mstp_Bridge
 *
 **PROC-**********************************************************************/
static void
mstp_updtRolesCist(void)
{
   MSTP_COMM_PORT_INFO_t         *commPortPtr        = NULL;
   MSTP_CIST_PORT_INFO_t         *cistPortPtr        = NULL;
   bool                          cistRgnRootChanged = FALSE;
   bool                          hadNonZeroCistEPC  = FALSE;
   MSTP_CIST_BRIDGE_PRI_VECTOR_t  cistRootPriVec;
   MSTP_PORT_ID_t                 cistRootPortId;
   LPORT_t                        lport;
   MSTP_PORT_ROLE_t               selectedRole = MSTP_PORT_ROLE_UNKNOWN;
   MSTP_CIST_ROOT_TIMES_t         cistRootTimes;
   bool                           rootTimeChange = FALSE;
   uint16_t                       rootHelloTime = 0;
   char                           oldRootPortName[PORTNAME_LEN];
   char                           newRootPortName[PORTNAME_LEN];
   char                           designatedRoot[MSTP_ROOT_ID] = {0};
   char                           regionalRoot[MSTP_ROOT_ID] = {0};
   hadNonZeroCistEPC = (MSTP_CIST_ROOT_PRIORITY.extRootPathCost == 0);

   /*------------------------------------------------------------------------
    * Assume that the Bridge's own Bridge Priority Vector is the best, i.e.
    * it is the Bridge's Root Priority Vector. Further if we find any port
    * whose Root Path Priority Vector is better we will update the Root
    * Priority Vector with that better info.
    * NOTE: Bridge's Bridge Priority Vector = {B : 0 : B : 0 : B : 0}, i.e.
    *       the CIST Root Identifier, CIST Regional Root Identifier,
    *       and Designated Bridge Identifier components are all equal
    *       to the value of the CIST Bridge Identifier of this Bridge.
    *       The remaining components (External Root Path Cost, Internal
    *       Root Path Cost, Designated Port Identifier) are set to zero.
    *------------------------------------------------------------------------*/
   cistRootPriVec = MSTP_CIST_BRIDGE_PRIORITY;

   /*------------------------------------------------------------------------
    * Root Port is not chosen yet (assume this Bridge is the CIST Root)
    *------------------------------------------------------------------------*/
   cistRootPortId = 0;

   /*------------------------------------------------------------------------
    * Find a Priority Vector that is the best of the set of Priority Vectors
    * comprising the Bridge's own Bridge Priority Vector plus all the
    * calculated Root Path Priority Vectors whose 'DesignatedBridgeID' Bridge
    * Address component is not equal to that component of the Bridge's own
    * Bridge Priority Vector and Port's 'restrictedRole' parameter is FALSE
    *------------------------------------------------------------------------*/
   for(lport = 1; lport <= MAX_LPORTS; lport++)
   {
      commPortPtr = MSTP_COMM_PORT_PTR(lport);
      cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT((commPortPtr != NULL) ?
             (cistPortPtr != NULL) : (cistPortPtr == NULL));

      if(commPortPtr && cistPortPtr)
      {
         if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                      MSTP_PORT_PORT_ENABLED) &&
            (cistPortPtr->infoIs == MSTP_INFO_IS_RECEIVED) &&
            (cistPortPtr->rcvdInfoWhile != 0))

         {/* port is not 'Disabled', and has a Port Priority Vector that has
           * been recorded from a received message and not aged out
           * ('infoIs' == 'Received') */
            MSTP_CIST_ROOT_PATH_PRI_VECTOR_t rootPathPriVec;

            /*----------------------------------------------------------------
             * Calculate Root Path Priority Vector for the Port
             * NOTE: A Root Path Priority Vector for a Port can be calculated
             *       from a Port Priority Vector that contains information from
             *       a Message Priority Vector
             *---------------------------------------------------------------*/
            rootPathPriVec = cistPortPtr->portPriority;

            if(MAC_ADDRS_EQUAL(rootPathPriVec.dsnBridgeID.mac_address,
                               MSTP_CIST_BRIDGE_PRIORITY.dsnBridgeID.mac_address)
               ||
               MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                         MSTP_PORT_RESTRICTED_ROLE))
            {/* we are interested only in ports whose 'DesignatedBridgeID'
              * Bridge Address component is not equal to that component of the
              * Bridge's own Bridge Priority Vector and Port's 'restrictedRole'
              * parameter is FALSE */
               continue;
            }

           /*----------------------------------------------------------------
            * Modify Port's Root Path Priority Vector according to the MST
            * Region membership of the sending Bridge
            *----------------------------------------------------------------*/
           if(!MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                         MSTP_PORT_RCVD_INTERNAL))
            {/* the Port Priority Vector was received from a Bridge that is
              * in a different MST Region than this receiving Bridge */

               rootPathPriVec.extRootPathCost +=
                                             commPortPtr->ExternalPortPathCost;
               mstp_util_set_cist_table_value(CIST_PATH_COST,rootPathPriVec.extRootPathCost);
               rootPathPriVec.rgnRootID = MSTP_CIST_BRIDGE_IDENTIFIER;
               /* the Internal Root Path Cost component of the Message Priority
                * Vector must have been set to zero on reception */
               STP_ASSERT(cistPortPtr->msgPriority.intRootPathCost == 0);
            }
            else
            {/* the Port Priority Vector was received from a Bridge that is
              * in the same MST Region as this receiving Bridge */
               char port[20] = {0};
               rootPathPriVec.intRootPathCost +=
                                             cistPortPtr->InternalPortPathCost;
               mstp_util_set_cist_table_value(ROOT_PATH_COST,rootPathPriVec.intRootPathCost);
               intf_get_port_name(lport,port);
               mstp_util_set_cist_port_table_value(port,PORT_PATH_COST,rootPathPriVec.intRootPathCost);
               mstp_util_set_cist_port_table_value(port,CIST_PATH_COST,rootPathPriVec.intRootPathCost);
               mstp_util_set_cist_port_table_value(port,DESIGNATED_PATH_COST,rootPathPriVec.intRootPathCost);
            }

            /*----------------------------------------------------------------
             * Compare newly calculated Port's Root Path Priority Vector
             * against the current Bridge's Root Priority Vector.
             *    - If new info is better then update Bridge's Root Priority
             *      Vector with that new info
             *    - If Priority Vectors are the same, but received Port ID is
             *      better than current Root Port ID then update the
             *      Bridge's Root Priority Vector with that new info
             *---------------------------------------------------------------*/
           if((mstp_cistPriorityVectorsCompare(&rootPathPriVec,
                                               &cistRootPriVec) < 0) ||
              (!mstp_cistPriorityVectorsCompare(&rootPathPriVec,
                                                &cistRootPriVec) &&
               (cistPortPtr->portId < cistRootPortId)))
           {/* the Port's Root Path Priority Vector is better than the
             * current Bridge's Root Priority Vector, so update it
             * from the better vector */
              cistRootPriVec = rootPathPriVec;
              cistRootPortId = cistPortPtr->portId;
           }
         }
      }/* end 'if(commPortPtr && cistPortPtr)' statement */
   }/* end 'for(lport = 1; lport <= MAX_LPORTS; lport++)' loop */

   cistRgnRootChanged = !MSTP_BRIDGE_ID_EQUAL(MSTP_CIST_ROOT_PRIORITY.rgnRootID,
                                              cistRootPriVec.rgnRootID);

   if((mstp_cistPriorityVectorsCompare(&MSTP_CIST_ROOT_PRIORITY,
                                       &cistRootPriVec) != 0)
      && cistRgnRootChanged &&
      (hadNonZeroCistEPC || (cistRootPriVec.extRootPathCost != 0)))
   {/* The Root Priority Vector for the CIST is recalculated and has a
     * different Regional Root Identifier than that previously selected
     * and has or had a non-zero CIST External Root Path Cost */
      mstp_syncMaster();
   }

   /*-------------------------------------------------------------------------
    * Check if the CST Root has been changed, if so then update the CST Root
    * change history.
    *------------------------------------------------------------------------*/
   if(!MSTP_BRIDGE_ID_EQUAL(MSTP_CIST_ROOT_PRIORITY.rootID,
                            cistRootPriVec.rootID))
   {
      mstp_updtMstiRootInfoChg(MSTP_CISTID);
      mstp_updateCstRootHistory(cistRootPriVec.rootID);
      mstp_logNewRootId(MSTP_CIST_ROOT_PRIORITY.rootID,
                        cistRootPriVec.rootID,TRUE,MSTP_CISTID);
   }
   snprintf(designatedRoot,MSTP_ROOT_ID,"%d.%d.%02x:%02x:%02x:%02x:%02x:%02x",cistRootPriVec.rootID.priority,
           MSTP_CISTID, cistRootPriVec.rootID.mac_address[0],
           cistRootPriVec.rootID.mac_address[1],cistRootPriVec.rootID.mac_address[2],
           cistRootPriVec.rootID.mac_address[3],cistRootPriVec.rootID.mac_address[4],
           cistRootPriVec.rootID.mac_address[5]);
   mstp_util_set_cist_table_string(DESIGNATED_ROOT,designatedRoot);

   /*-------------------------------------------------------------------------
    * Check if the IST Regional Root has been changed, if so then update
    * the IST Regional Root change history.
    *------------------------------------------------------------------------*/
   if(cistRgnRootChanged)
   {
      mstp_updtMstiRootInfoChg(MSTP_CISTID);
      mstp_updateIstRootHistory(cistRootPriVec.rgnRootID);
      mstp_logNewRootId(MSTP_CIST_ROOT_PRIORITY.rgnRootID,
                        cistRootPriVec.rgnRootID,FALSE,MSTP_CISTID);
   }
   snprintf(regionalRoot,MSTP_ROOT_ID,"%d.%d.%02x:%02x:%02x:%02x:%02x:%02x",cistRootPriVec.rgnRootID.priority,
           MSTP_CISTID,cistRootPriVec.rgnRootID.mac_address[0],
           cistRootPriVec.rgnRootID.mac_address[1],cistRootPriVec.rgnRootID.mac_address[2],
           cistRootPriVec.rgnRootID.mac_address[3],cistRootPriVec.rgnRootID.mac_address[4],
           cistRootPriVec.rgnRootID.mac_address[5]);
   mstp_util_set_cist_table_string(REGIONAL_ROOT,regionalRoot);

   if (cistRootPortId != MSTP_CIST_ROOT_PORT_ID)
   {
      /* PortId "0" indicates the bridge is the root */
      if(cistRootPortId != 0) {
        char port[20] = {0};
        intf_get_port_name(MSTP_GET_PORT_NUM(cistRootPortId),port);
        mstp_util_set_cist_table_string(ROOT_PORT,port);
      }
      else {
        mstp_util_set_cist_table_string(ROOT_PORT,"0");
      }
      mstp_updtMstiRootInfoChg(MSTP_CISTID);

      /* Log root port change */
      if(mstp_debugLog                 &&
         (MSTP_CIST_ROOT_PORT_ID != 0) &&
         cistRootPortId != 0)
      {
         intf_get_port_name(MSTP_GET_PORT_NUM(cistRootPortId), newRootPortName);
         intf_get_port_name(MSTP_GET_PORT_NUM(MSTP_CIST_ROOT_PORT_ID), oldRootPortName);
         VLOG_DBG("%s Root Port changed from %s to %s",
               "CIST",
               oldRootPortName,
               newRootPortName);
         log_event("MSTP_NEW_ROOT_PORT",
              EV_KV("proto", "CIST"),
              EV_KV("old_port","%s", oldRootPortName),
              EV_KV("new_port","%s", newRootPortName));

      }
   }

   /*-------------------------------------------------------------------------
    * Record calculated Root Priority Vector to the CIST's per-Bridge
    * variables: 'cistRootPortId' and 'cistRootPriority'.
    *------------------------------------------------------------------------*/
   MSTP_CIST_ROOT_PORT_ID  = cistRootPortId;
   MSTP_CIST_ROOT_PRIORITY = cistRootPriVec;
   mstp_util_set_cist_table_value(ROOT_PRIORITY,MSTP_CIST_ROOT_PRIORITY.rootID.priority);

   /*-------------------------------------------------------------------------
    * Calculate the Bridge's Root Times ('rootTimes') for the CIST.
    * Set 'rootTimes' equal to:
    *    1) 'BridgeTimes', if the chosen Root Priority Vector is the Bridge
    *       Priority Vector, otherwise
    *    2) 'portTimes' for the port associated with the selected
    *       Root Priority Vector, with the Message Age component incremented
    *       by 1 second and rounded to the nearest whole second if the
    *       information was received from a Bridge external to the MST
    *       Region ('rcvdInternal' FALSE), and with 'remainingHops'
    *       decremented by one if the information was received from a Bridge
    *       internal to the MST Region ('rcvdInternal' TRUE).
    *------------------------------------------------------------------------*/
   cistRootTimes = MSTP_CIST_ROOT_TIMES;
   rootHelloTime = MSTP_CIST_ROOT_HELLO_TIME;
   if(cistRootPortId == 0)
   {/* case 1) from the above, i.e. this Bridge is the Root for the tree as
     * this Bridge's own Priority Vector is the best over all Port's
     * Root Path Priority Vectors */
      MSTP_CIST_ROOT_TIMES = MSTP_CIST_BRIDGE_TIMES;
      MSTP_CIST_ROOT_HELLO_TIME = 0;

      /* Copy the operational timers from config as the bridge is the root for thsi CIST */
      mstp_util_set_cist_table_value(OPER_HELLO_TIME, mstp_Bridge.HelloTime);
      mstp_util_set_cist_table_value(OPER_FORWARD_DELAY, mstp_Bridge.FwdDelay);
      mstp_util_set_cist_table_value(OPER_MAX_AGE, mstp_Bridge.MaxAge);
      mstp_util_set_cist_table_value(OPER_TX_HOLD_COUNT, mstp_Bridge.TxHoldCount);
   }
   else
   {/* case 2) from the above */
      commPortPtr = MSTP_COMM_PORT_PTR(MSTP_GET_PORT_NUM(cistRootPortId));
      STP_ASSERT(commPortPtr);
      cistPortPtr = MSTP_CIST_PORT_PTR(MSTP_GET_PORT_NUM(cistRootPortId));
      STP_ASSERT(cistPortPtr);

      MSTP_CIST_ROOT_TIMES.messageAge = cistPortPtr->portTimes.messageAge;
      MSTP_CIST_ROOT_TIMES.maxAge     = cistPortPtr->portTimes.maxAge;
      MSTP_CIST_ROOT_TIMES.fwdDelay   = cistPortPtr->portTimes.fwdDelay;
      /*---------------------------------------------------------------------
       * since CIST's 'rootTimes' does not include 'Hello Time' variable,
       * copy it to a global variable 'cistRootHelloTime'. PIM state
       * machine will use it to update 'portTimes', so that value will be
       * used in BPDU's transmitted from this Bridge's designated Ports down
       * the tree.
       *---------------------------------------------------------------------*/
      MSTP_CIST_ROOT_HELLO_TIME       = cistPortPtr->portTimes.helloTime;
      MSTP_CIST_ROOT_TIMES.hops       = cistPortPtr->portTimes.hops;
      /* Update 'Message Age' and 'remainingHops' components with respect to
       * the current value of 'rcvdInternal' variable */
      if(!MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                    MSTP_PORT_RCVD_INTERNAL))
      {
         MSTP_CIST_ROOT_TIMES.messageAge = cistPortPtr->portTimes.messageAge+1;
      }
      else
      {
         MSTP_CIST_ROOT_TIMES.hops = (cistPortPtr->portTimes.hops > 0) ?
                                     (cistPortPtr->portTimes.hops - 1) : 0;
      }
   }
   rootTimeChange = mstpCistCompareRootTimes(&cistRootTimes, rootHelloTime);
   if(rootTimeChange == TRUE)
   {
      /* If there is a change in the root times, inform this to standby */
      mstp_updtMstiRootInfoChg(MSTP_CISTID);
   }
   /*-------------------------------------------------------------------------
    * After calculation of the Bridge's Root Priority Vector and Root Times
    * we have to do the following:
    * 1). update the Designated Priority Vector and the Designated Times
    *     for each Port.
    * 2). assign the CIST Port Role for each Port
    * 3). set 'updtInfo' for those Ports that should have Port Priority Vector
    *     and Port Times updated from the Designated Priority Vector and
    *     Designated Times (PIM SM will do the update by looking at the
    *     'updtInfo' status).
    *------------------------------------------------------------------------*/
   for(lport = 1; lport <= MAX_LPORTS; lport++)
   {
      selectedRole = MSTP_PORT_ROLE_UNKNOWN;
      commPortPtr = MSTP_COMM_PORT_PTR(lport);
      cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT((commPortPtr != NULL) ?
             (cistPortPtr != NULL) : (cistPortPtr == NULL));

      if(commPortPtr && cistPortPtr)
      {
         /*-------------------------------------------------------------------
          * Update the Designated Priority Vector for the Port. (Steps
          * 1-4 below).
          * NOTE: The Designated Priority Vector for a port Q on Bridge B
          *       is the Root Priority Vector with B's Bridge Identifier B
          *       substituted for the 'DesignatedBridgeID' and Q's Port
          *       Identifier Q substituted for the 'DesignatedPortID' and
          *       'RcvPortID' components. If Q is attached to a LAN which has
          *       one or more STP Bridges attached (as determined by the Port
          *       Protocol Migration state machine), B's Bridge Identifier B
          *       is also substituted for the 'RRootID' component.
          *------------------------------------------------------------------*/

         /*-------------------------------------------------------------------
          * 1). Copy Bridge's Root Priority Vector to the
          *     Port's Designated Priority Vector
          *------------------------------------------------------------------*/
         char designatedRoot[MSTP_ROOT_ID] = {0};
         char port_name[PORTNAME_LEN] = {0};
         cistPortPtr->designatedPriority = MSTP_CIST_ROOT_PRIORITY;
         snprintf(designatedRoot,MSTP_ROOT_ID,"%d.%d.%02x:%02x:%02x:%02x:%02x:%02x",cistPortPtr->designatedPriority.rootID.priority,
                 MSTP_CISTID,cistPortPtr->designatedPriority.rootID.mac_address[0],
                 cistPortPtr->designatedPriority.rootID.mac_address[1],cistPortPtr->designatedPriority.rootID.mac_address[2],
                 cistPortPtr->designatedPriority.rootID.mac_address[3],cistPortPtr->designatedPriority.rootID.mac_address[4],
                 cistPortPtr->designatedPriority.rootID.mac_address[5]);
         intf_get_port_name(lport,port_name);
         mstp_util_set_cist_port_table_string(port_name,DESIGNATED_ROOT,designatedRoot);

         /*-------------------------------------------------------------------
          * 2). Substitute 'DesignatedBridgeID' with this Bridge Identifier
          *------------------------------------------------------------------*/
         char designatedBridge[MSTP_ROOT_ID] = {0};
         cistPortPtr->designatedPriority.dsnBridgeID =
             MSTP_CIST_BRIDGE_IDENTIFIER;
         snprintf(designatedBridge,MSTP_ROOT_ID,"%d.%d.%02x:%02x:%02x:%02x:%02x:%02x",cistPortPtr->designatedPriority.dsnBridgeID.priority,
                 MSTP_CISTID, cistPortPtr->designatedPriority.dsnBridgeID.mac_address[0],
                 cistPortPtr->designatedPriority.dsnBridgeID.mac_address[1],cistPortPtr->designatedPriority.dsnBridgeID.mac_address[2],
                 cistPortPtr->designatedPriority.dsnBridgeID.mac_address[3],cistPortPtr->designatedPriority.dsnBridgeID.mac_address[4],
                 cistPortPtr->designatedPriority.dsnBridgeID.mac_address[5]);
         mstp_util_set_cist_port_table_string(port_name,DESIGNATED_BRIDGE,designatedBridge);

         /*-------------------------------------------------------------------
          * 3). Substitute 'DesignatedPortID' with this Port Identifier
          *------------------------------------------------------------------*/
         char dsnPort[10] = {0};
         cistPortPtr->designatedPriority.dsnPortID = cistPortPtr->portId;
         if (cistPortPtr->portId != 0)
         {
             intf_get_port_name(MSTP_GET_PORT_NUM(cistPortPtr->portId),dsnPort);
             mstp_util_set_cist_port_table_string(port_name,DESIGNATED_PORT,dsnPort);
         }
         else
         {
             mstp_util_set_cist_port_table_string(port_name,DESIGNATED_PORT,"0");
         }

         if(!MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,MSTP_PORT_SEND_RSTP))
         {/* 4). Port is attached to a LAN which has one or more STP Bridges
           * attached, substitute 'RRootID' with this Bridge Identifier */
             char regionalRoot[MSTP_ROOT_ID] = {0};
             cistPortPtr->designatedPriority.rgnRootID =
                 MSTP_CIST_BRIDGE_IDENTIFIER;
             snprintf(regionalRoot,MSTP_ROOT_ID,"%d.%d.%02x:%02x:%02x:%02x:%02x:%02x", cistPortPtr->designatedPriority.rgnRootID.priority,
                     MSTP_CISTID, cistPortPtr->designatedPriority.rgnRootID.mac_address[0],
                     cistPortPtr->designatedPriority.rgnRootID.mac_address[1],cistPortPtr->designatedPriority.rgnRootID.mac_address[2],
                     cistPortPtr->designatedPriority.rgnRootID.mac_address[3],cistPortPtr->designatedPriority.rgnRootID.mac_address[4],
                     cistPortPtr->designatedPriority.rgnRootID.mac_address[5]);
             mstp_util_set_cist_port_table_string(port_name,CIST_REGIONAL_ROOT_ID,regionalRoot);
         }

         /*------------------------------------------------------------------
          * Update the Designated Times for the Port.
          * NOTE: The value for the 'designatedTimes' of the Port is
          *       copied from the CIST 'rootTimes' paramater.
          *-----------------------------------------------------------------*/
         cistPortPtr->designatedTimes = MSTP_CIST_ROOT_TIMES;

         /* Clear the root inconsistent  flag */
         cistPortPtr->rootInconsistent = FALSE;

         /*------------------------------------------------------------------
          * Assign the CIST Port Role for the Port.
          * (802.1Q-REV/D5.0 13.26.23 f)-m))
          *------------------------------------------------------------------*/
         if(cistPortPtr->infoIs == MSTP_INFO_IS_DISABLED)
         {/* the port is Disabled */

            /*----------------------------------------------------------------
             * 13.26.23 f)
             *---------------------------------------------------------------*/
            selectedRole = MSTP_PORT_ROLE_DISABLED;
         }
         else if(cistPortPtr->infoIs == MSTP_INFO_IS_AGED)
         {/* the Port Priority Vector information is aged */
            if (cistPortPtr->loopInconsistent)
            {
               selectedRole = MSTP_PORT_ROLE_ALTERNATE;
               MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap,
                     MSTP_CIST_PORT_UPDT_INFO);
            }
            else
            {
               /*---------------------------------------------------------------
                * 13.26.23 h)
                *-------------------------------------------------------------*/
               selectedRole = MSTP_PORT_ROLE_DESIGNATED;
               MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap,
                     MSTP_CIST_PORT_UPDT_INFO);
            }
         }
         else if((cistPortPtr->infoIs == MSTP_INFO_IS_MINE)
                 &&
                 (cistPortPtr->loopInconsistent == FALSE)
                 )
         {/* the Port Priority Vector is derived from another port on the
           * Bridge or from the Bridge itself as the Root Bridge */
            bool timesEqual;

            /*----------------------------------------------------------------
             * 13.26.23 i)
             *---------------------------------------------------------------*/
            selectedRole = MSTP_PORT_ROLE_DESIGNATED;
            timesEqual = ((cistPortPtr->designatedTimes.fwdDelay ==
                           cistPortPtr->portTimes.fwdDelay) &&
                          (cistPortPtr->designatedTimes.maxAge ==
                           cistPortPtr->portTimes.maxAge) &&
                          (cistPortPtr->designatedTimes.messageAge ==
                           cistPortPtr->portTimes.messageAge) &&
                          (cistPortPtr->designatedTimes.hops ==
                           cistPortPtr->portTimes.hops));
            if(timesEqual && !MSTP_IS_THIS_BRIDGE_CIST_ROOT)
            {
               timesEqual = (cistPortPtr->portTimes.helloTime ==
                                                    MSTP_CIST_ROOT_HELLO_TIME);
            }

            if((mstp_cistPriorityVectorsCompare(&cistPortPtr->portPriority,
                                 &cistPortPtr->designatedPriority) != 0) ||
               (timesEqual == FALSE))
            {/* either the Port Priority Vector differs from the Designated
              * Priority Vector or the Port's associated timer parameters
              * differ from those for the Root Port. In any case set 'updtInfo'
              * flag for the Port */
               MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap,
                                      MSTP_CIST_PORT_UPDT_INFO);
            }
         }
         else if(cistPortPtr->infoIs == MSTP_INFO_IS_RECEIVED)
         {/* the Port Priority Vector is received in a Configuration Message
           * and is not aged */
            if(commPortPtr->rcvdSelfSentPkt)
            {/* The received BPDU is the result of an existing loopback
              * condition */
               selectedRole = MSTP_PORT_ROLE_BACKUP;
               MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap,
                                      MSTP_CIST_PORT_UPDT_INFO);
            }
            else
            if(cistPortPtr->portId == MSTP_CIST_ROOT_PORT_ID)
            {/* the Root Priority Vector is now derived from this Port */

               /*-------------------------------------------------------------
                * 13.26.23 j)
                *------------------------------------------------------------*/
               selectedRole = MSTP_PORT_ROLE_ROOT;
               MSTP_MSTI_PORT_CLR_BIT(cistPortPtr->bitMap,
                                      MSTP_CIST_PORT_UPDT_INFO);
            }
            else
            {/* the Root Priority Vector is not now derived from this Port */
               MSTP_CIST_DESIGNATED_PRI_VECTOR_t *dsnPriVecPtr =
                                          &cistPortPtr->designatedPriority;
               MSTP_CIST_PORT_PRI_VECTOR_t       *portPriVecPtr =
                                          &cistPortPtr->portPriority;

               if((mstp_cistPriorityVectorsCompare(dsnPriVecPtr,
                                                   portPriVecPtr) < 0))
               {/* the Designated Priority Vector is better than the Port
                 * Priority Vector */

               /*-------------------------------------------------------------
                * 13.26.23 m)
                *------------------------------------------------------------*/
                  selectedRole = MSTP_PORT_ROLE_DESIGNATED;
                  MSTP_CIST_PORT_SET_BIT(cistPortPtr->bitMap,
                                         MSTP_CIST_PORT_UPDT_INFO);
               }
               else
               {/* the Designated Priority Vector is not better than the Port
                 * Priority Vector */

                  MSTP_CIST_PORT_INFO_t *cistRootPortPtr;
                  MSTP_CIST_MSG_PRI_VECTOR_t  *msgPriVecPtr;

                  cistRootPortPtr =
                     MSTP_CIST_PORT_PTR(MSTP_GET_PORT_NUM(
                                                       MSTP_CIST_ROOT_PORT_ID));
                  if(cistRootPortPtr)
                  {
                     msgPriVecPtr = &cistPortPtr->msgPriority;
                  }

                  if(MSTP_BRIDGE_ID_EQUAL(portPriVecPtr->dsnBridgeID,
                                          MSTP_CIST_BRIDGE_IDENTIFIER)
                     && (portPriVecPtr->dsnPortID != cistPortPtr->portId))
                  {/* the Designated Bridge and Designated Port components of
                    * the Port Priority Vector reflect another Port on this
                    * Bridge */

                     /*-------------------------------------------------------
                      * 13.26.23 l)
                      *------------------------------------------------------*/
                     selectedRole = MSTP_PORT_ROLE_BACKUP;
                     MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap,
                                            MSTP_CIST_PORT_UPDT_INFO);
                  }
                  else
                  {/* the Designated Bridge and Designated Port components of
                    * the Port Priority Vector do not reflect another Port on
                    * this Bridge */
                     /*-------------------------------------------------------
                      * 13.26.23 k)
                      *------------------------------------------------------*/
                     selectedRole = MSTP_PORT_ROLE_ALTERNATE;
                     MSTP_CIST_PORT_CLR_BIT(cistPortPtr->bitMap,
                                            MSTP_CIST_PORT_UPDT_INFO);
                  }

                  if((MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                                MSTP_PORT_RESTRICTED_ROLE)) &&
                     ((!cistRootPortPtr) ||
                      (mstp_cistPriorityVectorsCompare(&cistRootPortPtr->msgPriority,
                                                             msgPriVecPtr) > 0)))
                  {
                     cistPortPtr->rootInconsistent = TRUE;
                     //mstp_sendRootGaurdInconsistencyTrap(MSTP_CISTID, lport);
                  }
               }
            }
         }
         /*-------------------------------------------------------------------
          * We need to inform about the Role change to interested sub-systems
          * This can be used for Distributed STP in future.
          *------------------------------------------------------------------*/
         if (selectedRole != MSTP_PORT_ROLE_UNKNOWN)
         {
            if(cistPortPtr->selectedRole != selectedRole)
            {
                char port_role[20] = {0};
                char port[20] = {0};
                mstp_updatePortHistory(MSTP_CISTID, lport, selectedRole);
                intf_get_port_name(lport,port);
                mstp_convertPortRoleEnumToString(selectedRole,port_role);
                mstp_util_set_cist_port_table_string(port,PORT_ROLE,port_role);
                /* Does this generate Topology change if so record the
                   current and prev port roles */
                if (mstpCheckForTcGeneration(MSTP_CISTID, lport,
                            selectedRole))
                {
                    mstpUpdateTcHistory(MSTP_CISTID, lport, TRUE);
                    /*send a trap*/
                    //mstp_sendTopologyChangeTrap(MSTP_CISTID, lport);
                }
            }
            cistPortPtr->selectedRole = selectedRole;
         }
      }/* end 'if(commPortPtr && cistPortPtr)' statement */
   }/* end 'for(lport = 1; lport <= MAX_LPORTS; lport++)' loop */

}

/**PROC+**********************************************************************
 * Name:      mstp_updtRolesMsti
 *
 * Purpose:   Helper function called by the 'updtRolesTree' function to
 *            calculate the MSTI Priority Vectors (13.9, 13.11) and Timer
 *            Values. It also assignes the MSTI Port Role for each
 *            Port and updates Port's Port Priority Vector and Spanning
 *            Tree Timer Information.
 *            (802.1Q-REV/D5.0 13.26.23)
 *
 * Params:    mstid -> MST Instance Identifier
 *
 * Returns:   none
 *
 * Globals:   mstp_CB, mstp_Bridge
 *
 **PROC-**********************************************************************/
static void
mstp_updtRolesMsti(MSTID_t mstid)
{
   MSTP_COMM_PORT_INFO_t         *commPortPtr;
   MSTP_MSTI_PORT_INFO_t         *mstiPortPtr;
   MSTP_MSTI_BRIDGE_PRI_VECTOR_t  mstiRootPriVec;
   MSTP_PORT_ID_t                 mstiRootPortId;
   LPORT_t                        lport;
   MSTP_PORT_ROLE_t               selectedRole = MSTP_PORT_ROLE_UNKNOWN;
   MSTP_MSTI_ROOT_TIMES_t         mstiRootTimes;
   bool                           rootTimeChange = FALSE;
   char                           oldRootPortName[PORTNAME_LEN];
   char                           newRootPortName[PORTNAME_LEN];
   char                           msti_str[10];
   char                           designatedRoot[MSTP_ROOT_ID] = {0};

   /*------------------------------------------------------------------------
    * Assume that the Bridge's own Bridge Priority Vector is the best, i.e.
    * it is the Bridge's Root Priority Vector. Further if we find any port
    * whose Root Path Priority Vector is better we will update the Root
    * Priority Vector with that better info.
    * NOTE: Bridge's Bridge Priority Vector = {B : 0 : B : 0}, i.e.
    *       the MSTI Regional Root Identifier and Designated Bridge Identifier
    *       components are equal to the value of the MSTI Bridge Identifier.
    *       The remaining components (MSTI Internal Root Path Cost,
    *       MSTI Designated Port Identifier) are set to zero.
    *------------------------------------------------------------------------*/
   mstiRootPriVec = MSTP_MSTI_BRIDGE_PRIORITY(mstid);

   /*------------------------------------------------------------------------
    * Root Port is not chosen yet (assume this Bridge is the MSTI Regional Root)
    *------------------------------------------------------------------------*/
   mstiRootPortId = 0;

   /*------------------------------------------------------------------------
    * Find a Priority Vector that is the best of the set of Priority Vectors
    * comprising the Bridge's own Bridge Priority Vector plus all the
    * calculated Root Path Priority Vectors whose 'DesignatedBridgeID' Bridge
    * Address component is not equal to that component of the Bridge's own
    * Bridge Priority Vector and Port's 'restrictedRole' parameter is FALSE
    *------------------------------------------------------------------------*/
   for(lport = 1; lport <= MAX_LPORTS; lport++)
   {
      commPortPtr = MSTP_COMM_PORT_PTR(lport);
      mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
      if (!(commPortPtr && mstiPortPtr))
        continue;

      STP_ASSERT((commPortPtr != NULL) ?
             (mstiPortPtr != NULL) : (mstiPortPtr == NULL));

      if(commPortPtr && mstiPortPtr)
      {
         if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                      MSTP_PORT_PORT_ENABLED) &&
            (mstiPortPtr->infoIs == MSTP_INFO_IS_RECEIVED) &&
            (mstiPortPtr->rcvdInfoWhile != 0))
         {/* port is not 'Disabled', and has a Port Priority Vector that has
           * been recorded from a received message and not aged out
           * ('infoIs' == 'Received') */
            MSTP_MSTI_ROOT_PATH_PRI_VECTOR_t rootPathPriVec;

            /*---------------------------------------------------------------
             * Calculate Root Path Priority Vector for the Port
             * NOTE: A Root Path Priority vector for a given MSTI can be
             *       calculated for a Port that has received a Port Priority
             *       Vector from a Bridge in the same Region by adding the
             *       Internal Port Path Cost of the receiving Port to the
             *       Internal Root Path Cost component of the Port Priority
             *       Vector.
             *---------------------------------------------------------------*/
            rootPathPriVec = mstiPortPtr->portPriority;

            if(MAC_ADDRS_EQUAL(rootPathPriVec.dsnBridgeID.mac_address,
                      MSTP_MSTI_BRIDGE_PRIORITY(mstid).dsnBridgeID.mac_address)
               ||
               MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                         MSTP_PORT_RESTRICTED_ROLE))
            {/* we are interested only in ports whose 'DesignatedBridgeID'
              * Bridge Address component is not equal to that component of the
              * Bridge's own Bridge Priority Vector and Port's 'restrictedRole'
              * parameter is FALSE */
               continue;
            }

           /*----------------------------------------------------------------
            * Add own Internal Port Path Cost of the receiving Port to the
            * current Root Path Cost value
            *----------------------------------------------------------------*/
           rootPathPriVec.intRootPathCost += mstiPortPtr->InternalPortPathCost;
           mstp_util_set_msti_table_value(ROOT_PATH_COST,rootPathPriVec.intRootPathCost,mstid);

            /*----------------------------------------------------------------
             * Compare newly calculated Port's Root Path Priority Vector
             * against the current Bridge's Root Priority Vector.
             *    - If new info is better then update Bridge's Root Priority
             *      Vector with that new info
             *    - If Priority Vectors are the same, but received Port ID is
             *      better than current Root Port ID then update the
             *      Bridge's Root Priority Vector with that new info
             *---------------------------------------------------------------*/
           if((mstp_mstiPriorityVectorsCompare(&rootPathPriVec,
                                               &mstiRootPriVec) < 0) ||
              (!mstp_mstiPriorityVectorsCompare(&rootPathPriVec,
                                                &mstiRootPriVec) &&
               (mstiPortPtr->portId < mstiRootPortId)))

           {/* the Port's Root Path Priority Vector is better than the
             * current Bridge's Root Priority Vector, so update it
             * from the better vector */
              mstiRootPriVec = rootPathPriVec;
              mstiRootPortId = mstiPortPtr->portId;
           }

         }
      }/* end of '(commPortPtr && mstiPortPtr)' statement */
   }/* end of 'for(lport = 1; lport <= MAX_LPORTS; lport++)' */

   /*-------------------------------------------------------------------------
    * Check if the MSTI Regional Root has been changed, if so then update
    * the MSTI Reginal Root change history.
    *------------------------------------------------------------------------*/
   if(!MSTP_BRIDGE_ID_EQUAL(MSTP_MSTI_ROOT_PRIORITY(mstid).rgnRootID,
                            mstiRootPriVec.rgnRootID))
   {
      mstp_updtMstiRootInfoChg(mstid);
      mstp_updateMstiRootHistory(mstid, mstiRootPriVec.rgnRootID);
      mstp_logNewRootId(MSTP_MSTI_ROOT_PRIORITY(mstid).rgnRootID,
                        mstiRootPriVec.rgnRootID, FALSE, mstid);
   }
   snprintf(designatedRoot,MSTP_ROOT_ID,"%d.%d.%02x:%02x:%02x:%02x:%02x:%02x", mstiRootPriVec.rgnRootID.priority,
           mstid, mstiRootPriVec.rgnRootID.mac_address[0],
           mstiRootPriVec.rgnRootID.mac_address[1],mstiRootPriVec.rgnRootID.mac_address[2],
           mstiRootPriVec.rgnRootID.mac_address[3],mstiRootPriVec.rgnRootID.mac_address[4],
           mstiRootPriVec.rgnRootID.mac_address[5]);
   mstp_util_set_msti_table_string(DESIGNATED_ROOT,designatedRoot,mstid);

   if (mstiRootPortId != MSTP_MSTI_ROOT_PORT_ID(mstid))
   {
      mstp_updtMstiRootInfoChg(mstid);

      if(mstp_debugLog     &&
         MSTP_GET_PORT_NUM(MSTP_MSTI_ROOT_PORT_ID(mstid) != 0) &&
         mstiRootPortId != 0)
      {
         /* Log root port change */
         intf_get_port_name(MSTP_GET_PORT_NUM(mstiRootPortId), newRootPortName);
         intf_get_port_name(MSTP_GET_PORT_NUM(MSTP_MSTI_ROOT_PORT_ID(mstid)),
               oldRootPortName);
         snprintf(msti_str, sizeof(msti_str), "MSTI %d", mstid);
         VLOG_DBG("%s Root Port changed from %s to %s",
               msti_str,
               oldRootPortName,
               newRootPortName);
         log_event("MSTP_NEW_ROOT_PORT",
               EV_KV("proto", "%s", msti_str),
               EV_KV("old_port", "%s", oldRootPortName),
               EV_KV("new_port", "%s", newRootPortName));
      }
   }

   /*-------------------------------------------------------------------------
    * Record calculated Root Priority Vector to the MSTI's per-Bridge
    * variables: 'mstiRootPortId' and 'mstiRootPriority'.
    *------------------------------------------------------------------------*/
   MSTP_MSTI_ROOT_PORT_ID(mstid)  = mstiRootPortId;
   if (MSTP_MSTI_ROOT_PORT_ID(mstid))
   {
       char root_port[10] = {0};
       intf_get_port_name(MSTP_GET_PORT_NUM(MSTP_MSTI_ROOT_PORT_ID(mstid)), root_port);
       mstp_util_set_msti_table_string(ROOT_PORT, root_port, mstid);
   }
   MSTP_MSTI_ROOT_PRIORITY(mstid) = mstiRootPriVec;
   mstp_util_set_msti_table_value(ROOT_PRIORITY,(MSTP_MSTI_ROOT_PRIORITY(mstid).rgnRootID.priority-mstid),mstid);

   /*-------------------------------------------------------------------------
    * Calculate the Bridge's Root Times ('rootTimes') for the MSTI.
    * Set 'rootTimes' equal to:
    *    1) 'BridgeTimes', if the chosen Root Priority Vector is the Bridge
    *       Priority Vector, otherwise
    *    2) 'portTimes' for the port associated with the selected
    *       Root Priority Vector, with 'remainingHops' decremented by one
    *       if the information was received from a Bridge internal to the MST
    *       Region ('rcvdInternal' TRUE).
    *------------------------------------------------------------------------*/
   mstiRootTimes = MSTP_MSTI_ROOT_TIMES(mstid);

   if(mstiRootPortId == 0)
   {/* case 1) from the above, i.e. this Bridge is the Root for the tree as
     * this Bridge's own Priority Vector is the best over all Port's
     * Root Path Priority Vectors */
      MSTP_MSTI_ROOT_TIMES(mstid) = MSTP_MSTI_BRIDGE_TIMES(mstid);
   }
   else
   {/* case 2) from the above */
      commPortPtr = MSTP_COMM_PORT_PTR(MSTP_GET_PORT_NUM(mstiRootPortId));
      STP_ASSERT(commPortPtr);

      if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,MSTP_PORT_RCVD_INTERNAL))
      {
         mstiPortPtr =
            MSTP_MSTI_PORT_PTR(mstid,MSTP_GET_PORT_NUM(mstiRootPortId));

         STP_ASSERT(mstiPortPtr);
         MSTP_MSTI_ROOT_TIMES(mstid).hops =
                                         (mstiPortPtr->portTimes.hops > 0) ?
                                         (mstiPortPtr->portTimes.hops - 1) : 0;
      }
   }

   rootTimeChange = (mstiRootTimes.hops != MSTP_MSTI_ROOT_TIMES(mstid).hops) ?
                    TRUE : FALSE;
   /* Root time changed. we need to update this to standby */
   if(rootTimeChange)
   {
      mstp_updtMstiRootInfoChg(mstid);
      mstp_util_set_msti_table_value(REMAINING_HOPS, MSTP_MSTI_ROOT_TIMES(mstid).hops, mstid);
   }

   /*-------------------------------------------------------------------------
    * After calculation of the Bridge's Root Priority Vector and Root Times
    * we have to do the following:
    * 1). update the Designated Priority Vector and the Designated Times
    *     for each Port.
    * 2). assign the MSTI Port Role for each Port.
    * 3). set 'updtInfo' for those Ports that should have Port Priority Vector
    *     and Port Times updated from the Designated Priority Vector and
    *     Designated Times (PIM SM will do the update by looking at the
    *     'updtInfo' status).
    *------------------------------------------------------------------------*/
   for(lport = 1; lport <= MAX_LPORTS; lport++)
   {
      selectedRole = MSTP_PORT_ROLE_UNKNOWN;
      commPortPtr = MSTP_COMM_PORT_PTR(lport);
      mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
      if (!(commPortPtr && mstiPortPtr))
        continue;

      STP_ASSERT((commPortPtr != NULL) ?
             (mstiPortPtr != NULL) : (mstiPortPtr == NULL));

      if(commPortPtr && mstiPortPtr)
      {
         MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

         STP_ASSERT(cistPortPtr);

         /*-------------------------------------------------------------------
          * Update the Designated Priority Vector for the Port. (Steps
          * 1-3 below).
          * NOTE: The Designated Priority Vector for a port Q on Bridge B
          *       is the Root Priority Vector with B's Bridge Identifier B
          *       substituted for the 'DesignatedBridgeID' and Q's Port
          *       Identifier Q substituted for the 'DesignatedPortID' and
          *       'RcvPortID' components.
          *------------------------------------------------------------------*/

         /*-------------------------------------------------------------------
          * 1). Copy Bridge's Root Priority Vector to the
          *     Port's Designated Priority Vector
          *------------------------------------------------------------------*/
         mstiPortPtr->designatedPriority = MSTP_MSTI_ROOT_PRIORITY(mstid);
         char designatedRoot[MSTP_ROOT_ID] = {0};
         snprintf(designatedRoot,MSTP_ROOT_ID,"%d.%d.%02x:%02x:%02x:%02x:%02x:%02x",mstiPortPtr->designatedPriority.rgnRootID.priority,
                 mstid ,mstiPortPtr->designatedPriority.rgnRootID.mac_address[0],
                 mstiPortPtr->designatedPriority.rgnRootID.mac_address[1],mstiPortPtr->designatedPriority.rgnRootID.mac_address[2],
                 mstiPortPtr->designatedPriority.rgnRootID.mac_address[3],mstiPortPtr->designatedPriority.rgnRootID.mac_address[4],
                 mstiPortPtr->designatedPriority.rgnRootID.mac_address[5]);
         mstp_util_set_msti_port_table_string(DESIGNATED_ROOT,designatedRoot,mstid,lport);
         mstp_util_set_msti_port_table_value(DESIGNATED_ROOT_PRIORITY,(mstiPortPtr->designatedPriority.rgnRootID.priority-mstid),mstid,lport);
         mstp_util_set_msti_port_table_value(DESIGNATED_COST,mstiPortPtr->designatedPriority.intRootPathCost,mstid,lport);

         /*-------------------------------------------------------------------
          * 2). Substitute 'DesignatedBridgeID' with this Bridge Identifier
          *------------------------------------------------------------------*/
         mstiPortPtr->designatedPriority.dsnBridgeID =
                                            MSTP_MSTI_BRIDGE_IDENTIFIER(mstid);
         char designatedBridge[MSTP_ROOT_ID] = {0};
         snprintf(designatedBridge,MSTP_ROOT_ID,"%d.%d.%02x:%02x:%02x:%02x:%02x:%02x", mstiPortPtr->designatedPriority.dsnBridgeID.priority,
                 mstid , mstiPortPtr->designatedPriority.dsnBridgeID.mac_address[0],
                 mstiPortPtr->designatedPriority.dsnBridgeID.mac_address[1],mstiPortPtr->designatedPriority.dsnBridgeID.mac_address[2],
                 mstiPortPtr->designatedPriority.dsnBridgeID.mac_address[3],mstiPortPtr->designatedPriority.dsnBridgeID.mac_address[4],
                 mstiPortPtr->designatedPriority.dsnBridgeID.mac_address[5]);
         mstp_util_set_msti_port_table_string(DESIGNATED_BRIDGE,designatedRoot,mstid,lport);
         mstp_util_set_msti_port_table_value(DESIGNATED_BRIDGE_PRIORITY,(mstiPortPtr->designatedPriority.dsnBridgeID.priority-mstid),mstid,lport);

         /*-------------------------------------------------------------------
          * 3). Substitute 'DesignatedPortID' with this Port Identifier
          *------------------------------------------------------------------*/
         char dsnPort[10] = {0};
         mstiPortPtr->designatedPriority.dsnPortID = mstiPortPtr->portId;
         if (mstiPortPtr->portId != 0)
         {
             intf_get_port_name(MSTP_GET_PORT_NUM(mstiPortPtr->designatedPriority.dsnPortID),dsnPort);
             mstp_util_set_msti_port_table_string(DESIGNATED_PORT,dsnPort,mstid,lport);
         }
         else
         {
             mstp_util_set_msti_port_table_string(DESIGNATED_PORT,"0",mstid,lport);
         }

         /*------------------------------------------------------------------
          * Update the Designated Times for the Port.
          * NOTE: The value for the 'designatedTimes' of the Port is
          *       copied from this MSTI's 'rootTimes' parameter
          *-----------------------------------------------------------------*/
         mstiPortPtr->designatedTimes = MSTP_MSTI_ROOT_TIMES(mstid);


         mstiPortPtr->rootInconsistent = FALSE;
         /*------------------------------------------------------------------
          * Assign the MSTI Port Role for the Port.
          * (802.1Q-REV/D5.0 13.26.23 f)-m))
          *------------------------------------------------------------------*/
         if(mstiPortPtr->infoIs == MSTP_INFO_IS_DISABLED)
         {/* the Port is Disabled */

            /*----------------------------------------------------------------
             * 13.26.23 f)
             *---------------------------------------------------------------*/
            selectedRole = MSTP_PORT_ROLE_DISABLED;
         }
         else if((cistPortPtr->infoIs == MSTP_INFO_IS_RECEIVED) &&
                 !MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                            MSTP_PORT_RCVD_INTERNAL))
         {/* the Port is not 'Disabled' and the CIST Port Priority Information
           * is received from a Bridge external to the MST Region */
            bool checkForUpdate = FALSE;

            if(cistPortPtr->selectedRole == MSTP_PORT_ROLE_ROOT)
            {/* the selected CIST Port Role (calculated prior to invoking
              * this procedure) is 'RootPort' */

               /*-------------------------------------------------------------
                * 13.26.23 g) case 1
                *------------------------------------------------------------*/
               selectedRole = MSTP_PORT_ROLE_MASTER;
               checkForUpdate = TRUE;
            }
            else if(cistPortPtr->selectedRole == MSTP_PORT_ROLE_ALTERNATE)
            {/* the selected CIST Port Role (calculated prior to invoking
              * this procedure) is 'AlternatePort' */

               /*-------------------------------------------------------------
                * 13.26.23 g) case 2
                *------------------------------------------------------------*/
               selectedRole = MSTP_PORT_ROLE_ALTERNATE;
               checkForUpdate = TRUE;
            }
            else if(cistPortPtr->selectedRole == MSTP_PORT_ROLE_BACKUP)
            {/* if the CIST Port Role is Backup Port then each MSTI's Port Role
              * should be the same (as at a Boundary Port frames allocated to
              * the CIST and all MSTIs are forwarded or not forwarded alike) */
               selectedRole = MSTP_PORT_ROLE_BACKUP;
               checkForUpdate = TRUE;
            }

            if(checkForUpdate)
            {
               bool timesEqual = (mstiPortPtr->designatedTimes.hops ==
                                   mstiPortPtr->portTimes.hops);

               if((mstp_mstiPriorityVectorsCompare(&mstiPortPtr->portPriority,
                                 &mstiPortPtr->designatedPriority) != 0) ||
               (timesEqual == FALSE))
               {/* either the Port Priority Vector differs from the
                 * Designated Priority Vector or the Port's associated timer
                 * parameter differs from the one for the Root Port. In any
                 * case set 'updtInfo' flag for the Port */
                  MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap,
                                         MSTP_MSTI_PORT_UPDT_INFO);
               }
            }
         }
         else
         {/* the Port is not 'Disabled' and the CIST Port Priority Information
           * is not received from a Bridge external to the Region */
            if(mstiPortPtr->infoIs == MSTP_INFO_IS_AGED)
            {/* the Port Priority Vector information is aged */
               if (mstiPortPtr->loopInconsistent)
               {
                  selectedRole = MSTP_PORT_ROLE_ALTERNATE;
                  MSTP_CIST_PORT_SET_BIT(mstiPortPtr->bitMap,
                        MSTP_MSTI_PORT_UPDT_INFO);
               }
               else
               {
                  /*----------------------------------------------------------
                   * 13.26.23 h)
                   *----------------------------------------------------------*/
                  selectedRole = MSTP_PORT_ROLE_DESIGNATED;
                  MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap,
                        MSTP_MSTI_PORT_UPDT_INFO);
               }
            }
            else if((mstiPortPtr->infoIs == MSTP_INFO_IS_MINE)
                    &&
                   (mstiPortPtr->loopInconsistent == FALSE)
                    )
            {/* the Port Priority Vector is derived from another port on the
              * Bridge or from the Bridge itself as the Root Bridge */
               bool timesEqual = (mstiPortPtr->designatedTimes.hops ==
                                   mstiPortPtr->portTimes.hops);

               /*-------------------------------------------------------------
                * 13.26.23 i)
                *------------------------------------------------------------*/
               selectedRole = MSTP_PORT_ROLE_DESIGNATED;

               if((mstp_mstiPriorityVectorsCompare
                                (&mstiPortPtr->portPriority,
                                 &mstiPortPtr->designatedPriority) != 0) ||
                  (timesEqual == FALSE))
               {/* either the Port Priority Vector differs from the Designated
                 * Priority Vector or the Port's associated timer parameters
                 * differ from those for the Root Port. In any case set
                 * 'updtInfo' flag for the Port */
                  MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap,
                                         MSTP_MSTI_PORT_UPDT_INFO);
               }
            }
            else if(mstiPortPtr->infoIs == MSTP_INFO_IS_RECEIVED)
            {/* the Port Priority Vector is received in a Configuration Message
              * and is not aged */
               if(commPortPtr->rcvdSelfSentPkt)
               {/* The received BPDU is the result of an existing loopback
                 * condition */
                  selectedRole = MSTP_PORT_ROLE_BACKUP;
                  MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap,
                                         MSTP_MSTI_PORT_UPDT_INFO);
               }
               else
               if(mstiPortPtr->portId == MSTP_MSTI_ROOT_PORT_ID(mstid))
               {/* the Root Priority Vector is now derived from this Port */

                  /*----------------------------------------------------------
                   * 13.26.23 j)
                   *---------------------------------------------------------*/
                  selectedRole = MSTP_PORT_ROLE_ROOT;
                  MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap,
                                         MSTP_MSTI_PORT_UPDT_INFO);
               }
               else
               {/* the Root Priority Vector is not now derived from this Port */
                  MSTP_MSTI_DESIGNATED_PRI_VECTOR_t *dsnPriVecPtr =
                                          &mstiPortPtr->designatedPriority;
                  MSTP_MSTI_PORT_PRI_VECTOR_t       *portPriVecPtr =
                                          &mstiPortPtr->portPriority;

                  if((mstp_mstiPriorityVectorsCompare(dsnPriVecPtr,
                                                      portPriVecPtr) < 0))
                  {/* the Designated Priority Vector is better than the Port
                    * Priority Vector */

                     /*------------------------------------------------------
                      * 13.26.23 m)
                      *------------------------------------------------------*/
                     selectedRole = MSTP_PORT_ROLE_DESIGNATED;
                     MSTP_MSTI_PORT_SET_BIT(mstiPortPtr->bitMap,
                                            MSTP_MSTI_PORT_UPDT_INFO);
                   }
                  else
                  {/* the Designated Priority Vector is not better than the Port
                    * Priority Vector */
                     MSTP_MSTI_PORT_INFO_t *mstiRootPortPtr;
                     MSTP_MSTI_MSG_PRI_VECTOR_t  *msgPriVecPtr;

                     mstiRootPortPtr =
                        MSTP_MSTI_PORT_PTR(mstid,
                              MSTP_GET_PORT_NUM(MSTP_MSTI_ROOT_PORT_ID(mstid)));
                     if(mstiRootPortPtr)
                     {
                        msgPriVecPtr = &mstiPortPtr->msgPriority;
                     }

                     if(MSTP_BRIDGE_ID_EQUAL(portPriVecPtr->dsnBridgeID,
                                             MSTP_MSTI_BRIDGE_IDENTIFIER(mstid))
                        && (portPriVecPtr->dsnPortID != mstiPortPtr->portId))
                     {/* the Designated Bridge and Designated Port components of
                       * the Port Priority Vector reflect another Port on this
                       * Bridge */

                        /*----------------------------------------------------
                         * 13.26.23 l)
                         *---------------------------------------------------*/
                        selectedRole = MSTP_PORT_ROLE_BACKUP;
                        MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap,
                                               MSTP_MSTI_PORT_UPDT_INFO);
                     }
                     else
                     {/* the Designated Bridge and Designated Port components of
                       * the Port Priority Vector do not reflect another Port on
                       * this Bridge */

                        /*----------------------------------------------------
                         * 13.26.23 k)
                         *---------------------------------------------------*/
                        selectedRole = MSTP_PORT_ROLE_ALTERNATE;
                        MSTP_MSTI_PORT_CLR_BIT(mstiPortPtr->bitMap,
                                               MSTP_MSTI_PORT_UPDT_INFO);
                     }
                     if((MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                                   MSTP_PORT_RESTRICTED_ROLE)) &&
                        ((!mstiRootPortPtr) ||
                         (mstp_mstiPriorityVectorsCompare(&mstiRootPortPtr->msgPriority,
                                                          msgPriVecPtr) > 0)))
                     {
                        mstiPortPtr->rootInconsistent = TRUE;
                        //mstp_sendRootGaurdInconsistencyTrap(mstid, lport);
                     }
                  }
               }
            }
         }
         /*-------------------------------------------------------------------
          * We need to inform about the Role change to interested sub-systems
          * It can be used for Distributed STP in future.
          *------------------------------------------------------------------*/
         if (selectedRole != MSTP_PORT_ROLE_UNKNOWN)
         {
            if(mstiPortPtr->selectedRole != selectedRole)
            {
               char port_role[20] = {0};
               mstp_updatePortHistory(mstid, lport, selectedRole);
               mstp_convertPortRoleEnumToString(selectedRole,port_role);
               mstp_util_set_msti_port_table_string(PORT_ROLE,port_role,mstid,lport);
               /* Does this generate Topology change if so record the
                  current and prev port roles */
               if (mstpCheckForTcGeneration(mstid, lport,
                                            selectedRole))
               {
                  mstpUpdateTcHistory(mstid, lport, TRUE);
                  /*send a trap*/
                  //mstp_sendTopologyChangeTrap(mstid, lport);
               }
            }
            mstiPortPtr->selectedRole = selectedRole;
         }
      }/* end of '(commPortPtr && mstiPortPtr)' statement */
   }/* end of 'for(lport = 1; lport <= MAX_LPORTS; lport++)' loop */
}

/**PROC+**********************************************************************
 * Name:      mstp_updtRolesDisabledTree
 *
 * Purpose:   This procedure sets 'selectedRole' to 'DisabledPort' for all
 *            Ports of the Bridge for a given tree (CIST or MSTI).
 *            (802.1Q-REV/D5.0 13.26.24)
 *            Called from Port Role Selection (PRS) state machine.
 *
 * Params:    mstid -> MST Instance Identifier
 *
 * Returns:   none
 *
 * Globals:   mstp_CB, mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_updtRolesDisabledTree(MSTID_t mstid)
{
   LPORT_t lport;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(MSTP_INSTANCE_IS_VALID(mstid));

   if(mstid == MSTP_CISTID)
   {/* set all CIST ports */
      MSTP_CIST_PORT_INFO_t *cistPortPtr;

      for(lport = 1; lport <= MAX_LPORTS; lport++)
      {
         cistPortPtr = MSTP_CIST_PORT_PTR(lport);
         if(cistPortPtr)
            cistPortPtr->selectedRole = MSTP_PORT_ROLE_DISABLED;
      }
   }
   else
   {/* set all ports for a given MSTI */
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr;

      for(lport = 1; lport <= MAX_LPORTS; lport++)
      {
         mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
         if(mstiPortPtr)
            mstiPortPtr->selectedRole = MSTP_PORT_ROLE_DISABLED;
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_AllSyncedCondition
 *
 * Purpose:   Utility function to verify if 'allSynced' condition
 *            is met for a given Port for a given Tree.
 *            The condition 'allSynced' is TRUE for a given Port,
 *            for a given Tree, if and only if:
 *            a) for all Ports for the given Tree, 'selected' is TRUE,
 *               the Port's role is the same as its 'selectedRole', and
 *               'updtInfo' is FALSE; and
 *            b) the role of the given Port is
 *               1) Root Port or Alternate Port, and 'synced' is TRUE
 *                  for all Ports for the given Tree other than the
 *                  Root Port; or
 *               2) Designated Port, and 'synced' is TRUE for all Ports
 *                  for the given Tree other than the given Port;
 *                  or
 *               3) Master Port, and 'synced' is TRUE for all Ports for
 *                  the given Tree other than the given Port.
 *            Called from the Port Role Transition (PRT) State Machine *
 *            (802.1Q-REV/D5.0 13.25.1)
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   TRUE if 'allSynced' condition is met for a given 'lport' for a
 *            given 'mstid', FALSE otherwise
 *
 * Globals:
 *
 **PROC-**********************************************************************/
bool
mstp_AllSyncedCondition(MSTID_t mstid, LPORT_t lport)
{
   bool             allSynced          = FALSE;
   MSTP_PORT_ROLE_t role               = MSTP_PORT_ROLE_UNKNOWN;
   bool            roleEqSelectedRole = FALSE;
   bool            updtInfo           = TRUE;
   bool            otherPortsSynced   = TRUE;
   bool            allPortsSelected   = TRUE;
   LPORT_t          lportTmp           = 0;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(IS_VALID_LPORT(lport));
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));

   /*------------------------------------------------------------------------
    * Collect information necessary to determine the 'allSynced' condition
    *------------------------------------------------------------------------*/
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      STP_ASSERT(cistPortPtr);
      role               = cistPortPtr->role;
      roleEqSelectedRole = (role == cistPortPtr->selectedRole);
      updtInfo           =  MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                                      MSTP_CIST_PORT_UPDT_INFO);
      if(roleEqSelectedRole && !updtInfo)
      {
         for(lportTmp = 1; lportTmp <= MAX_LPORTS; lportTmp++)
         {
            if((cistPortPtr = MSTP_CIST_PORT_PTR(lportTmp)))
            {
               /* check if 'selected' is TRUE for all Ports
                * for the given Tree */
               if(!MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                             MSTP_CIST_PORT_SELECTED))
               {
                  allPortsSelected = FALSE;
                  break;
               }

               if(role == MSTP_PORT_ROLE_ALTERNATE)
               {/* check if 'synced' is TRUE for all Ports for the given Tree
                 * other than the Root Port */
                  if((cistPortPtr->role != MSTP_PORT_ROLE_ROOT) &&
                     !MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                                MSTP_CIST_PORT_SYNCED))
                  {
                     otherPortsSynced = FALSE;
                     break;
                  }
               }
               else if((role == MSTP_PORT_ROLE_ROOT) ||
                       (role == MSTP_PORT_ROLE_DESIGNATED) ||
                       (role == MSTP_PORT_ROLE_MASTER))
               {/* check if 'synced' is TRUE for all Ports for the given Tree
                 * other than given Port */
                  if((lportTmp != lport) &&
                     !MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                                MSTP_CIST_PORT_SYNCED))
                  {
                     otherPortsSynced = FALSE;
                     break;
                  }
               }
            }
         }
      }
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      STP_ASSERT(mstiPortPtr);
      role               = mstiPortPtr->role;
      roleEqSelectedRole = (role == mstiPortPtr->selectedRole);
      updtInfo           =  MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                                      MSTP_MSTI_PORT_UPDT_INFO);
      if(roleEqSelectedRole && !updtInfo)
      {
         for(lportTmp = 1; lportTmp <= MAX_LPORTS; lportTmp++)
         {
            if((mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lportTmp)))
            {
               /* check if 'selected' is TRUE for all Ports
                * for the given Tree */
               if(!MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                             MSTP_MSTI_PORT_SELECTED))
               {
                  allPortsSelected = FALSE;
                  break;
               }

               if(role == MSTP_PORT_ROLE_ALTERNATE)
               {/* check if 'synced' is TRUE for all Ports for the given Tree
                 * other than the Root Port */
                  if((mstiPortPtr->role != MSTP_PORT_ROLE_ROOT) &&
                     !MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                                MSTP_MSTI_PORT_SYNCED))
                  {
                     otherPortsSynced = FALSE;
                     break;
                  }
               }
               else if((role == MSTP_PORT_ROLE_ROOT) ||
                       (role == MSTP_PORT_ROLE_DESIGNATED) ||
                       (role == MSTP_PORT_ROLE_MASTER))
               {/* check if 'synced' is TRUE for all Ports for the given Tree
                 * other than given Port */
                  if((lportTmp != lport) &&
                     !MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                                MSTP_MSTI_PORT_SYNCED))
                  {
                     otherPortsSynced = FALSE;
                     break;
                  }
               }
            }
         }
      }
   }

  /*-------------------------------------------------------------------------
   * Final check for 'allSynced' condition
   *-------------------------------------------------------------------------*/
   allSynced = (roleEqSelectedRole && !updtInfo &&
                allPortsSelected && otherPortsSynced);

   return allSynced;
}

/**PROC+**********************************************************************
 * Name:      mstp_allTransmitReadyCondition
 *
 * Purpose:   Utility function to verify if 'allTransmitReady' condition
 *            is met for a given Port for all Trees (the CIST and all MSTIs).
 *            The condition 'allTransmitReady' is TRUE if and only if,
 *            for the given Port for all Trees:
 *               a) 'selected' is TRUE; and
 *               b) 'updtInfo' is FALSE.
 *
 * Params:    lport -> logical port number
 *
 * Returns:   TRUE if 'allTransmitReady' condition is met for a given 'lport',
 *            FALSE otherwise
 *
 * Globals:
 *
 **PROC-**********************************************************************/
bool
mstp_allTransmitReadyCondition(LPORT_t lport)
{
   bool                   allTransmitReady = FALSE;
   bool                  selected         = FALSE;
   bool                  updtInfo         = FALSE;
   MSTP_CIST_PORT_INFO_t *cistPortPtr      = MSTP_CIST_PORT_PTR(lport);

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(MSTP_NUM_OF_VALID_TREES > 0);
   STP_ASSERT(IS_VALID_LPORT(lport));
   STP_ASSERT(cistPortPtr);

  /*-------------------------------------------------------------------------
   * Check Port's 'allTransmitReady' condition for the CIST
   *-------------------------------------------------------------------------*/
   selected = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                        MSTP_CIST_PORT_SELECTED);
   updtInfo = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                        MSTP_CIST_PORT_UPDT_INFO);
   allTransmitReady = (selected && !updtInfo);

   if(allTransmitReady && (MSTP_NUM_OF_VALID_TREES > 1))
   {
      MSTID_t mstid;

     /*----------------------------------------------------------------------
      * Check Port's 'allTransmitReady' condition for all MSTIs
      *----------------------------------------------------------------------*/
      for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
      {
         if(MSTP_MSTI_VALID(mstid))
         {
            MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid,
                                                                    lport);
            STP_ASSERT(mstiPortPtr);
            selected = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                                 MSTP_MSTI_PORT_SELECTED);
            updtInfo = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                                 MSTP_MSTI_PORT_UPDT_INFO);
            allTransmitReady = (selected && !updtInfo);
         }

         if(!allTransmitReady)
            break;
      }
   }

   return allTransmitReady;
}

/**PROC+**********************************************************************
 * Name:      mstp_ReRootedCondition
 *
 * Purpose:   Utility function to verify if 'reRooted' condition
 *            is met for a given Port for a given Tree.
 *            The condition 'reRooted' is TRUE if the 'rrWhile' timer
 *            is clear (zero) for all Ports for the given Tree other than
 *            the given Port.
 *            (802.1Q-REV/D5.0 13.25 f); 802.1D-2004 17.20.10)
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            lport -> logical port number
 *
 * Returns:   TRUE if 'reRooted' condition is met for a given 'lport' for a
 *            given 'mstid', FALSE otherwise
 *
 * Globals:
 *
 **PROC-**********************************************************************/
bool
mstp_ReRootedCondition(MSTID_t mstid, LPORT_t lport)
{
   bool    res = TRUE;
   LPORT_t lportTmp;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));

  /*------------------------------------------------------------------------
   * Check for the 'reRooted' condition
   *------------------------------------------------------------------------*/
   for(lportTmp = 1; lportTmp <= MAX_LPORTS; lportTmp++)
   {
      if(lportTmp == lport)
         continue;

      if(mstid == MSTP_CISTID)
      {
         MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lportTmp);

         if(cistPortPtr && (cistPortPtr->rrWhile != 0))
            res = FALSE;
      }
      else
      {
         MSTP_MSTI_PORT_INFO_t *mstiPortPtr =
                                           MSTP_MSTI_PORT_PTR(mstid, lportTmp);

         if(mstiPortPtr && (mstiPortPtr->rrWhile != 0))
            res = FALSE;
      }

      if(!res)
         break;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_forwardDelayParameter
 *
 * Purpose:   Calculate the value of 'forwardDelay' parameter to be
 *            used by the Port Role Transitions (PRT) State Machine.
 *
 * Params:    lport -> logical port number
 *
 * Returns:   the value of 'HelloTime' if 'sendRstp' is TRUE,
 *            and the value of 'FwdDelay' otherwise.
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
uint16_t
mstp_forwardDelayParameter(LPORT_t lport)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr  = NULL;
   uint16_t                forwardDelay = 0;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);
   if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_SEND_RSTP))
      forwardDelay = commPortPtr->HelloTime;
   else
      forwardDelay = MSTP_CIST_ROOT_TIMES.fwdDelay;

   return forwardDelay;
}

/**PROC+**********************************************************************
 * Name:      mstp_isPortRoleSetOnAnyTree
 *
 * Purpose:   Verify if given 'lport' has assigned given 'role' on any tree
 *
 * Params:    lport -> logical port number
 *            role  -> Port Role to check against to
 *
 * Returns:   TRUE if 'lport' has the 'role' assigned to it on any tree,
 *            FALSE otherwise
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
bool
mstp_isPortRoleSetOnAnyTree(LPORT_t lport, MSTP_PORT_ROLE_t role)
{
   bool res = FALSE;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(IS_VALID_LPORT(lport));

   if(MSTP_CIST_PORT_PTR(lport) && (MSTP_CIST_PORT_PTR(lport)->role == role))
      res = TRUE;
   else
   {
      MSTID_t mstid;

      for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
      {
         if(MSTP_MSTI_VALID(mstid) &&
            MSTP_MSTI_PORT_PTR(mstid, lport) &&
            MSTP_MSTI_PORT_PTR(mstid, lport)->role == role)
         {
            res = TRUE;
            break;
         }
      }
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_updateCstRootHistory
 *
 * Purpose:   Update history information for the CST Root Changes
 *            NOTE: called by 'mstp_updtRolesCist' procedure.
 *
 * Params:    rootID -> Identifier of the new Root Bridge for the CST
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_updateCstRootHistory(MSTP_BRIDGE_IDENTIFIER_t rootID)
{
   int idx;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(MSTP_CIST_VALID);

   /* increment CST Root Changes Counter */
   MSTP_CIST_INFO.cstRootChangeCnt++;

   /* shift all entries one step down to the bottom of the history array */
   for(idx = MSTP_ROOT_HISTORY_MAX-1; idx > 0; idx--)
   {
      MSTP_CIST_INFO.cstRootHistory[idx] = MSTP_CIST_INFO.cstRootHistory[idx-1];
   }

   /* store new info in the first entry of the history array */
   idx = 0;
   MSTP_CIST_INFO.cstRootHistory[idx].rootID = rootID;
   MSTP_CIST_INFO.cstRootHistory[idx].timeStamp = time(NULL);
   MSTP_CIST_INFO.cstRootHistory[idx].valid = TRUE;
}

/**PROC+**********************************************************************
 * Name:      mstp_updateIstRootHistory
 *
 * Purpose:   Update history information for the IST Regional Root Changes
 *            NOTE: called by 'mstp_updtRolesCist' procedure.
 *
 * Params:    rgnRootID -> Identifier of the new Regional Root Bridge
 *                         for the IST
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_updateIstRootHistory(MSTP_BRIDGE_IDENTIFIER_t rgnRootID)
{
   int idx;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(MSTP_CIST_VALID);

   /* increment IST Regional Root Changes Counter */
   MSTP_CIST_INFO.istRgnRootChangeCnt++;

   /* shift all entries one step down to the bottom of the history array */
   for(idx = MSTP_ROOT_HISTORY_MAX-1; idx > 0; idx--)
   {
      MSTP_CIST_INFO.istRgnRootHistory[idx] =
                                      MSTP_CIST_INFO.istRgnRootHistory[idx-1];
   }

   /* store new info in the first entry of the history array */
   idx = 0;
   MSTP_CIST_INFO.istRgnRootHistory[idx].rootID = rgnRootID;
   MSTP_CIST_INFO.istRgnRootHistory[idx].timeStamp = time(NULL);
   MSTP_CIST_INFO.istRgnRootHistory[idx].valid = TRUE;
}

/**PROC+**********************************************************************
 * Name:      mstp_updateMstiRootHistory
 *
 * Purpose:   Update history information for the MSTI Regional Root Changes
 *            NOTE: called by 'mstp_updtRolesMsti' procedure.
 *
 * Params:    mstid     -> MSTI Identifier
 *            rgnRootID -> Identifier of the new Regional Root Bridge
 *                         for the MSTI
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstp_updateMstiRootHistory(MSTID_t mstid, MSTP_BRIDGE_IDENTIFIER_t rgnRootID)
{
   int idx;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(MSTP_MSTI_VALID(mstid));

   /* increment MSTI's Regional Root Changes Counter */
   MSTP_MSTI_INFO(mstid)->mstiRgnRootChangeCnt++;

   /* shift all entries one step down to the bottom of the history array */
   for(idx = MSTP_ROOT_HISTORY_MAX-1; idx > 0; idx--)
   {
      MSTP_MSTI_INFO(mstid)->mstiRgnRootHistory[idx] =
         MSTP_MSTI_INFO(mstid)->mstiRgnRootHistory[idx-1];
   }

   /* store new info in the first entry of the history array */
   idx = 0;
   MSTP_MSTI_INFO(mstid)->mstiRgnRootHistory[idx].rootID = rgnRootID;
   MSTP_MSTI_INFO(mstid)->mstiRgnRootHistory[idx].timeStamp =
                                                         time(NULL);
   MSTP_MSTI_INFO(mstid)->mstiRgnRootHistory[idx].valid = TRUE;
}

/**PROC+**********************************************************************
 * Name:      mstp_logNewRootId
 *
 * Purpose:   Print log message for root changes
 *
 * Params:    oldRootId -> old Root Bridge ID
 *            newRootd  -> newly calculated Root Bridge ID
 *
 * Returns:   None
 *
 * Globals:   None
 *
 * Constraints:
 **PROC-**********************************************************************/
void
mstp_logNewRootId(MSTP_BRIDGE_IDENTIFIER_t oldRootId,
                  MSTP_BRIDGE_IDENTIFIER_t newRootId,
                  bool isCST, MSTID_t mstid)

{
   char mstType[10];
   char old_mac[14], new_mac[14];
   MSTP_TREE_TYPE_t treeType;
   MAC_ADDRESS vlanMac = {0}; //, switchBaseMac;
   if(isCST == TRUE)
   {
      strcpy(mstType,"CST ");
   }
   else
   {
      if(mstid == MSTP_CISTID)
         strcpy(mstType,"IST ");
      else
         sprintf(mstType,"MSTI %d ",mstid);
   }

   //bsp_get_base_mac_addr(switchBaseMac);

   snprintf(old_mac, sizeof(old_mac), "%02x%02x%02x-%02x%02x%02x",
            PRINT_MAC_ADDR(oldRootId.mac_address));

   snprintf(new_mac, sizeof(new_mac), "%02x%02x%02x-%02x%02x%02x",
            PRINT_MAC_ADDR(newRootId.mac_address));
#if OPS_MSTP_TODO
   snprintf(stpLogMsg, RMON_MAX_LOG_STR, GET_RMON_EVENT(RMON_STP_NEW_ROOT),
            mstType,
            MSTP_GET_BRIDGE_PRIORITY(oldRootId),
            (MAC_ADDRS_EQUAL((switchBaseMac), (oldRootId.mac_address))?
            "(this device)": old_mac),
            MSTP_GET_BRIDGE_PRIORITY(newRootId),
            (MAC_ADDRS_EQUAL((switchBaseMac), (newRootId.mac_address))?
            "(this device)": new_mac));

   rmon_log_event(RMON_STP_NEW_ROOT, stpLogMsg);
#endif /*OPS_MSTP_TODO*/
   if(isCST && mstp_debugEventCist)
   {
       MSTP_PRINTF_EVENT("CIST - Root changed from %d:%02x%02x%02x-%02x%02x%02x to %d:%02x%02x%02x-%02x%02x%02x",
                         MSTP_GET_BRIDGE_PRIORITY(oldRootId),
                         PRINT_MAC_ADDR(oldRootId.mac_address),
                         MSTP_GET_BRIDGE_PRIORITY(newRootId),
                         PRINT_MAC_ADDR(newRootId.mac_address));
   }
   else if (mstid == 0 && mstp_debugEventCist)
   {
       MSTP_PRINTF_EVENT("IST - Root changed from %d:%02x%02x%02x-%02x%02x%02x to %d:%02x%02x%02x-%02x%02x%02x",
                         MSTP_GET_BRIDGE_PRIORITY(oldRootId),
                         PRINT_MAC_ADDR(oldRootId.mac_address),
                         MSTP_GET_BRIDGE_PRIORITY(newRootId),
                         PRINT_MAC_ADDR(newRootId.mac_address));
   }

   log_event("MSTP_NEW_ROOT",
       EV_KV("proto", "%s", mstType),
       EV_KV("old_priority", "%d", MSTP_GET_BRIDGE_PRIORITY(oldRootId)),
       EV_KV("old_mac", "%02x:%02x:%02x:%02x:%02x:%02x", PRINT_MAC_ADDR(oldRootId.mac_address)),
       EV_KV("new_priority", "%d", MSTP_GET_BRIDGE_PRIORITY(newRootId)),
       EV_KV("new_mac", "%02x:%02x:%02x:%02x:%02x:%02x", PRINT_MAC_ADDR(newRootId.mac_address)));

   /*send a trap*/
   //getVlanMacaddr(DEFAULT_VLAN_NUMBER, vlanMac); /*To be rewritten*/

   if(MAC_ADDRS_EQUAL(vlanMac, newRootId.mac_address))
   {
      treeType = (isCST ? MSTP_TREE_TYPE_CST :
                  (mstid == MSTP_CISTID ?MSTP_TREE_TYPE_IST : MSTP_TREE_TYPE_MST));
      printf("%d",treeType);
     // mstp_sendNewRootTrap(mstid, treeType );
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_findMstiPortStateChgMsg
 *
 * Purpose:   Find ports state change information block on the global
 *            queue for the given MST Instance.
 *
 * Params:    mstid -> MST Instance Identifier in question.
 *
 * Returns:   pointer to the tree change information block corresponding to
 *            the given 'mstid' if found, NULL otherwise.
 *
 * Globals:   none
 *
 **PROC-**********************************************************************/
MSTP_TREE_MSG_t *
mstp_findMstiPortStateChgMsg(MSTID_t mstid)
{
   MSTP_TREE_MSG_t *m = (MSTP_TREE_MSG_t *)qfirst_nodis(&MSTP_TREE_MSGS_QUEUE);

   for(; m != (MSTP_TREE_MSG_t *) Q_NULL;
         m  = (MSTP_TREE_MSG_t *) qnext_nodis(&MSTP_TREE_MSGS_QUEUE, &m->link))
   {
      if (m->mstid == mstid)
         break;
   }

   return m;
}

/**PROC+*********************************************************************
 * Name:      mstp_getMstiVidMap
 *
 * Purpose:   To fill caller's VID map with VIDs currently associated with
 *            given MST instance.
 *
 * Params:    mstid  -> MST instance identifier
 *            vidMap -> pointer to the caller's VID MAP location to be
 *                      filled in
 *
 * Returns:   none
 *
 * Globals:   mstp_MstiVidTable
 *
 * Constraints:
 *****************************************************************************/
void
mstp_getMstiVidMap(MSTID_t mstid, VID_MAP *vidMap)
{
   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(vidMap);

   /*------------------------------------------------------------------------
    * If MST Instance does exist then copy it's run time VID MAP data to
    * the caller's provided buffer, otherwise just clear it
    *------------------------------------------------------------------------*/
   if(MSTP_INSTANCE_IS_VALID(mstid))
      copy_vid_map(&mstp_MstiVidTable[mstid], vidMap);
   else
      clear_vid_map(vidMap);

}

/**PROC+**********************************************************************
 * Name:      mstp_getMstIdForVid
 *
 * Purpose:   This function returns MST Instance Identifier to which given
 *            'vid' is mapped to.
 *
 * Params:    vid -> ID of VLAN in question
 *
 * Returns:   the MST Instance Identifier the given 'vid' is mapped to
 *
 * Globals:   mstp_MstiVidTable
 *
 * Constraints:
 **PROC-**********************************************************************/
MSTID_t
mstp_getMstIdForVid(VID_t vid)
{
   MSTID_t mstid = MSTP_NO_MSTID;
   MSTID_t tmpMstid;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(IS_VALID_VID(vid));


   /*------------------------------------------------------------------------
    * Search in 'mstp_MstiVidTable'
    *------------------------------------------------------------------------*/
   for(tmpMstid = MSTP_CISTID; tmpMstid <= MSTP_INSTANCES_MAX; tmpMstid++)
   {
      if(is_vid_set(&mstp_MstiVidTable[tmpMstid], vid))
      {
         mstid = tmpMstid;
         break;
      }
   }

   return mstid;
}

/**PROC+**********************************************************************
 * Name:      mstp_getComponentId
 *
 * Purpose:   Convert VID map from SNMP format to the switch's internal fromat
 *            NOTE: MSTP MIB objects representing VIDs information designed
 *                  so that VIDs are encoded bitwise from left to right, which
 *                  may differ from the internal bit map representation.
 *
 * Params:    vidMap  -> VID map to convert
 *
 * Returns:   none
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
int  mstp_getComponentId()
{
  return MSTP_MIN_COMPONENT_ID;
}


/**PROC+**********************************************************************
 * Name:      mstp_getMstiUptime
 *
 * Purpose    Get Uptime of each port
 *
 *
 * Params:    lport
 *
 *
 * Returns:   PortUptime
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
int
mstp_getMstiUptime(MSTID_t mstid, LPORT_t lport)
{
 uint32_t     mstiPort_uptime;
 MSTP_MSTI_PORT_INFO_t *mstiPortPtr = NULL;

 mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

 mstiPort_uptime = time(NULL) - mstiPortPtr->mstiPort_uptime;
 return (mstiPort_uptime);
}

/**PROC+**********************************************************************
 * Name:      mstp_getCistUptime
 *
 * Purpose    Get Uptime of each port
 *
 *
 * Params:    lport
 *
 *
 * Returns:   PortUptime
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
int
mstp_getCistUptime(LPORT_t lport)
{
 uint32_t     cistPort_uptime;
 MSTP_CIST_PORT_INFO_t *cistPortPtr = NULL;

 cistPortPtr = MSTP_CIST_PORT_PTR(lport);

 cistPort_uptime = time(NULL) - cistPortPtr->cistPort_uptime;
 return (cistPort_uptime);
}
/**PROC+**********************************************************************
 * Name:      mstp_isTopologyChange
 *
 * Purpose:   Whether Topology has changed for the CIST or the MSTIs).
 *
 * Params:    MSTP instance id
 *
 * Returns:   TRUE if topology change else FALSE
 *
 * Globals:   none
 *
 **PROC-**********************************************************************/
bool
mstp_isTopologyChange(MSTID_t mstid)
{
   LPORT_t                lport;
   MSTP_CIST_PORT_INFO_t *cistPortPtr;
   MSTP_MSTI_PORT_INFO_t *mstiPortPtr;
   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(mstid <= MSTP_INSTANCES_MAX);


   for(lport = 1;lport <= MAX_LPORTS; lport++)
   {
      /*------------------------------------------------------------------------
       * check the CIST
       *----------------------------------------------------------------------*/
      if(mstid == MSTP_CISTID )
      {
         cistPortPtr = MSTP_CIST_PORT_PTR(lport);
         STP_ASSERT(cistPortPtr);
         if(cistPortPtr && (cistPortPtr->tcWhile != 0))
         {
            return TRUE;
         }

      }
      /*---------------------------------------------------------------------
       * continue check through  configured MSTIs
       *---------------------------------------------------------------------*/
      else
      {
         STP_ASSERT(mstid <= MSTP_INSTANCES_MAX);
         mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
         STP_ASSERT(mstiPortPtr);
         if(mstiPortPtr && (mstiPortPtr->tcWhile != 0))
         {
            return TRUE;
         }
      }
   }
   return FALSE;
}

/**PROC+*********************************************************************
 * Name:         mstp_printVidMap
 *
 * Purpose:      To print list of VIDs set in the provided vid map
 *               with specified MSTP instance (the CIST or an MSTI).
 *
 * Params:       srcVidMap  -> pointer to the VID MAP to be printed out
 *               lineLen    -> max length of the output line to be displayed
 *               indent     -> output indentation length (left margin size)
 *
 * Return        none
 *
 * Constraints
 *****************************************************************************/
void
mstp_printVidMap(VID_MAP *srcVidMap, uint16_t lineLen, uint16_t indent)
{
#define MSTP_MAX_VID_STR_LEN 10 /* length of "xxxx-xxxx" + '\0' */
   VID_MAP vidMap;
   int     vid;
   int     vidFound       = 0;
   bool   findRange      = FALSE;
   int     printedLineLen = 0;
   char    vidStr[MSTP_MAX_VID_STR_LEN];
   char   *tmp;
   char   *vidDelimiter = ",";
   char   *rangeDelimiter = "-";
   int     l = 0;

   STP_ASSERT(srcVidMap);
   STP_ASSERT(lineLen >= MSTP_MAX_VID_STR_LEN);
   if(!are_any_vids_set(srcVidMap))
      return;

   clear_vid_map(&vidMap);
   copy_vid_map(srcVidMap, &vidMap);

   /* Print VIDs that are set in the VID MAP
    * NOTE: We loop one extra time, so that we can print the final VID
    *       before we exit */
   STP_ASSERT(sizeof(vidMap)*8 == MAX_VLAN_ID);
   tmp = vidStr;
   for(vid = MIN_VLAN_ID; vid <= MAX_VLAN_ID + 1; vid++)
   {
      if(is_vid_set(&vidMap, vid))
      {/* VID is set */
         if(findRange == FALSE)
         {/* print the VID found and start looking for a range */
            STP_ASSERT((tmp - vidStr) < (int)sizeof(vidStr));
            sprintf(tmp, "%d%n", vid, &l);
            tmp += l;
            findRange = TRUE;
            vidFound = vid;
         }
         /* clear VID from map to keep track on how many others left */
         clear_vid(&vidMap, vid);
      }
      else
      {/* VID is not set */
         if(findRange == TRUE)
         {/* we tried to find a VID range and the first VID in range has been
           * already printed */
            int rangeSize = (vid - 1) - vidFound;

            if(rangeSize == 0)
            {/* no range detected (i.e. no next adjacent VID found), if
              * there are still other VIDs follow in the map then print
              * 'vidDelimiter' */
               if(are_any_vids_set(&vidMap))
               {
                  STP_ASSERT((tmp - vidStr) < (int)sizeof(vidStr));
                  sprintf(tmp, "%s%n", vidDelimiter, &l);
                  tmp += l;
               }
            }
            else
            {/* the VID range is detected; print last VID in the range, if
              * range size is greater than 1 then print 'rangeDelimiter',
              * otherwise use 'vidDelimiter' */
               STP_ASSERT((tmp - vidStr) < (int)sizeof(vidStr));
               sprintf(tmp, "%s%d%n",
                       (rangeSize > 1) ? rangeDelimiter : vidDelimiter,
                       vid - 1, &l);
               tmp += l;
               if(are_any_vids_set(&vidMap))
               {
                  STP_ASSERT((tmp - vidStr) < (int)sizeof(vidStr));
                  sprintf(tmp, "%s%n", vidDelimiter, &l);
                  tmp += l;
               }
            }
            findRange = FALSE;

            /* Format output lines if necessary */
            if((printedLineLen + strlen(vidStr)) > lineLen)
            {
               printf("\n");
               printf("%*s", indent, "");
               printedLineLen = 0;
            }
            printf("%s%n", vidStr, &l);
            printedLineLen += l;
            tmp = vidStr;
         }
      }
   }
}

/**PROC+*********************************************************************
 * Name:         mstp_vidMapToVidStr
 *
 * Purpose:      To fill caller's supplied buffer with the list of VIDs
 *               set in the passed 'srcVidMap'. It fills buffer up to the
 *               specified buffer size.
 *
 * Params:       srcVidMap  -> pointer to the VID MAP
 *               buf        -> buffer to be filled in
 *               bufLen     -> length of the buffer
 *
 * Return        the next VID yet to be printed, '0' if no unprinted VIDs
 *               left in the map
 *
 * Constraints
 *****************************************************************************/
VID_t
mstp_vidMapToVidStr(VID_MAP *srcVidMap, char *buf, uint16_t bufLen)
{
#define MSTP_MAX_VID_STR_LEN 10 /* length of "xxxx-xxxx" + '\0' */
   VID_MAP vidMap;
   VID_t   vid            = 0;
   VID_t   vidFound       = 0;
   VID_t   maxVidFound    = 0;
   VID_t   nextVidToPrint = 0;
   VID_t   i              = 0;
   bool   findRange      = FALSE;
   int     l              = 0;
   char   *vidDelimiter   = " ";
   char   *rangeDelimiter = "-";
   char   *tmp            = NULL;
   char   *d              = NULL;
   char    vidStr[MSTP_MAX_VID_STR_LEN];
   char    vidStr1[MSTP_MAX_VID_STR_LEN];
   char    vidStr2[MSTP_MAX_VID_STR_LEN];

   STP_ASSERT(srcVidMap);
   STP_ASSERT(buf);
   STP_ASSERT(bufLen>0);

   clear_vid_map(&vidMap);
   copy_vid_map(srcVidMap, &vidMap);

   tmp = buf;
   for(vid = MIN_VLAN_ID; vid <= MAX_VLAN_ID + 1; vid++)
   {
      if(is_vid_set(&vidMap, vid))
      {/* VID is set */
         if(findRange == FALSE)
         {/* The first VID in a potential range. Mark it and continue. */
            findRange = TRUE;
            vidFound = vid;
            maxVidFound = vid;
         }
         else
         {/* The next VID in the range. Move the end of the range. */
            maxVidFound = vid;
         }
      }
      else
      {/* VID is not set */
         if(findRange == TRUE){/* A range just ended. Print it */
             if (vidFound == maxVidFound)
             {/* A range of 1 VID */
                 sprintf(vidStr,"%d",vidFound);
                 //itoa(vidFound, vidStr);
                 l = strlen(vidStr);
                 if(((tmp - buf) + l) > bufLen)
                    break;
                 sprintf(tmp, "%s", vidStr);
                 tmp += l;
                 clear_vid(&vidMap, vidFound);
             }
             else
             { /* multiple-VID range */
                 int rangeSize = maxVidFound - vidFound;
                 d = ((rangeSize > 1) ? rangeDelimiter : vidDelimiter);
                 //itoa(vidFound, vidStr1);
                 sprintf(vidStr1,"%d",vidFound);
                 //itoa(maxVidFound, vidStr2);
                 sprintf(vidStr2,"%d",vidFound);
                 sprintf(vidStr, "%s%s%s", vidStr1, d, vidStr2);
                 l = strlen(vidStr);
                 if(((tmp - buf) + l) > bufLen)
                    break;
                 sprintf(tmp, "%s", vidStr);
                 tmp += l;
                 for(i = vidFound; i<=maxVidFound; i++) {
                     clear_vid(&vidMap, i);
                 }
             }
             findRange = FALSE;
             /* if there are still other VIDs follow in the map then print
              * 'vidDelimiter' */
             if(are_any_vids_set(&vidMap))
             {
                 l = strlen(vidDelimiter);
                 if(((tmp - buf) + l) > bufLen)
                    break;
                 sprintf(tmp, "%s", vidDelimiter);
                 tmp += l;
             }
         }
      }
   }

   nextVidToPrint = find_first_vid_set(&vidMap);
   return (IS_VALID_VID(nextVidToPrint)) ? nextVidToPrint : 0;
}

/** ======================================================================= **
 *                                                                           *
 *     Static (local to this file) Functions                                 *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_updtMstiRootInfoChg
 *
 * Purpose:   Add the state change information of the logical port on the
 *            given Spanning Tree to the global tree changes info collector
 *            for further distribution to the interested external subsystems.
 *
 * Params:    mstid -> MST Instance Identifier for which a port has the state
 *                     change.
 *
 * Returns:   none
 *
 * Globals:   none
 *
 **PROC-**********************************************************************/
static void
mstp_updtMstiRootInfoChg(MSTID_t mstid)
{
   MSTP_TREE_MSG_t *m = mstp_findMstiPortStateChgMsg(mstid);


   if(m == NULL)
   {
      m = calloc(1, sizeof(MSTP_TREE_MSG_t));
      m->mstid        = mstid;
      m->link.q_flink = NULL;
      m->link.q_blink = NULL;
      insqti_nodis(&MSTP_TREE_MSGS_QUEUE, &m->link);
   }

   m->rootInfoChanged = TRUE;
}

/**PROC+**********************************************************************
 * Name:      mstp_updtMstiPortStateChgMsg
 *
 * Purpose:   Add the state change information of the logical port on the
 *            given Spanning Tree to the global tree changes info collector
 *            for further distribution to the interested external subsystems.
 *
 * Params:    mstid -> MST Instance Identifier for which a port has the state
 *                     change.
 *            lport -> logical port number that changed the state
 *            state -> the new state of the logical port
 *
 * Returns:   none
 *
 * Globals:   none
 *
 **PROC-**********************************************************************/
static void
mstp_updtMstiPortStateChgMsg(MSTID_t mstid, LPORT_t lport,
                             MSTP_ACT_TYPE_t state)
{
   MSTP_TREE_MSG_t *m = mstp_findMstiPortStateChgMsg(mstid);

   if(m == NULL)
   {
      m = calloc(1, sizeof(MSTP_TREE_MSG_t));
      m->mstid        = mstid;
      m->link.q_flink = NULL;
      m->link.q_blink = NULL;
      insqti_nodis(&MSTP_TREE_MSGS_QUEUE, &m->link);
   }

   switch(state)
   {
      case MSTP_ACT_PROPAGATE_DOWN:
      case MSTP_ACT_DISABLE_FORWARDING:
         clear_port(&m->portsFwd, lport);
         clear_port(&m->portsLrn, lport);
         set_port(&m->portsBlk, lport);
         clear_port(&m->portsUp, lport);
         set_port(&m->portsDwn, lport);
         break;
      case MSTP_ACT_PROPAGATE_UP:
      case MSTP_ACT_ENABLE_FORWARDING:
         set_port(&m->portsFwd, lport);
         clear_port(&m->portsLrn, lport);
         clear_port(&m->portsBlk, lport);
         set_port(&m->portsUp, lport);
         clear_port(&m->portsDwn, lport);
         break;
      case MSTP_ACT_ENABLE_LEARNING:
         clear_port(&m->portsFwd, lport);
         set_port(&m->portsLrn, lport);
         clear_port(&m->portsBlk, lport);
         clear_port(&m->portsUp, lport);
         clear_port(&m->portsDwn, lport);
         break;
      default:
         STP_ASSERT(0);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_portIsForwardingOnAnyTree
 *
 * Purpose:   Check if given logical port is in FORWARDING state on any of the
 *            configured Spanning Trees (the CIST or the MSTIs).
 *
 * Params:    lport -> logical port number in question
 *
 * Returns:   TRUE if 'lport' is in FORWARDING state on any of the configured
 *            Trees, FALSE otherwise.
 *
 * Globals:   none
 *
 **PROC-**********************************************************************/
bool
mstp_portIsForwardingOnAnyTree(LPORT_t lport)
{
   bool                   fwd;
   MSTP_CIST_PORT_INFO_t *cistPortPtr;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(IS_VALID_LPORT(lport));

   /*------------------------------------------------------------------------
    * check the CIST
    *------------------------------------------------------------------------*/
   cistPortPtr = MSTP_CIST_PORT_PTR(lport);
   STP_ASSERT(cistPortPtr);
   fwd = MSTP_CIST_PORT_IS_BIT_SET(cistPortPtr->bitMap,
                                   MSTP_CIST_PORT_FORWARDING);

   if(!fwd)
   {
      MSTID_t                mstid;
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr;

      /*---------------------------------------------------------------------
       * continue check through all configured MSTIs
       *---------------------------------------------------------------------*/
      for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
      {
         if(MSTP_MSTI_VALID(mstid))
         {
            mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
            STP_ASSERT(mstiPortPtr);
            fwd = MSTP_MSTI_PORT_IS_BIT_SET(mstiPortPtr->bitMap,
                                            MSTP_MSTI_PORT_FORWARDING);
            if(fwd)
               break;
         }
      }
   }

   return fwd;
}
/**PROC+**********************************************************************
 * Name:      mstp_updatePmaps
 *
 * Purpose:   This function called when number of Spanning Trees is 1 (the CIST)
 *            and updates 'MSTP_FWD_LPORTS' and 'MSTP_BLK_LPORTS'
 *            global port maps to keep track of logical ports MSTP have told
 *            IDL they are forwarding or blocked. These maps will be used when
 *            we have more than one Spanning Tree configured, in order to
 *            filter those ports whose states are already known by IDL. Thus
 *            we are accomplish the following things:
 *              a) preventing IDL from confusion, as the same port may have
 *                 different states on different Trees
 *              b) eliminating message flooding when a port is transitioning to
 *                 the same state on multiple Trees
 *            In general, we are trying to keep IDL informed about ports states
 *            on per-Box basis rather then on per-Tree.
 *
 * Params:    pmap    -> pointer to the map of logical ports that have state
 *                       change
 *            action  -> indicates what type of action is being performed
 *                       on the port(s)
 *                       (MSTP_ACT_DISABLE_FORWARDING,
 *                        MSTP_ACT_ENABLE_FORWARDING,
 *                        MSTP_ACT_ENABLE_LEARNING)
 *
 * Returns:   none
 *
 * Globals:   mstp_CB.fwdLports, mstp_CB.blkLports
 *
 **PROC-**********************************************************************/
void
mstp_updatePmaps(PORT_MAP *pmap, MSTP_ACT_TYPE_t action)
{
   PORT_MAP tmp_pmap;

   STP_ASSERT(MSTP_ENABLED && (MSTP_NUM_OF_VALID_TREES == 1));

   clear_port_map(&tmp_pmap);
   if(action == MSTP_ACT_ENABLE_FORWARDING)
   {
      /*---------------------------------------------------------------------
       * Update global 'fwdLports' and 'blkLports' maps with the
       * ports we tell IDL they are forwarding.
       *---------------------------------------------------------------------*/
      bit_or_port_maps(pmap, &MSTP_FWD_LPORTS);
      copy_port_map(pmap, &tmp_pmap);
      bit_inverse_port_map(&tmp_pmap);
      bit_and_port_maps(&tmp_pmap, &MSTP_BLK_LPORTS);
   }
   else
   {
      STP_ASSERT(action == MSTP_ACT_DISABLE_FORWARDING ||
             action == MSTP_ACT_ENABLE_LEARNING);
      /*---------------------------------------------------------------------
       * Update global 'fwdLports' and 'blkLports' maps with the
       * ports we tell IDL they are blocked.
       *---------------------------------------------------------------------*/
      bit_or_port_maps(pmap, &MSTP_BLK_LPORTS);
      copy_port_map(pmap, &tmp_pmap);
      bit_inverse_port_map(&tmp_pmap);
      bit_and_port_maps(&tmp_pmap, &MSTP_FWD_LPORTS);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_filterPmapsFromDuplicatePorts
 *
 * Purpose:   From 'srcPmap' remove logical ports that we have already told
 *            IDL are forwarding or ports that are still forwarding on at
 *            least one Tree while blocked on the others, thus leaving in
 *            'dstPmap' only those ports whose states changed for the whole Box.
 *            NOTE: MSTP ports do change their state on per-Vlan basis, i.e.
 *                  the same port may be forwarding or blocked on multiple
 *                  VLANs at the same time. As IDL maintaines port state info
 *                  on per-Box basis we will inform IDL only about logical
 *                  ports that are either first time become forwarding on some
 *                  Tree (first forwarding for the whole Box) or become blocked
 *                  on all configured Trees (blocked for the whole Box).
 *
 * Params:    srcPmap -> pointer to the map of logical ports that have state
 *                       change
 *            dstPmap -> pointer to the map of logical ports whose state change
 *                       needs to be propagated to IDL.
 *            action  -> indicates what type of action is being performed
 *                       on the port(s)
 *                       (MSTP_ACT_DISABLE_FORWARDING,
 *                        MSTP_ACT_ENABLE_FORWARDING,
 *                        MSTP_ACT_ENABLE_LEARNING)
 *
 * Returns:   none
 *
 * Globals:   mstp_CB.fwdLports, mstp_CB.blkLports
 *
 **PROC-**********************************************************************/
void
mstp_filterPmapsFromDuplicatePorts(PORT_MAP *srcPmap, PORT_MAP *dstPmap,
                                       MSTP_ACT_TYPE_t action)
{
   PORT_MAP tmp_pmap;

   STP_ASSERT(MSTP_ENABLED && (MSTP_NUM_OF_VALID_TREES > 1));
   STP_ASSERT(srcPmap);
   STP_ASSERT(dstPmap);
   STP_ASSERT(are_any_ports_set(srcPmap));

   clear_port_map(dstPmap);
   if(action == MSTP_ACT_ENABLE_FORWARDING)
   {
      /*---------------------------------------------------------------------
       * extract from 'srcPmap' only those ports that are first forwarding on
       * the whole Box (first forwarding on one of the all Trees), i.e we have
       * not told yet IDL they are forwarding.
       *---------------------------------------------------------------------*/
      copy_port_map(&MSTP_FWD_LPORTS, &tmp_pmap);
      bit_inverse_port_map(&tmp_pmap);
      bit_and_port_maps(srcPmap, &tmp_pmap);
      /*---------------------------------------------------------------------
       * update 'dstPmap' with the newly forwarding ports. Also update global
       * 'fwdLports' and 'blkLports' maps with the ports we tell
       *  IDL they are forwarding.
       *---------------------------------------------------------------------*/
      if(are_any_ports_set(&tmp_pmap))
      {
         copy_port_map(&tmp_pmap, dstPmap);
         bit_or_port_maps(dstPmap, &MSTP_FWD_LPORTS);
         bit_inverse_port_map(&tmp_pmap);
         bit_and_port_maps(&tmp_pmap, &MSTP_BLK_LPORTS);
      }
   }
   else
   {
      LPORT_t lport;

      STP_ASSERT(action == MSTP_ACT_DISABLE_FORWARDING ||
             action == MSTP_ACT_ENABLE_LEARNING);
      /*---------------------------------------------------------------------
       * extract from 'srcPmap' only those ports that are blocked on the
       * whole Box (not forwarding on any Tree).
       *---------------------------------------------------------------------*/
      copy_port_map(srcPmap, dstPmap);
      for (lport = (LPORT_t)find_first_port_set(dstPmap);
           IS_VALID_LPORT(lport);
           lport = (LPORT_t)find_next_port_set(dstPmap, lport))
      {
         if(mstp_portIsForwardingOnAnyTree(lport))
         {
            clear_port(dstPmap, lport);
         }
      }

      /*---------------------------------------------------------------------
       * update 'dstPmap' with the newly blocked ports. Also update global
       * 'fwdLports' and 'blkLports' maps with the ports that we
       * tell IDL they are blocked.
       *---------------------------------------------------------------------*/
      if(are_any_ports_set(dstPmap))
      {
         copy_port_map(&MSTP_BLK_LPORTS, &tmp_pmap);
         bit_inverse_port_map(&tmp_pmap);
         bit_and_port_maps(&tmp_pmap, dstPmap);
         if(are_any_ports_set(dstPmap))
         {
            bit_or_port_maps(dstPmap, &MSTP_BLK_LPORTS);
            copy_port_map(dstPmap, &tmp_pmap);
            bit_inverse_port_map(&tmp_pmap);
            bit_and_port_maps(&tmp_pmap, &MSTP_FWD_LPORTS);
         }
      }
   }
}
/**PROC+**********************************************************************
 * Name:      mstp_convertLportSpeedToPathCost
 *
 * Purpose:   convert port speed to MSTP path cost value.
 *
 * Params:    speedDplx -> pointer to the SPEED_DPLX data structure
 *
 * Returns:   Path Cost value that corresponds to the current value of the
 *            port's physical link characteristics.
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_convertLportSpeedToPathCost(SPEED_DPLX* speedDplx)
{
    STP_ASSERT(speedDplx);

    switch(speedDplx->speed)
    {
        case SPEED_10MB:
            return MSTP_PORT_PATH_COST_ETHERNET;
            break;
        case SPEED_100MB:
            return MSTP_PORT_PATH_COST_100MB;
            break;
        case SPEED_1000MB:
            return MSTP_PORT_PATH_COST_1000MB;
            break;
        case SPEED_2500MB:
            return MSTP_PORT_PATH_COST_2500MB;
            break;
        case SPEED_5000MB:
            return MSTP_PORT_PATH_COST_5000MB;
            break;
        case SPEED_10000MB:
            return MSTP_PORT_PATH_COST_10000MB;
            break;
        case SPEED_40000MB:
            return MSTP_PORT_PATH_COST_40000MB;
            break;
        default:
            //STP_ASSERT(0);
            return MSTP_PORT_PATH_COST_ETHERNET;
            break;
    }
}

/**PROC+**********************************************************************
 * Name:      mstp_isNeighboreBridgeInMyRegion
 *
 * Purpose:   Check if MST Configuration Identification information in
 *            the received BPDU (located in the packet buffer) is identical
 *            to this Bridge's one.
 *
 * Params:    pkt  -> pointer to the packet buffer with BPDU in
 *
 * Returns:   TRUE if MST Configuration Identifiers of the sending Bridge
 *            and this receiving Bridge are identical, FALSE otherwise.
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
static bool
mstp_isNeighboreBridgeInMyRegion(MSTP_RX_PDU *pkt)
{
   MSTP_MST_BPDU_t             *bpdu;
   MSTP_MST_CONFIGURATION_ID_t  bpdu_mstCfgId;
   MSTP_MST_CONFIGURATION_ID_t  my_mstCfgId;
   bool                         res = FALSE;

   STP_ASSERT(pkt);
   STP_ASSERT(mstp_isMstBpdu(pkt));

   memset((void *)&bpdu_mstCfgId, 0, sizeof(MSTP_MST_CONFIGURATION_ID_t));
   memset((void *)&my_mstCfgId, 0, sizeof(MSTP_MST_CONFIGURATION_ID_t));

   /*------------------------------------------------------------------------
    * get sending Bridge MST Config Id
    *------------------------------------------------------------------------*/
   bpdu = (MSTP_MST_BPDU_t *)(pkt->data);
   bpdu_mstCfgId = bpdu->mstConfigurationId;

   /*------------------------------------------------------------------------
    * get this Bridge MST Config Id
    *------------------------------------------------------------------------*/
   memset(&my_mstCfgId, 0 , sizeof(my_mstCfgId));
   mstp_getMyMstConfigurationId(&my_mstCfgId);

   /*------------------------------------------------------------------------
    * compare MST Ids
    *------------------------------------------------------------------------*/
   if((my_mstCfgId.formatSelector == bpdu_mstCfgId.formatSelector)
      &&
      (!memcmp(my_mstCfgId.configName, bpdu_mstCfgId.configName,
               MSTP_MST_CONFIG_NAME_LEN))
      &&
      (my_mstCfgId.revisionLevel == getShortFromPacket(&bpdu_mstCfgId.revisionLevel))
      &&
      !memcmp(my_mstCfgId.digest, bpdu_mstCfgId.digest, MSTP_DIGEST_SIZE))
   {
      res = TRUE;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_mstRgnCfgConsistencyCheck
 *
 * Purpose:   Perform consistency check for the MST Region Configuration
 *            information used by this receiving Bridge and transmitting
 *            neighbor Bridge (e.g. transmitting Bridge may claim itself
 *            to be in the same region as this Bridge but has a different
 *            VLANs->MSTIs mapping, which is very likely indicates the
 *            misconfiguration error).
 *            Update statistics counter if inconsistency error has been
 *            detected.
 *
 * Params:    bpdu  -> pointer to the received MST BPDU
 *            lport -> logical port number MST BPDU was received on
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
static void
mstp_mstRgnCfgConsistencyCheck(MSTP_MST_BPDU_t *bpdu, LPORT_t lport)
{
   MSTP_CIST_PORT_INFO_t       *cistPortPtr   = NULL;
   bool                         sameFormat    = FALSE;
   bool                         sameName      = FALSE;
   bool                         sameRevision  = FALSE;
   bool                         sameDigest    = FALSE;
   MSTP_MST_CONFIGURATION_ID_t  bpdu_mstCfgId;
   MSTP_MST_CONFIGURATION_ID_t  my_mstCfgId;

   STP_ASSERT(bpdu);
   STP_ASSERT(IS_VALID_LPORT(lport));

   cistPortPtr = MSTP_CIST_PORT_PTR(lport);
   STP_ASSERT(cistPortPtr);

   memset((void *)&bpdu_mstCfgId,0,sizeof(MSTP_MST_CONFIGURATION_ID_t));
   memset((void *)&my_mstCfgId,0,sizeof(MSTP_MST_CONFIGURATION_ID_t));
   /*------------------------------------------------------------------------
    * get transmitting Bridge MST Config Id
    *------------------------------------------------------------------------*/
   bpdu_mstCfgId = bpdu->mstConfigurationId;

   /*------------------------------------------------------------------------
    * get this Bridge MST Config Id
    *------------------------------------------------------------------------*/
   memset(&my_mstCfgId, 0, sizeof(my_mstCfgId));
   mstp_getMyMstConfigurationId(&my_mstCfgId);

   /*------------------------------------------------------------------------
    * compare MST Ids
    *------------------------------------------------------------------------*/
   sameFormat   = (my_mstCfgId.formatSelector == bpdu_mstCfgId.formatSelector);
   sameName     = !memcmp(my_mstCfgId.configName, bpdu_mstCfgId.configName,
                          MSTP_MST_CONFIG_NAME_LEN);
   sameRevision = (my_mstCfgId.revisionLevel == ntohs(bpdu_mstCfgId.revisionLevel));
   sameDigest   = !memcmp(my_mstCfgId.digest, bpdu_mstCfgId.digest,
                          MSTP_DIGEST_SIZE);
#if 1
   if(sameFormat && sameName && sameRevision && !sameDigest)
#else/* 0 */
   if((sameFormat && sameName && sameRevision && !sameDigest) ||
     (sameDigest && !(sameFormat && sameName && sameRevision)))
#endif /* 0 */
   {/* update statistics info */
      cistPortPtr->dbgCnts.mstCfgErrorBpduCnt++;
      cistPortPtr->dbgCnts.mstCfgErrorBpduCntLastUpdated =
                                                         time(NULL);
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_cistPriorityVectorsCompare
 *
 * Purpose:   Compares two CIST priority vectors.
 *            NOTE: For all components of a priority vector a lesser
 *                  numerical value is better, and earlier components
 *                  are more significant.
 *            (802.1Q-REV/D5.0 13.9; 13.10)
 *
 * Params:    v1 -> a pointer to the first CIST priority vector
 *            v2 -> a pointer to the second CIST priority vector
 *
 * Returns:   returns an integer less than, equal to, or greater than zero,
 *            depending on whether 'v1' is less than (better),
 *            equal to (same), or greater than (worse) 'v2'.
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
static int
mstp_cistPriorityVectorsCompare(MSTP_CIST_BRIDGE_PRI_VECTOR_t *v1,
                                MSTP_CIST_BRIDGE_PRI_VECTOR_t *v2)
{
   int res;

   STP_ASSERT(v1 && v2);

   if((MSTP_BRIDGE_ID_EQUAL(v1->rootID, v2->rootID))
      &&
      (v1->extRootPathCost == v2->extRootPathCost)
      &&
      (MSTP_BRIDGE_ID_EQUAL(v1->rgnRootID, v2->rgnRootID))
      &&
      (v1->intRootPathCost == v2->intRootPathCost)
      &&
      (MSTP_BRIDGE_ID_EQUAL(v1->dsnBridgeID, v2->dsnBridgeID))
      &&
      (v1->dsnPortID == v2->dsnPortID))
   {/* the first priority vector is the same as the second one */
      res = 0;
   }
   else
   if((MSTP_BRIDGE_ID_LOWER(v1->rootID, v2->rootID))
      ||
      (MSTP_BRIDGE_ID_EQUAL(v1->rootID, v2->rootID) &&
       (v1->extRootPathCost < v2->extRootPathCost))
      ||
      (MSTP_BRIDGE_ID_EQUAL(v1->rootID, v2->rootID) &&
       (v1->extRootPathCost == v2->extRootPathCost) &&
       (MSTP_BRIDGE_ID_LOWER(v1->rgnRootID, v2->rgnRootID)))
      ||
      (MSTP_BRIDGE_ID_EQUAL(v1->rootID, v2->rootID) &&
       (v1->extRootPathCost == v2->extRootPathCost) &&
       (MSTP_BRIDGE_ID_EQUAL(v1->rgnRootID, v2->rgnRootID)) &&
       (v1->intRootPathCost < v2->intRootPathCost))
      ||
      (MSTP_BRIDGE_ID_EQUAL(v1->rootID, v2->rootID) &&
       (v1->extRootPathCost == v2->extRootPathCost) &&
       (MSTP_BRIDGE_ID_EQUAL(v1->rgnRootID, v2->rgnRootID)) &&
       (v1->intRootPathCost == v2->intRootPathCost) &&
       MSTP_BRIDGE_ID_LOWER(v1->dsnBridgeID, v2->dsnBridgeID))
      ||
      (MSTP_BRIDGE_ID_EQUAL(v1->rootID, v2->rootID) &&
       (v1->extRootPathCost == v2->extRootPathCost) &&
       (MSTP_BRIDGE_ID_EQUAL(v1->rgnRootID, v2->rgnRootID)) &&
       (v1->intRootPathCost == v2->intRootPathCost) &&
       (MSTP_BRIDGE_ID_EQUAL(v1->dsnBridgeID, v2->dsnBridgeID)) &&
       (v1->dsnPortID < v2->dsnPortID)))
   {/* the first priority vector is better than the second one */
      res = -1;
   }
   else
   {/* the first priority vector is worse than the second one */
      res = 1;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_mstiPriorityVectorsCompare
 *
 * Purpose:   Compares two MSTI priority vectors.
 *            NOTE: For all components of a priority vector a lesser
 *                  numerical value is better, and earlier components
 *                  are more significant.
 *            (802.1Q-REV/D5.0 13.9; 13.11)
 *
 * Params:    v1 -> a pointer to the first MSTI priority vector
 *            v2 -> a pointer to the second MSTI priority vector
 *
 * Returns:   returns an integer less than, equal to, or greater than zero,
 *            depending on whether 'v1' is less than (better),
 *            equal to (same), or greater than (worse) 'v2'.
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
static int
mstp_mstiPriorityVectorsCompare(MSTP_MSTI_BRIDGE_PRI_VECTOR_t *v1,
                                MSTP_MSTI_BRIDGE_PRI_VECTOR_t *v2)
{
   int res;

   STP_ASSERT(v1 && v2);

   if((MSTP_BRIDGE_ID_EQUAL(v1->rgnRootID, v2->rgnRootID))
      &&
      (v1->intRootPathCost == v2->intRootPathCost)
      &&
      (MSTP_BRIDGE_ID_EQUAL(v1->dsnBridgeID, v2->dsnBridgeID))
      &&
      (v1->dsnPortID == v2->dsnPortID))
   {/* the first priority vector is the same as the second one */
      res = 0;
   }
   else
   if((MSTP_BRIDGE_ID_LOWER(v1->rgnRootID, v2->rgnRootID))
      ||
      (MSTP_BRIDGE_ID_EQUAL(v1->rgnRootID, v2->rgnRootID) &&
       (v1->intRootPathCost < v2->intRootPathCost))
      ||
      (MSTP_BRIDGE_ID_EQUAL(v1->rgnRootID, v2->rgnRootID) &&
       (v1->intRootPathCost == v2->intRootPathCost) &&
       (MSTP_BRIDGE_ID_LOWER(v1->dsnBridgeID, v2->dsnBridgeID)))
      ||
      (MSTP_BRIDGE_ID_EQUAL(v1->rgnRootID, v2->rgnRootID) &&
       (v1->intRootPathCost == v2->intRootPathCost) &&
       (MSTP_BRIDGE_ID_EQUAL(v1->dsnBridgeID, v2->dsnBridgeID)) &&
       (v1->dsnPortID < v2->dsnPortID)))
   {/* the first priority vector is better than the second one */
      res = -1;
   }
   else
   {/* the first priority vector is worse than the second one */
      res = 1;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_findMstiCfgMsgInBpdu
 *
 * Purpose:   In the received BPDU search for the location of the MSTI
 *            Configuration Message for the given MSTI.
 *
 * Params:    bpdu  -> pointer to the packet buffer with BPDU in
 *            mstid -> MST Instance Identifier
 *
 * Returns:   returns pointer to the location of the MSTI Configuration
 *            Message if found, NULL otherwise.
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
static MSTP_MSTI_CONFIG_MSG_t *
mstp_findMstiCfgMsgInBpdu(MSTP_RX_PDU *pkt, MSTID_t mstid)
{
   MSTP_MST_BPDU_t        *bpdu          = NULL;
   MSTP_MSTI_CONFIG_MSG_t *mstiCfgMsgPtr = NULL;
   char                   *end           = NULL;
   int                     len           = NULL;
   MSTID_t                 sysid         = NULL;
   bool                   found         = FALSE;

   STP_ASSERT(pkt);
   STP_ASSERT(MSTP_VALID_MSTID(mstid));

   /*------------------------------------------------------------------------
    * sanity checks
    *------------------------------------------------------------------------*/
   if(mstp_isMstBpdu(pkt) == FALSE)
   {/* wrong BPDU type */
      STP_ASSERT(0);
      return NULL;
   }

   bpdu = (MSTP_MST_BPDU_t *)(pkt->data);
   len  = MSTP_MSTI_CFG_MSGS_SIZE(bpdu);
   if(len == 0)
   {
      STP_ASSERT(0);
      return NULL;
   }

   STP_ASSERT(len/sizeof(MSTP_MSTI_CONFIG_MSG_t) <= 64);

   mstiCfgMsgPtr = (MSTP_MSTI_CONFIG_MSG_t *) bpdu->mstiConfigMsgs;
   end           = (char*)mstiCfgMsgPtr + len;

   /*------------------------------------------------------------------------
    * do search
    *------------------------------------------------------------------------*/
   while((char*)mstiCfgMsgPtr < end)
   {
      sysid = MSTP_GET_BRIDGE_SYS_ID_FROM_PKT(mstiCfgMsgPtr->mstiRgnRootId);
      if(sysid == mstid)
      {
         found = TRUE;
         break;
      }

      mstiCfgMsgPtr++;
   }

   return found ? mstiCfgMsgPtr : NULL;
}

/**PROC+**********************************************************************
 * Name:      mstp_isStpConfigBpdu
 *
 * Purpose:   Examine passed in packet buffer whether it contains valid
 *            Configuration BPDU
 *            (802.1Q-REV/D5.0 14.4 a))
 *
 * Params:    pkt -> pointer to the packet buffer
 *
 * Returns:   TRUE if valid Configuration BPDU is found in the packet buffer,
 *            FALSE otherwise
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_isStpConfigBpdu(MSTP_RX_PDU *pkt)
{
   MSTP_CFG_BPDU_t *bpdu;
   uint32_t         length = 0;
   bool             res = FALSE;

   STP_ASSERT(pkt);

   bpdu   = (MSTP_CFG_BPDU_t *)(pkt->data);
   length = MSTP_BPDU_LENGTH(bpdu);

   /* NOTE: Added check for the 'Protocol Version Identifier' to match the
    *           logic of 'mstp_updtBPDUVersion' routine that treats a TCN or
    *           Config BPDU as being 'STP' type only if version is '0' or '1',
    *           as the standard determines. */
   if((bpdu->protocolId == MSTP_STP_RST_MST_PROTOCOL_ID) &&
      (bpdu->protocolVersionId < MSTP_PROTOCOL_VERSION_ID_RST) &&
      (bpdu->bpduType == MSTP_BPDU_TYPE_STP_CONFIG) &&
      (length >= MSTP_STP_CONFIG_BPDU_LEN_MIN))
   {
      res = TRUE;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_isStpTcnBpdu
 *
 * Purpose:   Examine passed in packet buffer whether it contains valid
 *            Topology Change Notification BPDU
 *            (802.1Q-REV/D5.0 14.4 b) )
 *
 * Params:    pkt -> pointer to the packet buffer
 *
 * Returns:   TRUE if valid TCN BPDU is found in the packet buffer,
 *            FALSE otherwise
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_isStpTcnBpdu(MSTP_RX_PDU *pkt)
{
   MSTP_TCN_BPDU_t *bpdu;
   uint32_t         length = 0;
   bool             res = FALSE;

   STP_ASSERT(pkt);

   bpdu   = (MSTP_TCN_BPDU_t *)(pkt->data);
   length = MSTP_BPDU_LENGTH(bpdu);

   /* NOTE: Added check for the 'Protocol Version Identifier' to match the
    *           logic of 'mstp_updtBPDUVersion' routine that treats a TCN or
    *           Config BPDU as being 'STP' type only if version is '0' or '1',
    *           as the standard determines. */
   if((bpdu->protocolId == MSTP_STP_RST_MST_PROTOCOL_ID) &&
      (bpdu->protocolVersionId < MSTP_PROTOCOL_VERSION_ID_RST) &&
      (bpdu->bpduType == MSTP_BPDU_TYPE_STP_TCN) &&
      (length >= MSTP_STP_TCN_BPDU_LEN_MIN))
   {
      res = TRUE;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_isRstBpdu
 *
 * Purpose:   Examine passed in packet buffer whether it contains valid
 *            RST BPDU
 *            (802.1Q-REV/5.0 14.4 c)-d))
 *
 * Params:    pkt -> pointer to the packet buffer
 *
 * Returns:   TRUE if valid RST BPDU is found in the packet buffer,
 *            FALSE otherwise
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_isRstBpdu(MSTP_RX_PDU *pkt)
{
   MSTP_RST_BPDU_t *bpdu;
   bool             res = FALSE;

   STP_ASSERT(pkt);

   bpdu = (MSTP_RST_BPDU_t *)(pkt->data);
   if(bpdu->protocolId == MSTP_STP_RST_MST_PROTOCOL_ID)
   {/* A Spanning Tree Packet */
      uint32_t length = 0 ;// MSTP_BPDU_LENGTH(bpdu);

      if(bpdu->protocolVersionId == MSTP_PROTOCOL_VERSION_ID_RST)
      {/* RSTP packet */
         if((bpdu->bpduType == MSTP_BPDU_TYPE_RST) &&
            (length >= MSTP_RST_BPDU_LEN_MIN))
         {/* meet test case 14.4 c) */
            res = TRUE;
         }
      }
      else if(bpdu->protocolVersionId >= MSTP_PROTOCOL_VERSION_ID_MST)
      {/* MSTP or future version of Spanning Tree */
         if(bpdu->bpduType == MSTP_BPDU_TYPE_MST)
         {
            MSTP_MST_BPDU_t *mst_bpdu = (MSTP_MST_BPDU_t *)bpdu;

            if((length >= MSTP_STP_CONFIG_BPDU_LEN_MIN) &&
               (length <= MSTP_MST_BPDU_LEN_MIN))
            {
               res = TRUE;    /* meet case 14.4 d)-1) */
            }
            else if(mst_bpdu->version1Length != 0)
            {
               res = TRUE;    /* meet case 14.4 d)-2) */
            }
            else
            {
               int mstiMsgsNum =
                  MSTP_MSTI_CFG_MSGS_SIZE(mst_bpdu)/sizeof(MSTP_MSTI_CONFIG_MSG_t);

               if(!(mstiMsgsNum >= 0 && mstiMsgsNum <= 64))
                  res = TRUE; /* meet case 14.4 d)-3) */
            }
         }
      }
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_isMstBpdu
 *
 * Purpose:   Examine passed in packet buffer whether it contains valid
 *            MST BPDU
 *            (802.1Q-REV/D5.0 14.4 e))
 *
 * Params:    pkt -> pointer to the packet buffer
 *
 * Returns:   TRUE if valid MST BPDU is found in the packet buffer,
 *            FALSE otherwise
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_isMstBpdu(MSTP_RX_PDU *pkt)
{
   MSTP_MST_BPDU_t *bpdu;
   uint32_t         length = 0;
   bool             res = FALSE;

   STP_ASSERT(pkt);
   bpdu   = (MSTP_MST_BPDU_t *)(pkt->data);
   length = MSTP_BPDU_LENGTH(bpdu);

   if((bpdu->protocolId == MSTP_STP_RST_MST_PROTOCOL_ID) &&
      (bpdu->protocolVersionId >= MSTP_PROTOCOL_VERSION_ID_MST) &&
      (bpdu->bpduType == MSTP_BPDU_TYPE_MST) &&
      (length >= MSTP_MST_BPDU_LEN_MIN) &&
      (bpdu->version1Length == 0))
   {
      int mstiMsgsNum;

      mstiMsgsNum = (ntohs(bpdu->version3Length) - 64)/
          sizeof(MSTP_MSTI_CONFIG_MSG_t);
      if(mstiMsgsNum >= 0 && mstiMsgsNum <= 64)
         res = TRUE;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_isSelfSentPkt
 *
 * Purpose:   Perform the check if the packet was received as a result of an
 *            'external' loop condition (i.e. packet relayed through the port
 *            is looping back on the port).
 *
 * Params:    pkt -> pointer to the packet buffer
 *
 * Returns:   TRUE if received packet is self sent packet, FALSE otherwise
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
static bool
mstp_isSelfSentPkt(MSTP_RX_PDU *pkt)
{
    bool res = FALSE;
   ENET_HDR    *enetHdr;  /* pointer to start of ethernet header */
   LPORT_t      lport;    /* logical port pkt arrived on */
   const char *my_mac = NULL;
   MAC_ADDRESS  portSrc;  /* port's own source MAC address */
   MAC_ADDRESS *src_mac = NULL;

   STP_ASSERT(pkt);
   lport = GET_PKT_LOGICAL_PORT(pkt);
   /* Get the logical port's source MAC address */
   my_mac = intf_get_mac_addr(lport);
   sscanf(my_mac,"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",&portSrc[0],&portSrc[1],&portSrc[2],&portSrc[3],&portSrc[4],&portSrc[5]);
   src_mac = (MAC_ADDRESS *)pkt->data + ENET_ADDR_SIZE;
   res = MAC_ADDRS_EQUAL(src_mac,portSrc);

   /* Extract ethernet header from the received frame */
   enetHdr = (ENET_HDR *)(pkt->data);
   /* Compare source MAC addresses */
   res = MAC_ADDRS_EQUAL(enetHdr->src, portSrc);

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_getBpduType
 *
 * Purpose:   Identify type of the received BPDU
 *
 * Params:    pkt -> pointer to the packet buffer with BPDU in
 *            NOTE: the order of BPDU type verification is important as
 *                      the rules defined in 802.1Q-REV/D5.0 14.4 d) case 1
 *                      and 14.4 e) case 1 overlap, that may cause MST BPDU
 *                      be identified as RST BPDU if MST BPDU does not
 *                      carry optional MSTI Configuration Messages. So we
 *                      do a check first for MST BPDU type and only if it
 *                      fails we do a check for RST BPDU type.
 *
 * Returns:   one of the following:
 *            'MSTP_BPDU_TYPE_MSTP'    if MST BPDU or
 *            'MSTP_BPDU_TYPE_RSTP'    if RST BPDU or
 *            'MSTP_BPDU_TYPE_STP'     if STP Configuration BPDU or
 *            'MSTP_BPDU_TYPE_TCN'     if STP TCN BPDU or
 *            'MSTP_BPDU_TYPE_UNKNOWN' if none of the above
 *
 * Globals:   none
 *
 * Constraints:
 **PROC-**********************************************************************/
MSTP_BPDU_TYPE_t
mstp_getBpduType(MSTP_RX_PDU *pkt)
{
   MSTP_BPDU_TYPE_t bpduType;

   STP_ASSERT(pkt);

   if(mstp_isMstBpdu(pkt))
      bpduType = MSTP_BPDU_TYPE_MSTP;
   else if(mstp_isRstBpdu(pkt))
      bpduType = MSTP_BPDU_TYPE_RSTP;
   else if(mstp_isStpConfigBpdu(pkt))
      bpduType = MSTP_BPDU_TYPE_STP;
   else if(mstp_isStpTcnBpdu(pkt))
      bpduType = MSTP_BPDU_TYPE_TCN;
   else
      bpduType = MSTP_BPDU_TYPE_UNKNOWN;

   return bpduType;
}

/*===========================================================================
 * Miscellaneous functions used to provide detail information about MSTP
 * ports dynamic variables (these functions currently called from 'browse.cc'
 * only).
 *===========================================================================*/

/**PROC+**********************************************************************
 * Name:      mstp_validRootHistoryEntry
 *
 * Purpose:   Check if requested entry in a Root Changes History table is
 *            valid.
 *            NOTE: There are 3 different kinds of Root may exist in MSTP
 *                  environment:
 *                  - Common Spanning Tree Root
 *                  - Internal Spanning Regional Root
 *                  - MST Instance Regional Root
 *                  For each case we maintain a separate Root Changes History
 *                  table
 *
 * Params:    mstid     -> MSTI Identifier (the CIST or an MSTI)
 *            treeType  -> type of the Spanning Tree (CST, IST or MSTI)
 *            idx       -> entry index in the table to lookup
 *
 * Returns:   TRUE if requested entry contains valid information,
 *            FALSE otherwise
 *
 * Globals:   mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
bool
mstp_validRootHistoryEntry(MSTID_t mstid, MSTP_TREE_TYPE_t treeType,
                           uint32_t idx)
{
   bool valid = FALSE;

   if(!MSTP_ENABLED)
      return FALSE;


   if(MSTP_INSTANCE_IS_VALID(mstid) && (idx < MSTP_ROOT_HISTORY_MAX))
   {
      switch(treeType)
      {
         case MSTP_TREE_TYPE_CST:
            STP_ASSERT(mstid == MSTP_CISTID);
            valid = MSTP_CIST_INFO.cstRootHistory[idx].valid;
         break;
         case MSTP_TREE_TYPE_IST:
            STP_ASSERT(mstid == MSTP_CISTID);
            valid = MSTP_CIST_INFO.istRgnRootHistory[idx].valid;
         break;
         case MSTP_TREE_TYPE_MST:
            STP_ASSERT(mstid != MSTP_CISTID);
            valid = MSTP_MSTI_INFO(mstid)->mstiRgnRootHistory[idx].valid ;
         break;
         default:
            STP_ASSERT(0);
         break;
      }
   }

   return valid;
}

/**PROC+**********************************************************************
 * Name:      mstp_getRootHistoryEntry
 *
 * Purpose:   Read an entry from the Root Changes History table
 *
 * Params:    mstid     -> MSTI Identifier (the CIST or an MSTI)
 *            treeType  -> type of the Spanning Tree (CST, IST or MSTI)
 *            idx       -> entry index in the table to lookup
 *            mac_addr  -> Root's MAC Address to return
 *            priority  -> Root's Priority to return
 *            timeStamp -> time stamp of the last entry update to return
 *
 * Returns:   TRUE if requested entry was found and contains valid information,
 *            FALSE otherwise. Fills caller's provided place holders with the
 *            data from the valid entry
 *
 * Globals:   mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
bool
mstp_getRootHistoryEntry(MSTID_t mstid, MSTP_TREE_TYPE_t treeType, uint32_t idx,
                         MAC_ADDRESS mac_addr, uint16_t *priority,
                         time_t *timeStamp)
{
   bool               found = FALSE;
   MSTP_ROOT_HISTORY_t rootEntry;

   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(idx < MSTP_ROOT_HISTORY_MAX);
   STP_ASSERT(mac_addr && priority && timeStamp);

   if(!MSTP_ENABLED || !MSTP_INSTANCE_IS_VALID(mstid))
      return 0;

   if(mstp_validRootHistoryEntry(mstid, treeType, idx))
   {
      found = TRUE;
      switch(treeType)
      {
         case MSTP_TREE_TYPE_CST:
            rootEntry = MSTP_CIST_INFO.cstRootHistory[idx];
         break;
         case MSTP_TREE_TYPE_IST:
            rootEntry = MSTP_CIST_INFO.istRgnRootHistory[idx];
         break;
         case MSTP_TREE_TYPE_MST:
            rootEntry = MSTP_MSTI_INFO(mstid)->mstiRgnRootHistory[idx];
         break;
         default:
            STP_ASSERT(0);
         break;
      }
   }


   if(found)
   {
      MAC_ADDR_COPY(rootEntry.rootID.mac_address, mac_addr);
      *priority = MSTP_GET_BRIDGE_PRIORITY(rootEntry.rootID);
      *timeStamp = rootEntry.timeStamp;
   }

   return found;
}

/**PROC+**********************************************************************
 * Name:      mstp_rootChangesCounter
 *
 * Purpose:   Read the value of Root Changes Counter for the given tree
 *
 * Params:    none
 *
 * Returns:   the Root Changes Counter value for the given tree
 *
 * Globals:   mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_rootChangesCounter(MSTID_t mstid, MSTP_TREE_TYPE_t treeType)
{
   uint32_t rootChangeCnt = 0;

   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));

   if(!MSTP_ENABLED || !MSTP_INSTANCE_IS_VALID(mstid))
      return 0;


   if(mstid == MSTP_CISTID)
   {
      if(treeType == MSTP_TREE_TYPE_CST)
         rootChangeCnt = MSTP_CIST_INFO.cstRootChangeCnt;
      else
      if(treeType == MSTP_TREE_TYPE_IST)
         rootChangeCnt = MSTP_CIST_INFO.istRgnRootChangeCnt;
      else
         STP_ASSERT(0);
   }
   else
   {
      STP_ASSERT(treeType == MSTP_TREE_TYPE_MST);
      rootChangeCnt = MSTP_MSTI_INFO(mstid)->mstiRgnRootChangeCnt;
   }

   return rootChangeCnt;
}

/**PROC+**********************************************************************
 * Name:      mstp_clrMstiPortDbgCntInfo
 *
 * Purpose:   Clear (reset to zero) all debug counters maintained on the
 *            specified port for the given Instance of Spanning Tree
 *            (the CIST or an MSTI)
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            pmap  -> pointer to the map of lports
 *
 * Returns:   none
 *
 * Globals:   mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
void
mstp_clrMstiPortDbgCntInfo(MSTID_t mstid, LPORT_t lport)
{
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));

   if(!MSTP_ENABLED || !MSTP_INSTANCE_IS_VALID(mstid))
      return;


   /*------------------------------------------------------------------------
    * Clear CIST/MSTI port's Debug Counter Information
    *------------------------------------------------------------------------*/
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      if(cistPortPtr)
         memset(&cistPortPtr->dbgCnts, 0, sizeof(cistPortPtr->dbgCnts));
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      if(mstiPortPtr)
         memset(&mstiPortPtr->dbgCnts, 0, sizeof(mstiPortPtr->dbgCnts));
   }

}

/**PROC+**********************************************************************
 * Name:      mstp_clrMstiDbgCntsInfo
 *
 * Purpose:   Clear (reset to zero) all debug counters maintained for the
 *            specified Instance of Spanning Tree (the CIST or an MSTI).
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *
 * Returns:   none
 *
 * Globals:   mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
void
mstp_clrMstiDbgCntsInfo(MSTID_t mstid)
{
   LPORT_t lport;

   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));

   if(!MSTP_ENABLED || !MSTP_INSTANCE_IS_VALID(mstid))
      return;

   /*------------------------------------------------------------------------
    * Clear the CIST's/MSTI's Debug Information maintained on a per-port basis
    *------------------------------------------------------------------------*/
   for(lport = 1; lport <= MAX_LPORTS; lport++)
   {
      if(MSTP_COMM_PORT_PTR(lport))
         mstp_clrMstiPortDbgCntInfo(mstid, lport);
   }

}

/**PROC+**********************************************************************
 * Name:      mstp_clrMstpBridgeDbgInfo
 *
 * Purpose:   Clear (reset to zero) all debug counters maintained for this
 *            MSTP Bridge.
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
mstp_clrMstpBridgeDbgInfo(void)
{
   MSTID_t mstid;

   if(!MSTP_ENABLED)
      return;

   /*------------------------------------------------------------------------
    * Clear Debug Information maintained for all Spanning Tree Instances
    * (the CIST and all MSTIs)
    *------------------------------------------------------------------------*/
   mstp_clrMstiDbgCntsInfo(MSTP_CISTID);
   for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
   {
      if(MSTP_INSTANCE_IS_VALID(mstid))
         mstp_clrMstiDbgCntsInfo(mstid);
   }

}

/**PROC+**********************************************************************
 * Name:      mstp_getMstiPortDbgCntInfo
 *
 * Purpose:   Get the value of the specified debug counter maintained for
 *            the given port for the given Instance of Spanning Tree
 *            (the CIST or an MSTI), supply counter's time stamp information
 *            if requested.
 *            NOTE: this function reflects the current state of supported
 *                  debug information and is the subject for future changes
 *
 * Params:    mstid     -> Spanning Tree Instance Identifier (the CIST or an MSTI)
 *            lport     -> logical port number
 *            cntId     -> counter type to look for
 *            timeStamp -> optional place holder for the counter's time stamp
 *                         to be return
 *
 * Returns:   the debug counter value and optionally counter's time stamp
 *
 * Globals:   mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_getMstiPortDbgCntInfo(MSTID_t mstid, LPORT_t lport,
                           uint32_t cntId, time_t *timeStamp)
{
   uint32_t value = 0;

   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));

   if(!MSTP_ENABLED || !MSTP_INSTANCE_IS_VALID(mstid))
      return 0;


   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = NULL;

      if((cistPortPtr = MSTP_CIST_PORT_PTR(lport)))
      {
         switch(cntId)
         {
            case MSTP_CIST_DBG_CNT_INVALID_BPDUS:
               value = cistPortPtr->dbgCnts.invalidBpduCnt;
               if(timeStamp)
                  *timeStamp = cistPortPtr->dbgCnts.invalidBpduCntLastUpdated;
               break;
            case MSTP_CIST_DBG_CNT_ERRANT_BPDUS:
               value = cistPortPtr->dbgCnts.errantBpduCnt;
               if(timeStamp)
                  *timeStamp = cistPortPtr->dbgCnts.errantBpduCntLastUpdated;
               break;
            case MSTP_CIST_DBG_CNT_MST_CFG_ERROR_BPDUS:
               value = cistPortPtr->dbgCnts.mstCfgErrorBpduCnt;
               if(timeStamp)
                  *timeStamp = cistPortPtr->dbgCnts.mstCfgErrorBpduCntLastUpdated;
               break;
            case MSTP_CIST_DBG_CNT_LOOPED_BACK_BPDUS:
               value = cistPortPtr->dbgCnts.loopBackBpduCnt;
               if(timeStamp)
                  *timeStamp = cistPortPtr->dbgCnts.loopBackBpduCntLastUpdated;
               break;
            case MSTP_CIST_DBG_CNT_STARVED_BPDUS:
               value = cistPortPtr->dbgCnts.starvedBpduCnt;
               if(timeStamp)
                  *timeStamp = cistPortPtr->dbgCnts.starvedBpduCntLastUpdated;
               break;
            case MSTP_CIST_DBG_CNT_EXCEEDED_MAX_AGE_BPDUS:
               value = cistPortPtr->dbgCnts.agedBpduCnt;
               if(timeStamp)
                  *timeStamp = cistPortPtr->dbgCnts.agedBpduCntLastUpdated;
               break;
            case MSTP_CIST_DBG_CNT_EXCEEDED_MAX_HOPS_BPDUS:
               value = cistPortPtr->dbgCnts.exceededHopsBpduCnt;
               if(timeStamp)
                  *timeStamp = cistPortPtr->dbgCnts.exceededHopsBpduCntLastUpdated;
               break;
            case MSTP_CIST_DBG_CNT_TC_DETECTED:
               value = cistPortPtr->dbgCnts.tcDetectCnt;
               if(timeStamp)
                  *timeStamp = cistPortPtr->dbgCnts.tcDetectCntLastUpdated;
               break;
            case MSTP_CIST_DBG_CNT_TC_FLAGS_TX:
               value = cistPortPtr->dbgCnts.tcFlagTxCnt;
               if(timeStamp)
                  *timeStamp = cistPortPtr->dbgCnts.tcFlagTxCntLastUpdated;
               break;
            case MSTP_CIST_DBG_CNT_TC_FLAGS_RX:
               value = cistPortPtr->dbgCnts.tcFlagRxCnt;
               if(timeStamp)
                  *timeStamp = cistPortPtr->dbgCnts.tcFlagRxCntLastUpdated;
               break;
            case MSTP_CIST_DBG_CNT_TC_ACK_FLAGS_TX:
               value = cistPortPtr->dbgCnts.tcAckFlagTxCnt;
               if(timeStamp)
                  *timeStamp = cistPortPtr->dbgCnts.tcAckFlagTxCntLastUpdated;
               break;
            case MSTP_CIST_DBG_CNT_TC_ACK_FLAGS_RX:
               value = cistPortPtr->dbgCnts.tcAckFlagRxCnt;
               if(timeStamp)
                  *timeStamp = cistPortPtr->dbgCnts.tcAckFlagRxCntLastUpdated;
               break;
            case MSTP_CIST_DBG_CNT_MST_BPDUS_TX:
               value = cistPortPtr->dbgCnts.mstBpduTxCnt;
               if(timeStamp)
                  *timeStamp = cistPortPtr->dbgCnts.mstBpduTxCntLastUpdated;
               break;
            case MSTP_CIST_DBG_CNT_MST_BPDUS_RX:
               value = cistPortPtr->dbgCnts.mstBpduRxCnt;
               if(timeStamp)
                  *timeStamp = cistPortPtr->dbgCnts.mstBpduRxCntLastUpdated;
               break;
            case MSTP_CIST_DBG_CNT_RST_BPDUS_TX:
               value = cistPortPtr->dbgCnts.rstBpduTxCnt;
               if(timeStamp)
                  *timeStamp = cistPortPtr->dbgCnts.rstBpduTxCntLastUpdated;
               break;
            case MSTP_CIST_DBG_CNT_RST_BPDUS_RX:
               value = cistPortPtr->dbgCnts.rstBpduRxCnt;
               if(timeStamp)
                  *timeStamp = cistPortPtr->dbgCnts.rstBpduRxCntLastUpdated;
               break;
            case MSTP_CIST_DBG_CNT_CFG_BPDUS_TX:
               value = cistPortPtr->dbgCnts.cfgBpduTxCnt;
               if(timeStamp)
                  *timeStamp = cistPortPtr->dbgCnts.cfgBpduTxCntLastUpdated;
               break;
            case MSTP_CIST_DBG_CNT_CFG_BPDUS_RX:
               value = cistPortPtr->dbgCnts.cfgBpduRxCnt;
               if(timeStamp)
                  *timeStamp = cistPortPtr->dbgCnts.cfgBpduRxCntLastUpdated;
               break;
            case MSTP_CIST_DBG_CNT_TCN_BPDUS_TX:
               value = cistPortPtr->dbgCnts.tcnBpduTxCnt;
               if(timeStamp)
                  *timeStamp = cistPortPtr->dbgCnts.tcnBpduTxCntLastUpdated;
               break;
            case MSTP_CIST_DBG_CNT_TCN_BPDUS_RX:
               value = cistPortPtr->dbgCnts.tcnBpduRxCnt;
               if(timeStamp)
                  *timeStamp = cistPortPtr->dbgCnts.tcnBpduRxCntLastUpdated;
               break;
            default:
               STP_ASSERT(0);
               break;
         }
      }
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = NULL;

      if((mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport)))
      {
         switch(cntId)
         {
            case MSTP_MSTI_DBG_CNT_STARVED_MSTI_MSGS:
               value = mstiPortPtr->dbgCnts.starvedMsgCnt;
               if(timeStamp)
                  *timeStamp = mstiPortPtr->dbgCnts.starvedMsgCntLastUpdated;
               break;
            case MSTP_MSTI_DBG_CNT_EXCEEDED_MAX_HOPS_MSTI_MSGS:
               value = mstiPortPtr->dbgCnts.exceededHopsMsgCnt;
               if(timeStamp)
               {
                  *timeStamp =
                     mstiPortPtr->dbgCnts.exceededHopsMsgCntLastUpdated;
               }
               break;
            case MSTP_MSTI_DBG_CNT_TC_DETECTED:
               value = mstiPortPtr->dbgCnts.tcDetectCnt;
               if(timeStamp)
                  *timeStamp = mstiPortPtr->dbgCnts.tcDetectCntLastUpdated;
               break;
            case MSTP_MSTI_DBG_CNT_TC_FLAGS_TX:
               value = mstiPortPtr->dbgCnts.tcFlagTxCnt;
               if(timeStamp)
                  *timeStamp = mstiPortPtr->dbgCnts.tcFlagTxCntLastUpdated;
               break;
            case MSTP_MSTI_DBG_CNT_TC_FLAGS_RX:
               value = mstiPortPtr->dbgCnts.tcFlagRxCnt;
               if(timeStamp)
                  *timeStamp = mstiPortPtr->dbgCnts.tcFlagRxCntLastUpdated;
               break;
            case MSTP_MSTI_DBG_CNT_MSTI_MSGS_TX:
               value = mstiPortPtr->dbgCnts.mstiMsgTxCnt;
               if(timeStamp)
                  *timeStamp = mstiPortPtr->dbgCnts.mstiMsgTxCntLastUpdated;
               break;
            case MSTP_MSTI_DBG_CNT_MSTI_MSGS_RX:
               value = mstiPortPtr->dbgCnts.mstiMsgRxCnt;
               if(timeStamp)
                  *timeStamp = mstiPortPtr->dbgCnts.mstiMsgRxCntLastUpdated;
               break;
            default:
               STP_ASSERT(0);
               break;
         }
      }
   }

   return value;
}

/**PROC+**********************************************************************
 * Name:      mstp_getMstiPortsDbgCntInfo
 *
 * Purpose:   For the given debug counter's calculate the aggregated value
 *            collected from all ports for a given Instance of Spanning Tree
 *            (the CIST or an MSTI)
 *
 * Params:    mstid -> MST Instance Identifier (the CIST or an MSTI)
 *            cntId -> debug counter identifier to look for
 *
 * Returns:   the debug counter's (aggregate) value
 *
 * Globals:   mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
static uint32_t
mstp_getMstiPortsDbgCntInfo(MSTID_t mstid, uint32_t cntId)
{
   LPORT_t                lport       = 0;
   uint32_t               value       = 0;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));

   if(!MSTP_ENABLED || !MSTP_INSTANCE_IS_VALID(mstid))
      return 0;


   /*------------------------------------------------------------------------
    * Collect debug counter information from all ports for the given Spanning
    * Tree Instance
    *------------------------------------------------------------------------*/
   STP_ASSERT(MSTP_INSTANCE_IS_VALID(mstid));
   for(lport = 1; lport <= MAX_LPORTS; lport++)
   {
      if(MSTP_COMM_PORT_PTR(lport))
         value += mstp_getMstiPortDbgCntInfo(mstid, lport, cntId, NULL);
   }


   return value;
}

/**PROC+**********************************************************************
 * Name:      mstp_getMstiDbgCntInfo
 *
 * Purpose:   Obtain a value for the specified debug counter maintained
 *            for the given Instance of Spanning Tree.
 *            NOTE: Depending on counter type the return value may represent
 *                  an aggregate value collected from different locations.
 *            NOTE1: So far we maintain MSTI's debug counters only on a
 *                   per-tree/per-port basis.
 *
 * Params:    cntId -> debug counter identifier to look for
 *
 * Returns:   current value for the requested type of debug information
 *
 * Globals:   mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_getMstiDbgCntInfo(MSTID_t mstid, uint32_t cntId)
{
   uint32_t value = 0;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));

   if(!MSTP_ENABLED || !MSTP_INSTANCE_IS_VALID(mstid))
      return 0;

   /*------------------------------------------------------------------------
    * Get the CIST's or an MSTI's Ports Debug Counter Information
    *------------------------------------------------------------------------*/
   value = mstp_getMstiPortsDbgCntInfo(mstid, cntId);

   return value;
}

/**PROC+**********************************************************************
 * Name:      mstp_getMstpBridgeDbgCntInfo
 *
 * Purpose:   Obtain a value for the specified debug counter maintained
 *            for this MSTP Bridge.
 *            NOTE:  Depending on counter type the return value may represent
 *                   an aggregate value collected from different locations.
 *            NOTE1: So far we maintain MSTP Bridge debug counters only on a
 *                   per-tree/per-port basis.
 *            NOTE2: this function reflects the current state of supported
 *                   debug information and is the subject for future changes
 *
 * Params:    cntId -> debug counter identifier to look for
 *
 * Returns:   current value for the requested type of debug information
 *
 * Globals:   mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_getMstpBridgeDbgCntInfo(uint32_t cntId)
{
   MSTID_t mstid = MSTP_NO_MSTID;
   uint32_t value = 0;

   STP_ASSERT((cntId > 0) && (cntId < MSTP_BRIDGE_DBG_CNT_TYPE_MAX));

   if(!MSTP_ENABLED)
      return 0;


   /*------------------------------------------------------------------------
    * Get Debug Counter Information in a way specific to the counter type
    *------------------------------------------------------------------------*/
   switch(cntId)
   {
      case MSTP_BRIDGE_DBG_CNT_INVALID_BPDUS:
         value = mstp_getMstiPortsDbgCntInfo(MSTP_CISTID,
                                              MSTP_CIST_DBG_CNT_INVALID_BPDUS);
         break;
      case MSTP_BRIDGE_DBG_CNT_ERRANT_BPDUS:
         value = mstp_getMstiPortsDbgCntInfo(MSTP_CISTID,
                                               MSTP_CIST_DBG_CNT_ERRANT_BPDUS);
         break;
      case MSTP_BRIDGE_DBG_CNT_MST_CFG_ERROR_BPDUS:
         value = mstp_getMstiPortsDbgCntInfo(MSTP_CISTID,
                                        MSTP_CIST_DBG_CNT_MST_CFG_ERROR_BPDUS);
         break;
      case MSTP_BRIDGE_DBG_CNT_LOOPED_BACK_BPDUS:
         value = mstp_getMstiPortsDbgCntInfo(MSTP_CISTID,
                                          MSTP_CIST_DBG_CNT_LOOPED_BACK_BPDUS);
         break;
      case MSTP_BRIDGE_DBG_CNT_STARVED_BPDUS_MSTI_MSGS:
         value = mstp_getMstiPortsDbgCntInfo(MSTP_CISTID,
                                              MSTP_CIST_DBG_CNT_STARVED_BPDUS);
         for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
         {
            if(MSTP_MSTI_VALID(mstid))
               value += mstp_getMstiPortsDbgCntInfo(mstid,
                                          MSTP_MSTI_DBG_CNT_STARVED_MSTI_MSGS);
         }
         break;
      case MSTP_BRIDGE_DBG_CNT_EXCEEDED_MAX_AGE_BPDUS:
         value = mstp_getMstiPortsDbgCntInfo(MSTP_CISTID,
                                     MSTP_CIST_DBG_CNT_EXCEEDED_MAX_AGE_BPDUS);
         break;
      case MSTP_BRIDGE_DBG_CNT_EXCEEDED_MAX_HOPS_BPDUS_MSTI_MSGS:
         value = mstp_getMstiPortsDbgCntInfo(MSTP_CISTID,
                                    MSTP_CIST_DBG_CNT_EXCEEDED_MAX_HOPS_BPDUS);
         for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
         {
            if(MSTP_MSTI_VALID(mstid))
               value += mstp_getMstiPortsDbgCntInfo(mstid,
                                MSTP_MSTI_DBG_CNT_EXCEEDED_MAX_HOPS_MSTI_MSGS);
         }
         break;
      case MSTP_BRIDGE_DBG_CNT_TC_DETECTED:
         value = mstp_getMstiPortsDbgCntInfo(MSTP_CISTID,
                                                MSTP_CIST_DBG_CNT_TC_DETECTED);
         for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
         {
            if(MSTP_MSTI_VALID(mstid))
               value += mstp_getMstiPortsDbgCntInfo(mstid,
                                                MSTP_MSTI_DBG_CNT_TC_DETECTED);
         }
         break;
      case MSTP_BRIDGE_DBG_CNT_TC_FLAGS_TX:
         value = mstp_getMstiPortsDbgCntInfo(MSTP_CISTID,
                                                MSTP_CIST_DBG_CNT_TC_FLAGS_TX);
         for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
         {
            if(MSTP_MSTI_VALID(mstid))
               value += mstp_getMstiPortsDbgCntInfo(mstid,
                                                MSTP_MSTI_DBG_CNT_TC_FLAGS_TX);
         }
         break;
      case MSTP_BRIDGE_DBG_CNT_TC_FLAGS_RX:
         value = mstp_getMstiPortsDbgCntInfo(MSTP_CISTID,
                                                MSTP_CIST_DBG_CNT_TC_FLAGS_RX);
         for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
         {
            if(MSTP_MSTI_VALID(mstid))
               value += mstp_getMstiPortsDbgCntInfo(mstid,
                                                MSTP_MSTI_DBG_CNT_TC_FLAGS_RX);
         }
         break;
      case MSTP_BRIDGE_DBG_CNT_TC_ACK_FLAGS_TX:
         value = mstp_getMstiPortsDbgCntInfo(MSTP_CISTID,
                                            MSTP_CIST_DBG_CNT_TC_ACK_FLAGS_TX);
         break;
      case MSTP_BRIDGE_DBG_CNT_TC_ACK_FLAGS_RX:
         value = mstp_getMstiPortsDbgCntInfo(MSTP_CISTID,
                                            MSTP_CIST_DBG_CNT_TC_ACK_FLAGS_RX);
         break;
      case MSTP_BRIDGE_DBG_CNT_TCN_BPDUS_TX:
         value = mstp_getMstiPortsDbgCntInfo(MSTP_CISTID,
                                               MSTP_CIST_DBG_CNT_TCN_BPDUS_TX);
         break;
      case MSTP_BRIDGE_DBG_CNT_TCN_BPDUS_RX:
         value = mstp_getMstiPortsDbgCntInfo(MSTP_CISTID,
                                               MSTP_CIST_DBG_CNT_TCN_BPDUS_RX);
         break;
     case MSTP_BRIDGE_DBG_CNT_CFG_BPDUS_TX:
         value = mstp_getMstiPortsDbgCntInfo(MSTP_CISTID,
                                               MSTP_CIST_DBG_CNT_CFG_BPDUS_TX);
         break;
      case MSTP_BRIDGE_DBG_CNT_CFG_BPDUS_RX:
         value = mstp_getMstiPortsDbgCntInfo(MSTP_CISTID,
                                               MSTP_CIST_DBG_CNT_CFG_BPDUS_RX);
         break;
      case MSTP_BRIDGE_DBG_CNT_RST_BPDUS_TX:
         value = mstp_getMstiPortsDbgCntInfo(MSTP_CISTID,
                                               MSTP_CIST_DBG_CNT_RST_BPDUS_TX);
         break;
      case MSTP_BRIDGE_DBG_CNT_RST_BPDUS_RX:
         value = mstp_getMstiPortsDbgCntInfo(MSTP_CISTID,
                                               MSTP_CIST_DBG_CNT_RST_BPDUS_RX);
         break;
      case MSTP_BRIDGE_DBG_CNT_MST_BPDUS_MSTI_MSGS_TX:
         value = mstp_getMstiPortsDbgCntInfo(MSTP_CISTID,
                                               MSTP_CIST_DBG_CNT_MST_BPDUS_TX);
         for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
         {
            if(MSTP_MSTI_VALID(mstid))
               value += mstp_getMstiPortsDbgCntInfo(mstid,
                                               MSTP_MSTI_DBG_CNT_MSTI_MSGS_TX);
         }
         break;
      case MSTP_BRIDGE_DBG_CNT_MST_BPDUS_MSTI_MSGS_RX:
         value = mstp_getMstiPortsDbgCntInfo(MSTP_CISTID,
                                               MSTP_CIST_DBG_CNT_MST_BPDUS_RX);
         for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
         {
            if(MSTP_MSTI_VALID(mstid))
               value += mstp_getMstiPortsDbgCntInfo(mstid,
                                               MSTP_MSTI_DBG_CNT_MSTI_MSGS_RX);
         }
         break;
      default:
         STP_ASSERT(0);
         break;
   }

   return value;
}

/**PROC+**********************************************************************
 * Name:      mstp_DbgCntScope
 *
 * Purpose:   Given debug counter identifier determine the scope of debug
 *            information associated with this counter (e.g. whole Bridge,
 *            the CIST, all MSTIs, the CIST and all MSTIs, all Ports)
 *            NOTE: this function reflects the current state of supported
 *                  debug information and is the subject for future changes
 *
 * Params:    mstid -> integer representing an Instance of Spanning Tree
 *                     (the CIST or an MSTI) or whole Bridge (MSTP_NO_MSTID)
 *            cntId -> debug counter identifier
 *
 * Returns:   type of debug information associated with given counter
 *
 * Globals:   mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
MSTP_DBG_CNT_SCOPE_t
mstp_DbgCntScope(MSTID_t mstid, uint32_t cntId)
{
   uint32_t res = MSTP_DBG_CNT_SCOPE_UNKNOWN;

   if(mstid == MSTP_NO_MSTID)
   {
      switch(cntId)
      {
         /* CIST */
         case MSTP_BRIDGE_DBG_CNT_INVALID_BPDUS:
         case MSTP_BRIDGE_DBG_CNT_ERRANT_BPDUS:
         case MSTP_BRIDGE_DBG_CNT_MST_CFG_ERROR_BPDUS:
         case MSTP_BRIDGE_DBG_CNT_LOOPED_BACK_BPDUS:
         case MSTP_BRIDGE_DBG_CNT_EXCEEDED_MAX_AGE_BPDUS:
         case MSTP_BRIDGE_DBG_CNT_TC_ACK_FLAGS_TX:
         case MSTP_BRIDGE_DBG_CNT_TC_ACK_FLAGS_RX:
         case MSTP_BRIDGE_DBG_CNT_TCN_BPDUS_TX:
         case MSTP_BRIDGE_DBG_CNT_TCN_BPDUS_RX:
         case MSTP_BRIDGE_DBG_CNT_CFG_BPDUS_TX:
         case MSTP_BRIDGE_DBG_CNT_CFG_BPDUS_RX:
         case MSTP_BRIDGE_DBG_CNT_RST_BPDUS_TX:
         case MSTP_BRIDGE_DBG_CNT_RST_BPDUS_RX:
            res = MSTP_DBG_CNT_SCOPE_CIST;
             break;
         /* CIST/MSTIs */
         case MSTP_BRIDGE_DBG_CNT_STARVED_BPDUS_MSTI_MSGS:
         case MSTP_BRIDGE_DBG_CNT_EXCEEDED_MAX_HOPS_BPDUS_MSTI_MSGS:
         case MSTP_BRIDGE_DBG_CNT_TC_DETECTED:
         case MSTP_BRIDGE_DBG_CNT_TC_FLAGS_TX:
         case MSTP_BRIDGE_DBG_CNT_TC_FLAGS_RX:
         case MSTP_BRIDGE_DBG_CNT_MST_BPDUS_MSTI_MSGS_TX:
         case MSTP_BRIDGE_DBG_CNT_MST_BPDUS_MSTI_MSGS_RX:
            res = MSTP_DBG_CNT_SCOPE_CIST_MSTIS;
            break;
         default:
            STP_ASSERT(0);
            break;
       }
   }
   else
   {
      STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));

      /* Ports */
      res = MSTP_DBG_CNT_SCOPE_PORTS;
   }

   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_rootBridgeId
 *
 * Purpose:   Read ID of the Root Bridge currently known on this switch for
 *            the given tree
 *
 * Params:    mstid    -> MSTI Identifier (the CIST or an MSTI)
 *            treeType -> type of the Spanning Tree (CST, IST or MST)
 *            mac_addr -> place holder where to return the Mac Address of
 *                        the current Root Bridge
 *            priority -> place holder where to return the Priority value
 *                        of the current Root Bridge.
 *
 * Returns:   ID of the currently known Root Bridge for the tree
 *            (placed to 'mac_addr' and 'priority')
 *
 * Globals:   mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
void
mstp_rootBridgeId(MSTID_t mstid, MSTP_TREE_TYPE_t treeType,
                  MAC_ADDRESS mac_addr, uint16_t *priority)
{
   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(MSTP_INSTANCE_IS_VALID(mstid));
   STP_ASSERT(mac_addr && priority);

   memset(mac_addr, 0, sizeof(MAC_ADDRESS));
   *priority = 0;


   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_ROOT_PRI_VECTOR_t rootPriority = MSTP_CIST_ROOT_PRIORITY;

      if(treeType == MSTP_TREE_TYPE_CST)
      {
         MAC_ADDR_COPY(rootPriority.rootID.mac_address, mac_addr);
         *priority = MSTP_GET_BRIDGE_PRIORITY(rootPriority.rootID);
      }
      else
      if(treeType == MSTP_TREE_TYPE_IST)
      {
         MAC_ADDR_COPY(rootPriority.rgnRootID.mac_address, mac_addr);
         *priority = MSTP_GET_BRIDGE_PRIORITY(rootPriority.rgnRootID);
      }
      else
         STP_ASSERT(0);
   }
   else
   {
      MSTP_MSTI_ROOT_PRI_VECTOR_t rootPriority = MSTP_MSTI_ROOT_PRIORITY(mstid);

      STP_ASSERT(treeType == MSTP_TREE_TYPE_MST);
      MAC_ADDR_COPY(rootPriority.rgnRootID.mac_address, mac_addr);
      *priority = MSTP_GET_BRIDGE_PRIORITY(rootPriority.rgnRootID);
   }

}

/**PROC+**********************************************************************
 * Name:      mstp_portMstRgnBoundary
 *
 * Purpose:   Check whether 'lport' is located on the boundary of MST Region
 *            (by refering to the current value of 'rcvdInternal' port's
 *             variable).
 *            NOTE: 'rcvdInternal' variable set TRUE by the Port Receive State
 *                   Machine when the received BPDU was transmitted by a Bridge
 *                   in the same MST Region as the receiving Bridge and FALSE
 *                   otherwise.
 *
 * Params:    lport -> logical port number
 *
 * Returns:   TRUE if 'lport' is located on the boundary of MST Region,
 *            FALSE otherwise.
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
bool
mstp_portMstRgnBoundary(LPORT_t lport)
{
   bool res = FALSE;

   STP_ASSERT(MSTP_ENABLED);
   STP_ASSERT(IS_VALID_LPORT(lport));

   if(MSTP_COMM_PORT_PTR(lport))
      res = !MSTP_COMM_PORT_IS_BIT_SET(MSTP_COMM_PORT_PTR(lport)->bitMap,
                                       MSTP_PORT_RCVD_INTERNAL);


   return res;
}

/**PROC+**********************************************************************
 * Name:      mstp_portExternalRootPathCost
 *
 * Purpose:   Read External Root Path Cost value known on 'lport'
 *
 * Params:    lport -> logical port number
 *
 * Returns:   External Root Path Cost Value known on MSTI's 'lport'
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_portExternalRootPathCost(LPORT_t lport)
{
   uint32_t extRootPathCost = 0;

   STP_ASSERT(IS_VALID_LPORT(lport));


   if(MSTP_CIST_PORT_PTR(lport))
   {
      extRootPathCost =
         MSTP_CIST_PORT_PTR(lport)->portPriority.extRootPathCost;
   }


   return extRootPathCost;
}

/**PROC+**********************************************************************
 * Name:      mstp_portMstBpduTxCnt
 *
 * Purpose:   Read the number of MST BPDUs transmitted on 'lport'
 *
 * Params:    lport -> logical port number
 *
 * Returns:   number of MST BPDUs transmitted on 'lport'
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_portMstBpduTxCnt(LPORT_t lport)
{
   uint32_t cnt = 0;

   STP_ASSERT(IS_VALID_LPORT(lport));


   if(MSTP_CIST_PORT_PTR(lport))
      cnt = MSTP_CIST_PORT_PTR(lport)->dbgCnts.mstBpduTxCnt;


   return cnt;
}

/**PROC+**********************************************************************
 * Name:      mstp_portMstBpduRxCnt
 *
 * Purpose:   Read the number of MST BPDUs received on 'lport'
 *
 * Params:    lport -> logical port number
 *
 * Returns:   number of MST BPDUs received on 'lport'
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_portMstBpduRxCnt(LPORT_t lport)
{
   uint32_t cnt = 0;

   STP_ASSERT(IS_VALID_LPORT(lport));


   if(MSTP_CIST_PORT_PTR(lport))
      cnt = MSTP_CIST_PORT_PTR(lport)->dbgCnts.mstBpduRxCnt;


   return cnt;
}

/**PROC+**********************************************************************
 * Name:      mstp_portCfgBpduTxCnt
 *
 * Purpose:   Read the number of Configuration BPDUs transmitted on 'lport'
 *
 * Params:    lport -> logical port number
 *
 * Returns:   number of Configuration BPDUs transmitted on 'lport'
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_portCfgBpduTxCnt(LPORT_t lport)
{
   uint32_t cnt = 0;

   STP_ASSERT(IS_VALID_LPORT(lport));


   if(MSTP_CIST_PORT_PTR(lport))
      cnt = MSTP_CIST_PORT_PTR(lport)->dbgCnts.cfgBpduTxCnt;


   return cnt;
}

/**PROC+**********************************************************************
 * Name:      mstp_portCfgBpduRxCnt
 *
 * Purpose:   Read the number of Configuration BPDUs received on 'lport'
 *
 * Params:    lport -> logical port number
 *
 * Returns:   number of Configuration BPDUs received on 'lport'
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_portCfgBpduRxCnt(LPORT_t lport)
{
   uint32_t cnt = 0;

   STP_ASSERT(IS_VALID_LPORT(lport));

   if(MSTP_CIST_PORT_PTR(lport))
      cnt = MSTP_CIST_PORT_PTR(lport)->dbgCnts.cfgBpduRxCnt;


   return cnt;
}

/**PROC+**********************************************************************
 * Name:      mstp_portTcnBpduTxCnt
 *
 * Purpose:   Read the number of TCN BPDUs transmitted on 'lport'
 *
 * Params:    lport -> logical port number
 *
 * Returns:   number of TCN BPDUs transmitted on 'lport'
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_portTcnBpduTxCnt(LPORT_t lport)
{
   uint32_t cnt = 0;

   STP_ASSERT(IS_VALID_LPORT(lport));


   if(MSTP_CIST_PORT_PTR(lport))
      cnt = MSTP_CIST_PORT_PTR(lport)->dbgCnts.tcnBpduTxCnt;


   return cnt;
}

/**PROC+**********************************************************************
 * Name:      mstp_portTcnBpduRxCnt
 *
 * Purpose:   Read the number of TCN BPDUs received on 'lport'
 *
 * Params:    lport -> logical port number
 *
 * Returns:   number of TCN BPDUs received on 'lport'
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_portTcnBpduRxCnt(LPORT_t lport)
{
   uint32_t cnt = 0;

   STP_ASSERT(IS_VALID_LPORT(lport));


   if(MSTP_CIST_PORT_PTR(lport))
      cnt = MSTP_CIST_PORT_PTR(lport)->dbgCnts.tcnBpduRxCnt;


   return cnt;
}

/**PROC+**********************************************************************
 * Name:      mstp_portTcAckFlagTxCnt
 *
 * Purpose:   Read how many times the TC ACK Flag was set in the Configuration
 *            BPDUs transmitted through 'lport'.
 *
 * Params:    lport -> logical port number
 *
 * Returns:   number of times the TC ACK Flag was set in Configuration BPDUs
 *            transmitted through 'lport'
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_portTcAckFlagTxCnt(LPORT_t lport)
{
   uint32_t cnt = 0;

   STP_ASSERT(IS_VALID_LPORT(lport));


   if(MSTP_CIST_PORT_PTR(lport))
      cnt = MSTP_CIST_PORT_PTR(lport)->dbgCnts.tcAckFlagTxCnt;


   return cnt;
}

/**PROC+**********************************************************************
 * Name:      mstp_portTcAckFlagRxCnt
 *
 * Purpose:   Read how many times the TC ACK Flag was set in the Configuration
 *            BPDUs received on 'lport'.
 *
 * Params:    lport -> logical port number
 *
 * Returns:   number of times the TC ACK Flag was set in Configuration BPDUs
 *            received on 'lport'
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_portTcAckFlagRxCnt(LPORT_t lport)
{
   uint32_t cnt = 0;

   STP_ASSERT(IS_VALID_LPORT(lport));


   if(MSTP_CIST_PORT_PTR(lport))
      cnt = MSTP_CIST_PORT_PTR(lport)->dbgCnts.tcAckFlagRxCnt;


   return cnt;
}

/**PROC+**********************************************************************
 * Name:      mstp_portLoopBackBpduCnt
 *
 * Purpose:   Read the number of loop-backed BPDUs received on 'lport'.
 *            NOTE: Loop-backed BPDUs are the ones that transmitting port
 *                   receives back as the result of an external loop
 *                   existence.
 *
 * Params:    lport -> logical port number
 *
 * Returns:   number of received loop-backed BPDUs
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_portLoopBackBpduCnt(LPORT_t lport)
{
   uint32_t cnt = 0;

   STP_ASSERT(IS_VALID_LPORT(lport));


   if(MSTP_CIST_PORT_PTR(lport))
      cnt = MSTP_CIST_PORT_PTR(lport)->dbgCnts.loopBackBpduCnt;


   return cnt;
}

/**PROC+**********************************************************************
 * Name:      mstp_portAgedBpduCnt
 *
 * Purpose:   Read the number of times when received BPDUs were aged out on
 *            'lport'
 *            NOTE: Aged BPDU is the one whose 'Message Age' exeeds the
 *                   'Max Age' at the time of processing this BPDU.
 *
 * Params:    lport -> logical port number
 *
 * Returns:   number of BPDUs aged out on 'lport'
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_portAgedBpduCnt(LPORT_t lport)
{
   uint32_t cnt = 0;

   STP_ASSERT(IS_VALID_LPORT(lport));

   if(MSTP_CIST_PORT_PTR(lport))
      cnt = MSTP_CIST_PORT_PTR(lport)->dbgCnts.agedBpduCnt;

   return cnt;
}

/**PROC+**********************************************************************
 * Name:      mstp_mstiPortRgnRootBridgeId
 *
 * Purpose:   Read ID of the Regional Root Bridge known on MSTI's 'lport'
 *
 * Params:    lport    -> logical port number
 *            mac_addr -> place holder where to return the
 *                        Mac Address of the Regional Root Bridge
 *            priority -> place holder where to return the Priority value
 *                        of the Regional Root Bridge.
 *
 * Returns:   the ID of the Regional Root Bridge known on MSTI's 'lport'
 *            (placed to 'mac_addr' and 'priority')
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
void
mstp_mstiPortRgnRootBridgeId(MSTID_t mstid, LPORT_t lport,
                                  MAC_ADDRESS mac_addr, uint16_t *priority)
{
   STP_ASSERT(IS_VALID_LPORT(lport));
   STP_ASSERT(mac_addr && priority);

   memset(mac_addr, 0, sizeof(MAC_ADDRESS));
   *priority = 0;


   if(MSTP_INSTANCE_IS_VALID(mstid))
   {
      if(mstid == MSTP_CISTID)
      {
         MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

         if(cistPortPtr)
         {
            MAC_ADDR_COPY(cistPortPtr->portPriority.rgnRootID.mac_address,
                          mac_addr);
            *priority = cistPortPtr->portPriority.rgnRootID.priority;
         }
      }
      else
      {
         MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

         if(mstiPortPtr)
         {
            MAC_ADDR_COPY(mstiPortPtr->portPriority.rgnRootID.mac_address,
                          mac_addr);
            *priority = mstiPortPtr->portPriority.rgnRootID.priority;
         }
      }
   }

}

/**PROC+**********************************************************************
 * Name:      mstp_mstiPortInternalRootPathCost
 *
 * Purpose:   Read Internal Root Path Cost value known on MSTI's 'lport'
 *
 * Params:    lport -> logical port number
 *
 * Returns:   Internal Root Path Cost Value known on MSTI's 'lport'
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_mstiPortInternalRootPathCost(MSTID_t mstid, LPORT_t lport)
{
   uint32_t intRootPathCost = 0;

   STP_ASSERT(IS_VALID_LPORT(lport));


   if(MSTP_INSTANCE_IS_VALID(mstid))
   {
      if(mstid == MSTP_CISTID)
      {
         if(MSTP_CIST_PORT_PTR(lport))
         {
            intRootPathCost =
               MSTP_CIST_PORT_PTR(lport)->portPriority.intRootPathCost;
         }
      }
      else
      {
         if(MSTP_MSTI_PORT_PTR(mstid, lport))
         {
            intRootPathCost =
               MSTP_MSTI_PORT_PTR(mstid, lport)->portPriority.intRootPathCost;
         }
      }
   }

   return intRootPathCost;
}

/**PROC+**********************************************************************
 * Name:      mstp_mstiPortDsnBridgeId
 *
 * Purpose:   Read ID of the Designated Bridge known on MSTI's 'lport'
 *
 * Params:    lport    -> logical port number
 *            mac_addr -> place holder where to return the Mac Address of the
 *                        Designated Bridge
 *            priority -> place holder where to return the Priority value
 *                        of the Designated Bridge.
 *
 * Returns:   the ID of the Designated Bridge known on MSTI's 'lport'
 *            (placed to 'mac_addr' and 'priority')
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
void
mstp_mstiPortDsnBridgeId(MSTID_t mstid, LPORT_t lport,
                         MAC_ADDRESS mac_addr, uint16_t *priority)
{
   STP_ASSERT(IS_VALID_LPORT(lport));
   STP_ASSERT(mac_addr && priority);

   memset(mac_addr, 0, sizeof(MAC_ADDRESS));
   *priority = 0;


   if(MSTP_INSTANCE_IS_VALID(mstid))
   {
      if(mstid == MSTP_CISTID)
      {
         MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

         if(cistPortPtr)
         {
            MAC_ADDR_COPY(cistPortPtr->portPriority.dsnBridgeID.mac_address,
                          mac_addr);
            *priority = cistPortPtr->portPriority.dsnBridgeID.priority;
         }
      }
      else
      {
         MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

         if(mstiPortPtr)
         {
            MAC_ADDR_COPY(mstiPortPtr->portPriority.dsnBridgeID.mac_address,
                          mac_addr);
            *priority = mstiPortPtr->portPriority.dsnBridgeID.priority;
         }
      }
   }

}

/**PROC+**********************************************************************
 * Name:      mstp_mstiPortDsnPortId
 *
 * Purpose:   Read ID of the Designated Port known on MSTI's 'lport'
 *
 * Params:    mstid -> MST Instance ID
 *            lport -> logical port number
 *
 * Returns:   Designated Port ID known on given MSTI's 'lport'
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
MSTP_PORT_ID_t
mstp_mstiPortDsnPortId(MSTID_t mstid, LPORT_t lport)
{
   MSTP_PORT_ID_t dsnPortId = 0;

   STP_ASSERT(IS_VALID_LPORT(lport));


   if(MSTP_INSTANCE_IS_VALID(mstid))
   {
      if(mstid == MSTP_CISTID)
      {
         if(MSTP_CIST_PORT_PTR(lport))
            dsnPortId = MSTP_CIST_PORT_PTR(lport)->portPriority.dsnPortID;
      }
      else
      {
         if(MSTP_MSTI_PORT_PTR(mstid, lport))
         {
            dsnPortId =
               MSTP_MSTI_PORT_PTR(mstid, lport)->portPriority.dsnPortID;
         }
      }
   }


   return dsnPortId;
}

/**PROC+**********************************************************************
 * Name:      mstp_mstiPortTcDetectCnt
 *
 * Purpose:   Read the number of Topology Changes detected on the MSTI's
 *            'lport'.
 *
 * Params:    mstid -> MST Instance ID
 *            lport -> logical port number
 *
 * Returns:   number of Topology Changes detected on given MSTI's 'lport'
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_mstiPortTcDetectCnt(MSTID_t mstid, LPORT_t lport)
{
   uint32_t cnt = 0;

   STP_ASSERT(IS_VALID_LPORT(lport));


   if(MSTP_INSTANCE_IS_VALID(mstid))
   {
      if(mstid == MSTP_CISTID)
      {
         if(MSTP_CIST_PORT_PTR(lport))
            cnt = MSTP_CIST_PORT_PTR(lport)->dbgCnts.tcDetectCnt;
      }
      else
      {
         if(MSTP_MSTI_PORT_PTR(mstid, lport))
            cnt = MSTP_MSTI_PORT_PTR(mstid, lport)->dbgCnts.tcDetectCnt;
      }
   }


   return cnt;
}

/**PROC+**********************************************************************
 * Name:      mstp_mstiPortTcFlagTxCnt
 *
 * Purpose:   Read the number of times the TC flag was set in BPDUs or
 *            MSTI Configuration Messages transmitted through this MSTI's port
 *
 * Params:    mstid -> MST Instance ID
 *            lport -> logical port number
 *
 * Returns:   number of times the TC flag was set in messages transmitted
 *            through 'lport'
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_mstiPortTcFlagTxCnt(MSTID_t mstid, LPORT_t lport)
{
   uint32_t cnt = 0;

   STP_ASSERT(IS_VALID_LPORT(lport));


   if(MSTP_INSTANCE_IS_VALID(mstid))
   {
      if(mstid == MSTP_CISTID)
      {
         if(MSTP_CIST_PORT_PTR(lport))
            cnt = MSTP_CIST_PORT_PTR(lport)->dbgCnts.tcFlagTxCnt;
      }
      else
      {
         if(MSTP_MSTI_PORT_PTR(mstid, lport))
            cnt = MSTP_MSTI_PORT_PTR(mstid, lport)->dbgCnts.tcFlagTxCnt;
      }
   }


   return cnt;
}

/**PROC+**********************************************************************
 * Name:      mstp_mstiPortTcFlagRxCnt
 *
 * Purpose:   Read the number of times the TC flag was detected in BPDUs or
 *            MSTI Configuration Messages received on this MSTI's port
 *
 * Params:    mstid -> MST Instance ID
 *            lport -> logical port number
 *
 * Returns:   number of times the TC flag was detected in messages received
 *            on 'lport'
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_mstiPortTcFlagRxCnt(MSTID_t mstid, LPORT_t lport)
{
   uint32_t cnt = 0;

   STP_ASSERT(IS_VALID_LPORT(lport));

   if(MSTP_INSTANCE_IS_VALID(mstid))
   {
      if(mstid == MSTP_CISTID)
      {
         if(MSTP_CIST_PORT_PTR(lport))
            cnt = MSTP_CIST_PORT_PTR(lport)->dbgCnts.tcFlagRxCnt;
      }
      else
      {
         if(MSTP_MSTI_PORT_PTR(mstid, lport))
            cnt = MSTP_MSTI_PORT_PTR(mstid, lport)->dbgCnts.tcFlagRxCnt;
      }
   }


   return cnt;
}

/**PROC+**********************************************************************
 * Name:      mstp_mstiPortExceededHopsBpduCnt
 *
 * Purpose:   Read how many BPDUs with 'remainingHops' less than or equal
 *            to zero were received on MSTI's 'lport'.
 *
 * Params:    mstid -> MST Instance ID
 *            lport -> logical port number
 *
 * Returns:   Number of received BPDUs with the 'remainingHops' parameter
 *            being less than or equal to zero.
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_mstiPortExceededHopsBpduCnt(MSTID_t mstid, LPORT_t lport)
{
   uint32_t cnt = 0;

   STP_ASSERT(IS_VALID_LPORT(lport));


   if(MSTP_INSTANCE_IS_VALID(mstid))
   {
      if(mstid == MSTP_CISTID)
      {
         if(MSTP_CIST_PORT_PTR(lport))
            cnt = MSTP_CIST_PORT_PTR(lport)->dbgCnts.exceededHopsBpduCnt;
      }
      else
      {
         if(MSTP_MSTI_PORT_PTR(mstid, lport))
            cnt = MSTP_MSTI_PORT_PTR(mstid, lport)->dbgCnts.exceededHopsMsgCnt;
      }
   }


   return cnt;
}

/**PROC+**********************************************************************
 * Name:      mstp_get_bridge_oper_edge
 *
 * Purpose:   Allows access to lport's operEdge value
 *
 * Params:    lport -> logical port number
 *
 * Returns:   lport's operEdge value
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
bool
mstp_get_bridge_oper_edge(LPORT_t lport)
{
   bool                 result;
   MSTP_COMM_PORT_INFO_t  *commPortPtr  = NULL;

   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);

   result = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                      MSTP_PORT_OPER_EDGE);


   return result;
}
bool
mstp_isp2pEnable(LPORT_t port)
{
   MSTP_COMM_PORT_INFO_t *commPortPtr;
   if(MSTP_ENABLED)
   {
      commPortPtr = MSTP_COMM_PORT_PTR(port);
      if(commPortPtr && (MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                        MSTP_PORT_OPER_POINT_TO_POINT_MAC)))
      {
       return(TRUE);
      }
    }
    return(FALSE);
}

/**PROC+**********************************************************************
 * Name:      mstp_portBpduFilterCheck
 *
 * Purpose:   returns TRUE, for bpdu validation if the lport passing the bpdu
 *            is on the 'hpSwitchStpPortBpduFilter' data structure
 *
 * Params:    lport -> logical port number
 *
 * Returns:   TRUE if lport is part of the hpSwitchStpPortBpduFilter
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
bool
mstp_portBpduFilterCheck(LPORT_t lport)
{
   bool result;
   STP_ASSERT(IS_VALID_LPORT(lport));


   if(MSTP_COMM_IS_BPDU_FILTER(lport))
   {/* drop the BPDU by not validating it */
      result = TRUE;
   }
   else
   {/* port is not disabled, continue with normal stp operations */
      result = FALSE;
   }


   return (result);
}

/**PROC+**********************************************************************
 * Name:      mstp_countBpduFilters
 *
 * Purpose:   Provides a public function that accesses and returns the number
 *            of BPDU filters currently in place.
 *
 * Params:    none
 *
 * Returns:   Count of ports with BPDU filtering enabled.
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
int
mstp_countBpduFilters(void)
{
   LPORT_t lport;
   int     count = 0;


   lport = (LPORT_t)find_first_port_set(&mstp_Bridge.bpduFilterLports);
   if(lport > 0)
   {
      while(lport <= MAX_LPORTS)
      {
         /* Because filter flag isn't part of port-info,
          * no ptr checked needed. */
         if(MSTP_COMM_IS_BPDU_FILTER(lport))
         {
            ++count;
         }
         ++lport;
      }
   }


   return (count);
}

/**PROC+**********************************************************************
 * Name:      mstp_errantBpduCounter_get
 *
 * Purpose:   Provides a function that accesses and returns a private data
 *            structure value for MSTP's per-port errant BPDUs that have
 *            been filtered away.  At startup when config-SNMP is configuring
 *            the ports, called with NULL cist-port ptr just before port is
 *            built out.
 *
 * Params:    lport -> logical port number
 *
 * Returns:   Value of errant (enexpected) BPDU frames received on port.
 *
 * Globals:   mstp_Bridge, mstp_CB
 *
 * Constraints:
 **PROC-**********************************************************************/
uint32_t
mstp_errantBpduCounter_get(LPORT_t lport)
{
   uint32_t   result = 0;


   if(MSTP_CIST_PORT_PTR(lport))
      result = MSTP_CIST_PORT_PTR(lport)->dbgCnts.errantBpduCnt;


   return (result);
}

/**PROC+**********************************************************************
 * Name:      mstp_dot1dStpPortState
 *
 * Purpose:   Retrieve port state in format defined in BRIDGE-MIB (RFC-1493)
 *
 * Params:    lport -> logical port number
 *
 * Returns:   Port State as defined in BRIDGE-MIB
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/
int32_t
mstp_dot1dStpPortState(LPORT_t lport)
{
   //int32_t                  state = D_hpicfBridgeMSTPortState_broken;
   int32_t                  state = 6;
   MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);
   MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

   if(!commPortPtr || !cistPortPtr)
   {
      STP_ASSERT(0);
      return state;
   }
   if(commPortPtr->inBpduError == TRUE)
      //state = D_hpicfBridgeMSTPortState_bpduError;
      state = 7;
   else
   if(cistPortPtr->loopInconsistent == TRUE)
      //state = D_hpicfBridgeMSTPortState_loopInconsistent;
      state = 8;
   else
   if(!MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap, MSTP_PORT_PORT_ENABLED))
      //state = D_hpicfBridgeMSTPortState_disabled;
      state = 1;
   else if(cistPortPtr->pstState == MSTP_PST_STATE_LEARNING)
      //state = D_hpicfBridgeMSTPortState_learning;
      state = 4;
   else if(cistPortPtr->pstState == MSTP_PST_STATE_FORWARDING)
      //state = D_hpicfBridgeMSTPortState_forwarding;
      state = 5;
   else if(cistPortPtr->pstState == MSTP_PST_STATE_DISCARDING)
   {
      if(cistPortPtr->prtState == MSTP_PRT_STATE_DESIGNATED_DISCARD)
         state = 3;
         //state = D_hpicfBridgeMSTPortState_listening;
      else
         //state = D_hpicfBridgeMSTPortState_blocking;
         state = 2;
   }
   else
   {
      //state = D_hpicfBridgeMSTPortState_broken;
      state = 1;
   }
   return (state);
}
/**PROC+**********************************************************************
 * Name:      mstp_isPortInBpduError
 *
 * Purpose:   This function returns whether STP is currently holding the
 *            port in bpdu Error (BPDU PROTECITON), aka "disabled".
 *
 * Params:    lport -> logical port number
 *
 * Returns:   FALSE if not holding port in bpdu error, TRUE otherwise.
 *
 * Note:
 **PROC-**********************************************************************/
bool mstp_isPortInBpduError(LPORT_t lport)
{
   bool                 result;
   MSTP_COMM_PORT_INFO_t  *commPortPtr  = NULL;

   STP_ASSERT(IS_VALID_LPORT(lport));

   commPortPtr = MSTP_COMM_PORT_PTR(lport);
   STP_ASSERT(commPortPtr);
   result = commPortPtr->inBpduError;

   return result;
}

/**PROC+**********************************************************************
 * Name:      mstp_getMstiPortDbgAllCntInfo
 *
 * Purpose:   fills CIST and MST counters
 *
 * Params: mstid - MSTP instance ID
 *         lport - Lport
 *         mCnt  - structure to hold instance independent counters
 *         mInstCnt  - structure to hold instance dependent counters
 * Returns: 1 if structured filled with data, 0 otherwise
 **PROC-**********************************************************************/
uint32_t
mstp_getMstiPortDbgAllCntInfo(uint16_t mstid, LPORT_t lport,
                           mstpCntrs_t *mCnt, mstpInstCntrs_t *mInstCnt)
{
   MSTP_CIST_PORT_INFO_t *cistPortPtr = NULL;
   MSTP_MSTI_PORT_INFO_t *mstiPortPtr = NULL;

   STP_ASSERT((mstid == MSTP_CISTID) || MSTP_VALID_MSTID(mstid));
   STP_ASSERT(IS_VALID_LPORT(lport));

   if(!MSTP_ENABLED || !MSTP_INSTANCE_IS_VALID(mstid))
      return 0;


   if((cistPortPtr = MSTP_CIST_PORT_PTR(lport)))
   {
       mCnt->invalidBpduCnt = cistPortPtr->dbgCnts.invalidBpduCnt;
       mCnt->invalidBpduCntLastUpdated =
          cistPortPtr->dbgCnts.invalidBpduCntLastUpdated;
       mCnt->errantBpduCnt = cistPortPtr->dbgCnts.errantBpduCnt;
       mCnt->errantBpduCntLastUpdated =
          cistPortPtr->dbgCnts.errantBpduCntLastUpdated;
       mCnt->mstCfgErrorBpduCnt = cistPortPtr->dbgCnts.mstCfgErrorBpduCnt;
       mCnt->mstCfgErrorBpduCntLastUpdated =
          cistPortPtr->dbgCnts.mstCfgErrorBpduCntLastUpdated;
       mCnt->loopBackBpduCnt = cistPortPtr->dbgCnts.loopBackBpduCnt;
       mCnt->loopBackBpduCntLastUpdated =
           cistPortPtr->dbgCnts.loopBackBpduCntLastUpdated;
       mCnt->starvedBpduCnt = cistPortPtr->dbgCnts.starvedBpduCnt;
       mCnt->starvedBpduCntLastUpdated =
          cistPortPtr->dbgCnts.starvedBpduCntLastUpdated;
       mCnt->agedBpduCnt = cistPortPtr->dbgCnts.agedBpduCnt;
       mCnt->agedBpduCntLastUpdated =
          cistPortPtr->dbgCnts.agedBpduCntLastUpdated;
       mCnt->exceededHopsBpduCnt = cistPortPtr->dbgCnts.exceededHopsBpduCnt;
       mCnt->exceededHopsBpduCntLastUpdated =
          cistPortPtr->dbgCnts.exceededHopsBpduCntLastUpdated;
       mCnt->tcDetectCnt = cistPortPtr->dbgCnts.tcDetectCnt;
       mCnt->tcDetectCntLastUpdated =
          cistPortPtr->dbgCnts.tcDetectCntLastUpdated;
       mCnt->tcFlagTxCnt = cistPortPtr->dbgCnts.tcFlagTxCnt;
       mCnt->tcFlagTxCntLastUpdated =
          cistPortPtr->dbgCnts.tcFlagTxCntLastUpdated;
       mCnt->tcFlagRxCnt = cistPortPtr->dbgCnts.tcFlagRxCnt;
       mCnt->tcFlagRxCntLastUpdated = cistPortPtr->dbgCnts.tcFlagRxCntLastUpdated;
       mCnt->tcAckFlagTxCnt = cistPortPtr->dbgCnts.tcAckFlagTxCnt;
       mCnt->tcAckFlagTxCntLastUpdated =
          cistPortPtr->dbgCnts.tcAckFlagTxCntLastUpdated;
       mCnt->tcAckFlagRxCnt = cistPortPtr->dbgCnts.tcAckFlagRxCnt;
       mCnt->tcAckFlagRxCntLastUpdated =
          cistPortPtr->dbgCnts.tcAckFlagRxCntLastUpdated;
       mCnt->mstBpduTxCnt = cistPortPtr->dbgCnts.mstBpduTxCnt;
       mCnt->mstBpduTxCntLastUpdated =
          cistPortPtr->dbgCnts.mstBpduTxCntLastUpdated;
       mCnt->mstBpduRxCnt = cistPortPtr->dbgCnts.mstBpduRxCnt;
       mCnt->mstBpduRxCntLastUpdated =
          cistPortPtr->dbgCnts.mstBpduRxCntLastUpdated;
       mCnt->rstBpduTxCnt = cistPortPtr->dbgCnts.rstBpduTxCnt;
       mCnt->rstBpduTxCntLastUpdated =
         cistPortPtr->dbgCnts.rstBpduTxCntLastUpdated;
       mCnt->rstBpduRxCnt = cistPortPtr->dbgCnts.rstBpduRxCnt;
       mCnt->rstBpduRxCntLastUpdated =
          cistPortPtr->dbgCnts.rstBpduRxCntLastUpdated;
       mCnt->cfgBpduTxCnt = cistPortPtr->dbgCnts.cfgBpduTxCnt;
       mCnt->cfgBpduTxCntLastUpdated =
          cistPortPtr->dbgCnts.cfgBpduTxCntLastUpdated;
       mCnt->cfgBpduRxCnt = cistPortPtr->dbgCnts.cfgBpduRxCnt;
       mCnt->cfgBpduRxCntLastUpdated =
          cistPortPtr->dbgCnts.cfgBpduRxCntLastUpdated;
       mCnt->tcnBpduTxCnt = cistPortPtr->dbgCnts.tcnBpduTxCnt;
       mCnt->tcnBpduTxCntLastUpdated =
         cistPortPtr->dbgCnts.tcnBpduTxCntLastUpdated;
       mCnt->tcnBpduRxCnt = cistPortPtr->dbgCnts.tcnBpduRxCnt;
       mCnt->tcnBpduRxCntLastUpdated =
         cistPortPtr->dbgCnts.tcnBpduRxCntLastUpdated;
   }

   if((mstid != MSTP_CISTID) &&
                            (mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport)))
   {
      mInstCnt->starvedMsgCnt = mstiPortPtr->dbgCnts.starvedMsgCnt;
      mInstCnt->starvedMsgCntLastUpdated =
            mstiPortPtr->dbgCnts.starvedMsgCntLastUpdated;
      mInstCnt->exceededHopsMsgCnt = mstiPortPtr->dbgCnts.exceededHopsMsgCnt;
      mInstCnt->exceededHopsMsgCntLastUpdated =
                      mstiPortPtr->dbgCnts.exceededHopsMsgCntLastUpdated;
      mInstCnt->tcDetectCnt = mstiPortPtr->dbgCnts.tcDetectCnt;
      mInstCnt->tcDetectCntLastUpdated = mstiPortPtr->dbgCnts.tcDetectCntLastUpdated;
      mInstCnt->tcFlagTxCnt = mstiPortPtr->dbgCnts.tcFlagTxCnt;
      mInstCnt->tcFlagTxCntLastUpdated = mstiPortPtr->dbgCnts.tcFlagTxCntLastUpdated;
      mInstCnt->tcFlagRxCnt = mstiPortPtr->dbgCnts.tcFlagRxCnt;
      mInstCnt->tcFlagRxCntLastUpdated = mstiPortPtr->dbgCnts.tcFlagRxCntLastUpdated;
      mInstCnt->mstiMsgTxCnt = mstiPortPtr->dbgCnts.mstiMsgTxCnt;
      mInstCnt->mstiMsgTxCntLastUpdated =
            mstiPortPtr->dbgCnts.mstiMsgTxCntLastUpdated;
      mInstCnt->mstiMsgRxCnt = mstiPortPtr->dbgCnts.mstiMsgRxCnt;
      mInstCnt->mstiMsgRxCntLastUpdated =
            mstiPortPtr->dbgCnts.mstiMsgRxCntLastUpdated;
   }


   return 1;
}

/**PROC+**********************************************************************
 * Name:      mstpCistCompareRootTimes
 *
 * Purpose:   To check if there is any changes in the time values received from
 *            root
 *
 * Params:    rootTime  -> contains forward-delay,max-age,max-hops etc
 *            helloTime ->Hello time value received from root
 * Returns:   TRUE if changed else FALSE
 **PROC-**********************************************************************/

bool
mstpCistCompareRootTimes(MSTP_CIST_ROOT_TIMES_t *rootTime,  uint16_t helloTime)
{
   if ((rootTime->fwdDelay == MSTP_CIST_ROOT_TIMES.fwdDelay) &&
       (rootTime->maxAge == MSTP_CIST_ROOT_TIMES.maxAge) &&
       (rootTime->messageAge == MSTP_CIST_ROOT_TIMES.messageAge) &&
       (rootTime->hops == MSTP_CIST_ROOT_TIMES.hops) &&
       (helloTime == MSTP_CIST_ROOT_HELLO_TIME))
   {
      /* Everything is same. Return FALSE */
      return FALSE;
   }
   return TRUE;
}
/**PROC+**********************************************************************
 * Name:      mstp_updatePortHistory
 *
 * Purpose:   To update port role change history
 *
 * Params:    mstid  -> MST instance ID
 *            lport  -> Port number
 *
 * Returns:   No
 **PROC-**********************************************************************/
void
mstp_updatePortHistory(MSTID_t mstid, LPORT_t lport,
                       MSTP_PRT_STATE_t newState)
{
   int idx;

   STP_ASSERT(MSTP_ENABLED);

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);
#ifdef OPS_MSTP_TODO
      if((cistPortPtr->selectedRole == MSTP_PORT_ROLE_UNKNOWN) ||
         (cistPortPtr->selectedRole == newState))
      {
         return;
      }
#endif /*OPS_MSTP_TODO*/
      /* shift all entries one step down to the bottom of the history array */
      for(idx = MSTP_PORT_HISTORY_MAX-1; idx > 0; idx--)
      {
         cistPortPtr->portHistory[idx] = cistPortPtr->portHistory[idx-1];
      }
      /* store new info in the first entry of the history array */
      idx = 0;
      cistPortPtr->portHistory[idx].newState = newState;
      cistPortPtr->portHistory[idx].oldState = cistPortPtr->selectedRole;

      if(cistPortPtr->infoIs == MSTP_INFO_IS_AGED)
      {
         cistPortPtr->portHistory[idx].aged = 2;
      }
      else
         cistPortPtr->portHistory[idx].aged = 1;

      cistPortPtr->portHistory[idx].timeStamp = time(NULL);
      cistPortPtr->portHistory[idx].portPriority.rootID =
         cistPortPtr->portPriority.rootID;
      cistPortPtr->portHistory[idx].portPriority.extRootPathCost =
         cistPortPtr->portPriority.extRootPathCost;
      cistPortPtr->portHistory[idx].portPriority.rgnRootID =
         cistPortPtr->portPriority.rgnRootID;
      cistPortPtr->portHistory[idx].portPriority.intRootPathCost =
         cistPortPtr->portPriority.intRootPathCost;
      cistPortPtr->portHistory[idx].portPriority.dsnBridgeID =
         cistPortPtr->portPriority.dsnBridgeID;
      cistPortPtr->portHistory[idx].portPriority.dsnPortID =
         cistPortPtr->portPriority.dsnPortID;
      cistPortPtr->portHistory[idx].valid = TRUE;
      if(MSTP_CIST_PORT_STATE_CHANGE)
      {
         if(((cistPortPtr->portHistory[idx].oldState ==
              (int)MSTP_PORT_ROLE_ALTERNATE) ||
             (cistPortPtr->portHistory[idx].oldState ==
              (int)MSTP_PORT_ROLE_BACKUP)) &&
            ((cistPortPtr->portHistory[idx].newState ==
              (int)MSTP_PORT_ROLE_ROOT) ||
             (cistPortPtr->portHistory[idx].newState ==
              (int)MSTP_PORT_ROLE_DESIGNATED)))
         {
            char portName[PORTNAME_LEN];

            intf_get_port_name(lport, portName);

            VLOG_DBG("Port %s unblocked on CST",
                      portName);
            log_event("MSTP_CIST_PORT_UNBLOCK",
                EV_KV("port", "%s", portName));
         }
         else
            if(((cistPortPtr->portHistory[idx].newState ==
                 (int)MSTP_PORT_ROLE_ALTERNATE) ||
                (cistPortPtr->portHistory[idx].newState ==
                 (int)MSTP_PORT_ROLE_BACKUP)) &&
               ((cistPortPtr->portHistory[idx].oldState ==
                 (int)MSTP_PORT_ROLE_ROOT) ||
                (cistPortPtr->portHistory[idx].oldState ==
                 (int)MSTP_PORT_ROLE_DESIGNATED)))
            {
               char portName[PORTNAME_LEN];

               intf_get_port_name(lport, portName);

               VLOG_DBG("Port %s blocked on CST",
                        portName);
               log_event("MSTP_CIST_PORT_BLOCK",
                   EV_KV("port", "%s", portName));
            }
      }
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      if(mstiPortPtr->selectedRole == MSTP_PORT_ROLE_UNKNOWN)
      {
         return;
      }
      /* shift all entries one step down to the bottom of the history array */
      for(idx = MSTP_PORT_HISTORY_MAX-1; idx > 0; idx--)
      {
         mstiPortPtr->portHistory[idx] = mstiPortPtr->portHistory[idx-1];
      }
      /* store new info in the first entry of the history array */
      idx = 0;
      mstiPortPtr->portHistory[idx].newState = newState;
      mstiPortPtr->portHistory[idx].oldState = mstiPortPtr->selectedRole;
      if(mstiPortPtr->infoIs == MSTP_INFO_IS_AGED)
      {
         mstiPortPtr->portHistory[idx].aged = 2;
      }
      else
         mstiPortPtr->portHistory[idx].aged = 1;
      mstiPortPtr->portHistory[idx].timeStamp = time(NULL);
      mstiPortPtr->portHistory[idx].portPriority.rgnRootID =
         mstiPortPtr->portPriority.rgnRootID;
      mstiPortPtr->portHistory[idx].portPriority.intRootPathCost =
         mstiPortPtr->portPriority.intRootPathCost;
      mstiPortPtr->portHistory[idx].portPriority.dsnBridgeID =
         mstiPortPtr->portPriority.dsnBridgeID;
      mstiPortPtr->portHistory[idx].portPriority.dsnPortID =
         mstiPortPtr->portPriority.dsnPortID;
      mstiPortPtr->portHistory[idx].valid = TRUE;

      if(MSTP_MSTI_PORT_STATE_CHANGE(mstid))
      {
         if(((mstiPortPtr->portHistory[idx].oldState ==
              (int)MSTP_PORT_ROLE_ALTERNATE) ||
             (mstiPortPtr->portHistory[idx].oldState ==
              (int)MSTP_PORT_ROLE_BACKUP)) &&
            ((mstiPortPtr->portHistory[idx].newState ==
              (int)MSTP_PORT_ROLE_ROOT) ||
             (mstiPortPtr->portHistory[idx].newState ==
              (int)MSTP_PORT_ROLE_DESIGNATED)))
         {
            char portName[PORTNAME_LEN];

            intf_get_port_name(lport, portName);

            VLOG_DBG("Port %s unblocked on MSTI%d",
                     portName, mstid);
            log_event("MSTP_MSTI_PORT_UNBLOCK",
                EV_KV("port", "%s", portName),
                EV_KV("instance", "%d", mstid));
         }
         else
            if(((mstiPortPtr->portHistory[idx].newState ==
                 (int)MSTP_PORT_ROLE_ALTERNATE) ||
                (mstiPortPtr->portHistory[idx].newState ==
                 (int)MSTP_PORT_ROLE_BACKUP)) &&
               ((mstiPortPtr->portHistory[idx].oldState ==
                 (int)MSTP_PORT_ROLE_ROOT) ||
                (mstiPortPtr->portHistory[idx].oldState ==
                 (int)MSTP_PORT_ROLE_DESIGNATED)))
            {
               char portName[PORTNAME_LEN];

               intf_get_port_name(lport, portName);
               VLOG_DBG("Port %s blocked on MSTI%d",
                     portName, mstid);

               log_event("MSTP_MSTI_PORT_BLOCK",
                   EV_KV("port", "%s", portName),
                   EV_KV("instance", "%d", mstid));


            }
      }
   }
}
/**PROC+**********************************************************************
 * Name:      mstpGetPortHistory
 *
 * Purpose:   To update port role change history
 *
 * Params:    mstid  -> MST instance ID
 *            lport  -> Port number
 *            histIndex -> history Index
 *
 * Returns:   Port History
 **PROC-**********************************************************************/
int
mstpGetPortHistory(MSTID_t mstid, LPORT_t lport, uint8_t histIndex,
                   MSTP_PORT_HISTORY_t *portHistory)
{

   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      if(cistPortPtr == NULL)
      {
         return 0;
      }

      portHistory->oldState = cistPortPtr->portHistory[histIndex].oldState;
      portHistory->newState = cistPortPtr->portHistory[histIndex].newState;
      portHistory->aged = cistPortPtr->portHistory[histIndex].aged;
      portHistory->timeStamp = cistPortPtr->portHistory[histIndex].timeStamp;
      memcpy(&portHistory->portPriority ,
             &cistPortPtr->portHistory[histIndex].portPriority,
             sizeof(MSTP_CIST_BRIDGE_PRI_VECTOR_t));
      portHistory->valid = cistPortPtr->portHistory[histIndex].valid;
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = NULL;

      if(mstp_Bridge.ForceVersion !=
                3)
      {
         return 0;
      }

      mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
      if(mstiPortPtr == NULL)
      {
         return 0;
      }

      portHistory->oldState = mstiPortPtr->portHistory[histIndex].oldState;
      portHistory->newState = mstiPortPtr->portHistory[histIndex].newState;
      portHistory->aged = mstiPortPtr->portHistory[histIndex].aged;
      portHistory->timeStamp = mstiPortPtr->portHistory[histIndex].timeStamp;
      memcpy(&portHistory->portPriority,
             &mstiPortPtr->portHistory[histIndex].portPriority,
             sizeof(MSTP_CIST_BRIDGE_PRI_VECTOR_t));
      portHistory->valid = mstiPortPtr->portHistory[histIndex].valid;
   }
   return 0;
}
/**PROC+**********************************************************************
 * Name:      mstpValidPortHistory
 *
 * Purpose:   To validate port role change history entry
 *
 * Params:    mstid  -> MST instance ID
 *            lport  -> Port number
 *            histIndex -> history Index
 *
 * Returns:   Port History
 **PROC-**********************************************************************/
bool
mstpValidPortHistory(MSTID_t mstid, LPORT_t lport, uint8_t histIndex)
{
   bool valid = FALSE;
   if(mstid == MSTP_CISTID)
   {
      MSTP_CIST_PORT_INFO_t *cistPortPtr = MSTP_CIST_PORT_PTR(lport);
      if(!cistPortPtr)
      {
         return valid;
      }
      valid = cistPortPtr->portHistory[histIndex].valid;
   }
   else
   {
      MSTP_MSTI_PORT_INFO_t *mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
      if(!mstiPortPtr)
      {
         return valid;
      }
      valid = mstiPortPtr->portHistory[histIndex].valid;
   }
   return valid;
}
/**PROC+**********************************************************************
 * Name:      mstpValidTcHistory
 *
 * Purpose:   Update history information for the Topology Changes
 *
 * Params:    mstid  -> MST instance ID
 *            lport  -> Port number
 *            idx    -> index in to the history table
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
bool
mstpValidTcHistory(bool originated, MSTID_t mstid, uint8_t idx)
{
   bool                        valid = FALSE;
   MSTP_CIST_INFO_t            *cistPtr = NULL;
   MSTP_MSTI_INFO_t            *mstiPtr = NULL;
   MSTP_TC_HISTORY_t           tcEntry;

   STP_ASSERT(MSTP_ENABLED);

   if (idx >= MSTP_TC_HISTORY_MAX)
   {
      STP_ASSERT(0);
      return FALSE;
   }

   if(!MSTP_ENABLED)
      return 0;


   if(mstid == MSTP_CISTID)
   {
      if(!(cistPtr = &mstp_Bridge.CistInfo))
      {
         return FALSE;
      }

      if(originated)
         tcEntry = cistPtr->tcOrigHistory[idx];
      else
         tcEntry = cistPtr->tcRcvHistory[idx];
   }
   else
   {
      if(!(mstiPtr = MSTP_MSTI_INFO(mstid)))
      {
         return FALSE;
      }

      if(originated)
         tcEntry = mstiPtr->tcOrigHistory[idx];
      else
         tcEntry = mstiPtr->tcRcvHistory[idx];
   }

   valid = tcEntry.valid;
    return valid;
}

/**PROC+**********************************************************************
 * Name:      mstpCheckForTcGeneration
 *
 * Purpose:   Checks if the port is going generate TC.
 *
 *
 * Params:    MSTID, lport and previous port roles.
 *
 *
 * Returns:   Return TRUE if TC can be generated. FALSE otherwise.
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
bool
mstpCheckForTcGeneration(MSTID_t mstid,
                         LPORT_t lport,
                         MSTP_PORT_ROLE_t newRole)
{
   bool                         edgePort;
   bool                         sendRSTP;
   char                         portName[20];
   char                         mst_str[10];
   MSTP_CIST_PORT_INFO_t       *cistPortPtr;
   MSTP_MSTI_PORT_INFO_t       *mstiPortPtr;
   MSTP_COMM_PORT_INFO_t       *commPortPtr;
   MSTP_PORT_ROLE_t             prevRole;


   STP_ASSERT(MSTP_ENABLED);

   if(mstid == MSTP_CISTID)
   {
      cistPortPtr = MSTP_CIST_PORT_PTR(lport);
      prevRole = cistPortPtr->selectedRole;
   }
   else
   {
      mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
      prevRole = mstiPortPtr->selectedRole;
   }

   commPortPtr = MSTP_COMM_PORT_PTR(lport);

   edgePort = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                        MSTP_PORT_OPER_EDGE);

   sendRSTP = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                                        MSTP_PORT_SEND_RSTP);
   /*
    * If not edge and we are transitioning to Forwarding
    */
   if(!edgePort &&
      ((prevRole == MSTP_PORT_ROLE_DISABLED) ||
       (prevRole == MSTP_PORT_ROLE_ALTERNATE) ||
       (prevRole == MSTP_PORT_ROLE_BACKUP)) &&
      ((newRole == MSTP_PORT_ROLE_ROOT) ||
       (newRole == MSTP_PORT_ROLE_MASTER) ||
       (newRole == MSTP_PORT_ROLE_DESIGNATED)))
   {

      intf_get_port_name(lport, portName);
      if(mstid == MSTP_CISTID)
      {
        VLOG_DBG("%s - Topology Change generated on port %s going in to %s",
                    "CIST",portName,"forwarding");
        log_event("MSTP_TC_ORIGINATED",
            EV_KV("proto", "%s", "CIST"),
            EV_KV("port", "%s", portName),
            EV_KV("state", "%s", "forwarding"));
      }
      else
      {
         snprintf(mst_str, sizeof(mst_str), "MSTI %d", mstid);
         VLOG_DBG("%s - Topology Change generated on port %s going in to %s",
                    mst_str,portName,"forwarding");
         log_event("MSTP_TC_ORIGINATED",
             EV_KV("proto", "%s", mst_str),
             EV_KV("port", "%s", portName),
             EV_KV("state", "%s", "forwarding"));

      }
      return TRUE;
   }
   /*
    * We generate TC when port moves to blocking for a remote STP port.
    */
   else if (!edgePort &&
            !sendRSTP &&
            ((prevRole == MSTP_PORT_ROLE_ROOT)     ||
             (prevRole == MSTP_PORT_ROLE_MASTER)   ||
             (prevRole == MSTP_PORT_ROLE_DESIGNATED)) &&
            ((newRole == MSTP_PORT_ROLE_ALTERNATE) ||
             (newRole == MSTP_PORT_ROLE_BACKUP)))
   {
      intf_get_port_name(lport, portName);
      if(mstid == MSTP_CISTID)
      {
        VLOG_DBG("%s - Topology Change generated on port %s going in to %s",
                    "CIST",portName,"blocking");
        log_event("MSTP_TC_ORIGINATED",
            EV_KV("proto", "%s", "CIST"),
            EV_KV("port", "%s", portName),
            EV_KV("state", "%s", "blocking"));
      }
      else
      {
         snprintf(mst_str, sizeof(mst_str), "MSTI %d", mstid);
         VLOG_DBG("%s - Topology Change generated on port %s going in to %s",
                    mst_str,portName,"blocking");
         log_event("MSTP_TC_ORIGINATED",
             EV_KV("proto", "%s", mst_str),
             EV_KV("port", "%s", portName),
             EV_KV("state", "%s", "blocking"));
      }
      return TRUE;
   }

   /* In all other cases TC is not generated */
   return FALSE;
}
/**PROC+**********************************************************************
 * Name:      mstpUpdateTcHistory
 *
 * Purpose:   Update history information for the Topology Changes
 *
 * Params:    mstid  -> MST instance ID
 *            lport  -> Port number
 *            originated -> Set to TRUE for TC originated history
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 **PROC-**********************************************************************/
void
mstpUpdateTcHistory(MSTID_t mstid, LPORT_t lport, bool originated)
{
   int                         idx;
   MSTP_TC_HISTORY_t           *tcHistory;
   MSTP_CIST_PORT_INFO_t       *cistPortPtr;
   MSTP_CIST_INFO_t            *cistPtr;
   MSTP_MSTI_INFO_t            *mstiPtr;
   MSTP_MSTI_PORT_INFO_t       *mstiPortPtr;
   MSTP_COMM_PORT_INFO_t       *commPortPtr;

   STP_ASSERT(MSTP_ENABLED);

   if(mstid == MSTP_CISTID)
   {
      cistPtr = &mstp_Bridge.CistInfo;
      cistPortPtr = MSTP_CIST_PORT_PTR(lport);

      if(originated)
         tcHistory = cistPtr->tcOrigHistory;
      else
         tcHistory = cistPtr->tcRcvHistory;
   }
   else
   {
      mstiPtr = MSTP_MSTI_INFO(mstid);
      mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);

      if(originated)
         tcHistory = mstiPtr->tcOrigHistory;
      else
         tcHistory = mstiPtr->tcRcvHistory;
   }

      STP_ASSERT(tcHistory);

      /* shift all entries one step down to the bottom of the history array */
      for(idx = MSTP_TC_HISTORY_MAX-1; idx > 0; idx--)
      {
         if(tcHistory[idx-1].valid == TRUE)
         {
            tcHistory[idx] = tcHistory[idx-1];
         }
      }

      /* store new info in the first entry of the history array */
      idx = 0;
      tcHistory[idx].lport = lport;

      commPortPtr = MSTP_COMM_PORT_PTR(lport);
      STP_ASSERT(commPortPtr);

      if(mstid == MSTP_CISTID)
      {
         /* The last Port history change is a cause for this TC
          * which is stored in zeroth entry */
         tcHistory[idx].prevState = cistPortPtr->portHistory[0].oldState;
         tcHistory[idx].newState = cistPortPtr->portHistory[0].newState;
      }
      else
      {
         /* The last Port history change is a cause for this TC
          * which is stored in zeroth entry */
         tcHistory[idx].prevState = mstiPortPtr->portHistory[0].oldState;
         tcHistory[idx].newState = mstiPortPtr->portHistory[0].newState;
      }

      MAC_ADDR_COPY(commPortPtr->bpduSrcMac, tcHistory[idx].mac);
      tcHistory[idx].timeStamp = time(NULL);
      tcHistory[idx].valid = TRUE;
}

/**PROC+**********************************************************************
* Name:      mstp_getTcHistoryEntry
*
* Purpose:   Read an entry from the Root Changes History table
*
* Params:
*             mstid  -> MST instance ID
*             lport  -> Port number
*             originated -> Set to TRUE for TC originated history
*
* Returns:   TRUE if requested entry was found and contains valid information,
*            FALSE otherwise. Fills caller's provided place holders with the
*            data from the valid entry
*
* Globals:   mstp_CB
*
* Constraints:
**PROC-**********************************************************************/
bool
mstpGetTcHistoryEntry(bool                   originated,
                       MSTID_t                mstid,
                       uint32_t               idx,
                       MSTP_TC_HISTORY_t      *getEntry)
{
   bool                      found = FALSE;
   bool                      valid = FALSE;
   MSTP_TC_HISTORY_t          tcEntry;
   MSTP_CIST_INFO_t           *cistPtr;
   MSTP_MSTI_INFO_t           *mstiPtr;

   if (idx >= MSTP_TC_HISTORY_MAX)
   {
      STP_ASSERT(0);
      return FALSE;
   }

   STP_ASSERT(getEntry);

   if(!MSTP_ENABLED)
      return 0;


   if(mstid == MSTP_CISTID)
   {
      cistPtr = &mstp_Bridge.CistInfo;

      if(originated)
         tcEntry = cistPtr->tcOrigHistory[idx];
      else
         tcEntry = cistPtr->tcRcvHistory[idx];
   }
   else
   {
      mstiPtr = MSTP_MSTI_INFO(mstid);

      if(originated)
         tcEntry = mstiPtr->tcOrigHistory[idx];
      else
         tcEntry = mstiPtr->tcRcvHistory[idx];
   }

   valid = tcEntry.valid;
   if(valid)
   {
      found=TRUE;
   }

   if(found)
   {
      getEntry->lport     = tcEntry.lport;
      getEntry->timeStamp = tcEntry.timeStamp;
      MAC_ADDR_COPY(tcEntry.mac, getEntry->mac);
      getEntry->prevState = tcEntry.prevState;
      getEntry->newState  = tcEntry.newState;
   }

   return found;
}

/**PROC+*****************************************************************
 * Name:      mstp_updatePortOperEdgeState
 *
 * Purpose:   Put the edge port state in to MSTP message queue
 *
 * Params:  idx  -> Index to the bridge-id mapping tablea
 *          lport -> interface index
 *          state -> edge/non-egde
 *
 * Returns:   void
 **PROC-*****************************************************************/
void mstp_updatePortOperEdgeState(MSTID_t mstid, LPORT_t lport, bool state)
{
   MSTP_TREE_MSG_t *m = mstp_findMstiPortStateChgMsg(mstid);

   if(m == NULL)
   {
      m = calloc(1, sizeof(MSTP_TREE_MSG_t));
      m->mstid        = mstid;
      m->link.q_flink = NULL;
      m->link.q_blink = NULL;
      insqti_nodis(&MSTP_TREE_MSGS_QUEUE, &m->link);
   }
   if (state == TRUE)
   {
      set_port(&m->portsSetEdge, lport);
      clear_port(&m->portsClearEdge, lport);
   }
   else
   {
      set_port(&m->portsClearEdge, lport);
      clear_port(&m->portsSetEdge, lport);
   }
}
/**PROC+**********************************************************************
 * Name:     mstpIsDebugEventSet
 *
 * Purpose:  whether debug "event" logging is enabled on any of the instance ?
 *
 * Params:   void
 *
 * Returns:  TRUE/FALSE
 **PROC-**********************************************************************/
bool mstpIsDebugEventSet()
{
   uint16_t i   = 0;
   bool     ret = FALSE;
   if(mstp_debugEventCist)
   {
      ret = TRUE;
   }
   for(i = 1; i <= MSTP_INSTANCES_MAX; i++)
   {
#if OPS_MSTP_TODO
      if(isBitSet(&mstp_debugEventInstances.map,i, MSTP_MSTID_MAX))
      {
         ret = TRUE;
      }
#endif /*OPS_MSTP_TODO*/
   }
   return(ret);
}
/**PROC+**********************************************************************
 * Name:    mstpIsDebugPktSet
 *
 * Purpose:  whether debug "pkt" logging is enabled on any of the ports ?
 *
 * Params:   void
 *
 * Returns:  TRUE/FALSE
 **PROC-**********************************************************************/

bool mstpIsDebugPktSet()
{
   uint32_t lport = 0, i = 0;
   bool ret = FALSE;

   if(are_any_ports_set(&mstp_debugPktEnabledForCist))
   {
      ret = TRUE;
   }
   for(lport = 1; IS_VALID_LPORT(lport); lport++)
   {
      for(i = 1; i <= MSTP_INSTANCES_MAX; i++)
      {
#if OPS_MSTP_TODO
         if(isBitSet(&mstp_debugPktEnabledInstances[lport].map,
                     i,MSTP_MSTID_MAX))
         {
            ret = TRUE;
         }
#endif /*OPS_MSTP_TODO*/
      }
   }
   return(ret);
}
/**PROC+**********************************************************************
 * Name:      mstpSetDebugEventInstances
 *
 * Purpose:   set/unset the instances on which debug logging has to be enabled.
 *            This is called by cli - "debug mstp events [instance <i>]
 *
 * Params:   instance, set/unset
 *
 * Returns:   void
 *
 **PROC-**********************************************************************/

void mstpSetDebugEventInstances(uint32_t instance, bool set )
{

   //uint16_t i = 0;


   if(instance == MSTP_CISTID)
   {
      if(set)
      {
         mstp_debugEventCist = TRUE ;
      }
      else
      {
         mstp_debugEventCist = FALSE ;
      }

   }
   else if (instance <= MSTP_INSTANCES_MAX)
   {
      if(set)
      {
         //setBit(&mstp_debugEventInstances.map,instance, MSTP_MSTID_MAX);
      }
      else
      {
         //clrBit(&mstp_debugEventInstances.map, instance, MSTP_MSTID_MAX);
      }
   }
   else /*for all instances*/
   {
      if(set)
      {
         mstp_debugEventCist = TRUE;

         //for(i = 1; i<= MSTP_INSTANCES_MAX; i++)
           // setBit(&mstp_debugEventInstances.map,i, MSTP_MSTID_MAX);
      }
      else
      {
         mstp_debugEventCist = FALSE ;

         //for(i = 1; i<= MSTP_INSTANCES_MAX; i++)
            //clrBit(&mstp_debugEventInstances.map,i, MSTP_MSTID_MAX);
      }

   }

   return ;
}

/**PROC+**********************************************************************
 * Name:      mstpSetDebugPktInstances
 *
 * Purpose:   set/unset the instances on which debug logging has to be enabled.
 *            This is  called by cli -
 *            "debug mstp packet ports <plist> [instance <i>]"
 *
 * Params:   port_list, instance, set/unset
 *
 * Returns:   void
 *
 **PROC-**********************************************************************/
void mstpSetDebugPktInstances(PORT_MAP *portMap, uint32_t instance, bool set)
{
   uint32_t lport;


   if(instance == MSTP_CISTID)
   {
      if(set)
      {
         bit_or_port_maps(portMap, &mstp_debugPktEnabledForCist);
      }
      else
      {
         if(!are_any_ports_set(portMap))
         {
            /* logging is disabled for CIST on all ports */
            clear_port_map(&mstp_debugPktEnabledForCist);
         }
         else
         {
            for(lport = (LPORT_t)find_first_port_set(portMap);
                IS_VALID_LPORT(lport);
                lport = (LPORT_t)find_next_port_set(portMap,lport))
            {
               clear_port(&mstp_debugPktEnabledForCist,lport);
            }
         }
      }

   }
   else if (instance <= MSTP_INSTANCES_MAX)
   {
      if(set)
      {
         bit_or_port_maps(portMap,&mstp_debugPktEnabledPorts);
         for(lport = (LPORT_t)find_first_port_set(portMap);
             IS_VALID_LPORT(lport);
             lport = (LPORT_t)find_next_port_set(portMap, lport))
         {
            //setBit(&mstp_debugPktEnabledInstances[lport].map,
            //       instance,MSTP_MSTID_MAX);
         }

      }
      else
      {
         for(lport = (LPORT_t)find_first_port_set(portMap);
             IS_VALID_LPORT(lport);
             lport = (LPORT_t)find_next_port_set(portMap, lport))
         {
            //clrBit(&mstp_debugPktEnabledInstances[lport].map,
            //       instance,MSTP_MSTID_MAX);
         }
      }

   }
   else /* for all instances*/
   {
      if(set)
      {
         /*update CIST data structures*/
         bit_or_port_maps(portMap, &mstp_debugPktEnabledForCist);

         for(lport = (LPORT_t)find_first_port_set(portMap);
          IS_VALID_LPORT(lport);
          lport = (LPORT_t)find_next_port_set(portMap, lport))
         {
            set_port(&mstp_debugPktEnabledPorts, lport);
            //for(i = 1; i <= MSTP_INSTANCES_MAX; i++)
               //setBit(&mstp_debugPktEnabledInstances[lport].map,
               //       i,MSTP_MSTID_MAX);
         }
      }
      else
      {
         /*update CIST data structures*/
         if(!are_any_ports_set(portMap))
         {
            /* logging is disabled for CIST on all ports */
            clear_port_map(&mstp_debugPktEnabledForCist);

            memset(&mstp_debugPktEnabledInstances,0,
                   sizeof(mstp_debugPktEnabledInstances));
            clear_port_map(&mstp_debugPktEnabledPorts);
         }
         else
         {
            for(lport = (LPORT_t)find_first_port_set(portMap);
                IS_VALID_LPORT(lport);
                lport = (LPORT_t)find_next_port_set(portMap, lport))
            {
               clear_port(&mstp_debugPktEnabledForCist,lport);
               clear_port(&mstp_debugPktEnabledPorts, lport);
              // for(i = 1; i <= MSTP_INSTANCES_MAX; i++)
              //    clrBit(&mstp_debugPktEnabledInstances[lport].map,
              //           i,MSTP_MSTID_MAX);
            }
         }
      }
   }

   return ;
}
/**PROC+*****************************************************************
 * Name: mstp_mapPortRole
 *
 * Purpose: to map the protocol values with MIB values.
 *
 * Params: Port Role.
 *
 * Returns: corresponding MIB values
 *
 **PROC-*****************************************************************/



uint32_t mstp_mapPortRole(uint32_t role)
{
   if(role == MSTP_PORT_ROLE_DISABLED||
      role == MSTP_PORT_ROLE_UNKNOWN)
   {
      //return D_hpicfMstpInstancePortRoleChangeCurrentPortRole_disabled;
      return 1;
   }
   else if (role == MSTP_PORT_ROLE_BACKUP)
   {
      //return D_hpicfMstpInstancePortRoleChangeCurrentPortRole_backup;
      return 5;
   }
   else if(role == MSTP_PORT_ROLE_ALTERNATE)
   {
      //return D_hpicfMstpInstancePortRoleChangeCurrentPortRole_alternate;
      return 4;
   }
   else if (role == MSTP_PORT_ROLE_DESIGNATED)
   {
      return 3;
      //return D_hpicfMstpInstancePortRoleChangeCurrentPortRole_designated;
   }
   else if(role == MSTP_PORT_ROLE_ROOT)
   {
      return 2;
      //return D_hpicfMstpInstancePortRoleChangeCurrentPortRole_root;
   }
   else if (role == MSTP_PORT_ROLE_MASTER)
   {
      //return D_hpicfMstpInstancePortRoleChangeCurrentPortRole_boundary;
      return 6;
   }
   else
   {
      STP_ASSERT(0);
   }
   return 0;
}

/**PROC+**********************************************************************
 *Name:      stp_is_port_configurable
 *
 *Purpose:   check whether port is part of STP
 *
 *Params:    lport
 *
 *Returns:   TRUE/FALSE
 *
 **PROC-**********************************************************************/
bool stp_is_port_configurable(LPORT_t lport)
{
    bool res = FALSE;
   return res;
}

char *
date()
{
    /* Return the current date as incomplete ISO 8601 (2012-12-12T16:13:30) */
    static char date[] = "2012-12-12T16:13:30";
    time_t t = time(NULL);
    struct tm *tmp = localtime(&t);
    strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%S", tmp);
    return date;
}

void intf_get_port_name(LPORT_t lport, char *port_name)
{
    struct iface_data *idp = NULL;
    if ((lport > 0) && (lport <= MAX_LPORTS))
    {
        idp = find_iface_data_by_index(lport);
        if(idp == NULL)
        {
            STP_ASSERT(FALSE);
        }
        strncpy(port_name,idp->name,10);
    }
    else
    {
        STP_ASSERT(FALSE);
    }
}


bool intf_get_lport_speed_duplex(LPORT_t lport, SPEED_DPLX *sd)
{
    struct iface_data *idp = NULL;
    STP_ASSERT(sd);
    STP_ASSERT((lport != 0) && (lport <= MAX_LPORTS));

    if ((lport <= MAX_LPORTS))
    {
        idp = find_iface_data_by_index(lport);
        if(idp == NULL)
        {
            return FALSE;
        }
        sd->speed = idp->link_speed;
        sd->duplex = idp->duplex;
        return(TRUE);
    }
    return(FALSE);
}
int mstp_util_get_valid_l2_ports(const struct ovsrec_bridge *bridge_row) {
    int i = 0, port_count = 0;

    if (!bridge_row){
        VLOG_INFO("Invalid Input %s:%d", __FILE__, __LINE__);
        STP_ASSERT(0);
        return port_count;
    }

    for (i = 0; i < bridge_row->n_ports; i++) {
        if (!bridge_row->ports[i]){
            continue;
        }

        if (strcmp(bridge_row->ports[i]->name,"bridge_normal") == 0) {
            continue;
        }

        if (!mstpd_is_valid_port_row(bridge_row->ports[i])){
            /* port row not interested by mstp */
            continue;
        }
        port_count++;
    }
    return port_count;
}
