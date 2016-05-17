/*
 * (c) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
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
#ifndef __MSTP_FSM__H__
#define __MSTP_FSM__H__

#include <dynamic-string.h>
#include <vswitch-idl.h>
#include <openvswitch/vlog.h>
#include "mstp_cmn.h"
#include "mstp_recv.h"
#include <assert.h>

#define packed

/* enable structure packing */
#if !defined (__GNUC__)
#pragma pack(1)
#endif

/* some platforms require stronger medicine */
#if defined (__GNUC__)
#define PACKED  __attribute__((packed))
#else
#define PACKED
#endif

/* switch types */
typedef uint16_t PORT_t;         /* Generic port number (either an Lport or Pport    */
typedef PORT_t   LPORT_t;        /* logical port number  (1 to MAX_LPORTS)   */
typedef uint16_t VID_t;          /* Vlan ID (12 bit number 0 to 4095)        */
typedef uint16_t VLAN_GROUP_t;   /* vlan group number (1 to MAX_VLAN_GROUPS) */
typedef uint32_t PROTOCOL_TYPE_t;/* Protocol type (filters/QOS/etc)          */
typedef uint32_t IFINDEX_t;      /* interface index for end-points           */
typedef uint16_t TYP_LEN;
typedef uint8_t OCTET;

/* port number 1 to 255 for pports, 256 to 511 for lag */
#define MAX_PPORTS 255
#define MAX_LPORTS 512
#define MAX_ENTRIES_IN_POOL MAX_LPORTS
#define MAX_VLAN_ID 4095
#define MIN_VLAN_ID 1
#define Q_NULL NULL
#define PORTNAME_LEN 20
#define SIZEOF_LSAP_HDR 17
#define SIZEOF_ENET_HDR 14
#define PRIORITY_MULTIPLIER 4096
#define PORT_PRIORITY_MULTIPLIER 16

#define IS_VALID_LPORT(lport) ((lport >= 1) && (lport <= MAX_LPORTS))
#define INTERNAL_VID (0x0fff) /* 4095 */

#define IS_VALID_VID(vid)          ((vid >= MIN_VLAN_ID) && (vid <= MAX_VLAN_ID))
 /* Port bit map, one bit per port */
#define PORT_MAP_ARRAY_SIZE    ((MAX_LPORTS + 31) / 32)

typedef struct {
       uint32_t map[PORT_MAP_ARRAY_SIZE];
} PORT_MAP;

#define MSTI_MAP_ARRAY_SIZE  ((65+31)/32)

typedef struct {
    uint32_t map[MSTI_MAP_ARRAY_SIZE];
} MSTI_MAP;

typedef struct PORT_LIST {
    LPORT_t  count;          /* number of ports in message           */
    LPORT_t  first_port;     /* port number of first port in message */
    PORT_MAP port_map;       /* port map of ports in message         */
} PORT_LIST;

/* Mac address definition */
typedef uint8_t MAC_ADDRESS[6];

typedef struct queue_thread {
      struct queue_thread *q_flink; /* forward link */
        struct queue_thread *q_blink; /* backward link */
} QUEUE_THREAD;

typedef struct queue_thread QUEUE_HEAD; /* same as a thread */
#pragma pack(push,1)
typedef struct LSAP_HDR
{
    MAC_ADDRESS   dst;         /* destination MAC address */
    MAC_ADDRESS   src;         /* source MAC address */
    TYP_LEN       len;         /* type field / length field */
    OCTET         dsap;        /* destination service access point */
    OCTET         ssap;        /* source service access point */
    OCTET         ctrl;        /* short ctrl values */
} LSAP_HDR;
#pragma pack(pop)
#define ENET_ADDR_SIZE 6
#define VLAN_ID_MAP_ARRAY_SIZE ((MAX_VLAN_ID + 31) / 32)
typedef struct
{
       uint32_t vidMap[VLAN_ID_MAP_ARRAY_SIZE];
} VID_MAP;

typedef uint8_t* struct_handle_t;
typedef uint8_t* hash_handle_t;
typedef uint8_t* throttle_handle_t;


typedef enum PORT_DUPLEX {HALF_DUPLEX = 1,
                              FULL_DUPLEX} PORT_DUPLEX;
/*
 * defines for reporting speed to other modules
 */
typedef enum PPORT_SPEED
{
    SPEED_NONE     = 0,        /* speed not available (port down) */
    SPEED_10MB     = 10,       /* 10Mbps speed */
    SPEED_100MB    = 100,      /* 100Mbps speed */
    SPEED_1000MB   = 1000,     /* 1000Mbps speed */
    SPEED_2500MB   = 2500,     /* 2500Mbps speed */
    SPEED_4000MB   = 4000,     /* 4000Mbps speed */
    SPEED_5000MB   = 5000,     /* 5000Mbps speed */
    SPEED_10000MB  = 10000,    /* 10000Mbps speed */
    SPEED_40000MB  = 40000     /* 40000Mbps speed */
} PPORT_SPEED_t;


/* when ports come up, IDL includes the speed and dplx of each port */
typedef struct SPEED_DPLX {
        PPORT_SPEED_t   speed;
        PORT_DUPLEX  duplex;
} SPEED_DPLX;
#define MAX_VLANS 256
#define VLAN_MAP_ARRAY_SIZE    ((MAX_VLANS + 31) / 32)

typedef struct {
       uint32_t vmap[VLAN_MAP_ARRAY_SIZE];
} VLAN_MAP;

bool insqti_nodis(QUEUE_HEAD *head, QUEUE_THREAD *newItem);
QUEUE_THREAD *qfirst_nodis(const QUEUE_HEAD *head);
QUEUE_THREAD *qnext_nodis(const QUEUE_HEAD *head, const QUEUE_THREAD *currentItem);
bool remqhere_nodis(QUEUE_HEAD *head, QUEUE_THREAD *currentItem);
bool qempty(const QUEUE_HEAD *head);
QUEUE_THREAD *qfirst(const QUEUE_HEAD *head);
QUEUE_THREAD *remqhi(QUEUE_HEAD *head);
QUEUE_THREAD *remqhi_nodis(QUEUE_HEAD *head);
void inique(QUEUE_HEAD *head);
void inique_nodis(QUEUE_HEAD *head);

#define MSTP_MAX_CONFIG_NAME_LEN    32
#define DEF_ADMIN_STATUS            false
#define DEF_HELLO_TIME              2
#define DEF_FORWARD_DELAY           15
#define DEF_ADMIN_EDGE              false
#define DEF_BPDU_STATUS             false
#define DEF_BRIDGE_PRIORITY         8
#define DEF_MAX_AGE                 20
#define DEF_HOLD_COUNT              6
#define DEF_MAX_HOPS                20
#define DEF_CONFIG_REV              "0"
#define DEF_MSTP_PORT_PRIORITY      8
#define DEF_MSTP_COST               20000
#define DEF_LINK_TYPE               "point_to_point"
#define BLOCK_ALL_MSTP              "block_all_mstp"

/*********** MSTP_CONFIG OF BRIDGE TABLE **************************/
#define MSTP_STATE_BLOCK           "Blocking"
#define MSTP_STATE_LEARN           "Learning"
#define MSTP_STATE_FORWARD         "Forwarding"
#define MSTP_STATE_DISABLE         "Disabled"

#define MSTP_ROLE_ROOT             "Root"
#define MSTP_ROLE_DESIGNATE        "Designated"
#define MSTP_ROLE_ALTERNATE        "Alternate"
#define MSTP_ROLE_BACKUP           "Backup"
#define MSTP_ROLE_DISABLE          "Disabled"
#define MSTP_ROLE_MASTER           "Master"

/*********** MSTP_CONFIG OF BRIDGE TABLE **************************/
#define MSTP_ADMIN_STATUS           "mstp_MSTP_ADMIN_STATUS"
#define MSTP_HELLO_TIME             "mstp_hello_time"
#define MSTP_FORWARD_DELAY          "mstp_forward_delay"
#define MSTP_MAX_AGE                "mstp_max_age"
#define MSTP_TX_HOLD_COUNT_DB       "mstp_tx_hold_count"
#define MSTP_MAX_HOP_COUNT          "mstp_maximum_hop_count"
#define MSTP_BRIDGE_PRIORITY        "mstp_priority"
#define MSTP_PORT_PRIORITY          "mstp_port_priority"
#define MSTP_PORT_COST              "mstp_admin_path_cost"
#define MSTP_CONFIG_REV             "mstp_config_revision"
#define MSTP_CONFIG_NAME            "mstp_config_name"
#define MSTP_INSTANCE_CONFIG        "mstp_instances_configured"
#define MSTP_TX_BPDU                "mstp_tx_bpdu"
#define MSTP_RX_BPDU                "mstp_rx_bpdu"

/************ MSTP_CONFIG OF PORT TABLE **************************/

#define MSTP_ADMIN_EDGE             "admin_edge_port"
#define MSTP_BPDU_FILTER            "bpdu-filter"
#define MSTP_BPDU_GUARD             "bpdu-guard"
#define MSTP_LOOP_GUARD             "loop-guard"
#define MSTP_ROOT_GUARD             "root-guard"
#define MSTP_OPER_EDGE              "oper_edge_port"


/************ mstp_msti_config TABLE **************************/

#define MSTP_INSTANCE_ID            "mstp_instid"
#define MSTP_VLANS                  "mstp_vlans"
#define STG_ID                      "mstp_stg"
#define DESIGNATED_ROOT             "mstp_designated_root"
#define ROOT_PATH_COST              "mstp_root_path_cost"
#define ROOT_PORT                   "mstp_root_port"
#define ROOT_PRIORITY               "mstp_root_priority"
#define REMAINING_HOPS              "mstp_remaing_hops"
#define TIME_SINCE_TOP_CHANGE       "mstp_time_since_top_change"
#define TOP_CHANGE_CNT              "mstp_top_change_cnt"
#define OPER_HELLO_TIME             "mstp_oper_hello_time"
#define OPER_FORWARD_DELAY          "mstp_oper_forward_delay"
#define OPER_MAX_AGE                "mstp_oper_max_age"
#define OPER_TX_HOLD_COUNT          "mstp_oper_tx_hold_count"
#define HELLO_EXPIRY_TIME           "mstp_hello_expiry_time"
#define FORWARD_DELAY_EXP_TIME      "mstp_forward_delay_expiry_time"
#define MESSAGE_EXP_TIME            "mstp_messageage_expiry_time"
#define TOPO_CHANGE_EXP_TIME        "mstp_topology_change_expirty_time"
#define NOTIFICATION_EXP_TIME       "mstp_notification_expiry_time"
#define HOLD_TIMER_EXP_TIME         "mstp_hold_timer_expiry_time"
#define CIST_PATH_POST              "mstp_cist_path_cost"
#define REGIONAL_ROOT               "mstp_regional_root"
#define PORT_ROLE                   "mstp_port_role"
#define PORT_STATE                  "mstp_port_state"
#define LINK_TYPE                   "mstp_link_type"
#define CIST_REGIONAL_ROOT_ID       "mstp_cist_regional_root_id"
#define CIST_PATH_COST              "mstp_cist_path_cost"
#define PORT_PATH_COST              "mstp_port_path_cost"
#define DESIGNATED_PATH_COST        "mstp_designated_path_cost"
#define DESIGNATED_BRIDGE           "mstp_designated_bridge"
#define DESIGNATED_PORT             "mstp_designated_port"
#define PORT_HELLO_TIME             "mstp_port_hello_time"
#define BRIDGE_IDENTIFIER           "mstp_bridge_identifier"
#define TOPOLOGY_CHANGE             "mstp_topology_change"
#define DESIGNATED_ROOT_PRIORITY    "mstp_designated_root_priority"
#define DESIGNATED_COST             "mstp_designated_cost"
#define DESIGNATED_BRIDGE_PRIORITY  "mstp_designated_bridge_priority"

#define ENET_MIN_PKT_SIZE 64
#define ENET_HDR_SIZ      14
#define ENET_CRC_LEN       4
#define ETHERMIN (ENET_MIN_PKT_SIZE - ENET_HDR_SIZ - ENET_CRC_LEN)  /* 46 */

#define PRINT_MAC_ADDR(a)       \
        *((u_char *)(a)),   *((u_char *)(a)+1), *((u_char *)(a)+2), \
    *((u_char *)(a)+3), *((u_char *)(a)+4), *((u_char *)(a)+5)

#define MAC_ADDR_COPY(from, to) \
        (memcpy((char *)(to), (char *)(from), ENET_ADDR_SIZE))

#define MAC_ADDRS_COMPARE(a, b) \
        (memcmp((char *)(a), (char *)(b), ENET_ADDR_SIZE))

#define MAC_ADDR_INVERT(mac) \
        mac[0] = ~mac[0]; \
    mac[1] = ~mac[1]; \
    mac[2] = ~mac[2]; \
    mac[3] = ~mac[3]; \
    mac[4] = ~mac[4]; \
    mac[5] = ~mac[5];

#define IS_BPDU(a) \
                  ((MAC_ADDRS_COMPARE(a, stp_multicast) >= 0) \
                                 && (MAC_ADDRS_COMPARE(a, gvrp_multicast_mac) <= 0))
#define IS_IGMP_MULTICAST(a) \
            ((MAC_ADDRS_COMPARE(a, Igmp_mac_addr_low) >= 0) \
                      && (MAC_ADDRS_COMPARE(a, Igmp_mac_addr_high) <= 0))
#ifdef STRICT_ALIGNMENT

#define IS_BROADCAST(a)  \
        (MAC_ADDRS_EQUAL((a), bcastMAC))

#define SET_BROADCAST_ADDR(a) \
        (MAC_ADDR_COPY(bcastMAC, (a)))

#define IS_MULTICAST(a) \
        (*(uint8_t *)(a) & 0x01)

#define IS_NULL_MAC(a)  \
        (MAC_ADDRS_EQUAL((a), nullMAC))

#define CLEAR_MAC_ADDR(a) \
        (MAC_ADDR_COPY( nullMAC, (a)))

#define MAC_ADDRS_EQUAL(a, b) \
        (! MAC_ADDRS_COMPARE((a), (b)))

#else /* STRICT_ALIGNMENT */


#define IS_BROADCAST(a) \
        (*(uint32_t *)(a) == (uint32_t) ~0 \
              && *(uint16_t *)((char *)(a) + sizeof(uint32_t)) == (uint16_t) ~0)

#define SET_BROADCAST_ADDR(a) \
        (*(uint32_t *)(a) = 0xffffffff, \
              *(uint16_t *)((char *)(a) + sizeof(uint32_t)) = 0xffff)

#define IS_MULTICAST(a) \
        (*(uint8_t *)(a) & 0x01)

#define IS_NULL_MAC(a)  \
        (*(uint32_t *)(a) == (uint32_t) 0 \
              && *(uint16_t *)((char *)(a) + sizeof(uint32_t)) == (uint16_t) 0)

#define MAC_ADDRS_EQUAL(a, b) \
        ((*(uint32_t *)(a) == *(uint32_t *)(b)) \
              && (*(uint16_t *)((char *)(a) + sizeof(uint32_t)) \
                                               == *(uint16_t *)((char *)(b) + sizeof(uint32_t))))

#define CLEAR_MAC_ADDR(a) \
        (*(uint32_t *)(a) = 0x0, \
              *(uint16_t *)((char *)(a) + sizeof(uint32_t)) = 0x0)

#endif  /* else STRICT_ALIGNMENT */

#define getShortFromPacket(shortPtr)                   \
       (uint16_t)(((*(uint8_t *)(shortPtr)) << 8) |        \
                            (*(((uint8_t *)(shortPtr)) + 1)))

#define getLongFromPacket(longPtr) \
       (uint32_t)(((*(uint8_t *)(longPtr)) << 24)        | \
                            ((*(((uint8_t *)(longPtr)) + 1)) << 16) | \
                            ((*(((uint8_t *)(longPtr)) + 2)) << 8)  | \
                            (*(((uint8_t *)(longPtr)) + 3)))

/* link header formats */
typedef uint16_t    TYP_LEN;        /* enet type size = 802.3 length size */
typedef TYP_LEN    ETHER_TYPE;
typedef ETHER_TYPE TAG_ETH_TYPE;   /* tag type is just another Ether type */
typedef uint16_t    TAG_INFO;       /* tag info contains vlan tag, priority*/

typedef struct ENET_HDR
{
  MAC_ADDRESS   dst;        /* destination MAC address */
  MAC_ADDRESS   src;        /* source MAC address */
  ETHER_TYPE    type;       /* type field / length field */
} ENET_HDR;

#define GET_PKT_LOGICAL_PORT(pkt)       ((pkt) -> lport)

#define SNAP        0x03        /* snap with short 802.2 header */
/*****************************************************************************
 *  *        Macros Definition
 *   *****************************************************************************/
/*---------------------------------------------------------------------------
 * Operation Codes used by Multiple Instance Spanning Tree Protocol
 *---------------------------------------------------------------------------*/
MAC_ADDRESS stp_multicast;

/*---------------------------------------------------------------------------
 * Maximum length of the MST Region Name
 *---------------------------------------------------------------------------*/
#define MSTP_MAX_REG_NAME_LEN 32

/*---------------------------------------------------------------------------
 * Current limit for MST Instances supported by the MST Bridge.
 * NOTE: No more than 64 MSTI Configuration Messages may be encoded in an
 *       MST BPDU, and no more than 64 MSTIs may be supported by an MST
 *       Bridge. In 'mstp_init' function there is an assert to check that
 *       MSTP_INSTANCES_MAX <= 64.
 *       (P802.1Q-REV/D5.0 13.14)
 *---------------------------------------------------------------------------*/
#define MSTP_INSTANCES_MAX          64

/*---------------------------------------------------------------------------
 *  * MST Instance Identifiers ranges
 *   *---------------------------------------------------------------------------*/
#define MSTP_CISTID                 0
#define MSTP_MSTID_MIN              1
#define MSTP_MSTID_MAX              MSTP_INSTANCES_MAX
#define MSTP_NO_MSTID               255
#define MSTP_NON_STP_BRIDGE         255
#define MSTP_VALID_MSTID(mstid) \
    (((mstid) >= MSTP_MSTID_MIN) && ((mstid) <= MSTP_MSTID_MAX))

/*---------------------------------------------------------------------------
 *  * The value of CTRL field in LSAP header used by MSTP
 *   *---------------------------------------------------------------------------*/
#define MSTP_LSAP_HDR_CTRL_VAL     0x03


/*---------------------------------------------------------------------------
 *  * Default values used in configuration file,
 *   * values are defined in IEEE P802.1w Table 17-6
 *    *
 *     * IEEE 802.1t-2001 standard uses the computation 20,000,000/port speed in Mbps
 *      *
 *       * E.g for 40G, port speed in Mbps is 40000
 *        *
 *         * path cost for 40G = 20,000,000/40,000
 *          *                   = 500
 *           *---------------------------------------------------------------------------*/
#define MSTP_PORT_PATH_COST_ETHERNET   2000000
#define MSTP_PORT_PATH_COST_100MB      200000
#define MSTP_PORT_PATH_COST_1000MB     20000
#define MSTP_PORT_PATH_COST_2500MB     8000
#define MSTP_PORT_PATH_COST_5000MB     4000
#define MSTP_PORT_PATH_COST_10000MB    2000
#define MSTP_PORT_PATH_COST_40000MB    500
#define MSTP_PORT_PATH_COST_AUTO       0 /* Indicates that switch determines
                                          * the path cost dynamically (auto) */

/*---------------------------------------------------------------------------
 *  * Default values used in configuration file,
 *   * values are defined as per proprietary standard
 *    *---------------------------------------------------------------------------*/
#define MSTP_PROP_PORT_PATH_COST_ETHERNET   2000
#define MSTP_PROP_PORT_PATH_COST_100MB      200
#define MSTP_PROP_PORT_PATH_COST_1000MB     20
#define MSTP_PROP_PORT_PATH_COST_2500MB     8
#define MSTP_PROP_PORT_PATH_COST_5000MB     4
#define MSTP_PROP_PORT_PATH_COST_10000MB    2
#define MSTP_PROP_PORT_PATH_COST_40000MB    1

/*---------------------------------------------------------------------------
 *  * MSTP protocol defaults
 *   *---------------------------------------------------------------------------*/
#define MSTP_DEF_BRIDGE_PRIORITY 32768
#define MSTP_DEF_PORT_PRIORITY   128
#define MSTP_DEF_TRUNK_PRIORITY  64
#define MSTP_MAX_PORT_PRIORITY   240

/*---------------------------------------------------------------------------
 *  * The part of VID map MIB obj limit (1/4 of the VID map) and
 *   * other limitations
 *    *---------------------------------------------------------------------------*/
#define MSTP_VLAN_MAP_SIZE 128
#define MSTP_VLAN_MAPS_NUM 4
#define MSTP_VLAN_MAP_BITS 1024

/*---------------------------------------------------------------------------
 *  * Following defines the default value for MSTP/RSTP BPDU Proteciton to
 *   * re-enable a port. 0 means, disable forever.
 *    *---------------------------------------------------------------------------*/
#define STP_BPDU_PROTECTION_DEFAULT_TIMEOUT 0

/*****************************************************************************
 *  *        MSTP Data Structures and Types Definition
 *   *****************************************************************************/
/*---------------------------------------------------------------------------
 *  * Used to identify type of the Spanning Tree, which is one of the following:
 *   *  CST  - Common Spanning Tree
 *    *  IST  - Internal Spanning Tree
 *     *  MSTI - Tree associated with an MST Instance
 *      *---------------------------------------------------------------------------*/
typedef enum
{
    MSTP_TREE_TYPE_UNKNOWN = 0, /*  0 */
    MSTP_TREE_TYPE_CST,         /*  1 */
    MSTP_TREE_TYPE_IST,         /*  2 */
    MSTP_TREE_TYPE_MST,         /*  3 */
    MSTP_TREE_TYPE_MAX          /*  4 */

} MSTP_TREE_TYPE_t;

/*---------------------------------------------------------------------------
 *  * Used to represent the scope of collected debug information, e.g. the whole
 *   * Bridge, or the CIST, or all MSTIs, or the CIST and all MSTIs, or all Ports
 *    * NOTE: please update 'cv_mstp_dbg_cnt_scope' (cet_stp.c) if you modify this
 *     *       enumeration list
 *      *---------------------------------------------------------------------------*/
typedef enum
{
    MSTP_DBG_CNT_SCOPE_UNKNOWN = 0, /* 0 */
    MSTP_DBG_CNT_SCOPE_BRIDGE,      /* 1 */
    MSTP_DBG_CNT_SCOPE_CIST,        /* 2 */
    MSTP_DBG_CNT_SCOPE_MSTIS,       /* 3 */
    MSTP_DBG_CNT_SCOPE_CIST_MSTIS,  /* 4 */
    MSTP_DBG_CNT_SCOPE_PORTS,       /* 5 */
    MSTP_DBG_CNT_SCOPE_MAX          /* 6 */

} MSTP_DBG_CNT_SCOPE_t;

/*---------------------------------------------------------------------------
 *  * Used to identify type of Debug Information maintained for this MSTP Bridge
 *   * NOTE: please update 'cv_mstp_comm_dbg_cnt_name' (cet_stp.c) if you
 *    *       change this enumeration list
 *     *---------------------------------------------------------------------------*/

typedef enum
{
    MSTP_BRIDGE_DBG_CNT_UNKNOWN = 0,                      /*  0 */
    /*
     *     * Debug Counters maintained on a per-instance/per-port basis
     *         */
    MSTP_BRIDGE_DBG_CNT_INVALID_BPDUS,                    /*  1 */
    MSTP_BRIDGE_DBG_CNT_ERRANT_BPDUS,                     /*  2 */
    MSTP_BRIDGE_DBG_CNT_MST_CFG_ERROR_BPDUS,              /*  3 */
    MSTP_BRIDGE_DBG_CNT_LOOPED_BACK_BPDUS,                /*  4 */
    MSTP_BRIDGE_DBG_CNT_STARVED_BPDUS_MSTI_MSGS,          /*  5 */
    MSTP_BRIDGE_DBG_CNT_EXCEEDED_MAX_AGE_BPDUS,           /*  6 */
    MSTP_BRIDGE_DBG_CNT_EXCEEDED_MAX_HOPS_BPDUS_MSTI_MSGS,/*  7 */
    MSTP_BRIDGE_DBG_CNT_TC_DETECTED,                      /*  8 */
    MSTP_BRIDGE_DBG_CNT_TC_FLAGS_TX,                      /*  9 */
    MSTP_BRIDGE_DBG_CNT_TC_FLAGS_RX,                      /* 10 */
    MSTP_BRIDGE_DBG_CNT_TC_ACK_FLAGS_TX,                  /* 11 */
    MSTP_BRIDGE_DBG_CNT_TC_ACK_FLAGS_RX,                  /* 12 */
    MSTP_BRIDGE_DBG_CNT_TCN_BPDUS_TX,                     /* 13 */
    MSTP_BRIDGE_DBG_CNT_TCN_BPDUS_RX,                     /* 14 */
    MSTP_BRIDGE_DBG_CNT_CFG_BPDUS_TX,                     /* 15 */
    MSTP_BRIDGE_DBG_CNT_CFG_BPDUS_RX,                     /* 16 */
    MSTP_BRIDGE_DBG_CNT_RST_BPDUS_TX,                     /* 17 */
    MSTP_BRIDGE_DBG_CNT_RST_BPDUS_RX,                     /* 18 */
    MSTP_BRIDGE_DBG_CNT_MST_BPDUS_MSTI_MSGS_TX,           /* 19 */
    MSTP_BRIDGE_DBG_CNT_MST_BPDUS_MSTI_MSGS_RX,           /* 20 */
    MSTP_BRIDGE_DBG_CNT_TYPE_MAX                          /* 21 */

} MSTP_BRIDGE_DBG_CNT_TYPE_t;

/*---------------------------------------------------------------------------
 *  * Used to identify type of Debug Information maintained for the CIST
 *   * (Common and Internal Spanning Tree)
 *    * NOTE: please update 'cv_mstp_cist_dbg_cnt_name' (cet_stp.c) if you
 *     *       change this enumeration list
 *      *---------------------------------------------------------------------------*/

typedef enum
{
    MSTP_CIST_DBG_CNT_UNKNOWN = 0,             /*  0 */
    /*
     *     * CIST's Debug Counters maintained on a per-port basis
     *         */
    MSTP_CIST_DBG_CNT_INVALID_BPDUS,           /*  1 */
    MSTP_CIST_DBG_CNT_ERRANT_BPDUS,            /*  2 */
    MSTP_CIST_DBG_CNT_MST_CFG_ERROR_BPDUS,     /*  3 */
    MSTP_CIST_DBG_CNT_LOOPED_BACK_BPDUS,       /*  4 */
    MSTP_CIST_DBG_CNT_STARVED_BPDUS,           /*  5 */
    MSTP_CIST_DBG_CNT_EXCEEDED_MAX_AGE_BPDUS,  /*  6 */
    MSTP_CIST_DBG_CNT_EXCEEDED_MAX_HOPS_BPDUS, /*  7 */
    MSTP_CIST_DBG_CNT_TC_DETECTED,             /*  8 */
    MSTP_CIST_DBG_CNT_TC_FLAGS_TX,             /*  9 */
    MSTP_CIST_DBG_CNT_TC_FLAGS_RX,             /* 10 */
    MSTP_CIST_DBG_CNT_TC_ACK_FLAGS_TX,         /* 11 */
    MSTP_CIST_DBG_CNT_TC_ACK_FLAGS_RX,         /* 12 */
    MSTP_CIST_DBG_CNT_TCN_BPDUS_TX,            /* 13 */
    MSTP_CIST_DBG_CNT_TCN_BPDUS_RX,            /* 14 */
    MSTP_CIST_DBG_CNT_CFG_BPDUS_TX,            /* 15 */
    MSTP_CIST_DBG_CNT_CFG_BPDUS_RX,            /* 16 */
    MSTP_CIST_DBG_CNT_RST_BPDUS_TX,            /* 17 */
    MSTP_CIST_DBG_CNT_RST_BPDUS_RX,            /* 18 */
    MSTP_CIST_DBG_CNT_MST_BPDUS_TX,            /* 19 */
    MSTP_CIST_DBG_CNT_MST_BPDUS_RX,            /* 20 */
    MSTP_CIST_DBG_CNT_TYPE_MAX                 /* 21 */

} MSTP_CIST_DBG_CNT_TYPE_t;

/*---------------------------------------------------------------------------
 *  * Used to identify type of Debug information maintained for an MSTI
 *   * NOTE: please update 'cv_mstp_msti_dbg_cnt_name' (cet_stp.c) if you
 *    *       change this enumeration list
 *     *---------------------------------------------------------------------------*/
typedef enum
{
    MSTP_MSTI_DBG_CNT_UNKNOWN = 0,                 /*  0 */
    /*
     *     * MSTI's Debug Counters maintained on a per-port basis
     *         */
    MSTP_MSTI_DBG_CNT_STARVED_MSTI_MSGS,           /*  1 */
    MSTP_MSTI_DBG_CNT_EXCEEDED_MAX_HOPS_MSTI_MSGS, /*  2 */
    MSTP_MSTI_DBG_CNT_TC_DETECTED,                 /*  3 */
    MSTP_MSTI_DBG_CNT_TC_FLAGS_TX,                 /*  4 */
    MSTP_MSTI_DBG_CNT_TC_FLAGS_RX,                 /*  5 */
    MSTP_MSTI_DBG_CNT_MSTI_MSGS_TX,                /*  6 */
    MSTP_MSTI_DBG_CNT_MSTI_MSGS_RX,                /*  7 */
    MSTP_MSTI_DBG_CNT_TYPE_MAX                     /*  8 */

} MSTP_MSTI_DBG_CNT_TYPE_t;

/* structure to hold instance independent counters */

typedef struct mstpCntrs {

    uint32_t invalidBpduCnt;
    time_t invalidBpduCntLastUpdated;
    uint32_t errantBpduCnt;
    time_t errantBpduCntLastUpdated;
    uint32_t mstCfgErrorBpduCnt;
    time_t mstCfgErrorBpduCntLastUpdated;
    uint32_t loopBackBpduCnt;
    time_t loopBackBpduCntLastUpdated;
    uint32_t starvedBpduCnt;
    time_t starvedBpduCntLastUpdated;
    uint32_t agedBpduCnt;
    time_t agedBpduCntLastUpdated;
    uint32_t exceededHopsBpduCnt;
    time_t exceededHopsBpduCntLastUpdated;
    uint32_t tcDetectCnt;
    time_t tcDetectCntLastUpdated;
    uint32_t tcFlagTxCnt;
    time_t tcFlagTxCntLastUpdated;
    uint32_t tcFlagRxCnt;
    time_t tcFlagRxCntLastUpdated;
    uint32_t tcAckFlagTxCnt;
    time_t tcAckFlagTxCntLastUpdated;
    uint32_t tcAckFlagRxCnt;
    time_t tcAckFlagRxCntLastUpdated;
    uint32_t mstBpduTxCnt;
    time_t mstBpduTxCntLastUpdated;
    uint32_t mstBpduRxCnt;
    time_t mstBpduRxCntLastUpdated;
    uint32_t rstBpduTxCnt;
    time_t rstBpduTxCntLastUpdated;
    uint32_t rstBpduRxCnt;
    time_t rstBpduRxCntLastUpdated;
    uint32_t cfgBpduTxCnt;
    time_t cfgBpduTxCntLastUpdated;
    uint32_t cfgBpduRxCnt;
    time_t cfgBpduRxCntLastUpdated;
    uint32_t tcnBpduTxCnt;
    time_t tcnBpduTxCntLastUpdated;
    uint32_t tcnBpduRxCnt;
    time_t tcnBpduRxCntLastUpdated;
} mstpCntrs_t;

/* structure to hold MSTP instance counters */

typedef struct mstpInstCntrs {

    uint32_t starvedMsgCnt;
    time_t starvedMsgCntLastUpdated;
    uint32_t exceededHopsMsgCnt;
    time_t exceededHopsMsgCntLastUpdated;
    uint32_t tcDetectCnt;
    time_t tcDetectCntLastUpdated;
    uint32_t tcFlagTxCnt;
    time_t tcFlagTxCntLastUpdated;
    uint32_t tcFlagRxCnt;
    time_t tcFlagRxCntLastUpdated;
    uint32_t mstiMsgTxCnt;
    time_t mstiMsgTxCntLastUpdated;
    uint32_t mstiMsgRxCnt;
    time_t mstiMsgRxCntLastUpdated;
} mstpInstCntrs_t;

uint32_t
mstp_getMstiPortDbgAllCntInfo(uint16_t mstid, LPORT_t lport,
        mstpCntrs_t *mCnt, mstpInstCntrs_t *mInstCnt);


/*****************************************************************************
 *  *        External Declarations
 *   *****************************************************************************/

/*---------------------------------------------------------------------------
 *  * Running STP implementation version
 *   * (0 -> 802.1d STP, 2 -> 802.1w RSTP, 3 -> 802.1s MSTP)
 *    * Variable is defined in 'rstp_init.c'
 *     *---------------------------------------------------------------------------*/
uint8_t Stp_version;

/*---------------------------------------------------------------------------
 *  * Functions prototypes
 *   *---------------------------------------------------------------------------*/

/*
 *  * mstp_init.c
 *   */
void mstpInitialInit();
/*
 *  * mstp_dyn_reconfig.c
 *   */
void mstp_adminStatusUpdate(int status);
void mstp_addLport(LPORT_t lport);
void mstp_removeLport(LPORT_t lport);
bool mstp_isp2pEnable(LPORT_t lport);
/*
 *  * mstp_util.c
 *   */

void     mstp_semTake();
void     mstp_semGive();
uint32_t mstp_convertLportSpeedToPathCost(SPEED_DPLX* speedDplx);
uint32_t mstp_rootChangesCounter(uint16_t mstid,
        MSTP_TREE_TYPE_t treeType);
void     mstp_rootBridgeId(uint16_t mstid, MSTP_TREE_TYPE_t treeType,
        MAC_ADDRESS mac_addr, uint16_t *priority);
bool     mstp_validRootHistoryEntry(uint16_t mstid,
        MSTP_TREE_TYPE_t treeType,
        uint32_t idx);
bool     mstp_portMstRgnBoundary(LPORT_t lport);
uint32_t mstp_portExternalRootPathCost(LPORT_t lport);
uint32_t mstp_portMstBpduTxCnt(LPORT_t lport);
uint32_t mstp_portMstBpduRxCnt(LPORT_t lport);
uint32_t mstp_portCfgBpduTxCnt(LPORT_t lport);
uint32_t mstp_portCfgBpduRxCnt(LPORT_t lport);
uint32_t mstp_portTcnBpduTxCnt(LPORT_t lport);
uint32_t mstp_portTcnBpduRxCnt(LPORT_t lport);
uint32_t mstp_portTcAckFlagTxCnt(LPORT_t lport);
uint32_t mstp_portTcAckFlagRxCnt(LPORT_t lport);
uint32_t mstp_portLoopBackBpduCnt(LPORT_t lport);
uint32_t mstp_portAgedBpduCnt(LPORT_t lport);
void     mstp_mstiPortRgnRootBridgeId(uint16_t mstid, LPORT_t lport,
        MAC_ADDRESS mac_addr,
        uint16_t *priority);
uint32_t mstp_mstiPortInternalRootPathCost(uint16_t mstid, LPORT_t lport);
void     mstp_mstiPortDsnBridgeId(uint16_t mstid, LPORT_t lport,
        MAC_ADDRESS mac_addr,
        uint16_t *priority);
uint16_t mstp_mstiPortDsnPortId(uint16_t mstid, LPORT_t lport);
uint32_t mstp_mstiPortTcDetectCnt(uint16_t mstid, LPORT_t lport);
uint32_t mstp_mstiPortTcFlagTxCnt(uint16_t mstid, LPORT_t lport);
uint32_t mstp_mstiPortTcFlagRxCnt(uint16_t mstid, LPORT_t lport);
uint32_t mstp_mstiPortExceededHopsBpduCnt(uint16_t mstid, LPORT_t lport);
bool     mstp_isLportFwdOnVlan(LPORT_t lport, VID_t vlan);
bool     mstp_isPortInBpduError(LPORT_t lport);
bool     mstp_get_bridge_oper_edge(LPORT_t lport);
uint32_t mstp_errantBpduCounter_get(LPORT_t lport);
int      mstp_countBpduFilters(void);
bool     mstp_getRootHistoryEntry(uint16_t mstid,
        MSTP_TREE_TYPE_t treeType,
        uint32_t idx,
        MAC_ADDRESS mac_addr,
        uint16_t *priority,
        time_t *timeStamp);
uint32_t mstp_getMstpBridgeDbgCntInfo(uint32_t cntType);
uint32_t mstp_getMstiDbgCntInfo(uint16_t mstid, uint32_t cntType);
uint32_t mstp_getMstiPortDbgCntInfo(uint16_t mstid, LPORT_t lport,
        uint32_t idx, time_t *timeStamp);
void     mstp_clrMstpBridgeDbgInfo(void);
void     mstp_clrMstiDbgCntsInfo(uint16_t mstid);
void     mstp_clrMstiPortDbgCntInfo(uint16_t mstid, LPORT_t lport);
MSTP_DBG_CNT_SCOPE_t
mstp_DbgCntScope(uint16_t mstid, uint32_t cntType);
void     mstp_getMstiVidMap(uint16_t mstid, VID_MAP *vidMap);
void     mstp_getMstiVidMapFromCfg(uint16_t mstid, VID_MAP *vidMap,
        bool pending);
uint16_t mstp_getMstIdForVid(VID_t vid);
uint16_t mstp_getMstIdForVidFromCfg(VID_t vid, bool pending);
void     mstp_printVidMap(VID_MAP *srcVidMap, uint16_t lineLen,
        uint16_t indent);
VID_t    mstp_vidMapToVidStr(VID_MAP *srcVidMap, char *buf,
        uint16_t bufLen);
void     mstp_convertVlanMstiMappingCfg(bool pending);
void     mstp_setDynReconfigChangeFlag(void);
bool isMstp64Instance(void);


/*****************************************************************************
 *        Macros Definition
 *****************************************************************************/

/*---------------------------------------------------------------------------
 * This macro enables/disables code used for debugging of operation of the
 * Multiple Spanning Tree Protocol.
 * NOTE: If code is compiled with this macro being enabled use 'mstpDbg'
 *       NCL command to see the list of all possible debug commands.
 *---------------------------------------------------------------------------*/
#if 1
#define MSTP_DEBUG
#endif

#define TRUE true
#define FALSE false

#define STP_PATH_COST_ETHERNET   100
#define STP_PATH_COST_100MB      10
#define STP_PATH_COST_1000MB     5
#define STP_PATH_COST_2500MB     4 /*used 4 to make it better than 1G and within the recommended range*/
#define STP_PATH_COST_5000MB     3 /*used 3 to make it better than 2.5G*/
#define STP_PATH_COST_10000MB    1
#define STP_PATH_COST_40000MB    1


/*standard mib*/

#define MSTP_MIN_COMPONENT_ID 1
#define MSTP_MAX_COMPONENT_ID 1
#define MSTP_ROOT_ID        100
/*------------------------------------------------------------------------
 * Defines for LOG mesage throttle
 *------------------------------------------------------------------------
 */
#define MSTP_MAX_LOG_LENGTH        150

#define MSTP_THROTTLE_HASH_TBL_SIZE      255
#define MSTP_THROTTLE_STRUCTS_PER_MALLOC 20
                                         /* # of structs per chunk for throttle*/
#define MSTP_THROTTLE_STRUCT_LIMIT       1000
                                         /* Max structs for throttle entries   */
#define MSTP_THROTTLE_MIN_FREE_STRUCTS   5
                                         /* Min free structs for throttle      */

#define MSTP_THROTTLE_STRUCT_S           "Throttle structure memmory\n"
#define MSTP_THROTTLE_HASH_S             "Throttle hash\n"
#define MSTP_THROTTLE_INFO_S             "Info log throttle\n"
#define MSTP_THROTTLE_WARN_S             "Warn log throttle\n"
#define MSTP_THROTTLE_ERROR_S            "Error log throttle\n"
#define MSTP_THROTTLE_CRIT_S             "Critical log throttle\n"

/* The following times are used to throttle issuing of identical logs*/
#define MSTP_INFO_LOG_TIME  1000/* min time interval in sec before
                                 * duplicate info log entries
                                 */
#define MSTP_WARN_LOG_TIME   600 /* min time interval in sec before
                                  * duplicate warn log entries
                                  */
#define MSTP_ERROR_LOG_TIME   60  /* min time interval in sec before
                                   * duplicate error log entries
                                   */
#define MSTP_CRIT_LOG_TIME     6 /* min time interval in sec before
                                  * duplicate crit log entries
                                  */

/*---------------------------------------------------------------------------
 * definitions of MSTP parameters max/min values
 *---------------------------------------------------------------------------*/
#define MSTP_HELLO_MIN_SEC                  1     /* in seconds */
#define MSTP_HELLO_MAX_SEC                  10    /* in seconds */
#define MSTP_FWD_DELAY_MIN_SEC              4     /* in seconds */
#define MSTP_FWD_DELAY_MAX_SEC              30    /* in seconds */

/*---------------------------------------------------------------------------
 * administrative status of MSTP protocol
 *---------------------------------------------------------------------------*/
#define MSTP_ADMIN_STATUS_ENABLE         1
#define MSTP_ADMIN_STATUS_DISABLE        2

/*---------------------------------------------------------------------------
 * Default VLANs group number (implicit VLAN group 0)
 *---------------------------------------------------------------------------*/
#define MSTP_VLAN_GROUP_CIST                0

/*---------------------------------------------------------------------------
 * MSTP timer tick interval
 *---------------------------------------------------------------------------*/
#define MSTP_ONE_SECOND                     1
#define MSTP_HUNDREDS_OF_SECOND             100

/*---------------------------------------------------------------------------
 * MSTP SMs performance parameters default values
 * (802.1D-2004 17.14)
 *---------------------------------------------------------------------------*/
#define MSTP_TX_HOLD_COUNT                 6 /* counter */
#define MSTP_MIGRATE_TIME_SEC              3 /* time in seconds */

/*---------------------------------------------------------------------------
 * Spanning Tree Family Protocols Identifier (common for STP, RSTP, MSTP)
 * as it is being carried in BPDUs (2 octets long)
 * (802.1Q-REV/D5.0 14.5)
 *---------------------------------------------------------------------------*/
#define MSTP_STP_RST_MST_PROTOCOL_ID        0x0000

/*---------------------------------------------------------------------------
 * Protocol Version IDs as transmitted in STP, RSTP and MSTP BPDUs
 * (1 octet long)
 * (802.1Q-REV/D5.0 14.5)
 *---------------------------------------------------------------------------*/
#define MSTP_PROTOCOL_VERSION_ID_STP        0x00
#define MSTP_PROTOCOL_VERSION_ID_RST        0x02
#define MSTP_PROTOCOL_VERSION_ID_MST        0x03

/*---------------------------------------------------------------------------
 * BPDU type values for STP, RSTP, MSTP as they are being carried in BPDUs
 * (1 octet long)
 * (802.1Q-REV/D5.0 14.5)
 *---------------------------------------------------------------------------*/
#define MSTP_BPDU_TYPE_STP_CONFIG           0x00
#define MSTP_BPDU_TYPE_STP_TCN              0x80
#define MSTP_BPDU_TYPE_RST                  0x02 /* identical to MSTP */
#define MSTP_BPDU_TYPE_MST                  0x02 /* identical to RSTP */

/*---------------------------------------------------------------------------
 * Used to encode values from the 'CIST Flags' field in the received BPDUs
 * (1 octet long)
 * (802.1Q-REV/D5.0 14.6)
 *---------------------------------------------------------------------------*/
#define MSTP_CIST_FLAG_TC                   0x01
#define MSTP_CIST_FLAG_PROPOSAL             0x02
#define MSTP_CIST_FLAG_PORT_ROLE            0x0c
#define MSTP_CIST_FLAG_LEARNING             0x10
#define MSTP_CIST_FLAG_FORWADING            0x20
#define MSTP_CIST_FLAG_AGREEMENT            0x40
#define MSTP_CIST_FLAG_TC_ACK               0x80

/*---------------------------------------------------------------------------
 * Used to encode values from the 'MSTI Flags' field in the received
 * MSTI Configuration Messages (1 octet long)
 * (802.1Q-REV/D5.0 14.6.1)
 *---------------------------------------------------------------------------*/
#define MSTP_MSTI_FLAG_TC                   0x01
#define MSTP_MSTI_FLAG_PROPOSAL             0x02
#define MSTP_MSTI_FLAG_PORT_ROLE            0x0c
#define MSTP_MSTI_FLAG_LEARNING             0x10
#define MSTP_MSTI_FLAG_FORWADING            0x20
#define MSTP_MSTI_FLAG_AGREEMENT            0x40
#define MSTP_MSTI_FLAG_MASTER               0x80

/*---------------------------------------------------------------------------
 * Used for manipulation with Port Role values carried in BPDUs
 * Port Role values carried in the 'CIST Flags' and 'MSTI Flags'
 * fields of the received BPDUs, are encoded in two consecutive flag bits:
 *                        +---------------+
 *                        | | | | |X|X| | |
 *                        +---------------+
 * (802.1Q-REV/D5.0 14.2.1)
 *---------------------------------------------------------------------------*/
#define MSTP_BPDU_ROLE_MASTER_PORT          0x00
#define MSTP_BPDU_ROLE_ALTERNATE_OR_BACKUP  0x04
#define MSTP_BPDU_ROLE_ROOT                 0x08
#define MSTP_BPDU_ROLE_DESIGNATED           0x0c

/*---------------------------------------------------------------------------
 * STP, RSTP, MSTP BPDUs minimal lengths (in octets)
 *---------------------------------------------------------------------------*/
#define MSTP_STP_TCN_BPDU_LEN_MIN           4
#define MSTP_STP_CONFIG_BPDU_LEN_MIN        35
#define MSTP_RST_BPDU_LEN_MIN               36
#define MSTP_MST_BPDU_LEN_MIN               102

/*---------------------------------------------------------------------------
 * Number of seconds to delay between SNMP Traps on a given ports
 *---------------------------------------------------------------------------*/
#define MSTP_ERRANT_BPDU_HOLD_TIME          30

/*---------------------------------------------------------------------------
 * Spanning Tree BPDUs length calculation
 *---------------------------------------------------------------------------*/
#define MSTP_BPDU_LENGTH(bpdu) \
(ntohs((bpdu)->lsapHdr.len) - (SIZEOF_LSAP_HDR - SIZEOF_ENET_HDR))

/*---------------------------------------------------------------------------
 * MSTI Configuration Messages (conveyed in MST BPDU) total length
 * calculation
 * NOTE: version 3 field of the MST BPDU contains the number of octets
 *       taken by the parameters that follow it in the BPDU. MSTI
 *       configuration messages are located at offset of 64 octets from
 *       the version 3 field in the MST BPDU.
 *---------------------------------------------------------------------------*/
#define MSTP_MSTI_CFG_MSGS_SIZE(bpdu) \
(ntohs(((MSTP_MST_BPDU_t *)(bpdu))->version3Length) - 64)

/*---------------------------------------------------------------------------
 * This macro sets the 4-bit priority component of a Bridge Identifier.
 * A Bridge Identifier consists of 8 octets: 4 most significant bits of the
 * most significant octet comrises a settable priority component that permits
 * the relative priority of Bridges to be managed. The next most significant
 * 12 bits comprise a locally assigned system ID extensions. The six least
 * significant octets are derived from the globally unique Bridge MAC Address.
 * Priority component takes the values in range of 0-61440 in steps of 4096.
 * (802.1Q-REV/D5.0 13.23.2).
 *
 *  |Priority(2 bytes)|Bridge MAC address(6 bytes)                          |
 *  +--------+--------+--------+--------+--------+--------+--------+--------+
 *  |Pri |Sys ID      |        |        |        |        |        |        |
 *  +--------+--------+--------+--------+--------+--------+--------+--------+
 *
 *---------------------------------------------------------------------------*/
#define MSTP_SET_BRIDGE_PRIORITY(bridgeId, value) \
((bridgeId).priority = (((value)/4096) << 12) | (((bridgeId).priority) & 0x0FFF))

/*---------------------------------------------------------------------------
 * This macro extracts the value of 4-bit priority component from the
 * Bridge Identifier.
 *---------------------------------------------------------------------------*/
#define MSTP_GET_BRIDGE_PRIORITY(bridgeId) \
((bridgeId).priority & 0xF000)

/*---------------------------------------------------------------------------
 * This macro sets the 12-bit system ID extension component of the 2 bytes
 * long 'Priority' component of the 8 bytes long Bridge Identifier
 * (802.1Q-REV/D5.0 13.23.2)
 *---------------------------------------------------------------------------*/
#define MSTP_SET_BRIDGE_SYS_ID(bridgeId, value) \
((bridgeId).priority = ((value & 0x0FFF)  | (((bridgeId).priority) & 0xF000)))

/*---------------------------------------------------------------------------
 * This macro extracts the value of 12-bit system ID extension component from
 * the Bridge Identifier.
 *---------------------------------------------------------------------------*/
#define MSTP_GET_BRIDGE_SYS_ID(bridgeId)    (((bridgeId).priority) & 0x0FFF)

/*---------------------------------------------------------------------------
 * This macro extracts the value of 12-bit system ID extension component from
 * the Bridge Identifier in a received packet.
 *---------------------------------------------------------------------------*/
#define MSTP_GET_BRIDGE_SYS_ID_FROM_PKT(bridgeId) \
(ntohs((bridgeId).priority) & 0x0FFF)

/*---------------------------------------------------------------------------
 * This macro sets the 12-bit port number component of a Port Identifier.
 * A Port Identifier consists of 2 octets: 4 most significant bits of the
 * most significant octet comrises a settable priority component that permits
 * the relative priority of Ports to be managed. The 12 lower bits contain a
 * logical port number.
 * (802.1Q-REV/D5.0 13.24.11)
 *
 *  |Pri |Port Number |
 *  +--------+--------+
 *  |        |        |
 *  +--------+--------+
 *
 *---------------------------------------------------------------------------*/
#define MSTP_SET_PORT_NUM(portId, value) \
((portId) = (((value) & 0x0FFF) | ((portId) & 0xF000)))

/*---------------------------------------------------------------------------
 * This macro extracts the value of 12-bit port number component from the 2
 * bytes long Port Identifier
 *---------------------------------------------------------------------------*/
#define MSTP_GET_PORT_NUM(portId)           ((portId) & 0x0FFF)

/*---------------------------------------------------------------------------
 * This macro sets the 4-bit priority component of the 2 bytes long
 * Port Identifier. Valid range of values is 0-15 (i.e. 0-240 in steps of 16)
 * (802.1Q-REV/D5.0 13.24.11)
 *---------------------------------------------------------------------------*/
#define MSTP_SET_PORT_PRIORITY(portId, value) \
((portId) = (((value/16) << 12) | ((portId) & 0x0FFF)))

/*---------------------------------------------------------------------------
 * This macro extracts the value of 4-bit priority component from the 2
 * bytes long Port Identifier
 *---------------------------------------------------------------------------*/
#define MSTP_GET_PORT_PRIORITY(portId)      (((portId) >> 8) & 0x00F0)

/*----------------------------------------------------------------------------
 * These macros are used for manipulation with elsments of the
 * MST Configuration Table.
 * This table is considered to contain 4096 consecutive two octet elements,
 * where each element of the table (with the exception of the first and last)
 * contains an MSTID value encoded as a binary number, with the first octet
 * being most significant. The first element of the table contains the value 0,
 * the second element the MSTID value corresponding to VID 1, the third element
 * the MSTID value corresponding to VID 2, and so on, with the next to last
 * element of the table containing the MSTID value corresponding to VID 4094,
 * and the last element containing the value 0
 * (802.1Q-REV/D5.0 13.7)
 *---------------------------------------------------------------------------*/
#define MSTP_MST_CFG_TBL_SIZE          4096 /* the number of elements in the
                                             * MST Configuration Table       */
#define MSTP_MST_CFG_TBL_FIRST_VID_IDX 1    /* 1-st element with MSTID value */
#define MSTP_MST_CFG_TBL_LAST_VID_IDX  4094 /* last element with MSTID value */
#define MSTP_MST_CFG_ELEM_SIZE         2    /* the length in octets of an
                                             * element in the MST Configuration
                                             * Table                         */

/*---------------------------------------------------------------------------
 * MST Configuration Identifier macros.
 * (802.1Q-REV/D5.0 13.7)
 *---------------------------------------------------------------------------*/
#define MSTP_DIGEST_KEY_LEN         16   /* the length of the key used to
                                          * generate the Configuration
                                          * Digest */
#define MSTP_DIGEST_SIZE            16   /* the size of the Configuration
                                          * Digest created from MST
                                          * Configuration Table */
#define MSTP_MST_CONFIG_NAME_LEN    32   /* the length of the Configuration Name
                                          * fixed field of the MST Configuration
                                          * Identifier data structure */

/*---------------------------------------------------------------------------
 * These macros are used for comparison of Spanning Tree Bridge ID components
 * of the priority vectors MSTP Bridge operates with
 *---------------------------------------------------------------------------*/
#define MSTP_BRIDGE_ID_LOWER(a,b)                                  \
((((a).priority < (b).priority)  ||                                \
  (((a).priority == (b).priority) &&                               \
   (MAC_ADDRS_COMPARE((a).mac_address, (b).mac_address) < 0)))?(true):(false))

#define MSTP_BRIDGE_ID_EQUAL(a,b)                                  \
((((a).priority == (b).priority)  &&                               \
  (MAC_ADDRS_EQUAL((a).mac_address, (b).mac_address))) ? (true) : (false))

/*---------------------------------------------------------------------------
 * Miscellaneous macros used to facilitate references
 *---------------------------------------------------------------------------*/
#define MSTP_FWD_LPORTS                (mstp_CB.fwdLports)
#define MSTP_BLK_LPORTS                (mstp_CB.blkLports)
#define MSTP_MSGS                      (mstp_CB.msgs)
#define MSTP_TREE_MSGS_QUEUE           (mstp_CB.msgs.treeMsgQueue)
#define STP_PROTOCOL_VERSION_MSTP      3
#define MSTP_ENABLED \
((Spanning == true) && (Stp_version == STP_PROTOCOL_VERSION_MSTP))

#define MSTP_BEGIN                     (mstp_Bridge.BEGIN)
#define MSTP_DYN_RECONFIG_CHANGE       (mstp_Bridge.dynReconfig)
#define MSTP_NUM_OF_VALID_TREES        (mstp_Bridge.numOfValidTrees)

#define MSTP_CIST_INFO                 (mstp_Bridge.CistInfo)
#define MSTP_CIST_ROOT_TIMES           (MSTP_CIST_INFO.rootTimes)
#define MSTP_CIST_ROOT_HELLO_TIME      (MSTP_CIST_INFO.cistRootHelloTime)
#define MSTP_CIST_BRIDGE_TIMES         (MSTP_CIST_INFO.BridgeTimes)
#define MSTP_CIST_ROOT_PORT_ID         (MSTP_CIST_INFO.rootPortID)
#define MSTP_CIST_ROOT_PRIORITY        (MSTP_CIST_INFO.rootPriority)
#define MSTP_CIST_BRIDGE_PRIORITY      (MSTP_CIST_INFO.BridgePriority)
#define MSTP_CIST_BRIDGE_IDENTIFIER    (MSTP_CIST_INFO.BridgeIdentifier)
#define MSTP_CIST_PORT_STATE_CHANGE    (MSTP_CIST_INFO.portStateChangeLog)
#define MSTP_CIST_TC_TRAP_CONTROL      (MSTP_CIST_INFO.tcTrapControl)
#define MSTP_CIST_VALID                (MSTP_CIST_INFO.valid)
#define MSTP_IS_THIS_BRIDGE_CIST_ROOT  (MSTP_CIST_ROOT_PORT_ID == 0)

#define MSTP_MSTI_INFO(i)              (mstp_Bridge.MstiInfo[(i)])
#define MSTP_MSTI_ROOT_TIMES(i)        (MSTP_MSTI_INFO(i)->rootTimes)
#define MSTP_MSTI_BRIDGE_TIMES(i)      (MSTP_MSTI_INFO(i)->BridgeTimes)
#define MSTP_MSTI_ROOT_PORT_ID(i)      (MSTP_MSTI_INFO(i)->rootPortID)
#define MSTP_MSTI_ROOT_PRIORITY(i)     (MSTP_MSTI_INFO(i)->rootPriority)
#define MSTP_MSTI_BRIDGE_PRIORITY(i)   (MSTP_MSTI_INFO(i)->BridgePriority)
#define MSTP_MSTI_BRIDGE_IDENTIFIER(i) (MSTP_MSTI_INFO(i)->BridgeIdentifier)
#define MSTP_MSTI_PORT_STATE_CHANGE(i)   (MSTP_MSTI_INFO(i)->portStateChangeLog)
#define MSTP_MSTI_TC_TRAP_CONTROL(i)   (MSTP_MSTI_INFO(i)->tcTrapControl)
#define MSTP_MSTI_VALID(i)             \
(MSTP_MSTI_INFO(i) && MSTP_MSTI_INFO(i)->valid)

#define MSTP_IS_THIS_BRIDGE_RROOT(i)  mstp_isThisBridgeRegionalRoot(i)

#define MSTP_INSTANCE_IS_VALID(i) \
((i) == MSTP_CISTID ? MSTP_CIST_VALID : MSTP_MSTI_VALID(i))

#define MSTP_COMM_PORT_PTR(p)          (mstp_Bridge.PortInfo[(p)])
#define MSTP_COMM_PORT_SET_BIT(m,b) \
   setBit((m),(b),MSTP_PORT_BIT_MAP_MAX)
#define MSTP_COMM_PORT_CLR_BIT(m,b) \
   clrBit((m),(b),MSTP_PORT_BIT_MAP_MAX)
#define MSTP_COMM_PORT_IS_BIT_SET(m,b) \
   (isBitSet((m),(b),MSTP_PORT_BIT_MAP_MAX) ? true : false)

#define MSTP_COMM_ERRANT_BPDU_COUNT(p) \
                                 (MSTP_CIST_PORT_PTR(p)->dbgCnts.errantBpduCnt)

#define MSTP_ENABLED ((Spanning == true) && \
                      (Stp_version == STP_PROTOCOL_VERSION_MSTP))

/*---------------------------------------------------------------------------
 * Used to test, set and clear per-port BPDU filter option
 * It is outside of any flags word, to keep MSTP standard stuff separate
 * from non-standard extensions.  Part of bridge information, so don't
 * need to check MSTP_COMM_PORT_PTR(p).
 *---------------------------------------------------------------------------*/
#define MSTP_COMM_IS_BPDU_FILTER(p)    \
                           (is_port_set(&mstp_Bridge.bpduFilterLports,(p)))
#define MSTP_COMM_SET_BPDU_FILTER(p)   \
                           (set_port(&mstp_Bridge.bpduFilterLports,(p)))
#define MSTP_COMM_CLR_BPDU_FILTER(p)   \
                           (clear_port(&mstp_Bridge.bpduFilterLports,(p)))

/*---------------------------------------------------------------------------
 *  Test, set, and clear (default) for per-port BPDU Protection
 *---------------------------------------------------------------------------*/
#define MSTP_COMM_PORT_IS_BPDU_PROTECTED(p) \
                           (is_port_set(&mstp_Bridge.bpduProtectionLports,(p)))
#define MSTP_COMM_PORT_SET_BPDU_PROTECTION(p) \
                           (set_port(&mstp_Bridge.bpduProtectionLports,(p)))
#define MSTP_COMM_PORT_CLR_BPDU_PROTECTION(p) \
                           (clear_port(&mstp_Bridge.bpduProtectionLports,(p)))

/*---------------------------------------------------------------------------
 *  Test, set, and clear (default) for per-port loop guard config
 *---------------------------------------------------------------------------*/
#define MSTP_COMM_PORT_IS_LOOP_GUARD_PROTECTED(p) \
                           (is_port_set(&mstp_Bridge.loopGuardLports,(p)))
#define MSTP_COMM_PORT_SET_LOOP_GUARD_PROTECTION(p) \
                           (set_port(&mstp_Bridge.loopGuardLports,(p)))
#define MSTP_COMM_PORT_CLR_LOOP_GUARD_PROTECTION(p) \
                           (clear_port(&mstp_Bridge.loopGuardLports,(p)))


/*---------------------------------------------------------------------------
 * Used for reference to the CIST port data structure
 *---------------------------------------------------------------------------*/
#define MSTP_CIST_PORT_PTR(p)          (mstp_Bridge.CistInfo.CistPortInfo[(p)])

/*---------------------------------------------------------------------------
 * Used to test, set and clear CIST port variables held in 'bitMap' field
 * of the 'MSTP_CIST_PORT_INFO_t' data structure
 *---------------------------------------------------------------------------*/
#define MSTP_CIST_PORT_SET_BIT(m,b) \
   setBit((m),(b),MSTP_CIST_PORT_BIT_MAP_MAX)
#define MSTP_CIST_PORT_CLR_BIT(m,b) \
   clrBit((m),(b),MSTP_CIST_PORT_BIT_MAP_MAX)
#define MSTP_CIST_PORT_IS_BIT_SET(m,b) \
   (isBitSet((m),(b),MSTP_CIST_PORT_BIT_MAP_MAX) ? true : false)

/*---------------------------------------------------------------------------
 * Used for reference to the MSTI port data structure
 *---------------------------------------------------------------------------*/
#define MSTP_MSTI_PORT_PTR(i,p)        (MSTP_MSTI_INFO(i)->MstiPortInfo[(p)])

/*---------------------------------------------------------------------------
 * Used to test, set and clear MSTI port variables held in 'bitMap' field
 * of the 'MSTP_MSTI_PORT_INFO_t' data structure
 *---------------------------------------------------------------------------*/
#define MSTP_MSTI_PORT_SET_BIT(m,b) \
   setBit((m),(b),MSTP_MSTI_PORT_BIT_MAP_MAX)
#define MSTP_MSTI_PORT_CLR_BIT(m,b) \
   clrBit((m),(b),MSTP_MSTI_PORT_BIT_MAP_MAX)
#define MSTP_MSTI_PORT_IS_BIT_SET(m,b) \
   (isBitSet((m),(b),MSTP_MSTI_PORT_BIT_MAP_MAX) ? true : false)

/* Defines the size of the storage to trace the Root Change history */
#define MSTP_ROOT_HISTORY_MAX   10
#define MSTP_TC_HISTORY_MAX     10
#define MSTP_PORT_HISTORY_MAX   10

/*---------------------------------------------------------------------------
 * Used to fill a VID MAP with all VIDs taken from the range 1-4094
 *---------------------------------------------------------------------------*/
#define MSTP_ADD_ALL_VIDS_TO_VIDMAP(vidmap) \
{                                           \
   assert(vidmap);                          \
   memset(vidmap, 0xff, sizeof(VID_MAP));   \
   clear_vid(vidmap, INTERNAL_VID);         \
   clear_vid(vidmap, MAX_VLAN_ID);          \
}

/*---------------------------------------------------------------------------
 * Macros used in debugging code
 *---------------------------------------------------------------------------*/

#ifdef MSTP_DEBUG

char * date();
#define MSTP_DEBUG_BUF_LEN 80
#define MSTP_TX_BPDU_CNT   mstp_debugTxBpduCnt
#define MSTP_RX_BPDU_CNT   mstp_debugRxBpduCnt

#if (__GNUC__ < 3)
#define MSTP_PRINTF(format, args...) \
{                                    \
   char    time_str[DATESTRLEN];             \
   strncpy(time_str,date(),sizeof(time_str)); \
   snprintf(mstp_debugBuf, sizeof(mstp_debugBuf),            \
            "%-17s "format, time_str, ##args);               \
   VLOG_INFO(mstp_debugBuf); \
}
#else
#define MSTP_PRINTF(format, ...)     \
{                                    \
   char    time_str[20];             \
   strncpy(time_str,date(),sizeof(time_str)); \
   snprintf(mstp_debugBuf, sizeof(mstp_debugBuf),            \
            "%-17s "format, time_str, ##__VA_ARGS__);        \
   VLOG_INFO(mstp_debugBuf); \
}
#endif

#if (__GNUC__ < 3)
#define MSTP_PORT_PRINTF(p, format, args...)  \
if(is_port_set(&mstp_debugPorts, p))          \
{ MSTP_PRINTF(format, args) }
#else
#define MSTP_PORT_PRINTF(p, format, ...)      \
if(is_port_set(&mstp_debugPorts, p))          \
{ MSTP_PRINTF(format, __VA_ARGS__) }
#endif

#if (__GNUC__ < 3)
#define MSTP_PORT_STATUS_PRINTF(p, format, args...) \
if(mstp_debugPortStatus &&                          \
   is_port_set(&mstp_debugPorts, lport))            \
{ MSTP_PORT_PRINTF(lport, format, args)}
#else
#define MSTP_PORT_STATUS_PRINTF(p, format, ...)     \
if(mstp_debugPortStatus &&                          \
   is_port_set(&mstp_debugPorts, lport))            \
{ MSTP_PORT_PRINTF(lport, format, __VA_ARGS__) }
#endif

#if (__GNUC__ < 3)
#define MSTP_MSTI_PORT_STATUS_PRINTF(i, p, format, args...) \
if(mstp_debugPortStatus &&                                  \
   (((i == MSTP_CISTID) && mstp_debugCist) ||               \
    isBitSet(mstp_debugMstis.map, i, MSTP_MSTID_MAX))       \
   && is_port_set(&mstp_debugPorts,p))                      \
{ MSTP_PRINTF(format, args) }
#else
#define MSTP_MSTI_PORT_STATUS_PRINTF(i, p, format, ...)     \
if(mstp_debugPortStatus &&                                  \
   (((i == MSTP_CISTID) && mstp_debugCist) ||               \
    isBitSet(mstp_debugMstis.map, i, MSTP_MSTID_MAX))       \
   && is_port_set(&mstp_debugPorts,p))                      \
{ MSTP_PRINTF(format, __VA_ARGS__) }
#endif

#if (__GNUC__ < 3)
#define MSTP_MSTI_PORT_FLUSH_PRINTF(i, p, format, args...)   \
if(mstp_debugFlush &&                                        \
   (((mstid == MSTP_CISTID) && mstp_debugCist) ||            \
    isBitSet(mstp_debugMstis.map, mstid, MSTP_MSTID_MAX)) && \
    is_port_set(&mstp_debugPorts, lport))                    \
{ MSTP_PRINTF(format, args) }
#else
#define MSTP_MSTI_PORT_FLUSH_PRINTF(i, p, format, ...)       \
if(mstp_debugFlush &&                                        \
   (((mstid == MSTP_CISTID) && mstp_debugCist) ||            \
    isBitSet(mstp_debugMstis.map, mstid, MSTP_MSTID_MAX)) && \
    is_port_set(&mstp_debugPorts, lport))                    \
{ MSTP_PRINTF(format, __VA_ARGS__) }
#endif

#if (__GNUC__ < 3)
#define MSTP_SM_ST_PRINTF(m, format, args...)            \
if(((mstid == MSTP_CISTID) && mstp_debugCist) ||         \
   isBitSet(mstp_debugMstis.map, mstid, MSTP_MSTID_MAX)) \
{ MSTP_SM_PORT_PRINTF(m, lport, format, args) }
#else
#define MSTP_SM_ST_PRINTF(m, format, ...)                \
if(((mstid == MSTP_CISTID) && mstp_debugCist) ||         \
   isBitSet(mstp_debugMstis.map, mstid, MSTP_MSTID_MAX)) \
{ MSTP_SM_PORT_PRINTF(m, lport, format, __VA_ARGS__) }
#endif

#if (__GNUC__ < 3)
#define MSTP_SM_ST_PRINTF1(m, format, args...) \
        MSTP_SM_PORT_PRINTF(m, lport, format,args)
#else
#define MSTP_SM_ST_PRINTF1(m, format, ...)     \
        MSTP_SM_PORT_PRINTF(m, lport, format, __VA_ARGS__)
#endif

#if (__GNUC__ < 3)
#define MSTP_SM_ST_PRINTF2(m, format, args...) \
        MSTP_SM_PRINTF(m, format, args)
#else
#define MSTP_SM_ST_PRINTF2(m, format, ...)     \
        MSTP_SM_PRINTF(m, format, __VA_ARGS__)
#endif

#if (__GNUC__ < 3)
#define MSTP_SM_CALL_SM_PRINTF(m, format, args...) \
if(mstp_debugSmCallSm &&                           \
   is_port_set(&mstp_debugPorts, lport))           \
{ MSTP_PRINTF(format, args) }
#else
#define MSTP_SM_CALL_SM_PRINTF(m, format, ...)     \
if(mstp_debugSmCallSm &&                           \
   is_port_set(&mstp_debugPorts, lport))           \
{ MSTP_PRINTF(format, __VA_ARGS__) }
#endif

#if (__GNUC__ < 3)
#define MSTP_SM_CALL_SM_PRINTF1(m, format, args...)      \
if(mstp_debugSmCallSm &&                                 \
   isBitSet(mstp_debugSMs.sm_map, m, MSTP_SM_MAX_BIT) && \
   is_port_set(&mstp_debugPorts,lport))                  \
{ MSTP_PRINTF(format, args) }
#else
#define MSTP_SM_CALL_SM_PRINTF1(m, format, ...)          \
if(mstp_debugSmCallSm &&                                 \
   isBitSet(mstp_debugSMs.sm_map, m, MSTP_SM_MAX_BIT) && \
   is_port_set(&mstp_debugPorts,lport))                  \
{ MSTP_PRINTF(format, __VA_ARGS__) }
#endif

#if (__GNUC__ < 3)
#define MSTP_SM_PRINTF(m, format, args...)             \
if(isBitSet(mstp_debugSMs.sm_map, m, MSTP_SM_MAX_BIT)) \
{ MSTP_PRINTF(format, args) }
#else
#define MSTP_SM_PRINTF(m, format, ...)             \
if(isBitSet(mstp_debugSMs.sm_map, m, MSTP_SM_MAX_BIT)) \
{ MSTP_PRINTF(format, __VA_ARGS__) }
#endif

#if (__GNUC__ < 3)
#define MSTP_SM_PORT_PRINTF(m, p, format, args...)       \
if(isBitSet(mstp_debugSMs.sm_map, m, MSTP_SM_MAX_BIT) && \
   is_port_set(&mstp_debugPorts,p))                      \
{ MSTP_PRINTF(format, args) }
#else
#define MSTP_SM_PORT_PRINTF(m, p, format, ...)       \
if(isBitSet(mstp_debugSMs.sm_map, m, MSTP_SM_MAX_BIT) && \
   is_port_set(&mstp_debugPorts,p))                      \
{ MSTP_PRINTF(format, __VA_ARGS__) }
#endif

#if (__GNUC__ < 3)
#define MSTP_TX_FUNC_PRINTF(format, args...)                 \
if(mstp_debugTx &&                                           \
   (((mstid == MSTP_CISTID) && mstp_debugCist) ||            \
    isBitSet(mstp_debugMstis.map, mstid, MSTP_MSTID_MAX)) && \
    is_port_set(&mstp_debugPorts, lport))                    \
{                                                            \
   MSTP_PRINTF(format, args);                                \
   MSTP_BPDU_PRINTF(pkt);                                    \
}
#else
#define MSTP_TX_FUNC_PRINTF(format, ...)                     \
if(mstp_debugTx &&                                           \
   (((mstid == MSTP_CISTID) && mstp_debugCist) ||            \
    isBitSet(mstp_debugMstis.map, mstid, MSTP_MSTID_MAX)) && \
    is_port_set(&mstp_debugPorts, lport))                    \
{                                                            \
   MSTP_PRINTF(format, __VA_ARGS__);                         \
   MSTP_BPDU_PRINTF(pkt);                                    \
}
#endif

#if (__GNUC__ < 3)
#define MSTP_TX_FUNC_PRINTF1(format, args...)   \
if(mstp_debugTx)                                \
{ MSTP_PORT_PRINTF(lport, format, args) }
#else
#define MSTP_TX_FUNC_PRINTF1(format, ...)       \
if(mstp_debugTx)                                \
{ MSTP_PORT_PRINTF(lport, format, __VA_ARGS__) }
#endif

#if (__GNUC__ < 3)
#define MSTP_RX_FUNC_PRINTF(format, args...)                 \
if(mstp_debugRx &&                                           \
   (((mstid == MSTP_CISTID) && mstp_debugCist) ||            \
    isBitSet(mstp_debugMstis.map, mstid, MSTP_MSTID_MAX)) && \
    is_port_set(&mstp_debugPorts, lport))                    \
{                                                            \
   MSTP_PRINTF(format, args);                                \
   MSTP_BPDU_PRINTF(pkt);                                    \
}
#else
#define MSTP_RX_FUNC_PRINTF(format, ...)                     \
if(mstp_debugRx &&                                           \
   (((mstid == MSTP_CISTID) && mstp_debugCist) ||            \
    isBitSet(mstp_debugMstis.map, mstid, MSTP_MSTID_MAX)) && \
    is_port_set(&mstp_debugPorts, lport))                    \
{                                                            \
   MSTP_PRINTF(format, __VA_ARGS__);                         \
   MSTP_BPDU_PRINTF(pkt);                                    \
}
#endif

#if (__GNUC__ < 3)
#define MSTP_RX_FUNC_PRINTF1(format, args...) \
if(mstp_debugRx)                              \
{ MSTP_PORT_PRINTF(lport, format, args) }
#else
#define MSTP_RX_FUNC_PRINTF1(format, ...)     \
if(mstp_debugRx)                              \
{ MSTP_PORT_PRINTF(lport, format, __VA_ARGS__) }
#endif

#define MSTP_BPDU_PRINTF(pkt) \
if(mstp_debugBpduPrint)       \
{ mstp_dbgBpduPrint(pkt); }

#if (__GNUC__ < 3)
#define MSTP_DYN_CFG_PRINTF(format, args...) \
if(mstp_debugDynConfig)                      \
{ MSTP_PRINTF(format, args) }
#else
#define MSTP_DYN_CFG_PRINTF(format, ...)     \
if(mstp_debugDynConfig)                      \
{ MSTP_PRINTF(format, __VA_ARGS__) }
#endif

#if (__GNUC__ < 3)
#define MSTP_MISC_PRINTF(format, args...) \
if(mstp_debugMisc)                        \
{ MSTP_PRINTF(format, args) }
#else
#define MSTP_MISC_PRINTF(format, ...)     \
if(mstp_debugMisc)                        \
{ MSTP_PRINTF(format, __VA_ARGS__) }
#endif

#if (__GNUC__ < 3)
#define MSTP_MISC_PORT_PRINTF(format, args...) \
if(mstp_debugMisc &&                           \
   is_port_set(&mstp_debugPorts, lport))       \
{ MSTP_PRINTF(format, args) }
#else
#define MSTP_MISC_PORT_PRINTF(format, ...)     \
if(mstp_debugMisc &&                           \
   is_port_set(&mstp_debugPorts, lport))       \
{ MSTP_PRINTF(format, __VA_ARGS__) }
#endif

#if (__GNUC__ < 3)
#define MSTP_MISC_MSTI_PORT_PRINTF(format, args...)         \
if(mstp_debugMisc &&                                        \
   (((mstid == MSTP_CISTID) && mstp_debugCist) ||           \
   isBitSet(mstp_debugMstis.map, mstid, MSTP_MSTID_MAX)) && \
   is_port_set(&mstp_debugPorts, lport))                    \
{ MSTP_PRINTF(format, args) }
#else
#define MSTP_MISC_MSTI_PORT_PRINTF(format, ...)             \
if(mstp_debugMisc &&                                        \
   (((mstid == MSTP_CISTID) && mstp_debugCist) ||           \
   isBitSet(mstp_debugMstis.map, mstid, MSTP_MSTID_MAX)) && \
   is_port_set(&mstp_debugPorts, lport))                    \
{ MSTP_PRINTF(format, __VA_ARGS__) }
#endif

#if (__GNUC__ < 3)
#define MSTP_MISC_SM_MSTI_PORT_PRINTF(m, p, format, args...)\
if(mstp_debugMisc &&                                        \
   (((mstid == MSTP_CISTID) && mstp_debugCist) ||           \
   isBitSet(mstp_debugMstis.map, mstid, MSTP_MSTID_MAX)) && \
   isBitSet(mstp_debugSMs.sm_map, m, MSTP_SM_MAX_BIT) &&    \
   is_port_set(&mstp_debugPorts, p))                        \
{ MSTP_PRINTF(format, args) }
#else
#define MSTP_MISC_SM_MSTI_PORT_PRINTF(m, p, format, ...)    \
if(mstp_debugMisc &&                                        \
   (((mstid == MSTP_CISTID) && mstp_debugCist) ||           \
   isBitSet(mstp_debugMstis.map, mstid, MSTP_MSTID_MAX)) && \
   isBitSet(mstp_debugSMs.sm_map, m, MSTP_SM_MAX_BIT) &&    \
   is_port_set(&mstp_debugPorts, p))                        \
{ MSTP_PRINTF(format, __VA_ARGS__) }
#endif

#if (__GNUC__ < 3)
#define MSTP_UNCONDITIONAL_PRINTF(format, args...) \
{ MSTP_PRINTF(format, args) }
#else
#define MSTP_UNCONDITIONAL_PRINTF(format, ...)     \
{ MSTP_PRINTF(format, __VA_ARGS__) }
#endif

#define MSTP_PER_PORT_SM_CALL_SM_FMT \
"%-4s %-13s #> %-13s         lport %-3d "
#define MSTP_PER_TREE_SM_CALL_SM_FMT \
"%-4s %-13s #> %-13s MST %-2d          "
#define MSTP_PER_TREE_PER_PORT_SM_CALL_SM_FMT \
"%-4s %-13s #> %-13s MST %-2d  lport %-3d "
#define MSTP_PER_PORT_SM_STATE_TRANSITION_FMT \
"%-4s %-13s -> %-13s         lport %-3d "
#define MSTP_PER_TREE_PER_PORT_SM_STATE_TRANSITION_FMT \
"%-4s %-13s -> %-13s MST %-2d  lport %-3d "
#define MSTP_PER_TREE_SM_STATE_TRANSITION_FMT \
"%-4s %-13s -> %-13s MST %-2d          "
#define MSTP_TX_PKT_FMT \
"%s TX MSTI %d Port %d (F=0x%.2x)"
#define MSTP_RX_PKT_FMT \
"%s RX MSTI %d Port %d (F=0x%.2x) "
#define MSTP_PORT_STATE_FMT \
"%-18s %-3s                      lport %-3d "
#define MSTP_PORT_STATE_ON_TREE_FMT \
"%-18s %-3s              MST %-2d  lport %-3d "

#define MSTP_FWD_SYM     "+F"
#define MSTP_NO_FWD_SYM  "-F"
#define MSTP_LRN_SYM     "+L"
#define MSTP_NO_LRN_SYM  "-L"
#define MSTP_ENBL_SYM    "+P"
#define MSTP_DSBL_SYM    "-P"
#define MSTP_RX_SYM      "<*"
#define MSTP_TX_SYM      "*>"
#define MSTP_FLUSH_SYM   "~!"

/***************************************************/
/*These macros are used for user mode debug logging*/
/***************************************************/

#if (__GNUC__ < 3)
#define MSTP_EVENT_PRINTF(p,i,format, args...)            \
{                                                       \
   if(((i == MSTP_CISTID) && mstp_debugEventCist)       \
       || (isBitSet(&mstp_debugEventInstances.map,      \
                i, MSTP_MSTID_MAX)))                    \
   { MSTP_PRINTF_EVENT(format, args) }                  \
}
#else
#define MSTP_EVENT_PRINTF(p,i, format, ...)               \
{                                                       \
   if(((i == MSTP_CISTID) && mstp_debugEventCist)       \
      || (isBitSet(&mstp_debugEventInstances.map,       \
                   i, MSTP_MSTID_MAX)))                 \
   { MSTP_PRINTF_EVENT(format, __VA_ARGS__) }           \
}
#endif

#if (__GNUC__ < 3)
#define MSTP_PKT_PRINTF(p,i,format, args...)            \
{                                                       \
   if((((i == MSTP_CISTID) &&                           \
        is_port_set(&mstp_debugPktEnabledForCist, p))   \
       || (is_port_set(&mstp_debugPktEnabledPorts, p) &&\
        isBitSet(&mstp_debugPktEnabledInstances[p].map, \
                 i, MSTP_MSTID_MAX))))                  \
      { MSTP_PRINTF_PKT(format, args) }                 \
}
#else
#define MSTP_PKT_PRINTF(p,i, format, ...)               \
{                                                       \
   if((((i == MSTP_CISTID) &&                           \
        is_port_set(&mstp_debugPktEnabledForCist, p))   \
       || (is_port_set(&mstp_debugPktEnabledPorts, p) &&\
           isBitSet(&mstp_debugPktEnabledInstances[p].map, \
                    i, MSTP_MSTID_MAX))))                  \
   { MSTP_PRINTF_PKT(format, __VA_ARGS__) }             \
}
#endif

#if (__GNUC__ < 3)
#define MSTP_PRINTF_EVENT(format, args...)             \
{                                                      \
      char    time_str[DATESTRLEN];                    \
      strncpy(time_str, date(),sizeof(time_str));                    \
      snprintf(mstp_debugBuf, sizeof(mstp_debugBuf),   \
               "%s "format, time_str+9, ##args);       \
      VLOG_INFO(mstp_debugBuf);                      \
}
#else
#define MSTP_PRINTF_EVENT(format, ...)                \
{                                                     \
      char    time_str[20];                           \
      strncpy(time_str, date(),sizeof(time_str));                    \
      snprintf(mstp_debugBuf, sizeof(mstp_debugBuf),  \
             "%s "format, time_str+9, ##__VA_ARGS__); \
      VLOG_INFO(mstp_debugBuf);                     \
}
#endif


#if (__GNUC__ < 3)
#define MSTP_PRINTF_PKT(format, args...)              \
{                                                     \
      char    time_str[DATESTRLEN];                   \
      strncpy(time_str, date(),sizeof(time_str));                    \
      snprintf(mstp_debugBuf, sizeof(mstp_debugBuf),  \
               "%s "format, time_str+9, ##args);      \
      VLOG_INFO(mstp_debugBuf);                     \
}
#else
#define MSTP_PRINTF_PKT(format, ...)                  \
{                                                     \
      char    time_str[20];                           \
      strncpy(time_str, date(),sizeof(time_str));                    \
      snprintf(mstp_debugBuf, sizeof(mstp_debugBuf),  \
            "%s "format, time_str+9, ##__VA_ARGS__);  \
      VLOG_INFO(mstp_debugBuf);                     \
}
#endif


/***************************************************/
#else  /* !MSTP_DEBUG */

#define MSTP_TX_BPDU_CNT
#define MSTP_RX_BPDU_CNT

#define MSTP_PRINTF(format, ...)
#define MSTP_PORT_PRINTF(p, format, args...)
#define MSTP_PORT_STATUS_PRINTF(p, format, args...)
#define MSTP_MSTI_PORT_STATUS_PRINTF(i, p, format, ...)
#define MSTP_MSTI_PORT_FLUSH_PRINTF(i, p, format, args...)
#define MSTP_SM_ST_PRINTF(m, format, ...)
#define MSTP_SM_ST_PRINTF1(m, format, ...)
#define MSTP_SM_ST_PRINTF2(m, format, ...)
#define MSTP_SM_CALL_SM_PRINTF(m, format, ...)
#define MSTP_SM_CALL_SM_PRINTF1(m, format, ...)
#define MSTP_SM_PRINTF(m, format, args...)
#define MSTP_SM_PORT_PRINTF(m, p, format, args...)
#define MSTP_TX_FUNC_PRINTF(format, ...)
#define MSTP_TX_FUNC_PRINTF1(format, args...)
#define MSTP_RX_FUNC_PRINTF(format, ...)
#define MSTP_RX_FUNC_PRINTF1(format, ...)
#define MSTP_BPDU_PRINTF(p)
#define MSTP_DYN_CFG_PRINTF(format, ...)
#define MSTP_MISC_PRINTF(format, ...)
#define MSTP_MISC_PORT_PRINTF(format, ...)
#define MSTP_MISC_MSTI_PORT_PRINTF(format, ...)
#define MSTP_MISC_SM_MSTI_PORT_PRINTF(m, p, format, ...)
#define MSTP_UNCONDITIONAL_PRINTF(format, ...)

#endif /* !MSTP_DEBUG */

/* FDR Logging */
#define STP_ASSERT(x) assert(x)

/*****************************************************************************
 *        MSTP Data Structures and Types Definition
 *****************************************************************************/

/*---------------------------------------------------------------------------
 * Throttle Hash table indexes for different clients
 *---------------------------------------------------------------------------*/
typedef enum
{
   LOG_MSTP,
   MSTP_MAX_LOG_THROTTLE_CLIENT
}mstpLogThrottleClient_t;

/*---------------------------------------------------------------------------
 * include "logThrottle_pub.h" MST Pkt types
 *---------------------------------------------------------------------------*/
typedef enum {
  MSTP_PROTOCOL_DATA_PKT = 1,
  MSTP_ERRANT_PROTOCOL_DATA_PKT,
  MSTP_UNAUTHORIZED_BPDU_DATA_PKT,
  MSTP_INVALID_PKT
} MSTP_PKT_TYPE_t;

/*---------------------------------------------------------------------------
 * MST Instance Identifier (0 to MSTP_INSTANCES_MAX, 0 is for CIST)
 * NOTE: defined as 2 octets long because this is the requirement for building
 *       MST Configuration Table - that assumes to have an MSTID_t value in
 *       every row (see 'mstp_getMstConfigurationDigest()')
 *---------------------------------------------------------------------------*/
typedef uint16_t MSTID_t;

/*---------------------------------------------------------------------------
 * MSTP port ID (2 octest long)
 *    4  higher bits = port priority
 *    12 lower bits = logical port number
 * (802.1Q-REV/D5.0 13.24.11)
 *---------------------------------------------------------------------------*/
typedef uint16_t MSTP_PORT_ID_t;

/*---------------------------------------------------------------------------
 * Used to handle VLANs to MST Instance mapping info when read from MIB
 * NOTE: VLAN to Instance mapping in MIB is defined as 4 OCTET STRING MIB
 *       objects with size of 128 bytes each, every octet containing one bit
 *       per VLAN, so in total up to 4*128*8=4096 VIDs can be stored per
 *       Instance.
 *---------------------------------------------------------------------------*/
typedef struct MSTP_MIB_VLAN_MAP_t
{
   char map1k[MSTP_VLAN_MAP_SIZE]; /*    1-1024 bits (128 bytes) */
   char map2k[MSTP_VLAN_MAP_SIZE]; /* 1024-2048 bits (128 bytes) */
   char map3k[MSTP_VLAN_MAP_SIZE]; /* 2049-3072 bits (128 bytes) */
   char map4k[MSTP_VLAN_MAP_SIZE]; /* 3073-4096 bits (128 bytes) */

} MSTP_MIB_VLAN_MAP_t;

/*---------------------------------------------------------------------------
 * Data structures that are used to inform other Bridge's subsystems about
 * MSTP ports state changes.
 *---------------------------------------------------------------------------*/
typedef struct MSTP_TREE_MSG_t
{
   QUEUE_THREAD link;  /* link to the next state change block */
   MSTID_t      mstid;
   bool      rootInfoChanged;
   PORT_MAP     portsFwd;
   PORT_MAP     portsLrn;
   PORT_MAP     portsBlk;
   PORT_MAP     portsUp;
   PORT_MAP     portsDwn;
   PORT_MAP     portsMacAddrFlush;
   PORT_MAP     portsSetEdge;
   PORT_MAP     portsClearEdge;
} MSTP_TREE_MSG_t;

typedef struct MSTP_MESSAGES_t
{
   QUEUE_HEAD treeMsgQueue; /* per tree msgs to inform other subsystems */

} MSTP_TREE_MSGS_t;

/*---------------------------------------------------------------------------
 * MST Configuration Identification (51 octets long). Used to encode VIDs to
 * spanning trees allocation information in BPDU.
 * (802.1Q-REV/D5.0 13.7).
 *---------------------------------------------------------------------------*/
#pragma pack(push,1)
typedef struct MSTP_MST_CONFIGURATION_ID_t
{
   uint8_t   formatSelector; /* the value 0 is encoded */
   uint8_t   configName[MSTP_MST_CONFIG_NAME_LEN]; /* variable length
                          * octet string encoded within a fixed field of 32
                          * octets */
   uint16_t revisionLevel; /* the Revision Level */
   uint8_t   digest[MSTP_DIGEST_SIZE]; /* HMAC-MD5 signature created
                          * from MST Configuration Table with the
                          * 'mstp_DigestSignatureKey' used as the key value */

} MSTP_MST_CONFIGURATION_ID_t;
#pragma pack(pop)

/*---------------------------------------------------------------------------
 * MST Bridge Identifier (CIST or MSTI)
 * NOTE: only 4 most significant bits of 'priority' component are permitted to
 *       use for priority value, the other 12 bits comprise a locally assigned
 *       system ID extensions.
 *---------------------------------------------------------------------------*/
typedef struct MSTP_BRIDGE_IDENTIFIER_t
{
   uint16_t      priority;
   MAC_ADDRESS   mac_address;

} MSTP_BRIDGE_IDENTIFIER_t;

/*---------------------------------------------------------------------------
 * Bridge Identifiers used by STP, RSTP (identical to MSTP)
 *---------------------------------------------------------------------------*/
typedef MSTP_BRIDGE_IDENTIFIER_t STP_BRIDGE_IDENTIFIER_t;
typedef MSTP_BRIDGE_IDENTIFIER_t RSTP_BRIDGE_IDENTIFIER_t;

/*---------------------------------------------------------------------------
 * CIST Bridge Priority Vector.
 * (802.1Q-REV/D5.0 13.10; 13.23.3)
 *---------------------------------------------------------------------------*/
typedef struct MSTP_CIST_BRIDGE_PRI_VECTOR_t
{
   MSTP_BRIDGE_IDENTIFIER_t   rootID;          /* CIST Root ID */
   uint32_t                 extRootPathCost; /* CIST External Root Path Cost */
   MSTP_BRIDGE_IDENTIFIER_t rgnRootID;       /* CIST Regional Root ID        */
   uint32_t                 intRootPathCost; /* CIST Internal Root Path Cost */
   MSTP_BRIDGE_IDENTIFIER_t dsnBridgeID;     /* CIST Designated Bridge ID    */
   MSTP_PORT_ID_t           dsnPortID;       /* CIST Designated Port ID      */

} MSTP_CIST_BRIDGE_PRI_VECTOR_t;

/*---------------------------------------------------------------------------
 * CIST Root Priority Vector
 * The set of parameters in this data type is identical to those defined in
 * 'MSTP_CIST_BRIDGE_PRI_VECTOR_t' above, but the values they accept are
 * different.
 * (802.1Q-REV/D5.0 13.23.6)
 *---------------------------------------------------------------------------*/
typedef MSTP_CIST_BRIDGE_PRI_VECTOR_t MSTP_CIST_ROOT_PRI_VECTOR_t;

/*---------------------------------------------------------------------------
 * CIST Designated Priority Vector
 * The set of parameters in this data type is identical to those defined in
 * 'MSTP_CIST_BRIDGE_PRI_VECTOR_t' above, but the values they accept are
 * different.
 * (802.1Q-REV/D5.0 13.24.2)
 *---------------------------------------------------------------------------*/
typedef MSTP_CIST_BRIDGE_PRI_VECTOR_t MSTP_CIST_DESIGNATED_PRI_VECTOR_t;

/*---------------------------------------------------------------------------
 * CIST Message Priority Vector
 * The set of parameters in this data type is identical to those defined in
 * 'MSTP_CIST_BRIDGE_PRI_VECTOR_t' above, but the values they accept are
 * different.
 * (802.1Q-REV/D5.0 13.24.9)
 *---------------------------------------------------------------------------*/
typedef MSTP_CIST_BRIDGE_PRI_VECTOR_t MSTP_CIST_MSG_PRI_VECTOR_t;

/*---------------------------------------------------------------------------
 * CIST Port Priority Vector
 * The set of parameters in this data type is identical to those defined in
 * 'MSTP_CIST_BRIDGE_PRI_VECTOR_t' above, but the values they accept are
 * different.
 * (802.1Q-REV/D5.0 13.24.12)
 *---------------------------------------------------------------------------*/
typedef MSTP_CIST_BRIDGE_PRI_VECTOR_t MSTP_CIST_PORT_PRI_VECTOR_t;

/*---------------------------------------------------------------------------
 * CIST Port's Root Path Priority Vector
 * The set of parameters in this data type is identical to those defined in
 * 'MSTP_CIST_BRIDGE_PRI_VECTOR_t' above, but the values they accept are
 * different.
 * (802.1Q-REV/D5.0 13.10)
 *---------------------------------------------------------------------------*/
typedef MSTP_CIST_BRIDGE_PRI_VECTOR_t MSTP_CIST_ROOT_PATH_PRI_VECTOR_t;

/*---------------------------------------------------------------------------
 * CIST Bridge Times.
 * (802.1Q-REV/D5.0 13.23.4)
 *---------------------------------------------------------------------------*/
typedef struct MSTP_CIST_BRIDGE_TIMES_t
{
   uint16_t   fwdDelay;    /* current value of Bridge Forward Delay */
   uint16_t   maxAge;      /* current value of Bridge Max Age  */
   uint16_t   messageAge;  /* value of zero */
   uint16_t   hops;        /* current value of MaxHops */

} MSTP_CIST_BRIDGE_TIMES_t;

/*---------------------------------------------------------------------------
 * CIST Root Times.
 * The set of parameters in this data type is identical to those defined in
 * 'MSTP_CIST_BRIDGE_TIMES_t' above, but the values they accept are different.
 * (802.1Q-REV/D5.0 13.23.7)
 *---------------------------------------------------------------------------*/
typedef MSTP_CIST_BRIDGE_TIMES_t MSTP_CIST_ROOT_TIMES_t;

/*---------------------------------------------------------------------------
 * CIST Designated Times.
 * The set of parameters in this data type is identical to those defined in
 * 'MSTP_CIST_BRIDGE_TIMES_t' above, but the values they accept are different.
 * (802.1Q-REV/D5.0 13.24.3)
 *---------------------------------------------------------------------------*/
typedef MSTP_CIST_BRIDGE_TIMES_t MSTP_CIST_DESIGNATED_TIMES_t;

/*---------------------------------------------------------------------------
 * CIST Message Times.
 * (802.1Q-REV/D5.0 13.24.10)
 *---------------------------------------------------------------------------*/
typedef struct MSTP_CIST_MSG_TIMES_t
{
   uint16_t   messageAge;  /* Message Age value conveyed in received BPDU */
   uint16_t   maxAge;      /* Max Age value conveyed in received BPDU */
   uint16_t   fwdDelay;    /* Forward Delay value conveyed in received BPDU */
   uint16_t   helloTime;   /* Hello Time value conveyed in received BPDU */
   uint16_t   hops;        /* Remaining Hops value conveyed in received BPDU */

} MSTP_CIST_MSG_TIMES_t;

/*---------------------------------------------------------------------------
 * CIST Port Times.
 * The set of parameters in this data type is identical to those defined in
 * 'MSTP_CIST_MSG_TIMES_t' above, but the values they accept are different.
 * (802.1Q-REV/D5.0 13.24.13)
 *---------------------------------------------------------------------------*/
typedef MSTP_CIST_MSG_TIMES_t MSTP_CIST_PORT_TIMES_t;

/*---------------------------------------------------------------------------
 * MSTI Bridge Priority Vector.
 * (802.1Q-REV/D5.0 13.11; 13.23.3)
 *---------------------------------------------------------------------------*/
typedef struct MSTP_MSTI_BRIDGE_PRI_VECTOR_t
{
   MSTP_BRIDGE_IDENTIFIER_t rgnRootID;       /* MSTI Regional Root ID        */
   uint32_t                 intRootPathCost; /* MSTI Internal Root Path Cost */
   MSTP_BRIDGE_IDENTIFIER_t dsnBridgeID;     /* MSTI Designated Bridge ID    */
   MSTP_PORT_ID_t           dsnPortID;       /* MSTI Designated Port ID      */

} MSTP_MSTI_BRIDGE_PRI_VECTOR_t;

/*---------------------------------------------------------------------------
 * MSTI Root Priority Vector.
 * The set of parameters in this data type is identical to those defined in
 * 'MSTP_MSTI_BRIDGE_PRI_VECTOR_t' above, but the values they accept are
 * different.
 * (802.1Q-REV/D5.0 13.23.6)
 *---------------------------------------------------------------------------*/
typedef MSTP_MSTI_BRIDGE_PRI_VECTOR_t MSTP_MSTI_ROOT_PRI_VECTOR_t;

/*---------------------------------------------------------------------------
 * MSTI Designated Priority Vector.
 * The set of parameters in this data type is identical to those defined in
 * 'MSTP_MSTI_BRIDGE_PRI_VECTOR_t' above, but the values they accept are
 * different.
 * (802.1Q-REV/D5.0 13.24.2)
 *---------------------------------------------------------------------------*/
typedef MSTP_MSTI_BRIDGE_PRI_VECTOR_t MSTP_MSTI_DESIGNATED_PRI_VECTOR_t;

/*---------------------------------------------------------------------------
 * MSTI Message Priority Vector.
 * The set of parameters in this data type is identical to those defined in
 * 'MSTP_MSTI_BRIDGE_PRI_VECTOR_t' above, but the values they accept are
 * different.
 * (802.1Q-REV/D5.0 13.24.9)
 *---------------------------------------------------------------------------*/
typedef MSTP_MSTI_BRIDGE_PRI_VECTOR_t MSTP_MSTI_MSG_PRI_VECTOR_t;

/*---------------------------------------------------------------------------
 * MSTI Port Priority Vector.
 * The set of parameters in this data type is identical to those defined in
 * 'MSTP_MSTI_BRIDGE_PRI_VECTOR_t' above, but the values they accept are
 * different.
 * (802.1Q-REV/D5.0 13.24.12)
 *---------------------------------------------------------------------------*/
typedef MSTP_MSTI_BRIDGE_PRI_VECTOR_t MSTP_MSTI_PORT_PRI_VECTOR_t;

/*---------------------------------------------------------------------------
 * MSTI Port's Root Path Priority Vector
 * The set of parameters in this data type is identical to those defined in
 * 'MSTP_MSTI_BRIDGE_PRI_VECTOR_t' above, but the values they accept are
 * different.
 * (802.1Q-REV/D5.0 13.11)
 *---------------------------------------------------------------------------*/
typedef MSTP_MSTI_BRIDGE_PRI_VECTOR_t MSTP_MSTI_ROOT_PATH_PRI_VECTOR_t;

/*---------------------------------------------------------------------------
 * MSTI Bridge Times.
 * (802.1Q-REV/D5.0 13.23.4)
 *---------------------------------------------------------------------------*/
typedef struct MSTP_MSTI_BRIDGE_TIMES_t
{
   uint16_t   hops;  /* current value of Bridge Max Hops for a given MSTI */

} MSTP_MSTI_BRIDGE_TIMES_t;

/*---------------------------------------------------------------------------
 * MSTI Root Times.
 * The set of parameters in this data type is identical to those defined in
 * 'MSTP_MSTI_BRIDGE_TIMES_t' above, but the values they accept are
 * different.
 * (802.1Q-REV/D5.0 13.23.7)
 *---------------------------------------------------------------------------*/
typedef MSTP_MSTI_BRIDGE_TIMES_t MSTP_MSTI_ROOT_TIMES_t;

/*---------------------------------------------------------------------------
 * MSTI Designated Times.
 * The set of parameters in this data type is identical to those defined in
 * 'MSTP_MSTI_BRIDGE_TIMES_t' above, but the values they accept are
 * different.
 * (802.1Q-REV/D5.0 13.24.3)
 *---------------------------------------------------------------------------*/
typedef MSTP_MSTI_BRIDGE_TIMES_t MSTP_MSTI_DESIGNATED_TIMES_t;

/*---------------------------------------------------------------------------
 * MSTI Message Times.
 * The set of parameters in this data type is identical to those defined in
 * 'MSTP_MSTI_BRIDGE_TIMES_t' above, but the values they accept are
 * different.
 * (802.1Q-REV/D5.0 13.24.10)
 *---------------------------------------------------------------------------*/
typedef MSTP_MSTI_BRIDGE_TIMES_t MSTP_MSTI_MSG_TIMES_t;

/*---------------------------------------------------------------------------
 * MSTI Port Times.
 * The set of parameters in this data type is identical to those defined in
 * 'MSTP_MSTI_BRIDGE_TIMES_t' above, but the values they accept are
 * different.
 * (802.1Q-REV/D5.0 13.24.13)
 *---------------------------------------------------------------------------*/
typedef MSTP_MSTI_BRIDGE_TIMES_t MSTP_MSTI_PORT_TIMES_t;

/*---------------------------------------------------------------------------
 * MSTP ports 'adminPointToPointMac' parameter values
 * (802.1Q-REV/D5.0 13.18)
 * NOTE: please update 'MSTP_ADMIN_PPMAC_s' (mstp_show.c) if you
 *       change this enumeration list
 *---------------------------------------------------------------------------*/
typedef enum MSTP_ADMIN_POINT_TO_POINT_MAC_t
{
   MSTP_ADMIN_PPMAC_UNKNOWN = 0,
   MSTP_ADMIN_PPMAC_FORCE_TRUE,
   MSTP_ADMIN_PPMAC_FORCE_FALSE,
   MSTP_ADMIN_PPMAC_AUTO,
   MSTP_ADMIN_PPMAC_MAX

} MSTP_ADMIN_POINT_TO_POINT_MAC_e;
#ifdef MSTP_DEBUG
typedef MSTP_ADMIN_POINT_TO_POINT_MAC_e MSTP_ADMIN_POINT_TO_POINT_MAC_t;
#else  /* !MSTP_DEBUG */
typedef uint8_t MSTP_ADMIN_POINT_TO_POINT_MAC_t;
#endif /* !MSTP_DEBUG */

/*---------------------------------------------------------------------------
 * Indicates the type of action to perform
 *---------------------------------------------------------------------------*/
typedef enum
{
   MSTP_ACT_UNKNOWN = 0,
   MSTP_ACT_DISABLE_FORWARDING,
   MSTP_ACT_ENABLE_FORWARDING,
   MSTP_ACT_ENABLE_LEARNING,
   MSTP_ACT_PROPAGATE_UP,
   MSTP_ACT_PROPAGATE_DOWN,
   MSTP_ACT_MAX

} MSTP_ACT_TYPE_e;
#ifdef MSTP_DEBUG
typedef MSTP_ACT_TYPE_e MSTP_ACT_TYPE_t;
#else  /* !MSTP_DEBUG */
typedef uint8_t MSTP_ACT_TYPE_t;
#endif /* !MSTP_DEBUG */

/*---------------------------------------------------------------------------
 * Indicates the type of BPDU received (MSTP or RSTP or STP CFG or STP TCN)
 * NOTE: please update 'MSTP_BPDU_TYPE_s' (mstp_show.c) if you
 *       change this enumeration list
 *---------------------------------------------------------------------------*/
typedef enum
{
   MSTP_BPDU_TYPE_UNKNOWN = 0,
   MSTP_BPDU_TYPE_MSTP,
   MSTP_BPDU_TYPE_RSTP,
   MSTP_BPDU_TYPE_STP,
   MSTP_BPDU_TYPE_TCN,
   MSTP_BPDU_TYPE_MAX

} MSTP_BPDU_TYPE_e;
#ifdef MSTP_DEBUG
typedef MSTP_BPDU_TYPE_e MSTP_BPDU_TYPE_t;
#else  /* !MSTP_DEBUG */
typedef uint8_t MSTP_BPDU_TYPE_t;
#endif /* !MSTP_DEBUG */


/*---------------------------------------------------------------------------
 * Enumeration type below defines set of indices used to identify a bit
 * position in the bit map allocated to store the values of bool type
 * variables assosiated with the Port.
 * Those variables are per-Port for the whole Bridge, i.e. every single
 * per-Port variable applies to the CIST and to all MSTIs. The bit map used to
 * hold these variables is the 'bitMap' field of the 'MSTP_COMM_PORT_INFO_t'
 * data structure.
 *---------------------------------------------------------------------------*/
typedef enum
{
   MSTP_PORT_OPER_EDGE = 1,           /*  1 */
   MSTP_PORT_PORT_ENABLED,            /*  2 */
   MSTP_PORT_TICK,                    /*  3 */
   MSTP_PORT_INFO_INTERNAL,           /*  4 */
   MSTP_PORT_RCVD_INTERNAL,           /*  5 */
   MSTP_PORT_RESTRICTED_ROLE,         /*  6 */
   MSTP_PORT_RESTRICTED_TCN,          /*  7 */
   MSTP_PORT_NEW_INFO,                /*  8 */
   MSTP_PORT_NEW_INFO_MSTI,           /*  9 */
   MSTP_PORT_MCHECK,                  /* 10 */
   MSTP_PORT_RCVD_BPDU,               /* 11 */
   MSTP_PORT_RCVD_RSTP,               /* 12 */
   MSTP_PORT_RCVD_STP,                /* 13 */
   MSTP_PORT_RCVD_TC_ACK,             /* 14 */
   MSTP_PORT_RCVD_TCN,                /* 15 */
   MSTP_PORT_SEND_RSTP,               /* 16 */
   MSTP_PORT_TC_ACK,                  /* 17 */
   MSTP_PORT_FDB_FLUSH,               /* 18 */
   MSTP_PORT_ADMIN_EDGE_PORT,         /* 19 */
   MSTP_PORT_AUTO_EDGE,               /* 20 */
   MSTP_PORT_OPER_POINT_TO_POINT_MAC, /* 21 */
   MSTP_PORT_BIT_MAP_MAX              /* 22 */

} MSTP_PORT_BIT_MAP_IDX_e;

/*---------------------------------------------------------------------------
 * Enumeration type below defines set of indices used to identify a bit
 * position in the bit map allocated to store the values of bool type
 * variables assosiated with the Port.
 * Those variables are per-Port for the CIST, i.e. every single per-Port
 * variable applies to the CIST. The bit map used to hold these
 * variables is the 'bitMap' field of the 'MSTP_CIST_PORT_INFO_t' data
 * structure.
 *---------------------------------------------------------------------------*/
typedef enum
{
   MSTP_CIST_PORT_AGREE = 1,         /*  1 */
   MSTP_CIST_PORT_DISPUTED,          /*  2 */
   MSTP_CIST_PORT_FORWARD,           /*  3 */
   MSTP_CIST_PORT_FORWARDING,        /*  4 */
   MSTP_CIST_PORT_LEARN,             /*  5 */
   MSTP_CIST_PORT_LEARNING,          /*  6 */
   MSTP_CIST_PORT_PROPOSED,          /*  7 */
   MSTP_CIST_PORT_PROPOSING,         /*  8 */
   MSTP_CIST_PORT_RCVD_MSG,          /*  9 */
   MSTP_CIST_PORT_RCVD_TC,           /* 10 */
   MSTP_CIST_PORT_RE_ROOT,           /* 11 */
   MSTP_CIST_PORT_RESELECT,          /* 12 */
   MSTP_CIST_PORT_SELECTED,          /* 13 */
   MSTP_CIST_PORT_TC_PROP,           /* 14 */
   MSTP_CIST_PORT_UPDT_INFO,         /* 15 */
   MSTP_CIST_PORT_AGREED,            /* 16 */
   MSTP_CIST_PORT_SYNC,              /* 17 */
   MSTP_CIST_PORT_SYNCED,            /* 18 */
   MSTP_CIST_PORT_CHANGED_MASTER,    /* 19 */
   MSTP_CIST_PORT_BIT_MAP_MAX        /* 20 */

} MSTP_CIST_PORT_BIT_MAP_IDX_e;

/*---------------------------------------------------------------------------
 * Enumeration type below defines set of indices used to identify a bit
 * position in the bit map allocated to store the values of bool type
 * variables assosiated with the Port.
 * Those variables are per-Port per-MSTI, i.e. every single per-Port
 * variable applies to the particular MSTI. The bit map used to hold these
 * variables is the 'bitMap' field of the 'MSTP_MSTI_PORT_INFO_t' data
 * structure.
 *---------------------------------------------------------------------------*/
typedef enum
{
   MSTP_MSTI_PORT_AGREE = 1,          /*  1 */
   MSTP_MSTI_PORT_DISPUTED,           /*  2 */
   MSTP_MSTI_PORT_FORWARD,            /*  3 */
   MSTP_MSTI_PORT_FORWARDING,         /*  4 */
   MSTP_MSTI_PORT_LEARN,              /*  5 */
   MSTP_MSTI_PORT_LEARNING,           /*  6 */
   MSTP_MSTI_PORT_PROPOSED,           /*  7 */
   MSTP_MSTI_PORT_PROPOSING,          /*  8 */
   MSTP_MSTI_PORT_RCVD_MSG,           /*  9 */
   MSTP_MSTI_PORT_RCVD_TC,            /* 10 */
   MSTP_MSTI_PORT_RE_ROOT,            /* 11 */
   MSTP_MSTI_PORT_RESELECT,           /* 12 */
   MSTP_MSTI_PORT_SELECTED,           /* 13 */
   MSTP_MSTI_PORT_TC_PROP,            /* 14 */
   MSTP_MSTI_PORT_UPDT_INFO,          /* 15 */
   MSTP_MSTI_PORT_AGREED,             /* 16 */
   MSTP_MSTI_PORT_SYNC,               /* 17 */
   MSTP_MSTI_PORT_SYNCED,             /* 18 */
   MSTP_MSTI_PORT_MASTER,             /* 19 */
   MSTP_MSTI_PORT_MASTERED,           /* 20 */
   MSTP_MSTI_PORT_BIT_MAP_MAX         /* 21 */

} MSTP_MSTI_PORT_BIT_MAP_IDX_e;

/*---------------------------------------------------------------------------
 * Used to indicate the origin/state of the Port's Spanning Tree information
 * held fot the port ('infoIs') .
 * (802.1Q-REV/D5.0 13.24 x))
 * NOTE: please update 'MSTP_INFO_IS_s' (mstp_show.c) if you
 *       change this enumeration list
 *---------------------------------------------------------------------------*/
typedef enum
{
   MSTP_INFO_IS_UNKNOWN = 0,
   MSTP_INFO_IS_DISABLED,
   MSTP_INFO_IS_RECEIVED,
   MSTP_INFO_IS_MINE,
   MSTP_INFO_IS_AGED,
   MSTP_INFO_IS_MAX

} MSTP_INFO_IS_e;
#ifdef MSTP_DEBUG
typedef MSTP_INFO_IS_e MSTP_INFO_IS_t;
#else
typedef uint8_t MSTP_INFO_IS_t;
#endif /* MSTP_DEBUG */

/*---------------------------------------------------------------------------
 * Used to indicate the type of information received in CIST or MSTI message
 * ('rcvdInfo').
 * (802.1Q-REV/D5.0 13.24 ac))
 * NOTE: please update 'MSTP_RCVD_INFO_s' (mstp_show.c) if you
 *       change this enumeration list
 *---------------------------------------------------------------------------*/
typedef enum
{
   MSTP_RCVD_INFO_UNKNOWN = 0,
   MSTP_RCVD_INFO_SUPERIOR_DESIGNATED,
   MSTP_RCVD_INFO_REPEATED_DESIGNATED,
   MSTP_RCVD_INFO_INFERIOR_DESIGNATED,
   MSTP_RCVD_INFO_INFERIOR_ROOT_ALTERNATE,
   MSTP_RCVD_INFO_OTHER,
   MSTP_RCVD_INFO_MAX

} MSTP_RCVD_INFO_e;
#ifdef MSTP_DEBUG
typedef MSTP_RCVD_INFO_e MSTP_RCVD_INFO_t;
#else
typedef uint8_t MSTP_RCVD_INFO_t;
#endif /* MSTP_DEBUG */
/* for disabled role purpose*/
#define MSTP_DISABLED 5

/*---------------------------------------------------------------------------
 * Used to indicate the assigned Port Role ('role', 'selectedRole').
 * (802.1Q-REV/D5.0 13.24.15; 13.24.16)
 * NOTE: please update 'MSTP_PORT_ROLE_s' (mstp_show.c) if you
 *       change this enumeration list
 *---------------------------------------------------------------------------*/
typedef enum
{
   MSTP_PORT_ROLE_UNKNOWN    = 0,
   MSTP_PORT_ROLE_ROOT       = 1,
   MSTP_PORT_ROLE_ALTERNATE  = 2, /* 2 */
   MSTP_PORT_ROLE_DESIGNATED = 3, /* 3 */
   MSTP_PORT_ROLE_BACKUP     = 4,
   MSTP_PORT_ROLE_DISABLED   = 5,
   MSTP_PORT_ROLE_MASTER     = 6,
   MSTP_PORT_ROLE_MAX

} MSTP_PORT_ROLE_e;
#ifdef MSTP_DEBUG
typedef MSTP_PORT_ROLE_e MSTP_PORT_ROLE_t;
#else
typedef uint8_t MSTP_PORT_ROLE_t;
#endif /* MSTP_DEBUG */

/*---------------------------------------------------------------------------
 * The Port Timers (PTI) state machine states
 * (802.1Q-REV/D5.0 13.27; 802.1D-2004 17.22)
 * NOTE: please update 'MSTP_PTI_STATE_s' (mstp_show.c) if you
 *       change this enumeration list
 *---------------------------------------------------------------------------*/
typedef enum
{
   MSTP_PTI_STATE_UNKNOWN = 0,         /* uninitialized (erroneous) SM state */
   MSTP_PTI_STATE_ONE_SECOND,
   MSTP_PTI_STATE_TICK,
   MSTP_PTI_STATE_MAX

} MSTP_PTI_STATE_e;
#ifdef MSTP_DEBUG
typedef MSTP_PTI_STATE_e MSTP_PTI_STATE_t;
#else
typedef uint8_t MSTP_PTI_STATE_t;
#endif /* MSTP_DEBUG */

/*---------------------------------------------------------------------------
 * Port Receive (PRX) state machine states
 * (802.1Q-REV/D5.0 13.28)
 * NOTE: please update 'MSTP_PRX_STATE_s' (mstp_show.c) if you
 *       change this enumeration list
 *---------------------------------------------------------------------------*/
typedef enum
{
   MSTP_PRX_STATE_UNKNOWN = 0,         /* uninitialized (erroneous) SM state */
   MSTP_PRX_STATE_DISCARD,
   MSTP_PRX_STATE_RECEIVE,
   MSTP_PRX_STATE_MAX

} MSTP_PRX_STATE_e;
#ifdef MSTP_DEBUG
typedef MSTP_PRX_STATE_e MSTP_PRX_STATE_t;
#else
typedef uint8_t MSTP_PRX_STATE_t;
#endif /* MSTP_DEBUG */

/*---------------------------------------------------------------------------
 * Port Protocol Migration (PPM) state machine states
 * (802.1Q-REV/D5.0 13.29; 802.1D-2004 17.24)
 * NOTE: please update 'MSTP_PPM_STATE_s' (mstp_show.c) if you
 *       change this enumeration list
 *---------------------------------------------------------------------------*/
typedef enum
{
   MSTP_PPM_STATE_UNKNOWN = 0,         /* uninitialized (erroneous) SM state */
   MSTP_PPM_STATE_CHECKING_RSTP,
   MSTP_PPM_STATE_SELECTING_STP,
   MSTP_PPM_STATE_SENSING,
   MSTP_PPM_STATE_MAX

} MSTP_PPM_STATE_e;
#ifdef MSTP_DEBUG
typedef MSTP_PPM_STATE_e MSTP_PPM_STATE_t;
#else
typedef uint8_t MSTP_PPM_STATE_t;
#endif /* MSTP_DEBUG */

/*---------------------------------------------------------------------------
 * Port Transmit (PTX) state machine states
 * (802.1Q-REV/D5.0 13.31)
 * NOTE: please update 'MSTP_PTX_STATE_s' (mstp_show.c) if you
 *       change this enumeration list
 *---------------------------------------------------------------------------*/
typedef enum
{
   MSTP_PTX_STATE_UNKNOWN = 0,         /* uninitialized (erroneous) SM state */
   MSTP_PTX_STATE_TRANSMIT_INIT,
   MSTP_PTX_STATE_TRANSMIT_PERIODIC,
   MSTP_PTX_STATE_IDLE,
   MSTP_PTX_STATE_TRANSMIT_CONFIG,
   MSTP_PTX_STATE_TRANSMIT_TCN,
   MSTP_PTX_STATE_TRANSMIT_RSTP,
   MSTP_PTX_STATE_MAX

} MSTP_PTX_STATE_e;
#ifdef MSTP_DEBUG
typedef MSTP_PTX_STATE_e MSTP_PTX_STATE_t;
#else
typedef uint8_t MSTP_PTX_STATE_t;
#endif /* MSTP_DEBUG */

/*---------------------------------------------------------------------------
 * Bridge Detection (BDM) state machine states
 * (802.1Q-REV/D5.0 13.30; 802.1D-2004 17.25)
 * NOTE: please update 'MSTP_BDM_STATE_s' (mstp_show.c) if you
 *       change this enumeration list
 *---------------------------------------------------------------------------*/
typedef enum
{
   MSTP_BDM_STATE_UNKNOWN = 0,         /* uninitialized (erroneous) SM state */
   MSTP_BDM_STATE_EDGE,
   MSTP_BDM_STATE_NOT_EDGE,
   MSTP_BDM_STATE_MAX

} MSTP_BDM_STATE_e;
#ifdef MSTP_DEBUG
typedef MSTP_BDM_STATE_e MSTP_BDM_STATE_t;
#else
typedef uint8_t MSTP_BDM_STATE_t;
#endif /* MSTP_DEBUG */

/*---------------------------------------------------------------------------
 * Port Information (PIM) state machine states
 * (802.1Q-REV/D5.0 13.32)
 * NOTE: please update 'MSTP_PIM_STATE_s' (mstp_show.c) if you
 *       change this enumeration list
 *---------------------------------------------------------------------------*/
typedef enum
{
   MSTP_PIM_STATE_UNKNOWN = 0,         /* uninitialized (erroneous) SM state */
   MSTP_PIM_STATE_DISABLED,
   MSTP_PIM_STATE_AGED,
   MSTP_PIM_STATE_UPDATE,
   MSTP_PIM_STATE_CURRENT,
   MSTP_PIM_STATE_RECEIVE,
   MSTP_PIM_STATE_SUPERIOR_DESIGNATED,
   MSTP_PIM_STATE_REPEATED_DESIGNATED,
   MSTP_PIM_STATE_INFERIOR_DESIGNATED,
   MSTP_PIM_STATE_NOT_DESIGNATED,
   MSTP_PIM_STATE_OTHER,
   MSTP_PIM_STATE_MAX

} MSTP_PIM_STATE_e;
#ifdef MSTP_DEBUG
typedef MSTP_PIM_STATE_e MSTP_PIM_STATE_t;
#else
typedef uint8_t  MSTP_PIM_STATE_t;
#endif /* MSTP_DEBUG */

/*---------------------------------------------------------------------------
 * Port Role Selection (PRS) state machine states
 * (802.1Q-REV/D5.0 13.33)
 * NOTE: please update 'MSTP_PRS_STATE_s' (mstp_show.c) if you
 *       change this enumeration list
 *---------------------------------------------------------------------------*/
typedef enum
{
   MSTP_PRS_STATE_UNKNOWN = 0,         /* uninitialized (erroneous) SM state */
   MSTP_PRS_STATE_INIT_TREE,
   MSTP_PRS_STATE_ROLE_SELECTION,
   MSTP_PRS_STATE_MAX

} MSTP_PRS_STATE_e;
#ifdef MSTP_DEBUG
typedef MSTP_PRS_STATE_e MSTP_PRS_STATE_t;
#else
typedef uint8_t MSTP_PRS_STATE_t;
#endif /* MSTP_DEBUG */

/*---------------------------------------------------------------------------
 * Port Role Transitions (PRT) state machine states
 * (802.1Q-REV/D5.0 13.34)
 * NOTE: please update 'MSTP_PRT_STATE_s' (mstp_show.c) if you
 *       change this enumeration list
 *---------------------------------------------------------------------------*/
typedef enum
{
   MSTP_PRT_STATE_UNKNOWN= 0,          /* uninitialized (erroneous) SM state */

   /* Disabled Port role transitions */
   MSTP_PRT_STATE_INIT_PORT,
   MSTP_PRT_STATE_DISABLE_PORT,
   MSTP_PRT_STATE_DISABLED_PORT,

   /* Master Port role transitions */
   MSTP_PRT_STATE_MASTER_PORT,
   MSTP_PRT_STATE_MASTER_PROPOSED,
   MSTP_PRT_STATE_MASTER_AGREED,
   MSTP_PRT_STATE_MASTER_SYNCED,
   MSTP_PRT_STATE_MASTER_RETIRED,
   MSTP_PRT_STATE_MASTER_FORWARD,
   MSTP_PRT_STATE_MASTER_LEARN,
   MSTP_PRT_STATE_MASTER_DISCARD,

   /* Root Port role transitions */
   MSTP_PRT_STATE_ROOT_PORT,
   MSTP_PRT_STATE_ROOT_PROPOSED,
   MSTP_PRT_STATE_ROOT_AGREED,
   MSTP_PRT_STATE_ROOT_SYNCED,
   MSTP_PRT_STATE_REROOT,
   MSTP_PRT_STATE_ROOT_FORWARD,
   MSTP_PRT_STATE_ROOT_LEARN,
   MSTP_PRT_STATE_REROOTED,

   /* Designated Port role transitions */
   MSTP_PRT_STATE_DESIGNATED_PORT,
   MSTP_PRT_STATE_DESIGNATED_PROPOSE,
   MSTP_PRT_STATE_DESIGNATED_AGREED,
   MSTP_PRT_STATE_DESIGNATED_SYNCED,
   MSTP_PRT_STATE_DESIGNATED_RETIRED,
   MSTP_PRT_STATE_DESIGNATED_FORWARD,
   MSTP_PRT_STATE_DESIGNATED_LEARN,
   MSTP_PRT_STATE_DESIGNATED_DISCARD,

   /* Alternate and Backup Port role transitions */
   MSTP_PRT_STATE_BLOCK_PORT,
   MSTP_PRT_STATE_ALTERNATE_PROPOSED,
   MSTP_PRT_STATE_ALTERNATE_AGREED,
   MSTP_PRT_STATE_ALTERNATE_PORT,
   MSTP_PRT_STATE_BACKUP_PORT,

   MSTP_PRT_STATE_MAX

} MSTP_PRT_STATE_e;
#ifdef MSTP_DEBUG
typedef MSTP_PRT_STATE_e MSTP_PRT_STATE_t;
#else /* !MSTP_DEBUG */
typedef uint8_t MSTP_PRT_STATE_t;
#endif /* !MSTP_DEBUG */

/*---------------------------------------------------------------------------
 * Port State Transition (PST) state machine states
 * (802.1Q-REV/D5.0 13.35)
 * NOTE: please update 'MSTP_PST_STATE_s' (mstp_show.c) if you
 *       change this enumeration list
 *---------------------------------------------------------------------------*/
typedef enum
{
   MSTP_PST_STATE_UNKNOWN = 0,         /* uninitialized (erroneous) SM state */
   MSTP_PST_STATE_DISCARDING,
   MSTP_PST_STATE_LEARNING,
   MSTP_PST_STATE_FORWARDING,
   MSTP_PST_STATE_MAX

} MSTP_PST_STATE_e;
#ifdef MSTP_DEBUG
typedef MSTP_PST_STATE_e MSTP_PST_STATE_t;
#else
typedef uint8_t MSTP_PST_STATE_t;
#endif /* MSTP_DEBUG */

/*---------------------------------------------------------------------------
 * Topology Change (TCM) state machine states
 * (802.1Q-REV/D5.0 13.36)
 * NOTE: please update 'MSTP_TCM_STATE_s' (mstp_show.c) if you
 *       change this enumeration list
 *---------------------------------------------------------------------------*/
typedef enum
{
   MSTP_TCM_STATE_UNKNOWN = 0,         /* uninitialized (erroneous) SM state */
   MSTP_TCM_STATE_INACTIVE,
   MSTP_TCM_STATE_LEARNING,
   MSTP_TCM_STATE_DETECTED,
   MSTP_TCM_STATE_ACTIVE,
   MSTP_TCM_STATE_NOTIFIED_TCN,
   MSTP_TCM_STATE_NOTIFIED_TC,
   MSTP_TCM_STATE_PROPAGATING,
   MSTP_TCM_STATE_ACKNOWLEDGED,
   MSTP_TCM_STATE_MAX

} MSTP_TCM_STATE_e;
#ifdef MSTP_DEBUG
typedef MSTP_TCM_STATE_e MSTP_TCM_STATE_t;
#else /* !MSTP_DEBUG */
typedef uint8_t MSTP_TCM_STATE_t;
#endif /* !MSTP_DEBUG */

/*---------------------------------------------------------------------------
 * Used to encode defaultPathCost (hpicfBridgeMSTPathCostDefault)
 *---------------------------------------------------------------------------*/
typedef enum
{
   path_cost_invalid   = -1, /* on bttf compiler needs to be made to pick
                              * signed type for this enum                    */
   path_cost_8021d     = 1,
   path_cost_8021t     = 2,
   path_cost_prop      = 3

} PATH_COST_TYPE_e;

/*---------------------------------------------------------------------------
 * Data type to deal with the Root Changes History information
 *---------------------------------------------------------------------------*/
typedef struct MSTP_ROOT_HISTORY_t
{
   bool                     valid;     /* indicates whether this entry
                                        * is valid (i.e. has been set)       */
   time_t                   timeStamp; /* time when this entry has been set  */
   MSTP_BRIDGE_IDENTIFIER_t rootID;    /* Identifier of the Root Bridge      */

} MSTP_ROOT_HISTORY_t;

/*---------------------------------------------------------------------------
 * Data type to deal with the TC History information
 *---------------------------------------------------------------------------*/
typedef struct MSTP_TC_HISTORY_t
{
   bool                      valid;      /* is this a valid entry             */
   LPORT_t                   lport;      /* port on which TC is originated    */
   time_t                    timeStamp;  /* time when this entry has been set */
   MAC_ADDRESS               mac;        /* Mac of lport                      */
   MSTP_PRT_STATE_t          prevState;  /* state before TC                   */
   MSTP_PRT_STATE_t          newState;   /* state after TC                    */
} MSTP_TC_HISTORY_t;

/*---------------------------------------------------------------------------
 * Used to encode trapSource (hpSwitchStpErrantBpduDetector)
 *---------------------------------------------------------------------------*/
typedef enum
{
   BPDU_FILTER     = 1,
   BPDU_PROTECTION = 2,
} TRAP_SOURCE_TYPE_e;

/*---------------------------------------------------------------------------
 * MSTI Port Debug Counters used for debugging and troubleshooting purposes
 *---------------------------------------------------------------------------*/
typedef struct MSTP_MSTI_PORT_DBG_CNTS_t
{
   uint32_t mstiMsgTxCnt;                  /* # of TX-ed MSTI CFG MSGs        */
   time_t  mstiMsgTxCntLastUpdated;       /* time stamp                      */
   uint32_t mstiMsgRxCnt;                  /* # of RX-ed MSTI CFG MSGs        */
   time_t  mstiMsgRxCntLastUpdated;       /* time stamp                      */
   uint32_t exceededHopsMsgCnt;            /* # of RX-ed MSTI CFG MSGs with
                                           * 'remainingHops' parameter being
                                           * less than or equal to zero      */
   time_t  exceededHopsMsgCntLastUpdated; /* time stamp                      */
   uint32_t tcDetectCnt;                   /* # of Topology Changes detected
                                           * by this port                    */
   time_t  tcDetectCntLastUpdated;        /* time stamp                      */
   uint32_t tcFlagTxCnt;                   /* # of times the TC flag was set
                                           * in MSTI CFG MSGs TX-ed through
                                           * this port                       */
   time_t  tcFlagTxCntLastUpdated;        /* time stamp                      */
   uint32_t tcFlagRxCnt;                   /* # of times the TC flag was set
                                           * in MSTI CFG MSGs RX-ed on this
                                           * port                            */
   time_t  tcFlagRxCntLastUpdated;        /* time stamp                      */
   uint32_t starvedMsgCnt;                 /* # of times MSTI MSGs were not
                                           * received at scheduled time on
                                           * this port                       */
   time_t  starvedMsgCntLastUpdated;      /* time stamp                      */

} MSTP_MSTI_PORT_DBG_CNTS_t;

typedef struct MSTP_PORT_HISTORY
{
   MSTP_PRT_STATE_t              oldState;
   MSTP_PRT_STATE_t              newState;
   uint32_t                      aged;
   time_t                        timeStamp; /* time when this entry
                                               has been set  */
   MSTP_CIST_BRIDGE_PRI_VECTOR_t portPriority;
   uint32_t                      valid;
}MSTP_PORT_HISTORY_t;

/*---------------------------------------------------------------------------
 * MSTI Per-Port Parameters.
 *---------------------------------------------------------------------------*/
typedef struct MSTP_MSTI_PORT_INFO_t
{
   /* Statistics MIB support (RFC1493 MIB) */
   uint32_t                          forwardTransitions;
   time_t                            forwardTransitionsLastUpdated;

   /* State Machine Performance Parameters (802.1Q-REV/D5.0) */
   uint32_t                          InternalPortPathCost;/* 13.37.1         */
   bool                             useCfgPathCost;/* indicates whether to use
                                                    * user configured path cost
                                                    * value or 'autodetect' it
                                                    * from the link speed */
   uint32_t                           mstiPort_uptime;

   bool                             loopInconsistent;   /* TRUE if port
                                                          * state is
                                                          * inconsistent */

   bool                             rootInconsistent;
   /* Per-Port Variables (802.1Q-REV/D5.0 13.24) */
   MSTP_INFO_IS_t                    infoIs;             /*  x)              */
   MSTP_RCVD_INFO_t                  rcvdInfo;           /* ac)              */
   MSTP_MSTI_DESIGNATED_PRI_VECTOR_t designatedPriority; /* al)              */
   MSTP_MSTI_DESIGNATED_TIMES_t      designatedTimes;    /* am)              */
   MSTP_MSTI_MSG_PRI_VECTOR_t        msgPriority;        /* an)              */
   MSTP_MSTI_MSG_TIMES_t             msgTimes;           /* ao)              */
   MSTP_PORT_ID_t                    portId;             /* ap)              */
   MSTP_MSTI_PORT_PRI_VECTOR_t       portPriority;       /* aq)              */
   MSTP_MSTI_PORT_TIMES_t            portTimes;          /* ar)              */
   MSTP_PORT_ROLE_t                  role;               /* as)              */
   MSTP_PORT_ROLE_t                  selectedRole;       /* at)              */
   uint32_t                          bitMap[((MSTP_MSTI_PORT_BIT_MAP_MAX+31)/32)];
   /* NOTE: variables of bool type are combined into above bit map,
    * namely:
                                     agree,                  t)
                                     disputed                u)
                                     forward                 v)
                                     forwarding              w)
                                     learn                   y)
                                     learning                z)
                                     proposed               aa)
                                     proposing              ab)
                                     rcvdMsg                ad)
                                     rcvdTc                 ae)
                                     reRoot                 af)
                                     reselect               ag)
                                     selected               ah)
                                     tcProp                 ai)
                                     updtInfo               aj)
                                     agreed                 ak)
                                     sync                   au)
                                     synced                 av)
                                     master                 ax)
                                     mastered               ay)
   */

   /* State Machine Timers (802.1Q-REV/D5.0 13.21) */
   uint8_t                            fdWhile;            /*  d)              */
   uint8_t                            rrWhile;            /*  e)              */
   uint8_t                            rbWhile;            /*  f)              */
   uint8_t                            tcWhile;            /*  g)              */
   uint8_t                            rcvdInfoWhile;      /*  h)              */

   /* Per-Port State Machines states (802.1Q-REV/D5.0) */
   MSTP_PIM_STATE_t                  pimState;           /* 13.32            */
   MSTP_PRT_STATE_t                  prtState;           /* 13.34            */
   MSTP_PST_STATE_t                  pstState;           /* 13.35            */
   MSTP_TCM_STATE_t                  tcmState;           /* 13.36            */

   /* Counters used for debugging and troubleshooting purposes */
   MSTP_MSTI_PORT_DBG_CNTS_t         dbgCnts;

   MSTP_PORT_HISTORY_t               portHistory[MSTP_PORT_HISTORY_MAX];
} MSTP_MSTI_PORT_INFO_t;

/*---------------------------------------------------------------------------
 * CIST Port Debug Counters used for debugging and troubleshooting purposes
 *---------------------------------------------------------------------------*/
typedef struct MSTP_CIST_PORT_DBG_CNTS_t
{
   uint32_t mstBpduTxCnt;                  /* # of TX-ed MST BPDUs            */
   time_t  mstBpduTxCntLastUpdated;       /* time stamp                      */
   uint32_t mstBpduRxCnt;                  /* # of RX-ed MST BPDUs            */
   time_t  mstBpduRxCntLastUpdated;       /* time stamp                      */
   uint32_t rstBpduTxCnt;                  /* # of TX-ed RST BPDUs            */
   time_t  rstBpduTxCntLastUpdated;       /* time stamp                      */
   uint32_t rstBpduRxCnt;                  /* # of RX-ed RST BPDUs            */
   time_t  rstBpduRxCntLastUpdated;       /* time stamp                      */
   uint32_t cfgBpduTxCnt;                  /* # of TX-ed CFG BPDUs            */
   time_t  cfgBpduTxCntLastUpdated;       /* time stamp                      */
   uint32_t cfgBpduRxCnt;                  /* # of RX-ed CFG BPDUs            */
   time_t  cfgBpduRxCntLastUpdated;       /* time stamp                      */
   uint32_t tcnBpduTxCnt;                  /* # of TX-ed TCN BPDUs            */
   time_t  tcnBpduTxCntLastUpdated;       /* time stamp                      */
   uint32_t tcnBpduRxCnt;                  /* # of RX-ed TCN BPDUs            */
   time_t  tcnBpduRxCntLastUpdated;       /* time stamp                      */
   uint32_t agedBpduCnt;                   /* number of aged BPDUs            */
   time_t  agedBpduCntLastUpdated;        /* time stamp   */
   uint32_t exceededHopsBpduCnt;           /* # of RX-ed BPDUs with
                                           * 'remainingHops' parameter being
                                           * less than or equal to zero      */
   time_t  exceededHopsBpduCntLastUpdated;/* time stamp                      */
   uint32_t tcDetectCnt;                   /* # of Topology Changes
                                           * detected by this port           */
   time_t  tcDetectCntLastUpdated;        /* time stamp                      */
   uint32_t tcFlagTxCnt;                   /* # of times the TC flag was set
                                           * in CFG, RST or MST BPDUs TX-ed
                                           * through this port               */
   time_t  tcFlagTxCntLastUpdated;        /* time stamp                      */
   uint32_t tcFlagRxCnt;                   /* # of times the TC flag was set
                                           * in CFG, RST or MST BPDUs RX-ed
                                           * on this port                    */
   time_t  tcFlagRxCntLastUpdated;        /* time stamp                      */
   uint32_t tcAckFlagTxCnt;                /* # of TX-ed BPDUs with TC-ACK
                                           * flag set                        */
   time_t  tcAckFlagTxCntLastUpdated;     /* time stamp                      */
   uint32_t tcAckFlagRxCnt;                /* # of RX-ed BPDUs with TC-ACK
                                           * flag set                        */
   time_t  tcAckFlagRxCntLastUpdated;     /* time stamp                      */
   uint32_t starvedBpduCnt;                /* # of times BPDU was not received
                                           * at scheduled time on this port  */
   time_t  starvedBpduCntLastUpdated;     /* time stamp                      */
   uint32_t invalidBpduCnt;                /* # of received invalid BPDUs     */
   time_t  invalidBpduCntLastUpdated;     /* time stamp                      */
   uint32_t errantBpduCnt;                 /* # of received unexpected BPDUs  */
   time_t  errantBpduCntLastUpdated;      /* time stamp                      */
   uint32_t mstCfgErrorBpduCnt;            /* # of RX-ed BPDUs with
                                           * misconfiged MST Configuration
                                           * Identifier                      */
   time_t  mstCfgErrorBpduCntLastUpdated; /* time stamp                      */
   uint32_t loopBackBpduCnt;               /* # of looped-back BPDUs          */
   time_t  loopBackBpduCntLastUpdated;    /* time stamp                      */
} MSTP_CIST_PORT_DBG_CNTS_t;

/*---------------------------------------------------------------------------
 * CIST Per-Port Parameters.
 *---------------------------------------------------------------------------*/
typedef struct MSTP_CIST_PORT_INFO_t
{
   /* Statistics MIB support (RFC1493 MIB) */
   uint32_t                          forwardTransitions;
   time_t                            forwardTransitionsLastUpdated;

   /* State Machine Performance Parameters (802.1Q-REV/D5.0)  */
   uint32_t                          InternalPortPathCost;/* 13.37.1 */
   bool                             useCfgPathCost;/* indicates whether to use
                                                    * user configured path cost
                                                    * value or 'autodetect' it
                                                    * from the link speed */
  uint32_t                           cistPort_uptime;

   bool                             loopInconsistent;  /* TREU if port
                                                         * state is
                                                         * inconsistent */

   bool                             rootInconsistent;
   /* Per-Port Variables (802.1Q-REV/D5.0 13.24) */
   MSTP_INFO_IS_t                    infoIs;             /*  x)               */
   MSTP_RCVD_INFO_t                  rcvdInfo;           /* ac)               */
   MSTP_CIST_DESIGNATED_PRI_VECTOR_t designatedPriority; /* al)               */
   MSTP_CIST_DESIGNATED_TIMES_t      designatedTimes;    /* am)               */
   MSTP_CIST_MSG_PRI_VECTOR_t        msgPriority;        /* an)               */
   MSTP_CIST_MSG_TIMES_t             msgTimes;           /* ao)               */
   MSTP_PORT_ID_t                    portId;             /* ap)               */
   MSTP_CIST_PORT_PRI_VECTOR_t       portPriority;       /* aq)               */
   MSTP_CIST_PORT_TIMES_t            portTimes;          /* ar)               */
   MSTP_PORT_ROLE_t                  role;               /* as)               */
   MSTP_PORT_ROLE_t                  selectedRole;       /* at)               */
   uint32_t                        bitMap[((MSTP_CIST_PORT_BIT_MAP_MAX+31)/32)];
   /* NOTE: variables of bool type are combined into above bit map,
    * namely:
                                     agree,                  t)
                                     disputed                u)
                                     forward                 v)
                                     forwarding              w)
                                     learn                   y)
                                     learning                z)
                                     proposed               aa)
                                     proposing              ab)
                                     rcvdMsg                ad)
                                     rcvdTc                 ae)
                                     reRoot                 af)
                                     reselect               ag)
                                     selected               ah)
                                     tcProp                 ai)
                                     updtInfo               aj)
                                     agreed                 ak)
                                     sync                   au)
                                     synced                 av)
   */

   /* State Machine Timers (802.1Q-REV/D5.0 13.21) */
   uint8_t                            fdWhile;            /*  d)              */
   uint8_t                            rrWhile;            /*  e)              */
   uint8_t                            rbWhile;            /*  f)              */
   uint8_t                            tcWhile;            /*  g)              */
   uint8_t                            rcvdInfoWhile;      /*  h)              */

   /* Per-Port State Machines states (802.1Q-REV/D5.0) */
   MSTP_PIM_STATE_t                  pimState;           /* 13.32            */
   MSTP_PRT_STATE_t                  prtState;           /* 13.34            */
   MSTP_PST_STATE_t                  pstState;           /* 13.35            */
   MSTP_TCM_STATE_t                  tcmState;           /* 13.36            */

   /* Counters used for debugging and troubleshooting purposes */
   MSTP_CIST_PORT_DBG_CNTS_t         dbgCnts;
   MSTP_PORT_HISTORY_t               portHistory[MSTP_PORT_HISTORY_MAX];
} MSTP_CIST_PORT_INFO_t;

/*---------------------------------------------------------------------------
 * CIST and MSTIs common Per-Port information.
 *---------------------------------------------------------------------------*/
typedef struct MSTP_COMM_PORT_INFO_t
{
   /* State Machine Timers (802.1Q-REV/D5.0 13.21) */
   uint8_t                          mdelayWhile;    /* a)                     */
   uint8_t                          helloWhen;      /* b)                     */
   uint8_t                          edgeDelayWhile; /* c)                     */

   /* State Machine Performance Parameters (802.1Q-REV/D5.0 13.37) */
   bool                           useGlobalHelloTime;/* TRUE means use per
                                                       * box Hello Time value*/
   uint16_t                        HelloTime;           /* g)                */
   uint32_t                         ExternalPortPathCost;/* f)                */
   bool                           useCfgPathCost;/* indicates whether to use
                                                   * user configured path cost
                                                   * value or 'autodetect' it
                                                   * from the link speed     */
   bool                           rcvdSelfSentPkt;/* TRUE if this port RX-ed
                                                    * self-sent (externally
                                                    * looped-back) BPDU      */

   /* Per-Port Variables (802.1Q-REV/D5.0 13.24) */
   uint8_t                          txCount;        /* e)                     */
   uint32_t                         ageingTime;     /* a) */
   uint32_t                        bitMap[((MSTP_PORT_BIT_MAP_MAX + 31)/32)];
   /* NOTE: variables of bool type are combined into above bit map,
    * namely:
                                   operEdge           b)
                                   portEnabled        c)
                                   tick               d)
                                   infoInternal       f)
                                   rcvdInternal       g)
                                   restrictedRole     h)
                                   restrictedTcn      i)
                                   newInfo           aw)
                                   newInfoMsti        j)
                                   mcheck             k)
                                   rcvdBpdu           l)
                                   rcvdRSTP           m)
                                   rcvdSTP            n)
                                   rcvdTcAck          o)
                                   rcvdTcn            p)
                                   sendRSTP           q)
                                   tcAck              r)
                                   fdbFlush           s)
                                   adminEdgePort      k)
                                   autoEdge           m)
                                   operPointToPointMAC 802.1D-2004 6.4.3
   */

   /* Per-Port Variables (802.1D-2004 6.4.3) */
   MSTP_ADMIN_POINT_TO_POINT_MAC_t   adminPointToPointMAC;

   /* Per-Port State Machines states (802.1Q-REV/D5.0) */
   MSTP_PTI_STATE_t                ptiState; /* 13.27 (802.1D-2004 17.22)    */
   MSTP_PPM_STATE_t                ppmState; /* 13.29 (802.1D-2004 17.24)    */
   MSTP_PRX_STATE_t                prxState; /* 13.28 (802.1D-2004 17.23)    */
   MSTP_PTX_STATE_t                ptxState; /* 13.31 (802.1D-2004 17.26)    */
   MSTP_BDM_STATE_t                bdmState; /* 13.30 (802.1D-2004 17.25)    */

   /* Per-port BPDU Controls: BPDU-Filter; BPDU-Protection */
   uint8_t                          trapThrottleTimer;/* trap countdown timer */
   bool                           trapPending;  /* trap pending indication  */
   bool                           inBpduError;  /* TRUE if port received an
                                                  * unauthorized BPDU        */
   uint16_t                        reEnableTimer;/* seconds remaining until
                                                  * port in "inBpduError"
                                                  * state is reenabled       */
   TRAP_SOURCE_TYPE_e              trapSource;   /* Indicates last trigger
                                                  * of traps                 */
   MAC_ADDRESS                     bpduSrcMac;   /* Src Mac of RXed Bpdu     */
   uint32_t                         trapPortState;/* Stored port state at
                                                  * time of trap trigger     */
#ifdef MSTP_DEBUG
   bool                           dropBpdu;     /* When set to TRUE we drop
                                                  * BPDU on this port        */
#endif /* MSTP_DEBUG */

   /* Debug rate monitors: */
   uint32_t                        dbxTxCnt;
   uint32_t                        dbxTxRate;
   uint32_t                        dbxRxCnt;
   uint32_t                        dbxRxRate;


} MSTP_COMM_PORT_INFO_t;

/*---------------------------------------------------------------------------
 * MSTI specific information.
 *---------------------------------------------------------------------------*/
typedef struct MSTP_MSTI_INFO_t
{
   /* Per-Port Parameters */
   MSTP_MSTI_PORT_INFO_t            *MstiPortInfo[MAX_LPORTS + 1];

   /* Statistics MIB support (802.1Q-REV/D5.0 12.8.1.2.3) */
   uint32_t                          timeSinceTopologyChange; /* c)          */
   uint32_t                          topologyChangeCnt;       /* d)          */

   /* Per-Bridge Variables for the CIST (802.1Q-REV/D5.0 13.23)              */
   MSTP_BRIDGE_IDENTIFIER_t          BridgeIdentifier;  /* c) */
   MSTP_MSTI_BRIDGE_PRI_VECTOR_t     BridgePriority;          /* d)          */
   MSTP_MSTI_BRIDGE_TIMES_t          BridgeTimes;             /* e)          */
   MSTP_PORT_ID_t                    rootPortID;              /* f)          */
   MSTP_MSTI_ROOT_PRI_VECTOR_t       rootPriority;            /* g)          */
   MSTP_MSTI_ROOT_TIMES_t            rootTimes;               /* h)          */

   /* Per-Bridge State Machines states (802.1Q-REV/D5.0) */
   MSTP_PRS_STATE_t                  prsState;                /* 13.33       */

   /* VLAN group number associated with this instance */
   VLAN_GROUP_t                      vlanGroupNum;

   /* The MSTI Root Change History Information */
   uint32_t                           mstiRgnRootChangeCnt;/* # of times the
                                                       * MSTI Regional Root
                                                       * Bridge has been
                                                       * changed             */
   MSTP_ROOT_HISTORY_t               mstiRgnRootHistory[MSTP_ROOT_HISTORY_MAX];
   /* Per msti topology change history */
   MSTP_TC_HISTORY_t                 tcOrigHistory[MSTP_TC_HISTORY_MAX];
   MSTP_TC_HISTORY_t                 tcRcvHistory[MSTP_TC_HISTORY_MAX];

   /* Whether MSTI is initialized and running MSTP */
   bool                             valid;/* Indicates this data structure
                                            * is properly initialized        */

   bool                              portStateChangeLog;/* Enable/disable port
                                                      bloc/unblock per VLAN */
   bool                              tcTrapControl;
} MSTP_MSTI_INFO_t;

/*---------------------------------------------------------------------------
 * CIST specific information.
 *---------------------------------------------------------------------------*/
typedef struct MSTP_CIST_INFO_t
{
   /* Per-Port Parameters */
   MSTP_CIST_PORT_INFO_t            *CistPortInfo[MAX_LPORTS + 1];

   /* Statistics MIB support (802.1Q-REV/D5.0 12.8.1.2.3) */
   uint32_t                          timeSinceTopologyChange; /* c)          */
   uint32_t                          topologyChangeCnt;       /* d)          */

   /* Per-Bridge Variables for the CIST (802.1Q-REV/D5.0 13.23) */
   MSTP_BRIDGE_IDENTIFIER_t          BridgeIdentifier;        /* c)          */
   MSTP_CIST_BRIDGE_PRI_VECTOR_t     BridgePriority;          /* d)          */
   MSTP_CIST_BRIDGE_TIMES_t          BridgeTimes;             /* e)          */
   MSTP_PORT_ID_t                    rootPortID;              /* f)          */
   MSTP_CIST_ROOT_PRI_VECTOR_t       rootPriority;            /* g)          */
   MSTP_CIST_ROOT_TIMES_t            rootTimes;               /* h) */
   uint16_t                          cistRootHelloTime; /* to held 'Hello Time'
                                                         * value propagated
                                                         * by the CIST Root */

   /* Per-Bridge State Machines states (802.1Q-REV/D5.0) */
   MSTP_PRS_STATE_t                  prsState;                /* 13.33       */

   /* The CST Root change history information */
   uint32_t                           cstRootChangeCnt;/* # of times the CST
                                                       * Root Bridge has been
                                                       * changed             */
   MSTP_ROOT_HISTORY_t               cstRootHistory[MSTP_ROOT_HISTORY_MAX];

   /* The IST Regional Root change history information */
   uint32_t                           istRgnRootChangeCnt;/* # of times the IST
                                                       * Regional Root Bridge
                                                       * has been changed    */
   MSTP_ROOT_HISTORY_t               istRgnRootHistory[MSTP_ROOT_HISTORY_MAX];
   /* Topology Change History on Cist */
   MSTP_TC_HISTORY_t                 tcOrigHistory[MSTP_TC_HISTORY_MAX];
   MSTP_TC_HISTORY_t                 tcRcvHistory[MSTP_TC_HISTORY_MAX];
   /* Whether CIST is initialized and running MSTP */
   bool                             valid; /* Indicates this data structure
                                             * is properly initialized       */

   bool                              portStateChangeLog;/* Enable/disable port
                                                      bloc/unblock per VLAN */
   bool                              tcTrapControl;
} MSTP_CIST_INFO_t;

/*---------------------------------------------------------------------------
 * MSTP Bridge Operation Information.
 * This data structure is used to keep all operational information for the
 * Bridge running MST Protocol.
 *---------------------------------------------------------------------------*/
typedef struct MSTP_BRIDGE_INFO_t
{
   /* CIST and MSTIs common Per-Bridge Variables (802.1Q-REV/D5.0) */
   bool                        BEGIN;           /* 13.23 a)                */
   MSTP_MST_CONFIGURATION_ID_t  MstConfigId;     /* 13.23 b)                */

   /* CIST specific information */
   MSTP_CIST_INFO_t             CistInfo;

   /* MSTI specific information */
   MSTP_MSTI_INFO_t            *MstiInfo[MSTP_INSTANCES_MAX + 1];

   /* CIST and MSTIs common Per-Port information */
   MSTP_COMM_PORT_INFO_t       *PortInfo[MAX_LPORTS + 1];

   /* CIST and MSTIs common State Machine Performance Parameters
    * (802.1Q-REV/D5.0) */
   uint32_t                      MigrateTime;     /* 13.25 e)                 */
   uint32_t                      FwdDelay;        /* 13.25 k)                 */
   uint16_t                     HelloTime;       /* 13.25 l)                 */
   uint16_t                     MaxAge;          /* 13.25 m)                 */
   uint8_t                       TxHoldCount;     /* 13.25 i)                 */
   uint8_t                       MaxHops;         /* 13.22 o)                 */
   uint8_t                       ForceVersion;    /* 13.6.2                   */

   /* Misc globals */
   uint8_t                       numOfValidTrees; /* # of MSTIs currently
                                                  * running */
   int                          maxVlanGroups;   /* max VLAN groups
                                                  * supported for this boot  */
   bool                        dynReconfig;     /* indicates whether dynamic
                                                  * change occured that
                                                  * require re-initialization
                                                  * of MSTP                  */
   PATH_COST_TYPE_e             defaultPathCosts;/* indicates whether default
                                                  * path costs from 802.1d or
                                                  * 802.1t are used          */
   uint8_t                       trap_mask;       /* enabled STP traps        */
   bool                        preventTx;       /* Used to lock/unlock BPDU
                                                  * transmission on all MSTP
                                                  * ports                    */
   PORT_MAP                     bpduFilterLports;/* BPDU-Filtered ports      */
   /* Ports with bpdu protection enabled */
   PORT_MAP                     bpduProtectionLports;/* BPDU-Protected
                                                  * ports                    */
   /* Loop guard configured ports */
   PORT_MAP                     loopGuardLports;/* Loop guard configured
                                                 * ports                      */
   uint16_t                     portReEnableTimeout;/* time (in seconds)
                                                  * for BPDU-protected ports
                                                  * to be in down state after
                                                  * receiving unauthorized
                                                  * BPDUs                    */
} MSTP_BRIDGE_INFO_t;

/*---------------------------------------------------------------------------
 * Multiple Spanning Tree Protocol (MSTP) Control block
 *---------------------------------------------------------------------------*/
typedef struct MSTP_CB /* MSTP Control Block */
{
   PORT_MAP         fwdLports;/* lports that we have told IDL are
                                   * forwarding */
   PORT_MAP         blkLports;/* lports that we have told IDL are
                                   * blocked */
   MSTP_TREE_MSGS_t msgs;         /* info to be sent to other subsystems */
   uint32_t         prBpduCnt;    /* number of BPDUs processed by MSTP Control
                                   * Task per drivers poll interval */
   uint32_t         prBpduWm;     /* high water mark of BPDUs processed by MSTP
                                   * Control Task per drivers poll interval */
   uint32_t         rxBpduCnt;    /* to count number of BPDUs received by MSTP
                                   * Control Task within 1 second interval */
   uint32_t         rxBpduWm;     /* high water mark of BPDUs received by MSTP
                                   * Control Task within 1 second interval */
   /* to collect max number of transmitted BPDUs (per second) */
   uint32_t         txBpduCnt;
   uint32_t         txBpduWm;

} MSTP_CB_t;

/*****************************************************************************
 *        BPDU formats and parameters
 *****************************************************************************/

/*---------------------------------------------------------------------------
 * Used to encode STP Configuration BPDUs
 * (sizeof(LSAP_HDR) + MSTP_STP_CONFIG_BPDU_LEN_MIN = 52 octets long)
 * (802.1Q-REV/D5.0 14.3.1; 802.1D-2004 9.3.1)
 *---------------------------------------------------------------------------*/
#pragma pack(push,1)
typedef struct MSTP_CFG_BPDU_t
{
   LSAP_HDR                 lsapHdr;
   uint16_t                 protocolId;
   uint8_t                   protocolVersionId;
   uint8_t                   bpduType;
   uint8_t                   flags;
   STP_BRIDGE_IDENTIFIER_t  rootId;
   uint32_t                 rootPathCost;
   STP_BRIDGE_IDENTIFIER_t  bridgeId;
   uint16_t                 portId;
   uint16_t                 msgAge;
   uint16_t                 maxAge;
   uint16_t                 helloTime;
   uint16_t                 fwdDelay;
} MSTP_CFG_BPDU_t;
/*---------------------------------------------------------------------------
 * Used to encode STP Topology change notification BPDUs
 * (sizeof(LSAP_HDR) + MSTP_STP_TCN_BPDU_LEN_MIN = 21 octets long)
 * (802.1Q-REV/D5.0 14.3.1; 802.1D-2004 9.3.2)
 *---------------------------------------------------------------------------*/
typedef struct MSTP_TCN_BPDU_t
{
   LSAP_HDR                 lsapHdr;
   uint16_t                 protocolId;
   uint8_t                   protocolVersionId;
   uint8_t                   bpduType;

} MSTP_TCN_BPDU_t;

/*---------------------------------------------------------------------------
 * Common (minimal) part of all BPDUs MSTP operates with
 * (used to facilitate validation of the received BPDUs)
 *---------------------------------------------------------------------------*/
typedef MSTP_TCN_BPDU_t MSTP_BPDU_COMMON_HEADER_t;

/*---------------------------------------------------------------------------
 * Used to encode RST BPDUs
 * (sizeof(LSAP_HDR) + MSTP_RST_BPDU_LEN_MIN = 53 octets long)
 * (802.1Q-REV/D5.0 14.3.2; 802.1D-2004 9.3.3)
 *---------------------------------------------------------------------------*/
typedef struct MSTP_RST_BPDU_t
{
   LSAP_HDR                 lsapHdr;
   uint16_t                 protocolId;
   uint8_t                   protocolVersionId;
   uint8_t                   bpduType;
   uint8_t                   flags;
   RSTP_BRIDGE_IDENTIFIER_t rootId;
   uint32_t                 rootPathCost;
   RSTP_BRIDGE_IDENTIFIER_t bridgeId;
   uint16_t                 portId;
   uint16_t                 msgAge;
   uint16_t                 maxAge;
   uint16_t                 helloTime;
   uint16_t                 fwdDelay;
   uint8_t                   version1Length;

} MSTP_RST_BPDU_t;

/*---------------------------------------------------------------------------
 * Used to encode MST BPDUs
 * (sizeof(LSAP_HDR) + MSTP_MST_BPDU_LEN_MIN +
 *                                    sizeof(mstiConfigMsgs) = 120 octets long)
 * NOTE: 'mstiConfigMsgs' may be absent
 * (802.1Q-REV/D5.0 14.3.3)
 *---------------------------------------------------------------------------*/
typedef struct MSTP_MST_BPDU_t
{
   /* STP & RSTP & MSTP common parameters */
   LSAP_HDR                    lsapHdr;
   uint16_t                    protocolId;
   uint8_t                      protocolVersionId;
   uint8_t                      bpduType;
   uint8_t                      cistFlags;
   MSTP_BRIDGE_IDENTIFIER_t    cistRootId;
   uint32_t                    cistExtPathCost;
   MSTP_BRIDGE_IDENTIFIER_t    cistRgnRootId;
   uint16_t                    cistPortId;
   uint16_t                    msgAge;
   uint16_t                    maxAge;
   uint16_t                    helloTime;
   uint16_t                    fwdDelay;
   /* RSTP & MSTP common parameters */
   uint8_t                      version1Length;
   /* MSTP only specific parameters */
   uint16_t                    version3Length;
   MSTP_MST_CONFIGURATION_ID_t mstConfigurationId;
   uint32_t                    cistIntRootPathCost;
   MSTP_BRIDGE_IDENTIFIER_t    cistBridgeId;
   uint8_t                      cistRemainingHops;
   uint8_t                      mstiConfigMsgs[1];

} MSTP_MST_BPDU_t;

/*---------------------------------------------------------------------------
 * Used to encode MSTI Configuration Messages in MST BPDUs (16 octets long)
 * (802.1Q-REV/D5.0 14.6.1)
 *---------------------------------------------------------------------------*/
typedef struct MSTP_MSTI_CONFIG_MSG_t
{
   uint8_t                   mstiFlags;
   MSTP_BRIDGE_IDENTIFIER_t mstiRgnRootId;
   uint32_t                 mstiIntRootPathCost;
   uint8_t                   mstiBridgePriority;
   uint8_t                   mstiPortPriority;
   uint8_t                   mstiRemainingHops;

} MSTP_MSTI_CONFIG_MSG_t;
#pragma pack(pop)

/*****************************************************************************
 *        MSTP Debug support
 *****************************************************************************/
#ifdef MSTP_DEBUG

typedef enum
{
   MSTP_PIM = 1,
   MSTP_PRS,
   MSTP_PRT,
   MSTP_PRX,
   MSTP_PST,
   MSTP_TCM,
   MSTP_PPM,
   MSTP_PTX,
   MSTP_PTI,
   MSTP_BDM,
   MSTP_SM_MAX_BIT = MSTP_BDM

} MSTP_SM_TYPE_e;

typedef struct MSTP_SM_MAP
{
   uint32_t sm_map[((MSTP_SM_MAX_BIT + 31)/32)];
} MSTP_SM_MAP;

typedef struct MSTP_MSTI_MAP
{
   uint32_t map[((MSTP_INSTANCES_MAX + 31)/32)];
} MSTP_MSTI_MAP;

#endif /* MSTP_DEBUG */
/*****************************************************************************
 *        External Declarations
 *****************************************************************************/

/*---------------------------------------------------------------------------
 * MSTP misc globals
 *---------------------------------------------------------------------------*/
MSTP_CB_t         mstp_CB;
MSTP_BRIDGE_INFO_t
                         mstp_Bridge;
VID_MAP           mstp_MstiVidTable[MSTP_INSTANCES_MAX + 1];
MSTID_t           mstp_vlanGroupNumToMstIdTable[MSTP_INSTANCES_MAX + 1];
const uint8_t     mstp_DigestSignatureKey[MSTP_DIGEST_KEY_LEN];

struct_handle_t     gMstpStructMem[MSTP_MAX_LOG_THROTTLE_CLIENT];
hash_handle_t       gMstpThrottleHashTbl[MSTP_MAX_LOG_THROTTLE_CLIENT];
throttle_handle_t   gMstpInfoThrottle[MSTP_MAX_LOG_THROTTLE_CLIENT];

/*---------------------------------------------------------------------------
 * Global variable held the running STP implementation version
 * (0 -> 802.1d STP, 2 -> 802.1w RSTP, 3 -> 802.1Q MSTP)
 * Defined in 'rstp_init.c'
 *---------------------------------------------------------------------------*/
uint8_t Stp_version;

/*---------------------------------------------------------------------------
 * Global variable that is used to indicate to external features that some
 * implementation version of STP protocol is running. Defined in 'stp_init.c'.
 *---------------------------------------------------------------------------*/
uint8_t Spanning;

/*---------------------------------------------------------------------------
 * Global variable used to indicate that the initialization of STP is
 * completed. Defined in 'stp_init.c'.
 *---------------------------------------------------------------------------*/
bool   Stp_Initialized;


char* const   MSTP_ADMIN_PPMAC_s[MSTP_ADMIN_PPMAC_MAX];
char* const   MSTP_BPDU_TYPE_s[MSTP_BPDU_TYPE_MAX];
char* const   MSTP_PORT_ROLE_s[MSTP_PORT_ROLE_MAX];
char* const   MSTP_INFO_IS_s[MSTP_INFO_IS_MAX];
char* const   MSTP_RCVD_INFO_s[MSTP_RCVD_INFO_MAX];
char* const   MSTP_PTI_STATE_s[MSTP_PTI_STATE_MAX];
char* const   MSTP_PTX_STATE_s[MSTP_PTX_STATE_MAX];
char* const   MSTP_PRX_STATE_s[MSTP_PRX_STATE_MAX];
char* const   MSTP_PPM_STATE_s[MSTP_PPM_STATE_MAX];
char* const   MSTP_PIM_STATE_s[MSTP_PIM_STATE_MAX];
char* const   MSTP_PRS_STATE_s[MSTP_PRS_STATE_MAX];
char* const   MSTP_PRT_STATE_s[MSTP_PRT_STATE_MAX];
char* const   MSTP_PST_STATE_s[MSTP_PST_STATE_MAX];
char* const   MSTP_TCM_STATE_s[MSTP_TCM_STATE_MAX];
char* const   MSTP_BDM_STATE_s[MSTP_BDM_STATE_MAX];
char* const   MSTP_BRIDGE_DBG_CNT_NAME_s[MSTP_BRIDGE_DBG_CNT_TYPE_MAX];


#ifdef MSTP_DEBUG

PORT_MAP                  mstp_debugPorts;
MSTP_MSTI_MAP             mstp_debugMstis;
bool                     mstp_debugCist;
MSTP_SM_MAP               mstp_debugSMs;
bool                     mstp_debugSmCallSm;
bool                     mstp_debugTx;
bool                     mstp_debugRx;
bool                     mstp_debugBpduPrint;
bool                     mstp_debugDynConfig;
bool                     mstp_debugFlush;
bool                     mstp_debugPortStatus;
bool                     mstp_debugMisc;
bool                     mstp_debugLog;
uint32_t                  mstp_debugRxBpduCnt;
uint32_t                  mstp_debugTxBpduCnt;
char                      mstp_debugBuf[MSTP_DEBUG_BUF_LEN];

PORT_MAP                  mstp_debugPktEnabledPorts;
MSTP_MSTI_MAP             mstp_debugPktEnabledInstances[MAX_LPORTS + 1];
PORT_MAP                  mstp_debugPktEnabledForCist;
MSTP_MSTI_MAP             mstp_debugEventInstances;
bool                     mstp_debugEventCist;

#endif /* MSTP_DEBUG */

/*---------------------------------------------------------------------------
 * Functions prototypes
 *---------------------------------------------------------------------------*/
/*
 * mstp_init.c
 */
void mstp_init(void);
void mstp_initMstiVlanTables(void);
void mstp_initStateMachines(void);
void mstp_initProtocolData(bool init);
MSTP_MSTI_PORT_INFO_t *
            mstp_initMstiPortData(MSTID_t mstid, LPORT_t lport, bool init);
MSTP_CIST_PORT_INFO_t *
            mstp_initCistPortData(LPORT_t lport, bool init);
void mstp_clearProtocolData(void);
void mstp_clearBridgeMstiData(MSTID_t mstid);
void mstp_clearMstiPortData(MSTID_t mstid, LPORT_t lport);
void mstp_clearCistPortData(LPORT_t lport);
void mstp_clearBridgeCistData(void);
void mstp_clearCommonPortData(LPORT_t lport);
void mstp_clearMstpToOthersMessageQueue(void);
void mstp_clearMstpToOthersMessageQueue(void);
void mstp_updateMstpCBPortMaps(LPORT_t lport);
/*
 * mstp_util.c
 */
void mstp_updatePortOperEdgeState(MSTID_t mstid, LPORT_t lport, bool state);
bool
mstpCistCompareRootTimes(MSTP_CIST_ROOT_TIMES_t *rootTime,  uint16_t helloTime);
void mstp_processTimerTickEvent();
void mstp_collectNotForwardingPorts(PORT_MAP *pmap);
void mstp_blockedPortsBackToForward(PORT_MAP *pmap);
uint32_t
            mstp_portAutoPathCostDetect(LPORT_t lport);
PORT_DUPLEX
            mstp_portDuplexModeDetect(LPORT_t lport);
int mstp_getComponentId();
bool mstp_isTopologyChange(MSTID_t mstid);
int  mstp_getCistUptime(LPORT_t lport);
int  mstp_getMstiUptime(MSTID_t mstid, LPORT_t lport);
void mstp_portAutoDetectParamsSet(LPORT_t lport, SPEED_DPLX *pSpeed);
MSTP_BPDU_TYPE_t
            mstp_getBpduType(MSTP_RX_PDU *pkt);
VLAN_GROUP_t
            mstp_mapMstIdToVlanGroupNum(MSTID_t mstid);
void mstp_unmapMstIdFromVlanGroupNum(MSTID_t mstid);
bool mstp_isThisBridgeRegionalRoot(MSTID_t mstid);
MSTP_PRT_STATE_t *
            mstp_utilPrtStatePtr(MSTID_t mstid, LPORT_t lport);
MSTP_PIM_STATE_t *
            mstp_utilPimStatePtr(MSTID_t mstid, LPORT_t lport);
MSTP_TCM_STATE_t *
            mstp_utilTcmStatePtr(MSTID_t mstid, LPORT_t lport);
bool mstp_rcvdAnyMsgCondition(LPORT_t lport);
void mstp_preventTxOnBridge(void);
void mstp_doPendingTxOnBridge(void);
void mstp_buildMstConfigurationDigest(uint8_t  *cfgDigest);
MSTID_t
            mstp_getMstIdForVlan(VID_t vlan);
MSTP_MSTI_CONFIG_MSG_t *
            mstp_findNextMstiCfgMsgInBpdu(MSTP_RX_PDU *pkt,
                                          MSTP_MSTI_CONFIG_MSG_t *current);
MSTP_TREE_MSG_t *
            mstp_findMstiPortStateChgMsg(MSTID_t mstid);
void mstp_disableForwarding(MSTID_t mstid, LPORT_t lport);
void mstp_disableLearning(MSTID_t mstid, LPORT_t lport);
void mstp_enableForwarding(MSTID_t msti, LPORT_t lport);
void mstp_enableLearning(MSTID_t mstid, LPORT_t lport);
void mstp_flush(MSTID_t mstid, LPORT_t lport);
bool mstp_ProtocolIsEnabled();
bool mstp_mapVlanToMsti(MSTID_t msti, VID_t vlan);
void mstp_noStpPropagatePortUpState(LPORT_t lport);
void mstp_noStpPropagatePortDownState(LPORT_t lport);
void mstp_getMyMstConfigurationId(MSTP_MST_CONFIGURATION_ID_t *mstCfgId);
void mstp_getMstConfigurationDigestStr(char *buf, int bufLen);
void mstp_enableActiveLogicalPorts(void);
void mstp_portEnable(LPORT_t lport);
void mstp_portDisable(LPORT_t lport);
bool mstp_validateBpdu(MSTP_RX_PDU *pkt);
bool mstp_betterOrSameInfo(MSTID_t mstid, LPORT_t lport,
                                  MSTP_INFO_IS_t newInfoIs);
void mstp_clearAllRcvdMsgs(LPORT_t lport);
void mstp_updtBPDUVersion(MSTP_RX_PDU *pkt, LPORT_t lport);
void mstp_clearReselectTree(MSTID_t mstid);
bool mstp_fromSameRegion(MSTP_RX_PDU *pkt, LPORT_t lport);
void mstp_newTcWhile(MSTID_t mstid, LPORT_t lport);
MSTP_RCVD_INFO_t
            mstp_rcvInfo(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport);

void mstp_recordAgreement(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport);
void mstp_recordMastered(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport);
void mstp_recordDispute(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport);
void mstp_recordMasteredMsti(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport);
void mstp_recordProposal(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport);
void mstp_recordPriority(MSTID_t mstid,  LPORT_t lport);
void mstp_recordTimes(MSTID_t mstid,  LPORT_t lport);
void mstp_setRcvdMsgs(MSTP_RX_PDU *pkt, LPORT_t lport);
void mstp_setReRootTree(MSTID_t mstid);
void mstp_setSelectedTree(MSTID_t mstid);
void mstp_setSyncTree(MSTID_t mstid);
void mstp_setTcFlags(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport);
void mstp_setTcPropTree(MSTID_t mstid, LPORT_t lport);
void mstp_syncMaster(void);
void mstp_txTcn(LPORT_t lport);
void mstp_txConfig(LPORT_t lport);
void mstp_txMstp(LPORT_t lport);
void mstp_updtRcvdInfoWhile(MSTID_t mstid, LPORT_t lport);
void mstp_updtRolesDisabledTree(MSTID_t mstid);
void mstp_updtRolesTree(MSTID_t mstid);
bool mstp_AllSyncedCondition(MSTID_t mstid, LPORT_t lport);
bool mstp_allTransmitReadyCondition(LPORT_t lport);
bool mstp_ReRootedCondition(MSTID_t mstid, LPORT_t lport);
uint16_t
            mstp_forwardDelayParameter(LPORT_t lport);
bool mstp_isPortRoleSetOnAnyTree(LPORT_t lport, MSTP_PORT_ROLE_t role);
void mstp_informOtherSubsystems(uint32_t operation);
void
mstp_informDBOnPortStateChange(uint32_t operation);
void mstp_updateCstRootHistory (MSTP_BRIDGE_IDENTIFIER_t rootID);
void mstp_updateIstRootHistory (MSTP_BRIDGE_IDENTIFIER_t rgnRootID);
void mstp_updateMstiRootHistory(MSTID_t mstid,
                                       MSTP_BRIDGE_IDENTIFIER_t rgnRootID);
void mstp_logNewRootId(MSTP_BRIDGE_IDENTIFIER_t oldRootId,
                              MSTP_BRIDGE_IDENTIFIER_t newRootId,
                              bool isCST, MSTID_t mstid);
void mstp_sendErrantBpduTrap(uint32_t index);
bool mstp_isTrapEnable(uint32_t trap);
bool mstp_isTcTrapEnabled(uint32_t mstid);
bool mstp_trapRateLimit(uint32_t trap, uint32_t lport);
int32_t mstp_dot1dStpPortState( LPORT_t lport );
void mstp_triggerTrap( LPORT_t lport, uint8_t trap_delay,
                              bool force_delay);
void mstp_8021x_cd_notify(LPORT_t lport, bool eligible);

/*
 * mstp_ctrl.c
 */
void mstp_processTimerTickEvent();

/*
 * mstp_dyn_reconfig.c
 */
bool mstp_updateMstiVidMapping(MSTID_t mstid,
                                      VID_MAP newVidMap);
/*standard mib*/
/*
 * mstp_recv.c
 */
MSTP_PKT_TYPE_t mstp_decodeBpdu(MSTP_RX_PDU *pkt);

/*
 * mstp_pti_sm.c
 */
void mstp_ptiSm(LPORT_t lport);
/*
 * mstp_prx_sm.c
 */
void mstp_prxSm(MSTP_RX_PDU *pkt, LPORT_t lport);

/*
 * mstp_pim_sm.c
 */
void mstp_pimSm(MSTP_RX_PDU *pkt, MSTID_t mstid, LPORT_t lport);
/*
 * mstp_prs_sm.c
 */
void mstp_prsSm(MSTID_t mstid);

/*
 * mstp_ppm_sm.c
 */
void mstp_ppmSm(LPORT_t lport);

/*
 * mstp_pst_sm.c
 */
void mstp_pstSm(MSTID_t mstid, LPORT_t lport);

/*
 * mstp_tcm_sm.c
 */
void mstp_tcmSm(MSTID_t mstid, LPORT_t lport);

/*
 * mstp_ptx_sm.c
 */
void mstp_ptxSm(LPORT_t lport);

/*
 * mstp_prt_sm.c
 */
void mstp_prtSm(MSTID_t mstid, LPORT_t lport);

/*
 * mstp_bdm_sm.c
 */
void mstp_bdmSm(LPORT_t lport);

/*
 * mstp_show.c
 */
bool mstp_return_topology_change(MSTID_t mstid);
void mstp_showInit(void);
void mstp_showMain(void* ses, int argc, char **argv);
bool isLportForwardingOnVlan(LPORT_t lport, VID_t vlan);
int  mstp_validateStrPortNumber(char *portStr);
int  mstp_validateStrMstid(char *mstidStr);
int  mstp_validateStrVid(char *vidStr);

/*
 * mstp_debug.c
 */
#ifdef MSTP_DEBUG
void mstp_debugInit(void);
void mstp_dbgMain(void* ses, int argc, char **argv);
void mstp_dbgBpduPrint(MSTP_RX_PDU *pkt);
#endif /* MSTP_DEBUG */

void
mstp_updatePortHistory(MSTID_t mstid, LPORT_t lport,
                       MSTP_PRT_STATE_t oldState);

bool
mstpValidPortHistory(MSTID_t mstid, LPORT_t lport, uint8_t histIndex);

int
mstpGetPortHistory(MSTID_t mstid, LPORT_t lport, uint8_t histIndex,
                   MSTP_PORT_HISTORY_t *portHistory);
void mstp_sendTopologyChangeTrap(uint32_t msti, uint32_t port);
bool mstpCheckForTcGeneration(MSTID_t mstid, LPORT_t lport,
                                     MSTP_PORT_ROLE_t);
void mstpUpdateTcHistory(MSTID_t mstid, LPORT_t lport, bool Originated);
bool mstpGetTcHistoryEntry(bool Orig, MSTID_t mstid,
                            uint32_t idx, MSTP_TC_HISTORY_t  *getEntry);
bool mstpValidTcHistory(bool originated, MSTID_t mstid,
                        uint8_t  idx);
void intf_get_port_name(LPORT_t lport, char *port_name);
bool intf_get_lport_speed_duplex(LPORT_t lport, SPEED_DPLX *sd);

void mstp_protocolData(MSTP_RX_PDU *msg);
void mstp_errantProtocolData(MSTP_RX_PDU *msg, TRAP_SOURCE_TYPE_e source);
void mstp_processUnauthorizedBpdu(MSTP_RX_PDU *msg, TRAP_SOURCE_TYPE_e source);
void mstp_convertPortRoleEnumToString(MSTP_PORT_ROLE_t role,char *string);
#endif /* MSTPD_FSM_H */
