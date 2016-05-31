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
#ifndef __MSTP_MAPPING__H__
#define __MSTP_MAPPING__H__

#include <assert.h>
#include <vswitch-idl.h>

#define STP_ASSERT(x) assert(x)

/* switch types */
typedef uint16_t PORT_t;         /* Generic port number (either an Lport or Pport    */
typedef PORT_t   LPORT_t;        /* logical port number  (1 to MAX_LPORTS)   */
typedef uint16_t VID_t;          /* Vlan ID (12 bit number 0 to 4095)        */
typedef uint16_t VLAN_GROUP_t;   /* vlan group number (1 to MAX_VLAN_GROUPS) */
typedef uint32_t PROTOCOL_TYPE_t;/* Protocol type (filters/QOS/etc)          */
typedef uint32_t IFINDEX_t;      /* interface index for end-points           */
typedef uint16_t TYP_LEN;
typedef uint8_t OCTET;

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
#endif /* MSTPD_MAPPING_H */
