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


#ifndef INLINES_H
#define INLINES_H
#include <assert.h>
#include "mstp_fsm.h"

void storeShortInPacket(uint16_t *packetPtr, uint16_t value);
void storeLongInPacket(uint32_t *packetPtr, uint32_t value);

uint8_t bit_count_table[256];

/* Conversion needed on this CPU */
#define ipctohll(x) ((uint64_t)((((x) & 0x00000000000000ff) << 56) | \
                                            (((x) & 0x000000000000ff00) << 40) | \
                                            (((x) & 0x0000000000ff0000) << 24) | \
                                            (((x) & 0x00000000ff000000) <<  8) | \
                                            (((x) & 0x000000ff00000000) >>  8) | \
                                            (((x) & 0x0000ff0000000000) >> 24) | \
                                            (((x) & 0x00ff000000000000) >> 40) | \
                                            (((x) & 0xff00000000000000) >> 56)))
#define ipctohl(x) ((uint32_t)((((x) & 0x000000ff) << 24) |  \
                                           (((x) & 0x0000ff00) <<  8) |  \
                                           (((x) & 0x00ff0000) >>  8) |  \
                                           (((x) & 0xff000000) >> 24)))
#define ipctohs(x) ((uint16_t)((((x) & 0x00ff) << 8) |       \
                                           (((x) & 0xff00) >> 8)))
#define htoipcll(x) ((uint64_t)((((x) & 0x00000000000000ff) << 56) | \
                                            (((x) & 0x000000000000ff00) << 40) | \
                                            (((x) & 0x0000000000ff0000) << 24) | \
                                            (((x) & 0x00000000ff000000) <<  8) | \
                                            (((x) & 0x000000ff00000000) >>  8) | \
                                            (((x) & 0x0000ff0000000000) >> 24) | \
                                            (((x) & 0x00ff000000000000) >> 40) | \
                                            (((x) & 0xff00000000000000) >> 56)))
#define htoipcl(x) ((uint32_t)((((x) & 0x000000ff) << 24) |  \
                                           (((x) & 0x0000ff00) <<  8) |  \
                                           (((x) & 0x00ff0000) >>  8) |  \
                                           (((x) & 0xff000000) >> 24)))
#define htoipcs(x) ((uint16_t)((((x) & 0x00ff) << 8) |       \
                                           (((x) & 0xff00) >> 8)))
#define __CTZ32(x) __builtin_ctz(x)
#define __CLZ32(x) __builtin_clz(x)
#define __FFS32(x) __builtin_ffs(x)

int sw_ffs(uint32_t bitmask);
int fls(uint32_t bitmask);
void setBit(uint32_t *map, uint32_t bit, uint32_t maxBits);
void clrBit(uint32_t *map, uint32_t bit, uint32_t maxBits);

int printBitMap(const uint32_t *map, int maxBits);
int printByteArrayBitMap(const uint8_t *map, int maxBits);
int print_vlan_map(const VLAN_MAP *map);
int print_vid_map(const VID_MAP *map);

uint8_t bit_count_table[256];

/* Bit map operations
 * Notes:
 *  (1) Bit 1 starts at bit position 0 in the map.
 *  (2) Each operation comes in two forms: xxx and xxxSmallBitmap, where
 *      the smallBitmap form is for bit maps less then 32 bits which
 *      can be processed more efficiently then larger bitmaps.
 */

/************ set bit in bitmap *************/

void setiBitInSmallBitmap(uint32_t *map, uint32_t bit, uint32_t maxBits);


void setBit(uint32_t *map, uint32_t bit, uint32_t maxBits);




void setBitInByteArray(uint8_t *map, uint32_t bit, uint32_t maxBits);
/************ clear bit in bitmap *************/


void clrBitInSmallBitmap(uint32_t *map, uint32_t bit, uint32_t maxBits);


void clrBit(uint32_t *map, uint32_t bit, uint32_t maxBits);


void clrBitInByteArray(uint8_t *map, uint32_t bit, uint32_t maxBits);


int ones8(uint8_t x);

/************ find first bit in bitmap *************/

int findFirstBitSetInSmallBitmap(const uint32_t *map, uint32_t maxBits);



int findFirstBitSet(const uint32_t *map, uint32_t maxBits);


int findFirstBitClr(const uint32_t *map, uint32_t maxBits);


int findFirstBitClrInByteArray(const uint8_t *map, uint32_t maxBits);

/************ find next bit in bitmap *************
 * Find the next bit set after the given prevBit.
 * Bits start at 1.  A prevBit of 0 is equivalent
 * to using findFirstBitSet()
 */

int findNextBitSetInSmallBitmap(const uint32_t *map, uint32_t prevBit,
                                uint32_t maxBits);

int findNextBitSet(const uint32_t *map, uint32_t prevBit, uint32_t maxBits);


int findNextBitClr(const uint32_t *map, uint32_t prevBit, uint32_t maxBits);


int findFirstBitSetInByteArrayBitmap(const uint8_t *map, uint32_t maxBits);


int findNextBitSetInByteArrayBitmap(const uint8_t *map, int prevBit,
                                    uint32_t maxBits);
/************ check bit set in bitmap *************/

bool isBitSetInSmallBitmap(const uint32_t *map, uint32_t bit,
                              uint32_t maxBits);

bool isBitSet(const uint32_t *map, uint32_t bit, uint32_t maxBits);


bool isBitSet64(const uint64_t *map, uint32_t bit, uint32_t maxBits);


bool isBitSetInByteArrayBitmap(const uint8_t *map, uint32_t bit,
                                  uint32_t maxBits);

void clearSmallBitmap(uint32_t *map, uint32_t maxBits);


void clearBitmap(uint32_t *map, uint32_t maxBits);


void clearByteArrayBitmap(uint8_t *map, uint32_t maxBits);

/************ set bitmap *************/

void setSmallBitmap(uint32_t *map, uint32_t maxBits);


void setBitmap(uint32_t *map, uint32_t maxBits);


uint32_t bitReverse (register uint32_t x);


void bitOrBitmaps(const uint32_t *fromMap, uint32_t *toMap, uint32_t maxBits);



void bitOrByteArrayBitmaps(const uint8_t *fromMap, uint8_t *toMap,
                           uint32_t maxBits);
/************ bit AND bitmap *************/

void bitAndSmallBitmaps(const uint32_t *fromMap, uint32_t *toMap,
                        uint32_t maxBits);

void bitAndBitmaps(const uint32_t *fromMap, uint32_t *toMap,
                   uint32_t maxBits);


void bitAndByteArrayBitmaps(const uint8_t *fromMap, uint8_t *toMap,
                            uint32_t maxBits);
/* Determine if two bitmaps overlap, similar to bitAndBitmaps but more
 * efficient */

bool bitmapsOverlap(const uint32_t *map1, const uint32_t *map2,
      uint32_t maxBits);

void bitInverseSmallBitmap(uint32_t *map, uint32_t maxBits);

void bitInverseBitmap(uint32_t *map, uint32_t maxBits);


void bitInverseByteArrayBitmap(uint8_t *map, uint32_t maxBits);
/************ bit XOR bitmap *************/

void bitXorSmallBitmaps(const uint32_t *fromMap, uint32_t *toMap,
                        uint32_t maxBits);

void bitXorBitmaps(const uint32_t *fromMap, uint32_t *toMap, uint32_t maxBits);


void bitXorByteArrayBitmaps(const uint8_t *fromMap, uint8_t *toMap,
                            uint32_t maxBits);
/************ bit SUB bitmap *************/
/*
 * Subtract fromMap from toMap.  All bits set in fromMap are cleared in toMap.
 * This is logically equivalent to ANDing toMap with the inverse of fromMap.
 * Note that unlike the operations above, this one is not commutative.
 */


void bitSubSmallBitmaps(const uint32_t *fromMap, uint32_t *toMap,
                        uint32_t maxBits);

void bitSubBitmaps(const uint32_t *fromMap, uint32_t *toMap, uint32_t maxBits);


void bitSubByteArrayBitmaps(const uint8_t *fromMap, uint8_t *toMap,
                            uint32_t maxBits);
/************ are any bits set in bitmap *************/

bool areAnyBitsSetInSmallBitmap(const uint32_t *map, uint32_t maxBits);


bool areAnyBitsSetInBitmap(const uint32_t *map, uint32_t maxBits);


uint32_t getNumOfBitsSetInSmallBitmap(const uint32_t *map, uint32_t maxBits);


uint32_t getNumOfBitsSetInBitmap(const uint32_t *map, uint32_t maxBits);


uint32_t getNumOfBitsSetInByteArrayBitmap(const uint8_t *map, uint32_t maxBits);


bool areAnyBitsSetInByteArrayBitmap(const uint8_t *map, uint32_t maxBits);

/************ are bitmaps equal *************/

bool areSmallBitmapsEqual(const uint32_t *map1, const uint32_t *map2,
                             uint32_t maxBits);


bool areBitmapsEqual(const uint32_t *map1, const uint32_t *map2,
                        uint32_t maxBits);


bool areByteArrayBitmapsEqual(const uint8_t *map1, const uint8_t *map2,
                                 uint32_t maxBits);
/************ are all bits set *************/

bool areAllBitsSetInSmallBitmap(const uint32_t *map, uint32_t maxBits);


bool areAllBitsSetInBitmap(const uint32_t *map, uint32_t maxBits);


bool areAllBitsSetInByteArrayBitmap(const uint8_t *map, uint32_t maxBits);

/************ copy bitmap *************/

void copySmallBitmap(const uint32_t *fromMap, uint32_t *toMap,
                     uint32_t maxBits);


void copyBitmap(const uint32_t *fromMap, uint32_t *toMap, uint32_t maxBits);


void copyByteArrayBitmap(const uint8_t *fromMap, uint8_t *toMap,
                         uint32_t maxBits);
#ifndef PC
/*
 * special routines to use when copying a bitMap into a msg or namespace item
 * that may be used on another processor
 */

void htoipcCopySmallBitmap(const uint32_t *fromMap, uint32_t *toMap,
                           uint32_t maxBits);

void htoipcCopyBitmap(const uint32_t *fromMap, uint32_t *toMap, uint32_t maxBits);


void htoipcCopyByteArrayBitmap(const uint8_t *fromMap, uint8_t *toMap,
                               uint32_t maxBits);
/*
 * special routines to use when copying a bitMap from a msg or namespace item
 * that may be used on another processor
 */

void ipctohCopySmallBitmap(const uint32_t *fromMap, uint32_t *toMap,
                           uint32_t maxBits);

void ipctohCopyBitmap(const uint32_t *fromMap, uint32_t *toMap, uint32_t maxBits);


void ipctohCopyByteArrayBitmap(const uint8_t *fromMap, uint8_t *toMap,
                               uint32_t maxBits);

#endif /* PC */

/*****************************************************************************
 * vlan map inlines
 *
 *   Used for setting and clearing vlans in vlan bitmaps
 *
 *   Note: since vlanMaps are not used as much as portMaps, we do optimize
 *         for switches that support less then 32 vlans
 ****************************************************************************/

void set_vlan(VLAN_MAP *map, uint32_t vlan);


void clear_vlan(VLAN_MAP *map, uint32_t vlan);


VID_t find_first_vlan_set(const VLAN_MAP *map);


VID_t find_next_vlan(const VLAN_MAP *map, uint32_t prevVlan);


bool is_vlan_set(const VLAN_MAP *map, uint32_t vlan);


void clear_vlan_map(VLAN_MAP *map);


uint32_t count_vlans(const VLAN_MAP *map);


void bit_or_vlan_maps(const VLAN_MAP *fromMap, VLAN_MAP *toMap);


void bit_and_vlan_maps(const VLAN_MAP *fromMap, VLAN_MAP *toMap);


void bit_xor_vlan_maps(const VLAN_MAP *fromMap, VLAN_MAP *toMap);


void bit_sub_vlan_maps(const VLAN_MAP *fromMap, VLAN_MAP *toMap);


void bit_inverse_vlan_map(VLAN_MAP *map);


bool are_any_vlans_set(const VLAN_MAP *map);


bool are_vlanmaps_equal(const VLAN_MAP *vlanMap1, const VLAN_MAP *vlanMap2);


void copy_vlan_map(const VLAN_MAP *fromMap, VLAN_MAP *toMap);

#ifndef PC
/*
 * special routine to use when copying a vlan_map into a msg or namespace item
 * that may be used on another processor
 */

void htoipc_copy_vlan_map(const VLAN_MAP *fromMap, VLAN_MAP *toMap);
/*
 * special routine to use when copying a vlan_map from a msg or namespace item
 * that may be used on another processor
 */

void ipctoh_copy_vlan_map(const VLAN_MAP *fromMap, VLAN_MAP *toMap);
#endif /* PC */


/*****************************************************************************
 * vlan id map inlines
 *
 *   Used for setting and clearing vlan identifiers in vlan id bitmaps
 *
 ****************************************************************************/

void set_vid(VID_MAP *map, uint32_t vid);


void clear_vid(VID_MAP *map, uint32_t vid);


VID_t find_first_vid_set(const VID_MAP *map);


VID_t find_next_vid(const VID_MAP *map, uint32_t prevVid);


bool is_vid_set(const VID_MAP *map, uint32_t vid);


void clear_vid_map(VID_MAP *map);


uint32_t count_vids(const VID_MAP *map);


void bit_or_vid_maps(const VID_MAP *fromMap, VID_MAP *toMap);


void bit_and_vid_maps(const VID_MAP *fromMap, VID_MAP *toMap);


void bit_xor_vid_maps(const VID_MAP *fromMap, VID_MAP *toMap);


void bit_sub_vid_maps(const VID_MAP *fromMap, VID_MAP *toMap);

bool vid_maps_overlap(const VID_MAP *map1, const VID_MAP *map2);


void bit_inverse_vid_map(VID_MAP *map);


bool are_any_vids_set(const VID_MAP *map);


bool are_vidmaps_equal(const VID_MAP *vidMap1, const VID_MAP *vidMap2);


void copy_vid_map(const VID_MAP *fromMap, VID_MAP *toMap);
/*
 * special routine to use when copying a vid_map into a msg or namespace item
 * that may be used on another processor
 */

void htoipc_copy_vid_map(const VID_MAP *fromMap, VID_MAP *toMap);
/*
 * special routine to use when copying a vid_map from a msg or namespace item
 * that may be used on another processor
 */

void ipctoh_copy_vid_map(const VID_MAP *fromMap, VID_MAP *toMap);

/******************************************************************************
 * Bit field functions
 *
 *  The following 5 functions can be used to manage arrays of 2-bit
 *  or 4-bit fields. fieldSize must be 2 or 4 in all calls below.
 *
 *  In reality, the data structure is a array of bytes with enought
 *  bytes to house the bits in fieldSize * maxFields. The 1st field
 *  is field 1.
 *
 *  To create a data structure for a 2-bit array, you might do
 *  something like:
 *
 *    #define MY_MAP_ARRAY_SIZE  (((MY_MAX_FIELDS * 2) + 7) / 8)
 *
 *    typedef struct {
 *       uint8_t map[MY_MAP_ARRAY_SIZE];
 *    } MY_MAP_DATATYPE_t;
 *
 *****************************************************************************/
void setFieldInBitArray(uint8_t *map, int field, int fieldValue,
                               int fieldSize, int maxFields);
void clearAllFieldsInBitArray(uint8_t *map,
                                     int fieldSize, int maxFields);
void copyAllFieldsInBitArray(const uint8_t *fromMap, uint8_t *toMap,
                                    int fieldSize, int maxFields);
void printAllFieldsInBitArray(const uint8_t *map,
                                     int fieldSize, int maxFields);


bool areBitArraysEqual(const uint8_t *map1, const uint8_t *map2,
                       int fieldSize, int maxFields);

void setFieldInBitmap(uint32_t *map,
                      int field, int fieldValue, int fieldSize, int maxFields);

int getFieldFromBitArray(const uint8_t *map, int field, int fieldSize, int maxFields);

int getFieldFromBitmap(const uint32_t *map, int field, int fieldSize, int maxFields);

int sw_ffs(uint32_t bitmask);

int ffc(uint32_t bitmask);
int ffsll(uint64_t bitmask);
int fls(uint32_t bitmask);
void setbit(uint32_t *bitmask, int offset);
void clrbit(uint32_t *bitmask, int offset);

/* The following defines map the legacy name to new names. They are deprecated
   for new usage. */
#define set_port(map, port) PortMap_setPort((map), (port))
#define clear_port(map, port) PortMap_clearPort((map), (port))
#define is_port_set(map, port) PortMap_isPortSet((map), (port))
#define clear_port_map(map) PortMap_clear((map))
#define bit_or_port_maps(fromMap, toMap) PortMap_bitOrPortMaps((fromMap), (toMap))
#define bit_and_port_maps(fromMap, toMap) PortMap_bitAndPortMaps((fromMap), (toMap))
#define bit_xor_port_maps(fromMap, toMap) PortMap_bitXorPortMaps((fromMap), (toMap))
#define bit_sub_port_maps(fromMap, toMap) PortMap_bitSubPortMaps((fromMap), (toMap))
#define bit_inverse_port_map(map) PortMap_bitInversePortMap((map))
#define are_any_ports_set(map) PortMap_areAnyPortsSet((map))
#define are_portmaps_equal(pm1, pm2) PortMap_arePortMapsEqual((pm1), (pm2))
#define copy_port_map(fromMap, toMap) PortMap_copy((fromMap), (toMap))
#define htoipc_copy_port_map(fromMap, toMap) PortMap_htoipcCopy((fromMap), (toMap))
#define ipctoh_copy_port_map(fromMap, toMap) PortMap_ipctohCopy((fromMap), (toMap))
#define print_port_map(map) PortMap_print((map))
#define print_port_map_with_commas(map) PortMap_printWithCommas((map))
#define get_num_of_ports_set(map) PortMap_getNumOfPortsSet((map))

/* Externs from PortMap.c */
int PortMap_print(const PORT_MAP *map);
int PortMap_printWithCommas(const PORT_MAP *map);


uint32_t PortMap_getNumOfPortsSet(const PORT_MAP *map);


void PortMap_setPort(PORT_MAP *map, PORT_t port);


void PortMap_clearPort(PORT_MAP *map, PORT_t port);


PORT_t PortMap_findFirstPortSet(const PORT_MAP *map);


PORT_t PortMap_findNextPortSet(const PORT_MAP *map, PORT_t prevPort);



bool PortMap_isPortSet(const PORT_MAP *map, PORT_t port);


int find_first_port_set(const PORT_MAP *map);


int find_next_port_set(const PORT_MAP *map, int prevPort);


void PortMap_clear(PORT_MAP *map);


void PortMap_bitOrPortMaps(const PORT_MAP *fromMap, PORT_MAP *toMap);


void PortMap_bitAndPortMaps(const PORT_MAP *fromMap, PORT_MAP *toMap);


void PortMap_bitXorPortMaps(const PORT_MAP *fromMap, PORT_MAP *toMap);


void PortMap_bitSubPortMaps(const PORT_MAP *fromMap, PORT_MAP *toMap);


void PortMap_bitInversePortMap(PORT_MAP *map);


bool PortMap_areAnyPortsSet(const PORT_MAP *map);


bool PortMap_arePortMapsEqual(const PORT_MAP *portMap1, const PORT_MAP *portMap2);


void PortMap_copy(const PORT_MAP *fromMap, PORT_MAP *toMap);

#ifndef PC
/*
 * special routine to use when copying a port_map into a msg or namespace item
 * that may be used on another processor
 */

void PortMap_htoipcCopy(const PORT_MAP *fromMap, PORT_MAP *toMap);

/*
 * special routine to use when copying a port_map from a msg or namespace item
 * that may be used on another processor
 */

void PortMap_ipctohCopy(const PORT_MAP *fromMap, PORT_MAP *toMap);
#endif /* PC */

#endif /* INLINES_H */
