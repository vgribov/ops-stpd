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
 *    File               : mstpd_inlines.c
 *    Description        : MSTP Protocol Bitmap related routines
 **********************************************************************************/

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>

#include <util.h>
#include <openvswitch/vlog.h>

#include <mqueue.h>
#include <assert.h>
#include "mstp_inlines.h"
#include "mstp_fsm.h"
#include <openssl/md5.h>

/* inlines.c in libw.ss compiles this code into library routines by define
 * extern to be nothing before including this file. For all other .c files
 * that include this file, you may or may not get inlines.
 */

uint8_t bit_count_table[256] = {
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
};

/*****************************************************************************/
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

/* Bit map operations
 * Notes:
 *  (1) Bit 1 starts at bit position 0 in the map.
 *  (2) Each operation comes in two forms: xxx and xxxSmallBitmap, where
 *      the smallBitmap form is for bit maps less then 32 bits which
 *      can be processed more efficiently then larger bitmaps.
 */

/************ set bit in bitmap *************/
extern
void setBitInSmallBitmap(uint32_t *map, uint32_t bit, uint32_t maxBits)
{
   if (map && (bit > 0) && (bit <= maxBits) && (maxBits <= 32))
   {
      map[0] |= (1 << (bit - 1));
   }
   else
   {
       assert(0);
   }
}

extern
void setBit(uint32_t *map, uint32_t bit, uint32_t maxBits)
{
   if ( maxBits  <= 32)
   {
      setBitInSmallBitmap(map, bit, maxBits);
      return;
   }
   if (map && (bit > 0) && (bit <= maxBits))
   {
         map[(bit-1)/32] |= (1 << ((bit-1) % 32));
   }
   else
   {
       assert(0);
   }
}



extern
void setBitInByteArray(uint8_t *map, uint32_t bit, uint32_t maxBits)
{
   if (map && (bit > 0) && (bit <= maxBits))
   {
      map[(bit-1)/8] |= (1 << ((bit-1) % 8));
   }
   else
   {
       assert(0);
   }
}

/************ clear bit in bitmap *************/

extern
void clrBitInSmallBitmap(uint32_t *map, uint32_t bit, uint32_t maxBits)
{
   if(map && (bit > 0) && (bit <= maxBits) && (maxBits <= 32))
   {
      map[0] &= ~(1 << (bit - 1));
   }
   else
   {
      assert(0);
   }
}

extern
void clrBit(uint32_t *map, uint32_t bit, uint32_t maxBits)
{
   if (maxBits <=32)
   {
      clrBitInSmallBitmap(map, bit, maxBits);
      return;
   }
   if(map && (bit > 0) && (bit <= maxBits))
   {
       map[(bit-1)/32] &= ~(1 << ((bit-1) % 32));
   }
   else
   {
       assert(0);
   }

}

extern
void clrBitInByteArray(uint8_t *map, uint32_t bit, uint32_t maxBits)
{
   if(map && (bit > 0) && (bit <= maxBits))
   {
      map[(bit-1)/8] &= (~(1 << ((bit-1) % 8)) & 0xff);
   }
   else
   {
      assert(0);
   }
}


extern
int ones8(uint8_t x)
{
   /* This is magic that returns the number of trailing 0s
     * in any 32 bit number
   */
   x -= ((x >> 1) & 0x55);
   x = (((x >> 2) & 0x33) + (x & 0x33));
   x = (((x >> 4) + x) & 0x0f);
   return(x & 0x3f);
}

/************ find first bit in bitmap *************/
extern
int findFirstBitSetInSmallBitmap(const uint32_t *map, uint32_t maxBits)
{
   uint32_t bit;

   if (!map || (maxBits > 32)) {
      assert(0);
      return -1;/*(0xffffffff);*/
   }

   /* sw_ffs() returns 0..31 or -1 if no bit is set. This function needs to
    * return 1..maxBits or -1 if no bit is set.
    */
   bit = sw_ffs(map[0]);
   if (bit != 0xffffffff)
      bit++;

   /* Only return the bit if it is within the specified range */
   if ((uint32_t)bit > maxBits)
      return -1;/*(0xffffffff);*/
   return(bit);
}


extern
int findFirstBitSet(const uint32_t *map, uint32_t maxBits)
{
   uint32_t i;
   uint32_t lsb; /* least significant bit */

   if (maxBits <= 32)
   {
       return findFirstBitSetInSmallBitmap(map, maxBits);
   }

   if (!map)
   {
       assert(0);
       return -1;/*(0xffffffff);*/
   }

   for (i = 0; i < maxBits; i += 32)
   {
      if (*map)
      {
         /* at least one bit is set in this word */
         /* return which one */
         /* This is the least significant bit of hi[i] */
         lsb = __FFS32(*map);
         if ((i + lsb) > maxBits)
            return -1;
         return (i + lsb);
      }
      map++;
   }
   return -1;
}

extern
int findFirstBitClr(const uint32_t *map, uint32_t maxBits)
{
   uint32_t i;
   int     bit;

   if (!map)
   {
      assert(0);
      return -1;/*(0xffffffff);*/
   }

   /* ffs() returns 0..31 or -1 if no bit is clr. This function needs to
    * return 1..maxBits or -1 if no bit is clr.
    */

   for (i = 0; i < maxBits; i += 32)
   {
      if (*map != 0xffffffff)
      {
         bit = ((int)(i + 1 + sw_ffs(~*map)));
         if ((uint32_t)bit > maxBits)
         {
            return -1;/*(0xffffffff);*/
         }
         return(bit);
      }
      map++;
   }

   return -1;/*(0xffffffff);*/
}

extern
int findFirstBitClrInByteArray(const uint8_t *map, uint32_t maxBits)
{
   uint32_t i;
   int     bit;

   if (!map)
   {
      assert(0);
      return -1;/*(0xffffffff);*/
   }

   for (i = 0; i < maxBits; i += 8)
   {
      if (*map != 0xff)
      {
         bit = ((int)(i + 1 + sw_ffs(~*map)));
         if ((uint32_t)bit > maxBits)
         {
            return -1;/*(0xffffffff);*/
         }
         return(bit);
      }
      map++;
   }

   return -1;/*(0xffffffff);*/
}

/************ find next bit in bitmap *************
 * Find the next bit set after the given prevBit.
 * Bits start at 1.  A prevBit of 0 is equivalent
 * to using findFirstBitSet()
 */
extern
int findNextBitSetInSmallBitmap(const uint32_t *map, uint32_t prevBit,
                                uint32_t maxBits)
{
   if (!map || (maxBits > 32) || (prevBit>maxBits))
   {
      assert(0);
      return -1;/*(0xffffffff);*/
   }
   /* Permit a prevBit of 32, but it will always return -1.         */
   /* This will enable use of a "while next bit!=-1" type of loop. */
   /* prevBit and return are 1-based bit numbers */
   /* A prevBit of 0 is the same as findFirstBitSet() */
   while (prevBit < 32)
   {
      if ((1<<prevBit) & map[0])
      {
         if ((prevBit+1) > maxBits)
         {
            return -1;/*(0xffffffff);*/
         }
         return(prevBit+1);
      }
      prevBit++;
   }
   return -1;/*(0xffffffff);*/
}


extern
int findNextBitSet(const uint32_t *map, uint32_t prevBit, uint32_t maxBits)
{
   int      word;
   uint32_t i;
   uint32_t lsb; /* least significant bit */
   uint32_t mask;
   if(maxBits <= 32)
   {
      return  findNextBitSetInSmallBitmap(map, prevBit, maxBits);
   }


   /* Permit a prevBit of maxBits, but it will always return -1.   */
   /* This will enable use of a "while next bit!=-1" type of loop. */
   if(!(map && (prevBit<=maxBits)))
   {
       assert(0);
       return -1;
   }

   /* Start at the bit just after prevBit */
   word = prevBit >> 5;
   map += word;
   prevBit = prevBit - (word << 5);
   mask = ~(1u << prevBit) + 1u;

   for (i = word * 32; i < maxBits; i += 32) {
      mask &= *map;
      if (mask) {
         /* at least one bit is set in this word */
         /* return which one */
         /* This is the least significant bit of hi[i] */
         lsb = __CTZ32(mask) + 1;
         if ((i + lsb) > maxBits)
         {
            return -1;
         }
         return (i + lsb);
      }
      map++;
      mask = ~0u; /* 0xffffffff */
   }

   return -1;/*(0xffffffff);*/
}

extern
int findNextBitClr(const uint32_t *map, uint32_t prevBit, uint32_t maxBits)
{
   int            word;
   unsigned int   mask;
   int            bitCount;
   unsigned int   ii;

   if(!(map && (prevBit<=maxBits)))
   {
       assert(0);
       return -1;
   }

   // calculate starting position in map -- word|bit
   word = prevBit >> 5;
   prevBit -= (word << 5);

   // move map pointer to starting word
   map += word;

   // ongoing count of skipped bits
   bitCount = word * 32;

   // set all bits prior to starting position to 1s so we don't count them
   mask = (1u << prevBit) - 1u;
   mask |= *map++;

   // only rightmost cleared bit position is inverted to a 1 all other bits 0
   mask = ~mask & (mask+1);

   for (ii = word * 32; ii < maxBits; ii+=32)
   {
      // 0 mask means that all bits in this word were 1s
      if (mask == 0)
         bitCount += 32;
      else
      {
         // count trailing zero bits up to 1-bit that is really the rightmost 0 bit :)
         bitCount += __CTZ32(mask);

         // found a 0 bit, so we're done
         break;
      }

      // go to next work & create the "rightmost clear bit" mask
      mask = *map++;
      mask = ~mask & (mask+1);
   }
   return (bitCount < (int)maxBits) ? bitCount+1 : -1;
}

extern
int findFirstBitSetInByteArrayBitmap(const uint8_t *map, uint32_t maxBits)
{
   uint32_t i;
   uint32_t lsb; /* least significant bit */

   if (!map)
   {
      assert(0);
      return -1;/*(0xffffffff);*/
   }
   /* This function needs to return 1..maxBits or -1 if no bit is set.
    */
   for (i = 0; i < maxBits; i += 8)
   {
      if (*map)
      {
         /* at least one bit is set in this word */
         /* return which one */
         /* This is the least significant bit of hi[i] */
         lsb = __CTZ32(*map) + 1;
         if ((i + lsb) > maxBits)
         {
            return -1;
         }
         return (i + lsb);
      }
      map++;
   }

   return -1;/*(0xffffffff);*/
}

extern
int findNextBitSetInByteArrayBitmap(const uint8_t *map, int prevBit,
                                    uint32_t maxBits)
{
   int      byte;
   uint32_t i;
   uint32_t lsb; /* least significant bit */
   uint8_t  mask;

   if (!map)
   {
      assert(0);
      return -1;/*(0xffffffff);*/
   }

   byte = prevBit / 8;
   map += byte;
   prevBit = prevBit - (byte * 8);
   mask = ~(1u << prevBit) + 1u;

   /* This function needs to return 1..maxBits or -1 if no bit is set.
    */

   for (i = byte * 8; i < maxBits; i += 8)
   {
      mask &= *map;
      if (mask)
      {
         /* at least one bit is set in this word */
         /* return which one */
         /* This is the least significant bit of hi[i] */
         lsb = __CTZ32(mask) + 1;
         if ((i + lsb) > maxBits)
         {
            return -1;
         }
         return (i + lsb);
      }
      map++;
      mask = 0xffu;
   }

   return -1;/*(0xffffffff);*/
}

/************ check bit set in bitmap *************/
extern
bool isBitSetInSmallBitmap(const uint32_t *map, uint32_t bit,
                              uint32_t maxBits)
{
   if ((!map) || maxBits > 32)
   {
      assert(0);
      return false;
   }
   if ((bit > 0) && (bit <= maxBits))
   {
      return(map[0] & (1 << ((int)bit - 1)));
   }
   else
   {
      return false;
   }
}

extern
bool isBitSet(const uint32_t *map, uint32_t bit, uint32_t maxBits)
{
   if (maxBits <= 32)
   {
       return isBitSetInSmallBitmap(map, bit, maxBits);
   }
   if (!map)
   {
      assert(0);
      return(false);
   }
   if ((bit > 0) && (bit <= maxBits))
   {
      return (map[(bit-1)/32] & (1 << ((int)(bit-1)%32)));
   }
   else
   {
      return false;
   }
}

extern
bool isBitSet64(const uint64_t *map, uint32_t bit, uint32_t maxBits)
{
   if (!map)
   {
      return(false);
   }
   if ((bit > 0) && (bit <= maxBits))
   {
      return (map[(bit)/ 64] & (1 << ((int)(bit) % 64)));
   }
   else
   {
      return false;
   }
}




extern
bool isBitSetInByteArrayBitmap(const uint8_t *map, uint32_t bit,
                                  uint32_t maxBits)
{
   if (!map)
   {
      assert(0);
      return(false);
   }
   if ((bit > 0) && (bit <= maxBits))
   {
      return(map[(bit-1)/8] & (1 << ((int)(bit-1)%8)));
   }
   else
   {
      return(false);
   }
}

/************ clear bitmap *************/
extern
void clearSmallBitmap(uint32_t *map, uint32_t maxBits)
{
   if(map && (maxBits <= 32))
   {
      map[0] = 0;
   }
   else
   {
       assert(0);
   }
}

extern
void clearBitmap(uint32_t *map, uint32_t maxBits)
{
   int i;

   if (maxBits <= 32)
   {
       clearSmallBitmap(map, maxBits);
       return;
   }
   if(!map)
   {
      assert(0);
      return;
   }

   for (i = maxBits; i > 0; i -= 32)
   {
      *map++ = 0;
   }
}



extern
void clearByteArrayBitmap(uint8_t *map, uint32_t maxBits)
{
   int   i;
   /* maxBits is ignored, if it is not divisible by 8 */

   if(!map)
   {
       assert(0);
       return;
   }

   for (i = maxBits; i > 0; i -= 8)
   {
      *map++ = 0;
   }
}

/************ set bitmap *************/
extern
void setSmallBitmap(uint32_t *map, uint32_t maxBits)
{
   if(map && (maxBits <= 32))
   {
      map[0] = ~(-(1 << maxBits));
   }
   else
   {
       assert(0);
   }
}

extern
void setBitmap(uint32_t *map, uint32_t maxBits)
{
   uint32_t i, mask;

   if (maxBits <= 32)
   {
      setSmallBitmap(map, maxBits);
      return;
   }

   assert(map);
   for (i = maxBits; i >= 32; i -= 32)
   {
      *map++ = 0xffffffff;
   }
   if (i > 0)
   {
      mask = ~(-(1 << i));
      *map = mask;
   }
}



/**PROC+**********************************************************************
 * Name:    bitReverse
 *
 * Purpose: reverse the order of bits in a word
 *
 * Params:  x     unsigned int
 *
 * Returns: unsigned int with bits reversed
 *
 **PROC-**********************************************************************/
extern
uint32_t bitReverse (register uint32_t x)
{
#ifdef __THUMB2_AWARE__
   return __RBIT(x);

#else /* !__THUMB2_AWARE__ */

   register uint32_t y = 0x55555555;

   x = (((x >> 1) & y) | ((x & y) << 1));
   y = 0x33333333;
   x = (((x >> 2) & y) | ((x & y) << 2));
   y = 0x0f0f0f0f;
   x = (((x >> 4) & y) | ((x & y) << 4));
   y = 0x00ff00ff;
   x = (((x >> 8) & y) | ((x & y) << 8));
   return((x >> 16) | (x << 16));
#endif /* __THUMB2_AWARE__ */
}

/************ bit OR bitmap *************/
extern
void bitOrSmallBitmaps(const uint32_t *fromMap, uint32_t *toMap,
                       uint32_t maxBits)
{
   if(fromMap && toMap && (maxBits <= 32))
   {
      toMap[0] |= fromMap[0];
   }
   else
   {
      assert(0);
   }
}


extern
void bitOrBitmaps(const uint32_t *fromMap, uint32_t *toMap, uint32_t maxBits)
{
   int i;
   int mask;

   if (maxBits <= 32)
   {
      bitOrSmallBitmaps(fromMap, toMap, maxBits);
      return;
   }
   if(fromMap && toMap)
   {
      /* do all but the final word a word at a time */
      for (i = maxBits; i >= 32; i -= 32)
      {
         *toMap++ |= *fromMap++;
      }

      if (i > 0)
      {
         /* mask off any extra bits in final word */
         mask = ~(-(1 << i));
         *toMap |= *fromMap;
         *toMap = *toMap & mask;
      }
   }
   else
   {
      assert(0);
   }
}



extern
void bitOrByteArrayBitmaps(const uint8_t *fromMap, uint8_t *toMap,
                           uint32_t maxBits)
{
   int i;
   int mask;

   if(fromMap && toMap)
   {
      /* do all but the final byte, a byte at a time */
      for (i = maxBits; i >= 8; i -= 8)
      {
         *toMap++ |= *fromMap++;
      }

      if (i > 0)
      {
         /* mask off any extra bits in final byte */
         mask = ~(-(1 << i));
         *toMap |= *fromMap;
         *toMap = *toMap & mask;
      }
   }
   else
   {
      assert(0);
   }
}

/************ bit AND bitmap *************/
extern
void bitAndSmallBitmaps(const uint32_t *fromMap, uint32_t *toMap,
                        uint32_t maxBits)
{
   if (!(fromMap && toMap) || ( maxBits > 32) )
   {
      assert(0);
      return;
   }
   toMap[0] &= fromMap[0];
}

extern
void bitAndBitmaps(const uint32_t *fromMap, uint32_t *toMap,
                   uint32_t maxBits)
{
   int i;
   int mask;

   if(maxBits <= 32)
   {
      bitAndSmallBitmaps(fromMap, toMap, maxBits);
      return;
   }

   if(fromMap && toMap)
   {

      /* do all but the final word a word at a time */
      for (i = maxBits; i >= 32; i -= 32)
      {
         *toMap++ &= *fromMap++;
      }

      if (i > 0)
      {
         /* mask off any extra bits in final word */
         mask = ~(-(1 << i));
         *toMap &= (*fromMap & mask);
      }
   }
   else
   {
      assert(0);
   }
}



extern
void bitAndByteArrayBitmaps(const uint8_t *fromMap, uint8_t *toMap,
                            uint32_t maxBits)
{
   int i;
   int mask;

   if(fromMap && toMap)
   {

      /* do all but the final byte, a byte at a time */
      for (i = maxBits; i >= 8; i -= 8)
      {
         *toMap++ &= *fromMap++;
      }

      if (i > 0)
      {
         /* mask off any extra bits in final byte */
         mask = ~(-(1 << i));
         *toMap &= (*fromMap & mask);
      }
   }
   else
   {
      assert(0);
   }
}

/* Determine if two bitmaps overlap, similar to bitAndBitmaps but more
 * efficient */
extern
bool bitmapsOverlap(const uint32_t *map1, const uint32_t *map2,
      uint32_t maxBits)
{
   int i;
   int mask;

   if(map1 && map2)
   {
      /* do all but the final word a word at a time */
      for (i = maxBits; i >= 32; i -= 32)
      {
         if (*map1++ & *map2++)
         {
            return true;
         }
      }

      if (i > 0)
      {
         /* mask off any extra bits in final word */
         mask = ~(-(1 << i));
         if (*map1 & *map2 & mask)
         {
            return true;
         }
      }

      return false;
   }
   else
   {
      assert(0);
      return false;
   }
}

/************ bit inverse bitmap *************/

extern
void bitInverseSmallBitmap(uint32_t *map, uint32_t maxBits)
{
   if(map && (maxBits <= 32))
   {
      map[0] = ~(map[0]);
   }
   else
   {
       assert(0);
   }
}
extern
void bitInverseBitmap(uint32_t *map, uint32_t maxBits)
{
   int i;
   int mask;

   if (maxBits <= 32)
   {
      bitInverseSmallBitmap(map, maxBits);
      return;
   }

   if(!map)
   {
       assert(0);
       return;
   }

   /* do all but the final word a word at a time */
   for (i = maxBits; i >= 32; i -= 32)
   {
      *map = ~(*map);
      map++;
   }

   if (i > 0)
   {
      /* mask off any extra bits in final word */
      mask = ~(-(1 << i));
      *map = (~(*map)) & mask;
   }
}



extern
void bitInverseByteArrayBitmap(uint8_t *map, uint32_t maxBits)
{
   int i;
   int mask;

   if(map)
   {

      /* do all but the final byte, a byte at a time */
      for (i = maxBits; i >= 8; i -= 8)
      {
         *map = ~(*map) & 0xff;
         map++;
      }

      if (i > 0)
      {
         /* mask off any extra bits in final byte */
         mask = ~(-(1 << i));
         *map = (~(*map)) & mask;
      }
   }
   else
   {
       assert(0);
   }
}

/************ bit XOR bitmap *************/
extern
void bitXorSmallBitmaps(const uint32_t *fromMap, uint32_t *toMap,
                        uint32_t maxBits)
{
   if(fromMap && toMap && (maxBits <= 32))
   {
      toMap[0] ^= fromMap[0];
   }
   else
   {
       assert(0);
   }
}

extern
void bitXorBitmaps(const uint32_t *fromMap, uint32_t *toMap, uint32_t maxBits)
{
   int i;
   int mask;

   if (maxBits <= 32)
   {
       bitXorSmallBitmaps(fromMap, toMap, maxBits);
       return;
   }

   if(fromMap && toMap)
   {
      /* do all but the final word a word at a time */
      for (i = maxBits; i >= 32; i -= 32)
      {
         *toMap++ ^= *fromMap++;
      }

      if (i > 0)
      {
         /* mask off any extra bits in final word */
         mask = ~(-(1 << i));
         *toMap ^= *fromMap;
         *toMap = *toMap & mask;
      }
   }
   else
   {
       assert(0);
   }
}



extern
void bitXorByteArrayBitmaps(const uint8_t *fromMap, uint8_t *toMap,
                            uint32_t maxBits)
{
   int i;
   int mask;

   if(fromMap && toMap)
   {

      /* do all but the final byte, a byte at a time */
      for (i = maxBits; i >= 8; i -= 8)
      {
         *toMap++ ^= *fromMap++;
      }

      if (i > 0)
      {
         /* mask off any extra bits in final byte */
         mask = ~(-(1 << i));
         *toMap ^= *fromMap;
         *toMap = *toMap & mask;
      }
   }
   else
   {
      assert(0);
   }
}

/************ bit SUB bitmap *************/
/*
 * Subtract fromMap from toMap.  All bits set in fromMap are cleared in toMap.
 * This is logically equivalent to ANDing toMap with the inverse of fromMap.
 * Note that unlike the operations above, this one is not commutative.
 */

extern
void bitSubSmallBitmaps(const uint32_t *fromMap, uint32_t *toMap,
                        uint32_t maxBits)
{
   if(fromMap && toMap && (maxBits <= 32))
   {
      toMap[0] &= ~fromMap[0];
   }
   else
   {
       assert(0);
   }
}
extern
void bitSubBitmaps(const uint32_t *fromMap, uint32_t *toMap, uint32_t maxBits)
{
   int i;
   int mask;

   if (maxBits <= 32)
   {
       bitSubSmallBitmaps(fromMap, toMap, maxBits);
       return;
   }
   if(fromMap && toMap)
   {
      /* do all but the final word a word at a time */
      for (i = maxBits; i >= 32; i -= 32)
      {
         *toMap++ &= ~*fromMap++;
      }

      if (i > 0)
      {
      /* mask off any extra bits in final word */
         mask = ~(-(1 << i));
         *toMap &= ~*fromMap;
         *toMap = *toMap & mask;
      }
   }
   else
   {
       assert(0);
   }
}



extern
void bitSubByteArrayBitmaps(const uint8_t *fromMap, uint8_t *toMap,
                            uint32_t maxBits)
{
   int i;
   int mask;

   if(fromMap && toMap)
   {

      /* do all but the final byte, a byte at a time */
      for (i = maxBits; i >= 8; i -= 8)
      {
      *toMap++ &= ~*fromMap++;
      }

      if (i > 0)
      {
         /* mask off any extra bits in final byte */
         mask = ~(-(1 << i));
         *toMap &= ~*fromMap;
         *toMap = *toMap & mask;
      }
   }
   else
   {
      assert(0);
   }
}

/************ are any bits set in bitmap *************/
extern
bool areAnyBitsSetInSmallBitmap(const uint32_t *map, uint32_t maxBits)
{
   if (!map || (maxBits > 32)) {
      assert(0);
      return(false);
   }

   return(map[0]);
}

extern
bool areAnyBitsSetInBitmap(const uint32_t *map, uint32_t maxBits)
{
   int i;
   /* maxBits is ignored, if it is not divisible by 32 */

   if (maxBits <= 32)
   {
       return areAnyBitsSetInSmallBitmap(map, maxBits);
   }

   if (!map) {
      assert(0);
      return(false);
   }

   for (i = maxBits; i > 0; i -= 32)
   {
      if (*map++)
      {
         return(true);
      }
   }
   return(false);
}



/************ No Of Bits set in bitmap *************/

extern
uint32_t getNumOfBitsSetInSmallBitmap(const uint32_t *map, uint32_t maxBits)
{
   uint32_t count=0;
   uint32_t val;

   if (!map || (maxBits > 32))
   {
      assert(0);
      return(0);
   }

   /* algorithm from http://graphics.stanford.edu/~seander/bithacks.html */
   val = map[0] - ((map[0] >> 1) & 0x55555555);
   val = (val & 0x33333333) + ((val >> 2) & 0x33333333);
   count = (((val + (val >> 4)) & 0xF0F0F0F) * 0x1010101) >> 24;
   return(count);
}

extern
uint32_t getNumOfBitsSetInBitmap(const uint32_t *map, uint32_t maxBits)
{
   int i;
   uint32_t val;
   uint32_t count=0;

   if (maxBits <= 32)
   {
       return getNumOfBitsSetInSmallBitmap(map, maxBits);
   }

   /* maxBits is ignored, if it is not divisible by 32 */

   if (!map)
   {
      assert(0);
      return(0);
   }

   for (i = maxBits; i > 0; i -= 32)
   {
      /* algorithm @ http://graphics.stanford.edu/~seander/bithacks.html */
      val = *map - ((*map >> 1) & 0x55555555);
      val = (val & 0x33333333) + ((val >> 2) & 0x33333333);
      count += (((val + (val >> 4)) & 0xF0F0F0F) * 0x1010101) >> 24;
      map++;
   }
   return(count);
}



extern
uint32_t getNumOfBitsSetInByteArrayBitmap(const uint8_t *map, uint32_t maxBits)
{
   int i;
   uint32_t count = 0;

   if (!map)
   {
      assert(0);
      return(0);
   }

   for (i = maxBits; i > 0; i -= 8)
   {
      count += bit_count_table[*map++];
   }

   return(count);
}

extern
bool areAnyBitsSetInByteArrayBitmap(const uint8_t *map, uint32_t maxBits)
{
   int i;

   if (!map)
   {
      assert(0);
      return(false);
   }

   for (i = maxBits; i > 0; i -= 8)
   {
      if (*map++)
      {
         return(true);
      }
   }
   return(false);
}

/************ are bitmaps equal *************/
extern
bool areSmallBitmapsEqual(const uint32_t *map1, const uint32_t *map2,
                             uint32_t maxBits)
{
   if (!map1 || !map2 || (maxBits > 32))
   {
      assert(0);
      return(false);
   }
   return(map1[0] == map2[0]);
}

extern
bool areBitmapsEqual(const uint32_t *map1, const uint32_t *map2,
                        uint32_t maxBits)
{
   int i;

   if (maxBits <= 32)
   {
      return areSmallBitmapsEqual(map1, map2, maxBits);
   }

   if (!map1 || !map2)
   {
      assert(0);
      return(false);
   }

   for (i = maxBits; i > 0; i -= 32)
   {
      if (*map1++ != *map2++)
      {
         return(false);
      }
   }

   return(true);
}



extern
bool areByteArrayBitmapsEqual(const uint8_t *map1, const uint8_t *map2,
                                 uint32_t maxBits)
{
   int i;

   if (!map1 || !map2)
   {
      assert(0);
      return(false);
   }
   for (i = maxBits; i > 0; i -= 8)
   {
      if (*map1++ != *map2++)
      {
         return(false);
      }
   }

   return(true);
}

/************ are all bits set *************/
extern
bool areAllBitsSetInSmallBitmap(const uint32_t *map, uint32_t maxBits)
{
   uint32_t mask = ~(-(1 << maxBits));
   if ((!map) || maxBits > 32)
   {
      assert(0);
      return false;
   }
   if ((map[0] & mask) != mask)
   {
       return false;
   }
   return true;
}

extern
bool areAllBitsSetInBitmap(const uint32_t *map, uint32_t maxBits)
{
   uint32_t i, mask;

   if (maxBits <= 32)
   {
       return areAllBitsSetInSmallBitmap(map, maxBits);
   }

   if (!map)
   {
      assert(0);
      return false;
   }
   for (i = maxBits; i >= 32; i -= 32)
   {
      if (*map++ != 0xffffffff)
      {
          return false;
      }
   }
   if (i > 0)
   {
      mask = ~(-(1 << i));
      if ((*map & mask) != mask)
      {
          return false;
      }
   }
   return true;
}



extern
bool areAllBitsSetInByteArrayBitmap(const uint8_t *map, uint32_t maxBits)
{
   uint32_t i;
   /* maxBits is ignored, if it is not divisible by 8 */

   if (!map)
   {
      assert(0);
      return(false);
   }

   for (i = 0; i < ((maxBits + 7) / 8); i++)
   {
      if (!map[i])
         return(false);
   }
   return(true);
}

/************ copy bitmap *************/
extern
void copySmallBitmap(const uint32_t *fromMap, uint32_t *toMap,
                     uint32_t maxBits)
{
   if(fromMap && toMap && (maxBits <= 32))
   {
      toMap[0] = fromMap[0];
   }
   else
   {
       assert(0);
   }
}

extern
void copyBitmap(const uint32_t *fromMap, uint32_t *toMap, uint32_t maxBits)
{
   int i;

   if (maxBits <= 32)
   {
      copySmallBitmap(fromMap, toMap, maxBits);
      return;
   }
   if(fromMap && toMap)
   {
      for (i = maxBits; i > 0; i -= 32)
      {
         *toMap++ = *fromMap++;
      }
   }
   else
   {
       assert(0);
   }
}



extern
void copyByteArrayBitmap(const uint8_t *fromMap, uint8_t *toMap,
                         uint32_t maxBits)
{
   int   i;

   if(fromMap && toMap)
   {
      for (i = maxBits; i > 0; i -= 8)
      {
         *toMap++ = *fromMap++;
      }
   }
}

#ifndef PC
/*
 * special routines to use when copying a bitMap into a msg or namespace item
 * that may be used on another processor
 */
extern
void htoipcCopySmallBitmap(const uint32_t *fromMap, uint32_t *toMap,
                           uint32_t maxBits)
{
   if(fromMap && toMap && (maxBits <= 32))
   {
      toMap[0] = htoipcl(fromMap[0]);
   }
   else
   {
       assert(0);
   }
}

extern
void htoipcCopyBitmap(const uint32_t *fromMap, uint32_t *toMap, uint32_t maxBits)
{
   int i;

   if(maxBits <=32)
   {
       htoipcCopySmallBitmap(fromMap, toMap, maxBits);
       return;
   }

   if(fromMap && toMap)
   {
      for (i = maxBits; i > 0; i -= 32)
      {
         *toMap++ = htoipcl(*fromMap);
         fromMap++; /* can't incr in htoipcl, else it gets done multiple times */
      }
   }
   else
   {
       assert(0);
   }
}



extern
void htoipcCopyByteArrayBitmap(const uint8_t *fromMap, uint8_t *toMap,
                               uint32_t maxBits)
{
   int i;

   /* No byte swap since copying bytes */
   if(fromMap && toMap)
   {
      for (i = maxBits; i > 0; i -= 8)
      {
         *toMap++ = *fromMap++;
      }
   }
   else
   {
      assert(0);
   }
}

/*
 * special routines to use when copying a bitMap from a msg or namespace item
 * that may be used on another processor
 */
extern
void ipctohCopySmallBitmap(const uint32_t *fromMap, uint32_t *toMap,
                           uint32_t maxBits)
{
   if(fromMap && toMap && (maxBits <= 32))
   {
      toMap[0] = ipctohl(fromMap[0]);
   }
   else
   {
       assert(0);
   }
}

extern
void ipctohCopyBitmap(const uint32_t *fromMap, uint32_t *toMap, uint32_t maxBits)
{
   int i;

   if (maxBits <= 32)
   {
       ipctohCopySmallBitmap(fromMap, toMap, maxBits);
       return;
   }

   if(fromMap && toMap)
   {
      for (i = maxBits; i > 0; i -= 32)
      {
         *toMap++ = ipctohl(*fromMap);
         fromMap++; /* can't incr in ipctohl, else it gets done multiple times */
      }
   }
   else
   {
       assert(0);
   }
}

extern
void ipctohCopyByteArrayBitmap(const uint8_t *fromMap, uint8_t *toMap,
                               uint32_t maxBits)
{
   int i;

   /* No byte swap since copying bytes */
   if(fromMap && toMap)
   {
      for (i = maxBits; i > 0; i -= 8)
      {
         *toMap++ = *fromMap++;
      }
   }
   else
   {
       assert(0);
   }
}


#endif /* PC */

/*****************************************************************************
 * vlan map inlines
 *
 *   Used for setting and clearing vlans in vlan bitmaps
 *
 *   Note: since vlanMaps are not used as much as portMaps, we do optimize
 *         for switches that support less then 32 vlans
 ****************************************************************************/
extern
void set_vlan(VLAN_MAP *map, uint32_t vlan)
{
   if(map)
   {
      setBit(&map->vmap[0], vlan, MAX_VLANS);
   }
   else
   {
       assert(0);
   }
}

extern
void clear_vlan(VLAN_MAP *map, uint32_t vlan)
{
   if(map)
   {
      clrBit(&map->vmap[0], vlan, MAX_VLANS);
   }
   else
   {
       assert(0);
   }
}

extern
VID_t find_first_vlan_set(const VLAN_MAP *map)
{
   if(map)
   {
      return((VID_t)findFirstBitSet(&map->vmap[0], MAX_VLANS));
   }
   else
   {
       assert(0);
       return (VID_t)-1;
   }
}

extern
VID_t find_next_vlan(const VLAN_MAP *map, uint32_t prevVlan)
{
   if(map)
   {
      return((VID_t)findNextBitSet(&map->vmap[0], prevVlan, MAX_VLANS));
   }
   else
   {
       assert(0);
       return ((VID_t)-1);
   }
}

extern
bool is_vlan_set(const VLAN_MAP *map, uint32_t vlan)
{
   if (!map)
   {
      assert(0);
      return(false);
   }
   return(isBitSet(&map->vmap[0], vlan, MAX_VLANS));
}

extern
void clear_vlan_map(VLAN_MAP *map)
{
   if(map)
   {
      clearBitmap(&map->vmap[0], MAX_VLANS);
   }
   else
   {
       assert(0);
   }
}

extern
uint32_t count_vlans(const VLAN_MAP *map)
{
   if(map)
   {
      return getNumOfBitsSetInByteArrayBitmap((uint8_t*)map, MAX_VLANS);
   }
   else
   {
      assert(0);
      return 0;
   }
}

extern
void bit_or_vlan_maps(const VLAN_MAP *fromMap, VLAN_MAP *toMap)
{
   if(fromMap && toMap)
   {
      bitOrBitmaps(&fromMap->vmap[0], &toMap->vmap[0], MAX_VLANS);
   }
   else
   {
      assert(0);
   }
}

extern
void bit_and_vlan_maps(const VLAN_MAP *fromMap, VLAN_MAP *toMap)
{
   if(fromMap && toMap)
   {
      bitAndBitmaps(&fromMap->vmap[0], &toMap->vmap[0], MAX_VLANS);
   }
   else
   {
      assert(0);
   }
}

extern
void bit_xor_vlan_maps(const VLAN_MAP *fromMap, VLAN_MAP *toMap)
{
   if(fromMap && toMap)
   {
      bitXorBitmaps(&fromMap->vmap[0], &toMap->vmap[0], MAX_VLANS);
   }
   else
   {
      assert(0);
   }
}

extern
void bit_sub_vlan_maps(const VLAN_MAP *fromMap, VLAN_MAP *toMap)
{
   if(fromMap && toMap)
   {
      bitSubBitmaps(&fromMap->vmap[0], &toMap->vmap[0], MAX_VLANS);
   }
   else
   {
       assert(0);
   }
}

extern
void bit_inverse_vlan_map(VLAN_MAP *map)
{
   if(map)
   {
      bitInverseBitmap(&map->vmap[0], MAX_VLANS);
   }
   else
   {
      assert(0);
   }
}

extern
bool are_any_vlans_set(const VLAN_MAP *map)
{
   if (!map)
   {
      assert(0);
      return(false);
   }
   return(areAnyBitsSetInBitmap(&map->vmap[0], MAX_VLANS));
}

extern
bool are_vlanmaps_equal(const VLAN_MAP *vlanMap1, const VLAN_MAP *vlanMap2)
{
   if (!vlanMap1 || !vlanMap2)
   {
      assert(0);
      return(false);
   }
   return(areBitmapsEqual(&vlanMap1->vmap[0], &vlanMap2->vmap[0], MAX_VLANS));
}

extern
void copy_vlan_map(const VLAN_MAP *fromMap, VLAN_MAP *toMap)
{
   if(fromMap && toMap)
   {
      copyBitmap(&fromMap->vmap[0], &toMap->vmap[0], MAX_VLANS);
   }
   else
   {
       assert(0);
   }
}

#ifndef PC
/*
 * special routine to use when copying a vlan_map into a msg or namespace item
 * that may be used on another processor
 */
extern
void htoipc_copy_vlan_map(const VLAN_MAP *fromMap, VLAN_MAP *toMap)
{
   if(fromMap && toMap)
   {
      htoipcCopyBitmap(&fromMap->vmap[0], &toMap->vmap[0], MAX_VLANS);
   }
   else
   {
      assert(0);
   }
}

/*
 * special routine to use when copying a vlan_map from a msg or namespace item
 * that may be used on another processor
 */
extern
void ipctoh_copy_vlan_map(const VLAN_MAP *fromMap, VLAN_MAP *toMap)
{
   if(fromMap && toMap)
   {
      ipctohCopyBitmap(&fromMap->vmap[0], &toMap->vmap[0], MAX_VLANS);
   }
   else
   {
      assert(0);
   }
}
#endif /* PC */


/*****************************************************************************
 * vlan id map inlines
 *
 *   Used for setting and clearing vlan identifiers in vlan id bitmaps
 *
 ****************************************************************************/
extern
void set_vid(VID_MAP *map, uint32_t vid)
{
   if(map)
   {
      setBit(&map->vidMap[0], vid, MAX_VLAN_ID);
   }
   else
   {
       assert(0);
   }
}

extern
void clear_vid(VID_MAP *map, uint32_t vid)
{
   if(map)
   {
      clrBit(&map->vidMap[0], vid, MAX_VLAN_ID);
   }
   else
   {
       assert(0);
   }
}

extern
VID_t find_first_vid_set(const VID_MAP *map)
{
   if(map)
   {
      return((VID_t)findFirstBitSet(&map->vidMap[0], MAX_VLAN_ID));
   }
   else
   {
       assert(0);
       return ((VID_t)-1);
   }
}

extern
VID_t find_next_vid(const VID_MAP *map, uint32_t prevVid)
{
   if(map)
   {
      return((VID_t)findNextBitSet(&map->vidMap[0], prevVid, MAX_VLAN_ID));
   }
   else
   {
       assert(0);
       return ((VID_t)-1);
   }
}

extern
bool is_vid_set(const VID_MAP *map, uint32_t vid)
{
   if (!map) {
      assert(0);
      return(false);
   }
   return(isBitSet(&map->vidMap[0], vid, MAX_VLAN_ID));
}

extern
void clear_vid_map(VID_MAP *map)
{
   if(map)
   {
      clearBitmap(&map->vidMap[0], MAX_VLAN_ID);
   }
   else
   {
       assert(0);
   }
}

extern
uint32_t count_vids(const VID_MAP *map)
{
   if(map)
   {
      return getNumOfBitsSetInBitmap((uint32_t*)map, MAX_VLAN_ID);
   }
   else
   {
       assert(0);
       return 0;
   }
}

extern
void bit_or_vid_maps(const VID_MAP *fromMap, VID_MAP *toMap)
{
   if(fromMap && toMap)
   {
      bitOrBitmaps(&fromMap->vidMap[0], &toMap->vidMap[0], MAX_VLAN_ID);
   }
   else
   {
      assert(0);
   }
}

extern
void bit_and_vid_maps(const VID_MAP *fromMap, VID_MAP *toMap)
{
   if(fromMap && toMap)
   {
      bitAndBitmaps(&fromMap->vidMap[0], &toMap->vidMap[0], MAX_VLAN_ID);
   }
   else
   {
      assert(0);
   }
}

extern
void bit_xor_vid_maps(const VID_MAP *fromMap, VID_MAP *toMap)
{
   if(fromMap && toMap)
   {
      bitXorBitmaps(&fromMap->vidMap[0], &toMap->vidMap[0], MAX_VLAN_ID);
   }
   else
   {
       assert(0);
   }

}

extern
void bit_sub_vid_maps(const VID_MAP *fromMap, VID_MAP *toMap)
{
   if(fromMap && toMap)
   {
      bitSubBitmaps(&fromMap->vidMap[0], &toMap->vidMap[0], MAX_VLAN_ID);
   }
   else
   {
      assert(0);
   }

}

extern
bool vid_maps_overlap(const VID_MAP *map1, const VID_MAP *map2)
{
   if(map1 && map2)
   {
      return bitmapsOverlap((uint32_t*)map1, (uint32_t*)map2, MAX_VLAN_ID);
   }
   else
   {
       assert(0);
       return false;
   }
}

extern
void bit_inverse_vid_map(VID_MAP *map)
{
   if(map)
   {
      bitInverseBitmap(&map->vidMap[0], MAX_VLAN_ID);
   }
   else
   {
      assert(0);
   }
}

extern
bool are_any_vids_set(const VID_MAP *map)
{
   if (!map)
   {
      assert(0);
      return(false);
   }
   return(areAnyBitsSetInBitmap(&map->vidMap[0], MAX_VLAN_ID));
}

extern
bool are_vidmaps_equal(const VID_MAP *vidMap1, const VID_MAP *vidMap2)
{
   if (!vidMap1 || !vidMap2)
   {
      assert(0);
      return(false);
   }
   return(areBitmapsEqual(&vidMap1->vidMap[0], &vidMap2->vidMap[0],
                          MAX_VLAN_ID));
}

extern
void copy_vid_map(const VID_MAP *fromMap, VID_MAP *toMap)
{
   if(fromMap && toMap)
   {
      copyBitmap(&fromMap->vidMap[0], &toMap->vidMap[0], MAX_VLAN_ID);
   }
   else
   {
      assert(0);
   }
}

/*
 * special routine to use when copying a vid_map into a msg or namespace item
 * that may be used on another processor
 */
extern
void htoipc_copy_vid_map(const VID_MAP *fromMap, VID_MAP *toMap)
{
      if(fromMap && toMap)
      {
         htoipcCopyBitmap(&fromMap->vidMap[0], &toMap->vidMap[0], MAX_VLAN_ID);
      }
      else
      {
          assert(0);
      }
}

/*
 * special routine to use when copying a vid_map from a msg or namespace item
 * that may be used on another processor
 */
extern
void ipctoh_copy_vid_map(const VID_MAP *fromMap, VID_MAP *toMap)
{
      if(fromMap && toMap)
      {
         ipctohCopyBitmap(&fromMap->vidMap[0], &toMap->vidMap[0], MAX_VLAN_ID);
      }
      else
      {
          assert(0);
      }
}

/**PROC+**********************************************************************
 * Name:      areBitArraysEqual
 *
 * Purpose:   compare two 2-bit or 4-bit bitmap array with a different
 *            2-bit or 4-bit bitmap array
 *
 * Params:    map1        - ptr to first bitmap array
 *            map2        - ptr to second bitmap array
 *            fieldSize   - 2 or 4 (size in bits)
 *            maxFields   - the maximum field that this array has
 *
 * Returns:   true if bit arrays are equal
 *
 **PROC-**********************************************************************/
extern
bool areBitArraysEqual(const uint8_t *map1, const uint8_t *map2,
                       int fieldSize, int maxFields)
{
   int size;

   assert((fieldSize == 2) || (fieldSize == 4));

   size = fieldSize * maxFields;

   return(areByteArrayBitmapsEqual(map1, map2, size));
}

/**PROC+**********************************************************************
 * Name:      setFieldInBitMap
 *
 * Purpose:   Allows setting fields in a 2-bit or 4-bit bitmap
 *
 * Params:    map         - ptr to bitmap overwhich the 2-bit
 *                          or 4-bit array is mapped
 *            field       - field (1-maxFields)
 *            fieldValue  - value being stored
 *            fieldSize   - 2 or 4 (size in bits)
 *            maxFields   - the maximum field that this array has
 *
 * Returns:   none
 *
 **PROC-**********************************************************************/
extern
void setFieldInBitmap(uint32_t *map,
                      int field, int fieldValue, int fieldSize, int maxFields)
{
   int wdOff;
   int bitOff;
   int mask;

   assert((field > 0) && (field <= maxFields));

   if ((field > 0) && (field <= maxFields)) {
      switch (fieldSize) {
       case 2:
         /* 2 bits per field */
         assert((fieldValue >= 0) && (fieldValue <= 3));

         wdOff  = (field * fieldSize) / 32;
         bitOff = ((field - 1) * fieldSize) % 32;

         mask = ~(0x3 << bitOff);
         map[wdOff] = (map[wdOff] & mask) | (fieldValue << bitOff);
         break;

       case 4:
         /* 4 bits per field */
         assert((fieldValue >= 0) && (fieldValue <= 15));

         wdOff  = (field * fieldSize) / 32;
         bitOff  = ((field - 1) * fieldSize) % 32;

         mask = ~(0xf << bitOff);
         map[wdOff] = (map[wdOff] & mask) | (fieldValue << bitOff);
         break;

       default:
         assert(0);
      }
   }
}


/**PROC+**********************************************************************
 * Name:      getFieldFromBitArray
 *
 * Purpose:   get a field value in a 2-bit or 4-bit bitmap array
 *
 * Params:    map         - ptr to array of bytes overwhich the 2-bit
 *                          or 4-bit array is mapped
 *            field       - field (1-maxFields)
 *            fieldSize   - 2 or 4 (size in bits)
 *            maxFields   - the maximum field that this array has
 *
 * Returns:   field value
 *
 **PROC-**********************************************************************/
extern
int getFieldFromBitArray(const uint8_t *map, int field, int fieldSize, int maxFields)
{
   int byteOff;
   int bitOff;
   int mask;
   int result = -1;

   assert((field > 0) && (field <= maxFields));

   if ((field > 0) && (field <= maxFields)) {
      switch (fieldSize) {
       case 2:
         /* 2 bits per field */
         byteOff = ((field - 1) * fieldSize) / 8;
         bitOff  = ((field - 1) * fieldSize) % 8;

         mask = 0x3 << bitOff;
         result = (map[byteOff] & mask) >> bitOff;
         break;

       case 4:
         /* 4 bits per field */
         byteOff = ((field - 1) * fieldSize) / 8;
         bitOff  = ((field - 1) * fieldSize) % 8;

         mask = 0xf << bitOff;
         result = (map[byteOff] & mask) >> bitOff;
         break;
       default:
         assert(0);
      }
   }
   return(result);
}

/**PROC+**********************************************************************
 * Name:      getFieldFromBitmap
 *
 * Purpose:   get a field value in a 2-bit or 4-bit bitmap array
 *
 * Params:    map         - ptr to array of bytes overwhich the 2-bit
 *                          or 4-bit array is mapped
 *            field       - field (1-maxFields)
 *            fieldSize   - 2 or 4 (size in bits)
 *            maxFields   - the maximum field that this array has
 *
 * Returns:   field value
 *
 **PROC-**********************************************************************/
extern
int getFieldFromBitmap(const uint32_t *map, int field, int fieldSize, int maxFields)
{
   int wdOff;
   int bitOff;
   int mask;
   int result = -1;

   assert((field > 0) && (field <= maxFields));

   if ((field > 0) && (field <= maxFields)) {
      switch (fieldSize) {
       case 2:
         /* 2 bits per field */
         wdOff = (field * fieldSize) / 32;
         bitOff  = ((field - 1) * fieldSize) % 32;

         mask = 0x3 << bitOff;
         result = (map[wdOff] & mask) >> bitOff;
         break;

       case 4:
         /* 4 bits per field */
         wdOff = (field * fieldSize) / 32;
         bitOff  = ((field - 1) * fieldSize) % 32;

         mask = 0xf << bitOff;
         result = (map[wdOff] & mask) >> bitOff;
         break;
       default:
         assert(0);
      }
   }
   return(result);
}


/**PROC+**********************************************************************
 * Name:      ffs
 *
 * Purpose:   Find the first bit set in bitmask
 *
 * Returns:   -1 if no bits set, or a bit position 0-31
 *            where 0 is the LSB
 *
 * Params:    bitmask - item to search for first bit set
 *
 * Globals:   none
 *
 * Operation:
 **PROC-**********************************************************************/
extern int sw_ffs(uint32_t bitmask)
{
   if (bitmask)
   {
      return __CTZ32(bitmask);
   }
   return (-1);
}

/**PROC+**********************************************************************
 * Name:      ffc
 *
 * Purpose:   Find the first bit cleared in bitmask
 *
 * Returns:   -1 if no bits clr'd, or a bit position 0-31
 *            where 0 is the LSB
 *
 * Params:    bitmask - item to search for first bit clear
 *
 * Globals:   none
 *
 * Operation:
 **PROC-**********************************************************************/
extern int ffc(uint32_t bitmask)
{
   return (sw_ffs(~bitmask));
}
#if 0
/**PROC+**********************************************************************
 * Name:      ffsll
 *
 * Purpose:   Find the first bit set in 64bit bitmask
 *
 * Returns:   -1 if no bits set, or a bit position 0-64
 *            where 0 is the LSB
 *
 * Params:    64bit bitmask
 *
 * Globals:   none
 *
 * Operation:
 **PROC-**********************************************************************/
extern int ffsll(uint64_t bitmask)
{
   unsigned long long int x = bitmask & -bitmask;

   if (x <= 0xffffffff)
   {
      return sw_ffs(bitmask);
   }
   else
   {
      return 32 + sw_ffs(bitmask >> 32);
   }
}
#endif /*0*/
/**PROC+**********************************************************************
 * Name:      fls
 *
 * Purpose:   Find the last bit set in bitmask
 *
 * Returns:   -1 if no bits set, or a bit position 0-31
 *            where 0 is the LSB
 *
 * Params:    bitmask - item to search for last bit set
 *
 * Globals:   none
 *
 * Operation:
 **PROC-**********************************************************************/
extern int fls(uint32_t bitmask)
{
   return (31 - __CLZ32(bitmask));
}

/**PROC+**********************************************************************
 * Name:      setbit
 *
 * Purpose:   sets the bit specified in the bitmask and leaves the other
 *            bits alone
 *
 * Returns:   none
 *
 * Params:    bitmask - item to be modified
 *            offset - bit offset to be modified
 *
 * Globals:   none
 *
 * Operation:
 **PROC-**********************************************************************/
extern void setbit(uint32_t *bitmask, int offset)
{
   uint32_t mask = 0x01<<offset;

   *bitmask |= mask;
}

/**PROC+**********************************************************************
 * Name:      clrbit
 *
 * Purpose:   clears the bit specified in the bitmask and leaves the other
 *            bits alone
 *
 * Returns:   none
 *
 * Params:    bitmask - item to be modified
 *            offset - bit offset to be modified
 *
 * Globals:   none
 *
 * Operation:
 **PROC-**********************************************************************/
extern void clrbit(uint32_t *bitmask, int offset)
{
   uint32_t mask = 0x01<<offset;

   *bitmask &= ~mask;
}

/**PROC+**********************************************************************
 *  * Name:      storeShortInPacket
 *   *
 *    * Purpose:   store a short in packet without causing a non-align memory
 *     *            access errro
 *      *
 *       * Params:    packetPtr - pointer to where to store short
 *        *            value     - value to store
 *         *
 *          * Returns:   none
 *           *
 *            * Note:      Because of the way this routine writes into memory, the
 *             *            data will be in network byte order regardless of the
 *              *            CPU host order. Because of this, there you should not
 *               *            call htons on the data passed to this routine.
 *                **PROC-**********************************************************************/
void storeShortInPacket(uint16_t *packetPtr, uint16_t value)
{
    *(uint8_t *)packetPtr = value >> 8;
    *(((uint8_t *)packetPtr) + 1) = value & 0xff;
}

/**PROC+**********************************************************************
 *  * Name:      storeLongInPacket
 *   *
 *    * Purpose:   store a long in packet without causing a non-align memory
 *     *            access error
 *      *
 *       * Params:    packetPtr - pointer to where to store long
 *        *            value     - value to store
 *         *
 *          * Returns:   none
 *           *
 *            * Note:      Because of the way this routine writes into memory, the
 *             *            data will be in network byte order regardless of the
 *              *            CPU host order. Because of this, there you should not
 *               *            call htonl on the data passed to this routine.
 *                **PROC-**********************************************************************/
void storeLongInPacket(uint32_t *packetPtr, uint32_t value)
{
    *(uint8_t *)packetPtr         = (value >> 24) & 0xff;
    *(((uint8_t *)packetPtr) + 1) = (value >> 16) & 0xff;
    *(((uint8_t *)packetPtr) + 2) = (value >>  8) & 0xff;
    *(((uint8_t *)packetPtr) + 3) = value & 0xff;
}

/*****************************************************************************
 * port map inlines
 *
 *   Used for setting and clearing ports in port bitmaps
 *
 *
 *   Note: There are currently two versions of these functions.
 *         One allows operations on port maps of up to 32 ports.
 *         The other allows operations on greater than 32 ports
 *         (scales according to MAX_LPORTS)
 *
 ****************************************************************************/
extern
uint32_t PortMap_getNumOfPortsSet(const PORT_MAP *map)
{
   assert(map);
#if (PORT_MAP_ARRAY_SIZE == 1)
   return (getNumOfBitsSetInSmallBitmap(&map->map[0], MAX_LPORTS));
#else
   return (getNumOfBitsSetInBitmap(&map->map[0],MAX_LPORTS));
#endif
}

extern
void PortMap_setPort(PORT_MAP *map, PORT_t port)
{
   assert(map);

#if (PORT_MAP_ARRAY_SIZE == 1)
   setBitInSmallBitmap(&map->map[0], port, MAX_LPORTS);
#else
   setBit(&map->map[0], port, MAX_LPORTS);
#endif
}

extern
void PortMap_clearPort(PORT_MAP *map, PORT_t port)
{
   assert(map);

#if (PORT_MAP_ARRAY_SIZE == 1)
   clrBitInSmallBitmap(&map->map[0], port, MAX_LPORTS);
#else
   clrBit(&map->map[0], port, MAX_LPORTS);
#endif
}

extern
PORT_t PortMap_findFirstPortSet(const PORT_MAP *map)
{
   int rv;
   assert(map);

#if (PORT_MAP_ARRAY_SIZE == 1)
   rv = findFirstBitSetInSmallBitmap(&map->map[0], MAX_LPORTS);
#else
   rv = findFirstBitSet(&map->map[0], MAX_LPORTS);
#endif
   if (rv == -1)
   {
     return(0xffff);
   }
   else
   {
     return((PORT_t)rv);
   }
}

extern
PORT_t PortMap_findNextPortSet(const PORT_MAP *map, PORT_t prevPort)
{
   int rv;
   assert(map);

#if (PORT_MAP_ARRAY_SIZE == 1)
   rv = findNextBitSetInSmallBitmap(&map->map[0], prevPort, MAX_LPORTS);
#else
   rv = findNextBitSet(&map->map[0], prevPort, MAX_LPORTS);
#endif
   if (rv == -1)
   {
     return(0xffff);
   }
   else
   {
     return((PORT_t)rv);
   }
}


extern
bool PortMap_isPortSet(const PORT_MAP *map, PORT_t port)
{
   if (!map) {
      assert(0);
      return(false);
   }
#if (PORT_MAP_ARRAY_SIZE == 1)
   return(isBitSetInSmallBitmap(&map->map[0], port, MAX_LPORTS));
#else
   return(isBitSet(&map->map[0], port, MAX_LPORTS));
#endif
}

extern
int find_first_port_set(const PORT_MAP *map)
{
   PORT_t   port;

   port = PortMap_findFirstPortSet(map);
   return (port == 0xffff) ? -1 : (int)port;
}

extern
int find_next_port_set(const PORT_MAP *map, int prevPort)
{
   PORT_t   port;

   port = PortMap_findNextPortSet(map, prevPort);
   return (port == 0xffff) ? -1 : (int)port;
}

extern
void PortMap_clear(PORT_MAP *map)
{
   assert(map);

#if (PORT_MAP_ARRAY_SIZE == 1)
   clearSmallBitmap(&map->map[0], MAX_LPORTS);
#else
   clearBitmap(&map->map[0], MAX_LPORTS);
#endif
}

extern
void PortMap_bitOrPortMaps(const PORT_MAP *fromMap, PORT_MAP *toMap)
{
   assert(fromMap && toMap);

#if (PORT_MAP_ARRAY_SIZE == 1)
   bitOrSmallBitmaps(&fromMap->map[0], &toMap->map[0], MAX_LPORTS);
#else
   bitOrBitmaps(&fromMap->map[0], &toMap->map[0], MAX_LPORTS);
#endif
}

extern
void PortMap_bitAndPortMaps(const PORT_MAP *fromMap, PORT_MAP *toMap)
{
   assert(fromMap && toMap);

#if (PORT_MAP_ARRAY_SIZE == 1)
   bitAndSmallBitmaps(&fromMap->map[0], &toMap->map[0], MAX_LPORTS);
#else
   bitAndBitmaps(&fromMap->map[0], &toMap->map[0], MAX_LPORTS);
#endif
}

extern
void PortMap_bitXorPortMaps(const PORT_MAP *fromMap, PORT_MAP *toMap)
{
   assert(fromMap && toMap);

#if (PORT_MAP_ARRAY_SIZE == 1)
   bitXorSmallBitmaps(&fromMap->map[0], &toMap->map[0], MAX_LPORTS);
#else
   bitXorBitmaps(&fromMap->map[0], &toMap->map[0], MAX_LPORTS);
#endif
}

extern
void PortMap_bitSubPortMaps(const PORT_MAP *fromMap, PORT_MAP *toMap)
{
   assert(fromMap && toMap);

#if (PORT_MAP_ARRAY_SIZE == 1)
   bitSubSmallBitmaps(&fromMap->map[0], &toMap->map[0], MAX_LPORTS);
#else
   bitSubBitmaps(&fromMap->map[0], &toMap->map[0], MAX_LPORTS);
#endif
}

extern
void PortMap_bitInversePortMap(PORT_MAP *map)
{
   assert(map);

#if (PORT_MAP_ARRAY_SIZE == 1)
   bitInverseSmallBitmap(&map->map[0], MAX_LPORTS);
#else
   bitInverseBitmap(&map->map[0], MAX_LPORTS);
#endif
}

extern
bool PortMap_areAnyPortsSet(const PORT_MAP *map)
{
   if (!map) {
      assert(0);
      return(false);
   }
#if (PORT_MAP_ARRAY_SIZE == 1)
   return(areAnyBitsSetInSmallBitmap(&map->map[0], MAX_LPORTS));
#else
   return(areAnyBitsSetInBitmap(&map->map[0], MAX_LPORTS));
#endif
}

extern
bool PortMap_arePortMapsEqual(const PORT_MAP *portMap1, const PORT_MAP *portMap2)
{
   if (!portMap1 || !portMap2) {
      assert(0);
      return(false);
   }
#if (PORT_MAP_ARRAY_SIZE == 1)
   return(areSmallBitmapsEqual(&portMap1->map[0], &portMap2->map[0],
                               MAX_LPORTS));
#else
   return(areBitmapsEqual(&portMap1->map[0], &portMap2->map[0], MAX_LPORTS));
#endif
}

extern
void PortMap_copy(const PORT_MAP *fromMap, PORT_MAP *toMap)
{
   assert(fromMap && toMap);

#if (PORT_MAP_ARRAY_SIZE == 1)
   copySmallBitmap(&fromMap->map[0], &toMap->map[0], MAX_LPORTS);
#else
   copyBitmap(&fromMap->map[0], &toMap->map[0], MAX_LPORTS);
#endif
}

#ifndef PC
/*
 * special routine to use when copying a port_map into a msg or namespace item
 * that may be used on another processor
 */
extern
void PortMap_htoipcCopy(const PORT_MAP *fromMap, PORT_MAP *toMap)
{
   assert(fromMap && toMap);
#if (PORT_MAP_ARRAY_SIZE == 1)
   htoipcCopySmallBitmap(&fromMap->map[0], &toMap->map[0], MAX_LPORTS);
#else
   htoipcCopyBitmap(&fromMap->map[0], &toMap->map[0], MAX_LPORTS);
#endif
}

/*
 * special routine to use when copying a port_map from a msg or namespace item
 * that may be used on another processor
 */
extern
void PortMap_ipctohCopy(const PORT_MAP *fromMap, PORT_MAP *toMap)
{
   assert(fromMap && toMap);
#if (PORT_MAP_ARRAY_SIZE == 1)
   ipctohCopySmallBitmap(&fromMap->map[0], &toMap->map[0], MAX_LPORTS);
#else
   ipctohCopyBitmap(&fromMap->map[0], &toMap->map[0], MAX_LPORTS);
#endif
}

/**PROC+**********************************************************************
 * Name:      insqti_nodis
 **PROC-**********************************************************************/
extern bool insqti_nodis(QUEUE_HEAD *head, QUEUE_THREAD *newItem)
{
    int nonempty;

    assert(head != NULL);
    assert(newItem != NULL);
    assert(newItem->q_flink == NULL);

    nonempty = (head->q_blink != (QUEUE_THREAD *)head);

    newItem->q_flink = (QUEUE_THREAD *)head;
    newItem->q_blink = head->q_blink;
    head->q_blink->q_flink = newItem;
    head->q_blink = newItem;
    return (nonempty);
}
/**PROC+**********************************************************************
 *  * Name:      qfirst_nodis
 **PROC-**********************************************************************/
extern QUEUE_THREAD *qfirst_nodis(const QUEUE_HEAD *head)
{
    QUEUE_THREAD *item;

    assert(head != NULL);

    item = head->q_flink;

    if (item == (QUEUE_THREAD *)head)
        item = NULL;
    return item;
}


extern QUEUE_THREAD *qnext_nodis(const QUEUE_HEAD *head, const QUEUE_THREAD *currentItem)
{
    QUEUE_THREAD *nextItem;

    assert(head != NULL);
    assert(currentItem != NULL);

    if (currentItem->q_flink == (QUEUE_THREAD *)head)
    {
        /* current item is last in queue, no next item */
        nextItem = (QUEUE_THREAD *)NULL;
    }
    else
    {
        /* have a "next" item, so get it */
        nextItem = currentItem->q_flink;
    }

    return (nextItem);
}

extern bool remqhere_nodis(QUEUE_HEAD *head, QUEUE_THREAD *currentItem)
{
    bool rtnValue = false;

    assert(head != NULL);
    assert(currentItem != NULL);

    if (currentItem == (QUEUE_THREAD *)head)
    {
        /* currentItem is head, can't remove it... */
    }
    else if (currentItem->q_flink == Q_NULL)
    {
        /* item NOT in queue, so no need to attempt removal */
    }
    else
    {
        /* proceed with removal */

        /* make previous item q_flink point to our q_flink */
        currentItem->q_blink->q_flink = currentItem->q_flink;

        /* make next item q_blink point to our q_blink */
        currentItem->q_flink->q_blink = currentItem->q_blink;

        /* set q_flink and q_blink to Q_NULL to show not in list anymore */
        currentItem->q_flink = Q_NULL;
        currentItem->q_blink = Q_NULL;
        rtnValue = true;
    }

    return (rtnValue);
}

extern bool qempty(const QUEUE_HEAD *head)
{
   assert(head != NULL);
    return (qfirst(head) == 0);
}

extern QUEUE_THREAD *qfirst(const QUEUE_HEAD *head)
{
    QUEUE_THREAD *item;
    item = qfirst_nodis(head);
    return item;
}
extern QUEUE_THREAD *remqhi(QUEUE_HEAD *head)
{
   QUEUE_THREAD *item;
   item = remqhi_nodis(head);
   return item;
}

extern QUEUE_THREAD *remqhi_nodis(QUEUE_HEAD *head)
{
   QUEUE_THREAD *item;

   assert(head != NULL);

   item = head->q_flink;
   if (item == (QUEUE_THREAD *)head)
      item = 0;
   else
   {
      assert(item->q_flink != Q_NULL);
      assert(item->q_blink != Q_NULL);
      head->q_flink = item->q_flink;
      item->q_flink->q_blink = (QUEUE_THREAD *)head;
      item->q_flink = Q_NULL;
      item->q_blink = Q_NULL;
   }
   return item;
}
extern void inique(QUEUE_HEAD *head)
{
   inique_nodis(head);
}

/**PROC+**********************************************************************
 * Name:      inique_nodis
 *
 * ISR safe:  NO
 *
 * Purpose:   initialize a queue
 *
 * Returns:   none
 *
 * Params:    *head - location where queue head is to be located
 *
 * Globals:   none
 *
 * Operation:
 **PROC-**********************************************************************/
extern void inique_nodis(QUEUE_HEAD *head)
{
   assert(head != NULL);

   head->q_flink = (QUEUE_THREAD *)head;
   head->q_blink = (QUEUE_THREAD *)head;
}

#endif /* PC */
