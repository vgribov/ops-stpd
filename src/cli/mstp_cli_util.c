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
/****************************************************************************
 *    File               : mstp_cli_util.c
 *    Description        : MSTP Protocol CLI Utilities
 ******************************************************************************/

#include "mstp_inlines.h"
#include "mstp_mapping.h"
#include "vtysh/vty.h"
#include "vtysh/command.h"
#include "vtysh/vtysh.h"
#include <openswitch-idl.h>

extern struct ovsdb_idl *idl;
#define MAX_VID_STR_LEN 10 /* length of "xxxx-xxxx" + '\0' */
#define MAX_INDENT      15
#define MAX_LINE_LEN    80
#define MSTP_CISTID                 0
#define MSTP_MSTID_MIN              1
#define MSTP_MSTID_MAX              64
#define MSTP_VALID_MSTID(mstid) \
    (((mstid) >= MSTP_MSTID_MIN) && ((mstid) <= MSTP_MSTID_MAX))

#define MEGA_BITS_PER_SEC  1000000
#define INTF_TO_MSTP_LINK_SPEED(s)    ((s)/MEGA_BITS_PER_SEC)
#define VERIFY_LAG_IFNAME(s) strncasecmp(s, "lag", 3)

#define DEF_LINK_SPEED                20000
/**PROC+**********************************************************************
* Name:      print_vidmap_multiline
*
* Purpose:   Prints a vidmap in multiple lines
*
* Returns:   Number of characters printed.
*
* Params:    vidMap            -> VIDMAP to be printed
*            lineLength        -> Length for printing VLAN list
*            lineIndent        -> Offset to start printing VLAN list
**PROC-**********************************************************************/
void print_vidmap_multiline(VID_MAP * vidMap, uint32_t lineLength,
                       uint32_t lineIndent) {
   int32_t   vid;
   int32_t   vidFound = 0;
   bool     findRange  = false;
   int32_t   printedLineLen = 0;
   char      vidStr[MAX_VID_STR_LEN] = {0};
   char      *tmp = NULL;
   char      *vidDelimiter = ",";
   char      *rangeDelimiter = "-";
   int       l = 0;
   int       rem_len = 0;

   STP_ASSERT(vidMap);

   /* Print VIDs that are set in the VID MAP
    * NOTE: We loop one extra time, so that we can print the final VID
    *       before we exit */
   tmp = vidStr;
   for(vid = MIN_VLAN_ID; vid <= MAX_VLAN_ID + 1; vid++)
   {
      rem_len = 0;
      if(is_vid_set(vidMap, vid))
      {/* VID is set */
         if(findRange == false)
         {/* print the VID found and start looking for a range */
            STP_ASSERT((tmp - vidStr) < (int)sizeof(vidStr));
            rem_len = (MAX_VID_STR_LEN - (vidStr - tmp));
            snprintf(tmp, rem_len, "%d%n", vid, &l);
            tmp += l;
            findRange = true;
            vidFound = vid;
         }
         /* clear VID from map to keep track on how many others left */
         clear_vid(vidMap, vid);
      }
      else
      {/* VID is not set */
         if(findRange == true)
         {/* we tried to find a VID range and the first VID in range has been
           * already printed */
            int rangeSize = (vid - 1) - vidFound;

            if(rangeSize == 0)
            {/* no range detected (i.e. no next adjacent VID found), if
              * there are still other VIDs follow in the map then print
              * 'vidDelimiter' */
               if(are_any_vids_set(vidMap))
               {
                  STP_ASSERT((tmp - vidStr) < (int)sizeof(vidStr));
                  rem_len = (MAX_VID_STR_LEN - (vidStr - tmp));
                  snprintf(tmp, rem_len, "%s%n", vidDelimiter, &l);
                  tmp += l;
               }
            }
            else
            {/* the VID range is detected; print last VID in the range, if
              * range size is greater than 1 then print 'rangeDelimiter',
              * otherwise use 'vidDelimiter' */
               STP_ASSERT((tmp - vidStr) < (int)sizeof(vidStr));
               rem_len = (MAX_VID_STR_LEN - (vidStr - tmp));
               snprintf(tmp, rem_len, "%s%d%n",
                       (rangeSize > 1) ? rangeDelimiter : vidDelimiter,
                       vid - 1, &l);
               tmp += l;
               if(are_any_vids_set(vidMap))
               {
                  STP_ASSERT((tmp - vidStr) < (int)sizeof(vidStr));
                  rem_len = (MAX_VID_STR_LEN - (vidStr - tmp));
                  snprintf(tmp, rem_len, "%s%n", vidDelimiter, &l);
                  tmp += l;
               }
            }
            findRange = false;

            /* Format output lines if necessary */
            if((printedLineLen + strlen(vidStr)) > lineLength)
            {
               vty_out(vty, "%s", VTY_NEWLINE);
               vty_out(vty, "%*s", lineIndent, "");
               printedLineLen = 0;
            }
            vty_out(vty, "%s%n", vidStr, &l);
            printedLineLen += l;
            tmp = vidStr;
         }
      }
   }
   return;
}

/**PROC+**********************************************************************
* Name:      print_vid_for_instance
*
* Purpose:   Prints a vidmap for specific instance
*
* Returns:   Number of characters printed.
*
* Params:    inst_id     -> MSTP Instance ID
* **PROC-**********************************************************************/

void
print_vid_for_instance(int inst_id) {

    const struct ovsrec_mstp_instance *mstp_row = NULL;
    const struct ovsrec_bridge *bridge_row = NULL;
    int mstid = 0, vid = 0;

    VID_MAP vidMap;
    clear_vid_map(&vidMap);

    bridge_row = ovsrec_bridge_first(idl);
    if (!bridge_row) {
        vty_out(vty, "No bridge record found%s:%d%s", __FILE__, __LINE__, VTY_NEWLINE);
        assert(0);
        return;
    }

    /* Print VLANS mapped to CIST*/
    if (inst_id == MSTP_CISTID) {
        /* Setting the VID to the bitmap*/
        for (mstid=0; mstid < bridge_row->n_mstp_instances; mstid++) {
            mstp_row = bridge_row->value_mstp_instances[mstid];
            if(mstp_row == NULL) {
                vty_out(vty, "No MSTP record found%s:%d%s", __FILE__, __LINE__, VTY_NEWLINE);
                assert(0);
                return;
            }
            for (vid=0; vid<mstp_row->n_vlans; vid++) {
                set_vid(&vidMap, mstp_row->vlans[vid]->id);
            }
        }
        bit_inverse_vid_map(&vidMap);
        print_vidmap_multiline(&vidMap, MAX_LINE_LEN, MAX_INDENT);
    }

    /* Print VLANS mapped to specific instance*/
    else if (MSTP_VALID_MSTID(inst_id)) {
        /* find the instance id*/
        for (mstid=0; mstid < bridge_row->n_mstp_instances; mstid++) {
            if (bridge_row->key_mstp_instances[mstid] == inst_id) {
                mstp_row = bridge_row->value_mstp_instances[mstid];
                break;
            }
        }

        if(mstp_row == NULL) {
            vty_out(vty, "No MSTP record found%s:%d%s", __FILE__, __LINE__, VTY_NEWLINE);
            return;
        }

        for (vid=0; vid<mstp_row->n_vlans; vid++) {
            set_vid(&vidMap, mstp_row->vlans[vid]->id);
        }
        print_vidmap_multiline(&vidMap, MAX_LINE_LEN, MAX_INDENT);
    }
}

int64_t
get_intf_link_cost(struct ovsrec_port *port) {

    int64_t link_speed = 0;
    const char *bond_status = NULL;
    if(!port) {
        vty_out(vty, "Invalid Input%s:%d%s", __FILE__, __LINE__, VTY_NEWLINE);
        return DEF_LINK_SPEED;
    }

    /* validation for non lag interfaces */
    if(VERIFY_LAG_IFNAME(port->name)) {
        if(!(port->interfaces) && !(port->interfaces[0]->link_speed)) {
            vty_out(vty, "Invalid Input%s:%d%s", __FILE__, __LINE__, VTY_NEWLINE);
            return DEF_LINK_SPEED;
        }
    }

    /* Get link speed from bond_status for lag interfaces */
    if(!VERIFY_LAG_IFNAME(port->name)) {
        bond_status = smap_get(&port->bond_status, PORT_BOND_STATUS_MAP_BOND_SPEED);
        if (bond_status) {
            /* There should only be one speed. */
            link_speed = INTF_TO_MSTP_LINK_SPEED(atoi(bond_status));
        }
    }
    /* Link speed for normal interfaces*/
    else {
        link_speed = INTF_TO_MSTP_LINK_SPEED(port->interfaces[0]->link_speed[0]);
    }

    switch(link_speed)
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
            return DEF_LINK_SPEED;
    }
}
