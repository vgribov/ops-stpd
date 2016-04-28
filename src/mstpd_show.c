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
 *    File               : mstpd_show.c
 *    Description        : MSTP Protocol Debug Show related routines
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
#include "mstp_ovsdb_if.h"
#include "mstp_fsm.h"
#include "mstp_inlines.h"
#include "mstp.h"

/* NOTE: this array is indexed by the values defined
 *       in 'MSTP_ADMIN_POINT_TO_POINT_MAC_e' enum list */
char* const MSTP_ADMIN_PPMAC_s[MSTP_ADMIN_PPMAC_MAX] =
{
   "UNKNOWN",
   "FORCE_TRUE",
   "FORCE_FALSE",
   "AUTO"
};

/* NOTE: this array is indexed by the values defined
 *       in 'MSTP_BPDU_TYPE_e' enum list */
char* const MSTP_BPDU_TYPE_s[MSTP_BPDU_TYPE_MAX] =
{
   "UWN",
   "MST",
   "RST",
   "STP",
   "TCN"
};

/* NOTE: this array is indexed by the values defined
 *       in 'MSTP_PORT_ROLE_e' enum list */
char* const MSTP_PORT_ROLE_s[MSTP_PORT_ROLE_MAX] =
{
   "UNKNOWN",
   "ROOT",
   "ALTERNATE",
   "DESIGNATED",
   "BACKUP",
   "DISABLED",
   "MASTER"
};

/* NOTE: this array is indexed by the values defined
 *       in 'MSTP_INFO_IS_e' enum list */
char* const MSTP_INFO_IS_s[MSTP_INFO_IS_MAX] =
{
   "UNKNOWN",
   "DISABLED",
   "RECEIVED",
   "MINE",
   "AGED",
};

/* NOTE: this array is indexed by the values defined
 *       in 'MSTP_RCVD_INFO_e' enum list */
char* const MSTP_RCVD_INFO_s[MSTP_RCVD_INFO_MAX] =
{
   "UNKNOWN",
   "SUPERIOR_DSGN",
   "REPEATED_DSGN",
   "INFERIOR_DSGN",
   "INFERIOR_ROOT_ALT",
   "OTHER"
};

/* NOTE: this array is indexed by the values defined
 *       in 'MSTP_PTI_STATE_e' enum list */
char* const MSTP_PTI_STATE_s[MSTP_PTI_STATE_MAX] =
{
   "UNKNOWN",
   "ONE_SECOND",
   "TICK"
};

/* NOTE: this array is indexed by the values defined
 *       in 'MSTP_PRX_STATE_e' enum list */
char* const MSTP_PRX_STATE_s[MSTP_PRX_STATE_MAX] =
{
   "UNKNOWN",
   "DISCARD",
   "RECEIVE"
};

/* NOTE: this array is indexed by the values defined
 *       in 'MSTP_PPM_STATE_e' enum list */
char* const MSTP_PPM_STATE_s[MSTP_PPM_STATE_MAX] =
{
   "UNKNOWN",
   "CHECKING_RSTP",
   "SELECTING_STP",
   "SENSING"
};

/* NOTE: this array is indexed by the values defined
 *       in 'MSTP_PTX_STATE_e' enum list */
char* const MSTP_PTX_STATE_s[MSTP_PTX_STATE_MAX] =
{
   "UNKNOWN",
   "TX_INIT",
   "TX_PERIODIC",
   "IDLE",
   "TX_CONFIG",
   "TX_TCN",
   "TX_RSTP"
};

/* NOTE: this array is indexed by the values defined
 *       in 'MSTP_BDM_STATE_e' enum list */
char* const MSTP_BDM_STATE_s[MSTP_BDM_STATE_MAX] =
{
   "UNKNOWN",
   "EDGE",
   "NOT_EDGE",
};

/* NOTE: this array is indexed by the values defined
 *       in 'MSTP_PIM_STATE_e' enum list */
char* const MSTP_PIM_STATE_s[MSTP_PIM_STATE_MAX] =
{
   "UNKNOWN",
   "DISABLED",
   "AGED",
   "UPDATE",
   "CURRENT",
   "RECEIVE",
   "SUPERIOR_DSGN",
   "REPEATED_DSGN",
   "INFERIOR_DSGN",
   "NOT_DSGN",
   "OTHER"
};

/* NOTE: this array is indexed by the values defined
 *       in 'MSTP_PRS_STATE_e' enum list */
char* const MSTP_PRS_STATE_s[MSTP_PRS_STATE_MAX] =
{
   "UNKNOWN",
   "INIT_TREE",
   "ROLE_SELECTION"
};

/* NOTE: this array is indexed by the values defined
 *       in 'MSTP_PRT_STATE_e' enum list */
char* const MSTP_PRT_STATE_s[MSTP_PRT_STATE_MAX] =
{
   /* uninitialized (erroneous) SM state */
   "UNKNOWN",

   /* Disabled Port role transitions */
   "INIT_PORT",
   "DISABLE_PORT",
   "DISABLED_PORT",

   /* Master Port role transitions */
   "MASTER_PORT",
   "MASTER_PROPOSED",
   "MASTER_AGREED",
   "MASTER_SYNCED",
   "MASTER_RETIRED",
   "MASTER_FORWARD",
   "MASTER_LEARN",
   "MASTER_DISCARD",

   /* Root Port role transitions */
   "ROOT_PORT",
   "ROOT_PROPOSED",
   "ROOT_AGREED",
   "ROOT_SYNCED",
   "REROOT",
   "ROOT_FORWARD",
   "ROOT_LEARN",
   "REROOTED",

   /* Designated Port role transitions */
   "DSGN_PORT",
   "DSGN_PROPOSE",
   "DSGN_AGREED",
   "DSGN_SYNCED",
   "DSGN_RETIRED",
   "DSGN_FORWARD",
   "DSGN_LEARN",
   "DSGN_DISCARD",

   /* Alternate and Backup Port role transitions */
   "BLOCK_PORT",
   "ALT_PROPOSED",
   "ALT_AGREED",
   "ALT_PORT",
   "BACKUP_PORT"
};

/* NOTE: this array is indexed by the values defined
 *       in 'MSTP_PST_STATE_e' enum list */
char* const MSTP_PST_STATE_s[MSTP_PST_STATE_MAX] =
{
   "UNKNOWN",
   "DISCARDING",
   "LEARNING",
   "FORWARDING"
};

/* NOTE: this array is indexed by the values defined
 *       in 'MSTP_TCM_STATE_e' enum list */
char* const MSTP_TCM_STATE_s[MSTP_TCM_STATE_MAX] =
{
   "UNKNOWN",
   "INACTIVE",
   "LEARNING",
   "DETECTED",
   "ACTIVE",
   "NOTIFIED_TCN",
   "NOTIFIED_TC",
   "PROPAGATING",
   "ACKNOWLEDGED"
};

static void mstp_showUsage(char *cmdName);
static void mstp_showCommonInfo(void);
static void mstp_showPortNames(LPORT_t lport, bool allPorts);

void rvShowMstp (bool);

static void mstp_showBpduFiltering(void);

/** ======================================================================= **
 *                                                                           *
 *     Global Functions (externed)                                           *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstpShow
 *
 * Purpose:   Display MSTP status/statistics info. This function called
 *            from the Tornado Shell ('windsh').
 *            NOTE: The shell can pass up to ten arguments to a function.
 *                  In fact, the shell always passes exactly ten arguments
 *                  to every function called, passing values of zero for any
 *                  arguments not specified. All user entered parameters are
 *                  being passed as the strings and user input looks something
 *                  like that
 *
 *                  -> mstpShow "msti", "1"
 *
 * Params:    arguments specified as the pointers to the strings
 *
 * Returns:   none
 *
 * Globals:   none
 **PROC-**********************************************************************/
void
mstpShow(char* s1, char* s2, char *s3, char *s4, char* s5,
         char* s6, char* s7, char* s8, char* s9, char* s10)
{
   char *argv[10+2];
   int   argc;
   int   i;

   //argv[0]  = (char*) mstpShowName;
   argv[1]  = s1;
   argv[2]  = s2;
   argv[3]  = s3;
   argv[4]  = s4;
   argv[5]  = s5;
   argv[6]  = s6;
   argv[7]  = s7;
   argv[8]  = s8;
   argv[9]  = s9;
   argv[10] = s10;
   argv[11] = NULL;

   for(i=0, argc=0; i <= 10; i++)
   {
      if(argv[i])
         argc++;
      else
         break;
   }

   mstp_showMain(NULL, argc, argv);
}

/**PROC+**********************************************************************
 * Name:      mstp_showMain
 *
 * Purpose:   Show MSTP status/statistics information.
 *            This function called from 'windsh' and NCL.
 *
 * Params:    ses  ->  terminal session that invoked the command
 *            argc ->  number of command's arguments
 *            argv ->  command's arguments list
 *
 * Returns:   none
 *
 * Globals:   none
 **PROC-**********************************************************************/
void
mstp_showMain(void* ses, int argc, char **argv)
{
   bool usage = false;
   bool unknown = false;

   assert(argc <= 10);

   if(argc == 1)
   {
      usage = true;
      goto end;
   }

   /*-----------------------------------------------------------------------
    * Parse and execute command
    *-----------------------------------------------------------------------*/
   if(argc == 2)
   {/* one argument show commands */
      if(!strcmp(argv[1],"help"))
      {
         usage = true;
         goto end;
      }
      else if(!strcmp(argv[1], "comm"))
      {
         mstp_showCommonInfo();
      }
      else if(!strcmp(argv[1], "imap"))
      {
      }
      else if(!strcmp(argv[1], "vgi"))
      {
      }
      else if(!strcmp(argv[1], "vi"))
      {
      }
      else if(!strcmp(argv[1], "pvgi"))
      {
      }
      else if(!strcmp(argv[1], "pi"))
      {
      }
      else if(!strcmp(argv[1], "fts"))
      {
      }
      else if(!strcmp(argv[1], "pname"))
      {
         mstp_showPortNames(0, true);
      }
      else if(!strcmp(argv[1], "filter"))
      {
         mstp_showBpduFiltering();
      }
      else
         unknown=usage=true;
   }
   else if(argc == 3)
   {/* two arguments show commands */
      if(!strcmp(argv[1], "msti"))
      {
         int mstid = mstp_validateStrMstid(argv[2]);

         if(mstid <= 0)
         {
            printf("wrong MSTI ID %s\n",argv[2]);
            goto end;
         }

      }
      else
         unknown=usage=true;
   }
   else if(argc == 4)
   {/* four arguments show commands */
      if(!strcmp(argv[1], "cist"))
      {
         if(!strcmp(argv[2], "p"))
         {
            int portNum = mstp_validateStrPortNumber(argv[3]);

            if(portNum < 0)
            {
               printf("wrong port number %s\n", argv[3]);
               goto end;
            }

         }
         else
            unknown=usage=true;
      }
      else if(!strcmp(argv[1], "comm"))
      {
         if(!strcmp(argv[2], "p"))
         {
            int portNum = mstp_validateStrPortNumber(argv[3]);

            if(portNum < 0)
            {
               printf("wrong port number %s\n", argv[3]);
               goto end;
            }

         }
         else
            unknown=usage=true;
      }
      else if(!strcmp(argv[1], "pname"))
      {
         if(!strcmp(argv[2], "p"))
         {
            int portNum = mstp_validateStrPortNumber(argv[3]);

            if(portNum < 0)
            {
               printf("wrong port number %s\n", argv[3]);
               goto end;
            }
            mstp_showPortNames(portNum, false);
         }
         else
            unknown=usage=true;
      }
      else if(!strcmp(argv[1], "vlan"))
      {
         if(!strcmp(argv[2], "v"))
         {
            int vid = mstp_validateStrVid(argv[3]);

            if(vid < 0)
            {
               printf("wrong vid %s\n", argv[3]);
               goto end;
            }
         }
         else
            unknown=usage=true;
      }
      else
         unknown=usage=true;
   }
   else if(argc == 5)
   {/* five arguments show commands */
      if(!strcmp(argv[1], "msti"))
      {
         int mstid = mstp_validateStrMstid(argv[2]);

         if(mstid <= 0)
         {
            printf("wrong MSTI ID %s\n",argv[2]);
            goto end;
         }

         if(!strcmp(argv[3], "p"))
         {
            int portNum = mstp_validateStrPortNumber(argv[4]);

            if(portNum < 0)
            {
               printf("wrong port number %s\n", argv[4]);
               goto end;
            }

         }
         else
            unknown=usage=true;
      }
      else
         unknown=usage=true;
   }
   else
      unknown=usage=true;

end:
   if(unknown)
      printf("\n!!!Unknown or incomplete cmd\n");

   if(usage)
      mstp_showUsage(argv[0]);
}

/**PROC+**********************************************************************
 * Name:      mstp_validateStrPortNumber
 *
 * Purpose:   This is helper function used to verify if string contains valid
 *            port number.
 *
 * Params:    portStr -> pointer to the string containing port number
 *
 * Returns:   port number as an integer if it is valid, -1 otherwise
 *
 * Globals:   none
 **PROC-**********************************************************************/
int
mstp_validateStrPortNumber(char *portStr)
{
   bool allDigits = true;
   int   portNum   = -1;
   int   i, len;

   assert(portStr);

   for(i=0,len=strlen(portStr); i < len; i++)
   {
      if(!isdigit((int)portStr[i]))
      {
         allDigits = false;
         break;
      }
   }

   if(allDigits)
   {
      portNum = atoi(portStr);
      portNum = (portNum >=1 && portNum <= MAX_LPORTS) ? portNum : -1;
   }

   return portNum;
}

/**PROC+**********************************************************************
 * Name:      mstp_validateStrMstid
 *
 * Purpose:   This is helper function used to verify if string contains valid
 *            MST Instance Identifier (0..MSTP_MSTID_MAX, 0 is for IST).
 *
 * Params:    mstidStr -> pointer to the string containing MST instance ID
 *
 * Returns:   MST instance ID as an integer if it is valid, -1 otherwise
 *
 * Globals:   none
 **PROC-**********************************************************************/
int
mstp_validateStrMstid(char *mstidStr)
{
   bool allDigits = true;
   int   mstid     = -1;
   int   i, len;

   assert(mstidStr);

   for(i=0,len = strlen(mstidStr); i<len; i++)
   {
      if(!isdigit((int)mstidStr[i]))
      {
         allDigits = false;
         break;
      }
   }

   if(allDigits)
   {
      mstid = atoi(mstidStr);
      mstid = (mstid >=0 && mstid <= MSTP_INSTANCES_MAX) ? mstid : -1;
   }

   return mstid;
}

/**PROC+**********************************************************************
 * Name:      mstp_validateStrVid
 *
 * Purpose:   This is helper function used to verify if string contains valid
 *            VLAN ID.
 *
 * Params:    vidStr -> pointer to the string containing VLAN ID
 *
 * Returns:   VLAN ID as an integer if it is valid, -1 otherwise
 *
 * Globals:   none
 **PROC-**********************************************************************/
int
mstp_validateStrVid(char *vidStr)
{
   bool allDigits = true;
   int   vid       = -1;
   int   i, len;

   assert(vidStr);

   for(i=0,len=strlen(vidStr); i < len; i++)
   {
      if(!isdigit((int)vidStr[i]))
      {
         allDigits = false;
         break;
      }
   }

   if(allDigits)
   {
      vid = atoi(vidStr);
      //vid = IS_VALID_VID(vid) ? vid : -1;
   }

   return vid;
}

/** ======================================================================= **
 *                                                                           *
 *     Static (local to this file) Functions                                 *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_showUsage
 *
 * Purpose:   Show list of all available show commands
 *
 * Params:    cmdName -> show command name
 *
 * Returns:   none
 *
 * Globals:   none
 **PROC-**********************************************************************/
static void
mstp_showUsage(char *cmdName)
{
   printf("\n");

   printf("Usage :\n");
   printf("%s cist [p <p>]        - show info for CIST or CIST's port 'p'\n",
          cmdName);
   printf("%s msti <i> [p <p>]    - show info for MSTI 'i' or MSTI's port 'p'\n",
          cmdName);
   printf("%s comm [p <p>]        - show common info for MST Bridge or port 'p'\n",
          cmdName);
   printf("%s imap                - show VLANs to MSTIs mapping info\n",
         cmdName);
   printf("%s pname [p <p>]       - show port numbers to names mapping\n",
          cmdName);
   printf("%s vlan [v <vid>]      - show VLAN info\n",
          cmdName);
   printf("%s filter              - show BPDU filter control and counters\n",
           cmdName);

   printf("\n");

}

void mstpd_daemon_intf_to_mstp_map_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    mstpd_daemon_intf_to_mstp_map_data_dump(&ds, argc, argv);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}


void
mstpd_daemon_intf_to_mstp_map_data_dump(struct ds *ds, int argc, const char *argv[])
{
    struct iface_data *idp = NULL;
    int i = 0;
    if (argv[1])
    {
        idp = find_iface_data_by_name((char *)argv[1]);
        if (idp)
        {
            ds_put_format(ds, "Interface Name : %s , MSTP Index: %d, L2port : %s\n", idp->name, idp->lport_id, is_port_set(&l2ports,i)?"True":"False");
        }
        else
        {
            ds_put_format(ds, "Interface name is invalid");
        }
        return;
    }
    for (i = 0; i < MAX_ENTRIES_IN_POOL; i++)
    {
        if(idp_lookup[i])
        {
            idp = idp_lookup[i];
            ds_put_format(ds, "Interface Name : %s , MSTP Index: %d, L2port : %s\n", idp->name, i, is_port_set(&l2ports,i)?"True":"False");
        }
    }
}


void mstpd_daemon_cist_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    mstpd_daemon_cist_data_dump(&ds, argc, argv);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

/**PROC+**********************************************************************
 * Name:      mstp_showCistInfo
 *
 * Purpose:   Show status/statistics information for the CIST
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 **PROC-**********************************************************************/
void
mstpd_daemon_cist_data_dump(struct ds *ds, int argc, const char *argv[])
{
   MSTP_CIST_INFO_t             *cistPtr = &mstp_Bridge.CistInfo;
   MSTP_CIST_BRIDGE_PRI_VECTOR_t pri_vec;
   MSTP_BRIDGE_IDENTIFIER_t      bid;
   MSTP_CIST_BRIDGE_TIMES_t      tms;

   ds_put_format(ds, "mstpEnabled       : %s\n", MSTP_ENABLED ? "Yes" : "No");
   ds_put_format(ds, "valid             : %s\n", cistPtr->valid ? "Yes" : "No");
   ds_put_format(ds,"cistRootPortID    : port#=%d, priority=%d\n",
          MSTP_GET_PORT_NUM(cistPtr->rootPortID),
          MSTP_GET_PORT_PRIORITY(cistPtr->rootPortID));
   ds_put_format(ds,"CistBridgeTimes   : ");
   tms = cistPtr->BridgeTimes;
   ds_put_format(ds,"{fwdDelay=%d maxAge=%d messageAge=%d hops=%d}\n",
          tms.fwdDelay,tms.maxAge,tms.messageAge,tms.hops);

   ds_put_format(ds,"cistRootTimes     : ");
   tms = cistPtr->rootTimes;
   ds_put_format(ds,"{fwdDelay=%d maxAge=%d messageAge=%d hops=%d}\n",
          tms.fwdDelay,tms.maxAge,tms.messageAge,tms.hops);
   ds_put_format(ds,"cistRootHelloTime : %d\n", MSTP_CIST_ROOT_HELLO_TIME);
   ds_put_format(ds,"BridgeIdentifier  : ");
   bid = cistPtr->BridgeIdentifier;
   ds_put_format(ds,"{mac=%02x:%02x:%02x:%02x:%02x:%02x priority=%d sysID=%d}\n",
          PRINT_MAC_ADDR(bid.mac_address),
          MSTP_GET_BRIDGE_PRIORITY(bid),
          MSTP_GET_BRIDGE_SYS_ID(bid));

   ds_put_format(ds,"CistBridgePriority:\n");
   pri_vec = cistPtr->BridgePriority;
   ds_put_format(ds,"\trootID      ");
   bid     = pri_vec.rootID;
   ds_put_format(ds,"{mac=%02x:%02x:%02x:%02x:%02x:%02x priority=%d sysID=%d}\n",
          PRINT_MAC_ADDR(bid.mac_address),
          MSTP_GET_BRIDGE_PRIORITY(bid),
          MSTP_GET_BRIDGE_SYS_ID(bid));
   ds_put_format(ds,"\textRootPathCost=%d\n",pri_vec.extRootPathCost);
   ds_put_format(ds,"\trgnRootID   ");
   bid     = pri_vec.rgnRootID;
   ds_put_format(ds,"{mac=%02x:%02x:%02x:%02x:%02x:%02x priority=%d sysID=%d}\n",
          PRINT_MAC_ADDR(bid.mac_address),
          MSTP_GET_BRIDGE_PRIORITY(bid),
          MSTP_GET_BRIDGE_SYS_ID(bid));
   ds_put_format(ds,"\tintRootPathCost=%d\n",pri_vec.intRootPathCost);
   ds_put_format(ds,"\tdsnBridgeID ");
   bid     = pri_vec.dsnBridgeID;
   ds_put_format(ds,"{mac=%02x:%02x:%02x:%02x:%02x:%02x priority=%d sysID=%d}\n",
          PRINT_MAC_ADDR(bid.mac_address),
          MSTP_GET_BRIDGE_PRIORITY(bid),
          MSTP_GET_BRIDGE_SYS_ID(bid));
   ds_put_format(ds,"\tdsnPortID=(%d;%d)\n",
          MSTP_GET_PORT_PRIORITY(pri_vec.dsnPortID),
          MSTP_GET_PORT_NUM(pri_vec.dsnPortID));

   ds_put_format(ds,"cistRootPriority  :\n");
   pri_vec = cistPtr->rootPriority;
   ds_put_format(ds,"\trootID      ");
   bid     = pri_vec.rootID;
   ds_put_format(ds,"{mac=%02x:%02x:%02x:%02x:%02x:%02x priority=%d sysID=%d}\n",
          PRINT_MAC_ADDR(bid.mac_address),
          MSTP_GET_BRIDGE_PRIORITY(bid),
          MSTP_GET_BRIDGE_SYS_ID(bid));
   ds_put_format(ds,"\textRootPathCost=%d\n",pri_vec.extRootPathCost);
   ds_put_format(ds,"\trgnRootID   ");
   bid     = pri_vec.rgnRootID;
   ds_put_format(ds,"{mac=%02x:%02x:%02x:%02x:%02x:%02x priority=%d sysID=%d}\n",
          PRINT_MAC_ADDR(bid.mac_address),
          MSTP_GET_BRIDGE_PRIORITY(bid),
          MSTP_GET_BRIDGE_SYS_ID(bid));
   ds_put_format(ds,"\tintRootPathCost=%d\n",pri_vec.intRootPathCost);
   ds_put_format(ds,"\tdsnBridgeID ");
   bid     = pri_vec.dsnBridgeID;
   ds_put_format(ds,"{mac=%02x:%02x:%02x:%02x:%02x:%02x priority=%d sysID=%d}\n",
          PRINT_MAC_ADDR(bid.mac_address),
          MSTP_GET_BRIDGE_PRIORITY(bid),
          MSTP_GET_BRIDGE_SYS_ID(bid));
   ds_put_format(ds,"\tdsnPortID=(%d;%d)\n",
          MSTP_GET_PORT_PRIORITY(pri_vec.dsnPortID),
          MSTP_GET_PORT_NUM(pri_vec.dsnPortID));
   ds_put_format(ds,"SM states         : PRS=%-13s\n",
          MSTP_PRS_STATE_s[cistPtr->prsState]);
   ds_put_format(ds,"TC Trap Control   : %s", ((cistPtr->tcTrapControl) ?
                                     "true" : "false"));

   ds_put_format(ds,"\n");

}

/**PROC+**********************************************************************
 * Name:      mstp_showCommonInfo
 *
 * Purpose:   Show status/statistics information common for the CIST and
 *            all MSTIs
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 **PROC-**********************************************************************/
static void
mstp_showCommonInfo(void)
{
   int i;

   printf("mstpEnabled        : %s\n", 1 ? "Yes" : "No");
   printf("numOfValidTrees    : %d\n", MSTP_NUM_OF_VALID_TREES);
   printf("ForceVersion       : %s\n",
          (1 == false) ? "0" :
          ((mstp_Bridge.ForceVersion == 0) ? "stpCompatible" :
           ((mstp_Bridge.ForceVersion ==  2) ? "rstp" : "mstp")));
   printf("FwdDelay           : %d\n", mstp_Bridge.FwdDelay);
   printf("TxHoldCount        : %d\n", mstp_Bridge.TxHoldCount);
   printf("MigrateTime        : %d\n", mstp_Bridge.MigrateTime);
   printf("HelloTime          : %d\n", mstp_Bridge.HelloTime);
   printf("maxAge             : %d\n", mstp_Bridge.MaxAge);
   printf("MaxHops            : %d\n", mstp_Bridge.MaxHops);
   printf("BEGIN              : %s\n",
          mstp_Bridge.BEGIN == true ? "True" : "False");
   printf("MstConfigId        : ");
   printf("formatSelector=%d\n",mstp_Bridge.MstConfigId.formatSelector);
   printf("\t\t     configName=%s\n",
          mstp_Bridge.MstConfigId.configName);
   printf("\t\t     revisionLevel=%d\n",ntohs(mstp_Bridge.MstConfigId.revisionLevel));
   printf("\t\t     digest=0x");
   for(i=0; i< MSTP_DIGEST_SIZE; i++)
      printf("%.2X",mstp_Bridge.MstConfigId.digest[i]);

   printf("\n");

}

/**PROC+**********************************************************************
 * Name:      mstpd_daemon_digest_unixctl_list
 *
 * Purpose:   Show MSTP config digest
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 **PROC-**********************************************************************/

void mstpd_daemon_digest_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    mstpd_daemon_digest_data_dump(&ds, argc, argv);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

/**PROC+**********************************************************************
 * Name:      mstpd_daemon_digest_data_dump
 *
 * Purpose:   Show VLANs to MSTIs mapping info
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge, mstp_MstiVidTable
 **PROC-**********************************************************************/
void
mstpd_daemon_digest_data_dump(struct ds *ds, int argc, const char *argv[])
{
   MSTID_t mstid;
   int     i;
   int     indent;
   int     length;

   ds_put_format(ds, "\n");

   ds_put_format(ds, "Digest Value: 0x");
   for(i=0; i< MSTP_DIGEST_SIZE; i++)
      ds_put_format(ds, "%.2X",mstp_Bridge.MstConfigId.digest[i]);
   ds_put_format(ds, "\n\n");

   ds_put_format(ds, "MSTID VGRP# ""MAPPED VIDs\n");
   ds_put_format(ds, "----- ----- %n", &indent);
   ds_put_format(ds, "-------------------------------------------------------"
          "------------%n\n", &length);
   for(mstid = MSTP_CISTID; mstid <= MSTP_INSTANCES_MAX; mstid++)
   {
      if(are_any_vids_set(&mstp_MstiVidTable[mstid]))
      {
         ds_put_format(ds, "%-5d %-5d ", mstid, MSTP_MSTI_INFO(mstid)->vlanGroupNum);
         mstp_printVidMap(&mstp_MstiVidTable[mstid], length, indent);
         ds_put_format(ds, "\n");
      }
   }

   ds_put_format(ds, "\n");

}


/**PROC+**********************************************************************
 * Name:      mstpd_daemon_msti_unixctl_list
 *
 * Purpose:   Show status/statistics information for the given MSTI
 *
 * Params:    mstid -> MST Instance Identifier
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 **PROC-**********************************************************************/

void mstpd_daemon_msti_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    mstpd_daemon_msti_data_dump(&ds, argc, argv);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

/**PROC+**********************************************************************
 * Name:      mstpd_daemon_msti_data_dump
 *
 * Purpose:   Show status/statistics information for the given MSTI
 *
 * Params:    mstid -> MST Instance Identifier
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 **PROC-**********************************************************************/
void
mstpd_daemon_msti_data_dump(struct ds *ds, int argc, const char *argv[])
{
   uint16_t mstid = 0;
   mstid = atoi(argv[1]);
   MSTP_MSTI_INFO_t             *mstiPtr;
   MSTP_MSTI_BRIDGE_PRI_VECTOR_t pri_vec;
   MSTP_BRIDGE_IDENTIFIER_t      bid;
   MSTP_MSTI_BRIDGE_TIMES_t      tms;

   assert(MSTP_VALID_MSTID(mstid));

   mstiPtr = mstp_Bridge.MstiInfo[mstid];
   if(mstiPtr == NULL)
   {
      ds_put_format(ds,"MST Instance %d does not exist\n", mstid);
      return;
   }

   ds_put_format(ds,"\n");

   ds_put_format(ds,"mstpEnabled       : %s\n", MSTP_ENABLED ? "Yes" : "No");
   ds_put_format(ds,"valid             : %s\n", mstiPtr->valid ? "Yes" : "No");
   ds_put_format(ds,"vlanGroupNum      : %d\n", mstiPtr->vlanGroupNum);
   ds_put_format(ds,"mstiRootPortID    : port#=%d, priority=%d\n",
          MSTP_GET_PORT_NUM(mstiPtr->rootPortID),
          MSTP_GET_PORT_PRIORITY(mstiPtr->rootPortID));
   ds_put_format(ds,"MstiBridgeTimes   : ");
   tms = mstiPtr->BridgeTimes;
   ds_put_format(ds,"{hops=%d}\n", tms.hops);

   ds_put_format(ds,"mstiRootTimes     : ");
   tms = mstiPtr->rootTimes;
   ds_put_format(ds,"{hops=%d}\n", tms.hops);

   ds_put_format(ds,"BridgeIdentifier  : ");
   bid = mstiPtr->BridgeIdentifier;
   ds_put_format(ds,"{mac=%02x:%02x:%02x:%02x:%02x:%02x priority=%d sysID=%d}\n",
          PRINT_MAC_ADDR(bid.mac_address),
          MSTP_GET_BRIDGE_PRIORITY(bid),
          MSTP_GET_BRIDGE_SYS_ID(bid));

   ds_put_format(ds,"MstiBridgePriority:\n");
   pri_vec = mstiPtr->BridgePriority;
   ds_put_format(ds,"\trgnRootID   ");
   bid     = pri_vec.rgnRootID;
   ds_put_format(ds,"{mac=%02x:%02x:%02x:%02x:%02x:%02x priority=%d sysID=%d}\n",
          PRINT_MAC_ADDR(bid.mac_address),
          MSTP_GET_BRIDGE_PRIORITY(bid),
          MSTP_GET_BRIDGE_SYS_ID(bid));
   ds_put_format(ds,"\tintRootPathCost=%d\n",pri_vec.intRootPathCost);
   ds_put_format(ds,"\tdsnBridgeID ");
   bid     = pri_vec.dsnBridgeID;
   ds_put_format(ds,"{mac=%02x:%02x:%02x:%02x:%02x:%02x priority=%d sysID=%d}\n",
          PRINT_MAC_ADDR(bid.mac_address),
          MSTP_GET_BRIDGE_PRIORITY(bid),
          MSTP_GET_BRIDGE_SYS_ID(bid));
   ds_put_format(ds,"\tdsnPortID=(%d;%d)\n",
          MSTP_GET_PORT_PRIORITY(pri_vec.dsnPortID),
          MSTP_GET_PORT_NUM(pri_vec.dsnPortID));

   ds_put_format(ds,"mstiRootPriority  :\n");
   pri_vec = mstiPtr->rootPriority;
   ds_put_format(ds,"\trgnRootID   ");
   bid     = pri_vec.rgnRootID;
   ds_put_format(ds,"{mac=%02x:%02x:%02x:%02x:%02x:%02x priority=%d sysID=%d}\n",
          PRINT_MAC_ADDR(bid.mac_address),
          MSTP_GET_BRIDGE_PRIORITY(bid),
          MSTP_GET_BRIDGE_SYS_ID(bid));
   ds_put_format(ds,"\tintRootPathCost=%d\n",pri_vec.intRootPathCost);
   ds_put_format(ds,"\tdsnBridgeID ");
   bid     = pri_vec.dsnBridgeID;
   ds_put_format(ds,"{mac=%02x:%02x:%02x:%02x:%02x:%02x priority=%d sysID=%d}\n",
          PRINT_MAC_ADDR(bid.mac_address),
          MSTP_GET_BRIDGE_PRIORITY(bid),
          MSTP_GET_BRIDGE_SYS_ID(bid));
   ds_put_format(ds,"\tdsnPortID=(%d;%d)\n",
          MSTP_GET_PORT_PRIORITY(pri_vec.dsnPortID),
          MSTP_GET_PORT_NUM(pri_vec.dsnPortID));
   ds_put_format(ds,"SM states         : PRS=%-13s\n",
          MSTP_PRS_STATE_s[mstiPtr->prsState]);
   ds_put_format(ds,"\nTotal BPDU Filters activated: %d\n",
          mstp_countBpduFilters());

   ds_put_format(ds,"TC Trap Control   : %s", ((mstiPtr->tcTrapControl) ?
                                     "true" : "false"));

   ds_put_format(ds,"\n");

}

/**PROC+**********************************************************************
 * Name:      mstpd_daemon_cist_port_unixctl_list
 *
 * Purpose:   Show status/statistics information for the given port
 *            on the CIST
 *
 * Params:    portNum -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 **PROC-**********************************************************************/

void mstpd_daemon_cist_port_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    mstpd_daemon_cist_port_data_dump(&ds, argc, argv);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

/**PROC+**********************************************************************
 * Name:      mstpd_daemon_cist_port_data_dump
 *
 * Purpose:   Show status/statistics information for the given port
 *            on the CIST
 *
 * Params:    portNum -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 **PROC-**********************************************************************/
void
mstpd_daemon_cist_port_data_dump(struct ds *ds, int argc, const char *argv[])
{
   MSTP_CIST_PORT_INFO_t *port;
   struct iface_data *idp = find_iface_data_by_name((char *)argv[1]);
   if (idp == NULL)
   {
      return;
   }
   LPORT_t portNum = idp->lport_id;

   assert(IS_VALID_LPORT(portNum));

   port = mstp_Bridge.CistInfo.CistPortInfo[portNum];
   if(port == NULL)
   {
      ds_put_format(ds,"CistPortInfo[%d]=NULL\n", portNum);
   }
   else
   {
      MSTP_CIST_DESIGNATED_PRI_VECTOR_t pri_vec;
      MSTP_BRIDGE_IDENTIFIER_t          bid;
      MSTP_CIST_MSG_TIMES_t             m_tms;
      MSTP_CIST_BRIDGE_TIMES_t          b_tms;

      ds_put_format(ds,"SM Timers     : ");
      ds_put_format(ds,"fdWhile=%d ", port->fdWhile);
      ds_put_format(ds,"rrWhile=%d ", port->rrWhile);
      ds_put_format(ds,"rbWhile=%d ", port->rbWhile);
      ds_put_format(ds,"tcWhile=%d ", port->tcWhile);
      ds_put_format(ds,"rcvdInfoWhile=%d\n", port->rcvdInfoWhile);

      ds_put_format(ds,"Perf Params   : ");
      {
         char buf[11];

         if(port->InternalPortPathCost == 0)
            strcpy(buf, "Auto");
         ds_put_format(ds,"InternalPortPathCost=%s, useCfgPathCost=%c\n",
                buf, port->useCfgPathCost ? 'T' : 'F');
      }

      ds_put_format(ds,"Per-Port Vars :\n");
      ds_put_format(ds,"   portId=(%d;%d) ",
             MSTP_GET_PORT_PRIORITY(port->portId),
             MSTP_GET_PORT_NUM(port->portId));
      ds_put_format(ds,"infoIs=%s ", MSTP_INFO_IS_s[port->infoIs]);
      ds_put_format(ds,"rcvdInfo=%s\n", MSTP_RCVD_INFO_s[port->rcvdInfo]);
      ds_put_format(ds,"   role=%s ", MSTP_PORT_ROLE_s[port->role]);
      ds_put_format(ds,"selectedRole=%s\n", MSTP_PORT_ROLE_s[port->selectedRole]);

      /*------------------------------------------------------------------
       * cistDesignatedTimes
       *------------------------------------------------------------------*/
      ds_put_format(ds,"   cistDesignatedTimes=");
      b_tms = port->designatedTimes;
      ds_put_format(ds,"{fwdDelay=%d maxAge=%d messageAge=%d hops=%d}\n",
             b_tms.fwdDelay,b_tms.maxAge,b_tms.messageAge,b_tms.hops);

      /*------------------------------------------------------------------
       * cistMsgTimes
       *------------------------------------------------------------------*/
      ds_put_format(ds,"   cistMsgTimes       =");
      m_tms = port->msgTimes;
      ds_put_format(ds,"{fwdDelay=%d maxAge=%d messageAge=%d hops=%d helloTime=%d}\n",
             m_tms.fwdDelay,m_tms.maxAge,m_tms.messageAge,
             m_tms.hops,m_tms.helloTime);

      /*------------------------------------------------------------------
       * cistPortTimes
       *------------------------------------------------------------------*/
      ds_put_format(ds,"   cistPortTimes      =");
      m_tms = port->portTimes;
      ds_put_format(ds,"{fwdDelay=%d maxAge=%d messageAge=%d hops=%d helloTime=%d}\n",
             m_tms.fwdDelay,m_tms.maxAge,m_tms.messageAge,
             m_tms.hops, m_tms.helloTime);

      /*------------------------------------------------------------------
       * cistDesignatedPriority
       *------------------------------------------------------------------*/
      ds_put_format(ds,"   cistDesignatedPriority=\n");
      pri_vec = port->designatedPriority;
      ds_put_format(ds,"      {rootID     =");
      bid     = pri_vec.rootID;
      ds_put_format(ds,"(%02x:%02x:%02x:%02x:%02x:%02x;%d;%d) : ",
             PRINT_MAC_ADDR(bid.mac_address),
             MSTP_GET_BRIDGE_PRIORITY(bid),
             MSTP_GET_BRIDGE_SYS_ID(bid));
      ds_put_format(ds,"extRootPathCost=%d :\n",pri_vec.extRootPathCost);
      ds_put_format(ds,"       rgnRootID  =");
      bid     = pri_vec.rgnRootID;
      ds_put_format(ds,"(%02x:%02x:%02x:%02x:%02x:%02x;%d;%d) : ",
             PRINT_MAC_ADDR(bid.mac_address),
             MSTP_GET_BRIDGE_PRIORITY(bid),
             MSTP_GET_BRIDGE_SYS_ID(bid));
      ds_put_format(ds,"intRootPathCost=%d :\n",pri_vec.intRootPathCost);
      ds_put_format(ds,"       dsnBridgeID=");
      bid     = pri_vec.dsnBridgeID;
      ds_put_format(ds,"(%02x:%02x:%02x:%02x:%02x:%02x;%d;%d} : ",
             PRINT_MAC_ADDR(bid.mac_address),
             MSTP_GET_BRIDGE_PRIORITY(bid),
             MSTP_GET_BRIDGE_SYS_ID(bid));
      ds_put_format(ds,"dsnPortID=(%d;%d)}\n",
             MSTP_GET_PORT_PRIORITY(pri_vec.dsnPortID),
             MSTP_GET_PORT_NUM(pri_vec.dsnPortID));

      /*------------------------------------------------------------------
       * cistMsgPriority
       *------------------------------------------------------------------*/
      ds_put_format(ds,"   cistMsgPriority=\n");
      pri_vec = port->msgPriority;
      ds_put_format(ds,"      {rootID     =");
      bid     = pri_vec.rootID;
      ds_put_format(ds,"(%02x:%02x:%02x:%02x:%02x:%02x;%d;%d} : ",
             PRINT_MAC_ADDR(bid.mac_address),
             MSTP_GET_BRIDGE_PRIORITY(bid),
             MSTP_GET_BRIDGE_SYS_ID(bid));
      ds_put_format(ds,"extRootPathCost=%d :\n",pri_vec.extRootPathCost);
      ds_put_format(ds,"       rgnRootID  =");
      bid     = pri_vec.rgnRootID;
      ds_put_format(ds,"(%02x:%02x:%02x:%02x:%02x:%02x;%d;%d) : ",
             PRINT_MAC_ADDR(bid.mac_address),
             MSTP_GET_BRIDGE_PRIORITY(bid),
             MSTP_GET_BRIDGE_SYS_ID(bid));
      ds_put_format(ds,"intRootPathCost=%d :\n",pri_vec.intRootPathCost);
      ds_put_format(ds,"       dsnBridgeID=");
      bid     = pri_vec.dsnBridgeID;
      ds_put_format(ds,"(%02x:%02x:%02x:%02x:%02x:%02x;%d;%d) : ",
             PRINT_MAC_ADDR(bid.mac_address),
             MSTP_GET_BRIDGE_PRIORITY(bid),
             MSTP_GET_BRIDGE_SYS_ID(bid));
      ds_put_format(ds,"dsnPortID=(%d;%d)}\n",
             MSTP_GET_PORT_PRIORITY(pri_vec.dsnPortID),
             MSTP_GET_PORT_NUM(pri_vec.dsnPortID));

      /*------------------------------------------------------------------
       * cistPortPriority
       *------------------------------------------------------------------*/
      ds_put_format(ds,"   cistPortPriority=\n");
      pri_vec = port->portPriority;
      ds_put_format(ds,"      {rootID     =");
      bid     = pri_vec.rootID;
      ds_put_format(ds,"(%02x:%02x:%02x:%02x:%02x:%02x;%d;%d} : ",
             PRINT_MAC_ADDR(bid.mac_address),
             MSTP_GET_BRIDGE_PRIORITY(bid),
             MSTP_GET_BRIDGE_SYS_ID(bid));
      ds_put_format(ds,"extRootPathCost=%d\n",pri_vec.extRootPathCost);
      ds_put_format(ds,"       rgnRootID  =");
      bid     = pri_vec.rgnRootID;
      ds_put_format(ds,"(%02x:%02x:%02x:%02x:%02x:%02x;%d;%d) : ",
             PRINT_MAC_ADDR(bid.mac_address),
             MSTP_GET_BRIDGE_PRIORITY(bid),
             MSTP_GET_BRIDGE_SYS_ID(bid));
      ds_put_format(ds,"intRootPathCost=%d\n",pri_vec.intRootPathCost);
      ds_put_format(ds,"       dsnBridgeID=");
      bid     = pri_vec.dsnBridgeID;
      ds_put_format(ds,"(%02x:%02x:%02x:%02x:%02x:%02x;%d;%d) : ",
             PRINT_MAC_ADDR(bid.mac_address),
             MSTP_GET_BRIDGE_PRIORITY(bid),
             MSTP_GET_BRIDGE_SYS_ID(bid));
      ds_put_format(ds,"dsnPortID=(%d;%d)}\n",
             MSTP_GET_PORT_PRIORITY(pri_vec.dsnPortID),
             MSTP_GET_PORT_NUM(pri_vec.dsnPortID));
      ds_put_format(ds,"Flags    : "
             "FWD=%d FWDI=%d LRN=%d  LRNI=%d  PRPSD=%d PRPSI=%d RROOT=%d "
             "RSELT=%d  SELTD=%d\n"
             "           "
             "AGR=%d AGRD=%d SYNC=%d SYNCD=%d TCPRP=%d UPDT=%d  "
             "RCVTC=%d RCVMSG=%d CMSTR=%d\n",
             MSTP_CIST_PORT_IS_BIT_SET(port->bitMap,MSTP_CIST_PORT_FORWARD),
             MSTP_CIST_PORT_IS_BIT_SET(port->bitMap,MSTP_CIST_PORT_FORWARDING),
             MSTP_CIST_PORT_IS_BIT_SET(port->bitMap,MSTP_CIST_PORT_LEARN),
             MSTP_CIST_PORT_IS_BIT_SET(port->bitMap,MSTP_CIST_PORT_LEARNING),
             MSTP_CIST_PORT_IS_BIT_SET(port->bitMap,MSTP_CIST_PORT_PROPOSED),
             MSTP_CIST_PORT_IS_BIT_SET(port->bitMap,MSTP_CIST_PORT_PROPOSING),
             MSTP_CIST_PORT_IS_BIT_SET(port->bitMap,MSTP_CIST_PORT_RE_ROOT),
             MSTP_CIST_PORT_IS_BIT_SET(port->bitMap,MSTP_CIST_PORT_RESELECT),
             MSTP_CIST_PORT_IS_BIT_SET(port->bitMap,MSTP_CIST_PORT_SELECTED),
             MSTP_CIST_PORT_IS_BIT_SET(port->bitMap,MSTP_CIST_PORT_AGREE),
             MSTP_CIST_PORT_IS_BIT_SET(port->bitMap,MSTP_CIST_PORT_AGREED),
             MSTP_CIST_PORT_IS_BIT_SET(port->bitMap,MSTP_CIST_PORT_SYNC),
             MSTP_CIST_PORT_IS_BIT_SET(port->bitMap,MSTP_CIST_PORT_SYNCED),
             MSTP_CIST_PORT_IS_BIT_SET(port->bitMap,MSTP_CIST_PORT_TC_PROP),
             MSTP_CIST_PORT_IS_BIT_SET(port->bitMap,MSTP_CIST_PORT_UPDT_INFO),
             MSTP_CIST_PORT_IS_BIT_SET(port->bitMap,MSTP_CIST_PORT_RCVD_TC),
             MSTP_CIST_PORT_IS_BIT_SET(port->bitMap,MSTP_CIST_PORT_RCVD_MSG),
             MSTP_CIST_PORT_IS_BIT_SET(port->bitMap,
                                                MSTP_CIST_PORT_CHANGED_MASTER));
      ds_put_format(ds,"SM states: PIM=%-13s PRT=%-12s PST=%-10s TCM=%-12s\n",
             MSTP_PIM_STATE_s[port->pimState],
             MSTP_PRT_STATE_s[port->prtState],
             MSTP_PST_STATE_s[port->pstState],
             MSTP_TCM_STATE_s[port->tcmState]);

   }
}

/**PROC+**********************************************************************
 * Name:      mstpd_daemon_msti_port_unixctl_list
 *
 * Purpose:   Show status/statistics information for the given port
 *            on the given MSTI
 *
 * Params:    mstid   -> MST Instance Identifier
 *            portNum -> logical port number
 *
 * Returns:   none
 *
 * Globals:   none
 **PROC-**********************************************************************/

void mstpd_daemon_msti_port_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    mstpd_daemon_msti_port_data_dump(&ds, argc, argv);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

/**PROC+**********************************************************************
 * Name:      mstpd_daemon_msti_port_data_dump
 *
 * Purpose:   Show status/statistics information for the given port
 *            on the given MSTI
 *
 * Params:    mstid   -> MST Instance Identifier
 *            portNum -> logical port number
 *
 * Returns:   none
 *
 * Globals:   none
 **PROC-**********************************************************************/
void
mstpd_daemon_msti_port_data_dump(struct ds *ds, int argc, const char *argv[])
{
   MSTID_t mstid = atoi(argv[1]);
   LPORT_t portNum = 0;
   MSTP_MSTI_INFO_t      *mstiPtr;
   MSTP_MSTI_PORT_INFO_t *port;
   struct iface_data *idp = find_iface_data_by_name((char *)argv[2]);
   if (idp == NULL)
   {
      return;
   }
   portNum = idp->lport_id;

   assert(MSTP_VALID_MSTID(mstid));
   assert(IS_VALID_LPORT(portNum));

   mstiPtr = mstp_Bridge.MstiInfo[mstid];
   if(mstiPtr == NULL)
   {
      ds_put_format(ds,"MST Instance %d does not exist\n", mstid);
      return;
   }

   port = mstiPtr->MstiPortInfo[portNum];
   if(port == NULL)
   {
      ds_put_format(ds,"MstiPortInfo[%d]=NULL\n", portNum);
   }
   else
   {
      MSTP_BRIDGE_IDENTIFIER_t          bid;
      MSTP_MSTI_DESIGNATED_PRI_VECTOR_t pri_vec;
      MSTP_MSTI_BRIDGE_TIMES_t          b_tms;

      ds_put_format(ds,"\n");
      ds_put_format(ds,"SM Timers     : ");
      ds_put_format(ds,"fdWhile=%d ", port->fdWhile);
      ds_put_format(ds,"rrWhile=%d ", port->rrWhile);
      ds_put_format(ds,"rbWhile=%d ", port->rbWhile);
      ds_put_format(ds,"tcWhile=%d ", port->tcWhile);
      ds_put_format(ds,"rcvdInfoWhile=%d\n", port->rcvdInfoWhile);

      ds_put_format(ds,"Perf Params   : ");

      ds_put_format(ds,"InternalPortPathCost=%d, useCfgPathCost=%c\n",
             port->InternalPortPathCost, port->useCfgPathCost ? 'T' : 'F');

      ds_put_format(ds,"Per-Port Vars :\n");
      ds_put_format(ds,"   portId=(%d;%d) ",
             MSTP_GET_PORT_PRIORITY(port->portId),
             MSTP_GET_PORT_NUM(port->portId));
      ds_put_format(ds,"infoIs=%s ", MSTP_INFO_IS_s[port->infoIs]);
      ds_put_format(ds,"rcvdInfo=%s\n", MSTP_RCVD_INFO_s[port->rcvdInfo]);
      ds_put_format(ds,"   role=%s ", MSTP_PORT_ROLE_s[port->role]);
      ds_put_format(ds,"selectedRole=%s\n", MSTP_PORT_ROLE_s[port->selectedRole]);

      /*------------------------------------------------------------------
       * mstiDesignatedTimes
       *------------------------------------------------------------------*/
      ds_put_format(ds,"   mstiDesignatedTimes=");
      b_tms = port->designatedTimes;
      ds_put_format(ds,"{hops=%d}\n", b_tms.hops);

      /*------------------------------------------------------------------
       * mstiMsgTimes
       *------------------------------------------------------------------*/
      ds_put_format(ds,"   mstiMsgTimes       =");
      b_tms = port->msgTimes;
      ds_put_format(ds,"{hops=%d}\n", b_tms.hops);

      /*------------------------------------------------------------------
       * mstiPortTimes
       *------------------------------------------------------------------*/
      ds_put_format(ds,"   mstiPortTimes      =");
      b_tms = port->portTimes;
      ds_put_format(ds,"{hops=%d}\n", b_tms.hops);

      /*------------------------------------------------------------------
       * mstiDesignatedPriority
       *------------------------------------------------------------------*/
      ds_put_format(ds,"   mstiDesignatedPriority=\n");
      pri_vec = port->designatedPriority;
      ds_put_format(ds,"      {rgnRootID  =");
      bid     = pri_vec.rgnRootID;
      ds_put_format(ds,"(%02x:%02x:%02x:%02x:%02x:%02x;%d;%d) : ",
             PRINT_MAC_ADDR(bid.mac_address),
             MSTP_GET_BRIDGE_PRIORITY(bid),
             MSTP_GET_BRIDGE_SYS_ID(bid));
      ds_put_format(ds,"intRootPathCost=%d :\n",pri_vec.intRootPathCost);
      ds_put_format(ds,"       dsnBridgeID=");
      bid     = pri_vec.dsnBridgeID;
      ds_put_format(ds,"(%02x:%02x:%02x:%02x:%02x:%02x;%d;%d} : ",
             PRINT_MAC_ADDR(bid.mac_address),
             MSTP_GET_BRIDGE_PRIORITY(bid),
             MSTP_GET_BRIDGE_SYS_ID(bid));
      ds_put_format(ds,"dsnPortID=(%d;%d)}\n",
             MSTP_GET_PORT_PRIORITY(pri_vec.dsnPortID),
             MSTP_GET_PORT_NUM(pri_vec.dsnPortID));

      /*------------------------------------------------------------------
       * mstiMsgPriority
       *------------------------------------------------------------------*/
      ds_put_format(ds,"   mstiMsgPriority=\n");
      pri_vec = port->msgPriority;
      ds_put_format(ds,"      {rgnRootID  =");
      bid     = pri_vec.rgnRootID;
      ds_put_format(ds,"(%02x:%02x:%02x:%02x:%02x:%02x;%d;%d) : ",
             PRINT_MAC_ADDR(bid.mac_address),
             MSTP_GET_BRIDGE_PRIORITY(bid),
             MSTP_GET_BRIDGE_SYS_ID(bid));
      ds_put_format(ds,"intRootPathCost=%d :\n",pri_vec.intRootPathCost);
      ds_put_format(ds,"       dsnBridgeID=");
      bid     = pri_vec.dsnBridgeID;
      ds_put_format(ds,"(%02x:%02x:%02x:%02x:%02x:%02x;%d;%d} : ",
             PRINT_MAC_ADDR(bid.mac_address),
             MSTP_GET_BRIDGE_PRIORITY(bid),
             MSTP_GET_BRIDGE_SYS_ID(bid));
      ds_put_format(ds,"dsnPortID=(%d;%d)}\n",
             MSTP_GET_PORT_PRIORITY(pri_vec.dsnPortID),
             MSTP_GET_PORT_NUM(pri_vec.dsnPortID));

      /*------------------------------------------------------------------
       * mstiPortPriority
       *------------------------------------------------------------------*/
      ds_put_format(ds,"   mstiPortPriority=\n");
      pri_vec = port->portPriority;
      ds_put_format(ds,"      {rgnRootID  =");
      bid     = pri_vec.rgnRootID;
      ds_put_format(ds,"(%02x:%02x:%02x:%02x:%02x:%02x;%d;%d) : ",
             PRINT_MAC_ADDR(bid.mac_address),
             MSTP_GET_BRIDGE_PRIORITY(bid),
             MSTP_GET_BRIDGE_SYS_ID(bid));
      ds_put_format(ds,"intRootPathCost=%d :\n",pri_vec.intRootPathCost);
      ds_put_format(ds,"       dsnBridgeID=");
      bid     = pri_vec.dsnBridgeID;
      ds_put_format(ds,"(%02x:%02x:%02x:%02x:%02x:%02x;%d;%d} : ",
             PRINT_MAC_ADDR(bid.mac_address),
             MSTP_GET_BRIDGE_PRIORITY(bid),
             MSTP_GET_BRIDGE_SYS_ID(bid));
      ds_put_format(ds,"dsnPortID=(%d;%d)}\n",
             MSTP_GET_PORT_PRIORITY(pri_vec.dsnPortID),
             MSTP_GET_PORT_NUM(pri_vec.dsnPortID));
      ds_put_format(ds,"Flags    : "
             "FWD=%d FWDI=%d LRN=%d  LRNI=%d  PRPSD=%d PRPSI=%d RROOT=%d"
             " RSELT=%d SELTD=%d\n"
             "           AGR=%d AGRD=%d SYNC=%d SYNCD=%d TCPRP=%d UPDT=%d"
             "  RCVTC=%d RCVMSG=%d\n"
             "           MSTR=%d       MSTRD=%d\n",
             MSTP_MSTI_PORT_IS_BIT_SET(port->bitMap,MSTP_MSTI_PORT_FORWARD),
             MSTP_MSTI_PORT_IS_BIT_SET(port->bitMap,MSTP_MSTI_PORT_FORWARDING),
             MSTP_MSTI_PORT_IS_BIT_SET(port->bitMap,MSTP_MSTI_PORT_LEARN),
             MSTP_MSTI_PORT_IS_BIT_SET(port->bitMap,MSTP_MSTI_PORT_LEARNING),
             MSTP_MSTI_PORT_IS_BIT_SET(port->bitMap,MSTP_MSTI_PORT_PROPOSED),
             MSTP_MSTI_PORT_IS_BIT_SET(port->bitMap,MSTP_MSTI_PORT_PROPOSING),
             MSTP_MSTI_PORT_IS_BIT_SET(port->bitMap,MSTP_MSTI_PORT_RE_ROOT),
             MSTP_MSTI_PORT_IS_BIT_SET(port->bitMap,MSTP_MSTI_PORT_RESELECT),
             MSTP_MSTI_PORT_IS_BIT_SET(port->bitMap,MSTP_MSTI_PORT_SELECTED),
             MSTP_MSTI_PORT_IS_BIT_SET(port->bitMap,MSTP_MSTI_PORT_AGREE),
             MSTP_MSTI_PORT_IS_BIT_SET(port->bitMap,MSTP_MSTI_PORT_AGREED),
             MSTP_MSTI_PORT_IS_BIT_SET(port->bitMap,MSTP_MSTI_PORT_SYNC),
             MSTP_MSTI_PORT_IS_BIT_SET(port->bitMap,MSTP_MSTI_PORT_SYNCED),
             MSTP_MSTI_PORT_IS_BIT_SET(port->bitMap,MSTP_MSTI_PORT_TC_PROP),
             MSTP_MSTI_PORT_IS_BIT_SET(port->bitMap,MSTP_MSTI_PORT_UPDT_INFO),
             MSTP_MSTI_PORT_IS_BIT_SET(port->bitMap,MSTP_MSTI_PORT_RCVD_TC),
             MSTP_MSTI_PORT_IS_BIT_SET(port->bitMap,MSTP_MSTI_PORT_RCVD_MSG),
             MSTP_MSTI_PORT_IS_BIT_SET(port->bitMap,MSTP_MSTI_PORT_MASTER),
             MSTP_MSTI_PORT_IS_BIT_SET(port->bitMap,MSTP_MSTI_PORT_MASTERED));
      ds_put_format(ds,"SM states: PIM=%-13s PRT=%-12s PST=%-10s TCM=%-12s\n",
             MSTP_PIM_STATE_s[port->pimState],
             MSTP_PRT_STATE_s[port->prtState],
             MSTP_PST_STATE_s[port->pstState],
             MSTP_TCM_STATE_s[port->tcmState]);

      ds_put_format(ds,"\n");

   }
}


/**PROC+**********************************************************************
 * Name:      mstpd_daemon_comm_port_unixctl_list
 *
 * Purpose:   Show status/statistics information for the given port
 *            that is common for the CIST and all MSTIs
 *
 * Params:    portNum -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 **PROC-**********************************************************************/

void mstpd_daemon_comm_port_unixctl_list(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    mstpd_daemon_comm_port_data_dump(&ds, argc, argv);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

/**PROC+**********************************************************************
 * Name:      mstpd_daemon_comm_port_data_dump
 *
 * Purpose:   Show status/statistics information for the given port
 *            that is common for the CIST and all MSTIs
 *
 * Params:    portNum -> logical port number
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 **PROC-**********************************************************************/
void
mstpd_daemon_comm_port_data_dump(struct ds *ds, int argc, const char *argv[])
{
   LPORT_t portNum = atoi(argv[1]);
   MSTP_COMM_PORT_INFO_t *port;

   assert(IS_VALID_LPORT(portNum));

   port = mstp_Bridge.PortInfo[portNum];
   if(port == NULL)
   {
      ds_put_format(ds,"PortInfo[%d]=NULL\n", portNum);
   }
   else
   {

      ds_put_format(ds,"\n");
      ds_put_format(ds,"SM Timers     : mdelayWhile=%d helloWhen=%d\n",
             port->mdelayWhile, port->helloWhen);

      {
         char buf[11];

         if(port->ExternalPortPathCost == 0)
            strcpy(buf, "Auto");
         ds_put_format(ds,"Perf Params   : HelloTime=%d, ExternalPortPathCost=%s\n",
                port->HelloTime, buf);
         ds_put_format(ds,"                useGlobalHelloTime=%d, useCfgPathCost=%c\n",
                port->useGlobalHelloTime, port->useCfgPathCost ? 'T' : 'F');
      }

      ds_put_format(ds,"Per-Port Vars : txCount=%d, adminPointToPointMAC=%s\n",
             port->txCount,
             MSTP_ADMIN_PPMAC_s[port->adminPointToPointMAC]);

      ds_put_format(ds,"Flags         : "
             "ENABLED=%d      RESTRICT_ROLE=%d RESTRICT_TCN=%d\n"
             "                "
             "ADMIN_EDGE=%d   AUTO_EDGE=%d     OPER_EDGE=%d     OPER_PPM=%d\n"
             "                "
             "RCVD_BPDU=%d    RCVD_TCN=%d      RCVD_TC_ACK=%d   RCVD_RSTP=%d\n"
             "                "
             "RCVD_STP=%d     RCVD_INTERNAL=%d INFO_INTERNAL=%d\n"
             "                "
             "TC_ACK=%d       NEW_INFO=%d      NEW_INFO_MSTI=%d\n"
             "                "
             "SEND_RSTP=%d    MCHECK=%d        FDB_FLUSH=%d\n",
             MSTP_COMM_PORT_IS_BIT_SET(port->bitMap,MSTP_PORT_PORT_ENABLED),
             MSTP_COMM_PORT_IS_BIT_SET(port->bitMap,MSTP_PORT_RESTRICTED_ROLE),
             MSTP_COMM_PORT_IS_BIT_SET(port->bitMap,MSTP_PORT_RESTRICTED_TCN),
             MSTP_COMM_PORT_IS_BIT_SET(port->bitMap,MSTP_PORT_ADMIN_EDGE_PORT),
             MSTP_COMM_PORT_IS_BIT_SET(port->bitMap,MSTP_PORT_AUTO_EDGE),
             MSTP_COMM_PORT_IS_BIT_SET(port->bitMap,MSTP_PORT_OPER_EDGE),
             MSTP_COMM_PORT_IS_BIT_SET(port->bitMap,
                                       MSTP_PORT_OPER_POINT_TO_POINT_MAC),
             MSTP_COMM_PORT_IS_BIT_SET(port->bitMap,MSTP_PORT_RCVD_BPDU),
             MSTP_COMM_PORT_IS_BIT_SET(port->bitMap,MSTP_PORT_RCVD_TCN),
             MSTP_COMM_PORT_IS_BIT_SET(port->bitMap,MSTP_PORT_TC_ACK),
             MSTP_COMM_PORT_IS_BIT_SET(port->bitMap,MSTP_PORT_RCVD_RSTP),
             MSTP_COMM_PORT_IS_BIT_SET(port->bitMap,MSTP_PORT_RCVD_STP),
             MSTP_COMM_PORT_IS_BIT_SET(port->bitMap,MSTP_PORT_RCVD_INTERNAL),
             MSTP_COMM_PORT_IS_BIT_SET(port->bitMap,MSTP_PORT_INFO_INTERNAL),
             MSTP_COMM_PORT_IS_BIT_SET(port->bitMap,MSTP_PORT_TC_ACK),
             MSTP_COMM_PORT_IS_BIT_SET(port->bitMap,MSTP_PORT_NEW_INFO),
             MSTP_COMM_PORT_IS_BIT_SET(port->bitMap,MSTP_PORT_NEW_INFO_MSTI),
             MSTP_COMM_PORT_IS_BIT_SET(port->bitMap,MSTP_PORT_SEND_RSTP),
             MSTP_COMM_PORT_IS_BIT_SET(port->bitMap,MSTP_PORT_MCHECK),
             MSTP_COMM_PORT_IS_BIT_SET(port->bitMap,MSTP_PORT_FDB_FLUSH));

      ds_put_format(ds,"Per-Port SMs  : PTI=%-10s PRX=%-7s PTX=%-11s PPM=%-13s\n"
             "                BDM=%-9s\n",
             MSTP_PTI_STATE_s[port->ptiState],
             MSTP_PRX_STATE_s[port->prxState],
             MSTP_PTX_STATE_s[port->ptxState],
             MSTP_PPM_STATE_s[port->ppmState],
             MSTP_BDM_STATE_s[port->bdmState]);

      ds_put_format(ds,"rcvdSelfSentPkt : %s\n", port->rcvdSelfSentPkt ? "Yes" : "No");

      ds_put_format(ds,"BPDU Filter     : %s\n",
             (MSTP_COMM_IS_BPDU_FILTER(portNum) ? "Yes" : "No"));
      ds_put_format(ds,"BPDU Protection : %s\n",
             (MSTP_COMM_PORT_IS_BPDU_PROTECTED(portNum) ? "Yes" : "No"));
      ds_put_format(ds,"inBpduError     : %s\n", port->inBpduError ? "Yes" : "No");
      ds_put_format(ds,"inBpduError     : %s\n", port->inBpduError ? "Yes" : "No");
      ds_put_format(ds,"Errant BPDUs    : %d\n", MSTP_COMM_ERRANT_BPDU_COUNT(portNum));
      ds_put_format(ds,"dropBPDUs       : %s\n", port->dropBpdu ? "Yes" : "No" );
      ds_put_format(ds,"\n");

   }
}

/**PROC+**********************************************************************
 * Name:      mstp_showPortNames
 *
 * Purpose:   Show logical port numbers to names mapping
 *
 * Params:    lport    -> logical port number to show info for
 *            allPorts -> whether to show info for all ports
 *
 * Returns:   none
 *
 * Globals:
 **PROC-**********************************************************************/
static void
mstp_showPortNames(LPORT_t lport, bool allPorts)
{
   char pname[PORTNAME_LEN];
   int  lp;

   if(allPorts)
   {
      printf("\n");
      printf(" Port   Port\n");
      printf(" Number Name\n");
      printf(" ------ --------\n");

      for (lp = 1; lp <= MAX_LPORTS; lp++)
      {
         intf_get_port_name(lp, pname);
         if(strlen(pname))
            printf(" %-6d %s\n", lp, pname);
      }
   }
   else
   {
      assert(IS_VALID_LPORT(lport));
      intf_get_port_name(lport, pname);
      if(strlen(pname)){
          printf("\n");
          printf(" Port   Port\n");
          printf(" Number Name\n");
          printf(" ------ --------\n");
          printf(" %-6d %s\n", lport, pname);
      }else{
          printf("wrong port number %i\n", lport);
      }
   }
}

/**PROC+**********************************************************************
 * Name:      mstp_showBpduFiltering
 *
 * Purpose:   Show info about filtering for all lports.  If nothing has been
 *            initialized, only the column headers are displayed.
 *            Sees if future SNMP Trap is needed.
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 **PROC-**********************************************************************/
static void
mstp_showBpduFiltering(void)
{
   MSTP_CIST_PORT_INFO_t *cistPortPtr = NULL;
   int      lport;

   printf("\n                  Errant    \n"
            " Port   Filter    Rx Count  \n"
            " ----   ------    --------  \n" );
   for(lport=1 ; lport <= MAX_LPORTS ; ++lport)
   {
      if((cistPortPtr = MSTP_CIST_PORT_PTR(lport)))
      {
         printf(" %3d    %4s    %9d   \n",
                       (int) lport,
                       (MSTP_COMM_IS_BPDU_FILTER(lport) ? "Yes" : "No"),
                cistPortPtr->dbgCnts.errantBpduCnt);
      }
   }
   printf("\n");
}
