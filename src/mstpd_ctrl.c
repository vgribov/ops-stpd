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

/***************************************************************************
 *    File               : mstpd_ctrl.c
 *    Description        : MSTP Protocol thread main entry point
 ***************************************************************************/
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
#include <ctype.h>
#include <util.h>
#include <openvswitch/vlog.h>
#include <assert.h>

#include <mqueue.h>
#include "mstp.h"
#include "mstp_cmn.h"
#include "mstp_recv.h"
#include "mstp_ovsdb_if.h"
#include "mstp_inlines.h"
#include "mstp_fsm.h"

VLOG_DEFINE_THIS_MODULE(mstpd_ctrl);

/*---------------------------------------------------------------------------
 * Local functions prototypes (forward declarations)
 *---------------------------------------------------------------------------*/
void mstp_checkDynReconfigChanges(void);


void
print_payload(unsigned char *payload);

/************************************************************************
 * Global Variables
 ************************************************************************/
static int mstp_init_done = false;
int mstpd_shutdown = 0;

PORT_MAP l2ports;
PORT_MAP ports_up;
PORT_MAP temp_l2ports;
bool mstp_enable = false;

/* Message Queue for MSTPD main protocol thread */
mqueue_t mstpd_main_rcvq;


/* epoll FD for MSTP PDU RX. */
int epfd = -1;

/* Max number of events returned by epoll_wait().
 * This number is arbitrary.  It's only used for
 * sizing the epoll events data structure. */
#define MAX_EVENTS 64

/* MSTP filter
 *
 * Berkeley Packet Filter to receive MSTP BPDU from interfaces.
 *
 * MSTP: "ether dst 01:80:c2:00:00:00"
 *
 *    tcpdump -dd "(ether dst 01:80:c2:00:00:00)"
 *
 * low-level BPF filter code:
 * (000) ld       [2]          ; load 4 bytes from Dst MAC offset 2
 * (001) jeq      #0xc2000000  ; compare 4 bytes, move to next instruction if equal
 * (002) ldh      [0]          ; load 4 bytes from Dst MAC offset 0
 * (003) jeq      #0x0180      ; compare 2 bytes, move to next instruction if equal
 * (004) ret      #65535       ; return 65535 bytes of packet
 * (005) ret      #0           ; return 0
 *
 * { 0x20, 0, 0, 0x00000002 },
 * { 0x15, 0, 3, 0xc2000000 },
 * { 0x28, 0, 0, 0x00000000 },
 * { 0x15, 0, 1, 0x00000180 },
 * { 0x6, 0,  0, 0x0000ffff },
 * { 0x6, 0,  0, 0x00000000 }
 */

#define MSTPD_FILTER_F \
    { 0x20, 0, 0, 0x00000002 }, \
    { 0x15, 0, 3, 0xc2000000 }, \
    { 0x28, 0, 0, 0x00000000 }, \
    { 0x15, 0, 1, 0x00000180 }, \
    { 0x6, 0, 0, 0x0000ffff }, \
    { 0x6, 0, 0, 0x00000000 }

static struct sock_filter mstpd_filter_f[] = { MSTPD_FILTER_F };
static struct sock_fprog mstpd_fprog = {
    .filter = mstpd_filter_f,
    .len = sizeof(mstpd_filter_f) / sizeof(struct sock_filter)
};

MAC_ADDRESS stp_multicast = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x00};


/************************************************************************
 * Event Receiver Functions
 ************************************************************************/
int
mstp_init_event_rcvr(void)
{
    int rc;

    rc = mqueue_init(&mstpd_main_rcvq);
    if (rc) {
        VLOG_ERR("Failed MSTP main receive queue init: %s",
                 strerror(rc));
    }

    return rc;
} /* mstp_init_event_rcvr */

int
mstp_free_event_queue(void)
{
    int rc;
    int free_msg_count = 0;

    rc = mqueue_free(&mstpd_main_rcvq,&free_msg_count);
    if (rc) {
        VLOG_ERR("Failed MSTP main free queue: %s",
                 strerror(rc));
    }
    else
    {
        VLOG_INFO("MSTP FREE_MESSAGE Queue count : %d", free_msg_count);
    }

    return rc;
} /* mstp_init_event_rcvr */

int
mstpd_send_event(mstpd_message *pmsg)
{
    int rc;

    rc = mqueue_send(&mstpd_main_rcvq, pmsg);
    if (rc) {
        VLOG_ERR("Failed to send to MSTP main receive queue: %s",
                 strerror(rc));
    }

    return rc;
} /* mstpd_send_event */

mstpd_message *
mstpd_wait_for_next_event(void)
{
    int rc;
    mstpd_message *pmsg = NULL;

    rc = mqueue_wait(&mstpd_main_rcvq, (void **)(void *)&pmsg);
    if (!rc) {
        pmsg->msg = (void *)(pmsg+1);
    } else {
        VLOG_ERR("MSTP main receive queue wait error, rc=%s",
                 strerror(rc));
    }

    return pmsg;
} /* mstpd_wait_for_next_event */

void
mstpd_event_free(mstpd_message *pmsg)
{
    if (pmsg != NULL) {
        free(pmsg);
    }
} /* mstpd_event_free */

/************************************************************************
 * MSTP PDU Send and Receive Functions
 ************************************************************************/
void *
mstpd_rx_pdu_thread(void *data)
{
    VLOG_DBG("MSTP RX thread");
    /* Detach thread to avoid memory leak upon exit. */
    pthread_detach(pthread_self());

    epfd = epoll_create1(0);
    if (epfd == -1) {
        VLOG_ERR("Failed to create epoll object.  rc=%d", errno);
        return NULL;
    }

    for (;;) {
        int n;
        int nfds;
        struct epoll_event events[MAX_EVENTS];

        if (mstpd_shutdown) {
           break;
        }

        nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);

        if (nfds < 0) {
            VLOG_ERR("epoll_wait returned error %s", strerror(errno));
            break;
        } else {
            VLOG_DBG("epoll_wait returned, nfds=%d", nfds);
        }

        for (n = 0; n < nfds; n++) {
            int count;
            int clientlen;
            struct sockaddr_ll clientaddr;
            mstpd_message *pmsg;
            int total_msg_size;
            MSTP_RX_PDU  *pkt_event;

            struct iface_data *idp = NULL;
            idp = (struct iface_data *)events[n].data.ptr;
            if (idp == NULL) {
                VLOG_ERR("Interface data missing for epoll event!");
                continue;
            } else {
                VLOG_DBG("epoll event #%d: events flags=0x%x, port=%d, sock=%d",n, events[n].events, idp->lport_id, idp->pdu_sockfd);
            }
            if (idp->pdu_registered == false) {
                /* Most likely just a race condition. */
                continue;
            }

            total_msg_size = sizeof(mstpd_message) + sizeof(MSTP_RX_PDU);

            pmsg = xzalloc(total_msg_size);
            pmsg->msg_type = e_mstpd_rx_bpdu;
            pkt_event = (MSTP_RX_PDU *)(pmsg+1);

            clientlen = sizeof(clientaddr);
            count = recvfrom(idp->pdu_sockfd, (void *)pkt_event->data,
                             MAX_MSTP_BPDU_PKT_SIZE, 0,
                             (struct sockaddr *)&clientaddr,
                             (unsigned int *)&clientlen);
            if (count < 0) {
                /* General socket error. */
                VLOG_ERR("Read failed, fd=%d: errno=%s",
                         idp->pdu_sockfd, strerror(errno));
                free(pmsg);
                continue;

            } else if (!count) {
                /* Socket is closed.  Get out. */
                VLOG_ERR("socket=%d closed", idp->pdu_sockfd);
                free(pmsg);
                continue;

            } else if (count <= MAX_MSTP_BPDU_PKT_SIZE) {
                VLOG_DBG("MSTP BPDU Send Event, count = %d ",count);
                pkt_event->pktLen = count;
                pkt_event->lport = idp->lport_id;
                print_payload(pkt_event->data);
                mstpd_send_event(pmsg);
            }
        } /* for nfds */
    } /* for(;;) */


    return NULL;
} /* mstpd_rx_pdu_thread */

/*
 * TODO: need to move registering reserved mcast addr with socket to common utils/repo
 */

int
register_stp_mcast_addr(int lport)
{
    int rc;
    int sockfd;
    struct sockaddr_ll addr;
    struct epoll_event event;
    struct iface_data *idp = NULL;
    int if_idx = 0;

    idp = find_iface_data_by_index(lport);
    if (idp == NULL) {
        VLOG_ERR("Failed to find interface data for register mcast addr! "
                 "lport=%d", lport);
        return -1;
    }
    if ((sockfd = socket(PF_PACKET, SOCK_RAW, 0)) < 0) {
        rc = errno;
        VLOG_ERR("Failed to open datagram socket rc=%s",
                 strerror(rc));
        return -1;
    }
    if_idx = if_nametoindex(idp->name);
    if (if_idx == 0) {
        VLOG_ERR("Error getting ifindex for port %d (if_name=%s)!",
                lport, idp->name);
        return -1;
    }


    rc = setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER,
                    &mstpd_fprog, sizeof(mstpd_fprog));
    if (rc < 0) {
        VLOG_ERR("Failed to attach socket filter rc=%s",
                  strerror(rc));
        close(sockfd);
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = if_idx;
    addr.sll_protocol = htons(ETH_P_802_2); /* 802.2 frames */

    rc = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0) {
        VLOG_ERR("Failed to bind socket to addr rc=%s",
                 strerror(rc));
        close(sockfd);
        return -1;
    }
    /* Save sockfd information in interface data. */
    idp->pdu_sockfd = sockfd;
    idp->pdu_registered = true;

    event.events = EPOLLIN;
    event.data.ptr = (void *)idp;

    rc = epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &event);
    if (rc == 0) {
        VLOG_DBG("Registered sockfd %d with epoll loop.",
                 sockfd);
    } else {
        VLOG_ERR("Failed to register sockfd with epoll "
                 "loop.  err=%s", strerror(errno));
        close(sockfd);
        return -1;
    }
    VLOG_DBG("Registered Socket Successfully!!! : %s",idp->name);

    return sockfd;
} /* register_stp_mcast_addr */

void
deregister_stp_mcast_addr(int lport)
{
    int rc;
    struct iface_data *idp = NULL;

    /* Find the interface data first. */
    idp = find_iface_data_by_index(lport);

    if (idp == NULL) {
        VLOG_ERR("Failed to find interface data for deregister mcast addr! "
                "lport=%d", lport);
        return;
    }
    if (idp->pdu_registered != true) {
        VLOG_ERR("Deregistering for mcast addr when not registered? "
                "port=%s", idp->name);
        return;
    }


    rc = epoll_ctl(epfd, EPOLL_CTL_DEL, idp->pdu_sockfd, NULL);
    if (rc == 0) {
        VLOG_DBG("Deregistered sockfd %d with epoll loop.",
                 idp->pdu_sockfd);
    } else {
        VLOG_ERR("Failed to deregister sockfd with epoll "
                 "loop.  err=%s", strerror(errno));
    }

    close(idp->pdu_sockfd);
    idp->pdu_sockfd = 0;
    idp->pdu_registered = false;

} /* deregister_stp_mcast_addr */


/************************************************************************
 * MSTP Protocol Thread
 ************************************************************************/
void *
mstpd_protocol_thread(void *arg)
{
    VLOG_DBG("MSTP Protocol thread");
    mstpd_message *pmsg;
    mstp_lport_state_change *state;
    mstp_lport_add *l2port_add;
    mstp_lport_delete *l2port_delete;
    mstp_vlan_add *vlan_add;
    mstp_vlan_delete *vlan_delete;
    mstp_admin_status *status;
    MSTP_RX_PDU *pkt;
    bool informDB = TRUE;
    uint32_t vlan = 0;
    uint32_t lport = 0;
    char port[PORTNAME_LEN] = {0};

    /* Detach thread to avoid memory leak upon exit. */
    pthread_detach(pthread_self());
    clear_port_map(&ports_up);
    clear_port_map(&l2ports);
    clear_port_map(&temp_l2ports);
    mstp_Bridge.ForceVersion = MSTP_PROTOCOL_VERSION_ID_MST;
    mstpInitialInit();

    VLOG_DBG("%s : waiting for events in the main loop", __FUNCTION__);

    /*******************************************************************
     * The main receive loop.
     *******************************************************************/
    while (1) {

        pmsg = mstpd_wait_for_next_event();
        informDB = TRUE;

        if (mstpd_shutdown) {
            break;
        }

        if (!pmsg) {
            VLOG_ERR("MSTPD protocol: Received NULL event!");
            continue;
        }

        switch (pmsg->msg_type)
        {
            case e_mstpd_global_config:
                update_mstp_global_config(pmsg);
                VLOG_DBG("Received a Global Config Update");
                break;

            case e_mstpd_cist_config:
                update_mstp_cist_config(pmsg);
                VLOG_DBG("Received a CIST config Update");
                break;

            case e_mstpd_cist_port_config:
                update_mstp_cist_port_config(pmsg);
                VLOG_DBG("Received a CIST Port config Update");
                break;

            case e_mstpd_msti_config:
                update_mstp_msti_config(pmsg);
                VLOG_DBG("Received a MSTI config Update");
                break;

            case e_mstpd_msti_port_config:
                update_mstp_msti_port_config(pmsg);
                VLOG_DBG("Received a MSTI Port config Update");
                break;

            case e_mstpd_msti_config_delete:
                delete_mstp_msti_config(pmsg);
                VLOG_DBG("Received a MSTI config Update");
                break;
            case e_mstpd_vlan_add:
                vlan = 0;
                VLOG_DBG("%s: Received VLAN Add Event", __FUNCTION__);
                vlan_add = (mstp_vlan_add *)pmsg->msg;
                vlan = vlan_add->vid;
                VLOG_DBG("Received an VLAN Add event: %d",vlan);
                handle_vlan_add_in_mstp_config(vlan);
                break;
            case e_mstpd_vlan_delete:
                vlan = 0;
                VLOG_DBG("%s: Received VLAN Delete Event", __FUNCTION__);
                vlan_delete = (mstp_vlan_delete *)pmsg->msg;
                vlan = vlan_delete->vid;
                VLOG_DBG("Received an VLAN Delete event: %d",vlan);
                break;
            case e_mstpd_lport_add:
                VLOG_DBG("%s : Recieved lport add event", __FUNCTION__);
                lport = 0;
                l2port_add = (mstp_lport_add *)pmsg->msg;
                lport = l2port_add->lportindex;
                memset(port,0,PORTNAME_LEN);
                set_port(&l2ports,lport);
                intf_get_port_name(lport,port);
                update_port_entry_in_cist_mstp_instances(port,e_mstpd_lport_add);
                update_port_entry_in_msti_mstp_instances(port,e_mstpd_lport_add);
                update_mstp_on_lport_add(lport);
                if (MSTP_ENABLED)
                {
                    /*trying to register a socket*/
                    if (register_stp_mcast_addr(lport) != -1)
                    {
                        mstp_addLport(lport);
                        if(!is_lport_down(lport))
                        {
                            SPEED_DPLX    ports_cfg = {0};
                            intf_get_lport_speed_duplex(lport,&ports_cfg);
                            mstp_portAutoDetectParamsSet(lport, &ports_cfg);
                            mstp_portEnable(lport);
                        }
                    }
                    else
                    {
                        /* Unable to register a socket, making a note of the port so that
                         * we can try to re-attempt in timer tick operation*/
                        set_port(&temp_l2ports,lport);
                    }
                }
                break;
            case e_mstpd_lport_delete:
                VLOG_DBG("%s : Recieved lport delete event", __FUNCTION__);
                lport = 0;
                memset(port,0,PORTNAME_LEN);
                l2port_delete = (mstp_lport_delete *)pmsg->msg;
                lport = l2port_delete->lportindex;
                strncpy(port,l2port_delete->lportname,PORTNAME_LEN);
                VLOG_DBG("Received an l2port delete event : %d",lport);
                clear_port(&l2ports,lport);
                update_port_entry_in_cist_mstp_instances(port,e_mstpd_lport_delete);
                update_port_entry_in_msti_mstp_instances(port,e_mstpd_lport_delete);
                if (MSTP_ENABLED)
                {
                    deregister_stp_mcast_addr(lport);
                    mstp_removeLport(lport);
                }
                break;
            case e_mstpd_lport_up:
            case e_mstpd_lport_down:
                /***********************************************************
                 * Msg from OVSDB interface for lports.
                 ***********************************************************/
                if (pmsg->msg_type == e_mstpd_lport_up)
                {
                    uint16_t lport = 0;
                    SPEED_DPLX    ports_cfg = {0};
                    state = (mstp_lport_state_change *)pmsg->msg;
                    lport = state->lportindex;
                    intf_get_lport_speed_duplex(lport,&ports_cfg);
                    if(MSTP_ENABLED)
                    {
                        MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);

                        if(commPortPtr)
                        {
                            /*------------------------------------------------------------
                             * inform MSTP about 'Up' event for the port
                             *------------------------------------------------------------*/
                            mstp_portAutoDetectParamsSet(lport, &ports_cfg);
                            mstp_portEnable(lport);
                        }
                    }
                    else
                    {
                        /*---------------------------------------------------------------
                         * MSTP is disabled, propagate port 'Up' state throughout
                         * the system
                         *---------------------------------------------------------------*/
                        mstp_noStpPropagatePortUpState(lport);
                    }

                }
                else if (pmsg->msg_type == e_mstpd_lport_down)
                {
                    uint16_t lport = 0;
                    state = (mstp_lport_state_change *)pmsg->msg;
                    lport = state->lportindex;
                    if(MSTP_ENABLED)
                    {
                        MSTP_COMM_PORT_INFO_t *commPortPtr = MSTP_COMM_PORT_PTR(lport);
                        if(commPortPtr)
                        {
                            /*------------------------------------------------------------
                             * MSTP is enabled, inform it about 'Down' event for the port
                             *------------------------------------------------------------*/
                            mstp_portDisable(lport);
                        }
                    }
                    else
                    {
                        /*---------------------------------------------------------------
                         * MSTP is disabled, propagate port 'Down' state throughout
                         * the system
                         *---------------------------------------------------------------*/
                        mstp_noStpPropagatePortDownState(lport);
                    }

                }
                break;
            case e_mstpd_admin_status:
                VLOG_DBG("%s : Admin Status Update", __FUNCTION__);
                status = (mstp_admin_status *)pmsg->msg;
                if (status->status == true)
                {
                    mstp_enable = true;
                    uint16_t port = 0;
                    for (port = find_first_port_set(&l2ports);
                            port > 0 && port <= MAX_LPORTS;
                            port = find_next_port_set(&l2ports, port))
                    {
                        /*Trying to register a socket*/
                        if(register_stp_mcast_addr(port) != -1)
                        {
                            if(is_port_set(&temp_l2ports,port))
                            {
                                clear_port(&temp_l2ports,port);
                            }
                        }
                        else
                        {
                            /*Unable to register a socket, making a note of the port so that
                             * we can try to re-attempt in timer tick operation*/
                            set_port(&temp_l2ports,port);
                        }
                    }
                }
                else
                {
                    mstp_enable = false;
                    uint16_t port = 0;
                    for (port = find_first_port_set(&l2ports);
                            port > 0 && port <= MAX_LPORTS;
                            port = find_next_port_set(&l2ports, port))
                    {
                        deregister_stp_mcast_addr(port);
                    }

                }
                mstp_adminStatusUpdate(mstp_enable);
                break;
            case e_mstpd_timer:
                /***********************************************************
                 * Msg from MSTP timers.
                 ***********************************************************/
                if (MSTP_ENABLED && are_any_ports_set(&temp_l2ports))
                {
                    uint16_t lport = 0;
                    for (lport = find_first_port_set(&temp_l2ports);
                            lport > 0 && lport <= MAX_LPORTS;
                            lport = find_next_port_set(&temp_l2ports, lport))
                    {
                        /* Try to register a socket, clear the port if successful*/
                        if (register_stp_mcast_addr(lport) != -1)
                        {
                            mstp_addLport(lport);
                            if(!is_lport_down(lport))
                            {
                                SPEED_DPLX    ports_cfg = {0};
                                intf_get_lport_speed_duplex(lport,&ports_cfg);
                                mstp_portAutoDetectParamsSet(lport, &ports_cfg);
                                mstp_portEnable(lport);
                            }
                            clear_port(&temp_l2ports,lport);
                        }
                    }
                }
                if(MSTP_ENABLED)
                {
                    mstp_processTimerTickEvent();
                }
                VLOG_DBG("%s : Recieved one sec timer tick event", __FUNCTION__);
                break;
            case e_mstpd_rx_bpdu:
                pkt = (MSTP_RX_PDU *)pmsg->msg;
                /***********************************************************
                 * Packet has arrived through interface socket.
                 ************************************************************/
                VLOG_DBG("%s : MSTP BPDU Packet arrived from interface socket",
                        __FUNCTION__);
                if(MSTP_ENABLED)
                {
                    MSTP_PKT_TYPE_t pktType;
                    pktType = mstp_decodeBpdu(pkt);
                    VLOG_DBG("%d : MSTP BPDU Packet arrived from interface socket", pktType);
                    switch (pktType) {
                        case MSTP_UNAUTHORIZED_BPDU_DATA_PKT:
                            mstp_processUnauthorizedBpdu(pkt, BPDU_PROTECTION);
                            break;

                        case MSTP_ERRANT_PROTOCOL_DATA_PKT:
                            mstp_errantProtocolData(pkt, BPDU_FILTER);
                            break;

                        case MSTP_PROTOCOL_DATA_PKT:
                            mstp_protocolData(pkt);
                            informDB = FALSE; /*Call already made in mstp_protocolData*/
                            break;

                        case MSTP_INVALID_PKT:
                            break;

                        default:
                            STP_ASSERT(0);
                            break;
                    }
                }
                break;
            default:
                VLOG_ERR("%s : message from unknown sender",
                     __FUNCTION__);
        }

        if (informDB) {
            mstp_informDBOnPortStateChange(pmsg->msg_type);
        }
        mstp_checkDynReconfigChanges();

        mstpd_event_free(pmsg);

    } /* while loop */

    return NULL;
} /* mstpd_protocol_thread */

/************************************************************************
 * Initialization & main functions
 ************************************************************************/
int
mmstp_init(u_long  first_time)
{
    int status = 0;

    if (first_time != true) {
        VLOG_ERR("Cannot handle revival from dead");
        status = -1;
        goto end;
    }

    if (mstp_init_done == true) {
        VLOG_WARN("Already initialized");
        status = -1;
        goto end;
    }

    /* Initialize MSTP main task event receiver queue. */
    if (mstp_init_event_rcvr()) {
        VLOG_ERR("Failed to initialize event receiver.");
        status = -1;
        goto end;
    }

    mstp_init_done  = true;

end:
    return status;
} /* mmstp_init */


/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_payload(unsigned char *payload)
{
    unsigned char *ethhead;
    char log[200];
    ethhead = payload;
    if (ethhead != NULL)
    {
        sprintf(log,"Destination MAC address: "
                "%02x:%02x:%02x:%02x:%02x:%02x"
                " Source MAC address: "
                "%02x:%02x:%02x:%02x:%02x:%02x\n",
                ethhead[0],ethhead[1],ethhead[2],
                ethhead[3],ethhead[4],ethhead[5],
                ethhead[6],ethhead[7],ethhead[8],
                ethhead[9],ethhead[10],ethhead[11]);
    }
    VLOG_DBG("Packet Format : %s",log);
    return;
}

/**PROC+**********************************************************************
 * Name:      mstp_processTimerTickEvent
 *
 * Purpose:   MSTP timer tick processing routine
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
mstp_processTimerTickEvent()
{
   MSTP_COMM_PORT_INFO_t *commPortPtr;
   LPORT_t                lport;
   char  lport_name[PORTNAME_LEN];

   if(MSTP_ENABLED == false)
   {
      /*---------------------------------------------------------------------
       * This function can be called when MSTP is disabled, e.g. session task
       * disabled the protocol while the timer was running. So if we still have
       * 'mstp_CB.timerMsg' allocated then free it and set pointer to NULL.
       *---------------------------------------------------------------------*/
      return;
   }
   /*------------------------------------------------------------------------
    * run Port Timers state machine for every active Port
    *------------------------------------------------------------------------*/
   for(lport = 1; lport <= MAX_LPORTS; lport++)
   {
      commPortPtr = MSTP_COMM_PORT_PTR(lport);
      if(commPortPtr)
      {
         /*We should not be proceeding for timer tick state machine
          * when interface is not registered for socket,
          * which means interface is not ready at this point of time.*/
         if(is_port_set(&temp_l2ports,lport))
         {
             VLOG_INFO("Skipping Timer State machine since interface: %d failed to register a socket",lport);
             continue;
         }

        /*--------------------------------------------------------------------
         * Check for pending STP Traps to be sent out
         *-------------------------------------------------------------------*/
         if(commPortPtr->trapPending == true)
         {
            assert(commPortPtr->trapThrottleTimer > 0);
            commPortPtr->trapThrottleTimer--;
            if(commPortPtr->trapThrottleTimer == 0)
            {
#ifdef OPS_MSTP_TODO
               mstp_sendErrantBpduTrap(lport);
#endif /*OPS_MSTP_TODO*/
               commPortPtr->trapPending = false;
            }
         }
         mstp_ptiSm(lport);

        /*--------------------------------------------------------------------
         * Decrement time to reenable timer for Bpdu Protection (if running)
         *-------------------------------------------------------------------*/
         if(commPortPtr->reEnableTimer > 0)
         {
            commPortPtr->reEnableTimer--;
            if(commPortPtr->reEnableTimer == 0)
            {
               enable_or_disable_port(lport, true);
               intf_get_port_name(lport,lport_name);
               VLOG_DBG("port %s - BPDU protection auto-reenable timer expired.",lport_name);
            }
         }
      }
   }
}

/** ======================================================================= **
 *                                                                           *
 *     Static (local to this file) Functions                                 *
 *                                                                           *
 ** ======================================================================= **/

/**PROC+**********************************************************************
 * Name:      mstp_checkDynReconfigChanges
 *
 * Purpose:   Re-initialize MSTP Entity as specified by the assertion of
 *            'BEGIN' in the state machine specification.
 *            NOTE: as per P802.1D/D1 the protocol re-initialization is
 *                  required if one of the following parameters is modified:
 *                  a) Force Protocol Version
 *                  b) Bridge Identifier Priority (CIST | MSTI)
 *                  c) Port Identifier Priority (CIST | MSTI)
 *                  d) Port Path Cost (CIST | MSTI)
 *                  (P802.1D/D1 17.13)
 *                  In the current MSTP implementation the following dynamic
 *                  reconfiguration changes also cause MSTP re-initialization:
 *                  - MstConfigId (configName, revisionLevel, digest)
 *                  - 'restrictedRole' per-port parameter change
 *
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
mstp_checkDynReconfigChanges(void)
{
   if(MSTP_ENABLED == false)
   {
      return;
   }

   if((MSTP_DYN_RECONFIG_CHANGE == false))
   {
      return;
   }

   MSTP_DYN_CFG_PRINTF("!DYN RECONFIG: %s", "start");
   Spanning = false;

   /*------------------------------------------------------------------------
    * Remove from the queue all pending MSTP messages to DB
    *------------------------------------------------------------------------*/
   mstp_clearMstpToOthersMessageQueue();
   /*------------------------------------------------------------------------
    * clear portmaps used to keep track of lports MSTP has told DB they are
    * forwarding or blocked (used to escape message flooding when MSTP
    * ports transitioning states on multiple Spanning Trees).
    *------------------------------------------------------------------------*/
   clear_port_map(&MSTP_FWD_LPORTS);
   clear_port_map(&MSTP_BLK_LPORTS);

   /*---------------------------------------------------------------------
    * clear in-memory data used by MSTP
    *---------------------------------------------------------------------*/
   mstp_clearProtocolData();
   Spanning = false;
   mstp_config_reinit();


   /*------------------------------------------------------------------------
    * clear global boolean flags - used as triggers for MSTP re-initialization
    *------------------------------------------------------------------------*/
   MSTP_DYN_RECONFIG_CHANGE  = false;

   MSTP_DYN_CFG_PRINTF("!DYN RECONFIG: %s", "end");
}

/**PROC+**********************************************************************
 * Name:      update_mstp_global_config
 *
 * Purpose:   Update MSTP global data structures
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/

void update_mstp_global_config(mstpd_message *pmsg)
{
    struct mstp_global_config *global_config = NULL;
    global_config = (mstp_global_config *)pmsg->msg;

    if(memcmp(mstp_Bridge.MstConfigId.configName, global_config->config_name,
                MSTP_MST_CONFIG_NAME_LEN))
    {
        memset(mstp_Bridge.MstConfigId.configName, 0, MSTP_MST_CONFIG_NAME_LEN);
        memcpy(mstp_Bridge.MstConfigId.configName, global_config->config_name,
                MSTP_MST_CONFIG_NAME_LEN);
        if (MSTP_ENABLED)
        {
            MSTP_DYN_RECONFIG_CHANGE = TRUE;
        }
    }
    if(mstp_Bridge.MstConfigId.revisionLevel != global_config->config_revision)
    {
        mstp_Bridge.MstConfigId.revisionLevel = global_config->config_revision;
        if (MSTP_ENABLED)
        {
            MSTP_DYN_RECONFIG_CHANGE = TRUE;
        }
    }
    VLOG_DBG("Config Change in GLOBAL: %d", MSTP_DYN_RECONFIG_CHANGE);
}
/**PROC+**********************************************************************
 * Name:      update_mstp_cist_config
 *
 * Purpose:   Update MSTP global data structures
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/

void update_mstp_cist_config(mstpd_message *pmsg)
{
    struct mstp_cist_config *cist_config = NULL;
    cist_config = (mstp_cist_config *)pmsg->msg;
    if (!cist_config){
        return;
    }
    if (!MSTP_CIST_VALID)
    {
       MSTP_NUM_OF_VALID_TREES++;
    }

    MSTP_CIST_VALID = TRUE;

    if(MSTP_GET_BRIDGE_PRIORITY(MSTP_CIST_BRIDGE_IDENTIFIER) !=
            cist_config->priority * PRIORITY_MULTIPLIER)
    {
        MSTP_SET_BRIDGE_PRIORITY(MSTP_CIST_BRIDGE_IDENTIFIER,
                cist_config->priority * PRIORITY_MULTIPLIER);
        if (MSTP_ENABLED)
        {
            MSTP_DYN_RECONFIG_CHANGE = TRUE;
        }
    }

    if(mstp_Bridge.FwdDelay != cist_config->forward_delay)
    {
        mstp_Bridge.FwdDelay = cist_config->forward_delay;
        MSTP_CIST_BRIDGE_TIMES.fwdDelay = mstp_Bridge.FwdDelay;

        /*------------------------------------------------------------------
         * If this Bridge is the CIST Root then:
         *  - we need to update 'portTimes' with the new 'fwdDelay'
         *    value for all designated ports, so new times value will be used
         *    in BPDU's transmitted from those designated ports down the tree.
         *  - we update 'designatedTimes' for every port to be in sync
         *    with the change.
         *  - we update 'rootTimes' to be in sync with the change.
         *------------------------------------------------------------------*/
        if(MSTP_IS_THIS_BRIDGE_CIST_ROOT)
        {
            LPORT_t lport;

            for(lport = 1; lport <= MAX_LPORTS; lport ++)
            {
                if(MSTP_CIST_PORT_PTR(lport))
                {
                    MSTP_CIST_PORT_PTR(lport)->portTimes.fwdDelay =
                        mstp_Bridge.FwdDelay;
                    MSTP_CIST_PORT_PTR(lport)->designatedTimes.fwdDelay =
                        mstp_Bridge.FwdDelay;
                }
            }

            MSTP_CIST_ROOT_TIMES.fwdDelay = mstp_Bridge.FwdDelay;
        }
    }

    if(mstp_Bridge.HelloTime != cist_config->hello_time)
    {
        LPORT_t lport;

        mstp_Bridge.HelloTime  = cist_config->hello_time;
        if(MSTP_IS_THIS_BRIDGE_CIST_ROOT)
            MSTP_CIST_ROOT_HELLO_TIME = mstp_Bridge.HelloTime;

        /*------------------------------------------------------------------
         * Update 'Hello Time' value of the ports which configured to use
         * global hello time.
         * NOTE: the changes in the value of this parameter do not require
         *       MSTP re-initialization as they do not cause changes in the
         *       active topology. But we need propagate the new value down
         *       the tree if this switch is the CIST Root.
         *------------------------------------------------------------------*/
        for(lport = 1; lport <= MAX_LPORTS; lport ++)
        {
            if(MSTP_COMM_PORT_PTR(lport))
            {
                if(MSTP_COMM_PORT_PTR(lport)->useGlobalHelloTime)
                {
                    MSTP_COMM_PORT_PTR(lport)->HelloTime = mstp_Bridge.HelloTime;

                    /*---------------------------------------------------------
                     * If this Bridge is the CIST Root then we also need to
                     * update 'Hello Time' component of the 'portTimes' for
                     * the port, so the new times value will be used in BPDU's
                     * transmitted from the designated port down the tree.
                     *---------------------------------------------------------*/
                    if(MSTP_IS_THIS_BRIDGE_CIST_ROOT)
                    {
                        STP_ASSERT(MSTP_CIST_PORT_PTR(lport));
                        MSTP_CIST_PORT_PTR(lport)->portTimes.helloTime =
                            mstp_Bridge.HelloTime;
                    }
                }
            }
        }
    }
    if(mstp_Bridge.MaxAge != cist_config->max_age)
    {
        mstp_Bridge.MaxAge = cist_config->max_age;
        MSTP_CIST_BRIDGE_TIMES.maxAge = mstp_Bridge.MaxAge;

        /*------------------------------------------------------------------
         * If this Bridge is the CIST Root then:
         *  - we need to update 'portTimes' with the new 'maxAge'
         *    value for all designated ports, so new times value will be used
         *    in BPDU's transmitted from those designated ports down the tree.
         *  - we update 'designatedTimes' for every port to be in sync
         *    with the change.
         * - we update 'rootTimes' to be in sync with the change.
         *------------------------------------------------------------------*/
        if(MSTP_IS_THIS_BRIDGE_CIST_ROOT)
        {
            LPORT_t lport;

            MSTP_CIST_ROOT_TIMES.maxAge = mstp_Bridge.MaxAge;

            for(lport = 1; lport <= MAX_LPORTS; lport ++)
            {
                if(MSTP_CIST_PORT_PTR(lport))
                {
                    MSTP_CIST_PORT_PTR(lport)->portTimes.maxAge =
                        mstp_Bridge.MaxAge;

                    MSTP_CIST_PORT_PTR(lport)->designatedTimes.maxAge =
                        mstp_Bridge.MaxAge;
                }
            }

            MSTP_CIST_ROOT_TIMES.maxAge = mstp_Bridge.MaxAge;
        }
    }

    if(mstp_Bridge.MaxHops != cist_config->max_hop_count)
    {
        mstp_Bridge.MaxHops = cist_config->max_hop_count;

        if(MSTP_CIST_VALID)
        {
            MSTP_CIST_BRIDGE_TIMES.hops  = mstp_Bridge.MaxHops;

            /*---------------------------------------------------------------
             * If this Bridge is the CIST Regional Root then:
             *  - we need to update 'portTimes' with the new 'MaxHops'
             *    value for all designated ports, so new times value will be
             *    used in BPDU's transmitted from those designated ports down
             *    the tree.
             *  - we update 'designatedTimes' for every port to be in sync
             *    with the change.
             *  - we update 'rootTimes' to be in sync with the change.
             *---------------------------------------------------------------*/
            if(MSTP_IS_THIS_BRIDGE_RROOT(MSTP_CISTID))
            {
                LPORT_t lport;

                for(lport = 1; lport <= MAX_LPORTS; lport ++)
                {
                    if(MSTP_CIST_PORT_PTR(lport))
                    {
                        MSTP_CIST_PORT_PTR(lport)->portTimes.hops =
                            mstp_Bridge.MaxHops;

                        MSTP_CIST_PORT_PTR(lport)->designatedTimes.hops =
                            mstp_Bridge.MaxHops;
                    }
                }

                MSTP_CIST_ROOT_TIMES.hops = mstp_Bridge.MaxHops;
            }
        }
    }

    if(mstp_Bridge.TxHoldCount != cist_config->tx_hold_count)
    {
        mstp_Bridge.TxHoldCount = cist_config->tx_hold_count;
    }

    /* Copy the operational timers from config as the bridge is the root for thsi CIST */
    if(MSTP_IS_THIS_BRIDGE_CIST_ROOT) {
        struct ovsdb_idl_txn *txn = NULL;
        MSTP_OVSDB_LOCK;
        txn = ovsdb_idl_txn_create(idl);
        if(txn == NULL) {
            VLOG_ERR("%s Transaction Failed %s:%d", program_name, __FILE__, __LINE__);
            return;
        }
        mstp_util_set_cist_table_value(OPER_HELLO_TIME, mstp_Bridge.HelloTime);
        mstp_util_set_cist_table_value(OPER_FORWARD_DELAY, mstp_Bridge.FwdDelay);
        mstp_util_set_cist_table_value(OPER_MAX_AGE, mstp_Bridge.MaxAge);
        mstp_util_set_cist_table_value(OPER_TX_HOLD_COUNT, mstp_Bridge.TxHoldCount);
        ovsdb_idl_txn_commit_block(txn);
        ovsdb_idl_txn_destroy(txn);
        MSTP_OVSDB_UNLOCK;
    }

    VLOG_DBG("Config Change in CIST Data : %d",MSTP_DYN_RECONFIG_CHANGE);
}

/**PROC+**********************************************************************
 * Name:      update_mstp_cist_port_config
 *
 * Purpose:   Update MSTP global data structures
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/

void update_mstp_cist_port_config(mstpd_message *pmsg)
{
    int lport = 0;
    struct mstp_cist_port_config *cist_port_config;
    cist_port_config = (mstp_cist_port_config *)pmsg->msg;
    if(cist_port_config)
    {
        MSTP_COMM_PORT_INFO_t *commPortPtr = NULL;
        MSTP_CIST_PORT_INFO_t *cistPortPtr = NULL;
        uint32_t path_cost = 0;
        lport = cist_port_config->port;
        VLOG_DBG("Protocol Thread: Lport for Cist port : %d",lport);
        if(!MSTP_COMM_PORT_PTR(lport))
        {
            /*------------------------------------------------------------------
             * Allocate memory to keep port's data
             * (common for the CIST and the MSTIs)
             *------------------------------------------------------------------*/
            MSTP_COMM_PORT_PTR(lport) = (MSTP_COMM_PORT_INFO_t *)malloc(sizeof(MSTP_COMM_PORT_INFO_t));
            memset(MSTP_COMM_PORT_PTR(lport), 0,sizeof(MSTP_COMM_PORT_INFO_t));
        }
        commPortPtr = MSTP_COMM_PORT_PTR(lport);
        if(!MSTP_CIST_PORT_PTR(lport))
        {
            /*------------------------------------------------------------------
             * Allocate memory to keep CIST port's data
             *------------------------------------------------------------------*/
            MSTP_CIST_PORT_PTR(lport) = (MSTP_CIST_PORT_INFO_t *)calloc(1, sizeof(MSTP_CIST_PORT_INFO_t));
        }
        cistPortPtr = MSTP_CIST_PORT_PTR(lport);
        MSTP_SET_PORT_NUM(cistPortPtr->portId,lport);
        if (cist_port_config->admin_path_cost != 0)
        {
            path_cost = cist_port_config->admin_path_cost;
        }
        else
        {
            path_cost = mstp_portAutoPathCostDetect(lport);
        }
        cistPortPtr->useCfgPathCost = cist_port_config->admin_path_cost;
        if(cistPortPtr->InternalPortPathCost != path_cost)
        {
            cistPortPtr->InternalPortPathCost = path_cost;
            if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                        MSTP_PORT_PORT_ENABLED) && MSTP_ENABLED)
            {/* Port is 'Enabled' and the path cost value has changed,
              * indicate that protocol re-initialization is required */
                MSTP_DYN_RECONFIG_CHANGE = TRUE;
            }
        }
        if (commPortPtr->ExternalPortPathCost != path_cost)
        {
            commPortPtr->ExternalPortPathCost = path_cost;
            if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                        MSTP_PORT_PORT_ENABLED) && MSTP_ENABLED)
            {/* Port is 'Enabled' and the path cost value has changed,
              * indicate that protocol re-initialization is required */
                MSTP_DYN_RECONFIG_CHANGE = TRUE;
            }
        }
        MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_MCHECK);
        MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap, MSTP_PORT_AUTO_EDGE);
        VLOG_DBG("PATH cost : %d",path_cost);
        bool curValue = MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                MSTP_PORT_ADMIN_EDGE_PORT) ? TRUE : FALSE;

        if(curValue != cist_port_config->admin_edge_port_disable)
        {
            if(cist_port_config->admin_edge_port_disable == TRUE)
            {
                MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap,
                        MSTP_PORT_ADMIN_EDGE_PORT);
                MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap,
                        MSTP_PORT_OPER_EDGE);
                mstp_updatePortOperEdgeState(MSTP_CISTID, lport, TRUE);
            }
            else
            {
                MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap,
                        MSTP_PORT_ADMIN_EDGE_PORT);
                MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap,
                        MSTP_PORT_OPER_EDGE);
                mstp_updatePortOperEdgeState(MSTP_CISTID, lport, FALSE);
            }
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
        /* update the port if and only if the CIST port is available */
        if(cistPortPtr &&
                MSTP_GET_PORT_PRIORITY(cistPortPtr->portId) != cist_port_config->port_priority * PORT_PRIORITY_MULTIPLIER)
        {
            MSTP_SET_PORT_PRIORITY(cistPortPtr->portId, cist_port_config->port_priority * PORT_PRIORITY_MULTIPLIER);
            if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                        MSTP_PORT_PORT_ENABLED) && MSTP_ENABLED)
            {/* Port is 'Enabled' and the priority value has changed,
              * indicate that protocol re-initialization is required */
                MSTP_DYN_RECONFIG_CHANGE = TRUE;
            }
        }

        MSTP_CIST_PORT_PTR(lport)->portTimes.fwdDelay =
            mstp_Bridge.FwdDelay;
        MSTP_CIST_PORT_PTR(lport)->designatedTimes.fwdDelay =
            mstp_Bridge.FwdDelay;
        MSTP_COMM_PORT_PTR(lport)->useGlobalHelloTime = TRUE;
        if(MSTP_COMM_PORT_PTR(lport)->useGlobalHelloTime)
        {
            MSTP_COMM_PORT_PTR(lport)->HelloTime = mstp_Bridge.HelloTime;

            /*---------------------------------------------------------
             * If this Bridge is the CIST Root then we also need to
             * update 'Hello Time' component of the 'portTimes' for
             * the port, so the new times value will be used in BPDU's
             * transmitted from the designated port down the tree.
             *---------------------------------------------------------*/
            if(MSTP_IS_THIS_BRIDGE_CIST_ROOT)
            {
                STP_ASSERT(MSTP_CIST_PORT_PTR(lport));
                MSTP_CIST_PORT_PTR(lport)->portTimes.helloTime =
                    mstp_Bridge.HelloTime;
            }
        }
        MSTP_CIST_PORT_PTR(lport)->portTimes.maxAge =
            mstp_Bridge.MaxAge;

        MSTP_CIST_PORT_PTR(lport)->designatedTimes.maxAge =
            mstp_Bridge.MaxAge;

        MSTP_CIST_PORT_PTR(lport)->portTimes.hops =
            mstp_Bridge.MaxHops;

        MSTP_CIST_PORT_PTR(lport)->designatedTimes.hops =
            mstp_Bridge.MaxHops;
        uint32_t restrictedRole =
            MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                    MSTP_PORT_RESTRICTED_ROLE) ? TRUE : FALSE ;

        if(restrictedRole != cist_port_config->restricted_port_role_disable)
        {
            if(cist_port_config->restricted_port_role_disable == TRUE)
            {
                MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap,
                        MSTP_PORT_RESTRICTED_ROLE);
                if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                            MSTP_PORT_PORT_ENABLED) &&
                        mstp_isPortRoleSetOnAnyTree(lport, MSTP_PORT_ROLE_ROOT) &&
                        MSTP_ENABLED)
                {/* Port is 'Enabled', is the 'Root' and 'restrictedRole' flag
                  * is set, indicate that protocol re-initialization is
                  * required */
                    MSTP_DYN_RECONFIG_CHANGE = TRUE;
                }
            }
            else
            {
                MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap,
                        MSTP_PORT_RESTRICTED_ROLE);
                if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                            MSTP_PORT_PORT_ENABLED) &&
                        mstp_isPortRoleSetOnAnyTree(lport, MSTP_PORT_ROLE_ALTERNATE) &&
                        MSTP_ENABLED)
                {/* Port is 'Enabled', is the 'Alternate' and 'restrictedRole'
                  * flag is cleared, indicate that protocol re-initialization
                  * is required */
                    MSTP_DYN_RECONFIG_CHANGE = TRUE;
                }
            }
        }
        uint32_t curTcn =
            MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                    MSTP_PORT_RESTRICTED_TCN) ? TRUE : FALSE;

        if(curTcn != cist_port_config->restricted_port_tcn_disable)
        {
            if(cist_port_config->restricted_port_tcn_disable == TRUE)
            {
                MSTP_COMM_PORT_SET_BIT(commPortPtr->bitMap,
                        MSTP_PORT_RESTRICTED_TCN);
            }
            else
            {
                MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap,
                        MSTP_PORT_RESTRICTED_TCN);
            }
        }
        if(cist_port_config->bpdu_filter_disable == TRUE)
        {
            if(!MSTP_COMM_IS_BPDU_FILTER(lport))
            {/* Changing to ON. */
                MSTP_COMM_SET_BPDU_FILTER(lport);
                if(MSTP_CIST_PORT_PTR(lport))
                    MSTP_CIST_PORT_PTR(lport)->dbgCnts.errantBpduCnt = 0;
                if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                            MSTP_PORT_PORT_ENABLED) && MSTP_ENABLED)
                {
                    /*---------------------------------------------------------
                     * Initialize port's Bridge Detect State Machine
                     * NOTE: Bridge Detect SM will set 'operEdgePort' value to
                     *       the value of 'AdminEdgePort'
                     *---------------------------------------------------------*/
                    MSTP_BEGIN = TRUE;
                    mstp_bdmSm(lport);
                    MSTP_BEGIN = FALSE;
                }
            }
        }
        else
        {
            if(MSTP_COMM_IS_BPDU_FILTER(lport))
            {/* Changing to OFF. */
                MSTP_COMM_CLR_BPDU_FILTER(lport);
                if(MSTP_CIST_PORT_PTR(lport))
                    MSTP_CIST_PORT_PTR(lport)->dbgCnts.errantBpduCnt = 0;
                if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                            MSTP_PORT_PORT_ENABLED) && MSTP_ENABLED)
                {
                    /*---------------------------------------------------------
                     * Initialize port's Bridge Detect State Machine
                     * NOTE: Bridge Detect SM will set 'operEdgePort' value to
                     *       the value of 'AdminEdgePort'
                     *---------------------------------------------------------*/
                    MSTP_BEGIN = TRUE;
                    mstp_bdmSm(lport);
                    MSTP_BEGIN = FALSE;

                    /*---------------------------------------------------------
                     * Execute port's Port Transmission State Machine
                     * NOTE: Port Transmission SM will initiate periodic
                     *       BPDUs transmissions on a port, if necessary
                     *---------------------------------------------------------*/
                    mstp_ptxSm(lport);
                }
            }
        }
        if( cist_port_config->bpdu_guard_disable == TRUE )
        {
            if( ! MSTP_COMM_PORT_IS_BPDU_PROTECTED(lport) )
            {
                /* Changing to ON. */
                MSTP_COMM_PORT_SET_BPDU_PROTECTION(lport);
                if(MSTP_CIST_PORT_PTR(lport))
                    MSTP_CIST_PORT_PTR(lport)->dbgCnts.errantBpduCnt = 0;
            }
        }
        else
        {
            if(MSTP_COMM_PORT_IS_BPDU_PROTECTED(lport))
            {
                MSTP_COMM_PORT_INFO_t *commPortPtr;

                /* Changing to OFF. */
                MSTP_COMM_PORT_CLR_BPDU_PROTECTION(lport);
                if(MSTP_CIST_PORT_PTR(lport))
                    MSTP_CIST_PORT_PTR(lport)->dbgCnts.errantBpduCnt = 0;

                /* Attempt to bring port back up if currently disabled */
                commPortPtr = MSTP_COMM_PORT_PTR(lport);
                if(commPortPtr->inBpduError == TRUE)
                {
                    commPortPtr->inBpduError   = FALSE;
                    commPortPtr->reEnableTimer = 0;
                    enable_logical_port(lport);
                }
            }
        }
        if(cist_port_config->loop_guard_disable == TRUE)
        {
            if(!MSTP_COMM_PORT_IS_LOOP_GUARD_PROTECTED(lport))
            {
                /* Changing to ON. */
                MSTP_COMM_PORT_SET_LOOP_GUARD_PROTECTION(lport);
            }
        }
        else
        {
            if(MSTP_COMM_PORT_IS_LOOP_GUARD_PROTECTED(lport))
            {
                int      mstid;
                bool    reconfig_needed = FALSE;

                /* Changing to OFF. */
                MSTP_COMM_PORT_CLR_LOOP_GUARD_PROTECTION(lport);
                if(MSTP_CIST_PORT_PTR(lport) &&
                        MSTP_CIST_PORT_PTR(lport)->loopInconsistent)
                {
                    MSTP_CIST_PORT_PTR(lport)->loopInconsistent = FALSE;
                    reconfig_needed = TRUE;
                }

                for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
                {
                    if(MSTP_MSTI_VALID(mstid) &&
                            MSTP_MSTI_PORT_PTR(mstid, lport) &&
                            MSTP_MSTI_PORT_PTR(mstid, lport)->loopInconsistent)
                    {
                        MSTP_MSTI_PORT_PTR(mstid, lport)->loopInconsistent =
                            FALSE;
                        reconfig_needed = TRUE;
                    }
                }
                /*---------------------------------------------------------------------
                 *  Dynamic reconfiguration is needed only if port is in
                 * inconsistent state and user reconfigures the loopguard
                 * configuration
                 *---------------------------------------------------------------------*/
                if(reconfig_needed && MSTP_ENABLED)
                {
                    MSTP_DYN_RECONFIG_CHANGE = TRUE;
                }
            }
        }
    }
}
/**PROC+**********************************************************************
 * Name:      update_mstp_msti_config
 *
 * Purpose:   Update MSTP global data structures
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/

void update_mstp_msti_config(mstpd_message *pmsg)
{
    struct mstp_msti_config *msti_data = NULL;
    MSTP_COMM_PORT_INFO_t *commPortPtr = NULL;
    MSTP_MSTI_PORT_INFO_t *mstiPortPtr = NULL;
    int mstid = 0;
    LPORT_t lport = 0;
    msti_data = (mstp_msti_config *)pmsg->msg;
    if (!msti_data) {
        return;
    }
    mstid = msti_data->mstid;
    if(!MSTP_MSTI_INFO(mstid))
    {
        /*---------------------------------------------------------------------
         * MSTI entry does not exist yet - allocate memory for it.
         *---------------------------------------------------------------------*/
        MSTP_MSTI_INFO(mstid) = (MSTP_MSTI_INFO_t *)
            calloc(1, sizeof(MSTP_MSTI_INFO_t));
        if (!MSTP_MSTI_INFO(mstid))
        {
            VLOG_ERR("Failed to allocate memory for MSTP MSTI Info");
            return;
        }
    }

    if (mstp_updateMstiVidMapping(msti_data->mstid,msti_data->vlans) && MSTP_ENABLED)
    {
        mstp_buildMstConfigurationDigest(mstp_Bridge.MstConfigId.digest);
        MSTP_DYN_RECONFIG_CHANGE = TRUE;
    }
    if(MSTP_GET_BRIDGE_PRIORITY(MSTP_MSTI_BRIDGE_IDENTIFIER(mstid)) !=
            msti_data->priority * PRIORITY_MULTIPLIER)
    {
        MSTP_SET_BRIDGE_PRIORITY(MSTP_MSTI_BRIDGE_IDENTIFIER(mstid),
                msti_data->priority * PRIORITY_MULTIPLIER);
        if (MSTP_ENABLED)
        {
            MSTP_DYN_RECONFIG_CHANGE = TRUE;
        }
    }
    for (lport = 1; lport <= MAX_LPORTS; lport++ )
    {
        uint32_t path_cost = 0;
        commPortPtr = MSTP_COMM_PORT_PTR(lport);
        if (!commPortPtr)
        {
            continue;
        }
        if(!MSTP_MSTI_PORT_PTR(mstid, lport))
        {
            /*------------------------------------------------------------------
             * Allocate memory to keep MSTI port's data
             *------------------------------------------------------------------*/
            MSTP_MSTI_PORT_PTR(mstid, lport) = (MSTP_MSTI_PORT_INFO_t *)calloc(1, sizeof(MSTP_MSTI_PORT_INFO_t));
            if(!MSTP_MSTI_PORT_PTR(mstid, lport))
            {
                VLOG_ERR("Failed to allocate memory for MSTP MSTI Port Info");
                return;
            }
        }
        mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
        MSTP_SET_PORT_NUM(mstiPortPtr->portId,lport);
        if(MSTP_GET_PORT_PRIORITY(mstiPortPtr->portId) !=
                DEF_MSTP_PORT_PRIORITY * PORT_PRIORITY_MULTIPLIER)
        {
            MSTP_SET_PORT_PRIORITY(mstiPortPtr->portId,
                    DEF_MSTP_PORT_PRIORITY * PORT_PRIORITY_MULTIPLIER);
            if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                        MSTP_PORT_PORT_ENABLED) && MSTP_ENABLED)
            {/* Port is 'Enabled' and the priority value has changed,
              * indicate that protocol re-initialization is required */
                MSTP_DYN_RECONFIG_CHANGE = TRUE;
            }
        }
        path_cost = mstp_portAutoPathCostDetect(lport);
        mstiPortPtr->useCfgPathCost = 0;
        if(mstiPortPtr->InternalPortPathCost != path_cost)
        {
            mstiPortPtr->InternalPortPathCost = path_cost;
            if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                        MSTP_PORT_PORT_ENABLED) && MSTP_ENABLED)
            {/* Port is 'Enabled' and the path cost value has changed,
              * indicate that protocol re-initialization is required */
                MSTP_DYN_RECONFIG_CHANGE = TRUE;
            }
        }
        mstp_initMstiPortData(mstid,lport,TRUE);
    }
    /*---------------------------------------------------------------------
     * Mark MST Instance as valid and increment global counter of valid
     * trees.
     *---------------------------------------------------------------------*/
    MSTP_MSTI_INFO(mstid)->valid = TRUE;
    MSTP_NUM_OF_VALID_TREES++;

}
/**PROC+**********************************************************************
 * Name:      update_mstp_msti_port_config
 *
 * Purpose:   Update MSTP global data structures
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/

void update_mstp_msti_port_config(mstpd_message *pmsg)
{
    struct mstp_msti_port_config *msti_port_config = NULL;
    msti_port_config = (mstp_msti_port_config *)pmsg->msg;
    int mstid = 0, lport = 0;
    mstid = msti_port_config->mstid;
    lport = msti_port_config->port;
    uint32_t path_cost = 0;
    MSTP_COMM_PORT_INFO_t *commPortPtr = NULL;
    MSTP_MSTI_PORT_INFO_t *mstiPortPtr = NULL;
    if(!MSTP_COMM_PORT_PTR(lport))
    {
        /*------------------------------------------------------------------
         * Allocate memory to keep port's data
         * (common for the CIST and the MSTIs)
         *------------------------------------------------------------------*/
        MSTP_COMM_PORT_PTR(lport) = (MSTP_COMM_PORT_INFO_t *)malloc(sizeof(MSTP_COMM_PORT_INFO_t));
        memset(MSTP_COMM_PORT_PTR(lport), 0,sizeof(MSTP_COMM_PORT_INFO_t));
    }
    commPortPtr = MSTP_COMM_PORT_PTR(lport);
    if(!MSTP_MSTI_PORT_PTR(mstid, lport))
    {
        /*------------------------------------------------------------------
         * Allocate memory to keep MSTI port's data
         *------------------------------------------------------------------*/
        MSTP_MSTI_PORT_PTR(mstid, lport) = (MSTP_MSTI_PORT_INFO_t *)calloc(1, sizeof(MSTP_MSTI_PORT_INFO_t));
    }
    mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
    MSTP_SET_PORT_NUM(mstiPortPtr->portId,lport);
    if(MSTP_GET_PORT_PRIORITY(mstiPortPtr->portId) !=
            msti_port_config->priority * PORT_PRIORITY_MULTIPLIER)
    {
        MSTP_SET_PORT_PRIORITY(mstiPortPtr->portId,
                msti_port_config->priority * PORT_PRIORITY_MULTIPLIER);
        if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                    MSTP_PORT_PORT_ENABLED) && MSTP_ENABLED)
        {/* Port is 'Enabled' and the priority value has changed,
          * indicate that protocol re-initialization is required */
            MSTP_DYN_RECONFIG_CHANGE = TRUE;
        }
    }
    if(msti_port_config->path_cost != 0)
        path_cost = msti_port_config->path_cost;
    else
        path_cost = mstp_portAutoPathCostDetect(lport);
    mstiPortPtr->useCfgPathCost = msti_port_config->path_cost;
    if(mstiPortPtr->InternalPortPathCost != path_cost)
    {
        mstiPortPtr->InternalPortPathCost = path_cost;
        if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                    MSTP_PORT_PORT_ENABLED) && MSTP_ENABLED)
        {/* Port is 'Enabled' and the path cost value has changed,
          * indicate that protocol re-initialization is required */
            MSTP_DYN_RECONFIG_CHANGE = TRUE;
        }
    }
}

void delete_mstp_msti_config(mstpd_message *pmsg)
{
    struct mstp_msti_config_delete *msti_config_delete = NULL;
    int mstid = 0,lport = 0;
    msti_config_delete = (mstp_msti_config_delete *)pmsg->msg;
    mstid = msti_config_delete->mstid;
    MSTP_TREE_MSG_t *m;

    STP_ASSERT(MSTP_VALID_MSTID(mstid));

    /*---------------------------------------------------------------------
     * If MST Instance does not exist then nothing to delete.
     *---------------------------------------------------------------------*/
    if(MSTP_MSTI_INFO(mstid) == NULL)
        return;

    /*---------------------------------------------------------------------
     * Delete the MSTI ports data
     *---------------------------------------------------------------------*/
    for(lport = 1; lport <= MAX_LPORTS; lport++)
    {
        if(MSTP_MSTI_PORT_PTR(mstid, lport))
        {
            mstp_clearMstiPortData(mstid, lport);
        }
    }
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
     * Update global MST Configuration Identification 'digest' value.
     * That value is being sent in MSTP BPDUs to propagate local VIDs to
     * MSTIs mapping information to other MSTP Bridges.
     *---------------------------------------------------------------------*/
    mstp_buildMstConfigurationDigest(mstp_Bridge.MstConfigId.digest);

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

    MSTP_DYN_RECONFIG_CHANGE = TRUE;
}
/**PROC+**********************************************************************
 * Name:      mstp_informDBOnPortStateChange
 *
 * Purpose:   Update DB on MSTP port State changes
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/

void
mstp_informDBOnPortStateChange(uint32_t operation)
{
   MSTP_TREE_MSG_t *m;
   MSTP_TREE_MSG_t *m_next;
   bool            remove_msg = FALSE;
   bool           isblk_msg = FALSE, isfwd_msg = FALSE;
   struct ovsdb_idl_txn *txn = NULL;
   const struct ovsrec_port *port_row = NULL;
   struct smap smap_other_config;
   MSTP_OVSDB_LOCK;
   txn = ovsdb_idl_txn_create(idl);

   m_next = (MSTP_TREE_MSG_t*) qfirst_nodis (&MSTP_TREE_MSGS_QUEUE);
   while(m_next != (MSTP_TREE_MSG_t*) Q_NULL)
   {
      m = m_next;
      m_next = (MSTP_TREE_MSG_t*)qnext_nodis(&MSTP_TREE_MSGS_QUEUE, &m->link);
       /*---------------------------------------------------------------------
      * propagate 'lport down' requests to DB
       *---------------------------------------------------------------------*/
      if(are_any_ports_set(&m->portsDwn))
      {
         int lport = 0;
         for(lport = find_first_port_set(&m->portsDwn);IS_VALID_LPORT(lport);
                  lport = find_next_port_set(&m->portsDwn, lport))
          {
             char port[20] = {0};
              intf_get_port_name(lport,port);
              OVSREC_PORT_FOR_EACH(port_row,idl)
                {
                    if(strcmp(port_row->name,port)==0)
                    {
                        smap_clone(&smap_other_config, &port_row->hw_config);
                        smap_replace(&smap_other_config, BLOCK_ALL_MSTP, "true");
                        ovsrec_port_set_hw_config(port_row, &smap_other_config);
                        smap_destroy(&smap_other_config);
                    }
                }
          }
         clear_port_map(&m->portsDwn);
      }
      /*---------------------------------------------------------------------
       * propagate 'block' request to DB
       *---------------------------------------------------------------------*/
      if(are_any_ports_set(&m->portsBlk))
      {
          VLOG_DBG("MSTP_DBG blocking ports on informDB");
          isblk_msg = TRUE;
          int lport = 0;
          for(lport = find_first_port_set(&m->portsBlk);IS_VALID_LPORT(lport);
                  lport = find_next_port_set(&m->portsBlk, lport))
          {
              char port[20] = {0};
              intf_get_port_name(lport,port);
              if (m->mstid != 0){
                  mstp_util_set_msti_port_table_string(PORT_STATE,"Blocking",m->mstid,lport);
              }
              else
              {
                  mstp_util_set_cist_port_table_string(port,PORT_STATE,"Blocking");
              }
          }
      }

      /*---------------------------------------------------------------------
       * propagate 'learn' requests to DB
       *---------------------------------------------------------------------*/
      if(are_any_ports_set(&m->portsLrn))
      {
          VLOG_DBG("MSTP_DBG Learning ports on informDB");
          int lport = 0;
          for(lport = find_first_port_set(&m->portsLrn);IS_VALID_LPORT(lport);
                  lport = find_next_port_set(&m->portsLrn, lport))
          {
              char port[20] = {0};
              intf_get_port_name(lport,port);
              if (m->mstid != 0){
                  mstp_util_set_msti_port_table_string(PORT_STATE,"Learning",m->mstid,lport);
              }
              else
              {
                  mstp_util_set_cist_port_table_string(port,PORT_STATE,"Learning");
              }
          }
        clear_port_map(&m->portsLrn);
      }

      /*---------------------------------------------------------------------
       * propagate 'forward' requests to DB
       *---------------------------------------------------------------------*/
      if(are_any_ports_set(&m->portsFwd))
      {
         VLOG_DBG("MSTP_DBG Forwarding ports on informDB");
         isfwd_msg = TRUE;
          int lport = 0;
          for(lport = find_first_port_set(&m->portsFwd);IS_VALID_LPORT(lport);
                  lport = find_next_port_set(&m->portsFwd, lport))
          {
              char port[20] = {0};
              intf_get_port_name(lport,port);
              if (m->mstid == MSTP_NON_STP_BRIDGE){
                  int mstid = 0;
                  mstp_util_set_cist_port_table_string(port,PORT_STATE,"Forwarding");
                  for(mstid = 1; mstid < MSTP_MSTID_MAX; mstid++)
                  {
                      if (MSTP_MSTI_VALID(mstid))
                      {
                          mstp_util_set_msti_port_table_string(PORT_STATE,"Forwarding",mstid,lport);
                      }
                  }
              }
              else if (m->mstid != 0){
                  mstp_util_set_msti_port_table_string(PORT_STATE,"Forwarding",m->mstid,lport);
              }
              else
              {
                  mstp_util_set_cist_port_table_string(port,PORT_STATE,"Forwarding");
              }
          }
      }
      if(are_any_ports_set(&m->portsUp))
      {
          int lport = 0;
          for(lport = find_first_port_set(&m->portsUp);IS_VALID_LPORT(lport);
                  lport = find_next_port_set(&m->portsUp, lport))
          {
              char port[20] = {0};
              intf_get_port_name(lport,port);
              OVSREC_PORT_FOR_EACH(port_row,idl)
              {
                  if(strcmp(port_row->name,port)==0)
                  {
                      smap_clone(&smap_other_config, &port_row->hw_config);
                      smap_replace(&smap_other_config, BLOCK_ALL_MSTP, "false");
                      ovsrec_port_set_hw_config(port_row, &smap_other_config);
                      smap_destroy(&smap_other_config);
                  }
              }
          }
          clear_port_map(&m->portsUp);
      }

#if 0
      if(are_any_ports_set(&m->portsClearEdge))
      {
         mstp_updatePortSecurity(&m->portsClearEdge,FALSE);
         clear_port_map(&m->portsClearEdge);
      }
#endif /*0*/
      /*Clear the block port map*/
      if(isblk_msg)
      {
         clear_port_map(&m->portsBlk);
         isblk_msg = FALSE;
      }
       /*Clear the forward port map*/
      if(isfwd_msg)
      {
         clear_port_map(&m->portsFwd);
         isfwd_msg = FALSE;
      }

      if(operation == e_mstpd_timer)
      {
         if(are_any_ports_set(&m->portsMacAddrFlush) &&
            (m->mstid <= MSTP_INSTANCES_MAX))
         {
             int lport = 0;
             for(lport = find_first_port_set(&m->portsMacAddrFlush);IS_VALID_LPORT(lport);
                     lport = find_next_port_set(&m->portsMacAddrFlush, lport))
             {
                 char port[20] = {0};
                 intf_get_port_name(lport,port);
                 if (m->mstid != 0){
                     mstp_util_msti_flush_mac_address(m->mstid,lport);
                 }
                 else
                 {
                     mstp_util_cist_flush_mac_address(port);
                 }
             }
         }

         remove_msg = TRUE;
      }

      /*---------------------------------------------------------------------
       * take pending message off the queue and free it
       *---------------------------------------------------------------------*/
      if(remove_msg)
      {
         remqhere_nodis(&MSTP_TREE_MSGS_QUEUE, &m->link);
         free(m);
      }
   }
   ovsdb_idl_txn_commit_block(txn);
   ovsdb_idl_txn_destroy(txn);
   MSTP_OVSDB_UNLOCK;
}
/**PROC+**********************************************************************
 * Name:      update_mstp_on_lport_add
 *
 * Purpose:   Update Global data on lport add
 *
 * Params:    none
 *
 * Returns:   none
 *
 * Globals:   mstp_Bridge
 *
 * Constraints:
 **PROC-**********************************************************************/

void update_mstp_on_lport_add(int lport)
{
    int path_cost = 0;
    MSTP_COMM_PORT_INFO_t *commPortPtr = NULL;
    MSTP_MSTI_PORT_INFO_t *mstiPortPtr = NULL;
    MSTP_CIST_PORT_INFO_t *cistPortPtr = NULL;
    if(!MSTP_COMM_PORT_PTR(lport))
    {
        /*------------------------------------------------------------------
         * Allocate memory to keep port's data
         * (common for the CIST and the MSTIs)
         *------------------------------------------------------------------*/
        MSTP_COMM_PORT_PTR(lport) = (MSTP_COMM_PORT_INFO_t *)malloc(sizeof(MSTP_COMM_PORT_INFO_t));
        memset(MSTP_COMM_PORT_PTR(lport), 0,sizeof(MSTP_COMM_PORT_INFO_t));
    }
    commPortPtr = MSTP_COMM_PORT_PTR(lport);
    if(!MSTP_CIST_PORT_PTR(lport))
    {
        /*------------------------------------------------------------------
         * Allocate memory to keep CIST port's data
         *------------------------------------------------------------------*/
        MSTP_CIST_PORT_PTR(lport) = (MSTP_CIST_PORT_INFO_t *)calloc(1, sizeof(MSTP_CIST_PORT_INFO_t));
    }
    cistPortPtr = MSTP_CIST_PORT_PTR(lport);
    MSTP_SET_PORT_NUM(cistPortPtr->portId,lport);
    path_cost = mstp_portAutoPathCostDetect(lport);
    cistPortPtr->useCfgPathCost = path_cost;
    cistPortPtr->InternalPortPathCost = path_cost;
    if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                MSTP_PORT_PORT_ENABLED) && MSTP_ENABLED)
    {/* Port is 'Enabled' and the path cost value has changed,
      * indicate that protocol re-initialization is required */
        MSTP_DYN_RECONFIG_CHANGE = TRUE;
    }
    MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap,
            MSTP_PORT_ADMIN_EDGE_PORT);
    MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap,
            MSTP_PORT_OPER_EDGE);
    mstp_updatePortOperEdgeState(MSTP_CISTID, lport, FALSE);
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
    /* update the port if and only if the CIST port is available */
    if(cistPortPtr &&
            MSTP_GET_PORT_PRIORITY(cistPortPtr->portId) != DEF_MSTP_PORT_PRIORITY)
    {
        MSTP_SET_PORT_PRIORITY(cistPortPtr->portId, DEF_MSTP_PORT_PRIORITY);
        if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                    MSTP_PORT_PORT_ENABLED) && MSTP_ENABLED)
        {/* Port is 'Enabled' and the priority value has changed,
          * indicate that protocol re-initialization is required */
            MSTP_DYN_RECONFIG_CHANGE = TRUE;
        }
    }
    MSTP_CIST_PORT_PTR(lport)->portTimes.fwdDelay =
        mstp_Bridge.FwdDelay;
    MSTP_CIST_PORT_PTR(lport)->designatedTimes.fwdDelay =
        mstp_Bridge.FwdDelay;
    MSTP_COMM_PORT_PTR(lport)->useGlobalHelloTime = TRUE;
    if(MSTP_COMM_PORT_PTR(lport)->useGlobalHelloTime)
    {
        MSTP_COMM_PORT_PTR(lport)->HelloTime = mstp_Bridge.HelloTime;

        /*---------------------------------------------------------
         * If this Bridge is the CIST Root then we also need to
         * update 'Hello Time' component of the 'portTimes' for
         * the port, so the new times value will be used in BPDU's
         * transmitted from the designated port down the tree.
         *---------------------------------------------------------*/
        if(MSTP_IS_THIS_BRIDGE_CIST_ROOT)
        {
            STP_ASSERT(MSTP_CIST_PORT_PTR(lport));
            MSTP_CIST_PORT_PTR(lport)->portTimes.helloTime =
                mstp_Bridge.HelloTime;
        }
    }
    MSTP_CIST_PORT_PTR(lport)->portTimes.maxAge =
        mstp_Bridge.MaxAge;

    MSTP_CIST_PORT_PTR(lport)->designatedTimes.maxAge =
        mstp_Bridge.MaxAge;

    MSTP_CIST_PORT_PTR(lport)->portTimes.hops =
        mstp_Bridge.MaxHops;

    MSTP_CIST_PORT_PTR(lport)->designatedTimes.hops =
        mstp_Bridge.MaxHops;
    MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap,
            MSTP_PORT_RESTRICTED_ROLE);
    if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                MSTP_PORT_PORT_ENABLED) &&
            mstp_isPortRoleSetOnAnyTree(lport, MSTP_PORT_ROLE_ALTERNATE) &&
            MSTP_ENABLED)
    {/* Port is 'Enabled', is the 'Alternate' and 'restrictedRole'
      * flag is cleared, indicate that protocol re-initialization
      * is required */
        MSTP_DYN_RECONFIG_CHANGE = TRUE;
    }
    MSTP_COMM_PORT_CLR_BIT(commPortPtr->bitMap,
            MSTP_PORT_RESTRICTED_TCN);
    if(MSTP_COMM_IS_BPDU_FILTER(lport))
    {/* Changing to OFF. */
        MSTP_COMM_CLR_BPDU_FILTER(lport);
        if(MSTP_CIST_PORT_PTR(lport))
            MSTP_CIST_PORT_PTR(lport)->dbgCnts.errantBpduCnt = 0;
        if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                    MSTP_PORT_PORT_ENABLED))
        {
            if (MSTP_ENABLED)
            {
                /*---------------------------------------------------------
                 * Initialize port's Bridge Detect State Machine
                 * NOTE: Bridge Detect SM will set 'operEdgePort' value to
                 *       the value of 'AdminEdgePort'
                 *---------------------------------------------------------*/
                MSTP_BEGIN = TRUE;
                mstp_bdmSm(lport);
                MSTP_BEGIN = FALSE;

                /*---------------------------------------------------------
                 * Execute port's Port Transmission State Machine
                 * NOTE: Port Transmission SM will initiate periodic
                 *       BPDUs transmissions on a port, if necessary
                 *---------------------------------------------------------*/
                mstp_ptxSm(lport);
            }
        }
    }
    if(MSTP_COMM_PORT_IS_BPDU_PROTECTED(lport))
    {
        MSTP_COMM_PORT_INFO_t *commPortPtr;

        /* Changing to OFF. */
        MSTP_COMM_PORT_CLR_BPDU_PROTECTION(lport);
        if(MSTP_CIST_PORT_PTR(lport))
            MSTP_CIST_PORT_PTR(lport)->dbgCnts.errantBpduCnt = 0;

        /* Attempt to bring port back up if currently disabled */
        commPortPtr = MSTP_COMM_PORT_PTR(lport);
        if(commPortPtr->inBpduError == TRUE)
        {
            commPortPtr->inBpduError   = FALSE;
            commPortPtr->reEnableTimer = 0;
            if (MSTP_ENABLED) {
                enable_logical_port(lport);
            }
        }
    }
    if(MSTP_COMM_PORT_IS_LOOP_GUARD_PROTECTED(lport))
    {
        int      mstid;
        bool    reconfig_needed = FALSE;

        /* Changing to OFF. */
        MSTP_COMM_PORT_CLR_LOOP_GUARD_PROTECTION(lport);
        if(MSTP_CIST_PORT_PTR(lport) &&
                MSTP_CIST_PORT_PTR(lport)->loopInconsistent)
        {
            MSTP_CIST_PORT_PTR(lport)->loopInconsistent = FALSE;
            reconfig_needed = TRUE;
        }

        for(mstid = MSTP_MSTID_MIN; mstid <= MSTP_INSTANCES_MAX; mstid++)
        {
            if(MSTP_MSTI_VALID(mstid) &&
                    MSTP_MSTI_PORT_PTR(mstid, lport) &&
                    MSTP_MSTI_PORT_PTR(mstid, lport)->loopInconsistent)
            {
                MSTP_MSTI_PORT_PTR(mstid, lport)->loopInconsistent =
                    FALSE;
                reconfig_needed = TRUE;
            }
        }
        /*---------------------------------------------------------------------
         *  Dynamic reconfiguration is needed only if port is in
         * inconsistent state and user reconfigures the loopguard
         * configuration
         *---------------------------------------------------------------------*/
        if(reconfig_needed && MSTP_ENABLED)
        {
            MSTP_DYN_RECONFIG_CHANGE = TRUE;
        }
    }
    int mstid = 1;
    for (mstid = 1; mstid <= MSTP_INSTANCES_MAX; mstid++) {
        if (!MSTP_MSTI_INFO(mstid) || MSTP_MSTI_INFO(mstid)->valid != TRUE)
        {
            continue;
        }
        uint32_t path_cost = 0;
        if(!MSTP_COMM_PORT_PTR(lport))
        {
            /*------------------------------------------------------------------
             * Allocate memory to keep port's data
             * (common for the CIST and the MSTIs)
             *------------------------------------------------------------------*/
            MSTP_COMM_PORT_PTR(lport) = (MSTP_COMM_PORT_INFO_t *)malloc(sizeof(MSTP_COMM_PORT_INFO_t));
            memset(MSTP_COMM_PORT_PTR(lport), 0,sizeof(MSTP_COMM_PORT_INFO_t));
        }
        commPortPtr = MSTP_COMM_PORT_PTR(lport);
        if(!MSTP_MSTI_PORT_PTR(mstid, lport))
        {
            /*------------------------------------------------------------------
             * Allocate memory to keep MSTI port's data
             *------------------------------------------------------------------*/
            MSTP_MSTI_PORT_PTR(mstid, lport) = (MSTP_MSTI_PORT_INFO_t *)calloc(1, sizeof(MSTP_MSTI_PORT_INFO_t));
        }
        mstiPortPtr = MSTP_MSTI_PORT_PTR(mstid, lport);
        MSTP_SET_PORT_NUM(mstiPortPtr->portId,lport);
        MSTP_SET_PORT_PRIORITY(mstiPortPtr->portId,
                MSTP_DEF_PORT_PRIORITY);
        if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                    MSTP_PORT_PORT_ENABLED) && MSTP_ENABLED)
        {/* Port is 'Enabled' and the priority value has changed,
          * indicate that protocol re-initialization is required */
            MSTP_DYN_RECONFIG_CHANGE = TRUE;
        }
        path_cost = mstp_portAutoPathCostDetect(lport);
        mstiPortPtr->useCfgPathCost = path_cost;
        if(mstiPortPtr->InternalPortPathCost != path_cost)
        {
            mstiPortPtr->InternalPortPathCost = path_cost;
            if(MSTP_COMM_PORT_IS_BIT_SET(commPortPtr->bitMap,
                        MSTP_PORT_PORT_ENABLED) && MSTP_ENABLED)
            {/* Port is 'Enabled' and the path cost value has changed,
              * indicate that protocol re-initialization is required */
                MSTP_DYN_RECONFIG_CHANGE = TRUE;
            }
        }
    }
}
