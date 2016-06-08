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

/************************************************************************//**
 * @ingroup ops-stpd
 *
 * @file
 * Main source file for the MSTP daemon.
 *
 *    The mstpd daemon provides loop-free topology
 *
 *    Its purpose in life is:
 *
 *       1. During operations, receive administrative
 *          configuration changes and apply to the hardware.
 *       2. Manage MSTP protocol operation.
 *       3. Dynamically configure hardware based on
 *          operational state changes as needed.
 ***************************************************************************/
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
#include <diag_dump.h>
#include <eventlog.h>

#include "mstp.h"
#include "mstp_ovsdb_if.h"
#include "mstp_cmn.h"

VLOG_DEFINE_THIS_MODULE(mstpd);

bool exiting = false;
static unixctl_cb_func ops_mstpd_exit;

extern int mstpd_shutdown;

/**
 * mstpd daemon's timer handler function.
 */
static void
mstpd_timerHandler(void)
{
    mstpd_message *ptimer_msg;

    ptimer_msg = (mstpd_message *)malloc(sizeof(mstpd_message));
    if (NULL == ptimer_msg) {
        VLOG_ERR("Out of memory for MSTP timer message.");
        return;
    }
    memset(ptimer_msg, 0, sizeof(mstpd_message));
    ptimer_msg->msg_type = e_mstpd_timer;
    mstpd_send_event(ptimer_msg);

} /* mstpd_timerHandler */

/**
 * callback handler function for diagnostic dump basic
 * INIT_DIAG_DUMP_BASIC will free allocated memory.
 */
static void
mstpd_diag_dump_basic_cb(const char *feature , char **buf)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    int argc = 2, i = 0, j = 0;
    const struct ovsrec_mstp_common_instance_port *cist_port = NULL;
    const struct ovsrec_mstp_instance *mstp_row = NULL;
    const struct ovsrec_bridge *bridge_row = NULL;
    const char *argv[3] = {0};
    char inst_id[2] = {0};

    if((!feature) || (!buf)) {
        VLOG_ERR("Invalid Input %s: %d\n", __FILE__, __LINE__ );
        return;
    }

    bridge_row = ovsrec_bridge_first(idl);
    if (!bridge_row) {
        VLOG_ERR("No record found %s: %d\n", __FILE__, __LINE__ );
        return;
    }

    /* populate basic diagnostic data to buffer */
    /* Populate CIST Data */
    mstpd_cist_data_dump(&ds, argc, argv);
    mstpd_daemon_cist_data_dump(&ds, argc, argv);

    /* Populate CIST port data*/
    OVSREC_MSTP_COMMON_INSTANCE_PORT_FOR_EACH(cist_port, idl) {
        memset(argv, 0, sizeof(argv));
        argv[1] = cist_port->port->name;
        mstpd_cist_port_data_dump(&ds, argc, argv);
        mstpd_daemon_cist_port_data_dump(&ds, argc, argv);
    }

    /* Populate MSTI data*/
    for (i=0; i < bridge_row->n_mstp_instances; i++) {
        memset(argv, 0, sizeof(argv));
        memset(inst_id, 0, sizeof(inst_id));
        snprintf(inst_id, sizeof(inst_id), "%ld", bridge_row->key_mstp_instances[i]);
        mstp_row = bridge_row->value_mstp_instances[i];
        if(!mstp_row) {
            VLOG_ERR("No MSTP Record found %s: %d",__FILE__, __LINE__);
            assert(0);
        }
        argv[1] = inst_id;
        mstpd_msti_data_dump(&ds, argc, argv);
        mstpd_daemon_msti_data_dump(&ds, argc, argv);

        /* Populate MSTI port data*/
        for (j=0; j < mstp_row->n_mstp_instance_ports; j++) {
            if(!mstp_row->mstp_instance_ports[j]) {
                VLOG_ERR("No MSTP Port Record found %s: %d",__FILE__, __LINE__);
                assert(0);
            }

            argv[2] = mstp_row->mstp_instance_ports[j]->port->name;
            mstpd_msti_port_data_dump(&ds, argc, argv);
            mstpd_daemon_msti_port_data_dump(&ds, argc, argv);
        }
    }

    *buf = ds.string;
    VLOG_DBG("basic diag-dump data populated for feature %s",
            feature);
}

/**
 * mstpd daemon's main initialization function.  Responsible for
 * creating various protocol & OVSDB interface threads.
 *
 * @param db_path pathname for OVSDB connection.
 */
static void
mstpd_init(const char *db_path, struct unixctl_server *appctl)
{
    int rc;
    int retval;
    sigset_t sigset;
    pthread_t ovs_if_thread;
    pthread_t mstpd_thread;
    pthread_t mstp_pdu_rx_thread;

    /* Block all signals so the spawned threads don't receive any. */
    sigemptyset(&sigset);
    sigfillset(&sigset);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);

    /* Spawn off the main MSTP protocol thread. */
    rc = pthread_create(&mstpd_thread,
                        (pthread_attr_t *)NULL,
                        mstpd_protocol_thread,
                        NULL);
    if (rc) {
        VLOG_ERR("pthread_create for MSTPD protocol thread failed! rc=%d", rc);
        exit(-rc);
    }
    /* Initialize IDL through a new connection to the dB. */
    mstpd_ovsdb_init(db_path);

    /* Register ovs-appctl commands for this daemon. */
    unixctl_command_register("mstpd/ovsdb/cist", "", 0, 0, mstpd_cist_unixctl_list, NULL);
    unixctl_command_register("mstpd/ovsdb/cist_port", "port", 1, 1, mstpd_cist_port_unixctl_list, NULL);
    unixctl_command_register("mstpd/ovsdb/msti", "msti", 1, 1, mstpd_msti_unixctl_list, NULL);
    unixctl_command_register("mstpd/ovsdb/msti_port", "msti port", 2, 2, mstpd_msti_port_unixctl_list, NULL);
    unixctl_command_register("mstpd/daemon/cist", "", 0, 0, mstpd_daemon_cist_unixctl_list, NULL);
    unixctl_command_register("mstpd/daemon/cist_port", "port", 1, 1, mstpd_daemon_cist_port_unixctl_list, NULL);
    unixctl_command_register("mstpd/daemon/msti", "msti", 1, 1, mstpd_daemon_msti_unixctl_list, NULL);
    unixctl_command_register("mstpd/daemon/msti_port", "msti port", 2, 2, mstpd_daemon_msti_port_unixctl_list, NULL);
    unixctl_command_register("mstpd/daemon/comm_port", "port", 1, 1, mstpd_daemon_comm_port_unixctl_list, NULL);
    unixctl_command_register("mstpd/daemon/mstp_debug_sm", "", 2, 2, mstpd_daemon_debug_sm_unixctl_list, NULL);
    unixctl_command_register("mstpd/daemon/mstp_digest", "", 0, 0, mstpd_daemon_digest_unixctl_list, NULL);
    unixctl_command_register("mstpd/daemon/intf_to_mstp_map", "", 0, 1, mstpd_daemon_intf_to_mstp_map_unixctl_list, NULL);

    INIT_DIAG_DUMP_BASIC(mstpd_diag_dump_basic_cb);

    retval = event_log_init("MSTP");
        if(retval < 0) {
            VLOG_ERR("Event log initialization failed");
    }

    /* Spawn off the OVSDB interface thread. */
    rc = pthread_create(&ovs_if_thread,
                        (pthread_attr_t *)NULL,
                        mstpd_ovs_main_thread,
                        (void *)appctl);
    if (rc) {
        VLOG_ERR("pthread_create for OVSDB i/f thread failed! rc=%d", rc);
        exit(-rc);
    }

    /* Spawn off MSTP RX thread. */
    rc = pthread_create(&mstp_pdu_rx_thread,
                        (pthread_attr_t *)NULL,
                        mstpd_rx_pdu_thread,
                        NULL);
    if (rc) {
        VLOG_ERR("pthread_create for MSTP PDU RX thread failed! rc=%d", rc);
        exit(-rc);
    }

} /* mstpd_init */

/**
 * mstpd usage help function.
 *
 */
static void
usage(void)
{
    printf("%s: OpenSwitch MSTP daemon\n"
           "usage: %s [OPTIONS] [DATABASE]\n"
           "where DATABASE is a socket on which ovsdb-server is listening\n"
           "      (default: \"unix:%s/db.sock\").\n",
           program_name, program_name, ovs_rundir());
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  --unixctl=SOCKET        override default control socket name\n"
           "  -h, --help              display this help message\n");
    exit(EXIT_SUCCESS);
} /* usage */

static char *
parse_options(int argc, char *argv[], char **unixctl_pathp)
{
    enum {
        OPT_UNIXCTL = UCHAR_MAX + 1,
        VLOG_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS,
    };
    static const struct option long_options[] = {
        {"help",        no_argument, NULL, 'h'},
        {"unixctl",     required_argument, NULL, OPT_UNIXCTL},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        case OPT_UNIXCTL:
            *unixctl_pathp = optarg;
            break;

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;

    switch (argc) {
    case 0:
        return xasprintf("unix:%s/db.sock", ovs_rundir());

    case 1:
        return xstrdup(argv[0]);

    default:
        VLOG_FATAL("at most one non-option argument accepted; "
                   "use --help for usage");
    }
} /* parse_options */

/**
 * mstpd daemon's ovs-appctl callback function for exit command.
 *
 * @param conn is pointer appctl connection data struct.
 * @param argc OVS_UNUSED
 * @param argv OVS_UNUSED
 * @param exiting_ is pointer to a flag that reports exit status.
 */
static void
ops_mstpd_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
                 const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, NULL);
} /* ops_mstpd_exit */

/**
 * Main function for mstpd daemon.
 *
 * @param argc is the number of command line arguments.
 * @param argv is an array of command line arguments.
 *
 * @return 0 for success or exit status on daemon exit.
 */
int
main(int argc, char *argv[])
{
    char *appctl_path = NULL;
    struct unixctl_server *appctl;
    char *ovsdb_sock;
    int retval;
    int mstp_tindex;
    struct itimerval timerVal;
    sigset_t sigset;
    int signum;

    set_program_name(argv[0]);
    proctitle_init(argc, argv);
    fatal_ignore_sigpipe();

    /* Parse command line args and get the name of the OVSDB socket. */
    ovsdb_sock = parse_options(argc, argv, &appctl_path);

    /* Initialize the metadata for the IDL cache. */
    ovsrec_init();

    /* Fork and return in child process; but don't notify parent of
     * startup completion yet. */
    daemonize_start();

    /* Create UDS connection for ovs-appctl. */
    retval = unixctl_server_create(appctl_path, &appctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }

    /* Register the ovs-appctl "exit" command for this daemon. */
    unixctl_command_register("exit", "", 0, 0, ops_mstpd_exit, &exiting);

    /* Main MSTP protocol state machine related initialization. */
    retval = mmstp_init(true);
    if (retval) {
        exit(EXIT_FAILURE);
    }
    /* Initialize various protocol and event sockets, and create
     * the IDL cache of the dB at ovsdb_sock. */
    mstpd_init(ovsdb_sock, appctl);
    free(ovsdb_sock);

    /* Notify parent of startup completion. */
    daemonize_complete();

    /* Enable asynch log writes to disk. */
    vlog_enable_async();

    VLOG_INFO_ONCE("%s (Spanning Tree Protocol Daemon) started", program_name);

    /* Set up timer to fire off every second. */
    timerVal.it_interval.tv_sec  = 1;
    timerVal.it_interval.tv_usec = 0;
    timerVal.it_value.tv_sec  = 1;
    timerVal.it_value.tv_usec = 0;

    if ((mstp_tindex = setitimer(ITIMER_REAL, &timerVal, NULL)) != 0) {
        VLOG_ERR("mstpd main: Timer start failed!\n");
    }

    /* Wait for all signals in an infinite loop. */
    sigfillset(&sigset);
    while (!mstpd_shutdown) {

        sigwait(&sigset, &signum);
        switch (signum) {

        case SIGALRM:
            mstpd_timerHandler();
            break;

        case SIGTERM:
        case SIGINT:
            VLOG_WARN("%s, sig %d caught", __FUNCTION__, signum);
            mstpd_shutdown = 1;
            break;

        default:
            VLOG_INFO("Ignoring signal %d.\n", signum);
            break;
        }
    }

    return 0;
} /* main */
