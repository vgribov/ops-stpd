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


#include "mstp.h"
#include "mstp_ovsdb_if.h"
#include "mstp_cmn.h"

VLOG_DEFINE_THIS_MODULE(mstpd);

bool exiting = false;
static unixctl_cb_func mstpd_unixctl_dump;
static unixctl_cb_func ops_mstpd_exit;

extern int mstpd_shutdown;

/**
 * ovs-appctl interface callback function to dump internal debug information.
 * This top level debug dump function calls other functions to dump mstpd
 * daemon's internal data. The function arguments in argv are used to
 * control the debug output.
 *
 * @param conn connection to ovs-appctl interface.
 * @param argc number of arguments.
 * @param argv array of arguments.
 * @param OVS_UNUSED aux argument not used.
 */
static void
mstpd_unixctl_dump(struct unixctl_conn *conn, int argc,
                   const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    mstpd_debug_dump(&ds, argc, argv);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
} /* mstpd_unixctl_dump */

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
 * mstpd daemon's main initialization function.  Responsible for
 * creating various protocol & OVSDB interface threads.
 *
 * @param db_path pathname for OVSDB connection.
 */
static void
mstpd_init(const char *db_path, struct unixctl_server *appctl)
{
    int rc;
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
    unixctl_command_register("mstpd/dump", "", 0, 2, mstpd_unixctl_dump, NULL);

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