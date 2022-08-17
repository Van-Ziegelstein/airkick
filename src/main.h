#ifndef AIRKICK_MAIN
#define AIRKICK_MAIN

#include <iwlib.h>
#include <linux/wireless.h>
#include <pcap.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <stdint.h>
#include "wlan_80211.h"


/* Commandline options */
#define PASSIVE_SCAN (1 << 0)
#define DISASSOCIATION_REQ (1 << 1)

/* declaration of shared global variables */

extern int termflag;
extern pcap_t *main_devhandle;
extern int status;

/* data structures */


struct airloop_params {

    struct wireless_scan *ap_list;
    struct pkt_decode_opts *decode_options; 
    pthread_mutex_t *term_mx;
    pthread_mutex_t *pcap_mx;
    int max_contrack;   
    time_t start_time;
    struct frame_thrower *attackers; 
    char *wifi_dev_name;
    char *vendors;
    char cmd_opts;
};

#endif

