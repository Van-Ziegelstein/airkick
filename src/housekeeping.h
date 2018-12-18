#ifndef HOUSEKEEPING
#define HOUSEKEEPING

#include "main.h"


/* Data types for the linked lists and the threaded signal handler */
enum res_list { IW_AP_SCAN, PACKET_DATA, THR_ID };

struct signal_thr_opts {
    
    sigset_t signal_set;
    pthread_mutex_t *term_mx;
};


/* Signal handlers */

void std_sighandler(int signal);

void *thr_sighandler(void *args);

void thr_sighandler_setup(pthread_t *thr_id, struct signal_thr_opts *sig_op);


/* Some wrappers around standard memory allocation routines. */

void *check_malloc(size_t size);

void *check_calloc(size_t blocknum, size_t blocksize);


/* Session management */

void inj_thr_cleanup(void *args);

void free_list(void *head_node, enum res_list type);

pcap_t *pcap_init(char *interface);

void capture_session_setup(struct airloop_params *cap_options);

void capture_session_cleanup(struct airloop_params *cap_options);

#endif
