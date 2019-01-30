#ifndef AIR_POLLUTION
#define AIR_POLLUTION

#include "main.h"


/* this holds the dynamic resources of the injection threads. */
struct inj_thr_res {

    pcap_t *dev_handle;
    u_char *packet;

};


void frame_inject(char *device, u_char *client, u_char *bssid, char frame_opts);

void *frame_inject_thr(void *job_args);

#endif
