#ifndef AIR_CONTROL
#define AIR_CONTROL

#include "main.h"


/* Initial arguments to be passed to the injection threads */
struct frame_thrower {

    pthread_t thr_id;
    pthread_mutex_t *term_mx;
    pthread_mutex_t *pcap_mx;
    u_char client[ETH_ALEN];
    u_char bssid[ETH_ALEN];
    char *dev_name;
    char frame_opts;
    struct frame_thrower *next;
    
};

struct pkt_decode_opts {
     
     struct con_info *framel_head; 
     u_char local_mac[ETH_ALEN];
     int con_count;
     
};


/* main routines to interact with the wireless world */

struct wireless_scan *scan_local_aps(char *interface, char opts);

void air_watch(u_char *session_args, const struct pcap_pkthdr *cap_header, const u_char *packet);

void air_freeze(u_char *session_args, const struct pcap_pkthdr *cap_header, const u_char *packet);

#endif
