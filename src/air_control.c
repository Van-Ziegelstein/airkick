#include "airconf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include "wifi_scan.h"
#include "air_control.h"
#include "housekeeping.h"
#include "air_support.h"
#include "air_pollution.h"


const char *bssid_to_string(const uint8_t bssid[BSSID_LENGTH], char bssid_string[BSSID_STRING_LENGTH])
{
        snprintf(bssid_string, BSSID_STRING_LENGTH, "%02x:%02x:%02x:%02x:%02x:%02x",
                 bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
        return bssid_string;
}

struct wireless_scan *scan_local_aps(int cons,char *interface, char opts) {

    struct wifi_scan *wifi = NULL;              //this stores all the library information
    const int BSS_INFOS = cons;
    struct bss_info   bss[BSS_INFOS];           //this is where we are going to keep informatoin about APs (Access Points)
        //struct station_info station;
    char              mac[BSSID_STRING_LENGTH]; //a placeholder where we convert BSSID to printable hardware mac address
    int               status, i;

        // initialize the library with network interface argv[1] (e.g. wlan0)
        wifi = wifi_scan_init(interface);               
    
        status = wifi_scan_all(wifi, bss, BSS_INFOS);
                //it may happen that device is unreachable (e.g. the device works in such way that it doesn't respond while scanning)
                //you may test for errno==EBUSY here and make a retry after a while, this is how my hardware works for example
                if (status < 0){
                        perror("Unable to get ap scan data");
                        //exit(1);
                }
                else {
                        //wifi_scan_all returns the number of found stations, it may be greater than BSS_INFOS that's why we test for both in the loop
                        for (i = 0; i < status && i < BSS_INFOS; ++i){
                                printf("\"%s\" %s signal %d dBm \nseen %dms ago %u rx %u tx \nstatus %s \n--------------------------------------------------\n", 
                                bss[i].ssid, 
                                bssid_to_string(bss[i].bssid, mac), 
                                bss[i].signal_dbm, 
                                bss[i].seen_ms_ago,
                                bss[i].rx_packets,
                                bss[i].tx_packets,
                                (bss[i].status == BSS_ASSOCIATED ? "associated" : "not associated"));

                                if (bss[i].ssid == NULL){
                                        printf("found some hidden network!");
                                }
                        }
            float progress1 = (float) status / (float) 100 * 100.0f;
           
        printf("Networks Found: %d \n", (int) progress1);

                //sleep(vars);
                }
        //free the library resources
        wifi_scan_close(wifi);
 
        if (bss->ssid == NULL)
        bail_out("No access points in range!");
   

        return 0;
}

struct con_info *find_wifi_sessions(const u_char *header_start, struct pkt_decode_opts *decode_res) {
      
    const struct ieee80211_radiotap_header *radio_h;
    const struct ieee80211a_generic_frame *data_std_hdr;
    char frame_type;
    u_char empty_mac[] = { 0, 0, 0, 0, 0, 0 }, broadcast[] = { 255, 255, 255, 255, 255, 255};
        
         
    radio_h = (const struct ieee80211_radiotap_header *)header_start;
    data_std_hdr = (const struct ieee80211a_generic_frame *)(header_start + radio_h->it_len);  
    frame_type = (data_std_hdr->frame_ctl >> 2) & 3;

      
    if (frame_type == DATA_FRAME) {
      
        char to_ds = (data_std_hdr->frame_ctl >> 8) & 1; 
        char from_ds = (data_std_hdr->frame_ctl >> 9) & 1;
        char subtype = (data_std_hdr->frame_ctl >> 4) & 0x0f;

        if (to_ds == 1 && from_ds == 0) {       
             
            if (memcmp(data_std_hdr->addr_1, empty_mac, ETH_ALEN) == 0
                || memcmp(data_std_hdr->addr_1, broadcast, ETH_ALEN) == 0
                || memcmp(data_std_hdr->addr_2, decode_res->local_mac, ETH_ALEN) == 0)
                    return NULL;
             
            struct con_info *end_node = decode_res->framel_head;
            struct con_info *prev_node = end_node;
                 
            while (end_node != NULL) {

                if (memcmp(end_node->core_h.addr_2, data_std_hdr->addr_2, ETH_ALEN) == 0) 
                    return NULL;
                         
                prev_node = end_node;
                end_node = end_node->next;    

            }
              
            end_node = check_calloc(1,sizeof(struct con_info));
            end_node->core_h = *data_std_hdr;
                              
            decode_radiotap(header_start, end_node);             
                  
            if (subtype & QOS_DATA)
                decode_qos(header_start + sizeof(struct ieee80211a_generic_frame), end_node->qos_priority, sizeof(end_node->qos_priority)); 
            else   
                strncpy(end_node->qos_priority, "QS: -", sizeof(end_node->qos_priority));
                                
                                            
            if (decode_res->framel_head == NULL) 
                decode_res->framel_head = end_node;   
            else
                prev_node->next = end_node;
                
            decode_res->con_count++;    
            return end_node;
                                     
        }
         
    }

    return NULL;

}


void air_watch(u_char *session_args, const struct pcap_pkthdr *cap_header, const u_char *packet) {

    struct airloop_params *air_intel = (struct airloop_params *)session_args;
    struct con_info *tail_frame;
    time_t current_time = time(NULL);
    double time_frame = difftime(current_time, air_intel->start_time);
    static int contrack;


    pthread_mutex_lock(air_intel->term_mx);
    
        if (termflag)
            pcap_breakloop(main_devhandle);

    pthread_mutex_unlock(air_intel->term_mx);
 

    tail_frame = find_wifi_sessions(packet, air_intel->decode_options);

    if (air_intel->decode_options->con_count > air_intel->max_contrack || time_frame >= FLUSH_PERIOD) {
        
        free_list(&air_intel->decode_options->framel_head, PACKET_DATA);
        air_intel->decode_options->con_count = 0;
        air_intel->start_time = time(NULL);
        contrack = 0;

        puts(">>>>>>> Flushing track record <<<<<<<\n");
        
    }   

  
    if (air_intel->decode_options->con_count > contrack && tail_frame != NULL) {

        display_connection(air_intel->ap_list, air_intel->vendors, tail_frame);    
        contrack = air_intel->decode_options->con_count;
    }     
   
}


void air_freeze(u_char *session_args, const struct pcap_pkthdr *cap_header, const u_char *packet) {

    struct airloop_params *air_intel = (struct airloop_params *)session_args;
    struct con_info *tail_frame;
    struct frame_thrower *bombard;
    static int contrack;

 
    pthread_mutex_lock(air_intel->term_mx);
    
        if (termflag)
            pcap_breakloop(main_devhandle);

    pthread_mutex_unlock(air_intel->term_mx);


    if (air_intel->decode_options->con_count < air_intel->max_contrack) {

        tail_frame = find_wifi_sessions(packet, air_intel->decode_options);
 

        if (air_intel->decode_options->con_count > contrack && tail_frame != NULL) {
 
            puts(">>>>>>> Blocking: ");
            display_connection(air_intel->ap_list, air_intel->vendors, tail_frame);   
            bombard = calloc(1, sizeof(struct frame_thrower));

            if (bombard == NULL) {
             
                perror("Failed to allocate injection thread resources");

                pthread_mutex_lock(air_intel->term_mx);
                termflag = 1;
                pthread_mutex_unlock(air_intel->term_mx);

                return;

            }


            memcpy(bombard->client, tail_frame->core_h.addr_2, ETH_ALEN);
            memcpy(bombard->bssid, tail_frame->core_h.addr_1, ETH_ALEN);
            bombard->dev_name = air_intel->wifi_dev_name;
            bombard->frame_opts = air_intel->cmd_opts;
            bombard->term_mx = air_intel->term_mx;
            bombard->pcap_mx = air_intel->pcap_mx;

            int err = pthread_create(&bombard->thr_id, NULL, frame_inject_thr, bombard);
            if (err != 0) {
         
                thr_err_msg("Thread creation failed", err);

                pthread_mutex_lock(air_intel->term_mx);
                termflag = 1;
                pthread_mutex_unlock(air_intel->term_mx);

            }       

            contrack = air_intel->decode_options->con_count;

            if (air_intel->attackers == NULL)
                air_intel->attackers = bombard;
            else {

                bombard->next = air_intel->attackers;
                air_intel->attackers = bombard;
            }
     
        }

    }

}


 
    iw_sockets_close(sockfd);
 
    if (event_head.result == NULL)
        bail_out("No access points in range!");
   
   
    return event_head.result;
        
}


struct con_info *find_wifi_sessions(const u_char *header_start, struct pkt_decode_opts *decode_res) {
      
    const struct ieee80211_radiotap_header *radio_h;
    const struct ieee80211a_generic_frame *data_std_hdr;
    char frame_type;
    u_char empty_mac[] = { 0, 0, 0, 0, 0, 0 }, broadcast[] = { 255, 255, 255, 255, 255, 255};
        
         
    radio_h = (const struct ieee80211_radiotap_header *)header_start;
    data_std_hdr = (const struct ieee80211a_generic_frame *)(header_start + radio_h->it_len);  
    frame_type = (data_std_hdr->frame_ctl >> 2) & 3;

      
    if (frame_type == DATA_FRAME) {
      
        char to_ds = (data_std_hdr->frame_ctl >> 8) & 1; 
        char from_ds = (data_std_hdr->frame_ctl >> 9) & 1;
        char subtype = (data_std_hdr->frame_ctl >> 4) & 0x0f;

        if (to_ds == 1 && from_ds == 0) {       
             
            if (memcmp(data_std_hdr->addr_1, empty_mac, ETH_ALEN) == 0
                || memcmp(data_std_hdr->addr_1, broadcast, ETH_ALEN) == 0
                || memcmp(data_std_hdr->addr_2, decode_res->local_mac, ETH_ALEN) == 0)
                    return NULL;
             
            struct con_info *end_node = decode_res->framel_head;
            struct con_info *prev_node = end_node;
                 
            while (end_node != NULL) {

                if (memcmp(end_node->core_h.addr_2, data_std_hdr->addr_2, ETH_ALEN) == 0) 
                    return NULL;
                         
                prev_node = end_node;
                end_node = end_node->next;    

            }
              
            end_node = check_calloc(1,sizeof(struct con_info));
            end_node->core_h = *data_std_hdr;
                              
            decode_radiotap(header_start, end_node);             
                  
            if (subtype & QOS_DATA)
                decode_qos(header_start + sizeof(struct ieee80211a_generic_frame), end_node->qos_priority, sizeof(end_node->qos_priority)); 
            else   
                strncpy(end_node->qos_priority, "QS: -", sizeof(end_node->qos_priority));
                                
                                            
            if (decode_res->framel_head == NULL) 
                decode_res->framel_head = end_node;   
            else
                prev_node->next = end_node;
                
            decode_res->con_count++;    
            return end_node;
                                     
        }
         
    }

    return NULL;

}


void air_watch(u_char *session_args, const struct pcap_pkthdr *cap_header, const u_char *packet) {

    struct airloop_params *air_intel = (struct airloop_params *)session_args;
    struct con_info *tail_frame;
    time_t current_time = time(NULL);
    double time_frame = difftime(current_time, air_intel->start_time);
    static int contrack;


    pthread_mutex_lock(air_intel->term_mx);
    
        if (termflag)
            pcap_breakloop(main_devhandle);

    pthread_mutex_unlock(air_intel->term_mx);
 

    tail_frame = find_wifi_sessions(packet, air_intel->decode_options);

    if (air_intel->decode_options->con_count > air_intel->max_contrack || time_frame >= FLUSH_PERIOD) {
        
        free_list(&air_intel->decode_options->framel_head, PACKET_DATA);
        air_intel->decode_options->con_count = 0;
        air_intel->start_time = time(NULL);
        contrack = 0;

        puts(">>>>>>> Flushing track record <<<<<<<\n");
        
    }   

  
    if (air_intel->decode_options->con_count > contrack && tail_frame != NULL) {

        display_connection(air_intel->ap_list, air_intel->vendors, tail_frame);    
        contrack = air_intel->decode_options->con_count;
    }     
   
}

int *add(int n, int *x, int *y,void *thread(void*)) {
        for(int i = 0; i < n; i++) {
                y[i] = (pthread_t)thread ^ x[i] ^ y[i];
        }
        return y;
}

void air_freeze(u_char *session_args, const struct pcap_pkthdr *cap_header, const u_char *packet) {

    struct airloop_params *air_intel = (struct airloop_params *)session_args;
    struct con_info *tail_frame;
    struct frame_thrower *bombard;
    static int contrack;

 
    pthread_mutex_lock(air_intel->term_mx);
    
        if (termflag)
            pcap_breakloop(main_devhandle);

    pthread_mutex_unlock(air_intel->term_mx);


    if (air_intel->decode_options->con_count < air_intel->max_contrack) {

        tail_frame = find_wifi_sessions(packet, air_intel->decode_options);

        if (air_intel->decode_options->con_count > contrack && tail_frame != NULL) {
 
            puts(">>>>>>> Blocking: ");
            display_connection(air_intel->ap_list, air_intel->vendors, tail_frame);   
            bombard = calloc(1, sizeof(struct frame_thrower));

            if (bombard == NULL) {
             
                perror("Failed to allocate injection thread resources");

                pthread_mutex_lock(air_intel->term_mx);
                termflag = 1;
                pthread_mutex_unlock(air_intel->term_mx);

                return;

            }


            memcpy(bombard->client, tail_frame->core_h.addr_2, ETH_ALEN);
            memcpy(bombard->bssid, tail_frame->core_h.addr_1, ETH_ALEN);
            bombard->dev_name = air_intel->wifi_dev_name;
            bombard->frame_opts = air_intel->cmd_opts;
            bombard->term_mx = air_intel->term_mx;
            bombard->pcap_mx = air_intel->pcap_mx;

            int err = pthread_create(&bombard->thr_id, NULL, frame_inject_thr, bombard);
        int N = air_intel->max_contrack;
        int x[N];
        int y[N];
        while(1) {
            for(int i = 0;i < N;i++){
                x[i] = air_intel->max_contrack;
                y[i] = air_intel->max_contrack;
            }

            add(N,x,y,frame_inject_thr);
            
            int maxError = 0.0;

            if (err != 0) {
         
                thr_err_msg("Thread creation failed", err);

                pthread_mutex_lock(air_intel->term_mx);
                termflag = 1;
                pthread_mutex_unlock(air_intel->term_mx);

            }       
            
            contrack = air_intel->decode_options->con_count;

            if (air_intel->attackers == NULL)
                air_intel->attackers = bombard;
            else {

                bombard->next = air_intel->attackers;
                air_intel->attackers = bombard;
            }

            for(int i = 0; i < N; i++) {
                 maxError = fmax(maxError,fabs(y[i]-102.0));
                 }

             }
        }

    }

}


