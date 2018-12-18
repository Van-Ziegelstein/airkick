#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include "air_support.h"
#include "config.h"

#define GNU_STRERROR_BUFFSIZE 1024

void usage() {

   char *messages[22] = { 
   
        "This program can bump wlan clients off the network by sending spoofed deauthentication frames.\n\n",
        "Currently there are three operation modes:\n\n", 
        "- Mode 1: Tracking of connections in the vicinity. Intended to help identify potential targets.\n",
        "Invocation: "PACKAGE_NAME" -m -i <interface> [ -c max_connections ] [ -t active|passive ]\n\n",
        "- Mode 2: Deauthentication of a single client.\n",
        "Invocation: "PACKAGE_NAME" -d -i <interface> -s <spoofed mac> -b <bssid>\n\n",
        "- Mode 3 (still experimental): Mass DoS-style attack against all connections in the local area.\n",
        "Invocation: "PACKAGE_NAME" -f -i <interface> [ -c max_connections ] [ -t active|passive ]\n\n",
	"Options:\n\n",
	"-s: the client mac address to spoof (format: xx:xx:xx:xx:xx:xx).\n",
	"-b: the bssid of the access point (format: xx:xx:xx:xx:xx:xx).\n",
	"-c: the maximum amount of connections to track in mode 1 and 3.\n",
	"-t: whether to query the local access points in an active scan or observe their beacon frames passively.\n\n",
        "Technical remarks: The default maximum of tracked connections is determined at compile time.\n",
        "Before you make use of the -t option, beware that the deauthentication flood of Mode 3 is threaded!\n",
        "The program will craft packets for every identified client in a seperate thread.\n",
        "Increase at your own risk.\n\n",
        "A word of caution: The program keeps clients deauthenticated by repeatedly sending frames.\n",
        "Even when targeting a single client as in Mode 2 this sudden increase in deauthentication frames\n",
        "can be observed with packet sniffers and thus possibly alert the local network admin.\n",
        "As for Mode 3...\n",
        "Well, all network security assets will have to be sleeping for that flood to pass unnoticed.\n\n"    
        
   };     

   for (int i = 0; i < 22; i++)
        printf("%s", messages[i]);
   
   exit(EXIT_SUCCESS);

}


void perror_exit(char *err_msg) {
     
     perror(err_msg);
     exit(EXIT_FAILURE);
}


void bail_out(char *err_msg) {

    puts(err_msg);
    exit(EXIT_FAILURE);
}


void thr_err_msg(char *err_msg, int errnum) {

    char transl_code[GNU_STRERROR_BUFFSIZE];
     
    if (strerror_r(errnum, transl_code, GNU_STRERROR_BUFFSIZE) != 0)
       puts(err_msg);
    else   
       printf("%s: %s\n", err_msg, transl_code);

}


void get_local_mac(char *interface, u_char *local_mac) {
 
  int sockfd;
  struct ifreq devparams;
 
  sockfd = iw_sockets_open();
  if (sockfd == -1)
      perror_exit("Socket creation failed");
       
  snprintf(devparams.ifr_name, IFNAMSIZ, "%s", interface); 
 
  if (ioctl(sockfd, SIOCGIFHWADDR, &devparams) == -1)
      perror_exit("Ioctl query failed");   
        
  if (devparams.ifr_hwaddr.sa_family != ARPHRD_ETHER)
      bail_out("Provided device is not an ethernet interface");  
 
  memcpy(local_mac, devparams.ifr_hwaddr.sa_data, ETH_ALEN);
 
  iw_sockets_close(sockfd);

}


void decode_radiotap(const u_char *header_start, struct con_info *con_params)  {
   
  const struct ieee80211_radiotap_header *radio_h;
  const uint *data_pos;
   
  radio_h = (const struct ieee80211_radiotap_header *)header_start;
  data_pos = &radio_h->it_present;
 
   
  do
  data_pos++;
  while (*data_pos & EXTENDED_BITMAP && radio_h->it_present & EXTENDED_BITMAP);
          
   
  for (int i = TSFT; i <= ANTENNA_SIGNAL; i = i<<1) {

      switch (radio_h->it_present & i) {

         case TSFT: 
         data_pos = (const uint *)((u_int64_t *)data_pos + 1);
         break;
   
   
         case FlAGS:
         data_pos = (const uint *)((uint8_t *)data_pos + 1);
         break;
   
   
         case RATE:
         data_pos = (const uint *)((uint8_t *)data_pos + 1);
         break;       

         case CHANNEL:
         con_params->freq = *((u_int16_t *)data_pos); 
         data_pos = (const uint *)((u_int16_t *)data_pos + 2);
         break;
   
   
         case FHSS:
         data_pos = (const uint *)((u_int8_t *)data_pos + 2);
         break;
   
         case ANTENNA_SIGNAL:
         con_params->sig_power = *((char *)data_pos);
         break;
   
      }

  } 
   
}


void decode_qos(const u_char *header_start, char *priority_buffer, int priority_buffsize) {

  const struct ieee80211_qos_control_field *qos_hdr_field;
   
  qos_hdr_field = (const struct ieee80211_qos_control_field *)header_start;
   
   
  if (qos_hdr_field->tid & BE || qos_hdr_field->tid & EE)
      strncpy(priority_buffer, "P: BE", priority_buffsize);
       
  else if (qos_hdr_field->tid & BK || qos_hdr_field->tid & TID_)
           strncpy(priority_buffer, "P: BG", priority_buffsize);    
        
  else if (qos_hdr_field->tid & CL || qos_hdr_field->tid & VI)
           strncpy(priority_buffer, "P: VI", priority_buffsize);     
   
  else if (qos_hdr_field->tid & VO || qos_hdr_field->tid & NC)
            strncpy(priority_buffer, "P: VO", priority_buffsize); 
       
  else
      strncpy(priority_buffer, "P: XX", priority_buffsize);   

}


void display_connection(struct wireless_scan *ap_entry, struct con_info *frame) {

  printf("[ Client: %02x", frame->core_h.addr_2[0]);
  for (int i = 1; i < ETH_ALEN; i++) 
       printf(":%02x", frame->core_h.addr_2[i]); 
   
  printf(" BSSID: %02x", frame->core_h.addr_1[0]);
  for (int i = 1; i < ETH_ALEN; i++) 
       printf(":%02x", frame->core_h.addr_1[i]); 
       
  while (ap_entry != NULL) {
           
         if (memcmp(frame->core_h.addr_1, ap_entry->ap_addr.sa_data, ETH_ALEN) == 0
             && ap_entry->b.has_essid == 1)
                printf(" SSID: %s", ap_entry->b.essid);
           
         ap_entry = ap_entry->next;    
               
  }
              
  printf(" %s ]\n", frame->qos_priority);             
  printf("{ Freq: %huMHz\tTX: %ddbm }\n\n", frame->freq, frame->sig_power);  

}


