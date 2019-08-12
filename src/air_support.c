#include "airconf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <stropts.h>
#include "air_support.h"

#define VENDOR_REGEX_LEN 41


void usage() {

   char *messages[15] = { 
   
	PACKAGE_STRING"\n\n",
        "Utility to bump wlan clients off the network with spoofed deauthentication or disassociation frames.\n",
        "Currently there are three operation modes:\n\n", 
        "- Mode 1: Tracking connections in the vicinity.\n",
        "Invocation: "PACKAGE_NAME" -m -i <interface> [ -c max_connections ] [ -p ]\n\n",
        "- Mode 2: Deauthentication of a single client.\n",
        "Invocation: "PACKAGE_NAME" -d -i <interface> -s <spoofed mac> -b <bssid> [ -a ]\n\n",
        "- Mode 3: DoS-style attack against all connections in the local area.\n",
        "Invocation: "PACKAGE_NAME" -f -i <interface> [ -c max_connections ] [ -p ] [ -a ]\n\n",
	"Options:\n\n",
	"-s: the client mac address to spoof (format: xx:xx:xx:xx:xx:xx).\n",
	"-b: the bssid of the access point (format: xx:xx:xx:xx:xx:xx).\n",
	"-c: the maximum amount of connections to track in mode 1 and 3.\n",
	"-p: Don't send probe requests but observe beacon frames passively instead.\n",
	"-a: Send disassociation instead of deauthentication frames.\n\n" 
        
   };     

   for (int i = 0; i < 15; i++)
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

    char transl_code[STRERROR_BUFFSIZE];
     
    if (strerror_r(errnum, transl_code, STRERROR_BUFFSIZE) != 0)
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
  int old_offset, data_offset = 0;
   
  radio_h = (const struct ieee80211_radiotap_header *)header_start;
   
  do {
     old_offset = data_offset;
     data_offset += sizeof(uint32_t);
  } while (*(uint32_t *)((char *)&radio_h->it_present + old_offset) & EXTENDED_BITMAP);
          
   
  for (int i = TSFT; i <= ANTENNA_SIGNAL; i = i<<1) {

      switch (radio_h->it_present & i) {

         case TSFT: 
         data_offset += sizeof(uint64_t);
         break;
   
   
         case FlAGS:
         data_offset += sizeof(uint8_t);
         break;
   
   
         case RATE:
         data_offset += sizeof(uint8_t);
         break;       

         case CHANNEL:
         con_params->freq = *(uint16_t *)((char *)&radio_h->it_present + data_offset); 
         data_offset += 2 * sizeof(uint16_t);
         break;
   
   
         case FHSS:
         data_offset += 2 * sizeof(uint8_t);
         break;
   
         case ANTENNA_SIGNAL:
         con_params->sig_power = *((char *)&radio_h->it_present + data_offset);
         break;
   
      }

  } 
   
}


void decode_qos(const u_char *header_start, char *priority_buffer, int priority_buffsize) {

  uint16_t qos_hdr_field = *((const uint16_t *)header_start);
  char tid = qos_hdr_field >> 12;
   
   
  if (tid == BE || tid == EE)
      strncpy(priority_buffer, "P: BE", priority_buffsize);
       
  else if (tid == BK || tid == TID_)
           strncpy(priority_buffer, "P: BG", priority_buffsize);    
        
  else if (tid == CL || tid == VI)
           strncpy(priority_buffer, "P: VI", priority_buffsize);     
   
  else if (tid == VO || tid == NC)
           strncpy(priority_buffer, "P: VO", priority_buffsize); 
       
  else
      strncpy(priority_buffer, "P: ??", priority_buffsize);   

}


void prefix_lookup(unsigned char *client, char *vendors) {

     char prefix_reg[VENDOR_REGEX_LEN + 1];
     snprintf(prefix_reg, VENDOR_REGEX_LEN + 1, "%02x%02x%02x[[:blank:]]+([[:graph:][:blank:]]+)", client[0], client[1], client[2]);
     regex_t pattern_buff;
     regmatch_t match[2];
  
  
     regcomp(&pattern_buff, prefix_reg, REG_EXTENDED|REG_ICASE);

     if (regexec(&pattern_buff, vendors, 2, match, 0) == 0 && match[1].rm_so != -1) 
        fwrite(vendors + match[1].rm_so, match[1].rm_eo - match[1].rm_so, 1, stdout);
     else 
        fputs("unknown", stdout); 

     regfree(&pattern_buff);   

}


void display_connection(struct wireless_scan *ap_entry, char *vendor, struct con_info *frame) {

  printf("[ Client: %02x", frame->core_h.addr_2[0]);
  for (int i = 1; i < ETH_ALEN; i++) 
       printf(":%02x", frame->core_h.addr_2[i]); 
   
  printf(" BSSID: %02x", frame->core_h.addr_1[0]);
  for (int i = 1; i < ETH_ALEN; i++) 
       printf(":%02x", frame->core_h.addr_1[i]); 
       
  while (ap_entry != NULL) {
           
         if (memcmp(frame->core_h.addr_1, ap_entry->ap_addr.sa_data, ETH_ALEN) == 0
             && ap_entry->b.has_essid) {
                
		printf(" SSID: %s", ap_entry->b.essid);
		break;
         }  

         ap_entry = ap_entry->next;    
               
  }
              
  printf(" %s ]\n", frame->qos_priority);             
  printf("{ Freq: %huMHz\tTX: %ddbm }\n", frame->freq, frame->sig_power);  

  fputs("{ Card vendor: ", stdout);
  prefix_lookup(frame->core_h.addr_2, vendor);
  printf(" }\n\n");

}


