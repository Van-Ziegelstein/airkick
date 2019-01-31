#ifndef AIR_SUPPORT
#define AIR_SUPPORT


#include "main.h"


/* Data structure for connection metadata */
struct con_info {

  struct ieee80211a_generic_frame core_h;
  char qos_priority[6];
  u_int16_t freq;
  char sig_power;
  struct con_info *next;

};


/* Info and error handlers */

void usage();

void perror_exit(char *err_msg); 

void bail_out(char *err_msg);

void thr_err_msg(char *err_msg, int errnum);


/* Support functions to parse the packet headers. */

void get_local_mac(char *interface, u_char *local_mac);

void decode_radiotap(const u_char *header_start, struct con_info *con_params);

void decode_qos(const u_char *header_start, char *priority_buffer, int priority_buffsize);

void prefix_lookup(unsigned char *client, char *vendors); 

void display_connection(struct wireless_scan *ap_entry, char *vendors, struct con_info *frame);

#endif
