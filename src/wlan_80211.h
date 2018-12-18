#ifndef __80211_H
#define __80211_H 1

#include <stdint.h>

/*  Some constants and structures to
 *  make sense" of wireless frames.
 *  Currently more stuff than needed.
 */


/* Radiotap bitmask */
#define TSFT 0x01
#define FlAGS 0x02
#define RATE 0x04
#define CHANNEL 0x08
#define FHSS 0x10
#define ANTENNA_SIGNAL 0x20
#define ANTENNA_NOISE 0x40
#define LOCK_QUALITY 0x80
#define TX_ATTENUATION 0x100
#define DB_TX_ATTENUATION 0x200
#define DBM_TX_POWER 0x400
#define ANTENNA 0x800
#define DB_ANTENNA_SIGNAL 0x1000
#define DB_ANTENNA_NOISE 0x2000
#define RX_FLAGS 0x4000
#define MCS 0x8000
#define A_MPDU_STATUS 0x10000
#define VHT 0x20000
#define TIMESTAMP 0x40000
#define EXTENDED_BITMAP 0x40000000


/* Wifi Frame Types */
#define MANAGEMENT_FRAME 0
#define CONTROL_FRAME 1
#define DATA_FRAME 2
#define RESERVED_FRAME_TYPE 3

/* Management subtypes */
#define ASSOCIATION_REQUEST 0
#define ASSOCIATION_RESPONSE 1
#define REASSOCIATION_REQUEST 2
#define REASSOCIATION_RESPONSE 3
#define PROBE_REQUEST 4
#define PROBE_RESPONSE 5
#define BEACON 8
#define ATIM 9
#define DISASSOCIATION 10
#define AUTHENTICATION 11
#define DEAUTHENTICATION 12
#define ACTION 13
#define ACTION_NO_ACK 14

/* Deauthentication reason codes */
#define UNSPECIFIED_REASON 1
#define LEAVING 3
#define INACTIVE 4

/* Data subtypes */
#define DATA 0
#define DATA_CF_ACK 1
#define DATA_CF_POLL 2
#define DATA_CF_ACK_CF_POLL 3
#define DATA_NULL 4
#define CF_ACK 5
#define CF_POLL 6
#define CF_ACK_CF_POLL 7
#define QOS_DATA 8
#define QOS_DATA_CF_ACK 9
#define QOS_DATA_CF_POLL 10
#define QOS_DATA_CF_ACK_CF_POLL 11
#define QOS_NULL 12
#define QOS_RESERVED 13
#define QOS_CF_POLL 14
#define QOS_CF_ACK_CF_POLL 15

/* Data QoS field TID values */
#define BE 0
#define BK 1
#define TID_ 2
#define EE 3
#define CL 4
#define VI 5
#define VO 6
#define NC 7

/* Some helpful constants */
#define QOS_FIELD_LEN 2
#define HT_CTL_FIELD_LEN 4
#define FRAME_CTL_LEN 2
#define FCS_LEN 4
#define DEAUTH_REASON_FIELD_LEN 2
#define SSID_OFFSET 12


struct ieee80211_radiotap_header {

        uint8_t    it_version;     
        uint8_t    it_pad;
        uint16_t   it_len;         
        uint32_t   it_present;     

}__attribute__((__packed__));


# if __BYTE_ORDER == __LITTLE_ENDIAN
struct frame_ctl_section {

  unsigned int   proto_version:2 ;
  unsigned int   type:2 ;
  unsigned int   subtype:4 ;
  unsigned int   to_ds:1 ;
  unsigned int   from_ds:1 ;
  unsigned int   more_frag:1 ;
  unsigned int   retry:1 ;
  unsigned int   pwr_mgt:1 ;
  unsigned int   more_data:1 ;
  unsigned int   protection:1 ;  
  unsigned int   order:1 ;

}__attribute__ ((__packed__));    
#endif
# if __BYTE_ORDER == __BIG_ENDIAN
struct frame_ctl_section {

  unsigned int   subtype:4 ;
  unsigned int   type:2 ;
  unsigned int   proto_version:2 ;
  unsigned int   order:1 ;
  unsigned int   protection:1 ;
  unsigned int   more_data:1 ;
  unsigned int   pwr_mgt:1 ;
  unsigned int   retry:1 ;
  unsigned int   more_frag:1 ;
  unsigned int   from_ds:1 ;
  unsigned int   to_ds:1 ; 

}__attribute__ ((__packed__));  
#endif  


//This struct serves as a template for standard managment and data frames.

struct ieee80211a_generic_frame {
    
  uint16_t duration_id;
  unsigned char  addr_1[ETH_ALEN];
  unsigned char  addr_2[ETH_ALEN];
  unsigned char  addr_3[ETH_ALEN];
  uint16_t seq_ctl;

}__attribute__ ((__packed__));

#endif
