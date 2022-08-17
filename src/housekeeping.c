#include <airconf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "housekeeping.h"
#include "air_control.h"
#include "air_support.h"
#include "air_pollution.h"


void std_sighandler(int signal) {

    if (signal == SIGABRT)
        status = EXIT_FAILURE;

    termflag = 1;

}


void *thr_sighandler(void *args) {

    struct signal_thr_opts *sig_op = (struct signal_thr_opts *) args;
    int sig;

    while (1) {

        int s = sigwait(&sig_op->signal_set, &sig);
        if (s != 0)
            bail_out("Bad signal set");

        if (sig == SIGABRT) 
            status = EXIT_FAILURE;
           
        pthread_mutex_lock(sig_op->term_mx);
            termflag = 1;
        pthread_mutex_unlock(sig_op->term_mx); 

    }

}


void thr_sighandler_setup(pthread_t *thr_id, struct signal_thr_opts *sig_op) {

    sigemptyset(&sig_op->signal_set);
    sigaddset(&sig_op->signal_set, SIGTERM);
    sigaddset(&sig_op->signal_set, SIGINT);
    sigaddset(&sig_op->signal_set, SIGABRT);
      
    int err = pthread_sigmask(SIG_BLOCK, &sig_op->signal_set, NULL);
    if (err != 0)
        perror_exit("Failed to set signal mask of main thread");
          
    err = pthread_create(thr_id, NULL, thr_sighandler, sig_op); 
    if (err != 0)
        perror_exit("Failed to create signal handling thread"); 

}


void *check_malloc(size_t size) {

    void *memblock = malloc(size);
    if (memblock == NULL)
        perror_exit("Heap memory allocation failed");
       
    return memblock;
}


void *check_calloc(size_t blocknum, size_t blocksize) {

    void *memblock = calloc(blocknum, blocksize);
    if (memblock == NULL)
        perror_exit("Heap memory allocation failed");
       
    return memblock;
}


int load_vendors(char **mapped_macs) {

    struct stat file_props;
    int vendor_fd = open(DATADIR, O_RDONLY);


    if (vendor_fd == -1)
        perror_exit("Couldn't open vendor id file");

    if (fstat(vendor_fd, &file_props) == -1)
        perror_exit("Couldn't stat vendor id file");

    *mapped_macs = mmap(NULL, file_props.st_size, PROT_READ, MAP_PRIVATE, vendor_fd, 0);
    if (mapped_macs == MAP_FAILED)
        perror_exit("Couldn't map vendor file into memory");

    close(vendor_fd);

    return file_props.st_size;

}


void inj_thr_cleanup(void *args) {

    struct inj_thr_res *resources = (struct inj_thr_res *) args;

    if (resources->packet != NULL) {
      
        free(resources->packet);
        resources->packet = NULL;

    }

    if (resources->dev_handle != NULL) {

        pcap_close(resources->dev_handle);
        resources->dev_handle = NULL;
      
    }
      
}


void free_list(void *head_node, enum res_list type) {

    void *head = *((void **) head_node);

    while (head != NULL) {

        void *old_head = head;

        switch(type) {

            case IW_AP_SCAN:
            head = ((struct wireless_scan *) head)->next;
            break;

            case PACKET_DATA:
            head = ((struct con_info *) head)->next;
            break;

            case THR_ID:
            head = ((struct frame_thrower *) head)->next;
            break;

        }

        free(old_head);

    }

    *((void **) head_node) = NULL;

}


pcap_t *wifi_card_setup(char *interface) {

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *dev_handle;
    int err;

    err = pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf);
    if (err != 0) {

        printf("Failed to initialize pcap library: %s\n", errbuf);
        exit(EXIT_FAILURE);

    }

    dev_handle = pcap_create(interface, errbuf);
    if (dev_handle == NULL) {

        printf("Failed to initialize network card: %s\n", errbuf);
        exit(EXIT_FAILURE);

    }
 
    pcap_set_snaplen(dev_handle, MAX_CAP_SIZE);
    if (pcap_set_promisc(dev_handle, 1) != 0)
    	puts("Warning, could not set promisc mode!");
    else
    if (pcap_can_set_rfmon(dev_handle) != 0)     
        puts("Warning, could not put device into monitor mode!");
    else
    if (pcap_set_rfmon(dev_handle, 0) != 0)
        puts("Error");
    else  
    err = pcap_activate(dev_handle); 
    if (err != 0) {
       
        pcap_perror(dev_handle, "Error when activating device");

        if (err < 0)
            exit(EXIT_FAILURE);

    }

    return dev_handle;
 
}


void capture_session_setup(struct airloop_params *cap_options) {

    if (cap_options->wifi_dev_name == NULL)
        bail_out("Wireless card must be specified");

    if (cap_options->max_contrack <= 0)
        bail_out("Bad connection number");
      

    cap_options->ap_list = scan_local_aps(cap_options->wifi_dev_name, cap_options->cmd_opts); 
    cap_options->start_time = time(NULL);

    cap_options->decode_options = check_calloc(1, sizeof(struct pkt_decode_opts));
    get_local_mac(cap_options->wifi_dev_name, cap_options->decode_options->local_mac);
    main_devhandle = wifi_card_setup(cap_options->wifi_dev_name);
    
}


void capture_session_cleanup(struct airloop_params *cap_options) {

    free_list(&cap_options->ap_list, IW_AP_SCAN);
    free_list(&cap_options->decode_options->framel_head, PACKET_DATA);
    free(cap_options->decode_options);
    pcap_close(main_devhandle);

}

