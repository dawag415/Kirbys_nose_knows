#include "sniffer.h"

//Finds BPF Device
void pick_device(bpfsnif *snif){
    char name[11]={0};
    for (int i = 0; i < 99; ++i) {
        sprintf(name, "/dev/bpf%i", i);
        snif->fd = open(name, O_RDWR);
        if (snif->fd != -1) { 
            strcpy(snif->devName, name);
            return;
        }
    }
}

//Prints modifiable options 
void print_options(bpfopt opt, FILE *log){
    fprintf(log ,"BPF Options:\n");
    fprintf(log, "  Network Device Interface: %s\n", opt.netDev);
    fprintf(log, "  Buffer Length: %d\n", opt.bufLen);
}

//Initialize sniffer struct and run checks
int init_sniffer(bpfopt opt, bpfsnif *snif)
{
    unsigned int enable = 1;

    if (opt.bufLen == 0) {
        //Get buffer length 
        if (ioctl(snif->fd, BIOCGBLEN, &snif->bufLen) == -1) {
            perror("ERROR: ioctl BIOCGBLEN");
            return -1;
        }
    } else {
        //Set buffer length with BIOSETIF as it must be set before the file
        //is attached to the interface 
        if (ioctl(snif->fd, BIOCSBLEN, &opt.bufLen) == -1) {
            perror("ERROR: ioctl BIOCSBLEN");
            return -1;
        }
        snif->bufLen = opt.bufLen;
    }
        struct ifreq interface;

     // Link to network interface
    strcpy(interface.ifr_name, opt.netDev);
    if(ioctl(snif->fd, BIOCSETIF, &interface) > 0) {
        perror("ioctl BIOCSETIF");
        return -1;
    }
    // Read immediatley upon receipt for enabled
    if (ioctl(snif->fd, BIOCIMMEDIATE, &enable) == -1) {
        perror("ioctl BIOCIMMEDIATE");
        return -1;
    }
    // Force promiscuois mode to process all packets. Not just those destined for the local host 
    if (ioctl(snif->fd, BIOCPROMISC, NULL) == -1) {
        perror("ioctl BIOCPROMISC");
        return -1;
    }
    return 1;
}

//Print parameters for Sniffer
void print_params(bpfsnif snif, FILE *log){
    fprintf(log, "BpfSniffer:\n");
    fprintf(log, "\t\tOpened BPF Device: %s\n", snif.devName);
    fprintf(log, "\t\tBuffer Length: %d\n", snif.bufLen);
}

//Free buffer and close files
void clean_up(FILE *log, bpfsnif *snif){
    free(snif->buf);
    fclose(log);
    close(snif->fd);
}

