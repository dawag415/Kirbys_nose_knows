#ifndef BPFDATA_H
# define BPFDATA_H

#include <stdlib.h>
#include <stdio.h> 
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <net/if.h>
#include <poll.h>

typedef struct BPFoption {
    //Network Device Interface
    char netDev[32];
    //Buffer Length
    unsigned int bufLen;
} bpfopt;

typedef struct BPFSniffer{
    //File Descriptor for BPF
    int fd; 
    //Name of BPF
    char devName[11];
    //Buffer Length
    unsigned int bufLen;
    char *buf;
} bpfsnif;

//Prints modifiable options 
void print_options(bpfopt, FILE *log);
//Initialize sniffer struct and run checks
int init_sniffer(bpfopt opt, bpfsnif *snif);
//Finds BPF Device
void pick_device(bpfsnif *snif);
//Print parameters for Sniffer 
void print_params(bpfsnif snif, FILE *log);
//Free buffer and close files
void clean_up(FILE *log, bpfsnif *snif);
#endif