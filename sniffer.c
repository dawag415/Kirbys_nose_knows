#include "sniffer.h"
#include "eth.h"
#include "ip.h"
#include "tcp.h"


//OPTIONS
//modify the value in quotes to adjust network device.
#define NETWORK_DEVICE "en0"
//modify the value in quotes to adjust the buffer size.
#define BUFFER_LENGTH 4096
int main()
{
    //All variables and structs declared
    FILE *log;
    bpfopt opt;
    bpfsnif snif;
    int readBytes;
    char *bpfBuf;
    struct bpf_hdr* bpfPacket;

    //Open log file
    log = fopen("log.txt", "a");
    if(log==NULL)
        perror("Error opening log.txt");
    // Initialize options struct and print options to log  
    strcpy(opt.netDev, NETWORK_DEVICE);
    opt.bufLen = BUFFER_LENGTH;
    print_options(opt, log);
    //Find device and open
    pick_device(&snif);
    fprintf(log, "open %s\n", snif.devName);
    //Initialize sniffer struct and run checks
    if (init_sniffer(opt, &snif) == -1)
        return -1;
    //Print sniffer params
    print_params(snif, log);
    
    readBytes=0;
    bpfBuf = (char *)malloc(sizeof(char) * snif.bufLen);
   //Start Sniffing
    while (1) {    
        // Clear Buffer
        memset(bpfBuf, 0, snif.bufLen);
        //Read
        readBytes = read(snif.fd, bpfBuf, snif.bufLen);
        
        if (readBytes == -1) {
            perror("ERROR: Could not read()");
            return errno;
        } 
        if (readBytes > 0) {
            char *ptr = 0;
            
            while((int)ptr + sizeof(bpfBuf) < readBytes) {
                bpfPacket = (struct bpf_hdr*)((long)bpfBuf + (long)ptr);
                
                fprintf(log, "------------------------------------------------------------------\n");
                fprintf(log, "\tEthernet Frame\n");
                ethhdr* eth = (ethhdr*)((long)bpfBuf + (long)ptr + bpfPacket->bh_hdrlen);
                fprintf(log, "\t\tSource MAC Address: %x:%x:%x:%x:%x:%x\n",
                    eth->srcMacAddr[0], eth->srcMacAddr[1], eth->srcMacAddr[2],
                        eth->srcMacAddr[3], eth->srcMacAddr[4], eth->srcMacAddr[5]);
                fprintf(log, "\t\tDestination MAC Address: %x:%x:%x:%x:%x:%x\n",
                    eth->destMacAddr[0], eth->destMacAddr[1], eth->destMacAddr[2],
                        eth->destMacAddr[3], eth->destMacAddr[4], eth->destMacAddr[5]);                
                if (eth->type == TYPE_IPV4) {
                    fprintf(log, "\t\tType: IPv4, %x\n", eth->type);
                    iphdr* ip = (iphdr*)((long)eth + sizeof(ethhdr));
                    fprintf(log, "\tIP Frame\n");
                    fprintf(log, "\t\tHeader Length: %d\n", ip->hdrLen * 4);
                    fprintf(log, "\t\tVersion: %d\n", ip->version);
                    fprintf(log, "\t\tTTL: %d\n", ip->ttl);
                    fprintf(log, "\t\tDestination IP Address: %d.%d.%d.%d\n", ip->destIPAddr[0],
                        ip->destIPAddr[1], ip->destIPAddr[2], ip->destIPAddr[3]);
                    fprintf(log, "\t\tSource IP Address: %d.%d.%d.%d\n", ip->srcIPAddr[0],
                        ip->srcIPAddr[1],ip->srcIPAddr[2], ip->srcIPAddr[3]);
                    if (ip->protocol == IP_PROTOCOL_TCP) {
                        tcphdr* tcp = (tcphdr*)((long)ip + (ip->hdrLen * 4));
                        fprintf(log, "\tTCP Frame\n");
                        fprintf(log, "\t\tDestination Port: %d\n", tcp->destPort);
                        fprintf(log, "\t\tSource Port: %d\n", tcp->srcPort);
                    }
                } else {
                    fprintf(log, "\t\ttype: Other, %x\n", eth->type);
                }
                // Move to the next packet (use BPF_WORDALIGN to consider padding）
                ptr += BPF_WORDALIGN(bpfPacket->bh_hdrlen + bpfPacket->bh_caplen);
            }
        }
    }
    clean_up(log, &snif);        
    return 0;
}