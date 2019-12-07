#ifndef IP_H
# define IP_H
//IP Protocols
# define IP_PROTOCOL_ICMP    1
# define IP_PROTOCOL_IGMP    2
# define IP_PROTOCOL_IPINIP  3
# define IP_PROTOCOL_TCP     6
# define IP_PROTOCOL_UDP     17

typedef struct IPOption{
    unsigned char  flag;
    unsigned char  length;
    unsigned short data;
} ipopt;

typedef struct IPHeader{
// Lil Endian
    unsigned char hdrLen: 4;
    unsigned char version: 4;
    // Service Type (IP Packet Priority)
    unsigned char tos;
    // The total IP packet size counted in bytes
    unsigned short totalLength;
    // IP Identification ID
    unsigned short id;
    // For Fragmentation of Packet
    unsigned short fragment;
    // Time to Live
    unsigned char ttl;
    // IP Protocol Number
    unsigned char protocol;
    // IP Checksum
    unsigned short checkSum;
    // Source Mac Address
    unsigned char srcIPAddr[4];
    // Destination IP Address
    unsigned char destIPAddr[4];
    // IP Options
    ipopt opt;
} iphdr;

#endif