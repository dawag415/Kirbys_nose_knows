#ifndef ETH_H
# define ETH_H
// Lil Endian Version Type Macros
# define TYPE_IPV4        0x0008
# define TYPE_ARP         0x0608
# define TYPE_RARP        0x3580
# define TYPE_APPLE_TALK  0x9b80
# define TYPE_IEEE8021Q   0x0081
# define TYPE_NETWARE_IPX 0x3781

typedef struct Ethernet_Header{
    // Destination Mac Address
    unsigned char destMacAddr[6];
    // Source Mac Address
    unsigned char srcMacAddr[6];
    // Lil Endian Type
    unsigned short type;
} ethhdr;

#endif
