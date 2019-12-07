#ifndef TCP_H
# define TCP_H

typedef struct {
	// Source Port Number
	unsigned short srcPort;
	// Destination Port Number
	unsigned short destPort;
	// Sequence Number
	unsigned int sequenceNum;
	// Acknowledgment Number
	unsigned int acknowledgmentNum;
	// Header Length
	unsigned int hdrLen: 4;
	// Resereved Zero Space
	unsigned int reserved: 6;
	
	// Control Bits
	struct ctrlbit {
		// Urgent Pointer Valid Flag
		unsigned int urg: 1;
		// Acknowledgment Flag
		unsigned int ack: 1;
		// Push（1:Do not buffer）
		unsigned int psh: 1;
		// TCP Reset Connection Flag
		unsigned int rst: 1;
		// Synchronize Sequence Numbers Flag
		unsigned int syn: 1;
		// End of Data Flag
		unsigned int fin: 1;
	} ctrlbit;
	
	// Window Size
	unsigned short windowSize;
    // Check Sum
    unsigned short checkSum;
	// Urgent Pointer
	unsigned short urgentPointer;
} tcphdr;

#endif