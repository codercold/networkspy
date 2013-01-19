//
// Ping.h
//

#pragma pack(1)


#define ICMP_ECHO_REPLY		0
#define ICMP_DEST_UNREACH	3
#define ICMP_TTL_EXPIRE		11
#define ICMP_ECHO_REQUEST	8


// IP Header -- RFC 791
typedef struct tagIPHDR
{
	u_char  VIHL;			// Version and IHL
	u_char	TOS;			// Type Of Service
	short	TotLen;			// Total Length
	short	ID;				// Identification
	short	FlagOff;		// Flags and Fragment Offset
	u_char	TTL;			// Time To Live
	u_char	Protocol;		// Protocol
	u_short	Checksum;		// Checksum
	struct	in_addr iaSrc;	// Internet Address - Source
	struct	in_addr iaDst;	// Internet Address - Destination
}IPHDR, *PIPHDR;


// ICMP Header - RFC 792
typedef struct tagICMPHDR
{
	u_char	Type;			// Type
	u_char	Code;			// Code
	u_short	Checksum;		// Checksum
	u_short	ID;				// Identification
	u_short	Seq;			// Sequence
	char	Data;			// Data
}ICMPHDR, *PICMPHDR;


typedef struct tagUDPHDR {
	unsigned short	srcport;
	unsigned short	dstport;
	unsigned short	msglen;
	unsigned short	chksum;
} UDPHDR, *PUDPHDER;



#define REQ_DATASIZE 32		// Echo Request Data size

// ICMP Echo Request
typedef struct tagECHOREQUEST
{
	ICMPHDR icmpHdr;
	DWORD	dwTime;
	char	cData[REQ_DATASIZE];
}ECHOREQUEST, *PECHOREQUEST;


// ICMP Echo Reply
typedef struct tagECHOREPLY
{
	IPHDR	ipHdr;
	ECHOREQUEST	echoRequest;
	char    cFiller[256];
}ECHOREPLY, *PECHOREPLY;


// Struct for passing back values to calling function
typedef struct tagECHOPARAMS
{
	u_long			lAddr;
	int				ttl;
	DWORD			dwElapsed;
	struct in_addr  replyFrom;
	u_char			icmpType;
	char			error[128];
}ECHOPARAMS, *PECHOPARAMS;

#pragma pack()


void Ping(PECHOPARAMS);
