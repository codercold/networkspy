#ifndef _STRUCTS_H
#define _STRUCTS_H

#pragma pack(1)
// NELSON #pragma comment(linker,"/FILEALIGN:0x200")


typedef struct {
	HWND	hWnd;
	BOOL	bContinue;
	HWND	hwnd, hwndList, hwndStatus;  // added to accomodate traceroute
	char	hostname[256];
} PARAMS, *PPARAMS;

typedef struct {
	HWND	hwnd;
	BOOL	bContinue;
	char	filename[MAX_PATH];
} DPARAMS, *PDPARAMS;


struct packet {
	int				size;
	unsigned char	*data;
	SYSTEMTIME		time;
};

struct packet_list {
	struct packet_list	*next;
	BYTE				*data;
	int					size;
	SYSTEMTIME			time;
};

typedef struct {
	int		mode;
	char	*buffer;
	HWND	hDlg;
} PRINTPARAMS;



/* Link Layer frame types */

struct ethernet_II {
	unsigned char	destaddr[6];
	unsigned char	sourceaddr[6];
	unsigned short	type;
};


struct ethernet_802_3 {
	unsigned char	destaddr[6];
	unsigned char	sourceaddr[6];
	unsigned short	length;
	/* 802.2 LLC */
	unsigned char	dsap;	// 0xFF for Novell
	unsigned char	ssap;	// 0xFF for Novell
	unsigned char	cntl;
	/* 802.2 SNAP */
	unsigned char	orgcode[3];
	unsigned short	type;
};




/* Transport layer structs */

struct iphdr {
	unsigned char	verlen;
	unsigned char	tos;
	unsigned short	totlen;
	unsigned short	id;
	unsigned short	frag;  /* first three bits are flags */
	unsigned char	ttl;
	unsigned char	prot;
	unsigned short	chksum;
	unsigned long	sourceip;
	unsigned long	destip;
};

struct arppkt {
	unsigned short	hwtype;
	unsigned short	protocol;
	unsigned char	hlen;
	unsigned char	plen;
	unsigned short	operation;
	unsigned char	sender_ha[6];
	unsigned char	sender_ip[4];
	unsigned char	target_ha[6];
	unsigned char	target_ip[4];
};

struct udphdr {
	unsigned short	srcport;
	unsigned short	dstport;
	unsigned short	msglen;
	unsigned short	chksum;
};

struct tcphdr {
	unsigned short  srcport;
	unsigned short  dstport;
	unsigned long	seqno;
	unsigned long	ackno;
	unsigned char	len;	/* first 4 bits */
	unsigned char	flags;	/* last 6 bits */
	unsigned short  winsize;
	unsigned short  chksum;
	unsigned short  urgentptr;
//	unsigned char	type;
//	unsigned char   len;
//	unsigned short  data;
};



struct icmphdr {	
	unsigned char type;	
	unsigned char code;	
	unsigned short chksum;
	unsigned short id;	
	unsigned short seqno;
};


struct igmphdr {
	unsigned char ver_type;
	unsigned char unused;
	unsigned short checksum;
	unsigned char ip_address[4];
};

struct filters {
	DWORD		arp;
	DWORD		icmp;
	DWORD		udp;
	DWORD		tcp;
	DWORD		igmp;
	DWORD		unknown;
	DWORD		srcip;
	DWORD		destip;
	DWORD		port;
	int		nSourceIPs;
	int		nDestinationIPs;
	unsigned short	the_port; 
} filter;


// IP Header -- RFC 2281
typedef struct tagHSRP
{
	unsigned char   version;		// Version  (expect 0)
	unsigned char	opcode;			// Op Code	(hello, coup or resign)
	unsigned char	state;			// State	(initial, learn, listen, speak, standby, active) 
	unsigned char	hellotime;		// Hello Time
	unsigned char	holdtime;		// Hold Time
	unsigned char	priority;		// Priority
	unsigned char	group;			// Group
	unsigned char	reserved;		// not used
	unsigned char	auth_data[8];	// Authentication Data
	unsigned long	virtualip;		// Virtual IP Address
		
} HSRP, *PHSRP;


#define HASHTABLE_SIZE	199
#define UDP	0
#define TCP 1

struct hash_entry {
	struct			hash_entry *next;
	char			type;
	unsigned short	port;
	char			str[16];
	unsigned int	data;	/* miscellaneous */
} hash_table[HASHTABLE_SIZE];


#endif