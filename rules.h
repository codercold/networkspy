#ifndef __RULES_H__
#define __RULES_H__

#pragma pack(1)
// NELSON #pragma comment(linker,"/FILEALIGN:0x200")


/*  Some numeric constants */
#define MAX_RULES		256;
#define MAX_RULE_LEN	256;


/* direction of source and destination IP adds */
#define UNI_DIR		0x01
#define BI_DIR		0x02
  

#define EXCEPT_SRC_IP  0x01
#define EXCEPT_DST_IP  0x02
#define ANY_SRC_PORT   0x04
#define ANY_DST_PORT   0x08
#define ANY_FLAGS      0x10
#define EXCEPT_SRC_PORT 0x20
#define EXCEPT_DST_PORT 0x40
#define BIDIRECTIONAL   0x80


#define	R_ICMP		0x01
#define R_IGMP		0x02
#define	R_TCP		0x06
#define R_UDP		0x11


/* Constants for TCP flags */
#define R_FIN		0x01
#define R_SYN       0x02
#define R_RST       0x04
#define R_PSH       0x08
#define R_ACK       0x10
#define R_URG       0x20
#define R_RES2      0x40
#define R_RES1      0x80


/* Constants for IP fragment bits */
#define R_MF		0x01
#define R_DF		0x02
#define R_RF		0x04


/* Constants for IP options */
#define R_RR		0x07
#define R_EOL		0x00
#define R_NOP		0x01
#define R_TS		0x24
#define R_SEC		0x00	// FIND THIS OUT
#define R_LSRR		0x03	
#define R_SSRR		0x09
#define R_SATID		0x00	// FIND THIS OUT		



typedef struct _RuleNode
{
	u_char counter_id;
	char   sip_op;		 /* operator like '!' */
    u_long sip;          /* src IP */
    u_long smask;        /* src netmask */
	char   dip_op;		 /* operator like '!' */
    u_long dip;          /* dest IP */
    u_long dmask;        /* dest netmask */

    u_short hsp;         /* hi src port */
    u_short lsp;         /* lo src port */
    u_short hdp;         /* hi dest port */
    u_short ldp;         /* lo dest port */

	u_char	dir;		/* the direction */


	char *msg, *content;
	int offset, depth;
	int msg_set, content_set, offset_set, depth_set, counter_id_set;

	/* ICMP header fields */
	u_char	itype;
	u_char  icode;
	u_short icmp_id;
	u_short icmp_seq;
	int itype_set, icode_set, icmp_id_set, icmp_seq_set;

	/* IP header fields */
	u_char	ttl;
	u_char	tos;
	u_short id;
	u_long	ipopts;
	u_char  fragbits;
	char	fragbits_op;
	u_short dsize;
	int ttl_set, tos_set, id_set, ipopts_set, fragbits_set, dsize_set;

	/* TCP header fields */
	u_char	flags;
	char	flags_op;
	u_long	seqnum;
	u_long	acknum;
	int flags_set, seqnum_set, acknum_set;

	struct _RuleNode	*next;

} RuleNode;



typedef struct _RulesHead
{
    RuleNode	*TcpList;
    RuleNode	*UdpList;
    RuleNode	*IcmpList;
	RuleNode	*ArpList;
} RulesHead;



typedef struct _Rules
{
	RulesHead	alert;
	RulesHead	log;
	RulesHead	counter;
} Rules;

BOOL		bEnableFilter;


typedef struct _KeyVal
{
    char				*keyword;
    char				*value;
	struct _KeyVal		*next;
} KeyVal;



typedef struct _Counter
{
	unsigned char	id;
	char			msg[32];
	unsigned long	count;
	unsigned long	bytes;
	unsigned long	prev_count;
	unsigned long	prev_bytes;
} Counter;


/* struct for storing rules in the ascii form (non-parsed) */
typedef struct _RulesText
{
	BOOL	bEnabled;
	char	rule[256];
} RulesText;

RulesText rule_text[256];
Counter	counter[256];

BOOL GenerateRules();
void DestroyRules();
VOID SetupCounters(HWND hWndList);
VOID SetupDefaultRules();
void DumpRule(RuleNode *);

BOOL CALLBACK RulesDlgProc(HWND, UINT, WPARAM, LPARAM);

Rules root;

#endif