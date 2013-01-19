/////////////////////////////////////////////////////////////////////////////
//// INCLUDE FILES

//#include <stdio.h>
//#include <conio.h>
#include <windows.h>
#include <WindowsX.h>
#include	<WinReg.H>
#include	<RegStr.H>

#include <Assert.h>

#include "WiNDIS.h"
#include	"ethertype.h"
#include	"TPFilter.h"

// Copyright And Configuration Management ----------------------------------
//
//              Trivial Protocol Filter (TPF) Module - TPFilter.c
//
//                       Win32 NDIS Framework (WinDis 32)
//                                    For
//                          Windows 95 And Windows NT
//
//     Copyright (c) 1997-1999, Printing Communications Associates, Inc.
//
//                             Thomas F. Divine
//                           4201 Brunswick Court
//                        Smyrna, Georgia 30080 USA
//                              (770) 432-4580
//                            tdivine@pcausa.com
// 
// End ---------------------------------------------------------------------


/*
// This filter ACCEPTS all IP packets, both RFC 894 And 802.3
static
struct bpf_insn BPFAcceptIP[] =
{
	// Handle 802.3 Case
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, MLength),
	BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 0x5DC, 12, 0),

	// Check 802.2 LLC. SAP 0xAA (SNAP), Control 0x03
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + LDSAP),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xAA, 0, 13),
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + LSSAP),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xAA, 0, 11),
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + LCntrl),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x3, 0, 9),

	// Internet Organization/Vendor Code 0x000000
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + SType + 0),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x00, 0, 7),
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, MHdrSize + SType + 1),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0000, 0, 5),

	// Internet Protocol 0x0800
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, MHdrSize + SType + 3),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IP, 2, 3),

	// Handle Ethernet RFC 894 Case
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IP, 0, 1),

	BPF_STMT(BPF_RET+BPF_K, (UINT )-1),	// Accept. Value is bytes to be returned
	BPF_STMT(BPF_RET+BPF_K, 0 )			// Reject
};

#define	TPF_IP_PROGLEN			18			// 19 BPF Instructions


// This filter ACCEPTS TCP packets (RFC 894 encapsulation only)
// This is actually used as a TEMPLATE. BPF instruction No. 5 contains
// 0x06 as the data value, which is the TCP IP protocol number.
//
static
struct bpf_insn BPFAcceptTCP[] =
{
	// Check Ethernet Protocol Word At Offset 12
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IP, 0, 3),

	// Check IP Protocol Byte At Offset 14 + 9 = 23
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 23),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x06, 0, 1),		// IP Protocol Type 0x06

	BPF_STMT(BPF_RET+BPF_K, (UINT )-1),	// Accept. Value is bytes to be returned
	BPF_STMT(BPF_RET+BPF_K, 0 )			// Reject
};

#define	TPF_TCP_PROGLEN			6			// 6 BPF Instructions


// This filter ACCEPTS all ARP packets, both RFC 894 And 802.3
static
struct bpf_insn BPFAcceptARP[] =
{
	// Handle 802.3 Case
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, MLength),
	BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 0x5DC, 13, 0),

	// Check 802.2 LLC. SAP 0xAA (SNAP), Control 0x03
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + LDSAP),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xAA, 0, 11),
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + LSSAP),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xAA, 0, 9),
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + LCntrl),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x3, 0, 7),

	// Internet Organization/Vendor Code 0x000000
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + SType + 0),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x00, 0, 5),
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, MHdrSize + SType + 1),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0000, 0, 3),

	// ARP Protocol 0x0806
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, MHdrSize + SType + 3),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_ARP, 0, 1),

	BPF_STMT(BPF_RET+BPF_K, (UINT )-1),	// Accept. Value is bytes to be returned

	// Handle Ethernet RFC 894 Case
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_ARP, 0, 1),

	BPF_STMT(BPF_RET+BPF_K, (UINT )-1),	// Accept. Value is bytes to be returned
	BPF_STMT(BPF_RET+BPF_K, 0 )			// Reject
};

#define	TPF_ARP_PROGLEN			19			// 19 BPF Instructions


// This filter ACCEPTS all RARP packets, both RFC 894 And 802.3
static
struct bpf_insn BPFAcceptRARP[] =
{
	// Handle 802.3 Case
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, MLength),
	BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 0x5DC, 13, 0),

	// Check 802.2 LLC. SAP 0xAA (SNAP), Control 0x03
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + LDSAP),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xAA, 0, 11),
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + LSSAP),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xAA, 0, 9),
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + LCntrl),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x3, 0, 7),

	// Internet Organization/Vendor Code 0x000000
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + SType + 0),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x00, 0, 5),
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, MHdrSize + SType + 1),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0000, 0, 3),

	// RARP Protocol 0x8035
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, MHdrSize + SType + 3),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_REVARP, 0, 1),

	BPF_STMT(BPF_RET+BPF_K, (UINT )-1),	// Accept. Value is bytes to be returned

	// Handle Ethernet RFC 894 Case
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_REVARP, 0, 1),

	BPF_STMT(BPF_RET+BPF_K, (UINT )-1),	// Accept. Value is bytes to be returned
	BPF_STMT(BPF_RET+BPF_K, 0 )			// Reject
};

#define	TPF_RARP_PROGLEN			19			// 19 BPF Instructions


// This filter ACCEPTS all NETBEUI packets
static
struct bpf_insn BPFAcceptNETBEUI[] =
{
	// Must be 802.3
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, MLength),
	BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 0x5DC, 5, 0),	// Check 802.3 Length

	// SAP 0xF0
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + LDSAP),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xF0, 0, 3),
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + LSSAP),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xF0, 0, 1),

	BPF_STMT(BPF_RET+BPF_K, (UINT )-1),	// Accept. Value is bytes to be returned
	BPF_STMT(BPF_RET+BPF_K, 0 )	// Reject
};

#define	TPF_NETBEUI_PROGLEN		8			// 8 BPF Instructions


// This filter ACCEPTS all EtherTalk Phase 2 packets
static
struct bpf_insn BPFAcceptEtalk2[] =
{
	// Must be 802.3
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, MLength),
	BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 0x5DC, 13, 0),

	// Check 802.2 LLC. SAP 0xAA (SNAP), Control 0x03
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + LDSAP),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xAA, 0, 11),
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + LSSAP),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xAA, 0, 9),
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + LCntrl),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x3, 0, 7),

	// Apple Ethernet Organization/Vendor Code 0x080007
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + SType + 0),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x08, 0, 5),
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, MHdrSize + SType + 1),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0007, 0, 3),

	// EtherTalk Protocol 0x809B
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, MHdrSize + SType + 3),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_ATALK, 0, 1),

	BPF_STMT(BPF_RET+BPF_K, (UINT )-1),	// Accept. Value is bytes to be returned
	BPF_STMT(BPF_RET+BPF_K, 0 )	// Reject
};

#define	TPF_ETALK2_PROGLEN	16			// 16 BPF Instructions


// This filter ACCEPTS all IPX packets
//
// See the reference:
//    Novell's Guide To NetWare LAN Analysys, Second Edition
//    Laura A Chappell and Dan E. Hawkes
//    Novell Press
//    ISBN 0-7821-1362-1
//
static
struct bpf_insn BPFAcceptIPX[] =
{
	// Must be 802.3
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, MLength),
	BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 0x5DC, 5, 0),	// Check 802.3 Length

	// Check IPX. First Two Data Bytes Are 0xFF
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xFF, 0, 3),

	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + 1),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xFF, 0, 1),

	BPF_STMT(BPF_RET+BPF_K, (UINT )-1),	// Accept. Value is bytes to be returned
	BPF_STMT(BPF_RET+BPF_K, 0 )	// Reject
};

#define	TPF_IPX_PROGLEN		8			// 8 BPF Instructions


// This filter ACCEPTS DEC Experimental packets
static
struct bpf_insn BPFAcceptDECExperimental[] =
{
	// Handle 802.3 Case
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, MLength),
	BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, 0x5DC, 12, 0),

	// Check 802.2 LLC. SAP 0xAA (SNAP), Control 0x03
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + LDSAP),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xAA, 0, 13),
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + LSSAP),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xAA, 0, 11),
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + LCntrl),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x3, 0, 9),

	// Internet Organization/Vendor Code 0x000000
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, MHdrSize + SType + 0),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x00, 0, 7),
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, MHdrSize + SType + 1),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0000, 0, 5),

	// Internet Protocol 0x0800
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, MHdrSize + SType + 3),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_DECEXP, 2, 3),

	// Handle Ethernet RFC 894 Case
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_DECEXP, 0, 1),

	BPF_STMT(BPF_RET+BPF_K, (UINT )-1),	// Accept. Value is bytes to be returned
	BPF_STMT(BPF_RET+BPF_K, 0 )			// Reject
};

#define	TPF_DECEXP_PROGLEN			18			// 19 BPF Instructions
*/

/////////////////////////////////////////////////////////////////////////////
//// TPF_InitBPFProgram
//
// Purpose
//
// Parameters
//
// Return Value
//
// Remarks
//

VOID TPF_InitBPFProgram(
			struct bpf_program *pBPFProgram
			)
{
	pBPFProgram->bf_insns = NULL;
	pBPFProgram->bf_len = 0;
}


/////////////////////////////////////////////////////////////////////////////
//// TPF_FreeBPFProgram
//
// Purpose
//
// Parameters
//
// Return Value
//
// Remarks
//

VOID TPF_FreeBPFProgram(
			struct bpf_program *pBPFProgram
			)
{
	if( !pBPFProgram )
		return;

	if( pBPFProgram->bf_len && pBPFProgram->bf_insns )
	{
		/* Free Memory
		-------------- */
		free( pBPFProgram->bf_insns );
	}

	/* Re-Initialize The BPF Program
	-------------------------------- */
	TPF_InitBPFProgram( pBPFProgram );
}

