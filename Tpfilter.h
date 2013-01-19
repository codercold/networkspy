/////////////////////////////////////////////////////////////////////////////
//// INCLUDE FILES

#ifndef __TPFILTER_H
#define __TPFILTER_H

// Copyright And Configuration Management ----------------------------------
//
//         Header For Trivial Protocol Filter (TPF) Module - TPFilter.h
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

typedef
enum _TPF_PROTO_TYPE
{
	TFP_IP_PROTO = 1,
	TFP_ARP_PROTO,
	TFP_RARP_PROTO,
	TFP_NETBEUI_PROTO,
	TFP_ETALK2_PROTO,
	TFP_IPX_PROTO,
	TFP_IP_PROTO_TCP,
	TFP_IP_PROTO_UDP,
	TFP_IP_PROTO_ICMP,
	TFP_IP_PROTO_IGMP,
	TFP_DECEXP_PROTO
}
	TPF_PROTO_TYPE;


#ifdef __cplusplus
extern "C" {
#endif

VOID TPF_InitBPFProgram(
			struct bpf_program *pBPFProgram
			);

DWORD TPF_ConcatBPFProgram(
			struct bpf_program *pBPFProgram,
			TPF_PROTO_TYPE nTPFProtoType
			);

VOID TPF_FreeBPFProgram(
			struct bpf_program *pBPFProgram
			);

#ifdef __cplusplus
}
#endif

#endif // __TPFILTER_H
