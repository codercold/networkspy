/////////////////////////////////////////////////////////////////////////////
//// INCLUDE FILES

#ifndef __HOOKUTIL_H
#define __HOOKUTIL_H

#include	"NdisHApi.h"

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


//#define PACKET_BUFFER_SIZE MAX_TOKENRING_4MBPS_SIZE
#define PACKET_BUFFER_SIZE MAX_ETHER_SIZE

/* About The SendPackage Structure
----------------------------------
 * Many of the HookPeek send packet samples illustrate asynchronous I/O
 * techniques. For most of these, certain data must exist from the
 * time the asynchronous call is made until it completes.
 *
 * Certainly, since DO_DIRECT_IO is often used (to eliminate some
 * unnecessary buffer copying), the packet data buffer must persist until
 * the asynchronous call completes. Other variables such as the OVERLAPPED
 * structure (used in some asynchronous calls) have a similar persistance
 * requirement.
 *
 * One way to deal with the required persistence is simply to allocate
 * a structure which contains all of the variables which must persist
 * until the asynchronous call completes. This is precisely the purpose
 * of the SendPackage structure.
 *
 * In some examples which use synchronous I/O or use asynchronous I/O
 * in some other way which guarentees the required persistance, such a
 * structure may NOT be required. However, all HookPeek samples use
 * the same SendPackage structure just for simplicity.
 *
 * Understand that the SendPackage design is NOT sacred. It's just an
 * example. You can eliminate it or use a completely alternate design
 * as long as you understand what you are doing.
 */
#define	TX_PACKAGE_SIGN	(DWORD )0x444E4553		/* SEND */

typedef struct _HookAdapter HookAdapter, *PHookAdapter;	// Forward

typedef
struct _SendPackage
{
	DWORD				nSignature;			// Character Signature "SEND"

	W32N_LIST_ENTRY	qLink;

	DWORD				nBytesReturned;
	DWORD				nFrameSize;
	
	PHookAdapter	pAdapter;

	/* MAGIC!!!
	-----------
	 * The offset of the OVERLAPPED field in the SendPackage structure
	 * MUST be different from the offset of the OVERLAPPED field in
	 * the ReceivePackage structure. This is because of a sanity check
	 * made using the CONTAINING_RECORD macro in the IOCP sample.
	 */
	OVERLAPPED		OverLapped;

	char				PacketBufferSpace[ PACKET_BUFFER_SIZE ];
	DWORD				Padding;		// Allow for possible misalignment of Buffer
}
	SendPackage, *PSendPackage;


/* About The ReceivePackage Structure
-------------------------------------
 * The comments made above concerning the SendPackage also apply to
 * the ReceivePackage structure defined below.
 */
#define	RX_PACKAGE_SIGN	(DWORD )0x56434552		/* RECV */

typedef
struct _ReceivePackage
{
	DWORD				nSignature;			// Character Signature "RECV"

	DWORD				nBytesReturned;

	PHookAdapter	pAdapter;

	/* MAGIC!!!
	-----------
	 * The offset of the OVERLAPPED field in the ReceivePackage structure
	 * MUST be different from the offset of the OVERLAPPED field in
	 * the SendPackage structure. This is because of a sanity check
	 * made using the CONTAINING_RECORD macro in the IOCP sample.
	 */
	OVERLAPPED		OverLapped;

	/* Note
	-------
	 * WinDis 32 V5.00.10.31 introduced a mechanism which provides
	 * a simple way to accomodate media which has packet data lengths
	 * larger then the 1500 bytes used by Ethernet.
	 *
	 * To suport this, the PacketBuffer field in the W32N_PACKET structure
	 * was changed from having a fixed length of:
	 *
	 *   (2*ETHER_ADDR_LENGTH) + ETHER_TYPE_LENGTH + MAX_ETHER_SIZE + 2
	 *
	 * to having a placeholder length of one (1) byte. This mechanism
	 * requires that additional memory for the actual buffer must be
	 * provided contiguous to and immediately following the placeholder
	 * PacketBuffer field.
	 *
	 *		// ATTENTION!!! Above not currently correct!!!
	 *		// Hardcoded to 4550 Bytes...
	 *
	 * Although there are other ways to fulfill this requirement, this
	 * test application simply provides the PacketBufferSpace character
	 * array immediately following the UserPacketData field.
	 *
	 * The Padding field accounts for the possibility that a compiler may
	 * do something funny.
	 */
	W32N_PACKET		UserPacketData;
	char				PacketBufferSpace[ PACKET_BUFFER_SIZE ];
	DWORD				Padding;		// Allow for possible misalignment of Buffer
}
	ReceivePackage, *PReceivePackage;


/* About The HookAdapter Structure
----------------------------------
 * The HookAdapter structure is simply a "coat hanger" structure which
 * consolidates many of the variables associated with an adapter in one
 * place.
 *
 * If you are dealing only with a single adapter, many of the HookAdapter
 * fields could simply have been global variables.
 *
 * If your application involves opening multiple adapters concurrently,
 * then a sturcture like HookAdapter will probably be needed.
 *
 * Understand that HookAdapter design is NOT sacred. It's just an
 * example. You can eliminate it or use a completely alternate design
 * as long as you understand what you are doing.
 */
typedef
struct _HookAdapter
{
	HANDLE		m_hDevice;
	DWORD			m_nMedium;
	DWORD			m_nLinkSpeed;
	DWORD			m_nMaxFrameSize;

	char			m_szAdapterName[ _MAX_PATH ];

	BOOL			m_bCurrentAddressValid;
	BYTE			m_CurrentAddress[ ETHER_ADDR_LENGTH ];

	char			m_szAdapterDriverDescription[ 80 ];

	OVERLAPPED	m_OverLapped;
	HANDLE		m_hDummyReceiveEvent;

	DWORD			m_nReceivedPacketCount;

	DWORD			m_nLastSequenceNo;
	DWORD			m_nSequenceErrorCount;
	DWORD			m_nSequenceErrorPlus;
	DWORD			m_nSequenceErrorMinus;

	DWORD			m_nSendPacketCount;
   DWORD       m_nPendingSendAPCCount;

	ULONG			m_nProtocolFramesRcvGood;
	ULONG			m_nRcvMissed_KernelResource;	// Frames Missed, Kernel Resource
	ULONG			m_nRcvMissed_UserResource;		// Frames Missed, User Resource

	ULONG			m_nProtocolFramesXmitGood;
	ULONG			m_nXmitMissed_KernelResource;	// Frames Missed, Kernel Resource

	char			m_szProtocolDriverDescription[ 80 ];

	HANDLE 		m_hReadPort;
	PReceivePackage	m_pRxPackageBase;
	DWORD			m_nPackageCount;	// Number Of Successfully Created Packages

	// For WaitForMultipleObjects Reception Example
	HANDLE		m_PackageHandles[ MAXIMUM_WAIT_OBJECTS ];
}
	HookAdapter, *PHookAdapter;


#ifdef __cplusplus
extern "C" {
#endif



/* Prototypes From HPRxUtil.c
----------------------------- */
DWORD HP_CreateReceivePackages(
			PHookAdapter pAdapter,
			DWORD nPackageCount,
			BOOL bInitOverlappedEvent
			);

void HP_DestroyReceivePackages( PHookAdapter pAdapter );


BOOLEAN HP_IsValidReceivePackage( PReceivePackage pRxPackage );


/* Prototypes From HPCtrl.c
--------------------------- */
BOOLEAN HP_DisableLoopback( PHookAdapter pAdapter );
BOOLEAN HP_SetPacketFilter( PHookAdapter pAdapter, ULONG nPacketFilter );

BOOLEAN HP_StartPromiscuousReception(
			PHookAdapter pAdapter
			 );

BOOLEAN HP_StopReception( PHookAdapter pAdapter );

BOOLEAN HP_UpdateAdapterDescription( PHookAdapter pAdapter );
BOOLEAN HP_UpdateAdapterMedium( PHookAdapter pAdapter );
BOOLEAN HP_UpdateAdapterCurrentAddress( PHookAdapter pAdapter );
BOOLEAN HP_UpdateAdapterLinkSpeed( PHookAdapter pAdapter );
BOOLEAN HP_UpdateAdapterMaxFrameSize( PHookAdapter pAdapter );

BOOLEAN HP_GetProtocolStatistics( PHookAdapter pAdapter );


#ifdef __cplusplus
}
#endif

#endif // __HOOKUTIL_H

