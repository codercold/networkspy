#ifndef __WINDIS_H__
#define __WINDIS_H__

#include "NdisHApi.h"
#include "bpf.h"


// Copyright And Configuration Management ----------------------------------
//
//       Header For C/C++ Win32 NDIS Framework (WinDis 32) API - WinDis.H
//                           Microsoft C/C++ Edition
//
//   Copyright (c) 1997-1999, Printing Communications Associates, Inc.
//                          http://www.pcausa.com
//
//                             Thomas F. Divine
//                           4201 Brunswick Court
//                        Smyrna, Georgia 30080 USA
//                              (770) 432-4580
//                         mailto:tdivine@pcausa.com
//
//
// End ---------------------------------------------------------------------

#ifdef _W32N_API
#undefine _W32N_API
#endif

#ifdef  _W32N_DLL   // Defined When Building DLL
#define _W32N_API   __declspec( dllexport )
#else
#define _W32N_API   __declspec( dllimport )
#endif               // _W32N_API

#define DEVICE_PREFIX   _T("\\\\.\\")
#define VXD_DEVICE_SUFFIX   _T(".VXD")
#define NT_DEVICE_SUFFIX   _T(".SYS")

#define W32N_REGSTR_PATH_NETCARDS   TEXT("Software\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards")

// #define REGSTR_PATH_CLASS        TEXT("System\\CurrentControlSet\\Services\\Class")
#define W32N_REGSTR_PATH_CLASS_NET  TEXT( "System\\CurrentControlSet\\Services\\Class\\Net")

#define W32N_REGSTR_PATH_CLASS_NET_NT5 "System\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
//#define XX GUID_DEVCLASS_NET

#ifdef __cplusplus
extern "C" {
#endif

#define LPPACKETIO_APC_NT LPOVERLAPPED_COMPLETION_ROUTINE

typedef
VOID
(WINAPI *LPPACKETIO_APC_9X)(
	LPOVERLAPPED lpOverlapped
	);

////////////////////////////////////////////////////////////////////////////
//        General Purpose Device Driver Load Support Utilities            //
////////////////////////////////////////////////////////////////////////////

_W32N_API DWORD W32N_OSGetPlatformVersion( DWORD nPlatformId );
_W32N_API BOOLEAN W32N_IsWindowsNT( void );
_W32N_API BOOLEAN W32N_IsWindows95( void );

_W32N_API BOOLEAN W32N_CheckLoadState( LPCSTR lpDriverBaseName );

_W32N_API BOOLEAN W32N_LoadDriver(
                  LPCSTR lpDriverBaseName,         // e.g., "TDIECHO"
                  LPCSTR lpDriverExecutablePath,   // Needed For NT Only
                  LPCSTR lpDriverDisplayName         // NT Only (May Be NULL)
                  );

_W32N_API BOOLEAN W32N_UnloadDriver( LPCSTR lpDriverBaseName );


////////////////////////////////////////////////////////////////////////////
//                    PCANDIS Regsitry Access Functions                  //
////////////////////////////////////////////////////////////////////////////

typedef
struct _W32N_ADAPTER_INFO
{
   TCHAR   cDescription[ _MAX_PATH ];
   TCHAR   cTitle[ _MAX_PATH ];            // e.g., "[1] Realtek RTL 8029 PCI Adapter"

   TCHAR   cServiceName[ _MAX_PATH ];      // NT Only: e.g., RTL80291
}
   W32N_ADAPTER_INFO, *PW32N_ADAPTER_INFO;


_W32N_API DWORD W32N_GetAdapterRegistryInfo(
                  PW32N_ADAPTER_INFO pAdapterInfo,
                  LPCTSTR pszEnumerator
                  );

////////////////////////////////////////////////////////////////////////////
//         PCANDIS Device Driver And Adapter Access Functions             //
////////////////////////////////////////////////////////////////////////////

_W32N_API DWORD W32N_GetLastError( VOID );

_W32N_API NDIS_STATUS W32N_MakeNdisRequest(
                        HANDLE        hDevice,
                        PW32N_REQUEST pW32NRequest,
                        LPOVERLAPPED  lpOverlapped,
                        BOOLEAN       bSync
                        );

_W32N_API DWORD W32N_PacketRead(
                  HANDLE       hAdapterDevice,
                  PW32N_PACKET pW32NPacket,
                  LPDWORD      lpBytesReturned,
                  LPOVERLAPPED lpOverlapped,
                  BOOLEAN      bSync
                  );

_W32N_API BOOL W32N_PacketReadEx(
                  HANDLE       hAdapterDevice,
                  PW32N_PACKET pW32NPacket,
                  LPDWORD      lpBytesReturned,
                  LPOVERLAPPED lpOverlapped,
                  PVOID        lpCompletionRoutine
                  );

_W32N_API DWORD W32N_CancelPacketRead(
                  HANDLE       hAdapterDevice,
                  PW32N_PACKET pW32NPacket
                  );

_W32N_API BOOL W32N_PacketSend(
                  HANDLE       hAdapterDevice,
                  PBYTE        lpSendBuffer,
                  DWORD        nSendBufferSize,
                  LPDWORD      lpBytesReturned,
                  LPOVERLAPPED lpOverlapped
                  );

_W32N_API BOOL W32N_PacketSendEx(
                  HANDLE       hAdapterDevice,
                  PBYTE        lpSendBuffer,
                  DWORD        nSendBufferSize,
                  LPDWORD      lpBytesReturned,   // Required For Windows 95 Implementation
                  LPOVERLAPPED lpOverlapped,
                  PVOID        lpCompletionRoutine
                  );

_W32N_API HANDLE   W32N_OpenAdapterA( LPSTR lpAdapterName );
_W32N_API HANDLE   W32N_OpenAdapterW( LPWSTR lpAdapterName );

#ifdef _UNICODE
#define W32N_OpenAdapter   W32N_OpenAdapterW
#else
#define W32N_OpenAdapter   W32N_OpenAdapterA
#endif

_W32N_API BOOLEAN   W32N_CloseAdapter( HANDLE hAdapterDevice );

_W32N_API BOOLEAN W32N_DisableLoopback(
                     HANDLE hAdapterDevice,
                     DWORD  nLinkAddrOffset,   // Offset Of Link Source Address Into Packet
                     DWORD  nLinkAddrLength,   // Length Of Link Source Address
                     PBYTE  pLinkAddrBytes   // Pointer To Link Source Address Bytes
                     );

_W32N_API BOOLEAN   W32N_SetBPFProgram(
                     HANDLE hAdapterDevice,
                     struct bpf_insn *pBPFProgram,
                     DWORD  nBPFProgramSize      // Bytes At pProgram
                     );

_W32N_API NDIS_STATUS W32N_MakePrivateRequest(
                        HANDLE        hDevice,
                        PW32N_REQUEST pW32NRequest,
                        LPOVERLAPPED  lpOverlapped,
                        BOOLEAN       bSync
                        );

_W32N_API HANDLE W32N_OpenProtocolDriver( void );

////////////////////////////////////////////////////////////////////////////
//                   BPF Functions For Use At Win32                       //
////////////////////////////////////////////////////////////////////////////

_W32N_API UINT bpf_filter( struct bpf_insn *, UCHAR *, INT, INT);
_W32N_API void bpf_dump( struct bpf_program *p, INT option );
_W32N_API char *bpf_image( struct bpf_insn *p, INT n);


////////////////////////////////////////////////////////////////////////////
//                         Visual Basic Exports                           //
////////////////////////////////////////////////////////////////////////////

DWORD WINAPI VBW32N_OSGetPlatformVersion( DWORD nPlatformId );

BOOLEAN WINAPI VBW32N_IsWindowsNT( void );

BOOLEAN WINAPI VBW32N_IsWindows95( void );

BOOLEAN WINAPI VBW32N_CheckLoadState( LPCSTR lpDriverBaseName );

BOOLEAN WINAPI VBW32N_LoadDriver(
   LPCSTR lpDriverBaseName,         // e.g., "TDIECHO"
   LPCSTR lpDriverExecutablePath,   // Needed For NT Only
   LPCSTR lpDriverDisplayName       // NT Only (May Be NULL)
   );

BOOLEAN WINAPI VBW32N_UnloadDriver( LPCSTR lpDriverBaseName );

DWORD WINAPI VBW32N_GetAdapterRegistryInfo(
   PW32N_ADAPTER_INFO pAdapterInfo,
   LPCTSTR pszEnumerator
   );

DWORD WINAPI VBW32N_GetLastError( VOID );

NDIS_STATUS WINAPI VBW32N_MakeNdisRequest(
                           HANDLE hDevice,
                           PW32N_REQUEST pW32NRequest,
                           LPOVERLAPPED lpOverlapped,
                           BOOLEAN bSync
                           );

DWORD WINAPI VBW32N_PacketRead(
                  HANDLE hAdapterDevice,
                  PW32N_PACKET pW32NPacket,
                  LPDWORD lpBytesReturned,
                  LPOVERLAPPED lpOverlapped,
                  BOOLEAN bSync
                  );

DWORD WINAPI VBW32N_PacketReadEx(
                  HANDLE hAdapterDevice,
                  PW32N_PACKET pW32NPacket,
                  LPDWORD lpBytesReturned,
                  LPOVERLAPPED lpOverlapped,
                  LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
                  );

DWORD WINAPI VBW32N_CancelPacketRead(
                  HANDLE hAdapterDevice,
                  PW32N_PACKET pW32NPacket
                  );

DWORD WINAPI VBW32N_PacketSend(
                  HANDLE hAdapterDevice,
                  PBYTE lpBuffer,
                  DWORD nBufferSize,
                  LPDWORD lpBytesReturned,
                  LPOVERLAPPED lpOverlapped
                  );

DWORD WINAPI VBW32N_PacketSendEx(
                  HANDLE hAdapterDevice,
                  PBYTE lpBuffer,
                  DWORD nNumberOfBytesToWrite,
                  LPDWORD lpBytesReturned,
                  LPOVERLAPPED lpOverlapped,
                  LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
                  );

HANDLE WINAPI VBW32N_OpenAdapterA( LPSTR lpAdapterName );

HANDLE WINAPI VBW32N_OpenAdapterW( LPWSTR lpAdapterName );

#ifdef _UNICODE
#define VBW32N_OpenAdapter   VBW32N_OpenAdapterW
#else
#define VBW32N_OpenAdapter   VBW32N_OpenAdapterA
#endif

BOOLEAN WINAPI VBW32N_CloseAdapter( HANDLE hAdapterDevice );

BOOLEAN WINAPI VBW32N_DisableLoopback(
                     HANDLE hAdapterDevice,
                     DWORD   nLinkAddrOffset,   // Offset Of Link Source Address Into Packet
                     DWORD   nLinkAddrLength,   // Length Of Link Source Address
                     PBYTE pLinkAddrBytes   // Pointer To Link Source Address Bytes
                     );

BOOLEAN WINAPI VBW32N_SetBPFProgram(
                     HANDLE hAdapterDevice,
                     struct bpf_insn *pBPFProgram,
                     DWORD nBPFProgramSize      // Bytes At pProgram
                     );

NDIS_STATUS WINAPI VBW32N_MakePrivateRequest(
                        HANDLE hDevice,
                        PW32N_REQUEST pW32NRequest,
                        LPOVERLAPPED lpOverlapped,
                        BOOLEAN bSync
                        );

HANDLE WINAPI VBW32N_OpenProtocolDriver( void );

UINT WINAPI VBbpf_filter( struct bpf_insn *insn, UCHAR *p1, INT i1, INT i2);

void WINAPI VBbpf_dump( struct bpf_program *p, INT option );

char * WINAPI VBbpf_image( struct bpf_insn *p, INT n);

#ifdef __cplusplus
}
#endif

#endif // __WINDIS_H__

