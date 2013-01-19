#ifndef _COMMON_H_
#define _COMMON_H_

//#define EVAL


#include <windows.h>



// Functions in decoder.c
VOID DecodeSelected(SYSTEMTIME, unsigned char *, int, char *);
VOID XML_DecodeSelected(SYSTEMTIME, unsigned char *, int, char *);
BOOL CALLBACK DecodeDlgProc(HWND, UINT, WPARAM, LPARAM);
BOOL CALLBACK AdapterDlgProc(HWND, UINT, WPARAM, LPARAM);
DWORD ThreadProc( void );


//Function in ports.c
BOOL CALLBACK PortsDlgProc(HWND, UINT, WPARAM, LPARAM);


// Functions in workthread.c
VOID	Sniff( PVOID );
VOID AddPacketToList(SYSTEMTIME, unsigned char *data, int size);
VOID ProcessPacket(SYSTEMTIME rTime, unsigned char *szBuffer, int size, BOOL bFilter);


// Functions in printc.
DWORD PrintHTML(PVOID ptr);
DWORD PrintSession(PVOID ptr);
BOOL CALLBACK PrintPreviewDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);


// Functions in remote.c
BOOL CALLBACK RemoteDlgProc(HWND, UINT, WPARAM, LPARAM);
BOOL CALLBACK ServerDlgProc(HWND, UINT, WPARAM, LPARAM);


// Functions in generator.c
BOOL CALLBACK PacketGDlgProc(HWND, UINT, WPARAM, LPARAM);
HWND CreatePacketGWindow( HWND, HINSTANCE );


DWORD WinDis(PVOID);




#endif