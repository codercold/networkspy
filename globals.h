#ifndef _GLOBALS_H
#define _GLOBALS_H


#define MY_CLOSE_WINDOW		(WM_USER + 101)
#define MY_UPDATE_PROGRESS	(WM_USER + 102)
#define MY_SET_RANGE		(WM_USER + 103)
#define MY_CAPTURE_COMPLETE	(WM_USER + 104)

#define INI_FILE			"NetworkSpy.ini"
#define APP_NAME			"Network Spy 2.0"


char	filename[MAX_PATH + 128];
int		bytes_used;
BOOL    g_bIsRunning, g_bShutdown;   
BOOL	g_bServerMode;
BOOL	g_bBufferDump;

//UINT	total_data;
UINT	new_data;
UINT	count;


/* Stats */
UINT	packets_captured;
UINT	total_bytes;


/*  Used to save raw packets in "buffer and dump" mode */
struct packet_list	*head_ptr, *cur_ptr;


HWND		hWndMain, hWndTabs;
HWND	    hWndAlertList, hWndCounterList, hWndARPList, hWndTraffic;
HWND		hWndToolbar, hWndStatus, hWndDecoder, hWndRawData;
HWND		hModelessDlg, hWndServer;
HINSTANCE	hInst;

CRITICAL_SECTION	g_csPing;


#endif
