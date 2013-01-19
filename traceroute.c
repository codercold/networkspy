#define WIN32_LEAN_AND_MEAN
#define MAX_HOPS	32

#include <windows.h>
#include <commctrl.h>
#include <winsock.h>

#include "resource.h"
#include "c-runtime.h"
#include "structs.h"
#include "globals.h"
#include "traceroute.h"
#include "icmp.h"
#include "utility.h"


typedef struct {
	HWND	hWndList;
	DWORD   nIndex;
	u_long	lAddr;
} HOSTLOOKUP, *PHOSTLOOKUP;


HWND CreateTracerouteListView (HWND hWndParent);
VOID AddTraceItem(HWND, int, int, char *, char *, char *);



DWORD HostLookupThread(PVOID pvoid)
{
	HOSTLOOKUP	*phlstruct;
	struct	hostent		*phostent;
	

	phlstruct = (HOSTLOOKUP *) pvoid;

	phostent = gethostbyaddr((char *)&phlstruct->lAddr,4,PF_INET);
	if ( phostent != 0) {
		ListView_SetItemText( phlstruct->hWndList, phlstruct->nIndex-1, 3, phostent->h_name);
	} else
		ListView_SetItemText( phlstruct->hWndList, phlstruct->nIndex-1, 3, " - - - ");

	free (phlstruct);
	
	return 0;
}



DWORD TraceRouteThread(PVOID pvoid)
{
	HANDLE			hThread;
	DWORD			dwID;
	PPARAMS			pparams;
	ECHOPARAMS		echoParams;
	PHOSTLOOKUP		pHostLookup;
	PHOSTENT		lpHost;
	int				i;
	char			str[64];

	pparams = (PPARAMS) pvoid;

	SetDlgItemText(pparams->hwnd, ID_TRACE, "Abort");
	SetWindowText(pparams->hwndStatus, "Looking up host ...");

	// Lookup host
	echoParams.lAddr = inet_addr(pparams->hostname);
	if (echoParams.lAddr == INADDR_NONE)
	{
		lpHost = gethostbyname(pparams->hostname);
		if (lpHost == NULL)
		{
			MessageBox(pparams->hwnd, "Hostname not found", APP_NAME, MB_ICONERROR | MB_OK);
			SetDlgItemText(pparams->hwnd, ID_TRACE, "Trace Route to Host");
			SetWindowText(pparams->hwndStatus, "Host lookup failed");
			return 0;
		}
		echoParams.lAddr = *((u_long FAR *) lpHost->h_addr);
	}

			
	wsprintf(str, "Tracing route to %s ...", pparams->hostname);	
	SetWindowText(pparams->hwndStatus, str);
	ListView_DeleteAllItems(pparams->hwndList);

	for (i = 1; i < MAX_HOPS; i++)
	{
		if (pparams->bContinue == FALSE)  break;

		echoParams.ttl = i;

		Ping(&echoParams);
		
		if ((echoParams.icmpType == ICMP_DEST_UNREACH) || (echoParams.dwElapsed > 90000)) 
		{
			AddTraceItem(pparams->hwndList, 1, i, "*", "* no response *", " - - - ");
			continue;
		}

		if ((echoParams.icmpType == ICMP_TTL_EXPIRE) ||
			(echoParams.icmpType == ICMP_ECHO_REPLY))
		{
			wsprintf(str, "%d ms", echoParams.dwElapsed);
			AddTraceItem(pparams->hwndList, 0, i, str, inet_ntoa(echoParams.replyFrom), "");
			
			
			// NELSON
			// pHostLookup = malloc(sizeof(HOSTLOOKUP));
			pHostLookup = (PHOSTLOOKUP) malloc(sizeof(HOSTLOOKUP));

			pHostLookup->hWndList = pparams->hwndList;
			pHostLookup->lAddr = echoParams.replyFrom.s_addr;
			pHostLookup->nIndex = i;

			hThread = CreateThread( NULL, 0,(LPTHREAD_START_ROUTINE)HostLookupThread, pHostLookup, 0, &dwID );
			if( hThread )	CloseHandle( hThread );
			
		}

		if (echoParams.icmpType == ICMP_ECHO_REPLY) break;
	}

	if (echoParams.icmpType == ICMP_ECHO_REPLY) 
	{
		wsprintf(str, "Trace complete: Destination reached after %d hops", i);
		SetWindowText(pparams->hwndStatus, str);
	}
	else
		SetWindowText(pparams->hwndStatus, "Trace complete: Destination not reached.");

	SetDlgItemText(pparams->hwnd, ID_TRACE, "Trace Route to Host");

	return 0;
}



BOOL CALLBACK TraceDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	char			str[100], szBuffer[64];
	RECT			rect;
	DWORD			dwID;
	HANDLE			hThread, hImage;
	static PARAMS	params;
	
	switch (uMsg)
	{
	case WM_INITDIALOG:
		hImage = LoadImage(hInst, MAKEINTRESOURCE(IDI_COPY), IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR);
		SendDlgItemMessage(hDlg, IDC_COPY, BM_SETIMAGE, IMAGE_ICON, (LPARAM) hImage);

		params.hwndList = CreateTracerouteListView(hDlg);
		params.hwndStatus = CreateStatusWindow(  WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,"Idle", hDlg,1003 );

		RestoreWindowPosition(hDlg);
		
		LoadList(GetDlgItem(hDlg, IDC_COMBO_HOSTS), "Trace Route");

		return TRUE;


	case WM_SIZE:
		MoveWindow(GetDlgItem(hDlg, IDC_COPY), LOWORD(lParam) - 50  , 50, 40, 40, TRUE);
		MoveWindow (params.hwndList, 0, 100, LOWORD(lParam ), HIWORD(lParam)-119, TRUE);
		SendMessage(params.hwndStatus, WM_SIZE, 0, 0L);
		return TRUE;


	case WM_ACTIVATE:          
         if( LOWORD( wParam ) == WA_INACTIVE )
            hModelessDlg = NULL;
         else
            hModelessDlg = hDlg;
         return TRUE;

	
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case ID_TRACE:
			GetDlgItemText(hDlg, ID_TRACE, str, 100);
			if (!lstrcmp(str,"Abort"))
				params.bContinue = FALSE;
			else
			{
				GetDlgItemText(hDlg, IDC_COMBO_HOSTS, str, sizeof(str));
				AddToList(GetDlgItem(hDlg, IDC_COMBO_HOSTS), str);
				params.hwnd = hDlg;
				params.bContinue = TRUE;
				lstrcpy(params.hostname, str);

				hThread = CreateThread( NULL, 0,(LPTHREAD_START_ROUTINE)TraceRouteThread, &params, 0, &dwID );
				if( hThread )	CloseHandle( hThread );
			}
			return TRUE;

		case IDC_COPY:
			CopyListViewData( params.hwndList, 4 );
			return TRUE;
		}
		break;


	case WM_SYSCOMMAND:
		if (wParam == SC_CLOSE)
		{
			GetDlgItemText(hDlg, ID_TRACE, str, 100);
			if (!lstrcmp(str,"Abort"))  // traceroute is still active
				return 0;
			else
			{
				DestroyWindow(hDlg);
				return 0;
			}
		}
		break;
	

	case WM_DESTROY:
		GetWindowRect(hDlg, &rect);
		SaveList(GetDlgItem(hDlg, IDC_COMBO_HOSTS), "Trace Route");
		SaveWindowPosition(hDlg);

		wsprintf(szBuffer, "%d", ListView_GetColumnWidth(params.hwndList, 0));
		WritePrivateProfileString("Trace Route", "Column1", szBuffer, "NetworkSpy.ini");
		wsprintf(szBuffer, "%d", ListView_GetColumnWidth(params.hwndList, 1));
		WritePrivateProfileString("Trace Route", "Column2", szBuffer, "NetworkSpy.ini");
		wsprintf(szBuffer, "%d", ListView_GetColumnWidth(params.hwndList, 2));
		WritePrivateProfileString("Trace Route", "Column3", szBuffer, "NetworkSpy.ini");
		wsprintf(szBuffer, "%d", ListView_GetColumnWidth(params.hwndList, 3));
		WritePrivateProfileString("Trace Route", "Column4", szBuffer, "NetworkSpy.ini");
		
		hModelessDlg = NULL;
		return TRUE;
	}
	return FALSE;
	
}



HWND CreateTracerouteListView (HWND hWndParent)                                     
{      
	RECT		rcl; 
	LV_COLUMN	lvC;
	DWORD		dw, dwType, dwValue = 90;
	HWND		hWndList;
	HANDLE		hImageList, hBitmap;

	InitCommonControls();

	GetClientRect(hWndParent, &rcl);

	// Create the list view window that starts out in report view
    // and allows label editing.
	hWndList = CreateWindowEx( WS_EX_CLIENTEDGE,
		WC_LISTVIEW,                // list view class
		"",                         // no default text
		WS_VISIBLE | WS_CHILD | WS_BORDER | WS_CLIPSIBLINGS |  
		LVS_REPORT | LVS_NOSORTHEADER,
		0, 40,
		rcl.right - rcl.left, rcl.bottom - rcl.top-40,
		hWndParent,
		(HMENU) 1010,
		hInst,
		NULL );



	if (hWndList == NULL )
		return NULL;


	hImageList= ImageList_Create(16, 16, TRUE , 1, 1);

	hBitmap = LoadImage(hInst, MAKEINTRESOURCE(IDB_CHECK), IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR);
	ImageList_AddMasked(hImageList, hBitmap, RGB(255, 255, 255));
	DeleteObject(hBitmap);

	hBitmap = LoadImage(hInst, MAKEINTRESOURCE(IDB_CROSS), IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR);
	ImageList_AddMasked(hImageList, hBitmap, RGB(255, 255, 255));
	DeleteObject(hBitmap);

	ListView_SetImageList(hWndList, hImageList, LVSIL_SMALL);
	ListView_SetImageList(hWndList, hImageList, LVSIL_NORMAL);



	ListView_SetBkColor(hWndList, RGB(255,255,255));
	ListView_SetTextBkColor(hWndList, RGB(255,255,255));
	ListView_SetTextColor(hWndList, RGB(0,0,0));

	
	lvC.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
	lvC.fmt = LVCFMT_CENTER; 
	
	dw = sizeof(dwValue);
	dwType = REG_DWORD;
	
	lvC.cx = GetPrivateProfileInt("Trace Route", "Column1", 50, INI_FILE);      
	lvC.pszText = "TTL";
	lvC.iSubItem = 1;
	ListView_InsertColumn(hWndList, 1, &lvC);

	lvC.cx = GetPrivateProfileInt("Trace Route", "Column2", 100, INI_FILE);    
	lvC.pszText = "RTT";
	lvC.iSubItem = 2;
	lvC.fmt = LVCFMT_LEFT; 
	ListView_InsertColumn(hWndList, 2, &lvC);

	lvC.cx = GetPrivateProfileInt("Trace Route", "Column3", 180, INI_FILE);     
	lvC.pszText = "IP Address";
	lvC.iSubItem = 3;
	ListView_InsertColumn(hWndList, 3, &lvC);

	lvC.cx = GetPrivateProfileInt("Trace Route", "Column4", 180, INI_FILE);     
	lvC.pszText = "Hostname";
	lvC.iSubItem = 4;
	ListView_InsertColumn(hWndList, 4, &lvC);

	return (hWndList);
}


VOID AddTraceItem(HWND hWndList, int nIcon, int TTL, char *RTT, char *IP, char *hostname)
{
	int				position;
	LV_ITEM			lvI;
	char			str[64];

	wsprintf(str, "%d", TTL);

	lvI.mask = LVIF_TEXT | LVIF_IMAGE;
	
	position = ListView_GetItemCount(hWndList);
	lvI.iItem = position;
	lvI.iSubItem = 0;
	lvI.pszText = str; 
	lvI.cchTextMax = 64;
	lvI.iImage = nIcon;

	position = ListView_InsertItem(hWndList, &lvI);
	ListView_SetItemText( hWndList, position, 1, RTT);
	ListView_SetItemText( hWndList, position, 2, IP);
	ListView_SetItemText( hWndList, position, 3, hostname);
	ListView_EnsureVisible(hWndList, position, FALSE);
}