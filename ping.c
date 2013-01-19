#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <commctrl.h>
#include <winsock.h>

#include "resource.h"
#include "c-runtime.h"
#include "structs.h"
#include "globals.h"
#include "ping.h"
#include "icmp.h"
#include "utility.h"


VOID AddPingItem(HWND hWndList, int nIcon, int nTry, char *host, char *rtt, char *comment);
HWND CreatePingListView (HWND hWndParent) ;


// === Ping a Specified Host ==================================================

DWORD PingHost( PVOID pvoid )
{
	PPARAMS			pparams;
	ECHOPARAMS		echoParams;
	LPHOSTENT		lpHost;
	int				i, nLoop, sum = 0;
	char			str[128];
	int				count, average, decimal1, decimal2;

	pparams = (PPARAMS) pvoid;

	SetDlgItemText(pparams->hwnd, ID_PING, "Stop");
	ListView_DeleteAllItems(pparams->hwndList);
	SendMessage(pparams->hwndStatus, SB_SETTEXT, (WPARAM) 1, (LPARAM) "");


	// Lookup host
	SetWindowText(pparams->hwndStatus, "Looking up host ...");
	echoParams.lAddr = inet_addr(pparams->hostname);
	if (echoParams.lAddr == INADDR_NONE)
	{
		lpHost = gethostbyname(pparams->hostname);
		if (lpHost == NULL)
		{
			MessageBox(pparams->hwnd, "Hostname not found", APP_NAME, MB_ICONERROR | MB_OK);
			SetDlgItemText(pparams->hwnd, ID_PING, "Ping");
			SetWindowText(pparams->hwndStatus, "Host lookup failed.");
			return 0;
		}
		echoParams.lAddr = *((u_long FAR *) lpHost->h_addr);
	}


	wsprintf(str, "Pinging %s ...", pparams->hostname);
	SetWindowText(pparams->hwndStatus, str);
	
	nLoop = GetDlgItemInt(pparams->hwnd, IDC_NUM, NULL, FALSE);
	echoParams.ttl = 32;
	count =0;

	for (i = 1; i <= nLoop; i++)
	{
		if (pparams->bContinue == FALSE)  break;

		Ping(&echoParams);
		if ((echoParams.dwElapsed < 1000000) && (echoParams.icmpType == ICMP_ECHO_REPLY)) 
		{
			++count;
			sum += echoParams.dwElapsed;
			wsprintf(str, "%d ms", echoParams.dwElapsed);
			AddPingItem(pparams->hwndList, 0, i, inet_ntoa(echoParams.replyFrom), str, "Host is alive");
		}
		else if (echoParams.icmpType == ICMP_DEST_UNREACH)
		{
			AddPingItem(pparams->hwndList, 1, i, inet_ntoa(echoParams.replyFrom), str, "Error: Destination is unreachable");
		}
		else if (echoParams.icmpType == ICMP_TTL_EXPIRE)
		{
			AddPingItem(pparams->hwndList, 1, i, inet_ntoa(echoParams.replyFrom), str, "Error: TTL Expired");
		}
		else   // error occurred
			AddPingItem(pparams->hwndList, 1, i, " - - - ", " - - - ", "Error: No response from host");
	
		
		// a little pause before the next ping
		Sleep(200);
	}


	if (count > 0)
	{
		average = sum / count;
		decimal1 = ((sum % count) * 10) / count;
		decimal2 = ((decimal1 % count) * 10) / count;

		wsprintf(str, "Average Roundtrip Time = %d.%d%d ms", average, decimal1, decimal2);
		SendMessage(pparams->hwndStatus, SB_SETTEXT, (WPARAM) 1, (LPARAM) str);
	}

	SetWindowText(pparams->hwndStatus, "Ping Complete.");
	SetDlgItemText(pparams->hwnd, ID_PING, "Ping");

  	return 0;
}



BOOL CALLBACK PingDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static PARAMS	params;
	char			str[100];
	HANDLE			hThread, hImage;
	DWORD			dwID;
	int parts[2] = {240,-1};

	
	switch (uMsg)
	{
	case WM_INITDIALOG:		

		params.hwndList = CreatePingListView(hDlg);
		params.hwndStatus = CreateStatusWindow(  WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,"Idle", hDlg,1003	);
		SendMessage(params.hwndStatus, SB_SETPARTS, (WPARAM) 2, (LPARAM) parts);

		SendDlgItemMessage( hDlg, IDC_SPIN1, UDM_SETRANGE, 0L, MAKELONG (9192, 1));
		LoadList(GetDlgItem(hDlg, IDC_COMBO_HOSTS), "Ping");
		
		GetPrivateProfileString("Ping", "Number of Times", "3", str, sizeof(str), INI_FILE);
		SetDlgItemText(hDlg, IDC_NUM, str);

		hImage = LoadImage(hInst, MAKEINTRESOURCE(IDI_COPY), IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR);
		SendDlgItemMessage(hDlg, IDC_COPY, BM_SETIMAGE, IMAGE_ICON, (LPARAM) hImage);

		RestoreWindowPosition(hDlg);
		//CenterWindow(hDlg);
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
		case ID_PING:
			GetDlgItemText(hDlg, ID_PING, str, 100);
			if (!strcmp(str, "Stop"))
				params.bContinue = FALSE;
			else
			{
				GetDlgItemText(hDlg, IDC_COMBO_HOSTS, str, 100);
				AddToList(GetDlgItem(hDlg, IDC_COMBO_HOSTS), str);
				params.hwnd = hDlg;
				params.bContinue = TRUE;
				lstrcpy(params.hostname, str);
				
				hThread = CreateThread( NULL, 0,(LPTHREAD_START_ROUTINE)PingHost, &params, 0, &dwID );
				if( hThread )	CloseHandle( hThread );
			}
			return TRUE;
		
		case IDC_COPY:
			CopyListViewData(params.hwndList, 4);
			return TRUE;
		}
		break;

	
	case WM_CLOSE:
		SaveList(GetDlgItem(hDlg, IDC_COMBO_HOSTS), "Ping");		
		SaveWindowPosition(hDlg);

		GetDlgItemText(hDlg, IDC_NUM, str, sizeof(str));
		WritePrivateProfileString("Ping", "Number of Times", str, INI_FILE);

		wsprintf(str, "%d", ListView_GetColumnWidth(params.hwndList, 0));
		WritePrivateProfileString("Ping", "Column1", str, INI_FILE);
		wsprintf(str, "%d", ListView_GetColumnWidth(params.hwndList, 1));
		WritePrivateProfileString("Ping", "Column2", str, INI_FILE);
		wsprintf(str, "%d", ListView_GetColumnWidth(params.hwndList, 2));
		WritePrivateProfileString("Ping", "Column3", str, INI_FILE);
		wsprintf(str, "%d", ListView_GetColumnWidth(params.hwndList, 3));
		WritePrivateProfileString("Ping", "Column4", str, INI_FILE);

		DestroyWindow(hDlg);
		return TRUE;

	case WM_DESTROY:
		hModelessDlg = NULL;
		return TRUE;
	}
	return FALSE;
	
}



HWND CreatePingListView (HWND hWndParent)                                     
{      
	RECT		rcl; 
	LV_COLUMN	lvC;
	DWORD		dw, dwType, dwValue = 90;
	HWND		hWndListview;
	HIMAGELIST	hImageList;
	HBITMAP		hBitmap;

	InitCommonControls();

	GetClientRect(hWndParent, &rcl);

	// Create the list view window that starts out in report view
    // and allows label editing.
	hWndListview = CreateWindowEx( WS_EX_CLIENTEDGE,
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



	if (hWndListview == NULL )
		return NULL;

	hImageList= ImageList_Create(16, 16, TRUE , 1, 1);

	hBitmap = LoadImage(hInst, MAKEINTRESOURCE(IDB_CHECK), IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR);
	ImageList_AddMasked(hImageList, hBitmap, RGB(255, 255, 255));
	DeleteObject(hBitmap);

	hBitmap = LoadImage(hInst, MAKEINTRESOURCE(IDB_CROSS), IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR);
	ImageList_AddMasked(hImageList, hBitmap, RGB(255, 255, 255));
	DeleteObject(hBitmap);

	ListView_SetImageList(hWndListview, hImageList, LVSIL_SMALL);
	ListView_SetImageList(hWndListview, hImageList, LVSIL_NORMAL);

	ListView_SetBkColor(hWndListview, RGB(255,255,255));
	ListView_SetTextBkColor(hWndListview, RGB(255,255,255));
	ListView_SetTextColor(hWndListview, RGB(0,0,0));

	
	lvC.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
	lvC.fmt = LVCFMT_CENTER; 
	
	dw = sizeof(dwValue);
	dwType = REG_DWORD;
	
	lvC.cx = GetPrivateProfileInt("Ping", "Column1", 50, INI_FILE);      
	lvC.pszText = "Try";
	lvC.iSubItem = 1;
	ListView_InsertColumn(hWndListview, 1, &lvC);

	lvC.cx = GetPrivateProfileInt("Ping", "Column2", 100, INI_FILE);    
	lvC.pszText = "Responding Host";
	lvC.iSubItem = 2;
	lvC.fmt = LVCFMT_LEFT; 
	ListView_InsertColumn(hWndListview, 2, &lvC);

	lvC.cx = GetPrivateProfileInt("Ping", "Column3", 180, INI_FILE);     
	lvC.pszText = "Roundtrip Time";
	lvC.iSubItem = 3;
	ListView_InsertColumn(hWndListview, 3, &lvC);

	lvC.cx = GetPrivateProfileInt("Ping", "Column4", 180, INI_FILE);     
	lvC.pszText = "Comment";
	lvC.iSubItem = 4;
	ListView_InsertColumn(hWndListview, 4, &lvC);

	return (hWndListview);
}


VOID AddPingItem(HWND hWndList, int nIcon, int nTry, char *host, char *rtt, char *comment)
{
	int				position;
	LV_ITEM			lvI;
	char			str[64];

	wsprintf(str, "%d", nTry);

	lvI.mask = LVIF_TEXT | LVIF_IMAGE;
	
	position = ListView_GetItemCount(hWndList);
	lvI.iItem = position;
	lvI.iSubItem = 0;
	lvI.pszText = str; 
	lvI.cchTextMax = 64;
	lvI.iImage = nIcon;

	position = ListView_InsertItem(hWndList, &lvI);
	ListView_SetItemText( hWndList, position, 1, host);
	ListView_SetItemText( hWndList, position, 2, rtt);
	ListView_SetItemText( hWndList, position, 3, comment);
	ListView_EnsureVisible(hWndList, position, FALSE);
}