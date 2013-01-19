#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>

#include "resource.h"
#include "ui.h"
#include "utility.h"



HWND CreateMainToolbar(HWND hWndParent, HINSTANCE hInst)
{
	HWND hWnd;

	TBBUTTON tbb[] = 
	{
		0,	IDC_LISTEN,	TBSTATE_ENABLED, TBSTYLE_BUTTON, 0, 0, 0, 0,
		1,	IDC_STOP,	TBSTATE_ENABLED, TBSTYLE_BUTTON, 0, 0, 0, 0,
		4,	IDC_CLEAR,	TBSTATE_ENABLED, TBSTYLE_BUTTON, 0, 0, 0, 0,	
		0,	0,			0,				TBSTYLE_SEP,	0, 0, 0, 0, 
		2,	IDC_DECODE,	TBSTATE_ENABLED, TBSTYLE_BUTTON, 0, 0, 0, 0,
		7,	ID_PRINT,	TBSTATE_ENABLED, TBSTYLE_BUTTON, 0, 0, 0, 0,
		0,	0,			0,				TBSTYLE_SEP,	0, 0, 0, 0, 
		3,	IDC_ADAPTER, TBSTATE_ENABLED, TBSTYLE_BUTTON, 0, 0, 0, 0,	
		5,	ID_OPTIONS_MANAGERULES, TBSTATE_ENABLED, TBSTYLE_BUTTON, 0, 0, 0, 0,
		0,	0,			0,				TBSTYLE_SEP,	0, 0, 0, 0,
		6,	IDC_ONLINE_HELP, TBSTATE_ENABLED, TBSTYLE_BUTTON, 0, 0, 0, 0,
	};

	hWnd = CreateToolbarEx ( hWndParent, 
							 WS_CHILD | WS_BORDER | WS_VISIBLE | WS_CLIPSIBLINGS | CCS_TOP | TBSTYLE_TOOLTIPS,
							 1001, 8, hInst, IDB_TOOLBAR,
							 tbb, 11, 32, 32, 32, 32,
							 sizeof(TBBUTTON) );

	return hWnd;
}



HWND CreateTabs (HWND hWndParent, HINSTANCE hInst)
{
	HWND	hWnd;
	TCITEM	tci;

	hWnd = CreateWindow(WC_TABCONTROL, "", 
						WS_VISIBLE | WS_TABSTOP | WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS, 
						160,45, 400, 40,
						hWndParent, NULL, hInst, NULL);

	//TabCtrl_SetImageList(hWnd, hImageList);

	tci.mask = TCIF_TEXT;
	tci.iImage = -1;

	tci.pszText = "Alerts";
	TabCtrl_InsertItem(hWnd, 0, &tci);

	tci.pszText = "Counters";
	TabCtrl_InsertItem(hWnd, 1, &tci);

	tci.pszText = "Arp Table";
	TabCtrl_InsertItem(hWnd, 2, &tci);

	TabCtrl_SetCurSel(hWnd, 0);

	return hWnd;
}



HWND CreateAlertsWindow (HWND hWndParent, HINSTANCE hInst)                                     
{      
	LV_COLUMN	lvC;
	DWORD		dwValue = 90;
	HWND		hWnd;

	hWnd = CreateWindowEx(  WS_EX_CLIENTEDGE,
					WC_LISTVIEW,                // list view class
					"",                         // no default text
					WS_VISIBLE | WS_CHILD | WS_BORDER | WS_CLIPSIBLINGS | 
					LVS_REPORT | LVS_NOSORTHEADER | LVS_SHOWSELALWAYS | LVS_SINGLESEL,
					0, 0, 0, 0, 
					//rcl.right - rcl.left, rcl.bottom - rcl.top-100,
					hWndParent,
					(HMENU) 1000,
					hInst,
					NULL );



	if (hWnd == NULL )  return NULL;

	ListView_SetExtendedListViewStyleEx(hWnd, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT );
	    
	ListView_SetBkColor(hWnd, RGB(255,255,255));
	ListView_SetTextBkColor(hWnd, RGB(255,255,255));
	ListView_SetTextColor(hWnd, RGB(0,0,0));


	
	lvC.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM; 
	
	
	dwValue = GetPrivateProfileInt("Packet Capture", "AlertColumn0", 70, "NetworkSpy.ini");
	lvC.cx = RANGE(30, dwValue, 300);       
	lvC.pszText = "Timestamp";
	lvC.iSubItem = 0;
	lvC.fmt = LVCFMT_LEFT;
	ListView_InsertColumn(hWnd, 0, &lvC);

	lvC.fmt = LVCFMT_LEFT;

	dwValue = GetPrivateProfileInt("Packet Capture", "AlertColumn1", 100, "NetworkSpy.ini");
	lvC.cx = RANGE(30, dwValue, 300);       
	lvC.pszText = "Source";
	lvC.iSubItem = 1;
	ListView_InsertColumn(hWnd, 1, &lvC);

	dwValue = GetPrivateProfileInt("Packet Capture", "AlertColumn2", 100, "NetworkSpy.ini");
	lvC.cx = RANGE(30, dwValue, 300);       
	lvC.pszText = "Destination";
	lvC.iSubItem = 2;
	ListView_InsertColumn(hWnd, 2, &lvC);

	dwValue = GetPrivateProfileInt("Packet Capture", "AlertColumn3", 60, "NetworkSpy.ini");
	lvC.cx = RANGE(30, dwValue, 300);         
	lvC.pszText = "Size";
	lvC.iSubItem = 3;
	ListView_InsertColumn(hWnd, 3, &lvC);

	dwValue = GetPrivateProfileInt("Packet Capture", "AlertColumn4", 65, "NetworkSpy.ini");
	lvC.cx = RANGE(30, dwValue, 300);          
	lvC.pszText = "Type";
	lvC.iSubItem = 4;
	ListView_InsertColumn(hWnd, 4, &lvC);

	dwValue = GetPrivateProfileInt("Packet Capture", "AlertColumn5", 145, "NetworkSpy.ini");
	lvC.cx = RANGE(30, dwValue, 300);      
	lvC.pszText = "Info";
	lvC.iSubItem = 5;
	ListView_InsertColumn(hWnd, 5, &lvC);

	dwValue = GetPrivateProfileInt("Packet Capture", "AlertColumn6", 145, "NetworkSpy.ini");
	lvC.cx = RANGE(30, dwValue, 300);      
	lvC.pszText = "IDS Message";
	lvC.iSubItem = 6;
	ListView_InsertColumn(hWnd, 6, &lvC);


	return (hWnd);
}



HWND CreateCountersWindow (HWND hWndParent, HINSTANCE hInst)                                     
{      
	LV_COLUMN	lvC;
	DWORD		dwValue = 90;
	HWND		hWnd;
	
	// Create the list view window that starts out in report view
    // and allows label editing.
	hWnd = CreateWindowEx( WS_EX_CLIENTEDGE,
		WC_LISTVIEW,                // list view class
		"",                         // no default text
		WS_CHILD | WS_BORDER |  WS_CLIPSIBLINGS | 
		LVS_REPORT | LVS_NOSORTHEADER | LVS_SHOWSELALWAYS | LVS_SINGLESEL,
		0, 0, 0, 0,
		hWndParent,
		(HMENU) 1001,
		hInst,
		NULL );



	if (hWnd == NULL )
		return NULL;

	ListView_SetExtendedListViewStyleEx(hWnd, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT );
	ListView_SetExtendedListViewStyleEx(hWnd, LVS_EX_GRIDLINES, LVS_EX_GRIDLINES );	       

	ListView_SetBkColor(hWnd, RGB(255,255,255));
	ListView_SetTextBkColor(hWnd, RGB(255,255,255));
	ListView_SetTextColor(hWnd, RGB(0,0,0));


	lvC.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM; 

	lvC.fmt = LVCFMT_LEFT;

	dwValue = GetPrivateProfileInt("Packet Capture", "CounterColumn0", 100, "NetworkSpy.ini");
	lvC.cx = RANGE(30, dwValue, 300);       
	lvC.pszText = "ID";
	lvC.iSubItem = 0;
	ListView_InsertColumn(hWnd, 0, &lvC);

	dwValue = GetPrivateProfileInt("Packet Capture", "CounterColumn1", 100, "NetworkSpy.ini");
	lvC.cx = RANGE(30, dwValue, 300);       
	lvC.pszText = "Message";
	lvC.iSubItem = 1;
	ListView_InsertColumn(hWnd, 1, &lvC);

	dwValue = GetPrivateProfileInt("Packet Capture", "CounterColumn2", 80, "NetworkSpy.ini");
	lvC.cx = RANGE(30, dwValue, 300);         
	lvC.pszText = "Count";
	lvC.iSubItem = 2;
	lvC.fmt = LVCFMT_RIGHT;
	ListView_InsertColumn(hWnd, 2, &lvC);

	dwValue = GetPrivateProfileInt("Packet Capture", "CounterColumn3", 80, "NetworkSpy.ini");
	lvC.cx = RANGE(30, dwValue, 300);         
	lvC.pszText = "Data";
	lvC.iSubItem = 3;
	lvC.fmt = LVCFMT_RIGHT;
	ListView_InsertColumn(hWnd, 3, &lvC);

	dwValue = GetPrivateProfileInt("Packet Capture", "CounterColumn4", 80, "NetworkSpy.ini");
	lvC.cx = RANGE(30, dwValue, 300);         
	lvC.pszText = "Count Rate";
	lvC.iSubItem = 4;
	lvC.fmt = LVCFMT_RIGHT;
	ListView_InsertColumn(hWnd, 4, &lvC);

	dwValue = GetPrivateProfileInt("Packet Capture", "CounterColumn5", 80, "NetworkSpy.ini");
	lvC.cx = RANGE(30, dwValue, 300);         
	lvC.pszText = "Data Rate";
	lvC.iSubItem = 5;
	lvC.fmt = LVCFMT_RIGHT;
	ListView_InsertColumn(hWnd, 5, &lvC);

	return (hWnd);
}



HWND CreateARPWindow (HWND hWndParent, HINSTANCE hInst)                                     
{      
	LV_COLUMN	lvC;
	DWORD		dwValue = 90;
	HWND		hWnd;
	

	hWnd = CreateWindowEx( WS_EX_CLIENTEDGE,
		WC_LISTVIEW,                // list view class
		"",                         // no default text
		WS_CHILD | WS_BORDER |  WS_CLIPSIBLINGS | 
		LVS_REPORT | LVS_NOSORTHEADER | LVS_SHOWSELALWAYS | LVS_SINGLESEL,
		0, 0, 0, 0,
		hWndParent,
		(HMENU) 1002,
		hInst,
		NULL );

	if (hWnd == NULL )
		return NULL;

	ListView_SetExtendedListViewStyleEx(hWnd, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT );
	ListView_SetExtendedListViewStyleEx(hWnd, LVS_EX_GRIDLINES, LVS_EX_GRIDLINES );
	ListView_SetBkColor(hWnd, RGB(255,255,255));
	ListView_SetTextBkColor(hWnd, RGB(255,255,255));
	ListView_SetTextColor(hWnd, RGB(0,0,0));


	lvC.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM; 


	dwValue = GetPrivateProfileInt("Packet Capture", "ArpColumn0", 60, "NetworkSpy.ini");
	lvC.cx = RANGE(30, dwValue, 300);       
	lvC.pszText = "Count";
	lvC.iSubItem = 0;
	lvC.fmt = LVCFMT_LEFT;
	ListView_InsertColumn(hWnd, 0, &lvC);

	dwValue = GetPrivateProfileInt("Packet Capture", "ArpColumn1", 160, "NetworkSpy.ini");
	lvC.cx = RANGE(30, dwValue, 300);       
	lvC.pszText = "MAC Address";
	lvC.iSubItem = 1;
	lvC.fmt = LVCFMT_LEFT;
	ListView_InsertColumn(hWnd, 1, &lvC);

	dwValue = GetPrivateProfileInt("Packet Capture", "ArpColumn2", 160, "NetworkSpy.ini");
	lvC.cx = RANGE(30, dwValue, 300);         
	lvC.pszText = "IP Address";
	lvC.iSubItem = 2;
	lvC.fmt = LVCFMT_LEFT;
	ListView_InsertColumn(hWnd, 2, &lvC);

/*	dwValue = GetPrivateProfileInt("Packet Capture", "Column14", 260, "NetworkSpy.ini");
	lvC.cx = RANGE(30, dwValue, 300);         
	lvC.pszText = "Ethernet Adapter";
	lvC.iSubItem = 4;
	lvC.fmt = LVCFMT_LEFT;
	ListView_InsertColumn(hWnd, 3, &lvC);
*/
	return (hWnd);
}



BOOL SaveColumnWidths(HWND hWndAlertList, HWND hWndCounterList, HWND hWndARPList)
{
	DWORD dw;
	char str[32];

	dw = ListView_GetColumnWidth(hWndAlertList, 0);
	wsprintf(str, "%d", dw);
	WritePrivateProfileString("Packet Capture", "AlertColumn0", str, "NetworkSpy.ini");
	
	dw = ListView_GetColumnWidth(hWndAlertList, 1);
	wsprintf(str, "%d", dw);
	WritePrivateProfileString("Packet Capture", "AlertColumn1", str, "NetworkSpy.ini");

	dw = ListView_GetColumnWidth(hWndAlertList, 2);
	wsprintf(str, "%d", dw);
	WritePrivateProfileString("Packet Capture", "AlertColumn2", str, "NetworkSpy.ini");

	dw = ListView_GetColumnWidth(hWndAlertList, 3);
	wsprintf(str, "%d", dw);
	WritePrivateProfileString("Packet Capture", "AlertColumn3", str, "NetworkSpy.ini");

	dw = ListView_GetColumnWidth(hWndAlertList, 4);
	wsprintf(str, "%d", dw);
	WritePrivateProfileString("Packet Capture", "AlertColumn4", str, "NetworkSpy.ini");

	dw = ListView_GetColumnWidth(hWndAlertList, 5);
	wsprintf(str, "%d", dw);
	WritePrivateProfileString("Packet Capture", "AlertColumn5", str, "NetworkSpy.ini");

	dw = ListView_GetColumnWidth(hWndAlertList, 6);
	wsprintf(str, "%d", dw);
	WritePrivateProfileString("Packet Capture", "AlertColumn6", str, "NetworkSpy.ini");

	dw = ListView_GetColumnWidth(hWndCounterList, 0);
	wsprintf(str, "%d", dw);
	WritePrivateProfileString("Packet Capture", "CounterColumn0", str, "NetworkSpy.ini");

	dw = ListView_GetColumnWidth(hWndCounterList, 1);
	wsprintf(str, "%d", dw);
	WritePrivateProfileString("Packet Capture", "CounterColumn1", str, "NetworkSpy.ini");

	dw = ListView_GetColumnWidth(hWndCounterList, 2);
	wsprintf(str, "%d", dw);
	WritePrivateProfileString("Packet Capture", "CounterColumn2", str, "NetworkSpy.ini");

	dw = ListView_GetColumnWidth(hWndCounterList, 3);
	wsprintf(str, "%d", dw);
	WritePrivateProfileString("Packet Capture", "CounterColumn3", str, "NetworkSpy.ini");

	dw = ListView_GetColumnWidth(hWndCounterList, 4);
	wsprintf(str, "%d", dw);
	WritePrivateProfileString("Packet Capture", "CounterColumn4", str, "NetworkSpy.ini");

	dw = ListView_GetColumnWidth(hWndCounterList, 5);
	wsprintf(str, "%d", dw);
	WritePrivateProfileString("Packet Capture", "CounterColumn5", str, "NetworkSpy.ini");

	dw = ListView_GetColumnWidth(hWndARPList, 0);
	wsprintf(str, "%d", dw);
	WritePrivateProfileString("Packet Capture", "ArpColumn0", str, "NetworkSpy.ini");

	dw = ListView_GetColumnWidth(hWndARPList, 1);
	wsprintf(str, "%d", dw);
	WritePrivateProfileString("Packet Capture", "ArpColumn1", str, "NetworkSpy.ini");

	dw = ListView_GetColumnWidth(hWndARPList, 2);
	wsprintf(str, "%d", dw);
	WritePrivateProfileString("Packet Capture", "ArpColumn2", str, "NetworkSpy.ini");

	dw = ListView_GetColumnWidth(hWndARPList, 3);
	wsprintf(str, "%d", dw);
	WritePrivateProfileString("Packet Capture", "ArpColumn3", str, "NetworkSpy.ini");


	return TRUE;
}




HWND CreateDecoderToolbar(HWND hWndParent, HINSTANCE hInstance)
{
	HWND hwnd;

	TBBUTTON tbb[] = 
	{
		0,	ID_OPEN,	TBSTATE_ENABLED, TBSTYLE_BUTTON, 0, 0, 0, 0,	
		1,	ID_SAVE,	TBSTATE_ENABLED, TBSTYLE_BUTTON, 0, 0, 0, 0,
		2,	ID_PRINT,	TBSTATE_ENABLED, TBSTYLE_BUTTON, 0, 0, 0, 0,	
		0,	0,			0,				TBSTYLE_SEP,	0, 0, 0, 0, 
		3,	ID_PACKET_PREVIOUS, TBSTATE_ENABLED, TBSTYLE_BUTTON, 0, 0, 0, 0,
		4,	ID_PACKET_NEXT,	TBSTATE_ENABLED, TBSTYLE_BUTTON,	0, 0, 0, 0, 
		0,	0,			0,				TBSTYLE_SEP,	0, 0, 0, 0, 
		5,	ID_CLOSE,	TBSTATE_ENABLED, TBSTYLE_BUTTON,	0, 0, 0, 0, 
	};

	hwnd = CreateToolbarEx ( hWndParent, 
							 WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | CCS_TOP,
							 1002, 6, hInstance, IDB_DECODER,
							 tbb, 8, 16, 16, 16, 16,
							 sizeof(TBBUTTON) );

	return hwnd;
}



LPARAM	GetSelectedItemLParam(HWND hWndAlertList)
{
	int		iCount, i;
	LV_ITEM	lvI;

	lvI.mask = LVIF_PARAM | LVIF_STATE;
	lvI.iItem = 0;
	lvI.iSubItem = 0;
	lvI.stateMask =LVIS_SELECTED;
	
	iCount = ListView_GetItemCount( hWndAlertList );
	for( i = 0; i < iCount; i++ )           
	{        
		lvI.iItem = i;
		ListView_GetItem(hWndAlertList, &lvI);
        if( lvI.state == LVIS_SELECTED )
			return lvI.lParam;
	}

	return 0;
}



LPARAM GetNextItemLParam(HWND hWndAlertList)
{
	int		iCount, i;
	LV_ITEM	lvI;

	lvI.mask = LVIF_PARAM | LVIF_STATE;
	lvI.iItem = 0;
	lvI.iSubItem = 0;
	lvI.stateMask =LVIS_SELECTED;
	
	iCount = ListView_GetItemCount( hWndAlertList );
	for( i = 0; i < iCount; i++ )           
	{        
		lvI.iItem = i;
		ListView_GetItem(hWndAlertList, &lvI);
        if( lvI.state == LVIS_SELECTED )
		{
			if (i != (iCount - 1))
			{	
				lvI.mask = LVIF_PARAM ;
				lvI.iItem = i + 1;
				ListView_GetItem(hWndAlertList, &lvI);
				lvI.mask = LVIF_STATE;
				lvI.state = LVIS_SELECTED;
				ListView_SetItem(hWndAlertList, &lvI);
				return lvI.lParam;
			}
		}
	}
	return 0;
}



LPARAM GetPreviousItemLParam(HWND hWndAlertList)
{
	int		iCount, i;
	LV_ITEM	lvI;

	lvI.mask = LVIF_PARAM | LVIF_STATE;
	lvI.iItem = 0;
	lvI.iSubItem = 0;
	lvI.stateMask =LVIS_SELECTED;
	
	iCount = ListView_GetItemCount( hWndAlertList );
	for( i = 0; i < iCount; i++ )           
	{        
		lvI.iItem = i;
		ListView_GetItem(hWndAlertList, &lvI);
        if( lvI.state == LVIS_SELECTED )
		{
			if (i != 0)
			{	
				lvI.mask = LVIF_PARAM ;
				lvI.iItem = i - 1;
				ListView_GetItem(hWndAlertList, &lvI);
				lvI.mask = LVIF_STATE;
				lvI.state = LVIS_SELECTED;
				ListView_SetItem(hWndAlertList, &lvI);
				return lvI.lParam;
			}
		}
	}
	return 0;
}


BOOL PopFileSaveDlg (HWND hwnd, char *szFile, int filter)
{
	OPENFILENAME ofn ;

	char szFilter[] = "Text Dump (*.TXT)\0*.txt\0"  \
					  "Raw Data (*.PKT)\0*.pkt\0" \
                      "HTML Files (*.HTML)\0*.html\0" \
					  "All Files (*.*)\0*.*\0\0" ;

	ZeroMemory(&ofn, sizeof(OPENFILENAME));

	ofn.lStructSize       = sizeof (OPENFILENAME) ;
    ofn.hInstance         = NULL ;
    ofn.lpstrFilter       = szFilter ;
    ofn.nFilterIndex      = filter ;
    ofn.nMaxFile          = _MAX_PATH ;
    ofn.nMaxFileTitle     = _MAX_FNAME + _MAX_EXT ;
    ofn.lpstrInitialDir   = NULL ;
    ofn.lpstrTitle        = NULL ;
    ofn.nFileOffset       = 0 ;
    ofn.nFileExtension    = 0 ;
    if (filter == 1)
		ofn.lpstrDefExt       = "txt" ;
    else if (filter == 2)
		ofn.lpstrDefExt       = "pkt" ;
	else if (filter == 3)
		ofn.lpstrDefExt       = "html" ;
	ofn.lCustData         = 0L ;
    ofn.lpfnHook          = NULL ;
    ofn.lpTemplateName    = NULL ;
	ofn.hwndOwner         = hwnd ;
    ofn.lpstrFile         = szFile;
    ofn.lpstrFileTitle    = "\0" ;
    ofn.Flags             = OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY;

    if (GetSaveFileName (&ofn) )
	{
		//lstrcpy(szFile, ofn.lpstrFile);
		return TRUE;
	}
	return FALSE;
}


BOOL PopSessionSaveDlg (HWND hwnd, char *szFile)
{
	OPENFILENAME ofn ;

	char szFilter[] = "Capture Session (*.NSS)\0*.nss\0"  \
					  "All Files (*.*)\0*.*\0\0" ;

	ZeroMemory(&ofn, sizeof(OPENFILENAME));

	ofn.lStructSize       = sizeof (OPENFILENAME) ;
    ofn.hInstance         = NULL ;
    ofn.lpstrFilter       = szFilter ;
    ofn.nFilterIndex      = 0 ;
    ofn.nMaxFile          = _MAX_PATH ;
    ofn.nMaxFileTitle     = _MAX_FNAME + _MAX_EXT ;
    ofn.lpstrInitialDir   = NULL ;
    ofn.lpstrTitle        = NULL ;
    ofn.nFileOffset       = 0 ;
    ofn.nFileExtension    = 0 ;
	ofn.lpstrDefExt       = "nss" ;
	ofn.lCustData         = 0L ;
    ofn.lpfnHook          = NULL ;
    ofn.lpTemplateName    = NULL ;
	ofn.hwndOwner         = hwnd ;
    ofn.lpstrFile         = szFile;
    ofn.lpstrFileTitle    = "\0" ;
    ofn.Flags             = OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY;

    if (GetSaveFileName (&ofn) )
	{
		//lstrcpy(szFile, ofn.lpstrFile);
		return TRUE;
	}
	return FALSE;
}



BOOL PopDumpSaveDlg (HWND hwnd, char *szFile)
{
	OPENFILENAME ofn ;

	char szFilter[] = "Text Files (*.TXT)\0*.txt\0"  \
					  "All Files (*.*)\0*.*\0\0" ;

	ZeroMemory(&ofn, sizeof(OPENFILENAME));

	ofn.lStructSize       = sizeof (OPENFILENAME) ;
    ofn.hInstance         = NULL ;
    ofn.lpstrFilter       = szFilter ;
    ofn.nFilterIndex      = 0 ;
    ofn.nMaxFile          = _MAX_PATH ;
    ofn.nMaxFileTitle     = _MAX_FNAME + _MAX_EXT ;
    ofn.lpstrInitialDir   = NULL ;
    ofn.lpstrTitle        = NULL ;
    ofn.nFileOffset       = 0 ;
    ofn.nFileExtension    = 0 ;
	ofn.lpstrDefExt       = "nss" ;
	ofn.lCustData         = 0L ;
    ofn.lpfnHook          = NULL ;
    ofn.lpTemplateName    = NULL ;
	ofn.hwndOwner         = hwnd ;
    ofn.lpstrFile         = szFile;
    ofn.lpstrFileTitle    = "\0" ;
    ofn.Flags             = OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY;

    if (GetSaveFileName (&ofn) )
	{
		//lstrcpy(szFile, ofn.lpstrFile);
		return TRUE;
	}
	return FALSE;
}



BOOL PopSessionOpenDlg (HWND hwnd, char *szFile)
{
	OPENFILENAME ofn ;

	char szFilter[] = "Capture Session (*.NSS)\0*.nss\0" \
                      "All Files (*.*)\0*.*\0\0" ;

	ZeroMemory(&ofn, sizeof(OPENFILENAME));

	ofn.lStructSize       = sizeof (OPENFILENAME) ;
    ofn.hInstance         = NULL ;
    ofn.lpstrFilter       = szFilter ;
    ofn.nFilterIndex      = 0;
    ofn.nMaxFile          = _MAX_PATH ;
    ofn.nMaxFileTitle     = _MAX_FNAME + _MAX_EXT ;
    ofn.lpstrInitialDir   = NULL ;
    ofn.lpstrTitle        = NULL ;
    ofn.nFileOffset       = 0 ;
    ofn.nFileExtension    = 0 ;
	ofn.lpstrDefExt       = "nss" ;
	ofn.lCustData         = 0L ;
    ofn.lpfnHook          = NULL ;
    ofn.lpTemplateName    = NULL ;
	ofn.hwndOwner         = hwnd ;
    ofn.lpstrFile         = szFile;
    ofn.lpstrFileTitle    = "\0" ;
    ofn.Flags             = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;

    if (GetOpenFileName (&ofn) )
	{
		//lstrcpy(szFile, ofn.lpstrFile);
		return TRUE;
	}
	return FALSE;
}


BOOL PopFileOpenDlg (HWND hwnd, char *szFile)
{
	OPENFILENAME ofn ;

	char szFilter[] = "Raw Data (*.PKT)\0*.pkt\0" \
					  "All Files (*.*)\0*.*\0\0" ;

	ZeroMemory(&ofn, sizeof(OPENFILENAME));

	ofn.lStructSize       = sizeof (OPENFILENAME) ;
    ofn.hInstance         = NULL ;
    ofn.lpstrFilter       = szFilter ;
    ofn.nFilterIndex      = 0;
    ofn.nMaxFile          = _MAX_PATH ;
    ofn.nMaxFileTitle     = _MAX_FNAME + _MAX_EXT ;
    ofn.lpstrInitialDir   = NULL ;
    ofn.lpstrTitle        = NULL ;
    ofn.nFileOffset       = 0 ;
    ofn.nFileExtension    = 0 ;
	ofn.lpstrDefExt       = "pkt" ;
	ofn.lCustData         = 0L ;
    ofn.lpfnHook          = NULL ;
    ofn.lpTemplateName    = NULL ;
	ofn.hwndOwner         = hwnd ;
    ofn.lpstrFile         = szFile;
    ofn.lpstrFileTitle    = "\0" ;
    ofn.Flags             = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;

    if (GetOpenFileName (&ofn) )
	{
		//lstrcpy(szFile, ofn.lpstrFile);
		return TRUE;
	}
	return FALSE;
}


