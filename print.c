#include <windows.h>
#include <commctrl.h>
#include "common.h"
#include "structs.h"
#include "globals.h"
#include "resource.h"
#include "qhtm.h"
#include "utility.h"
 

BOOL CALLBACK PrintStatusDlgProc(HWND, UINT, WPARAM, LPARAM);

HWND	hWndPrintStatus;
char printer_name[512];
BOOL bUserAbort;


BOOL CALLBACK AbortProc(HDC hdcPrn, int iCode)
{
	MSG		msg;

	while (!bUserAbort && PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
	{
		if (!hWndPrintStatus || !IsDialogMessage(hWndPrintStatus, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
	return !bUserAbort;
}


HDC GetDefaultPrinterDC (void)
{
	PRINTER_INFO_5 pinfo5[3];
	DWORD			dwNeeded, dwReturned;

	if (EnumPrinters (PRINTER_ENUM_DEFAULT, NULL, 5, (LPBYTE) pinfo5, sizeof(pinfo5), &dwNeeded, &dwReturned))
	{
		lstrcpy(printer_name, pinfo5[0].pPrinterName);
		return CreateDC(NULL, pinfo5[0].pPrinterName, NULL, NULL);
	}
	return 0;
}


DWORD PrintHTML(PVOID ptr)
{
	PRINTPARAMS	*pparams;
	PRINTDLG  pd = { 0 };
	DOCINFO di = { 0 };
	QHTMCONTEXT qhtmCtx; 
	RECT rcPage;
	int nNumberOfPages, iPage;	
	char	str[32];
	DEVMODE	*devMode;

	pparams = (PRINTPARAMS *) ptr;

	di.cbSize = sizeof(di);
	di.lpszDocName = "Network Spy output";

	if (pparams->mode == 0)
	{
		pd.hDC = GetDefaultPrinterDC();
	}
	else
	{
		pd.lStructSize = sizeof(pd);
		pd.Flags = PD_NOSELECTION | PD_NOPAGENUMS | PD_USEDEVMODECOPIES | PD_RETURNDC;
		pd.hwndOwner = pparams->hDlg;
		if( !PrintDlg( &pd ) )
		{
			free(pparams->buffer);
			free(pparams);
			return FALSE;
		}

		devMode = GlobalLock(pd.hDevMode);
		lstrcpy(printer_name, devMode->dmDeviceName);
		GlobalUnlock(pd.hDevMode);
	}


	EnableWindow(pparams->hDlg, FALSE);

	bUserAbort = FALSE;
	hWndPrintStatus = CreateDialog(hInst, MAKEINTRESOURCE(IDD_PRINT_STATUS), pparams->hDlg, PrintStatusDlgProc);
	SetDlgItemText(hWndPrintStatus, IDC_PRINTER, printer_name);

	qhtmCtx = QHTM_PrintCreateContext2(QHTM_ZOOM_DEFAULT);
	SetAbortProc(pd.hDC, AbortProc);
	
	if( StartDoc( pd.hDC, &di ) > 0)
	{
		if( QHTM_PrintSetText( qhtmCtx, pparams->buffer ) )	
		{
			rcPage.left = 20;
			rcPage.top = 20;
			rcPage.right = GetDeviceCaps( pd.hDC, HORZRES ) - 40;
			rcPage.bottom = GetDeviceCaps( pd.hDC, VERTRES ) - 40;

			QHTM_PrintLayout( qhtmCtx, pd.hDC, &rcPage, &nNumberOfPages );

			for(iPage = 0; iPage < nNumberOfPages; iPage++ )		
			{
				if( StartPage( pd.hDC ) <= 0 )
					break;	
			
				wsprintf(str, "Printing page %d of %d...", iPage + 1, nNumberOfPages);
				SetDlgItemText(hWndPrintStatus, IDC_STATUS, str);

				if( !QHTM_PrintPage( qhtmCtx, pd.hDC, iPage, &rcPage ) )
					break;

				if( EndPage( pd.hDC ) <= 0 )
					break;		
			}
		}

		EndDoc(pd.hDC);
	}

	if (!bUserAbort)
		EnableWindow(pparams->hDlg, TRUE);

	DeleteDC( pd.hDC );
	pd.hDC = NULL;
	QHTM_PrintDestroyContext( qhtmCtx );

	DestroyWindow(hWndPrintStatus);

	free(pparams->buffer);
	free(pparams);
	
	return 0;
}




DWORD PrintSession(PVOID ptr)
{
	static char szTextStr[] = "Network Spy Session";
	static DOCINFO di = { sizeof(DOCINFO), "Print1: Printing", NULL};
	PRINTDLG  pd = { 0 };
	BOOL	bError = FALSE;
	int		cxPage, cyPage, iPage, nNumberOfPages;
	HWND	hWndListview;
	char	szBuffer[128];
	int		i, numItems, charWidth, charHeight;
	HFONT		hHeaderFont;
	HFONT		hNormalFont;
	PRINTPARAMS	*pparams;
	DEVMODE		*devMode;


	pparams = (PRINTPARAMS *) ptr;
	hWndListview = pparams->hDlg;

	if (pparams->mode == 0)
	{
		pd.hDC = GetDefaultPrinterDC();
	}
	else
	{
		pd.lStructSize = sizeof(pd);
		pd.Flags = PD_NOSELECTION | PD_NOPAGENUMS | PD_USEDEVMODECOPIES | PD_RETURNDC;
		pd.hwndOwner = hWndMain;
		if( !PrintDlg( &pd ) )	
			return FALSE;

		devMode = GlobalLock(pd.hDevMode);
		lstrcpy(printer_name, devMode->dmDeviceName);
		GlobalUnlock(pd.hDevMode);
	}

	EnableWindow(hWndMain, FALSE);

	bUserAbort = FALSE;
	hWndPrintStatus = CreateDialog(hInst, MAKEINTRESOURCE(IDD_PRINT_STATUS), hWndMain, PrintStatusDlgProc);
	SetDlgItemText(hWndPrintStatus, IDC_PRINTER, printer_name);


	cxPage = GetDeviceCaps (pd.hDC, HORZRES);
	cyPage = GetDeviceCaps (pd.hDC, VERTRES);

	charWidth = cxPage / 80;
	charHeight = cyPage / 45;

	hHeaderFont = CreateFont(2 * charHeight, 0, 0, 0, FW_BOLD	, 0, 0, 0, 0, 0, 0, 0, FF_DONTCARE, "Arial");
	hNormalFont = CreateFont(charHeight - 20, 0, 0, 0, FW_NORMAL	, 0, 0, 0, 0, 0, 0, 0, FF_DONTCARE, "Arial");

	numItems = ListView_GetItemCount(hWndListview);
	nNumberOfPages = numItems / 42 + 1;

	SetAbortProc(pd.hDC, AbortProc);


	if (StartDoc (pd.hDC, &di) > 0)
	{
		for (iPage = 0; iPage < nNumberOfPages; iPage++)
		{
			if (StartPage (pd.hDC) > 0)
			{
				wsprintf(szBuffer, "Printing page %d of %d ...", iPage + 1, nNumberOfPages);
				SetDlgItemText(hWndPrintStatus, IDC_STATUS, szBuffer);

				MoveToEx(pd.hDC, 0, 5 * charHeight / 2, NULL);
				LineTo(pd.hDC, cxPage, 5 * charHeight / 2);

				SelectObject(pd.hDC, hHeaderFont);
				TextOut (pd.hDC, 5, 1, szTextStr, sizeof(szTextStr) - 1);

				SelectObject(pd.hDC, hNormalFont);

				for (i = 0; i < 42; i++)
				{
					if ((iPage * 42 + i) >= numItems) break;

					ListView_GetItemText(hWndListview, iPage * 42 + i, 0, szBuffer, sizeof(szBuffer));
					TextOut (pd.hDC, 2 * charWidth, (i + 3) * charHeight, szBuffer, lstrlen(szBuffer));

					ListView_GetItemText(hWndListview, iPage * 42 + i, 1, szBuffer, sizeof(szBuffer));
					TextOut (pd.hDC, 14 * charWidth, (i + 3) * charHeight, szBuffer, lstrlen(szBuffer));

					ListView_GetItemText(hWndListview, iPage * 42 + i, 2, szBuffer, sizeof(szBuffer));
					TextOut (pd.hDC, 28 * charWidth, (i + 3) * charHeight, szBuffer, lstrlen(szBuffer));

					ListView_GetItemText(hWndListview, iPage * 42 + i, 3, szBuffer, sizeof(szBuffer));
					TextOut (pd.hDC, 42 * charWidth, (i + 3) * charHeight, szBuffer, lstrlen(szBuffer));

					ListView_GetItemText(hWndListview, iPage * 42 + i, 4, szBuffer, sizeof(szBuffer));
					TextOut (pd.hDC, 48 * charWidth, (i + 3) * charHeight, szBuffer, lstrlen(szBuffer));

					ListView_GetItemText(hWndListview, iPage * 42 + i, 5, szBuffer, sizeof(szBuffer));
					TextOut (pd.hDC, 59 * charWidth, (i + 3) * charHeight, szBuffer, lstrlen(szBuffer));

				}

				if (EndPage (pd.hDC) <= 0)
					break;
			}
		}

		EndDoc(pd.hDC);
	}
	else
		bError = TRUE;

	if (!bUserAbort)
		EnableWindow(hWndMain, TRUE);

	DeleteDC (pd.hDC);
	DeleteObject (hHeaderFont);
	DeleteObject (hNormalFont);
	free (pparams);

	DestroyWindow(hWndPrintStatus);

	return bError;
}



BOOL CALLBACK PrintStatusDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		CenterWindow(hDlg);
		return TRUE;
	
	case WM_COMMAND:
		bUserAbort = TRUE;
		EnableWindow(GetParent(hDlg), TRUE);
		DestroyWindow(hDlg);
		hWndPrintStatus = 0;
		return TRUE;
	
	case WM_CLOSE:
		DestroyWindow(hDlg);
		return TRUE;
	
	}
	return FALSE;
}




BOOL CALLBACK PrintPreviewDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	int			nIndex, nCount, nColumns, i, j;
	static char *szBuffer;
	char		str[128];	
	HWND		hWndList;
	PRINTPARAMS *pparams;
	DWORD		dwValue;
	HANDLE		hThread;


	switch (uMsg)
	{
	case WM_INITDIALOG:
		RestoreWindowPosition(hDlg);

		szBuffer = malloc(64000);
		
		nIndex = TabCtrl_GetCurSel(hWndTabs);
		switch (nIndex)
		{
		case 0:
			wsprintf(szBuffer, "<BODY BGCOLOR=#ffffff><h2>Alert List</h2><table width=\"100%%\"><tr>");
			lstrcat(szBuffer, "<td bgcolor=#bbbbbb><b>Time Stamp</b></td>");
			lstrcat(szBuffer, "<td bgcolor=#bbbbbb><b>Source</b></td>");
			lstrcat(szBuffer, "<td bgcolor=#bbbbbb><b>Destination</b></td>");
			lstrcat(szBuffer, "<td bgcolor=#bbbbbb><b>Size</b></td>");
			lstrcat(szBuffer, "<td bgcolor=#bbbbbb><b>Type</b></td>");
			lstrcat(szBuffer, "<td bgcolor=#bbbbbb><b>Info</b></td>");
			lstrcat(szBuffer, "<td bgcolor=#bbbbbb><b>IDS Message</b></td></tr>");
	
			nColumns = 7;
			hWndList = hWndAlertList;
			
			break;


		case 1:
			wsprintf(szBuffer, "<BODY BGCOLOR=#ffffff><h2>Counters List</h2><hr><table width=\"100%%\"><tr>");
			lstrcat(szBuffer, "<td bgcolor=#bbbbbb><b>Counter ID</b></td>");
			lstrcat(szBuffer, "<td bgcolor=#bbbbbb><b>Label</b></td>");
			lstrcat(szBuffer, "<td bgcolor=#bbbbbb><b>Count</b></td>");
			lstrcat(szBuffer, "<td bgcolor=#bbbbbb><b>Total Bytes</b></td></tr>");
	
			nColumns = 4;
			hWndList = hWndCounterList;
			
			break;

		case 2:
			wsprintf(szBuffer, "<BODY BGCOLOR=#ffffff><h2>ARP Table</h2><hr><table width=\"100%%\"><tr>");
			lstrcat(szBuffer, "<td bgcolor=#bbbbbb><b>Count</b></td>");
			lstrcat(szBuffer, "<td bgcolor=#bbbbbb><b>MAC Address</b></td>");
			lstrcat(szBuffer, "<td bgcolor=#bbbbbb><b>IP Address</b></td>");
			lstrcat(szBuffer, "<td bgcolor=#bbbbbb><b>Ethernet Adapter Info</b></td></tr>");
	
			nColumns = 4;
			hWndList = hWndARPList;
			
			break;
		}

		nCount = ListView_GetItemCount(hWndList);
		for (i = 0; i < nCount; i++)
		{
			lstrcat(szBuffer, "<tr>");
			for (j = 0; j < nColumns; j++)
			{
				lstrcat(szBuffer, "<td>");
				ListView_GetItemText(hWndList, i, j, str, sizeof(str));
				lstrcat(szBuffer, str);
				lstrcat(szBuffer, "</td>");
			}
			lstrcat(szBuffer, "</tr>");
		}

		lstrcat(szBuffer, "</table></body>");

		SetDlgItemText(hDlg, IDC_HTML, szBuffer);
		InvalidateRect(GetDlgItem(hDlg, IDC_HTML), NULL, FALSE);

		return TRUE;


	case WM_ACTIVATE:          
         if( LOWORD( wParam ) == WA_INACTIVE )
            hModelessDlg = NULL;
         else
            hModelessDlg = hDlg;
         return TRUE;


	case WM_SIZE:
		MoveWindow(GetDlgItem(hDlg, IDC_HTML), 0, 34, LOWORD(lParam), HIWORD(lParam)-34, TRUE);
		return TRUE;


	
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case ID_PRINT:
			pparams = malloc(sizeof(PRINTPARAMS));
			pparams->mode = 0;
			pparams->hDlg = hDlg;
			pparams->buffer = malloc(lstrlen(szBuffer) + 1);
			lstrcpy(pparams->buffer, szBuffer);

			hThread = CreateThread( NULL, 0,(LPTHREAD_START_ROUTINE)PrintHTML, pparams, 0, &dwValue );
			if( hThread ) CloseHandle( hThread );
		
			return TRUE;

		case IDC_CLOSE:
			DestroyWindow(hDlg);
			return TRUE;
		}
		break;
		
	
	case WM_CLOSE:
		DestroyWindow(hDlg);
		return TRUE;


	case WM_DESTROY:
		SaveWindowPosition(hDlg);
		if (szBuffer != NULL)  free(szBuffer);
		hModelessDlg = NULL;
		return TRUE;
	}
	return FALSE;
}
