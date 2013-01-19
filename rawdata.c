#include <windows.h>

#include "resource.h"
#include "structs.h"
#include "common.h"
#include "globals.h"
#include "ui.h"
#include "utility.h"


BOOL CALLBACK RawDataDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	struct packet *pkt;
	unsigned char *ret;

	RECT	rect = {50, 50, 480, 300};
	

	switch (uMsg)
	{
	case WM_INITDIALOG:
		GetPrivateProfileStruct("Packet Capture", "RawData Rect", &rect, sizeof(RECT), "NetworkSpy.ini");

		/* Sanity Check */
		if ((rect.left < 0) || (rect.top < 0) || 
			(rect.left > GetSystemMetrics(SM_CXSCREEN)-50) || 
			(rect.top > GetSystemMetrics(SM_CYSCREEN)-50))
		{
			rect.left = 50;
			rect.top = 50;
			rect.right = 480;
			rect.bottom = 300;
		}

		MoveWindow(hDlg, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, TRUE);


		pkt = (struct packet *) GetSelectedItemLParam(hWndAlertList);
		if (pkt == NULL)
			return TRUE;

		ret = malloc(32000);
		PrintRawData(pkt->data, pkt->size, ret);
		SetDlgItemText(hDlg, IDC_EDIT_DATA, ret);
		free (ret);

		return TRUE;


	case WM_ACTIVATE:          
         if( LOWORD( wParam ) == WA_INACTIVE )
            hModelessDlg = NULL;
         else
            hModelessDlg = hDlg;
         return TRUE;


	case WM_SIZE:
		MoveWindow(GetDlgItem(hDlg, IDC_EDIT_DATA), 10, 10, LOWORD(lParam) - 20, HIWORD(lParam) - 20, TRUE);
		return TRUE;
	
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case ID_CLOSE:
			DestroyWindow(hDlg);
			return TRUE;
		}
		break;
	
	case WM_CLOSE:
		DestroyWindow(hDlg);
		return TRUE;

	case WM_DESTROY:
		GetWindowRect(hDlg, &rect);	
		WritePrivateProfileStruct("Packet Capture", "RawData Rect", &rect, sizeof(RECT), "NetworkSpy.ini");
		hModelessDlg = NULL;
		return TRUE;
	}
	return FALSE;
}