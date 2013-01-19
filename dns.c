#define WIN32_LEAN_AND_MEAN
#define NAME_LOOKUP_COMPLETE	(WM_USER + 101)

#include <windows.h>
#include <winsock.h>

#include "resource.h"
#include "globals.h"
#include "utility.h"
#include "dns.h"




BOOL CALLBACK HostLookupDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{	
	static char	buffer[MAXGETHOSTSTRUCT];
	struct		hostent *phostent;
	char		szBuffer[100];
	int			index;
	WSADATA		wsa;
	IN_ADDR		stDestAddr;
	u_long		lAddr;


	switch (uMsg)
	{
	case WM_INITDIALOG:
		WSAStartup(0x0101, &wsa);
		LoadList(GetDlgItem(hDlg, IDC_COMBO_HOSTNAMES), "DNS Lookup");
		RestoreWindowPosition(hDlg);
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
		case ID_RESOLVE:
			SetDlgItemText(hDlg, IDC_EDIT_OFFICIALNAME, "");
			SetDlgItemText(hDlg, IDC_EDIT_ALIASES, "");
			SetDlgItemText(hDlg, IDC_EDIT_ADDRESSES, "");
			EnableWindow(GetDlgItem(hDlg, ID_RESOLVE), FALSE);

			GetDlgItemText(hDlg, IDC_COMBO_HOSTNAMES, szBuffer, 100);
			AddToList(GetDlgItem(hDlg, IDC_COMBO_HOSTNAMES), szBuffer);

			lAddr = inet_addr(szBuffer);
			if (lAddr == INADDR_NONE)
				WSAAsyncGetHostByName(hDlg, NAME_LOOKUP_COMPLETE, szBuffer, buffer, MAXGETHOSTSTRUCT);
			else
				WSAAsyncGetHostByAddr(hDlg, NAME_LOOKUP_COMPLETE, (char *)&lAddr , 4, PF_INET, buffer, MAXGETHOSTSTRUCT);
			return TRUE;
		
		case ID_CLOSE:
			SendMessage(hDlg, WM_CLOSE, 0, 0);
			return TRUE;
		}
		break;
	

	case NAME_LOOKUP_COMPLETE:
		if (HIWORD(lParam))
		{
			LoadString(hInst, HIWORD(lParam), szBuffer, 100);
			MessageBox(hDlg,szBuffer,APP_NAME, MB_OK);
		}
		else
		{
			phostent = (struct hostent *)buffer;

			// NELSON
			// strcpy(szBuffer, phostent->h_name);
			strcpy_s(szBuffer, sizeof(szBuffer), phostent->h_name);

			SetDlgItemText(hDlg, IDC_EDIT_OFFICIALNAME, szBuffer);

			index = 0;
			while (phostent->h_addr_list[index])
			{
				stDestAddr.s_addr=*((unsigned long *) phostent->h_addr_list[index]);
				GetDlgItemText(hDlg, IDC_EDIT_ADDRESSES, szBuffer, 100);
				lstrcat(szBuffer, inet_ntoa(stDestAddr));
				lstrcat(szBuffer, "\r\n");
				SetDlgItemText(hDlg, IDC_EDIT_ADDRESSES, szBuffer);
				++index;
			}
			
			index = 0;
			while (phostent->h_aliases[index])
			{
				GetDlgItemText(hDlg, IDC_EDIT_ALIASES, szBuffer, 100);
				lstrcat(szBuffer, phostent->h_aliases[index]);
				lstrcat(szBuffer, "\r\n");
				SetDlgItemText(hDlg, IDC_EDIT_ALIASES, szBuffer);
				++index;
			}
			MessageBeep(0xFFFFFFFF);
		}	
		EnableWindow(GetDlgItem(hDlg, ID_RESOLVE), TRUE);
		return TRUE;
	
	
	case WM_CLOSE:
		WSACleanup();
		SaveWindowPosition(hDlg);
		SaveList(GetDlgItem(hDlg, IDC_COMBO_HOSTNAMES), "DNS Lookup");
		DestroyWindow(hDlg);
		return TRUE;


	case WM_DESTROY:
		hModelessDlg = NULL;
		return TRUE;
	}
	return FALSE;
	
}