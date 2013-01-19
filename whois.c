#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <winsock.h>

#include "c-runtime.h"
#include "utility.h"
#include "globals.h"
#include "resource.h"

#define IP_WSAEVENT				WM_USER + 101
#define NAME_LOOKUP_COMPLETE	WM_USER + 102
 

char custom_whois[256];

BOOL CALLBACK WhoisDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static HMENU	hMenu;
	int				x, selected_server;
	static int		count;
	u_long			lAddr;
	struct hostent	*phostent;
	struct sockaddr_in Sa;
	static SOCKET	s; 
	char			str[2048], *pszBase, *pszStr;
	static char		szBuffer[128000];
	static char		server[128];	
	static char		buffer[MAXGETHOSTSTRUCT];
	static HWND		hWndStatus;
	WSADATA			wsa;
	HANDLE			hImage;


	switch (uMsg)
	{
	case WM_INITDIALOG:
		hImage = LoadImage(hInst, MAKEINTRESOURCE(IDI_COPY), IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR);
		SendDlgItemMessage(hDlg, IDC_COPY, BM_SETIMAGE, IMAGE_ICON, (LPARAM) hImage);

		hWndStatus = CreateStatusWindow(  WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,"Idle", hDlg,1003 );

		LoadList(GetDlgItem(hDlg, IDC_COMBO_DOMAINS), "Whois");

		SendDlgItemMessage(hDlg, IDC_COMBO_SERVERS, CB_ADDSTRING , 0, (LPARAM) "American (whois.networksolutions.com)");
		SendDlgItemMessage(hDlg, IDC_COMBO_SERVERS, CB_ADDSTRING , 0, (LPARAM) "Asia/Pacific (whois.apnic.net)");
		SendDlgItemMessage(hDlg, IDC_COMBO_SERVERS, CB_ADDSTRING , 0, (LPARAM) "European (whois.ripe.net)");
		SendDlgItemMessage(hDlg, IDC_COMBO_SERVERS, CB_ADDSTRING , 0, (LPARAM) "US Military (whois.nic.mil)");
		SendDlgItemMessage(hDlg, IDC_COMBO_SERVERS, CB_ADDSTRING , 0, (LPARAM) "IP Addresses (whois.arin.net)");
		
		selected_server = GetPrivateProfileInt("Whois", "Selected Server", 0, INI_FILE);
		SendDlgItemMessage(hDlg, IDC_COMBO_SERVERS, CB_SETCURSEL  , (WPARAM) selected_server, 0);


		if (WSAStartup( MAKEWORD(1,1), &wsa ))
		{
			MessageBox (hDlg, "WSAStartup failed!",APP_NAME,MB_OK);
			return 0;
		}

		RestoreWindowPosition(hDlg);

		return TRUE;

	
	case WM_ACTIVATE:          
         if( LOWORD( wParam ) == WA_INACTIVE )
            hModelessDlg = NULL;
         else
            hModelessDlg = hDlg;
         return TRUE;


	case WM_SIZE:
		MoveWindow(GetDlgItem(hDlg, IDC_COPY), LOWORD(lParam) - 50  , 75, 40, 40, TRUE);
		MoveWindow (GetDlgItem(hDlg, IDC_EDIT_RESULT), 0, 125, LOWORD(lParam ), HIWORD(lParam)-145, TRUE);
		SendMessage(hWndStatus, WM_SIZE, 0, 0L);
		return TRUE;


	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case ID_LOOKUP:
			selected_server = SendDlgItemMessage(hDlg, IDC_COMBO_SERVERS, CB_GETCURSEL, 0, 0);

			switch (selected_server)
			{
			case 0:
				lstrcpy(server, "whois.networksolutions.com");
				break;

			case 1:
				lstrcpy(server, "whois.apnic.net");
				break;

			case 2:
				lstrcpy(server, "whois.ripe.net");
				break;
			
			case 3:
				lstrcpy(server, "whois.nic.mil");
				break;

			case 4:
				lstrcpy(server, "whois.arin.net");
				break;
			}


			GetDlgItemText(hDlg, IDC_COMBO_DOMAINS, str, 100);
			AddToList(GetDlgItem(hDlg, IDC_COMBO_DOMAINS), str);
				
			EnableWindow(GetDlgItem(hDlg, ID_LOOKUP), FALSE);
			
			SetWindowText(hWndStatus, "Looking up host...");


			s = socket(PF_INET,SOCK_STREAM,0);
			WSAAsyncSelect(s, hDlg, IP_WSAEVENT, FD_CONNECT|FD_READ|FD_WRITE|FD_CLOSE);
			
			WSAAsyncGetHostByName(hDlg, NAME_LOOKUP_COMPLETE, server, buffer, MAXGETHOSTSTRUCT);
	
			SetDlgItemText (hDlg, IDC_EDIT_RESULT, "");
			return TRUE;

		case IDC_COPY:
			GetDlgItemText(hDlg, IDC_EDIT_RESULT, szBuffer, sizeof(szBuffer));
			CopyToClipBoard( szBuffer );
		}

		break;

	
	case NAME_LOOKUP_COMPLETE:
		if (HIWORD(lParam))
		{
			LoadString(hInst, HIWORD(lParam), str, 100);
			SetWindowText(hWndStatus, str);
			EnableWindow(GetDlgItem(hDlg, ID_LOOKUP), TRUE);
			closesocket(s);
		}
		else
		{
			phostent = (struct hostent *)buffer;
			lAddr=*((unsigned long *) phostent->h_addr);
			Sa.sin_family=AF_INET;
			Sa.sin_addr.s_addr = lAddr;
			Sa.sin_port=htons(43);
			connect(s,(struct sockaddr *)&Sa,sizeof(Sa));
			SetWindowText(hWndStatus,  "Connecting...");
		}	
		return TRUE;

	
	case IP_WSAEVENT:
		switch (LOWORD(lParam))
		{
		case FD_CONNECT:
			if (HIWORD(lParam))
			{
				LoadString(hInst, HIWORD(lParam), str, 100);
				SetWindowText(hWndStatus,  str);
				EnableWindow(GetDlgItem(hDlg, ID_LOOKUP), TRUE);
				closesocket(s);
			}
			else
				SetDlgItemText(hDlg, IDC_STATUS, "Connected.");
			return TRUE;

		case FD_WRITE:
			SetWindowText(hWndStatus, "Connected. Waiting for reply...");
			GetDlgItemText(hDlg, IDC_COMBO_DOMAINS, str, 100);
			// NELSON strcat (str,"\r\n");
			strcat_s (str, sizeof(str), "\r\n");
			send(s,str,strlen(str),0);
			szBuffer[0] = '\0';
			return TRUE;

		case FD_READ:
			while((x = recv(s,str,sizeof(str),0)) != 0)
			{
				str[x] = '\0';
				
				//lstrcat(szBuffer, str);
			
				szBuffer[0] = '\0';

				pszBase = str;

				while (TRUE)
				{
					pszStr = NULL;
					pszStr = strchr(pszBase,10);
					if (pszStr)
					{
						*pszStr = '\0';
						lstrcat(szBuffer, pszBase);
						lstrcat(szBuffer, "\r\n");
						pszBase = pszStr + 1;
					}
					else
					{
						if (pszBase < &str[x])
							lstrcat(szBuffer, pszBase);
						break;
					}
				} 
				SendDlgItemMessage( hDlg, IDC_EDIT_RESULT, EM_SETSEL, 0xFFFFFFFF, -1 );
				SendDlgItemMessage( hDlg, IDC_EDIT_RESULT, EM_REPLACESEL, FALSE, (LPARAM)szBuffer );
			}
			return TRUE;


		case FD_CLOSE:
			closesocket(s);
			EnableWindow(GetDlgItem(hDlg, ID_LOOKUP), TRUE);
			SetWindowText(hWndStatus,  "Connection closed.");
			return TRUE;
		}
		break;

	
	case WM_CLOSE:
		closesocket(s);
		WSACleanup();
		SaveList(GetDlgItem(hDlg, IDC_COMBO_DOMAINS), "Whois");
		SaveWindowPosition(hDlg);
		selected_server = SendDlgItemMessage(hDlg, IDC_COMBO_SERVERS, CB_GETCURSEL, 0, 0);
		wsprintf(str, "%d", selected_server);
		WritePrivateProfileString("Whois", "Selected Server", str, INI_FILE);
		DestroyWindow(hDlg);
		return TRUE;

	case WM_DESTROY:
		hModelessDlg = NULL;
		return TRUE;
	}
	return FALSE;
	
}
