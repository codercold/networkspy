#include <windows.h>
#include <commctrl.h>

#include "resource.h"
#include "common.h"
#include "structs.h"
#include "globals.h"
#include "utility.h"

#define		IP_WSAEVENT			(WM_USER + 201)
#define		WM_MYNOTIFYMESSAGE	(WM_USER + 202)
#define		BUFFER_SIZE			32000


/*
	Communication protocol :-

	Client:  Connects to port 7035 of server
	Server:  Sends a greeting beginning with '+'
	Client:  Sends BEGN <user> <password>
	Server:  Responds with '+' to indicate success or '-' to indicate failure
			 and starts the packet capture (if autherization passes)
	Client:  Sends STOP to stop capture
	Server:  Sends "0 n bytes" to indicate how much data was captured
	Client:  Sends RETR to start downloading captured packets
	Either party can disconnect once the data has been transferred
*/



BOOL CALLBACK RemoteDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static SOCKET				s;
	static struct sockaddr_in	Sa;
	u_long				lAddr;
	char				host[64], str[64], user[32], password[32];
	static unsigned char	*buffer, *recv_buffer;
	int					i, n;
	WSADATA				wsa;
	static int			bytes_received, total_bytes, byte_offset;
	static struct packet	pkt;
	static BOOL	bReceivingData;

	switch (uMsg)
	{
	case WM_INITDIALOG:
		CenterWindow(hDlg);
		if (WSAStartup( 0x0101, &wsa ))
		{
			MessageBox (hDlg, "WSAStartup failed!",APP_NAME,MB_OK);
			return FALSE;
		}

		GetPrivateProfileString("Packet Capture", "Remote IP", "0.0.0.0", host, sizeof(host), "NetworkSpy.ini");
		GetPrivateProfileString("Packet Capture", "Remote User", "username", user, sizeof(user), "NetworkSpy.ini");
		GetPrivateProfileString("Packet Capture", "Remote Password", "", password, sizeof(password), "NetworkSpy.ini");
		
		SetDlgItemText(hDlg, IDC_EDIT_IP, host);
		SetDlgItemText(hDlg, IDC_EDIT_USER, user);
		SetDlgItemText(hDlg, IDC_EDIT_PASSWORD, password);

		buffer = malloc (BUFFER_SIZE);
		return TRUE;

	

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case ID_CONNECT:
			EnableWindow(GetDlgItem(hDlg, ID_CONNECT), FALSE);
			GetDlgItemText(hDlg, IDC_EDIT_IP, host, sizeof(host));

			lAddr = inet_addr(host);
			if (lAddr == INADDR_NONE)
			{
				SetDlgItemText(hDlg, IDC_STATUS, "Invalid IP");
				return TRUE;
			}
			
			s = socket(PF_INET,SOCK_STREAM,0);
			Sa.sin_family=AF_INET;
			Sa.sin_addr.s_addr = lAddr;
			Sa.sin_port=htons(7035);

			WSAAsyncSelect(s, hDlg, IP_WSAEVENT, FD_CONNECT | FD_READ |  FD_CLOSE);

			n = sizeof(Sa);
			connect(s, (struct sockaddr *) &Sa, n); 

			EnableWindow(GetDlgItem(hDlg, ID_CONNECT), FALSE);
			SetDlgItemText(hDlg, IDC_STATUS, "Connecting...");

			return TRUE;


		case ID_CAPTURE:
			GetDlgItemText(hDlg, ID_CAPTURE, str, sizeof(str));
			if (!lstrcmp(str, "Capture"))
			{
				bytes_received = 0;
				GetDlgItemText(hDlg, IDC_EDIT_USER, user, sizeof(user));
				GetDlgItemText(hDlg, IDC_EDIT_PASSWORD, password, sizeof(password));

				wsprintf(str, "BEGN %s %s\n", user, password);
				sendto (s, str, lstrlen(str), 0, (LPSOCKADDR) &Sa, sizeof(Sa));
				SetDlgItemText(hDlg, ID_CAPTURE, "Stop");
			}
			else
			{
				wsprintf(str, "%s", "STOP\n");
				send(s, str, lstrlen(str), 0);
				SetDlgItemText(hDlg, ID_CAPTURE, "Capture");
			}
			return TRUE;

		
		case ID_CANCEL:
			SendMessage(hDlg, WM_CLOSE, 0, 0);
			return TRUE;
		}
		break;


	case IP_WSAEVENT:
		switch (LOWORD(lParam))
		{
		case FD_CONNECT:
			if (HIWORD(lParam))		/* Connection failed for some reason */
			{
				if ( HIWORD(lParam) == WSAECONNREFUSED )
					SetDlgItemText(hDlg, IDC_STATUS, "Connection refused.");
				else if ( HIWORD(lParam) == WSAETIMEDOUT )
					SetDlgItemText(hDlg, IDC_STATUS, "Connection timed out.");
				else
					SetDlgItemText(hDlg, IDC_STATUS, "Connection failed.");

				EnableWindow(GetDlgItem(hDlg, ID_CONNECT), TRUE);
				return TRUE;
			}

			bReceivingData = FALSE;
			SetDlgItemText(hDlg, IDC_STATUS, "Connected.");
			EnableWindow(GetDlgItem(hDlg, ID_CAPTURE), TRUE);
			SendDlgItemMessage(hDlg, IDC_PROGRESS1, PBM_SETPOS, (WPARAM) 0, 0);
			return TRUE;

		case FD_CLOSE:
			SetDlgItemText(hDlg, IDC_STATUS, "Connection dropped.");
			EnableWindow(GetDlgItem(hDlg, ID_CONNECT), TRUE);
			EnableWindow(GetDlgItem(hDlg, ID_CAPTURE), FALSE);
			return TRUE;

		case FD_READ:
			/* if we are not receiving data, check to see end of line '\n' */
			if (bReceivingData == FALSE)
			{
				n = recv(s, &buffer[byte_offset], BUFFER_SIZE - byte_offset, 0);
				buffer[byte_offset + n] = '\0';

				if (strrchr(buffer, '\n') == NULL)  // not a complete line
				{
					byte_offset += n;
					return TRUE;
				}

				byte_offset = 0;


				if (buffer[0] == '0')
				{
					total_bytes = atoi(&buffer[2]);
					SendDlgItemMessage(hDlg, IDC_PROGRESS1, PBM_SETRANGE, 0, MAKELPARAM(0, total_bytes));
					
					wsprintf(str, "Downloading %d bytes...", total_bytes);
					SetDlgItemText(hDlg, IDC_STATUS, str);
					
					bReceivingData = TRUE;
					bytes_received = 0;
					recv_buffer = malloc(total_bytes);
					
					if (total_bytes > 0)
						send(s, "RETR\n", 5, 0);
					else
					{
						SetDlgItemText(hDlg, IDC_STATUS, "No packets captured during session");
						closesocket(s);
						EnableWindow(GetDlgItem(hDlg, ID_CONNECT), TRUE);
						EnableWindow(GetDlgItem(hDlg, ID_CAPTURE), FALSE);
					}
					return TRUE;
				}
				else if ((buffer[0] == '+') || (buffer[0] == '-'))
				{
					SetDlgItemText(hDlg, IDC_STATUS, &buffer[2]);
				}
				
			}
			else	/* receiving raw data (no text) */
			{
				n = recv(s, &recv_buffer[bytes_received], total_bytes - bytes_received, 0);

				bytes_received += n;
				wsprintf(str, "%d / %d bytes downloaded", bytes_received, total_bytes);
				SetDlgItemText(hDlg, IDC_STATUS, str);
				SendDlgItemMessage(hDlg, IDC_PROGRESS1, PBM_SETPOS, (WPARAM) bytes_received, 0);

				if (bytes_received >= total_bytes)
				{
					SetDlgItemText(hDlg, IDC_STATUS, "Download complete.");
					closesocket(s);
					EnableWindow(GetDlgItem(hDlg, ID_CONNECT), TRUE);
					EnableWindow(GetDlgItem(hDlg, ID_CAPTURE), FALSE);
					
					//MessageBox(hDlg, "download complete", "", MB_OK);
					i = 0;
					while (i < total_bytes - 2)
					{
						memcpy(&pkt.time, &recv_buffer[i], sizeof(SYSTEMTIME));

						i += sizeof(SYSTEMTIME);
						memcpy(&pkt.size, &recv_buffer[i], sizeof(int));

						i += sizeof(int);
						//data = malloc(pkt.size);
					
						if (i + pkt.size >= total_bytes)
						{
							wsprintf(str, "size=%d,recv=%d,total=%d",pkt.size, bytes_received, total_bytes); 
							//MessageBox(hDlg, str, "", MB_OK);
							break;
						}

						//memcpy(data, &recv_buffer[i], pkt.size);
						ProcessPacket(pkt.time, &recv_buffer[i], pkt.size, FALSE);
						//free(data);

						i += pkt.size;
					}

				}
			}
		}
		break;



	case WM_CLOSE:
		GetDlgItemText(hDlg, IDC_EDIT_IP, host, sizeof(host));
		GetDlgItemText(hDlg, IDC_EDIT_USER, user, sizeof(user));
		GetDlgItemText(hDlg, IDC_EDIT_PASSWORD, password, sizeof(password));

		WritePrivateProfileString("Packet Capture", "Remote IP", host, "NetworkSpy.ini");
		WritePrivateProfileString("Packet Capture", "Remote User", user, "NetworkSpy.ini");
		WritePrivateProfileString("Packet Capture", "Remote Password", password, "NetworkSpy.ini");
		
		closesocket(s);
		WSACleanup();
		free (buffer);
		free (recv_buffer);

		EndDialog(hDlg, 0);
		return TRUE;
	}
	return FALSE;
}


BOOL CALLBACK ServerDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static NOTIFYICONDATA	tnd;

	HANDLE		hThread;
	WSADATA		wsa;
	SOCKADDR_IN stLocalAddr;
	static SOCKADDR_IN stRemoteAddr;
	static SOCKET	hServerSocket, hClientSocket; /* only one client at a time */
	SOCKET	hTempSocket;
	int		n, nRet, dw, i, bytes_sent, total_bytes;
	DWORD	dwValue;
	static  BOOL  bServerIsActive;
	char	user[32], password[32], str[128], szCommand[128];
	static char *buffer;
	static int byte_offset;

	switch (uMsg)
	{
	case WM_INITDIALOG:
		CenterWindow(hDlg);
		if (WSAStartup( 0x0101, &wsa ))
		{
			MessageBox (hDlg, "WSAStartup failed!",APP_NAME,MB_OK);
			return FALSE;
		}

		GetPrivateProfileString("Packet Capture", "Server User", "username", user, sizeof(user), "NetworkSpy.ini");
		GetPrivateProfileString("Packet Capture", "Server Password", "", password, sizeof(password), "NetworkSpy.ini");
		GetPrivateProfileString("Packet Capture", "Server Timeout", "60", str, sizeof(str), "NetworkSpy.ini");
		
		SetDlgItemText(hDlg, IDC_EDIT_USER, user);
		SetDlgItemText(hDlg, IDC_EDIT_PASSWORD, password);
		SetDlgItemText(hDlg, IDC_EDIT_TIMEOUT, str);

		stLocalAddr.sin_family		= AF_INET;
		stLocalAddr.sin_addr.s_addr	= htonl(INADDR_ANY);
		stLocalAddr.sin_port        = htons(7035);
		
		hServerSocket = socket(PF_INET,SOCK_STREAM,0);
		WSAAsyncSelect(hServerSocket, hDlg, IP_WSAEVENT, FD_READ | FD_ACCEPT | FD_CLOSE);
		nRet = bind(hServerSocket, (LPSOCKADDR)&stLocalAddr, sizeof (stLocalAddr));
	
		if (!nRet)
		{
			listen(hServerSocket, 1);
			SendDlgItemMessage( hDlg, IDC_LIST_DEBUG, LB_INSERTSTRING, -1, (LPARAM)"Server started.");
		}
		else
			SendDlgItemMessage( hDlg, IDC_LIST_DEBUG, LB_INSERTSTRING, -1, (LPARAM)"Unable to bind to port");
		
		
		bServerIsActive = FALSE;

		tnd.cbSize =			sizeof(tnd);
		tnd.hWnd =				hDlg;
		tnd.uID =				1;
		tnd.uFlags =			NIF_ICON|NIF_MESSAGE|NIF_TIP;
		tnd.uCallbackMessage =	WM_MYNOTIFYMESSAGE;
		tnd.hIcon =				LoadIcon(hInst, MAKEINTRESOURCE(IDI_ICON1));
		lstrcpy(tnd.szTip, "Network Spy (Server Mode)");
		Shell_NotifyIcon(NIM_ADD, &tnd);

		buffer = malloc(BUFFER_SIZE);

		return TRUE;



	case IP_WSAEVENT:
		switch (LOWORD(lParam))
		{
		case FD_ACCEPT:
			wsprintf(str, "Incoming connection from %s", inet_ntoa(stRemoteAddr.sin_addr));
			SendDlgItemMessage( hDlg, IDC_LIST_DEBUG, LB_INSERTSTRING, -1, (LPARAM)str);
			dw = sizeof(stRemoteAddr);
			hTempSocket = accept(hServerSocket, (LPSOCKADDR) &stRemoteAddr, &dw);
			if (bServerIsActive)
			{
				send(hTempSocket, "- Server is Busy\n", 17, 0);
				closesocket(hTempSocket);
			}
			else
			{
				send(hTempSocket, "+ Network Spy Server Ready\n", 27, 0);
				hClientSocket = hTempSocket;
				byte_offset = 0;
			}
			return TRUE;

		case FD_CLOSE:
			g_bShutdown = TRUE;
			closesocket(hClientSocket);
			SendDlgItemMessage( hDlg, IDC_LIST_DEBUG, LB_INSERTSTRING, -1, (LPARAM)"Connection closed");
			return TRUE;

		case FD_READ:
			n = recv(hClientSocket, &buffer[byte_offset], BUFFER_SIZE - byte_offset, 0);
			buffer[byte_offset + n] = '\0';

			if (strrchr(buffer, '\n') == NULL)  // not a complete line
			{
				byte_offset += n;
				return TRUE;
			}

			byte_offset = 0;
			lstrcpy(szCommand, buffer);
			szCommand[4] = '\0';

			SendDlgItemMessage( hDlg, IDC_LIST_DEBUG, LB_INSERTSTRING, -1, (LPARAM)buffer);

			if (lstrcmp(szCommand, "RETR") == 0)
			{

				/* Send and Delete the linked list */
				n = 0;
				while (head_ptr != NULL)
				{
					cur_ptr = head_ptr;
					head_ptr = head_ptr->next;

					i = 0;
					memcpy(&buffer[i], &cur_ptr->time, sizeof(SYSTEMTIME));
					i += sizeof(SYSTEMTIME);
					memcpy(&buffer[i], &cur_ptr->size, sizeof(int));
					i += sizeof(int);
					memcpy(&buffer[i], cur_ptr->data, cur_ptr->size);
					i += cur_ptr->size;

					bytes_sent = 0;
					total_bytes = i;
					while (bytes_sent < total_bytes)
					{
						i = send(hClientSocket, &buffer[bytes_sent] , total_bytes - bytes_sent, 0);
						bytes_sent += i;
					}

					free(cur_ptr->data);
					free(cur_ptr);

					++n;  // packet count
				}
					
				bServerIsActive = FALSE;
				wsprintf(str, "%d packets uploaded", n);
				SendDlgItemMessage( hDlg, IDC_LIST_DEBUG, LB_INSERTSTRING, -1, (LPARAM) str);
			}
			else if (!lstrcmp(szCommand, "BEGN"))
			{
				GetDlgItemText(hDlg,IDC_EDIT_USER, user, sizeof(user));
				GetDlgItemText(hDlg,IDC_EDIT_PASSWORD, password, sizeof(password));

				wsprintf(str, "%s %s\n", user, password);
				if (!lstrcmp(str, &buffer[5]))
				{
					g_bShutdown = FALSE;
					g_bServerMode = TRUE;
					bytes_used = 0;
					hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) WinDis, NULL, 0, &dwValue);

					if( hThread ) CloseHandle( hThread );
			
					bServerIsActive = TRUE;

					wsprintf(str, "Capture activated from %s", inet_ntoa(stRemoteAddr.sin_addr));
					SendDlgItemMessage( hDlg, IDC_LIST_DEBUG, LB_INSERTSTRING, -1, (LPARAM)str);
					
					n = GetDlgItemInt(hDlg, IDC_EDIT_TIMEOUT, NULL, FALSE);

					SetTimer(hDlg, 1, n * 1000, NULL);
					send(hClientSocket, "+ Capture Activated\n" , 20, 0);
				}
				else
				{
					SendDlgItemMessage( hDlg, IDC_LIST_DEBUG, LB_INSERTSTRING, -1, (LPARAM)"Incorrect login");
					wsprintf(buffer, "- Incorrect login\n");
					send(hClientSocket, buffer , lstrlen(buffer), 0);
				}
				
			}
			else if (!lstrcmp(szCommand, "STOP")) 
			{
				g_bShutdown = TRUE;
			}
			return TRUE;
		}
		break;


	case WM_TIMER:
		KillTimer(hDlg, 1);
		g_bShutdown = TRUE;
		return TRUE;

	
	case MY_CAPTURE_COMPLETE:
		n = 0;
		cur_ptr = head_ptr;
		while (cur_ptr != NULL)
		{
			++n;
			cur_ptr = cur_ptr->next;
		}

		wsprintf(buffer, "0 %d\n", bytes_used + (n * (sizeof(SYSTEMTIME) + sizeof(int))));
		send(hClientSocket, buffer, lstrlen(buffer), 0);

		bServerIsActive = FALSE;
		
		return TRUE;


	case WM_COMMAND:
		switch (LOWORD(wParam))
		{	
		case ID_CANCEL:
			SendMessage(hDlg, WM_CLOSE, 0, 0);
			return TRUE;

		case ID_MINIMIZE:
			ShowWindow(hDlg, SW_HIDE);
			ShowWindow(hWndMain, SW_HIDE);
			return TRUE;

		}
		break;


	case WM_MYNOTIFYMESSAGE:
		switch (LOWORD(lParam))
		{
		case WM_LBUTTONUP:
			ShowWindow(hDlg, SW_SHOW);
			ShowWindow(hWndMain, SW_SHOW);
			SetForegroundWindow(hDlg);
			return 0;
		}
		break;

	
	case WM_CLOSE:
		g_bShutdown = TRUE;

		Shell_NotifyIcon(NIM_DELETE, &tnd);

		GetDlgItemText(hDlg, IDC_EDIT_USER, user, sizeof(user));
		GetDlgItemText(hDlg, IDC_EDIT_PASSWORD, password, sizeof(password));
		GetDlgItemText(hDlg, IDC_EDIT_TIMEOUT, str, sizeof(str));

		WritePrivateProfileString("Packet Capture", "Server User", user, "NetworkSpy.ini");
		WritePrivateProfileString("Packet Capture", "Server Password", password, "NetworkSpy.ini");
		WritePrivateProfileString("Packet Capture", "Server Timeout", str, "NetworkSpy.ini");

		g_bServerMode = FALSE;
		closesocket(hServerSocket);
		WSACleanup();
		free(buffer);

		EndDialog(hDlg, 0);
		return TRUE;
	}
	return FALSE;
}

