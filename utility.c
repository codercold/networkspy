#include <windows.h>
#include <winsock.h>
#include <commctrl.h>
#include "common.h"
#include "structs.h"
#include "globals.h"
#include "utility.h"
#include "resource.h"




BOOL CALLBACK AboutDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	char name[64], code[64];


	switch (uMsg)
	{
	case WM_INITDIALOG:
		CenterWindow(hDlg);

		SetDlgItemText(hDlg, IDC_HTML, 
						"<BODY BGCOLOR=#ffffff><FONT COLOR=#000099 SIZE=5>"
						"<IMG ALIGN=right SRC=RES:logo.png><b>Network Spy</b></FONT>"
						"<BR>Version 2.0<BR>"
						"Released: Jan 07, 2003<BR>"
						"Copyright ©1998-2003 Sumit Birla <BR> <BR>"
						"Website: <a TITLE=\"Click to visit home page\" href=http://sumitbirla.com/network-spy/netspy.php>http://sumitbirla.com/network-spy/</a><BR>");
		InvalidateRect(GetDlgItem(hDlg, IDC_HTML), NULL, TRUE);

		GetPrivateProfileString("Registration", "User Name", "NOT REGISTERED", name, sizeof(name), INI_FILE);
		SetDlgItemText(hDlg, IDC_EDIT_USERNAME, name);

		GetPrivateProfileString("Registration", "Key", "NOT REGISTERED", code, sizeof(code), INI_FILE);
		SetDlgItemText(hDlg, IDC_EDIT_REGKEY, code);

		if (CheckRegistration(name, code))
		{
			EnableWindow(GetDlgItem(hDlg, IDC_EDIT_USERNAME), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDC_EDIT_REGKEY), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDC_REGISTER), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDC_BUY), FALSE);
		}

		return TRUE;
	

	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return TRUE;


	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_REGISTER:
			GetDlgItemText(hDlg, IDC_EDIT_USERNAME, name, sizeof(name));
			GetDlgItemText(hDlg, IDC_EDIT_REGKEY, code, sizeof(code));
			if (CheckRegistration(name, code))
			{
				MessageBox(hDlg, "This software is now registered.", "Network Spy", MB_ICONINFORMATION);
				EnableWindow(GetDlgItem(hDlg, IDC_EDIT_USERNAME), FALSE);
				EnableWindow(GetDlgItem(hDlg, IDC_EDIT_REGKEY), FALSE);
				EnableWindow(GetDlgItem(hDlg, IDC_REGISTER), FALSE);
				EnableWindow(GetDlgItem(hDlg, IDC_BUY), FALSE);
			
				WritePrivateProfileString("Registration", "User Name", name, INI_FILE);
				WritePrivateProfileString("Registration", "Key", code, INI_FILE);
			}
			else
				MessageBox(hDlg, "Registration failed. Please correct the User Name and/or Registration Key or visit http://network-spy.com for help.", "Network Spy", MB_ICONINFORMATION);
			return TRUE;


		case IDC_BUY:
			ShellExecute(hDlg, NULL, "http://sumitbirla.com/network-spy/orders.php", NULL, NULL, 0);
			return TRUE;


		case ID_CLOSE:
			EndDialog(hDlg, 0);
			return TRUE;
		}
		break;
	}
	return FALSE;
}



BOOL isRegistered()
{
	char name[64], code[64];

	GetPrivateProfileString("Registration", "User Name", "NOT REGISTERED", name, sizeof(name), INI_FILE);
	GetPrivateProfileString("Registration", "Key", "NOT REGISTERED", code, sizeof(code), INI_FILE);
	
	return (CheckRegistration(name, code));

}


BOOL CheckRegistration(char *name, char *code)
{
	unsigned int	regcode = 4197762733;
	char str[32];

	if (lstrlen(name) < 4)
		return FALSE;

	regcode = (regcode & 0xfffcf7f2);
	regcode = regcode << (name[3] % 12);
	wsprintf(str, "%010u-%d%d", regcode, name[2] << 2, name[1] << 1);
	
	if (lstrcmp(str, code))
		return FALSE;

	return TRUE;
}

/*
program = SendDlgItemMessage(hDlg, IDC_COMBO_PROGRAM, CB_GETCURSEL, 0, 0);
regcode = (regcode & 0xfffcf7f2);
regcode = regcode << (name[3] % (10 + program));
wsprintf(str, "%010u-%d%d", regcode, name[2] << 2, name[1] << 1);
*/

VOID RestoreWindowPosition(HWND hDlg)
{
	RECT	rect;
	char	str[128];
	int		nRet;

	GetWindowText(hDlg, str, sizeof(str)-6);
	lstrcat(str, " Rect");

	nRet = GetPrivateProfileStruct("Packet Capture", str, &rect, sizeof(RECT), INI_FILE);

	if (nRet != 0) 
	{
		/* Sanity Check 
		rect.left = RANGE(0, rect.left, GetSystemMetrics(SM_CXSCREEN)-150);
		rect.top = RANGE(0, rect.top, GetSystemMetrics(SM_CYSCREEN)-150);
		rect.right = RANGE(rect.left + 300, rect.right, GetSystemMetrics(SM_CXSCREEN));
		rect.bottom = RANGE(rect.top + 200, rect.bottom, GetSystemMetrics(SM_CYSCREEN));
		*/
		MoveWindow(hDlg, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, TRUE);
	}
	else
		CenterWindow(hDlg);

}


VOID SaveWindowPosition(HWND hDlg)
{
	RECT	rect;
	char	str[128];

	/* save position only if no minimized or maximized */
	if (!IsIconic(hDlg))
	{	
		GetWindowRect(hDlg, &rect);
		GetWindowText(hDlg, str, sizeof(str)-6);
		lstrcat(str, " Rect");
		WritePrivateProfileStruct("Packet Capture", str, &rect, sizeof(RECT), INI_FILE);
	}

}



void CenterWindow(HWND hDlg)
{
	RECT	rect;
	long	cx, cy, cxClient, cyClient;

	GetWindowRect(hDlg, &rect);
		
	cxClient = rect.right - rect.left;
	cyClient = rect.bottom - rect.top;
	cx = GetSystemMetrics(SM_CXSCREEN);
	cy = GetSystemMetrics(SM_CYSCREEN);

	MoveWindow(	hDlg,
				(cx - cxClient) / 2,
				(cy - cyClient) / 2,
				cxClient,
				cyClient,
				TRUE );

	GetClientRect(hDlg, &rect);
	SendMessage(hDlg, WM_SIZE, SIZE_RESTORED, MAKELPARAM(rect.right, rect.bottom));
}



VOID SetListPosLast(HWND hDlg)
{
	int index;

	index = SendDlgItemMessage( hDlg, IDC_LIST1, LB_GETCOUNT, 0, 0 ) - 1;
	SendDlgItemMessage( hDlg, IDC_LIST1, LB_SETTOPINDEX, index, 0 );
}


VOID LoadList(HWND hwndList, char *name)
{
	int		index;
	char	str[256], item[12];

	for (index = 1; index < 11; index++)
	{
		wsprintf(item, "Item%d", index);
		GetPrivateProfileString(name, item,"", str, 256, INI_FILE);
		if (lstrcmp(str, ""))
			SendMessage(hwndList, CB_ADDSTRING, 0, (LPARAM)str);
	}
	SendMessage(hwndList, CB_SETCURSEL, 0, 0);
}

VOID SaveList(HWND hwndList, char *name)
{
	int		index, count;
	char	str[256], item[12];

	count = SendMessage(hwndList, CB_GETCOUNT, 0, 0);

	if (count > 11)
		count = 11;
	
	for (index = 0; index < count; index++)
	{
		wsprintf(item, "Item%d", index + 1);
		SendMessage(hwndList, CB_GETLBTEXT, index, (LPARAM)str);
		WritePrivateProfileString(name, item, str, INI_FILE);
	}
}

VOID AddToList(HWND hwndList, char *string)
{
	int		index, count;
	char	str[256];

	count = SendMessage(hwndList, CB_GETCOUNT, 0, 0);
	
	for (index = 0; index < count; index++)
	{
		SendMessage(hwndList, CB_GETLBTEXT, index, (LPARAM)str);
		if (!lstrcmp(string, str))
			SendMessage(hwndList, CB_DELETESTRING, index, 0);
	}
	SendMessage(hwndList, CB_INSERTSTRING, 0, (LPARAM)string);
	SendMessage(hwndList, CB_SETCURSEL, 0, 0);
}


BOOL CopyListViewData( HWND hWndList, int nColumns )
{
   HANDLE hMem;
   char *szBuffer, str[128];
   int		iCount, i, j;

   if( ! OpenClipboard( hWndList ) )
      return( FALSE );

   EmptyClipboard();

   hMem = GlobalAlloc( GHND | GMEM_DDESHARE, 65535 );
   szBuffer = GlobalLock( hMem );
   *szBuffer = '\0';
		
	iCount = ListView_GetItemCount( hWndList );
	for( i = 0; i < iCount; i++ )           
	{   
		for (j=0; j < nColumns;j++)
		{
			*str = '\0';
			ListView_GetItemText(hWndList, i, j, str, sizeof(str)-1);
			lstrcat(szBuffer, str);
			lstrcat(szBuffer,"\t");
		}
		lstrcat(szBuffer, "\r\n");
	}
   
   GlobalUnlock( hMem );
   SetClipboardData( CF_TEXT, hMem );
   CloseClipboard();

   return( TRUE );
}


BOOL CopyToClipBoard( char *str )
{
   HANDLE hMem;
   char *szBuffer;

   if( ! OpenClipboard( NULL ) )
      return( FALSE );

   EmptyClipboard();

   hMem = GlobalAlloc( GHND | GMEM_DDESHARE, lstrlen(str)+1 );
   szBuffer = GlobalLock( hMem );
   *szBuffer = '\0';
   lstrcat(szBuffer, str);
	
   GlobalUnlock( hMem );
   SetClipboardData( CF_TEXT, hMem );
   CloseClipboard();

   return( TRUE );
}




DWORD RANGE(DWORD min, DWORD val, DWORD max)
{
	if (val < min)
		return min;
	else if (val > max)
		return max;

	return val;
}


char *GetParamFromCommandLine(char *command)
{
	int i, j, len;

	len = lstrlen(command);

	for (i = 0; i < len; i++)
		if (command[i] == '"')
			break;

	for (j = i+1; j < len; j++)
		if (command[j] == '"')
		{
			if ((command[j+1] == ' ') && IsCharAlphaNumeric(command[j+2]))
				return &command[j+2];
			break;
		}
	
	return NULL;
}



char *IpToString(unsigned long ip)
{
	struct in_addr inaddr;

	inaddr.S_un.S_addr = ip;

	return inet_ntoa(inaddr);
}



void FormatByteValue(u_long numBytes, char *str)
{
	int r, q;

	if (numBytes < 1024)
	{
		wsprintf(str, "%d B", numBytes);
		return;
	}


	r = numBytes % 1024;
	q = numBytes / 1024;

	if (q < 1024)
	{
		wsprintf(str, "%d.%d kB", q, r*10/1024);
		return;
	}

	r = q % 1024;
	q = q / 1024;

	wsprintf(str, "%d.%d MB", q, r*10/1024);
}


void FormatBitRateValue(u_long numBytes, char *str)
{
	int r, q, numBits;

	numBits = numBytes * 8;

	r = numBits % 1000;
	q = numBits / 1000;

	if (q < 1000)
	{
		wsprintf(str, "%d.%d kbps", q, r*10/1000);
		return;
	}

	r = q % 1000;
	q = q / 1000;

	wsprintf(str, "%d.%d Mbps", q, r*10/1000);
}



void PrintRawData(unsigned char *data, int size, char *szBuffer)
{
	int i, j;
	char temp[256];


	lstrcpy(szBuffer, "0000  ");
	for (i = 0; i < size; i++)
	{
		wsprintf (temp, "%02X ", data[i]);
		lstrcat(szBuffer, temp);
		if (((i + 1) % 16) == 0)
		{
			lstrcat(szBuffer, "  ");
			for (j = i - 15; j <= i; j++)
			{
				if ((data[j] > 33) && (data[j] < 125)) 
					wsprintf (temp, "%c", data[j]);
				else
					wsprintf (temp, ".");
				lstrcat(szBuffer, temp);
			}
			wsprintf(temp, "\r\n%04X  ", i+1);
			lstrcat(szBuffer, temp);
		}
		else if (((i + 1) % 8) == 0)
			lstrcat(szBuffer, " ");
	}

	j = size % 16;
	for (i = j; i < 16; i++)
		lstrcat(szBuffer, "   ");
	
	if (j < 8)
		lstrcat(szBuffer, "   ");
	else
		lstrcat(szBuffer, "  ");
	
	for (i = size - j; i < size; i++)
	{
		if ((data[i] > 33) && (data[i] < 125)) 
			wsprintf (temp, "%c", data[i]);
		else
			wsprintf (temp, ".");
		
		lstrcat(szBuffer, temp);
	}
	lstrcat(szBuffer, "\r\n\r\n\r\n");

}



void ConvertPathToDir(char *path)
{
	int i, len;

	len = lstrlen(path);

	for (i = len-1; i > 0; i--)
	{
		if (path[i] == '\\')
		{
			path[i] = '\0';
			return;
		}
	}

	path[0] = '\0';
}



BOOL SavePacket(char *szFilename, char *data, int len)
{
	HANDLE	hFile;
	DWORD	BytesWritten;

	hFile = CreateFile( szFilename,
						GENERIC_WRITE,
						0,
						NULL,
						CREATE_ALWAYS,
						FILE_ATTRIBUTE_NORMAL,
						NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	WriteFile( hFile, data, len, &BytesWritten, NULL);

	CloseHandle(hFile);

	return TRUE;
}





DWORD ResolveIPs(PVOID ptr)
{
	int				iCount, index, subitem, i, j;
	BOOL			bPreviousFailed, bCapturePaused = FALSE;
	PDPARAMS		pparams;
	char			str[128], ip[128];
	WSADATA			wsa;
	u_long			lAddr;
	struct hostent  *phostent;
	DWORD			dwValue;
	HANDLE			hThread;

	pparams = (PDPARAMS) ptr;
	
	if (g_bShutdown == FALSE)
	{
		g_bShutdown = TRUE;
		bCapturePaused = TRUE;
	}

	WSAStartup(0x0101, &wsa);

	iCount = ListView_GetItemCount( hWndAlertList );
	SendMessage(pparams->hwnd, MY_SET_RANGE, (WPARAM) iCount, (LPARAM) pparams);

	for( index = 0; index < iCount; index++ )           
	{        
		for (subitem = 1; subitem < 3; subitem++)
		{
			bPreviousFailed = FALSE;
			ListView_GetItemText(hWndAlertList, index, subitem, ip, sizeof(ip));
			lAddr = inet_addr(ip);
			if (lAddr != INADDR_NONE)  // it is an IP string
			{
				// Check to see if a previous lookup on this IP failed	
				for (i = 0; i < index; i++)
				{
					for (j = 1; j < 3; j++)
					{
						ListView_GetItemText(hWndAlertList, i, j, str, sizeof(str));
						if (!lstrcmp(str, ip)) // found a matching string
						{
							bPreviousFailed = TRUE;
							break;
						}
					}
					if (bPreviousFailed) break;
				}
			}

			if (!bPreviousFailed && (lAddr != INADDR_NONE))
			{
				// retrieve and resolve IP here
				phostent = gethostbyaddr((char *)&lAddr, sizeof(lAddr), AF_INET);
				if (phostent != NULL)
					ListView_SetItemText(hWndAlertList, index, subitem, phostent->h_name);

					
				// if previous query yielded a hostname, check all other IPs
				// and if same found, replace with hostname found previously.
				if (phostent != NULL)
				{
					for (i = index + 1; i < iCount; i++)
						for (j = 1; j < 3; j++)
						{
							ListView_GetItemText(hWndAlertList, i, j, str, sizeof(str));
							if (lstrcmp(str, ip) == 0)
								ListView_SetItemText(hWndAlertList, i, j, phostent->h_name);
						}
				}
			}
			
		}

		iCount = ListView_GetItemCount( hWndAlertList );  // update in case capture is still on
		SendMessage(pparams->hwnd, MY_SET_RANGE, (WPARAM) iCount, (LPARAM) pparams);

		SendMessage(pparams->hwnd, MY_UPDATE_PROGRESS, (WPARAM) index, 0);
		if (pparams->bContinue == FALSE)
			break;
	}
	

	SendMessage(pparams->hwnd, MY_CLOSE_WINDOW, 0, 0);
	SendMessage(hWndStatus, SB_SETTEXT, (WPARAM) 1, (LPARAM) "Operation complete!");

	WSACleanup();

	if (bCapturePaused)
	{
		g_bShutdown = FALSE;
		hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) WinDis, NULL, 0, &dwValue);
		if( hThread ) CloseHandle( hThread );
	}

	return TRUE;
}





/* Hash table functions follow */

void initialize_hash_tables(void)
{
	int i;

	for (i = 0; i < HASHTABLE_SIZE; i++)
	{
		hash_table[i].port = 0;
		hash_table[i].next = NULL;		
	}
}



/*
	Function:	To add an entry in the table
	Parameters:	port number, label and type which can be 1 or 0 (tcp or udp)
	Returns:	0 if successfully added, -1 if entry already exists in table
*/
int add_to_table(unsigned short port, char *str, char type) 
{
	int			index;
	struct hash_entry *cur_ptr, *prev_ptr;


	index = port % HASHTABLE_SIZE;
	
	if (hash_table[index].port == 0)
	{
		hash_table[index].next = NULL;
		hash_table[index].port = port;
		hash_table[index].type = type;
		lstrcpy(hash_table[index].str, str);
	}	
	else
	{
		cur_ptr = &hash_table[index];
		while (cur_ptr)
		{
			if ((cur_ptr->port == port) && (cur_ptr->type == type))
				return -1;  // already exists in table
			prev_ptr = cur_ptr;
			cur_ptr = cur_ptr->next;
		}

		cur_ptr = malloc(sizeof(struct hash_entry));
		cur_ptr->next = NULL;
		cur_ptr->port = port;
		cur_ptr->type = type;
		lstrcpy(cur_ptr->str, str);
		prev_ptr->next = cur_ptr;
	}

	return 0;
}


/*
	Function:	removes and entry from the hash table
	Parameters:	port number, label and type which can be 1 or 0 (tcp or udp)
	Returns:	0 if successfully added, -1 if entry already exists in table
*/
int remove_from_table(unsigned short port, char type) 
{
	int			index;
	struct hash_entry *cur_ptr, *prev_ptr;


	/* Find out which slot this should be found in */
	index = port % HASHTABLE_SIZE;
	
	/* Case 1:  The slot is empty! */
	if (hash_table[index].port == 0) 
		return -1;
	/* Case 2:  There is something else in the slot */
	else if ((hash_table[index].port != port) || (hash_table[index].type != type))
	{
		prev_ptr = &hash_table[index];
		cur_ptr = hash_table[index].next;
		while (cur_ptr)
		{
			/* Found in the linked list */
			if ((cur_ptr->port == port) && (cur_ptr->type == type))
			{
				prev_ptr->next = cur_ptr->next;
				free(cur_ptr);
				return 0;
			}
			prev_ptr = cur_ptr;
			cur_ptr = cur_ptr->next;
		}
		return -1;	/* not found in the linked list */
	}
	/* Case 3:  The slot contains our entry */
	else
	{
		if (hash_table[index].next == NULL)		/* there are no linked entries */ 
			hash_table[index].port = 0;			/* mark it open */
		else
		{	/* move first linked entry to the main array and delete memory */
			cur_ptr = hash_table[index].next;
			memcpy(&hash_table[index], cur_ptr, sizeof(struct hash_entry));
			free(cur_ptr);
		}
		return 0;
	}
	return 0;
}



char * find_in_table(unsigned short port, char type) // 0 = UDP, 1 = TCP
{
	int	index;
	struct hash_entry *cur_ptr;

	index = port % HASHTABLE_SIZE;
	if ((hash_table[index].port == port) && (hash_table[index].type == type))
		return hash_table[index].str;
	
	cur_ptr = hash_table[index].next;
	while (cur_ptr)
	{
		if ((cur_ptr->port == port) && (cur_ptr->type == type))
			return cur_ptr->str;

		cur_ptr = cur_ptr->next;
	}

	return NULL;
}



void cleanup_hash_tables(void)
{
	struct hash_entry *cur_ptr, *prev_ptr;
	int i;

	for (i = 0; i < HASHTABLE_SIZE; i++)
	{
		prev_ptr = &hash_table[i];
		cur_ptr = hash_table[i].next;
		while (cur_ptr)
		{
			prev_ptr = cur_ptr;
			cur_ptr = cur_ptr->next;
			free(prev_ptr);
		}
	}

}



/**************************************************************************
 *
 *		DEBUG WINDOW ROUTINES
 *
 *************************************************************************/


BOOL CALLBACK DebugDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		return TRUE;
	

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case ID_CLOSE:
			DestroyWindow(hWndDebug);
			hWndDebug = NULL;
			return TRUE;
		}
		break;
	
	}
	return FALSE;
}


void OpenDebugWindow()
{
	if (hWndDebug == NULL)
		hWndDebug = CreateDialog(hInst, MAKEINTRESOURCE(IDD_DEBUG), NULL, DebugDlgProc);

}



void debug(char *str)
{
	if (hWndDebug != NULL) {
		SendDlgItemMessage( hWndDebug, IDC_EDIT_DEBUG, EM_SETSEL, 0xFFFFFFFF, -1 );
		SendDlgItemMessage( hWndDebug, IDC_EDIT_DEBUG, EM_REPLACESEL, FALSE, (LPARAM)str );
	}
}



void SetupDefaultServices()
{
	add_to_table(7,"echo",TCP);
	add_to_table(7,"echo",UDP);
	add_to_table(9,"discard",TCP);
	add_to_table(9,"discard",UDP);
	add_to_table(11,"systat",TCP);
	add_to_table(13,"daytime",TCP);
	add_to_table(13,"daytime",UDP);
	add_to_table(15,"netstat",TCP);
	add_to_table(17,"qotd",TCP);
	add_to_table(17,"qotd",UDP);
	add_to_table(19,"chargen",TCP);
	add_to_table(19,"chargen",UDP);
	add_to_table(20,"ftp-data",TCP);
	add_to_table(21,"ftp",TCP);
	add_to_table(23,"telnet",TCP);
	add_to_table(25,"smtp",TCP);
	add_to_table(37,"time",UDP);
	add_to_table(42,"name",TCP);
	add_to_table(43,"whois",TCP);
	add_to_table(53,"dns",UDP);
	add_to_table(69,"tftp",UDP);
	add_to_table(70,"gopher",TCP);
	add_to_table(79,"finger",TCP);
	add_to_table(80,"http",TCP);
	add_to_table(109,"pop2",TCP);
	add_to_table(110,"pop3",TCP);
	add_to_table(119,"nntp",TCP);
	add_to_table(123,"ntp",TCP);
	add_to_table(137,"netbios-ns",TCP);
	add_to_table(137,"netbios-ns",UDP);
	add_to_table(138,"netbios-dgm",TCP);
	add_to_table(138,"netbios-dgm",UDP);
	add_to_table(139,"netbios-ssn",TCP);
	add_to_table(139,"netbios-ssn",UDP);
	add_to_table(143,"imap2",TCP);
	add_to_table(143,"imap2",UDP);
	add_to_table(161,"snmp",UDP);
	add_to_table(162,"snmp-trap",UDP);
	add_to_table(194,"irc",TCP);
	add_to_table(443,"https",TCP);
	add_to_table(515,"printer",TCP);
	add_to_table(517,"talk",UDP);
	add_to_table(520,"route",UDP);
}


