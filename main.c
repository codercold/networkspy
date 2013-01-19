#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <winsock.h>

#include "resource.h"
#include "adapter.h"
#include "common.h"
#include "structs.h"
#include "globals.h"
#include "rules.h"
#include "ui.h"
#include "utility.h"
#include "fileio.h"
#include "QHTM.h"
#include "traffic.h"
#include "logging.h"
#include "ping.h"
#include "traceroute.h"
#include "dns.h"
#include "whois.h"



LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
BOOL CALLBACK DumpDlgProc(HWND, UINT, WPARAM, LPARAM);
BOOL CALLBACK SelectDumpDlgProc(HWND, UINT, WPARAM, LPARAM);
BOOL CALLBACK ProgressDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK ResolveDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK SplashDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

// NELSON
int main(void)
//int ProgramEntryPoint()

{
	HWND	hwnd;
	MSG			msg;
	WNDCLASSEX	wndclass;
	
	hwnd = FindWindow(APP_NAME, NULL);
	if (hwnd)
	{
		ShowWindow(hwnd, SW_SHOW);
		SetForegroundWindow(hwnd);
		return 0;
	}
			
	hInst = GetModuleHandle(0);
	QHTM_Initialise( hInst );

	wndclass.cbSize			= sizeof(wndclass);
	wndclass.style			= 0;
	wndclass.lpfnWndProc	= WndProc;
	wndclass.cbClsExtra		= 0;
	wndclass.cbWndExtra		= DLGWINDOWEXTRA;
	wndclass.hInstance		= hInst;
	wndclass.hIcon			= LoadIcon(hInst, MAKEINTRESOURCE(IDI_ICON1));
	wndclass.hCursor		= LoadCursor(NULL, IDC_ARROW);
	wndclass.hbrBackground	= (HBRUSH)(COLOR_MENU+1);
	wndclass.lpszMenuName	= MAKEINTRESOURCE(IDR_MENU1);
	wndclass.lpszClassName	= APP_NAME;
	wndclass.hIconSm		= LoadIcon(hInst, MAKEINTRESOURCE(IDI_ICON1));

	RegisterClassEx(&wndclass);

	hwnd = CreateDialog (hInst, MAKEINTRESOURCE(IDD_MAIN), NULL, 0);
	hWndMain = hwnd;

	if( ! hwnd )
		return( FALSE );

	hModelessDlg = NULL;

	while (GetMessage (&msg, NULL, 0, 0))
	{
		if( hModelessDlg )    
			if( IsDialogMessage( hModelessDlg, &msg ) ) 
				continue; 

		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}  
	ExitProcess(0);
	return msg.wParam;  
}



LRESULT CALLBACK WndProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	DWORD					dwValue;
	RECT					rect = {50, 50, 750, 600};
	POINT					pt;
	LPNMHDR					pnmh;
	int						parts[3], i, cumulative, remainder, throughput;
	static HMENU			hMenu, hPopupMenu;
	static char				szFile[MAX_PATH], szDir[MAX_PATH];
	static char				szPortsFile[MAX_PATH], szRulesFile[MAX_PATH];
	PDPARAMS				pparams;
	PRINTPARAMS				*print_params;
	HANDLE					hThread;
	char					*szBuffer, str[128];
	struct packet			*pkt;
	BOOL					status, bPeak;
	static int				peak, seconds;
	HWND					hWndTemp;
	WSADATA					wsa;


	switch (uMsg)
	{
	case WM_CREATE:
		/* Read in the adapter info */	
		GetPrivateProfileString("Packet Capture", "Adapter Desc", "", szAdapterDesc, sizeof(szAdapterDesc), INI_FILE);
		GetPrivateProfileString("Packet Capture", "Adapter", "", szAdapter, sizeof(szAdapter), INI_FILE);

		if (lstrlen(szAdapter) == 0)
			if(DialogBox(hInst, MAKEINTRESOURCE(IDD_ADAPTERS), hDlg, AdapterDlgProc)==0)
				ExitProcess(0); 

		g_bShutdown = TRUE;
		g_bServerMode = FALSE;
		initialize_hash_tables();

		GetWindowsDirectory(szPortsFile, MAX_PATH);
		lstrcat(szPortsFile, "\\netspy.ports");
		GetWindowsDirectory(szRulesFile, MAX_PATH);
		lstrcat(szRulesFile, "\\netspy.rules");
		if (LoadPortsFile(szPortsFile) == FALSE)
			SetupDefaultServices();

		hWndToolbar = CreateMainToolbar(hDlg, hInst);
		hWndStatus = CreateStatusWindow(  WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP, "Idle", hDlg, 1003);
		hWndTabs = CreateTabs(hDlg, hInst);
		hWndAlertList = CreateAlertsWindow(hDlg, hInst);
		hWndCounterList = CreateCountersWindow(hDlg, hInst); 
		hWndARPList = CreateARPWindow(hDlg, hInst); 
		hWndTraffic = CreateTrafficWindow(hDlg, hInst);
		MoveWindow(hWndTraffic, 0, 45, 150, 100, TRUE);

		parts[0] = 180;
		parts[1] = 320;
		parts[2] = -1;
		SendMessage(hWndStatus, SB_SETPARTS, (WPARAM) 3, (LPARAM) parts);

		RestoreWindowPosition(hDlg);

		hMenu = LoadMenu(hInst, MAKEINTRESOURCE(IDR_MENU2));
		hPopupMenu = GetSubMenu(hMenu, 0);		
			

		/* Read in logging options */
		i = GetPrivateProfileStruct("Packet Capture", "Logging Options", &logging, sizeof(logging), INI_FILE);
		if (i == 0)
		{
			logging.file_size = 1;
			GetCurrentDirectory(sizeof(logging.final_directory), logging.final_directory);
		}


		GetModuleFileName(NULL, szDir, MAX_PATH);
		ConvertPathToDir(szDir);

		g_bBufferDump = FALSE;
		head_ptr = NULL;
		cur_ptr = NULL;


		GetPrivateProfileStruct("Packet Capture", "Enable Filter", &bEnableFilter, sizeof(BOOL), INI_FILE);
		
		memset(rule_text, 0, sizeof(rule_text));
		if (LoadRules(szRulesFile) == FALSE)
			SetupDefaultRules();
		GenerateRules();
		SetupCounters(hWndCounterList);
		

		/* Load saved data if file specified on command line */
		if (GetParamFromCommandLine(GetCommandLine()) != NULL)
		{
			hThread = CreateThread( NULL, 0,(LPTHREAD_START_ROUTINE)LoadSession, GetParamFromCommandLine(GetCommandLine()), 0, &dwValue );
			if( hThread ) CloseHandle( hThread );
		}

		if (WSAStartup( MAKEWORD(2,1), &wsa ))
		{
			MessageBox (hDlg, "WSAStartup failed! Some functions will not work.", APP_NAME, MB_ICONERROR | MB_OK);
			return 0;
		}

		InitializeCriticalSection(&g_csPing);

		if (!isRegistered())
			DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUT), NULL, AboutDlgProc);

		return 0;


	case WM_SIZE:
		SendMessage(hWndToolbar, TB_AUTOSIZE, 0, 0L);
		SendMessage(hWndStatus, WM_SIZE, 0, 0L);
		MoveWindow(hWndTabs, 150, 45, LOWORD(lParam)-152, 25, TRUE);
		MoveWindow(hWndAlertList, 150, 70, LOWORD(lParam) - 150, HIWORD(lParam) - 90, TRUE);
		MoveWindow(hWndCounterList, 150, 70, LOWORD(lParam) - 150, HIWORD(lParam) - 90, TRUE);
		MoveWindow(hWndARPList, 150, 70, LOWORD(lParam) - 150, HIWORD(lParam) - 90, TRUE);
		return 0;

	
	case WM_NOTIFY:
        pnmh = (LPNMHDR) lParam;

 		if ( (pnmh->hwndFrom == hWndAlertList) && (pnmh->code == NM_DBLCLK) )
		{
			hWndDecoder = CreateDialog(hInst, MAKEINTRESOURCE(IDD_DECODE), hDlg, DecodeDlgProc);
			return 0;
		}
		else if ( (pnmh->hwndFrom == hWndAlertList) && (pnmh->code == NM_RCLICK) )
		{
			GetCursorPos(&pt);
			TrackPopupMenu(hPopupMenu, TPM_LEFTALIGN, pt.x, pt.y, 0, hDlg, NULL);
			return 0;
		}
		else if ((pnmh->code == TTN_NEEDTEXT))
		{
			LPTOOLTIPTEXT lpttt = (LPTOOLTIPTEXT) lParam;
			switch (lpttt->hdr.idFrom)
			{
			case IDC_LISTEN:
				lstrcpy(lpttt->szText, "Start listening");
				return 0;

			case IDC_STOP:
				lstrcpy(lpttt->szText, "Stop");
				return 0;

			case IDC_CLEAR:
				lstrcpy(lpttt->szText, "Clear screen");
				return 0;

			case IDC_DECODE:
				lstrcpy(lpttt->szText, "Decode selected packet");
				return 0;

			case ID_PRINT:
				lstrcpy(lpttt->szText, "Print");
				return 0;

			case IDC_ADAPTER:
				lstrcpy(lpttt->szText, "Adapters");
				return 0;

			case ID_OPTIONS_MANAGERULES:
				lstrcpy(lpttt->szText, "Manage Rules");
				return 0;

			case IDC_ONLINE_HELP:
				lstrcpy(lpttt->szText, "Help");
				return 0;

			default:
				lstrcpy(lpttt->szText, "Unknown");
				return 0;
			}
		}
		else if (pnmh->code == TCN_SELCHANGE)
		{
			i = TabCtrl_GetCurSel(pnmh->hwndFrom);
			switch(i)
			{
			case 0:
				ShowWindow(hWndAlertList, SW_SHOW);
				ShowWindow(hWndCounterList, SW_HIDE);
				ShowWindow(hWndARPList, SW_HIDE);
				SendMessage(hWndStatus, SB_SETTEXT, (WPARAM) 1, (LPARAM) "Showing alerts");
				return 0;

			case 1:
				ShowWindow(hWndCounterList, SW_SHOW);
				ShowWindow(hWndAlertList, SW_HIDE);
				ShowWindow(hWndARPList, SW_HIDE);
				SendMessage(hWndStatus, SB_SETTEXT, (WPARAM) 1, (LPARAM) "Showing counters");
				return 0;

			case 2:
				ShowWindow(hWndARPList, SW_SHOW);
				ShowWindow(hWndAlertList, SW_HIDE);
				ShowWindow(hWndCounterList, SW_HIDE);
				SendMessage(hWndStatus, SB_SETTEXT, (WPARAM) 1, (LPARAM) "Showing ARP table");
				return 0;
			}
		}
		break;



	case WM_TIMER:
		if (wParam == 1) 
		{
			/* update the stats on screen */
			++seconds;

			bPeak = FALSE;

			throughput = new_data * 8 / 1024;  // now in kbps
			if (throughput > peak)
			{
				peak = throughput;
				bPeak = TRUE;
			}

			i = throughput/10;  // some reasonable value so that something shows in graph
			SendMessage(hWndTraffic, TRAFFIC_ADD, 0, (LPARAM) &i);

			FormatBitRateValue(new_data, str);
			SetDlgItemText(hDlg, IDC_EDIT_THRUPUT, str);
			new_data = 0;

			if (bPeak)  SetDlgItemText(hDlg, IDC_EDIT_PEAK, str);

			SetDlgItemInt(hDlg, IDC_EDIT_COUNT, packets_captured, FALSE);
			FormatByteValue(total_bytes, str);
			SetDlgItemText(hDlg, IDC_EDIT_BYTES, str);
			
			i = seconds % 60;
			remainder = (seconds / 60) % 60;
			cumulative = seconds / 3600;
			wsprintf(str, "%.2d:%.2d:%.2d", cumulative, remainder, i);
			SetDlgItemText(hDlg, IDC_EDIT_TIME, str);
		}
		else if (wParam == 2)
		{
			for (i = 0; i < 256; i++)
			{
				if (counter[i].count > 0)
				{
					wsprintf(str, "%d / min", counter[i].count - counter[i].prev_count);
					ListView_SetItemText( hWndCounterList, i, 4, str);
					counter[i].prev_count = counter[i].count;

					FormatByteValue(counter[i].bytes - counter[i].prev_bytes, str);
					lstrcat(str, " / min");
					ListView_SetItemText( hWndCounterList, i, 5, str);
					counter[i].prev_bytes = counter[i].bytes;
				}
			}

		}
		else if (wParam == 3)
			g_bShutdown = TRUE;

		return 0;


	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_LISTEN:
			// capture is already active
			if (g_bShutdown == FALSE)
				return 0;

			/* Initialize stat variables */
			packets_captured = 0;
			total_bytes = 0;
			peak = 0;
			seconds = 0;
			
			/* Spawn the capture thread */
			g_bShutdown = FALSE;
			hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) WinDis, NULL, 0, &dwValue);
			if( hThread ) CloseHandle( hThread );

			return 0;


		case IDC_REMOTE:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_REMOTECAPTURE), hDlg, RemoteDlgProc);
			return 0;


		case IDC_STOP:
			g_bShutdown = TRUE;
			return 0;

		case IDC_DECODE:
			hWndDecoder = CreateDialog(hInst, MAKEINTRESOURCE(IDD_DECODE), hDlg, DecodeDlgProc);
			return 0;
		

		case IDC_DUMP_ALL:
			if (PopDumpSaveDlg(hDlg, szFile))
			{
				pparams = malloc(sizeof(DPARAMS));
				pparams->hwnd = CreateDialog(hInst, MAKEINTRESOURCE(IDD_PROGRESS), hDlg, DumpDlgProc);
				pparams->bContinue = TRUE;
				lstrcpy(pparams->filename, szFile);

				hThread = CreateThread( NULL, 0,(LPTHREAD_START_ROUTINE)DumpFile,
								pparams, 0, &dwValue );

				if( hThread ) CloseHandle( hThread );
			}
			return 0;


		case ID_ACTION_RESOLVEIPS:
			pparams = malloc(sizeof(DPARAMS));
			pparams->hwnd = CreateDialog(hInst, MAKEINTRESOURCE(IDD_PROGRESS), hDlg, ResolveDlgProc);
			pparams->bContinue = TRUE;
			//lstrcpy(pparams->filename, szFile);

			hThread = CreateThread( NULL, 0,(LPTHREAD_START_ROUTINE)ResolveIPs, pparams, 0, &dwValue );
			if( hThread ) CloseHandle( hThread );
			return 0;


		case ID_OPTIONS_NORMALMODE:
			CheckMenuItem(GetMenu(hDlg), ID_OPTIONS_NORMALMODE, MF_CHECKED);
			CheckMenuItem(GetMenu(hDlg), ID_OPTIONS_BUFFERDUMP, MF_UNCHECKED);
			CheckMenuItem(GetMenu(hDlg), ID_OPTIONS_LOGGINGMODE, MF_UNCHECKED);
			g_bBufferDump = FALSE;
			return 0;


		case ID_OPTIONS_BUFFERDUMP:
			CheckMenuItem(GetMenu(hDlg), ID_OPTIONS_NORMALMODE, MF_UNCHECKED);
			CheckMenuItem(GetMenu(hDlg), ID_OPTIONS_BUFFERDUMP, MF_CHECKED);
			CheckMenuItem(GetMenu(hDlg), ID_OPTIONS_LOGGINGMODE, MF_UNCHECKED);
			g_bBufferDump = TRUE;
			return 0;


		case ID_OPTIONS_SERVERMODE:
			hWndServer = CreateDialog(hInst, MAKEINTRESOURCE(IDD_SERVER), hDlg, ServerDlgProc);
			return 0;


		case ID_OPTIONS_PORTS:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_PORTS), hDlg, PortsDlgProc); 
			return 0;

		case ID_OPTIONS_LOGGING:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_LOGGING), hDlg, LoggingDlgProc);
			return 0;

		case ID_OPTIONS_MANAGERULES:
			status = DialogBox(hInst, MAKEINTRESOURCE(IDD_RULES), hDlg, RulesDlgProc);
			if (status) {
				DestroyRules();
				GenerateRules();
				SetupCounters(hWndCounterList);
			}
			return 0;

		case IDC_SAVE_BINARY:
			if (PopFileSaveDlg(hDlg, szFile, 2))
			{
				pkt = (struct packet *) GetSelectedItemLParam(hWndAlertList);
				if (pkt == NULL)
				{
					MessageBox(hDlg, "Nothing to save!", APP_NAME, MB_OK | MB_ICONEXCLAMATION);
					return 0;
				}

				lstrcpy(str, &szFile[lstrlen(szFile)-3]);
				if (!lstrcmp(str, "tml") || !lstrcmp(str, "htm"))
				{
					szBuffer = malloc(32000);
					DecodeSelected(pkt->time, pkt->data, pkt->size, szBuffer);
					status = SavePacket(szFile, szBuffer, lstrlen(szBuffer));
					free (szBuffer);
				}
				else if (!lstrcmp(str, "txt"))
				{
					szBuffer = malloc(32000);
					PrintRawData(pkt->data, pkt->size, szBuffer);
					status = SavePacket(szFile, szBuffer, lstrlen(szBuffer));
					free (szBuffer);
				}
				else
					status = SavePacket(szFile, pkt->data, pkt->size);
				
				if (status)
					SendMessage(hWndStatus, SB_SETTEXT, (WPARAM) 1, (LPARAM) "Packet saved!");
				else
					SendMessage(hWndStatus, SB_SETTEXT, (WPARAM) 1, (LPARAM) "Error saving packet!");
			}
			return 0;


		case ID_FILE_EXPORT:
			if (PopSessionSaveDlg(hDlg, szFile))
			{
				hThread = CreateThread( NULL, 0,(LPTHREAD_START_ROUTINE)SaveSession, szFile, 0, &dwValue );
				if( hThread ) CloseHandle( hThread );
			}
			return 0;


		case ID_FILE_IMPORT:
			if (PopSessionOpenDlg(hDlg, szFile))
			{
				hThread = CreateThread( NULL, 0,(LPTHREAD_START_ROUTINE)LoadSession, szFile, 0, &dwValue );
				if( hThread ) CloseHandle( hThread );
			}
			return 0;


		case ID_PRINT:
			print_params = malloc(sizeof(PRINTPARAMS));
			print_params->hDlg = hWndAlertList;
			print_params->mode = 0;
			hThread = CreateThread( NULL, 0,(LPTHREAD_START_ROUTINE)PrintSession, print_params, 0, &dwValue );
			if( hThread ) CloseHandle( hThread );
			return 0;


		case ID_PRINT_DLG:
			print_params = malloc(sizeof(PRINTPARAMS));
			print_params->hDlg = hWndAlertList;
			print_params->mode = 1;
			hThread = CreateThread( NULL, 0,(LPTHREAD_START_ROUTINE)PrintSession, print_params, 0, &dwValue );
			if( hThread ) CloseHandle( hThread );
			return 0;


		case ID_PRINT_PREVIEW:
			CreateDialog(hInst, MAKEINTRESOURCE(IDD_PRINT_PREVIEW), hDlg, PrintPreviewDlgProc);
			return 0;


		case IDC_EXIT:
			DestroyWindow(hDlg);
			return 0;

		case IDC_ADAPTER:
			g_bShutdown = TRUE;
			DialogBox(hInst, MAKEINTRESOURCE(IDD_ADAPTERS), hDlg, AdapterDlgProc); 
			return 0;

		case IDC_CLEAR:
			SetupCounters(hWndCounterList);
			ListView_DeleteAllItems(hWndARPList);
			if (ListView_GetItemCount(hWndAlertList) > 0) DialogBox(hInst, MAKEINTRESOURCE(IDD_DELETE), hDlg, ProgressDlgProc);
			bytes_used = 0;
			count = 0;
			return 0;

		case ID_TOOLS_PING:
			CreateDialog(hInst, MAKEINTRESOURCE(IDD_PING), hDlg, PingDlgProc);
			return 0;
		
		case ID_TOOLS_TRACEROUTE:
			CreateDialog(hInst, MAKEINTRESOURCE(IDD_TRACEROUTE), hDlg, TraceDlgProc);
			return 0;

		case ID_TOOLS_HOSTLOOKUP:
			CreateDialog(hInst, MAKEINTRESOURCE(IDD_HOSTLOOKUP), hDlg, HostLookupDlgProc);
			return 0;

		case ID_TOOLS_WHOIS:
			CreateDialog(hInst, MAKEINTRESOURCE(IDD_WHOIS), hDlg, WhoisDlgProc);
			return 0;

		case ID_PACKET_GENERATOR:
			CreateDialog(hInst, MAKEINTRESOURCE(IDD_PACKETG), hDlg, PacketGDlgProc);
			return 0;

		case ID_TOOLS_DEBUG:
			OpenDebugWindow();
			return 0;

		case ID_POPUP_SOURCEIP_TRACEROUTE:
			i = ListView_GetNextItem(hWndAlertList, -1, LVNI_ALL | LVNI_SELECTED);
			if (i < 0)  return 0;
			ListView_GetItemText(hWndAlertList, i, 1, str, sizeof(str));
			hWndTemp = CreateDialog(hInst, MAKEINTRESOURCE(IDD_TRACEROUTE), hDlg, TraceDlgProc);
			SetDlgItemText(hWndTemp, IDC_COMBO_HOSTS, str);
			SendMessage(hWndTemp, WM_COMMAND, ID_TRACE, 0);
			return 0;

		case ID_POPUP_DESTINATIONIP_TRACEROUTE:
			i = ListView_GetNextItem(hWndAlertList, -1, LVNI_ALL | LVNI_SELECTED);
			if (i < 0)  return 0;
			ListView_GetItemText(hWndAlertList, i, 2, str, sizeof(str));
			hWndTemp = CreateDialog(hInst, MAKEINTRESOURCE(IDD_TRACEROUTE), hDlg, TraceDlgProc);
			SetDlgItemText(hWndTemp, IDC_COMBO_HOSTS, str);
			SendMessage(hWndTemp, WM_COMMAND, ID_TRACE, 0);
			return 0;

		case ID_POPUP_SOURCEIP_PING:
			i = ListView_GetNextItem(hWndAlertList, -1, LVNI_ALL | LVNI_SELECTED);
			if (i < 0)  return 0;
			ListView_GetItemText(hWndAlertList, i, 1, str, sizeof(str));
			hWndTemp = CreateDialog(hInst, MAKEINTRESOURCE(IDD_PING), hDlg, PingDlgProc);
			SetDlgItemText(hWndTemp, IDC_COMBO_HOSTS, str);
			SendMessage(hWndTemp, WM_COMMAND, ID_PING, 0);
			return 0;

		case ID_POPUP_DESTINATIONIP_PING:
			i = ListView_GetNextItem(hWndAlertList, -1, LVNI_ALL | LVNI_SELECTED);
			if (i < 0)  return 0;
			ListView_GetItemText(hWndAlertList, i, 2, str, sizeof(str));
			hWndTemp = CreateDialog(hInst, MAKEINTRESOURCE(IDD_PING), hDlg, PingDlgProc);
			SetDlgItemText(hWndTemp, IDC_COMBO_HOSTS, str);
			SendMessage(hWndTemp, WM_COMMAND, ID_PING, 0);
			return 0;

		case ID_POPUP_SOURCEIP_DNSLOOKUP:
			i = ListView_GetNextItem(hWndAlertList, -1, LVNI_ALL | LVNI_SELECTED);
			if (i < 0)  return 0;
			ListView_GetItemText(hWndAlertList, i, 1, str, sizeof(str));
			hWndTemp = CreateDialog(hInst, MAKEINTRESOURCE(IDD_HOSTLOOKUP), hDlg, HostLookupDlgProc);
			SetDlgItemText(hWndTemp, IDC_COMBO_HOSTNAMES, str);
			SendMessage(hWndTemp, WM_COMMAND, ID_RESOLVE, 0);
			return 0;

		case ID_POPUP_DESTINATIONIP_DNSLOOKUP:
			i = ListView_GetNextItem(hWndAlertList, -1, LVNI_ALL | LVNI_SELECTED);
			if (i < 0)  return 0;
			ListView_GetItemText(hWndAlertList, i, 2, str, sizeof(str));
			hWndTemp = CreateDialog(hInst, MAKEINTRESOURCE(IDD_HOSTLOOKUP), hDlg, HostLookupDlgProc);
			SetDlgItemText(hWndTemp, IDC_COMBO_HOSTNAMES, str);
			SendMessage(hWndTemp, WM_COMMAND, ID_RESOLVE, 0);
			return 0;

		case ID_POPUP_SOURCEIP_WHOIS:
			i = ListView_GetNextItem(hWndAlertList, -1, LVNI_ALL | LVNI_SELECTED);
			if (i < 0)  return 0;
			ListView_GetItemText(hWndAlertList, i, 1, str, sizeof(str));
			hWndTemp = CreateDialog(hInst, MAKEINTRESOURCE(IDD_WHOIS), hDlg, WhoisDlgProc);
			SetDlgItemText(hWndTemp, IDC_COMBO_DOMAINS, str);
			SendDlgItemMessage(hWndTemp, IDC_COMBO_SERVERS, CB_SETCURSEL  , (WPARAM) 4, 0);
			SendMessage(hWndTemp, WM_COMMAND, ID_LOOKUP, 0);
			return 0;

		case ID_POPUP_DESTINATIONIP_WHOIS:
			i = ListView_GetNextItem(hWndAlertList, -1, LVNI_ALL | LVNI_SELECTED);
			if (i < 0)  return 0;
			ListView_GetItemText(hWndAlertList, i, 2, str, sizeof(str));
			hWndTemp = CreateDialog(hInst, MAKEINTRESOURCE(IDD_WHOIS), hDlg, WhoisDlgProc);
			SetDlgItemText(hWndTemp, IDC_COMBO_DOMAINS, str);
			SendDlgItemMessage(hWndTemp, IDC_COMBO_SERVERS, CB_SETCURSEL  , (WPARAM) 4, 0);
			SendMessage(hWndTemp, WM_COMMAND, ID_LOOKUP, 0);
			return 0;


		case IDC_ONLINE_HELP:
			ShellExecute(0, NULL, "http://sumitbirla.com/network-spy/help2/", NULL, NULL, SW_SHOW);
			return 0;

		case IDC_ABOUT:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUT), hDlg, AboutDlgProc); 
			return 0;
		}
		break;


	case MY_CAPTURE_COMPLETE:
		if (bytes_used > 0)
		{
			i = DialogBox(hInst, MAKEINTRESOURCE(IDD_DUMP), hDlg, SelectDumpDlgProc);
			if (i == 1)		/* to disk */
			{
				if (PopFileSaveDlg(hDlg, szFile, 1))
				{
					pparams = malloc(sizeof(DPARAMS));
					pparams->hwnd = CreateDialog(hInst, MAKEINTRESOURCE(IDD_PROGRESS), hDlg, DumpDlgProc);
					pparams->bContinue = TRUE;
					lstrcpy(pparams->filename, szFile);

					hThread = CreateThread( NULL, 0,(LPTHREAD_START_ROUTINE)DumpBuffer,
									pparams, 0, &dwValue );
						
					if( hThread ) CloseHandle( hThread );
					return 0;
				}
			}
			if (i == 2)		/* view in listview */
			{
				cur_ptr = head_ptr;
				while (cur_ptr != NULL)
				{
					ProcessPacket(cur_ptr->time, cur_ptr->data, cur_ptr->size, bEnableFilter);
					cur_ptr = cur_ptr->next;
				}
			}
			
			// Destroy the linked list
			while (head_ptr != NULL)
			{
				cur_ptr = head_ptr;
				head_ptr = head_ptr->next;
				free(cur_ptr->data);
				free(cur_ptr);
			}
			bytes_used = 0;
		}
		return 0;


	case WM_SYSCOMMAND:
		if (wParam == SC_CLOSE)
		{
			if (g_bIsRunning)
			{
				MessageBox(hDlg, "Packet capture is active.  Please stop capture before exiting program.", APP_NAME, MB_ICONEXCLAMATION | MB_OK);
				return 0;
			}
		}
		break;


	case WM_ENDSESSION:
		DestroyWindow(hDlg);
		return 0;


	case WM_DESTROY:
		hWndMain = NULL;
		g_bShutdown = TRUE;
		while (g_bIsRunning)
			Sleep(200); // Make sure thread exited


		// Delete the list if packets still in buffer
		if (ListView_GetItemCount(hWndAlertList) > 0) DialogBox(hInst, MAKEINTRESOURCE(IDD_DELETE), hDlg, ProgressDlgProc);


		DestroyMenu(hMenu);

		/* Save all settings */
		SaveWindowPosition(hDlg);
		SaveColumnWidths(hWndAlertList, hWndCounterList, hWndARPList);

		WritePrivateProfileString("Packet Capture", "Adapter", szAdapter, INI_FILE);
		WritePrivateProfileString("Packet Capture", "Adapter Desc", szAdapterDesc, INI_FILE);
		WritePrivateProfileStruct("Packet Capture", "Enable Filter", &bEnableFilter, sizeof(BOOL), INI_FILE);

		SavePortsFile(szPortsFile);
		SaveRules(szRulesFile);
		cleanup_hash_tables();

		DestroyRules();
		DestroyWindow(hWndDebug);
		DeleteCriticalSection(&g_csPing);
	
		WSACleanup();

		if (!isRegistered()) 
			DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUT), NULL, AboutDlgProc);

		PostQuitMessage (0);
		return 0;

	}
	return DefWindowProc(hDlg, uMsg, wParam, lParam);
}








BOOL CALLBACK DumpDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	HWND		hwndAnim;
	static PDPARAMS pparams;
	char			str[64];
	int				percent;
	static int		max;

	switch (uMsg)
	{
	case WM_INITDIALOG:
		InitCommonControls();
		
		hwndAnim = GetDlgItem(hDlg, IDC_ANIMATE1);
		Animate_Open(hwndAnim, MAKEINTRESOURCE(IDR_AVI2));

		//SendDlgItemMessage(hDlg, IDC_PROGRESS1, PBM_SETRANGE, 0, MAKELPARAM(0, bytes_used));

		SetTimer(hDlg, 1, 1000, NULL);
		return TRUE;
	
	case WM_TIMER:
		KillTimer(hDlg, 1);
		ShowWindow(hDlg, SW_SHOW);
		return TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case ID_CANCEL:
			pparams->bContinue = FALSE;
			//EndDialog(hDlg, 0);
			return TRUE;
		}
		break;
	
	case MY_SET_RANGE:
		max = wParam;
		pparams = (PDPARAMS) lParam;
		return TRUE;

		
	case MY_UPDATE_PROGRESS:
		percent = 100 * wParam / max;
		SendDlgItemMessage(hDlg, IDC_PROGRESS1, PBM_SETPOS, (WPARAM) percent, 0);
		wsprintf(str, "%d bytes saved", wParam);
		SetDlgItemText(hDlg, IDC_STATUS, str);
		return TRUE;

	case MY_CLOSE_WINDOW:
		KillTimer(hDlg, 1);
		Animate_Close(GetDlgItem(hDlg, IDC_ANIMATE1));
		EndDialog(hDlg, 0);
		return TRUE;

	case WM_CLOSE:
		Animate_Close(GetDlgItem(hDlg, IDC_ANIMATE1));
		EndDialog(hDlg, 0);
		return TRUE;
	
	}
	return FALSE;
}




BOOL CALLBACK SelectDumpDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{

	switch (uMsg)
	{
	case WM_INITDIALOG:
		CenterWindow(hDlg);
		return TRUE;
	
	
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_DISK:
			EndDialog(hDlg, 1);
			return TRUE;

		case IDC_BUTTON_VIEW:
			EndDialog(hDlg, 2);
			return TRUE;

		case IDC_BUTTON_CANCEL:
			EndDialog(hDlg, 0);
			return TRUE;
		}
		break;


	case WM_CLOSE:
		EndDialog(hDlg, 0);
		return TRUE;
	}
	return FALSE;
}




DWORD DeleteListThread(PVOID ptr)
{	
	int				index, num, percent, prev_percent=0;
	LV_ITEM			lvItem;
	struct packet	*pkt;
	PDPARAMS		pparams;
	char			str[64];
	BOOL			bPaused = FALSE;
	DWORD			dwValue;
	HANDLE			hThread;

	if (g_bShutdown == FALSE)
	{
		g_bShutdown = TRUE;
		/* wait for capture thread to shutdown */
		while (g_bIsRunning) Sleep(100);
		
		bPaused = TRUE;
	}

	

	pparams = (PDPARAMS) ptr;
	
	lvItem.mask = LVIF_PARAM;
	lvItem.iSubItem = 0;

	num = ListView_GetItemCount(hWndAlertList);

	for (index = 0; index < num; index++)
	{
		lvItem.iItem = index;
		ListView_GetItem(hWndAlertList, &lvItem);
		pkt = (struct packet *)lvItem.lParam;
		free(pkt->data);
		free(pkt);

		percent = 100 * (index + 1) / num;
		if ((percent - prev_percent) > 4)
		{
			SendDlgItemMessage(pparams->hwnd, IDC_PROGRESS1, PBM_SETPOS, (WPARAM) percent, 0);
			wsprintf(str, "%d packets deleted", index + 1);
			SetDlgItemText(pparams->hwnd, IDC_STATUS, str);
			prev_percent = percent;
		}
	}



	/* Using this loop cuz ListView_DeleteAllItems() is extremely slow */
	SendDlgItemMessage(pparams->hwnd, IDC_TASK, WM_SETTEXT, 0, (LPARAM) "Clearing list. Please wait...");
	prev_percent = 0;
	SendMessage(hWndAlertList, WM_SETREDRAW, (WPARAM) FALSE, 0);
	for (index = num - 1; index >= 0; index--)
	{
		ListView_DeleteItem(hWndAlertList, index);
		percent = 100 * (num - index) / num;
		if ((percent - prev_percent) > 4)
		{
			SendDlgItemMessage(pparams->hwnd, IDC_PROGRESS1, PBM_SETPOS, (WPARAM) percent, 0);
			wsprintf(str, "%d of %d items removed", num - index, num);
			SetDlgItemText(pparams->hwnd, IDC_STATUS, str);
			prev_percent = percent;
		}
	}
	SendMessage(hWndAlertList, WM_SETREDRAW, (WPARAM) TRUE, 0);


	SendMessage(pparams->hwnd, MY_CLOSE_WINDOW, 0, 0);
	SendMessage(hWndStatus, SB_SETTEXT, (WPARAM) 2, (LPARAM) "");

	
	/* Restart capture if it was previously active */
	if (bPaused)
	{
		g_bShutdown = FALSE;
		hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) WinDis, NULL, 0, &dwValue);
		if( hThread ) CloseHandle( hThread );
	}

	ExitThread(0);

	return 0;
}



BOOL CALLBACK ProgressDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	HWND		hwndAnim;
	PDPARAMS	pparams;
	HANDLE		hThread;
	DWORD		dw;

	switch (uMsg)
	{
	case WM_INITDIALOG:
		CenterWindow(hDlg);

		InitCommonControls();
		
		hwndAnim = GetDlgItem(hDlg, IDC_ANIMATE1);
		Animate_Open(hwndAnim, MAKEINTRESOURCE(IDR_AVI1));

		pparams = malloc(sizeof(DPARAMS));
		pparams->hwnd = hDlg;

		hThread = CreateThread( NULL, 0,(LPTHREAD_START_ROUTINE)DeleteListThread,
								pparams, 0, &dw );
		CloseHandle(hThread);
		return TRUE;

	
	case MY_CLOSE_WINDOW:
		Sleep(1500);
		Animate_Close(GetDlgItem(hDlg, IDC_ANIMATE1));
		EndDialog(hDlg, 0);
		return TRUE;

	case WM_CLOSE:
		Animate_Close(GetDlgItem(hDlg, IDC_ANIMATE1));
		EndDialog(hDlg, 0);
		return TRUE;
	}
	return FALSE;
}


/* Resolve IP addresses to their hostnames */
BOOL CALLBACK ResolveDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	HWND		hwndAnim;
	static PDPARAMS pparams;
	char			str[64];
	int				percent;
	static int		max;

	switch (uMsg)
	{
	case WM_INITDIALOG:
		InitCommonControls();
		
		hwndAnim = GetDlgItem(hDlg, IDC_ANIMATE1);
		Animate_Open(hwndAnim, MAKEINTRESOURCE(IDR_AVI2));

		SetDlgItemText(hDlg, IDC_TEXT, "Resolving IP addresses.  Please wait...");

		SetTimer(hDlg, 1, 1000, NULL);
		return TRUE;

	
	case WM_TIMER:
		KillTimer(hDlg, 1);
		ShowWindow(hDlg, SW_SHOW);
		return TRUE;


	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case ID_CANCEL:
			pparams->bContinue = FALSE;
			//EndDialog(hDlg, 0);
			return TRUE;
		}
		break;
	
	case MY_SET_RANGE:
		max = wParam;
		pparams = (PDPARAMS) lParam;
		return TRUE;

		
	case MY_UPDATE_PROGRESS:
		percent = 100 * wParam / max;
		SendDlgItemMessage(hDlg, IDC_PROGRESS1, PBM_SETPOS, (WPARAM) percent, 0);
		wsprintf(str, "%d of %d lookups complete", wParam, max);
		SetDlgItemText(hDlg, IDC_STATUS, str);
		return TRUE;

	case MY_CLOSE_WINDOW:
		KillTimer(hDlg, 1);
		Animate_Close(GetDlgItem(hDlg, IDC_ANIMATE1));
		EndDialog(hDlg, 0);
		return TRUE;

	case WM_CLOSE:
		Animate_Close(GetDlgItem(hDlg, IDC_ANIMATE1));
		EndDialog(hDlg, 0);
		return TRUE;
	
	}
	return FALSE;
}

