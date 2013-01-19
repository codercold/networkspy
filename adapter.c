#include <windows.h>

#include "adapter.h"
#include "resource.h"
#include "common.h"
#include "windis.h"
#include "HookUtil.h"

#include "utility.h"
#include "globals.h"


char *NAMETBLE[] =
{
      "802.3",
      "802.5",
      "Fddi",
      "Wan",
      "LocalTalk",
      "Dix",
      "Arcnet (Raw)",
      "Arcnet (878.2)",
      "ATM",
      "Wireless WAN",
      "Irda"
};


DWORD GetProperties(HWND hDlg, char *Adapter_Name)
{
	HookAdapter		hookadapter;
	char			str[64];

	SetDlgItemText(hDlg, IDC_LINK_SPEED, "Unknown");
	SetDlgItemText(hDlg, IDC_FRAME_SIZE, "Unknown");
	SetDlgItemText(hDlg, IDC_MEDIUM, "Unknown");
	SetDlgItemText(hDlg, IDC_ADDRESS, "Unknown");

	hookadapter.m_hDevice = W32N_OpenAdapter( Adapter_Name );
	if( hookadapter.m_hDevice == INVALID_HANDLE_VALUE )

	// NELSON - Added
	{
		char sTemp[1000];
		DWORD dwError = W32N_GetLastError();
		wsprintf(sTemp, "OpenAdapter error %ld", dwError);
		MessageBox(NULL, sTemp, "", MB_OK);

		return 0;

	// NELSON - Added
	}

	hookadapter.m_OverLapped.hEvent = CreateEvent(NULL,FALSE,FALSE,NULL);
	ResetEvent( hookadapter.m_OverLapped.hEvent );
	
	if (HP_UpdateAdapterLinkSpeed( &hookadapter ))
	{
		if (hookadapter.m_nLinkSpeed * 100 >= 1000000)
			wsprintf(str, "%d MBS", hookadapter.m_nLinkSpeed/10000);
		else
			wsprintf(str, "%d BPS", hookadapter.m_nLinkSpeed*100);
		SetDlgItemText(hDlg, IDC_LINK_SPEED, str);
	}


	if (HP_UpdateAdapterMaxFrameSize( &hookadapter ))
	{
		wsprintf(str, "%d bytes", hookadapter.m_nMaxFrameSize);
		SetDlgItemText(hDlg, IDC_FRAME_SIZE, str);
	}


	if (HP_UpdateAdapterMedium( &hookadapter ))
		SetDlgItemText(hDlg, IDC_MEDIUM, NAMETBLE[hookadapter.m_nMedium]);


	if (HP_UpdateAdapterCurrentAddress( &hookadapter ))
	{
		wsprintf(str, "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X", 
							(char *) hookadapter.m_CurrentAddress[0], 
							(char *) hookadapter.m_CurrentAddress[1], 
							(char *) hookadapter.m_CurrentAddress[2], 
							(char *) hookadapter.m_CurrentAddress[3], 
							(char *) hookadapter.m_CurrentAddress[4], 
							(char *) hookadapter.m_CurrentAddress[5]);

		SetDlgItemText(hDlg, IDC_ADDRESS, str);
	}
	

	W32N_CloseAdapter( hookadapter.m_hDevice );
	CloseHandle(hookadapter.m_OverLapped.hEvent);	

	return 0;
}




BOOL CALLBACK AdapterDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	char  desc[128], szName[64]; // NELSON - unused variable: , szBuffer[64];
	static char adapters[20][64];
	int		curSel = 0;
	DWORD	dw, dwType, nIndex, cbName, nVersion;
	HKEY		hKeyClassNet;
	LONG		nResult;
	W32N_ADAPTER_INFO AdapterInfo;

	switch (uMsg)
	{
	case WM_INITDIALOG:
		CenterWindow(hDlg);

		if( W32N_IsWindowsNT() )
		{
			nVersion = W32N_OSGetPlatformVersion( VER_PLATFORM_WIN32_NT );

			// NELSON - For Vista, nVersion is 0x0006, here is the status of the registry keys:
			// IS FOUND:  #define W32N_REGSTR_PATH_NETCARDS   TEXT("Software\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards")
			// NOT FOUND: #define W32N_REGSTR_PATH_CLASS_NET  TEXT( "System\\CurrentControlSet\\Services\\Class\\Net")
			// IS FOUND:  #define W32N_REGSTR_PATH_CLASS_NET_NT5 "System\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

			if( nVersion == 0x0005 )
			{
				/* Open NetworkCard Key For Windows NT 4.5
				------------------------------------------ */
				nResult = RegOpenKeyEx(
								HKEY_LOCAL_MACHINE,
								W32N_REGSTR_PATH_CLASS_NET_NT5, // Address Of Name Of Subkey To Open
								0,							// Options (Reserved)
								KEY_READ,				// Security Access Mask
								&hKeyClassNet
								);
			}
			else
			{
				/* Open NetworkCard Key For Windows NT 4.0
				------------------------------------------ */
				nResult = RegOpenKeyEx(
								HKEY_LOCAL_MACHINE,
								W32N_REGSTR_PATH_NETCARDS, // Address Of Name Of Subkey To Open
								0,							// Options (Reserved)
								KEY_READ,				// Security Access Mask
								&hKeyClassNet
								);
			}
		}
		else
		{
			nResult = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
									W32N_REGSTR_PATH_CLASS_NET, 
									0,		
									KEY_READ,
									&hKeyClassNet);
		}

		if( nResult == ERROR_SUCCESS )
		{
			nIndex = 0;

			while( nResult == ERROR_SUCCESS )
			{
				cbName = 64;
				dwType = REG_SZ;
				dw = sizeof(desc);

				nResult = RegEnumKeyEx(hKeyClassNet, nIndex, szName, &cbName,
										NULL,NULL,NULL, NULL);
				
				if( nResult != ERROR_SUCCESS )
					break;
				
				// NELSON - added block of code
				if (nVersion == 0x0006) {
					DWORD dwLength;

					AdapterInfo.cServiceName[0] = 0;
					strcpy_s(AdapterInfo.cTitle, sizeof(AdapterInfo.cTitle), "???");
					dwLength = sizeof(AdapterInfo.cTitle);
					RegGetValue(hKeyClassNet, szName, "Description", RRF_RT_REG_SZ, NULL, AdapterInfo.cTitle, &dwLength);
					dwLength = sizeof(AdapterInfo.cServiceName);
					RegGetValue(hKeyClassNet, szName, "ServiceName", RRF_RT_REG_SZ, NULL, AdapterInfo.cServiceName, &dwLength);
					lstrcpy(adapters[nIndex], "\\Device\\");
					lstrcat(adapters[nIndex], AdapterInfo.cServiceName);
				} else {
				// NELSON - end of added block of code (but there's a closing brace below)

					W32N_GetAdapterRegistryInfo( &AdapterInfo, szName); 
					if( W32N_IsWindowsNT() )
					{
						lstrcpy(adapters[nIndex], "\\Device\\");
						lstrcat(adapters[nIndex], AdapterInfo.cServiceName);
					}
					else
						lstrcpy(adapters[nIndex], szName);

				// NELSON
				}

				SendDlgItemMessage(hDlg, IDC_LIST1, LB_ADDSTRING, 0, (LPARAM)AdapterInfo.cTitle);
				
				if (!lstrcmp(szAdapter, adapters[nIndex]))
					curSel = nIndex;

				++nIndex;
			}

			RegCloseKey( hKeyClassNet );
		}
		else
		{
			MessageBox(hDlg, "Unable to retrieve adapter information from registry!", APP_NAME, MB_OK | MB_ICONEXCLAMATION);
			EndDialog(hDlg, 0);
			return FALSE;
		}

		SendDlgItemMessage(hDlg, IDC_LIST1, LB_SETCURSEL, (WPARAM) curSel, 0);
		GetProperties(hDlg, adapters[0]);
		return TRUE;
	

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_LIST1:
			if (HIWORD(wParam) == LBN_SELCHANGE)
			{
				nIndex = SendDlgItemMessage(hDlg, IDC_LIST1, LB_GETCURSEL, 0, 0);
				if (nIndex != LB_ERR)
					GetProperties(hDlg, adapters[nIndex]);
			}
			return 0;

		case ID_CLOSE:
			nIndex = SendDlgItemMessage(hDlg, IDC_LIST1, LB_GETCURSEL, 0, 0);
			if (nIndex != LB_ERR)
			{
				lstrcpy(szAdapter, adapters[nIndex]);
				SendDlgItemMessage(hDlg, IDC_LIST1, LB_GETTEXT, (WPARAM) nIndex, (LPARAM) desc);
				lstrcpy(szAdapterDesc, desc); 
				SetWindowText(hWndMain, desc);
			}

			//GetDlgItemText(hDlg, IDC_MEDIUM, szBuffer, 32);
			//if (lstrcmp(szBuffer, "802.3"))
			//{
			//	wsprintf(szBuffer, "%s does not appear to be an ethernet medium!", szAdapter);
			//	MessageBox(hDlg, szBuffer, APP_NAME, MB_OK | MB_ICONINFORMATION);
			//}

			EndDialog(hDlg, 1);
			return TRUE;
		
		case ID_CANCEL:
			EndDialog(hDlg, 0);
			return TRUE;
		}
		break;
	
	case WM_CLOSE:
		EndDialog(hDlg, 1);
		return TRUE;
	}
	return FALSE;
}