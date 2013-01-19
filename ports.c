#include <windows.h>
#include <commctrl.h>
#include "common.h"
#include "structs.h"
#include "globals.h"
#include "utility.h"
#include "resource.h"


BOOL CALLBACK PortsDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	LV_COLUMN	lvC;
	LV_ITEM		lvI;
	static HWND		hWndList;
	DWORD		dwValue;
	int			i, iCount, position; 
	char		str[32], label[16], type;
	unsigned short port;
	struct hash_entry *cur_ptr;


	switch (uMsg)
	{
	case WM_INITDIALOG:
		CenterWindow(hDlg);

		hWndList = GetDlgItem(hDlg, IDC_LISTVIEW);
		lvC.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM; 
	
		dwValue = GetPrivateProfileInt("Packet Capture", "Column10", 70, "NetworkSpy.ini");
		lvC.cx = RANGE(30, dwValue, 300);       
		lvC.pszText = "Label";
		lvC.iSubItem = 0;
		lvC.fmt = LVCFMT_LEFT;
		ListView_InsertColumn(hWndList, 1, &lvC);

		dwValue = GetPrivateProfileInt("Packet Capture", "Column11", 100, "NetworkSpy.ini");
		lvC.cx = RANGE(30, dwValue, 300);       
		lvC.pszText = "Port Num";
		lvC.iSubItem = 1;
		ListView_InsertColumn(hWndList, 1, &lvC);

		dwValue = GetPrivateProfileInt("Packet Capture", "Column12", 100, "NetworkSpy.ini");
		lvC.cx = RANGE(30, dwValue, 300);       
		lvC.pszText = "Protocol";
		lvC.iSubItem = 2;
		ListView_InsertColumn(hWndList, 2, &lvC);

		SendDlgItemMessage(hDlg, IDC_COMBO_PROTOCOL, CB_ADDSTRING, 0, (LPARAM) "udp");
		SendDlgItemMessage(hDlg, IDC_COMBO_PROTOCOL, CB_ADDSTRING, 0, (LPARAM) "tcp");
		SendDlgItemMessage(hDlg, IDC_COMBO_PROTOCOL, CB_SETCURSEL, (WPARAM) 0, 0);

		SendDlgItemMessage(hDlg, IDC_EDIT_LABEL, EM_SETLIMITTEXT, (WPARAM) 15, 0);
		SendDlgItemMessage(hDlg, IDC_EDIT_PORT, EM_SETLIMITTEXT, (WPARAM) 5, 0);


		for (i = 0; i < HASHTABLE_SIZE; i++)
		{
			if (hash_table[i].port != 0)
			{
				cur_ptr = &hash_table[i];
				while (cur_ptr)
				{
					lvI.mask = LVIF_TEXT ;
					lvI.iItem = ListView_GetItemCount(hWndList);
					lvI.iSubItem = 0;
					lvI.pszText = cur_ptr->str; 
					lvI.cchTextMax = 64;
					position = ListView_InsertItem(hWndList, &lvI);
					wsprintf(str, "%d", cur_ptr->port);
					ListView_SetItemText( hWndList, position, 1, str);
					if (cur_ptr->type == UDP)
					{
						ListView_SetItemText( hWndList, position, 2, "udp");
					}
					else
					{
						ListView_SetItemText( hWndList, position, 2, "tcp");
					}
					cur_ptr = cur_ptr->next;
				}
			}
		}
		return TRUE;


	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_ADD:
			i = GetDlgItemInt(hDlg, IDC_EDIT_PORT, NULL, FALSE);
			type = (char) SendDlgItemMessage(hDlg, IDC_COMBO_PROTOCOL, CB_GETCURSEL, 0, 0);
			GetDlgItemText(hDlg, IDC_EDIT_LABEL, label, sizeof(label));

			/* Check if label specified */
			if (lstrlen(label) == 0)
			{
				MessageBox(hDlg, "You must enter a label", APP_NAME, MB_OK | MB_ICONINFORMATION);
				return TRUE;
			}

			/* check port number */
			if ((i < 1) || (i > 65536))
			{
				MessageBox(hDlg, "Port number must be between 1 and 65536", APP_NAME, MB_OK | MB_ICONINFORMATION);
				return TRUE;
			}
			port = (unsigned short) i;

			if (add_to_table(port, label, type) == -1)
			{
				MessageBox(hDlg, "Entry already exists in table", APP_NAME, MB_OK | MB_ICONEXCLAMATION);
				return TRUE;
			}
			lvI.mask = LVIF_TEXT ;
			lvI.iItem = ListView_GetItemCount(hWndList);
			lvI.iSubItem = 0;
			lvI.pszText = label; 
			lvI.cchTextMax = 64;
			position = ListView_InsertItem(hWndList, &lvI);
			GetDlgItemText(hDlg, IDC_EDIT_PORT, str, sizeof(str));
			ListView_SetItemText( hWndList, position, 1, str);
			GetDlgItemText(hDlg, IDC_COMBO_PROTOCOL, str, sizeof(str));
			ListView_SetItemText( hWndList, position, 2, str);
			ListView_EnsureVisible(hWndList, position, FALSE);
			return TRUE;

		case IDC_BUTTON_DELETE:
			lvI.mask = LVIF_STATE;
			lvI.iItem = 0;
			lvI.iSubItem = 0;
			lvI.stateMask =LVIS_SELECTED;
			
			iCount = ListView_GetItemCount( hWndList );
			for( i = 0; i < iCount; i++ )           
			{        
				lvI.iItem = i;
				ListView_GetItem(hWndList, &lvI);
				if( lvI.state == LVIS_SELECTED )
				{
					ListView_GetItemText(hWndList, i, 1, str, sizeof(str));
					port = (unsigned short) atoi(str);
					ListView_GetItemText(hWndList, i, 2, str, sizeof(str));
					if (!lstrcmp(str,"udp")) 
						type = UDP;
					else
						type = TCP;

					if (remove_from_table(port, type) == 0)
						ListView_DeleteItem(hWndList, i);
					else
						MessageBox(hDlg, "Error removing entry", APP_NAME, MB_OK);
					return TRUE;
				}
			}
			return TRUE;

		case ID_CLOSE:
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