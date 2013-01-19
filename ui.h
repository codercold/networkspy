#ifndef _UI_H
#define _UI_H

HWND	CreateMainToolbar(HWND, HINSTANCE);
HWND	CreateTabs (HWND, HINSTANCE);
HWND	CreateAlertsWindow(HWND, HINSTANCE);
HWND	CreateCountersWindow (HWND, HINSTANCE); 
HWND	CreateARPWindow (HWND, HINSTANCE);

DWORD	DeleteList(HWND);
LPARAM	GetSelectedItemLParam(HWND);
LPARAM	GetNextItemLParam(HWND);
LPARAM	GetPreviousItemLParam(HWND);
BOOL	PopFileSaveDlg(HWND, char *, int);
BOOL	PopSessionSaveDlg (HWND, char *);
BOOL	PopDumpSaveDlg (HWND, char *);
BOOL	PopFileOpenDlg (HWND, char *);
BOOL	PopSessionOpenDlg (HWND, char *);
HWND	CreateDecoderToolbar(HWND hWndParent, HINSTANCE hInstance);
BOOL	SaveColumnWidths(HWND hWndAlertList, HWND hWndCounterList, HWND hWndArpList);

#endif