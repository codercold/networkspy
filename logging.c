#include <windows.h>
#include <commctrl.h>
#include "resource.h"

#include "logging.h"
#include "utility.h"
#include "globals.h"
#include "common.h"


HANDLE hLogFile;
DWORD BytesWritten;
DWORD  max_file_size, frame_num;
char   *szRawData;


BOOL StartNewLogFile()
{
	SYSTEMTIME	systime;
	char   szNewLogFile[MAX_PATH + 64];

	GetLocalTime(&systime);
	wsprintf(szNewLogFile, "%s\\%.4d-%.2d-%.2d_%.2d-%.2d-%.2d",logging.final_directory, 
			systime.wYear, systime.wMonth, systime.wDay,
			systime.wHour, systime.wMinute, systime.wSecond);

	if (logging.file_format == 0)  
		lstrcat(szNewLogFile, ".nss");
	else if (logging.file_format == 1)
		lstrcat(szNewLogFile, ".mon");
	else
		lstrcat(szNewLogFile, ".xml");

	//MessageBox(0, szNewLogFile, "", MB_OK);

	hLogFile = CreateFile( szNewLogFile,
						GENERIC_WRITE,
						FILE_SHARE_READ,
						NULL,
						OPEN_ALWAYS,
						FILE_ATTRIBUTE_NORMAL,
						NULL);

	if (hLogFile == INVALID_HANDLE_VALUE)
		return FALSE;

	frame_num = 0;
	szRawData = malloc(32000);

	SetFilePointer (hLogFile, GetFileSize(hLogFile, NULL), NULL, FILE_BEGIN) ;
	if (logging.file_format == 2)
		WriteFile( hLogFile, "<session>\r\n", 11, &BytesWritten, NULL);

	if (logging.file_size < 1) logging.file_size = 1;   // 1 MB minimum
	max_file_size = 1048576 * logging.file_size;		// convert to megabytes
	
	return TRUE;
}



BOOL AddToLog(SYSTEMTIME rTime, unsigned char *data, int size, char *ids)
{
	int len;
	BOOL bError = FALSE;


	/* Start a new log file if one hasn't been started already */
	if (hLogFile == NULL)
		StartNewLogFile();


	if (logging.file_format == 1)	// Hex Dump
	{
		wsprintf(szRawData, "- - - - - - - - - - - - - - - - Frame %d - - - - - - - - - - - - - - - - -\r\n\r\n\r\n\r\n", ++frame_num);
		lstrcat(szRawData, "ADDR  HEX                                                ASCII\r\n");

		PrintRawData(data, size, &szRawData[lstrlen(szRawData)]);

		len = lstrlen(szRawData);
		
		if (WriteFile( hLogFile, szRawData, len, &BytesWritten, NULL) == 0)  bError = TRUE;
	}
	else if (logging.file_format == 0)	// binary
	{
		if (WriteFile( hLogFile, &rTime, sizeof(SYSTEMTIME), &BytesWritten, NULL) == 0)  bError = TRUE;
		if (WriteFile( hLogFile, &size, sizeof(int), &BytesWritten, NULL) == 0)	bError = TRUE;
		if (WriteFile( hLogFile, data, size, &BytesWritten, NULL) == 0)  bError = TRUE;
	}
	else if (logging.file_format == 2)	// XML
	{
		XML_DecodeSelected(rTime, data, size, szRawData);
		if (WriteFile( hLogFile, szRawData, lstrlen(szRawData), &BytesWritten, NULL) == 0)  bError = TRUE;
	}


	if (bError)
	{
		g_bShutdown = TRUE;
		CloseHandle(hLogFile);
		MessageBox(hWndMain, "An error occurred attempting to write to log file. Capture stopped.", "Packet Capture", MB_OK | MB_ICONERROR);
	}
	
	if (GetFileSize(hLogFile, NULL) > max_file_size)
		EndLogging();

	return TRUE;
}



BOOL EndLogging()
{
	if (logging.file_format == 2)
		WriteFile( hLogFile, "</session>\r\n", 12, &BytesWritten, NULL);

	CloseHandle(hLogFile);
	free(szRawData);
	hLogFile = NULL;

	return TRUE;
}



BOOL CALLBACK LoggingDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		CenterWindow(hDlg);
		SendDlgItemMessage(hDlg, IDC_SPIN1, UDM_SETRANGE, 0L, MAKELONG (2048, 1));

		SendDlgItemMessage(hDlg, IDC_LIST_FORMAT, LB_ADDSTRING, 0, (LPARAM)"Binary");
		SendDlgItemMessage(hDlg, IDC_LIST_FORMAT, LB_ADDSTRING, 0, (LPARAM)"Hex Dump");
		SendDlgItemMessage(hDlg, IDC_LIST_FORMAT, LB_ADDSTRING, 0, (LPARAM)"XML");

		SetDlgItemText(hDlg, IDC_EDIT_FINAL_DIRECTORY, logging.final_directory);
		SetDlgItemInt(hDlg, IDC_EDIT_FILESIZE, logging.file_size, FALSE);
		SendDlgItemMessage(hDlg, IDC_LIST_FORMAT, LB_SETCURSEL, (WPARAM) logging.file_format, 0);

		return TRUE;

		
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case ID_SAVE:
			GetDlgItemText(hDlg, IDC_EDIT_FINAL_DIRECTORY, logging.final_directory, MAX_PATH-1);
			logging.file_size = GetDlgItemInt(hDlg, IDC_EDIT_FILESIZE, NULL, FALSE);
			logging.file_format = SendDlgItemMessage(hDlg, IDC_LIST_FORMAT, LB_GETCURSEL, 0, 0);
			
			if (GetFileAttributes(logging.final_directory) != FILE_ATTRIBUTE_DIRECTORY)
			{
				MessageBox(hDlg, "Final directory does not appear to be valid. Please re-enter directory name.", "Packet Capture", MB_OK | MB_ICONEXCLAMATION);
				return TRUE;
			}

			WritePrivateProfileStruct("Packet Capture", "Logging Options", &logging, sizeof(logging), "NetworkSpy.ini");

			EndDialog(hDlg, 0);
			return TRUE;

		case ID_CANCEL:
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

