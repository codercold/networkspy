#ifndef _LOGGING_H
#define _LOGGING_H


BOOL CALLBACK LoggingDlgProc(HWND, UINT, WPARAM, LPARAM);
BOOL StartNewLogFile();
BOOL AddToLog(SYSTEMTIME, unsigned char *, int, char *);
BOOL EndLogging();


struct logging_options {
	DWORD	file_size;
	char	final_directory[MAX_PATH];
	DWORD	file_format;
} logging;




#endif