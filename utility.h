#ifndef _UTILITY_H
#define _UTILITY_H


BOOL CALLBACK AboutDlgProc(HWND, UINT, WPARAM, LPARAM);
BOOL isRegistered();
BOOL CheckRegistration(char *user, char *key);


VOID SaveWindowPosition(HWND);
VOID RestoreWindowPosition(HWND);

VOID LoadList(HWND hwndList, char *name);
VOID SaveList(HWND hwndList, char *name);
VOID AddToList(HWND hwndList, char *string);
BOOL CopyListViewData( HWND hWndList, int nColumns );
BOOL CopyToClipBoard( char *str );


void PrintRawData(unsigned char *, int, char *);
void CenterWindow(HWND);
void ConvertPathToDir(char *);
DWORD RANGE(DWORD min, DWORD val, DWORD max);

BOOL SavePacket(char *szFilename, char *data, int len);
DWORD ResolveIPs(PVOID ptr);
char *IpToString(unsigned long ip);
char *GetParamFromCommandLine(char *command);
void FormatByteValue(u_long numBytes, char *str);
void FormatBitRateValue(u_long numBytes, char *str);


/* struct for the hash table */

void initialize_hash_tables(void);
int add_to_table(unsigned short, char *, char);
int remove_from_table(unsigned short port, char type);
char * find_in_table(unsigned short port, char type);
void cleanup_hash_tables(void);
void SetupDefaultServices();


// Functions in debug.c
void OpenDebugWindow();
void debug(char *str);
HWND hWndDebug;


#endif