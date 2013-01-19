#include <windows.h>
#include <commctrl.h>
#include "fileio.h"
#include "structs.h"
#include "globals.h"
#include "utility.h"
#include "rules.h"
#include "common.h"


/*
	Function:	Load port numbers and their corresponding labels
	Parameters:	Filename to read from
	Returns:	TRUE is successful, FALSE otherwise
*/
BOOL LoadPortsFile(char *szFilename)
{
	HANDLE	hFile;
	DWORD	nResult, BytesRead;
	struct hash_entry	he;

	hFile = CreateFile( szFilename,
						GENERIC_READ,
						FILE_SHARE_READ,
						NULL,
						OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL,
						NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;


	while (TRUE)
	{
		nResult = ReadFile(hFile, &he, sizeof(he), &BytesRead, NULL);
		if (BytesRead == 0)
			break;

		add_to_table(he.port, he.str, he.type);
	}

	CloseHandle(hFile);

	return TRUE;
}



/*
	Function:	Save udp/tcp port numbers and their corresponding labels
	Parameters:	Filename to write to (deletes existing file)
	Returns:	TRUE is successful, FALSE otherwise
*/
BOOL SavePortsFile(char *szFilename)
{
	HANDLE	hFile;
	DWORD	BytesWritten;
	int		index;
	struct hash_entry *cur_ptr;

	hFile = CreateFile( szFilename,
						GENERIC_WRITE,
						0,
						NULL,
						CREATE_ALWAYS,
						FILE_ATTRIBUTE_NORMAL,
						NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	for(index = 0; index < HASHTABLE_SIZE; index++)
	{
		cur_ptr = &hash_table[index];
		while(cur_ptr)
		{
			WriteFile( hFile, cur_ptr, sizeof(struct hash_entry), &BytesWritten, NULL);
			cur_ptr = cur_ptr->next;
		}
	}

	CloseHandle(hFile);


	/* Temporery code, TO BE REMOVED 
	hFile = CreateFile( "c:\\windows\\desktop\\debug.txt",
						GENERIC_WRITE,
						0,
						NULL,
						CREATE_ALWAYS,
						FILE_ATTRIBUTE_NORMAL,
						NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	for(index = 0; index < HASHTABLE_SIZE; index++)
	{
		cur_ptr = &hash_table[index];
		while(cur_ptr)
		{
			wsprintf(str, "%d ->", cur_ptr->port);
			WriteFile( hFile, str, lstrlen(str), &BytesWritten, NULL);
			cur_ptr = cur_ptr->next;
		}
		wsprintf(str, "\r\n");
		WriteFile( hFile, str, lstrlen(str), &BytesWritten, NULL);
	}

	CloseHandle(hFile);
*/
	return TRUE;
}



/*
	Function:	Save rules as fixed length structs 
	Parameters:	Filename to read from
	Returns:	TRUE is successful, FALSE otherwise
*/
BOOL LoadRules(char *szFilename)
{
	HANDLE	hFile;
	DWORD	nResult, BytesRead;


	hFile = CreateFile( szFilename,
						GENERIC_READ,
						FILE_SHARE_READ,
						NULL,
						OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL,
						NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	nResult = ReadFile(hFile, &rule_text, sizeof(rule_text), &BytesRead, NULL);
	if (BytesRead < sizeof(rule_text))
	{
		memset(&rule_text, 0, sizeof(rule_text));
		return FALSE;
	}

	CloseHandle(hFile);

	return TRUE;
}


/*
	Function:	Load and populate RulesText structure with rules  
	Parameters:	Filename to write to (deletes existing file)
	Returns:	TRUE is successful, FALSE otherwise
*/
BOOL SaveRules(char *szFilename)
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

	WriteFile( hFile, rule_text, sizeof(rule_text), &BytesWritten, NULL);
	
	CloseHandle(hFile);

	return TRUE;
}




/* 

	Function:	Load a file into binary buffer (used for loading .pkt files)
	Parameters:	Filename to read from
				Pointer to char * where location of read data will be saved
				Pointer to int where size of read file will be saved
	Returns:	TRUE is successful, FALSE otherwise
*/
BOOL LoadFile(char *szFilename, char **data, int *len)
{
	HANDLE	hFile;
	DWORD	nResult, BytesRead;
	int		size;
	char	*szBuffer;

	hFile = CreateFile( szFilename,
						GENERIC_READ,
						FILE_SHARE_READ,
						NULL,
						OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL,
						NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	size = GetFileSize(hFile, NULL);
	szBuffer = malloc(size);

	nResult = ReadFile(hFile, szBuffer, size, &BytesRead, NULL);
	if (BytesRead == 0)
	{
		free (szBuffer);
		return FALSE;
	}

	CloseHandle(hFile);

	*len = size;
	*data = szBuffer;

	return TRUE;
}



/* 

	Function:	Save binary data to file (used for saving .pkt files)
	Parameters:	Filename to save to
				Pointer to binary data
				size of data buffer
	Returns:	TRUE is successful, FALSE otherwise
*/
BOOL SaveFile(char *szFilename, char *data, int size)
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

	WriteFile( hFile, data, size, &BytesWritten, NULL);

	CloseHandle(hFile);

	return TRUE;
}



/* Dump the captured packets shown in ListView to file */

DWORD DumpFile(PVOID ptr)
{
	int				iCount, index;
	char			*ret, *szBuffer; // ret = 32000, szBuffer = 64000 bytes
	LV_ITEM			lvI;
	struct packet	*pkt;
	HANDLE			hFile;
	DWORD			BytesWritten;
	int				nTotalBytesWritten = 0;
	PDPARAMS		pparams;

	pparams = (PDPARAMS) ptr;

	hFile = CreateFile( pparams->filename,
						GENERIC_WRITE,
						0,
						NULL,
						CREATE_ALWAYS,
						FILE_ATTRIBUTE_NORMAL,
						NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	ret = malloc(32000);
	szBuffer = malloc(64000);

	lvI.mask = LVIF_PARAM ;
	lvI.iItem = 0;
	lvI.iSubItem = 0;
	
	SendMessage(pparams->hwnd, MY_SET_RANGE, (WPARAM) bytes_used, (LPARAM) pparams);

	iCount = ListView_GetItemCount( hWndAlertList );
	for( index = 0; index < iCount; index++ )           
	{        
		lvI.iItem = index;
		ListView_GetItem(hWndAlertList, &lvI);
		
		pkt = (struct packet *) lvI.lParam;

		wsprintf(szBuffer, "- - - - - - - - - - - - - - - - Frame %d - - - - - - - - - - - - - - - - -\r\n\r\n\r\n\r\n", index+1);
		lstrcat(szBuffer, "ADDR  HEX                                                ASCII\r\n");

		PrintRawData(pkt->data, pkt->size, ret);

		lstrcat(szBuffer, ret);

		WriteFile( hFile, szBuffer, lstrlen(szBuffer), &BytesWritten, NULL);
	
		nTotalBytesWritten += pkt->size;

		SendMessage(pparams->hwnd, MY_UPDATE_PROGRESS, (WPARAM) nTotalBytesWritten, 0);
	
		if (pparams->bContinue == FALSE)
			break;
	}
	
	CloseHandle(hFile);

	SendMessage(pparams->hwnd, MY_CLOSE_WINDOW, 0, 0);
	SendMessage(hWndStatus, SB_SETTEXT, (WPARAM) 1, (LPARAM) "Dump complete!");

	free (pparams);
	free (ret);
	free (szBuffer);
	return TRUE;
}




/* 
   Dump the packets saved in the linked list to a file 
   and destroy the linked list
*/

DWORD DumpBuffer(PVOID ptr)
{
	char			*ret, *szBuffer;			
	HANDLE			hFile;
	DWORD			BytesWritten;
	int				nTotalBytesWritten = 0, index;
	PDPARAMS		pparams;

	pparams = (PDPARAMS) ptr;

	hFile = CreateFile( pparams->filename,
						GENERIC_WRITE,
						0,
						NULL,
						CREATE_ALWAYS,
						FILE_ATTRIBUTE_NORMAL,
						NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	ret = malloc(32000);
	szBuffer = malloc(64000);

	SendMessage(pparams->hwnd, MY_SET_RANGE, (WPARAM) bytes_used, (LPARAM) pparams);

	index = 0;
	cur_ptr = head_ptr;

	while (cur_ptr != NULL)
	{
		wsprintf(szBuffer, "- - - - - - - - - - - - - - - - Frame %d - - - - - - - - - - - - - - - - -\r\n\r\n\r\n\r\n", index+1);
		lstrcat(szBuffer, "ADDR  HEX                                                ASCII\r\n");

		PrintRawData(cur_ptr->data, cur_ptr->size, ret);

		lstrcat(szBuffer, ret);

		WriteFile( hFile, szBuffer, lstrlen(szBuffer), &BytesWritten, NULL);
	
		nTotalBytesWritten += cur_ptr->size;

		SendMessage(pparams->hwnd, MY_UPDATE_PROGRESS, (WPARAM) nTotalBytesWritten, 0);
	
		cur_ptr = cur_ptr->next;
		++index;

		if (pparams->bContinue == FALSE)
			break;
	}
	
	CloseHandle(hFile);

	while (head_ptr != NULL)
	{
		cur_ptr = head_ptr;
		head_ptr = head_ptr->next;
		free(cur_ptr->data);
		free(cur_ptr);
	}

	bytes_used = 0;

	SendMessage(pparams->hwnd, MY_CLOSE_WINDOW, 0, 0);
	SendMessage(hWndStatus, SB_SETTEXT, (WPARAM) 1, (LPARAM) "Buffer and Dump session complete!");

	free (pparams);
	free (ret);
	free (szBuffer);

	return TRUE;
}



DWORD LoadSession(PVOID ptr)
{
	HANDLE	hFile;
	DWORD	nResult, BytesRead;
	int		size;
	char	*szBuffer, *szFilename;
	SYSTEMTIME systime;

	szFilename = (char *) ptr;

	hFile = CreateFile( szFilename,
						GENERIC_READ,
						FILE_SHARE_READ,
						NULL,
						OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL,
						NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		SendMessage(hWndStatus, SB_SETTEXT, (WPARAM) 0, (LPARAM) "Error importing data");
		MessageBeep(0xffffffff);
		return FALSE;
	}

	szBuffer = malloc(32000);

	SendMessage(hWndStatus, SB_SETTEXT, (WPARAM) 0, (LPARAM) "Importing data...");

	while(TRUE)
	{
		nResult = ReadFile(hFile, &systime, sizeof(SYSTEMTIME), &BytesRead, NULL);
		if (BytesRead == 0)
			break;

		ReadFile(hFile, &size, sizeof(int), &BytesRead, NULL);

		/*check for invalid file format */
		if ((size < 0) || (size > 1514))
			break;

		ReadFile(hFile, szBuffer, size, &BytesRead, NULL);
		ProcessPacket(systime, szBuffer, size, FALSE);
	}

	CloseHandle(hFile);

	free (szBuffer);

	SendMessage(hWndStatus, SB_SETTEXT, (WPARAM) 0, (LPARAM) "Data imported.");

	return TRUE;
}


DWORD SaveSession(PVOID ptr)
{
	HANDLE	hFile;
	DWORD	BytesWritten;
	char	*szFilename;

	int				index, num;
	LV_ITEM			lvItem;
	struct packet	*pkt;
	
	szFilename = (char *) ptr;

	hFile = CreateFile( szFilename,
						GENERIC_WRITE,
						0,
						NULL,
						CREATE_ALWAYS,
						FILE_ATTRIBUTE_NORMAL,
						NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		SendMessage(hWndStatus, SB_SETTEXT, (WPARAM) 0, (LPARAM) "File error!");
		MessageBeep(0xffffffff);
		return FALSE;
	}

	SendMessage(hWndStatus, SB_SETTEXT, (WPARAM) 0, (LPARAM) "Exporting data...");

	lvItem.mask = LVIF_PARAM;
	lvItem.iSubItem = 0;

	num = ListView_GetItemCount(hWndAlertList);

	for (index = 0; index < num; index++)
	{
		lvItem.iItem = index;
		ListView_GetItem(hWndAlertList, &lvItem);
		pkt = (struct packet *)lvItem.lParam;
		WriteFile( hFile, &pkt->time, sizeof(SYSTEMTIME), &BytesWritten, NULL);
		WriteFile( hFile, &pkt->size, sizeof(int), &BytesWritten, NULL);
		WriteFile( hFile, pkt->data, pkt->size, &BytesWritten, NULL);
	}
	

	CloseHandle(hFile);

	SendMessage(hWndStatus, SB_SETTEXT, (WPARAM) 0, (LPARAM) "Data exported.");

	return TRUE;
}
