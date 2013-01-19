#ifndef _FILEIO_H
#define _FILEIO_H


BOOL LoadPortsFile(char *szFilename);
BOOL SavePortsFile(char *szFilename);
BOOL LoadRules(char *szFilename);
BOOL SaveRules(char *szFilename);
DWORD DumpFile(PVOID);
DWORD DumpBuffer(PVOID);
DWORD SaveSession(PVOID);
DWORD LoadSession(PVOID);
BOOL LoadFile(char *szFilename, char **, int *);
BOOL SaveFile(char *szFilename, char *, int);


#endif