# Microsoft Developer Studio Project File - Name="Sniffer" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101

CFG=Sniffer - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "Sniffer.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "Sniffer.mak" CFG="Sniffer - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "Sniffer - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "Sniffer - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "Sniffer - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /W3 /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib comdlg32.lib advapi32.lib shell32.lib comctl32.lib wsock32.lib W32N50.lib QHTM.lib winspool.lib winmm.lib /nologo /entry:"ProgramEntryPoint" /subsystem:windows /machine:I386 /nodefaultlib /out:"Release/netspy.exe"
# SUBTRACT LINK32 /pdb:none

!ELSEIF  "$(CFG)" == "Sniffer - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MT /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib comdlg32.lib advapi32.lib shell32.lib comctl32.lib wsock32.lib W32N50.lib QHTM.lib winspool.lib winmm.lib /nologo /entry:"ProgramEntryPoint" /subsystem:windows /incremental:no /machine:I386 /pdbtype:sept
# SUBTRACT LINK32 /debug /nodefaultlib

!ENDIF 

# Begin Target

# Name "Sniffer - Win32 Release"
# Name "Sniffer - Win32 Debug"
# Begin Group "resources"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\check.bmp
# End Source File
# Begin Source File

SOURCE=.\copy.ico
# End Source File
# Begin Source File

SOURCE=.\decoderbar.bmp
# End Source File
# Begin Source File

SOURCE=.\filecopy.avi
# End Source File
# Begin Source File

SOURCE=.\Filedele.avi
# End Source File
# Begin Source File

SOURCE=.\logo.png
# End Source File
# Begin Source File

SOURCE=.\nic.ico
# End Source File
# Begin Source File

SOURCE=.\printer.ico
# End Source File
# Begin Source File

SOURCE=.\stop.bmp
# End Source File
# Begin Source File

SOURCE=.\toolbar.bmp
# End Source File
# End Group
# Begin Source File

SOURCE=.\adapter.c
# End Source File
# Begin Source File

SOURCE=".\c-runtime.c"
# End Source File
# Begin Source File

SOURCE=.\capture.c
# End Source File
# Begin Source File

SOURCE=.\decoder.c
# End Source File
# Begin Source File

SOURCE=.\dns.c
# End Source File
# Begin Source File

SOURCE=.\fileio.c
# End Source File
# Begin Source File

SOURCE=.\generator.c
# End Source File
# Begin Source File

SOURCE=.\HPCtrl.c
# End Source File
# Begin Source File

SOURCE=.\Hprxutil.c
# End Source File
# Begin Source File

SOURCE=.\icmp.c
# End Source File
# Begin Source File

SOURCE=.\logging.c
# End Source File
# Begin Source File

SOURCE=.\main.c
# End Source File
# Begin Source File

SOURCE=.\notes.txt
# End Source File
# Begin Source File

SOURCE=.\ping.c
# End Source File
# Begin Source File

SOURCE=.\PktRecv.c
# End Source File
# Begin Source File

SOURCE=.\ports.c
# End Source File
# Begin Source File

SOURCE=.\print.c
# End Source File
# Begin Source File

SOURCE=.\remote.c
# End Source File
# Begin Source File

SOURCE=.\resource.rc
# End Source File
# Begin Source File

SOURCE=.\rules.c
# End Source File
# Begin Source File

SOURCE=.\traceroute.c
# End Source File
# Begin Source File

SOURCE=.\traffic.c
# End Source File
# Begin Source File

SOURCE=.\ui.c
# End Source File
# Begin Source File

SOURCE=.\utility.c
# End Source File
# Begin Source File

SOURCE=.\whois.c
# End Source File
# End Target
# End Project
