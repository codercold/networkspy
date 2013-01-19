/*----------------------------------------------------------------------
Copyright (c) 1998 Gipsysoft. All Rights Reserved.
File:	QHTM.H
Owner:	russf@gipsysoft.com
Purpose:	Quick HTM display control interface header
----------------------------------------------------------------------*/
#ifndef QHTM_H
#define QHTM_H

#ifdef __cplusplus
extern "C" {
#endif	//	__cplusplus

	//
	//	The window classname to be used when creating the QHTM controls.
	//	Note that you can modify the styles for the control as any other control.
	#define QHTM_CLASSNAME	"QHTM_Window_Class_001"

	//
	//	Zoom constants, minimum, maximum and default.
	#define	QHTM_ZOOM_MIN	0
	#define	QHTM_ZOOM_MAX	4
	#define	QHTM_ZOOM_DEFAULT	2


	//
	//	The usual notify with a return value.
	typedef struct tagNMQHTM
	{
		NMHDR hdr;
		LPCTSTR pcszLinkText;
		LRESULT resReturnValue;
	} NMQHTM, FAR *LPNMQHTM;

	//
	//	Sent whenever a link is clicked.
	//	Set resReturnValue to FALSE to prevent QHTM from starting the user agent associated with the link.
	//	This would be used if you had encoded some of your own links to internal functions in the HTML
	//		see - APIExample of how this can be used.
	#define QHTMN_HYPERLINK		( 1 )

	//
	//	Load a HTML page from the resources
	//	::SendMessage( hwnd, QHTM_LOAD_FROM_RESOURCE, (WPARAM)hInst, (LPARAM)name );
	#define QHTM_LOAD_FROM_RESOURCE		( WM_USER + 1 )

	//
	//	Load the HTML from a file on disk.
	//	::SendMessage( hwnd, QHTM_LOAD_FROM_FILE, 0, (LPARAM)pcszName );
	#define QHTM_LOAD_FROM_FILE				( WM_USER + 2 )

	//
	//	Sets an option - see the values QHTM_OPT_* for further information
	//	::SendMessage( hwnd, QHTM_SET_OPTION, (LPARAM)nOptionIndex, OptionValue );
	#define QHTM_SET_OPTION				( WM_USER + 3 )

	//
	//	Gets an option - see the values QHTM_OPT_* for further information
	//	OptionValue = ::SendMessage( hwnd, QHTM_GET_OPTION, (WPARAM)nOptionIndex, 0 );
	#define QHTM_GET_OPTION				( WM_USER + 4 )

	//
	//	Goto a link with the HTML control. Used when you want to display a HTML document
	//	not from the start but at a named section within the document.
	//	::SendMessage( hwnd, QHTM_GOTO_LINK, 0, (LPARAM)pcszLinkName );
	#define QHTM_GOTO_LINK				( WM_USER + 5 )

	//
	//	Set/get the HTML tooltips state.
	//	::SendMessage( hwnd, QHTM_SET_OPTION, QHTM_OPT_TOOLTIPS, (WPARAM)bEnable );
	#define QHTM_OPT_TOOLTIPS			( 1 )
	#define QHTM_OPT_ZOOMLEVEL		( 2 )

	//
	//	Message cracker style macros
	#define QHTM_LoadFromResourceName( hwnd, hinst, name )	((BOOL) ::SendMessage( (hwnd), QHTM_LOAD_FROM_RESOURCE, (WPARAM)(hinst), (LPARAM)(name) ) )
	#define QHTM_LoadFromFile( hwnd, filename )	((BOOL) ::SendMessage( (hwnd), QHTM_LOAD_FROM_FILE, 0, (LPARAM)(filename) ) )
	#define QHTM_SetTooltips( hwnd, bEnable )	( (void) ::SendMessage( hwnd, QHTM_SET_OPTION, QHTM_OPT_TOOLTIPS, (WPARAM)bEnable ) )
	#define QHTM_GetTooltips( hwnd )	( (BOOL) ::SendMessage( hwnd, QHTM_GET_OPTION, QHTM_OPT_TOOLTIPS, 0) )
	#define QHTM_SetZoomLevel( hwnd, nLevel )	( (void) ::SendMessage( hwnd, QHTM_SET_OPTION, QHTM_OPT_ZOOMLEVEL, (WPARAM)nLevel ) )
	#define QHTM_GetZoomLevel( hwnd )	( (int) ::SendMessage( hwnd, QHTM_GET_OPTION, QHTM_OPT_ZOOMLEVEL, 0) )
	#define QHTM_GotoLink( hwnd, pcszLinkName )	((void) ::SendMessage( (hwnd), QHTM_GOTO_LINK, 0, (LPARAM)(pcszLinkName) ) )

	//
	//	Call this to initialise the Quick HTML control.
	BOOL WINAPI QHTM_Initialise( HINSTANCE hInst );

	//	Enable CoolTips in an application that currently uses the WIN32 Tool Tip control.
	BOOL WINAPI QHTM_EnableCooltips();

	//	Define a context type for printing. A context is used in a print procedure
	//	to communicate with the app
	typedef DWORD QHTMCONTEXT;

	//	Call this to create a new print context
	QHTMCONTEXT WINAPI QHTM_PrintCreateContext();

	//	Call this to create a new print context using a zoom level
	QHTMCONTEXT WINAPI QHTM_PrintCreateContext2( UINT uZoomLevel );

	//	Call this to destroy a print context
	BOOL WINAPI QHTM_PrintDestroyContext( QHTMCONTEXT );

	//	Call this to set the HTML
	BOOL WINAPI QHTM_PrintSetText( QHTMCONTEXT qhtmCtx, LPCTSTR pcszText );

	//	Call this to set the HTML ftom a file
	BOOL WINAPI QHTM_PrintSetTextFile( QHTMCONTEXT qhtmCtx, LPCTSTR pcszFilename );

	//	Call this to set the HTML ftom a resource
	BOOL WINAPI QHTM_PrintSetTextResource( QHTMCONTEXT qhtmCtx, HINSTANCE hInst, LPCTSTR pcszName );

	//	Call this to layout the HTML. Returns the number of pages in nPages
	BOOL WINAPI QHTM_PrintLayout( QHTMCONTEXT qhtmCtx, HDC dc, LPCRECT pRect, LPINT nPages );

	//	Call this to print a region of the HTML to a dc
	BOOL WINAPI QHTM_PrintRegion( QHTMCONTEXT qhtmCtx, HDC dc, LPCRECT prSrc, LPRECT prDest );

	//	Call to print a page of the HTML to a dc
	BOOL WINAPI QHTM_PrintPage( QHTMCONTEXT qhtmCtx, HDC hDC, UINT nPage, LPCRECT prDest);

	//	Get the print height of some HTML based on a maximum width.
	int WINAPI QHTM_PrintGetHTMLHeight( HDC hDC, LPCTSTR pcszText, int nMaxWidth );
	//	Using a zoom level
	int WINAPI QHTM_PrintGetHTMLHeight2( HDC hDC, LPCTSTR pcszText, int nMaxWidth, UINT uZoomLevel );

#ifdef __cplusplus
}
#endif	//	__cplusplus

#ifdef __AFXWIN_H__

	class CQHtmWnd : public CWnd
	//
	//	Simple wrapper class
	{
	public:
		//	Load the HTML from a file
		inline BOOL LoadFromFile( LPCTSTR pcszFilename )
		{
			return (BOOL)SendMessage( QHTM_LOAD_FROM_FILE, 0, (LPARAM)pcszFilename );
		}

		//	Load the HTML from a resource
		inline BOOL LoadFromResource( UINT uID )
		{
			return LoadFromResource( MAKEINTRESOURCE( uID ) );
		}

		//	Load the HTML from a resource
		inline BOOL LoadFromResource( LPCTSTR pcszName )
		{
			return (BOOL)SendMessage( QHTM_LOAD_FROM_RESOURCE, (WPARAM)AfxGetResourceHandle(), (LPARAM)pcszName );
		}

		//	Enable/disable tooltips on the control
		inline void SetToolTips( BOOL bEnable )
		{
			(void)SendMessage( QHTM_SET_OPTION, QHTM_OPT_TOOLTIPS, (WPARAM)bEnable );
		}

		//	Get the tooltips state
		inline BOOL GetToolTips()
		{
			return (BOOL)SendMessage( QHTM_GET_OPTION, QHTM_OPT_TOOLTIPS );
		}


		//	Enable/disable tooltips on the control
		inline void SetZoomLevel( int nLevel )
		{
			//	If this fires then either the window is invalid or teh zoom level is out of bounds!
			VERIFY( SendMessage( QHTM_SET_OPTION, QHTM_OPT_ZOOMLEVEL, (WPARAM)nLevel ) );
		}

		//	Get the current zoom level
		inline int GetZoomLevel()
		{
			return (int)SendMessage( QHTM_GET_OPTION, QHTM_OPT_ZOOMLEVEL );
		}

		//	Jump to a link
		inline void GotoLink( LPCTSTR pcszLink )
		{
			SendMessage( QHTM_GOTO_LINK, 0, (LPARAM)pcszLink );
		}

	};

#endif	//	__AFXWIN_H__

#endif //QHTM_H