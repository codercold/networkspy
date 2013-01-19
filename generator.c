#include <windows.h>

#include "windis.h"
#include "adapter.h"
#include "common.h"
#include "ui.h"
#include "globals.h"
#include "utility.h"
#include "fileio.h"
#include "resource.h"


#define WM_GETBUFFER	(WM_USER + 105)
#define WM_DECODEPACKET (WM_USER + 106)

LRESULT CALLBACK PacketGWndProc (HWND, UINT, WPARAM, LPARAM);
BOOL CALLBACK SendDlgProc(HWND, UINT, WPARAM, LPARAM);
BOOL CALLBACK SizeDlgProc(HWND, UINT, WPARAM, LPARAM);

int size = 64, rows, cols, lastrow;
unsigned char **pBuffer;
HWND hHtml;


unsigned char hextoint(unsigned char char1, unsigned char char2)
 {
	 if (char1 >= 'a' && char1 <= 'f')
		 char1 = char1 - 'a' + 10;
	 
	 if (char2 >= 'a' && char2 <= 'f')
		 char2 = char2 - 'a' + 10;
	 
	 if (char1 >= '0' && char1 <= '9')
		 char1 = char1 - '0';

	if (char2 >= '0' && char2 <= '9')
		 char2 = char2 - '0';

	 return (16*char1 + char2);
 }


void DeleteBuffer(unsigned char **pBuffer)
{
	int y;

	for (y = 0; y < rows; y++)
		free(pBuffer[y]);
	free(pBuffer);
}


unsigned char **CreateBuffer(int size)
{
	unsigned char **pBuffer;
	int i;

	rows = size / 16;
	lastrow = size % 16;
	if (lastrow)  
		++rows;
	cols = 93;

	pBuffer = (unsigned char **)malloc(rows*sizeof(unsigned char *));
	
	for (i = 0; i < rows; i++)
	{
		pBuffer[i] = (unsigned char *)malloc(cols*sizeof(unsigned char));
		wsprintf(pBuffer[i], "%04X: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ........................", i * 16);
	}

	
	if (lastrow)
	{
		wsprintf(pBuffer[rows-1], "%04X: ", (rows-1) * 16);
	
		for (i = 0; i < lastrow; i++)
			lstrcat(pBuffer[rows-1], "00 ");
	
		for (i = lastrow; i < 16; i++)
			lstrcat(pBuffer[rows-1], "   ");

		lstrcat(pBuffer[rows-1], "| ");

		for (i = 0; i < lastrow; i++)
			lstrcat(pBuffer[rows-1], ".");
		
		for (i = lastrow; i < 16; i++)
			lstrcat(pBuffer[rows-1], " ");
	}

	return pBuffer;
}


unsigned char *ConvertBufferToBinary(unsigned char **pBuffer)
{
	unsigned char *data;
	int i, j, index = 0;

	data = malloc(size*sizeof(unsigned char));
	
	if (data == NULL)
		return NULL;
	
	for (i = 0; i < rows; i++) 
		for (j = 0; j < 16; j++)
		{
			data[index] = hextoint(pBuffer[i][6 + j*3], pBuffer[i][7 + j*3]);
			++index;

			if (index >= size)
				break;
		}

	return data;
}


unsigned char **ConvertBinaryToBuffer(unsigned char *data, int size)
{
	unsigned char **pBuffer, temp[32];
	int i, j;

	lastrow = size % 16;

	if (lastrow)
		rows = (size / 16) + 1;
	else
		rows = size / 16;
	
	cols = 73;
	
	pBuffer = malloc(rows * sizeof(unsigned char *));

	for (i = 0; i < rows; i++)
		pBuffer[i] = malloc(cols * sizeof(unsigned char));


	for (i = 0; i < rows; i++)
	{
		wsprintf(pBuffer[i], "%04X: ", 16 * i);

		for (j = 0; j < 16; j++)
		{
			if ((i == rows-1) && (j >= lastrow) && lastrow)
				lstrcat(pBuffer[i], "   ");
			else
			{
				wsprintf(temp, "%02x ", data[i*16 + j]);
				lstrcat(pBuffer[i], temp);
			}
		}

		lstrcat(pBuffer[i], "| ");

		for (j = 0; j < 16; j++)
		{
			if ((i == rows-1)  && (j >= lastrow) && lastrow)
				wsprintf(temp, " ");
			else
			{
				if ((data[i*16 + j] > 33) && (data[i*16 + j] < 125))
					wsprintf(temp, "%c", data[i*16 + j]);
				else
					wsprintf(temp, ".");
			}
			lstrcat(pBuffer[i], temp);
		}		
	}

	return pBuffer;
}





void Send(unsigned char *packet, int size)
{
	DWORD		nBytesReturned, nResult;
	OVERLAPPED	g_OverLapped;
	HANDLE		g_hDevice;

	g_hDevice = W32N_OpenAdapter( szAdapter );
	
	if( g_hDevice == INVALID_HANDLE_VALUE )
	{
		MessageBox(0, "Unable to open adapter", APP_NAME, MB_OK | MB_ICONERROR);
		return;
	}
	
	g_OverLapped.hEvent = CreateEvent(NULL,FALSE,FALSE,NULL);
	
	nResult = W32N_PacketSend( 
						g_hDevice,
						packet,
						size,
						&nBytesReturned,
						&g_OverLapped);

	if (nResult)
		MessageBox(0, "Send Failed", APP_NAME, MB_ICONERROR | MB_OK);
}







HWND CreatePacketGWindow(HWND hWndParent, HINSTANCE hInstance)
{
	WNDCLASSEX	wndclass;
	HWND		hwnd;

	wndclass.cbSize        = sizeof (wndclass) ;
	wndclass.style         = CS_HREDRAW | CS_VREDRAW ;
	wndclass.lpfnWndProc   = PacketGWndProc ;
	wndclass.cbClsExtra    = 0 ;
	wndclass.cbWndExtra    = DLGWINDOWEXTRA;
	wndclass.hInstance     = hInstance ;
	wndclass.hIcon         = LoadIcon (hInstance, MAKEINTRESOURCE(IDI_ICON1)) ;
	wndclass.hCursor       = LoadCursor (NULL, IDC_ARROW) ;
	wndclass.hbrBackground = (HBRUSH) GetStockObject (WHITE_BRUSH) ;
	wndclass.lpszMenuName  = NULL ;
	wndclass.lpszClassName = "PacketGWindow" ;
	wndclass.hIconSm       = LoadIcon (hInstance, MAKEINTRESOURCE(IDI_ICON1)) ;
	
	RegisterClassEx (&wndclass) ;

	
	hwnd = CreateWindowEx (	WS_EX_ACCEPTFILES,
							"PacketGWindow", "Packet Generator",
							WS_CHILD | WS_VSCROLL | WS_VISIBLE,
							CW_USEDEFAULT, CW_USEDEFAULT,
							CW_USEDEFAULT, CW_USEDEFAULT,
							hWndParent, NULL, hInstance, NULL) ;
	return hwnd;
}



LRESULT CALLBACK PacketGWndProc (HWND hwnd, UINT iMsg, WPARAM wParam, LPARAM lParam)
{
	unsigned char	ascii;
	static int  cxChar, cxCaps, cxClient, cyClient, iVscrollPos, iVscrollMax, cyChar, xCaret = 6, yCaret;
	HDC         hdc ;
	int			y, i, iVscrollInc;
	static int	iPaintBeg, iPaintEnd;
	char		*szHTML;

	PAINTSTRUCT		ps;
	TEXTMETRIC		tm;
	static HFONT	hFont;
	SYSTEMTIME		systime;


	switch (iMsg)
	{
	//case WM_INITDIALOG:
	case WM_CREATE :	
		hdc = GetDC (hwnd) ;
		hFont = CreateFont(12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, FIXED_PITCH | FF_DONTCARE, "Courier");
		SelectObject (hdc, hFont) ;
		GetTextMetrics (hdc, &tm) ;
		cxChar = tm.tmAveCharWidth ;
		cyChar = tm.tmHeight ;
		ReleaseDC (hwnd, hdc) ;
	
		return 0 ;


	case WM_GETDLGCODE:
		return DLGC_WANTALLKEYS;


	case WM_LBUTTONDOWN:
		SetFocus(hwnd);
		return 0;


	case WM_SIZE :
		cxClient = LOWORD (lParam) ;
        cyClient = HIWORD (lParam) ;

        iVscrollMax = max (0, rows + 2 - cyClient / cyChar) ;
        iVscrollPos = min (iVscrollPos, iVscrollMax) ;

        SetScrollRange (hwnd, SB_VERT, 0, iVscrollMax, FALSE) ;
        SetScrollPos   (hwnd, SB_VERT, iVscrollPos, TRUE) ;

		return 0;


	case WM_VSCROLL:
		switch (LOWORD(wParam))
		{
		case SB_TOP:
			iVscrollInc = -iVscrollPos;
			break;

		case SB_BOTTOM:
			iVscrollInc = iVscrollMax = iVscrollPos;
			break;

		case SB_LINEUP:
			iVscrollInc = -1;
			break;
	
		case SB_LINEDOWN:
			iVscrollInc = 1;
			break;

		case SB_PAGEUP:
			iVscrollInc = min(-1, -cyClient / cyChar);
			break;

		case SB_PAGEDOWN:
			iVscrollInc = max(1, cyClient / cyChar);
			break;

		case SB_THUMBTRACK:
			iVscrollInc = HIWORD(wParam) - iVscrollPos;
			break;

		default:
			iVscrollInc = 0;
		}

		iVscrollInc = max (-iVscrollPos,
					  min (iVscrollInc, iVscrollMax - iVscrollPos));

		if (iVscrollInc != 0)
		{
			iVscrollPos += iVscrollInc;
			ScrollWindow(hwnd, 0, -cyChar * iVscrollInc, NULL, NULL);
			SetScrollPos(hwnd, SB_VERT, iVscrollPos, TRUE);
			
			xCaret = 6; yCaret = 0;
			SetCaretPos (xCaret * cxChar, 0) ;
			//UpdateWindow(hwnd);
			InvalidateRect(hwnd, NULL, TRUE);
		}

		return 0;


	case WM_SETFOCUS :
		// create and show the caret
		
		CreateCaret (hwnd, NULL, cxChar, cyChar) ;
		SetCaretPos (xCaret * cxChar, yCaret * cyChar) ;
		ShowCaret (hwnd) ;
		return 0 ;
		
	case WM_KILLFOCUS :
		// hide and destroy the caret
		HideCaret (hwnd) ;
		DestroyCaret () ;
		return 0 ;
		
	case WM_KEYDOWN :
		switch (wParam)
		{
		case VK_HOME :
			xCaret = 6 ;
			break ;
						
		case VK_PRIOR :
			yCaret = 0 ;
			break ;
			
		case VK_LEFT :
			xCaret = max (xCaret - 1, 6);
			if (pBuffer[yCaret][xCaret] == ' ')
				xCaret = max (xCaret - 1, 6);
			break ;
			
		case VK_RIGHT :
			++xCaret;
			
			if (lastrow && (yCaret + iPaintBeg == rows-1))
				if (xCaret > (4 + lastrow*3))
				{
					--xCaret;
					break;
				}

			if (xCaret > 52)
			{
				xCaret = 6;
				++yCaret;
				if (yCaret + iPaintBeg> rows - 1)
				{
					--yCaret;
					xCaret = 52;
				}
			}
			if ((xCaret % 3) == 2)
				++xCaret;
			break ;
			
		case VK_UP :
			yCaret = max (yCaret - 1, 0) ;
			break ;
			
		case VK_DOWN :
			if (lastrow && (xCaret > (4 + lastrow*3)))
				yCaret = min(yCaret + 1, rows - iPaintBeg - 2);
			else
				yCaret = min(yCaret + 1, rows - iPaintBeg - 1);
			break ;
		}
		
		SetCaretPos (xCaret * cxChar, yCaret * cyChar) ;
		return 0 ;
		
		case WM_CHAR :
			for (i = 0 ; i < (int) LOWORD (lParam) ; i++)
			{
				if (!((wParam >= '0' && wParam <='9') || (wParam >= 'a' && wParam <= 'f')))
					return 0;
					
					
				HideCaret (hwnd) ;
				hdc = GetDC (hwnd) ;
					
				SelectObject (hdc, hFont);
					
				pBuffer[yCaret + iPaintBeg][xCaret] = wParam;
				TextOut(hdc, xCaret * cxChar, (yCaret) * cyChar, &pBuffer[yCaret + iPaintBeg][xCaret], 1);
					
				if (pBuffer[yCaret + iPaintBeg][xCaret-1] == ' ')
					ascii = hextoint(pBuffer[yCaret + iPaintBeg][xCaret], pBuffer[yCaret + iPaintBeg][xCaret + 1]);
				else
					ascii = hextoint(pBuffer[yCaret + iPaintBeg][xCaret - 1], pBuffer[yCaret + iPaintBeg][xCaret]);
					
				if (ascii > 33 && ascii < 125)
				{
					pBuffer[yCaret + iPaintBeg][(xCaret/3) + 54] = ascii;
					TextOut(hdc, ((xCaret/3) + 54)* cxChar, yCaret * cyChar, &pBuffer[yCaret + iPaintBeg][(xCaret/3) + 54], 1);
				}
				else
				{
					pBuffer[yCaret + iPaintBeg][(xCaret/3) + 54] = '.';
					TextOut(hdc, ((xCaret/3) + 54)* cxChar, yCaret * cyChar, &pBuffer[yCaret + iPaintBeg][(xCaret/3) + 54], 1);
				}

				ShowCaret (hwnd) ;
				ReleaseDC (hwnd, hdc) ;
					
				SendMessage(hwnd, WM_KEYDOWN, VK_RIGHT, 0);
				SendMessage(hwnd, WM_DECODEPACKET, 0, 0);
				
				break ;
			}
			return 0 ;


		case WM_DECODEPACKET:
			szHTML = malloc(32000);
			GetSystemTime(&systime);
			DecodeSelected(systime, ConvertBufferToBinary(pBuffer), size, szHTML);
			SendMessage(hHtml, WM_SETTEXT, 0, (LPARAM) szHTML);
			InvalidateRect(hHtml, NULL, FALSE);
			free(szHTML);
			return 0;


	/*		
		case WM_DROPFILES:
			hDrop = (HANDLE) wParam;
			DragQueryFile(hDrop, 0, szFilename, sizeof(szFilename));
			pBuffer = LoadPacket(szFilename);
			GetWindowRect(hwnd, &rect);
			SendMessage(hwnd, WM_SIZE, 0, MAKEWPARAM(rect.bottom - rect.top, rect.right - rect.left));
			InvalidateRect(hwnd, NULL, TRUE);
			return 0;
*/

		case WM_PAINT :
			hdc = BeginPaint (hwnd, &ps) ;
			SelectObject (hdc, hFont) ;
			
			iPaintBeg = max (0, iVscrollPos + ps.rcPaint.top / cyChar );
			iPaintEnd = min (rows, iVscrollPos + ps.rcPaint.bottom / cyChar);
			
			i =0;
			for (y = iPaintBeg; y < iPaintEnd; y++, i++)	
				TextOut(hdc, 0, i * cyChar, pBuffer[y], 72);
			
			EndPaint (hwnd, &ps) ;
			return 0 ;


			
		case WM_DESTROY :
			DeleteBuffer(pBuffer);
			DeleteObject(hFont);
			return 0 ;
          }
		  return DefWindowProc (hwnd, iMsg, wParam, lParam) ;
 }
 



BOOL CALLBACK PacketGDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static HWND	hHexView;
	RECT rect = {100, 150, 680, 600};
	unsigned char *data;
	static char szFilename[MAX_PATH];
	char str[32];

	/* stuff to implement the split panes */
	static HCURSOR hCursor;
	static BOOL		bSplitterMoving;
	static DWORD	dwSplitterPos, dwValue;


	switch (uMsg)
	{
	case WM_INITDIALOG:
		hHexView = CreatePacketGWindow(hDlg, hInst);
		hHtml = GetDlgItem(hDlg, IDC_HTML);
		SetDlgItemText(hDlg, IDC_PACKET_SIZE, "64");
		pBuffer = CreateBuffer(64);

		GetPrivateProfileStruct("Packet Generator", "Window Rect", &rect, sizeof(RECT), "NetworkSpy.ini");
		/* Sanity Check */
		rect.left = RANGE(0, rect.left, GetSystemMetrics(SM_CXSCREEN)-150);
		rect.top = RANGE(0, rect.top, GetSystemMetrics(SM_CYSCREEN)-150);
		rect.right = RANGE(rect.left + 300, rect.right, rect.left + 1000);
		rect.bottom = RANGE(rect.top + 400, rect.bottom, rect.top + 1000);

		hCursor = LoadCursor(NULL, MAKEINTRESOURCE(IDC_SIZENS));
		bSplitterMoving = FALSE;
		
		dwSplitterPos = GetPrivateProfileInt("Packet Generator", "SplitterPos", 300, "NetworkSpy.ini");
		dwSplitterPos = RANGE(60, dwSplitterPos, rect.bottom - rect.top);

		MoveWindow(hDlg, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, TRUE);

		return TRUE;



	case WM_ACTIVATE:          
         if( LOWORD( wParam ) == WA_INACTIVE )
            hModelessDlg = NULL;
         else
            hModelessDlg = hDlg;
         return TRUE;


	case WM_SIZE:
		if (HIWORD(lParam) < 100)
			return TRUE;

		if (HIWORD(lParam) < dwSplitterPos)  
			dwSplitterPos = HIWORD(lParam) - 30;

		MoveWindow(hHtml, 0, 40, LOWORD(lParam), dwSplitterPos - 41, TRUE);
		MoveWindow(hHexView, 0, dwSplitterPos+2, LOWORD(lParam) , HIWORD(lParam) - dwSplitterPos - 2, TRUE);

		return TRUE;


	case WM_MOUSEMOVE:
		if (HIWORD(lParam) > 55)
		{
			SetCursor(hCursor);
			if ((wParam == MK_LBUTTON) && bSplitterMoving)
			{
				GetClientRect(hDlg, &rect);
				if ((HIWORD(lParam) > rect.bottom - 30) || (HIWORD(lParam) < 100))
					return TRUE;

				dwSplitterPos = HIWORD(lParam);
				SendMessage(hDlg, WM_SIZE, 0, MAKELPARAM(rect.right, rect.bottom));
			}
		}
		return TRUE;


	case WM_LBUTTONDOWN:
		SetCursor(hCursor);
		bSplitterMoving = TRUE;
		SetCapture(hDlg);
		return TRUE;


	case WM_LBUTTONUP:
		ReleaseCapture();
		bSplitterMoving = FALSE;
		return TRUE;


	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_OPEN_PACKET:
			if (PopFileOpenDlg(hDlg, szFilename))
			{
				LoadFile(szFilename, &data, &size);
				pBuffer = ConvertBinaryToBuffer(data, size);
				SendMessage(hHexView, WM_DECODEPACKET, 0, 0);
				InvalidateRect(hHexView, NULL, TRUE);
			}
			return TRUE;

		case IDC_SAVE_PACKET:
			if (PopFileSaveDlg(hDlg, szFilename, 2))
			{
				data = ConvertBufferToBinary(pBuffer);
				SaveFile(szFilename, data, size);
			}
			return TRUE;

		case ID_CLOSE:
			DestroyWindow(hDlg);
			return TRUE;

		case IDC_SET:
			DeleteBuffer(pBuffer);
			size = GetDlgItemInt(hDlg, IDC_PACKET_SIZE, NULL, FALSE);
			pBuffer = CreateBuffer(size);
			InvalidateRect(hHexView, NULL, TRUE);
			return TRUE;

		case IDC_SEND:
			data = ConvertBufferToBinary(pBuffer);
			Send(data, size);
			return TRUE;
		}
		break;
	

	case WM_CLOSE:
		DestroyWindow(hDlg);
		return TRUE;


	case WM_DESTROY:
		if (!IsIconic(hDlg) && !IsZoomed(hDlg))
		{
			GetWindowRect(hDlg, &rect);
			WritePrivateProfileStruct("Packet Generator", "Window Rect", &rect, sizeof(RECT), "NetworkSpy.ini");
			wsprintf(str, "%d", dwSplitterPos);
			WritePrivateProfileString("Packet Generator", "SplitterPos", str, "NetworkSpy.ini");
		}
		return TRUE;
	}
	return FALSE;
}