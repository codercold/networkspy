#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

#include "resource.h"


LRESULT CALLBACK HexviewProc (HWND, UINT, WPARAM, LPARAM);
BOOL CALLBACK SendDlgProc(HWND, UINT, WPARAM, LPARAM);
BOOL CALLBACK SizeDlgProc(HWND, UINT, WPARAM, LPARAM);


HWND CreateHexviewWindow(HWND hWnd, HINSTANCE hInst)
{
	WNDCLASS	wndclass;
	HWND		hwnd;

	wndclass.style			= CS_HREDRAW | CS_VREDRAW;
	wndclass.lpfnWndProc	= HexviewProc;
	wndclass.cbClsExtra		= 0;
	wndclass.cbWndExtra		= 0;
	wndclass.hInstance		= hInst;
	wndclass.hIcon			= NULL;
	wndclass.hCursor		= LoadCursor(NULL, IDC_ARROW);;
	wndclass.hbrBackground	= NULL;
	wndclass.lpszMenuName	= NULL;
	wndclass.lpszClassName	= "HexviewWindow";

	RegisterClass(&wndclass);

	hwnd = CreateWindowEx(WS_EX_CLIENTEDGE, "Hexview", "",
						WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS, 
						CW_USEDEFAULT, CW_USEDEFAULT, 
						CW_USEDEFAULT, CW_USEDEFAULT,
						hWnd, NULL,
						hInst, NULL);

	return hwnd;
}

LRESULT CALLBACK HexviewProc (HWND hwnd, UINT iMsg, WPARAM wParam, LPARAM lParam)
{
	static unsigned char **pBuffer = NULL ;
	unsigned char	ascii, *bin_data;
	static int  cxChar, cxCaps, cxClient, cyClient, 
				iVscrollPos, iVscrollMax, 
				cyChar, xCaret = 6, yCaret;
	HDC         hdc ;
	int			y, i, nResult, iVscrollInc;
	static int	iPaintBeg, iPaintEnd;
	char		szFilename[MAX_PATH], szBuffer[256];
	
	RECT			rect = {50, 50, 620, 300};
	PAINTSTRUCT		ps;
	TEXTMETRIC		tm;
	static HFONT	hFont;
	HDROP			hDrop;

	
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
		
		pBuffer = CreateBuffer(64);
		return 0 ;


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
				break ;
			}
			return 0 ;

			
		case WM_DROPFILES:
			hDrop = (HANDLE) wParam;
			DragQueryFile(hDrop, 0, szFilename, sizeof(szFilename));
			pBuffer = LoadPacket(szFilename);
			GetWindowRect(hwnd, &rect);
			SendMessage(hwnd, WM_SIZE, 0, MAKEWPARAM(rect.bottom - rect.top, rect.right - rect.left));
			InvalidateRect(hwnd, NULL, TRUE);
			return 0;


		case WM_PAINT :
			hdc = BeginPaint (hwnd, &ps) ;
			SelectObject (hdc, hFont) ;
			
			iPaintBeg = max (0, iVscrollPos + ps.rcPaint.top / cyChar );
			iPaintEnd = min (rows,
							 iVscrollPos + ps.rcPaint.bottom / cyChar);
			
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
	cols = 73;

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

	current_buffer = pBuffer;

	return pBuffer;
}

unsigned char *ConvertBufferToBinary(unsigned char **pBuffer)
{
	unsigned char *data;
	int i, j, index = 0;

	data = malloc(packetsize*sizeof(unsigned char));
	
	if (data == NULL)
		return NULL;
	
	for (i = 0; i < rows; i++) 
		for (j = 0; j < 16; j++)
		{
			data[index] = hextoint(pBuffer[i][6 + j*3], pBuffer[i][7 + j*3]);
			++index;

			if (index >= packetsize)
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

	current_buffer = pBuffer;

	return pBuffer;
}


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



