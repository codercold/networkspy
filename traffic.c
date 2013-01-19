#include <windows.h>
#include <commctrl.h>
#include "traffic.h"


LRESULT CALLBACK TrafficWndProc(HWND, UINT, WPARAM, LPARAM);



HWND CreateTrafficWindow(HWND hWnd, HINSTANCE hInst)
{
	WNDCLASS	wndclass;
	HWND		hwnd;

	wndclass.style			= CS_HREDRAW | CS_VREDRAW;
	wndclass.lpfnWndProc	= TrafficWndProc;
	wndclass.cbClsExtra		= 0;
	wndclass.cbWndExtra		= 0;
	wndclass.hInstance		= hInst;
	wndclass.hIcon			= NULL;
	wndclass.hCursor		= LoadCursor(NULL, IDC_ARROW);;
	wndclass.hbrBackground	= NULL;
	wndclass.lpszMenuName	= NULL;
	wndclass.lpszClassName	= "TrafficWindow";

	RegisterClass(&wndclass);

	hwnd = CreateWindowEx(WS_EX_CLIENTEDGE, "TrafficWindow", "",
						WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS, 
						CW_USEDEFAULT, CW_USEDEFAULT, 
						CW_USEDEFAULT, CW_USEDEFAULT,
						hWnd, NULL,
						hInst, NULL);

	return hwnd;
}


LRESULT CALLBACK TrafficWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	HDC			hdc;
	PAINTSTRUCT	ps;
	RECT		rect;
	static HPEN		hWhitePen, hGreenPen, hBlackPen, hBlackBrush, hWhiteBrush;
	static HDC		hdcMem;
	static HBITMAP	hBitmap;
	static int		i, full, value[30], *temp;
	static int		multiplier = 10;  // will be divided by 10 before use


	switch(msg)
	{
		case WM_CREATE:
			hdc = GetDC(hWnd);
			hdcMem = CreateCompatibleDC(hdc);
			hBitmap = CreateCompatibleBitmap(hdc, 200, 200);
			SelectObject(hdcMem, hBitmap);
			ReleaseDC (hWnd, hdc);

			hWhitePen = CreatePen(PS_SOLID, 0, RGB(255, 255, 255));
			hGreenPen = CreatePen(PS_SOLID, 1, RGB(0, 128, 0));
			hBlackPen = GetStockObject(BLACK_PEN);
			hBlackBrush = GetStockObject(BLACK_BRUSH);
			hWhiteBrush = GetStockObject(WHITE_BRUSH);

			full = 0;

			return 0;


		case TRAFFIC_ADD:
			temp = (int *) lParam;
			if (full < 30)
			{
				value[full] = *temp;
				++full;
			}
			else
			{
				for (i = 0; i < 29; i++)
					value[i] = value[i+1];

				value[29] = *temp;
			}
			InvalidateRect(hWnd, NULL, TRUE);
			return 0;


		case WM_ERASEBKGND:
			return 1;


		case WM_PAINT:
			
			hdc = BeginPaint(hWnd, &ps);
			GetClientRect(hWnd, &rect);
			SelectObject(hdcMem, hBlackPen);
			SelectObject(hdcMem, hBlackBrush);
			
			Rectangle( hdcMem, 
					   ps.rcPaint.left, 
					   ps.rcPaint.top, 
					   ps.rcPaint.right, 
					   ps.rcPaint.bottom);


			GetClientRect(hWnd, &rect);
			SelectObject(hdcMem, hGreenPen);
			for (i = 10; i < rect.bottom; i = i + 10)
			{
				MoveToEx(hdcMem, 0, i, NULL);
				LineTo(hdcMem, rect.right, i);
			}
			for (i = 10; i < rect.right; i = i + 10)
			{
				MoveToEx(hdcMem, i, 0, NULL);
				LineTo(hdcMem, i, rect.bottom);
			}


			SelectObject(hdcMem, hWhitePen);
			SelectObject(hdcMem, hWhiteBrush);
			for (i = 0; i < 30; i++)
				Rectangle(hdcMem, i*5, 95 - (value[i] * multiplier)/10 , i*5+3, 100);

			BitBlt(hdc, 0, 0, 200, 200, hdcMem, 0, 0, SRCCOPY);

			EndPaint(hWnd, &ps);
			return 0;


		case WM_RBUTTONUP:
			multiplier += 5;
			return 0;

		case WM_LBUTTONUP:
			if (multiplier > 10)  
				multiplier -= 5;
			return 0;

		case WM_DESTROY:
			DeleteObject(hWhitePen);
			DeleteObject(hGreenPen);
			DeleteObject(hBitmap);
			DeleteDC(hdcMem);
			return 0;
	}

	return DefWindowProc(hWnd, msg, wParam, lParam);
}