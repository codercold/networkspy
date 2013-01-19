#include "common.h"
#include "W32ndis.h"
#include "windis.h"


HANDLE		g_hDevice = INVALID_HANDLE_VALUE;
OVERLAPPED	g_OverLapped;


VOID DisplayError(char *function, BOOL bSuccess, HWND hDlg)
{
	char message[512];

	lstrcpy(message, function);

	if (bSuccess)
		lstrcat(message, " successful!");
	else
		lstrcat(message, " failed!");

	MessageBox(hDlg, message, APP_NAME, MB_OK);
}


BOOLEAN SetPacketFilter( ULONG nPacketFilter )
{
	HOOK_REQUEST	HookRequest;
	NDIS_STATUS		nNdisStatus;

	HookRequest.NdisRequest.RequestType = NdisRequestSetInformation;

	HookRequest.NdisRequest.DATA.SET_INFORMATION.Oid = OID_GEN_CURRENT_PACKET_FILTER;
	HookRequest.NdisRequest.DATA.SET_INFORMATION.InformationBuffer = &nPacketFilter;
	HookRequest.NdisRequest.DATA.SET_INFORMATION.InformationBufferLength = sizeof( ULONG );
	HookRequest.NdisRequest.DATA.SET_INFORMATION.BytesRead = 0;
	HookRequest.NdisRequest.DATA.SET_INFORMATION.BytesNeeded = 0;

	nNdisStatus = W32N_MakeNdisRequest(
					g_hDevice,
					&HookRequest,
					&g_OverLapped,
					TRUE					// Synchronous
					);

	if( nNdisStatus )
	{
		return( FALSE );
	}

	return( TRUE );
}


VOID WinDis(HWND hDlg)
{
	char str[1024];
	BOOL bReturn;
	PW32N_PACKET pUserPacketData; 
	DWORD	dwRet;

	pUserPacketData = malloc(sizeof(W32N_PACKET));

		g_hDevice = W32N_OpenAdapter("0001");
		if (g_hDevice == INVALID_HANDLE_VALUE)
		{
			MessageBox(hDlg, "Open Adapter failed", APP_NAME, MB_ICONERROR | MB_OK);
			return;
		}

		g_OverLapped.hEvent = CreateEvent(NULL,	FALSE, FALSE, NULL);
		ResetEvent( g_OverLapped.hEvent );

		bReturn = SetPacketFilter(NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_PROMISCUOUS);
		DisplayError("SetPacketFilter", bReturn, hDlg);

		bShutDown = FALSE;

		W32N_PacketRead(g_hDevice,
						pUserPacketData,
						NULL,
						&g_OverLapped,
						TRUE);

		//do
		//{
		//	bReturn = GetOverlappedResult(g_hDevice, &g_OverLapped, &dwRet, FALSE);
		//} while (!bReturn && !bShutDown);


		wsprintf(str, "Received a packet of size %d", pUserPacketData->nPacketDataLength);
		
		DisplayError(str, TRUE, hDlg);
		
		

		CloseHandle( g_OverLapped.hEvent );

		W32N_CloseAdapter(g_hDevice);

		free(pUserPacketData);

}


