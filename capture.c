#include <windows.h>
#include <commctrl.h>

#include "WiNDIS.h"
#include "HookUtil.h"

#include "adapter.h"
#include "resource.h"
#include "common.h"
#include "structs.h"
#include "globals.h"
#include "logging.h"
#include "rules.h"
#include "utility.h"


HookAdapter g_Adapter = { INVALID_HANDLE_VALUE };


#define MAX_LINK_NAME_LENGTH	64
#define NUM_RECIEVE_PACKAGES    64   //512


VOID WINAPI ReadCompleteApcNT(
				DWORD dwErrorCode,
				DWORD dwNumberOfBytesTransfered,
				LPOVERLAPPED lpOverlapped
				);

DWORD WINAPI ReadCompleteApc95(
				LPOVERLAPPED lpOverlapped
				);




DWORD HandleReadComplete( PReceivePackage pRxPackage )
{
   BOOLEAN  bResult;
   DWORD    nResult;
   char		str[32];
   SYSTEMTIME systime;

   if( g_bShutdown )
      return( 0 );


   if( HP_IsValidReceivePackage( pRxPackage ) )
   {
      if( pRxPackage->UserPacketData.nNdisStatus != NDIS_STATUS_SUCCESS )
      {
         //printf( "Read Error: 0x%4.4X\n",
         //   pRxPackage->UserPacketData.nNdisStatus );

         return( 0 );
      }

      ++((pRxPackage->pAdapter)->m_nReceivedPacketCount);

      
	  GetLocalTime(&systime);
	  ++packets_captured;
	  total_bytes += pRxPackage->UserPacketData.nBufferDataLength;
	  new_data += pRxPackage->UserPacketData.nBufferDataLength;

	  if (!g_bBufferDump && !g_bServerMode)
	  {
		  ProcessPacket(systime, 
						pRxPackage->UserPacketData.PacketBuffer,
						pRxPackage->UserPacketData.nBufferDataLength,
						bEnableFilter
						);
	  }
	  else	// add to the linked list
	  {
		if (head_ptr == NULL)
		{
			head_ptr = malloc(sizeof(struct packet_list));
			cur_ptr = head_ptr;
		}
		else
		{
			cur_ptr->next = malloc(sizeof(struct packet_list));
			cur_ptr = cur_ptr->next;
		}

		cur_ptr->next = NULL;
		cur_ptr->size = pRxPackage->UserPacketData.nBufferDataLength;
		cur_ptr->time = systime;
		cur_ptr->data = malloc(cur_ptr->size);
		memcpy(cur_ptr->data, pRxPackage->UserPacketData.PacketBuffer, cur_ptr->size);

		bytes_used += pRxPackage->UserPacketData.nBufferDataLength;
		wsprintf(str, "%d bytes captured", bytes_used);
		SendMessage(hWndStatus, SB_SETTEXT, (WPARAM) 1, (LPARAM) str);
	  }

	  
						
      //
      // Post Another Read On The Packet Package
      //
      if( !g_bShutdown )
      {
         if( W32N_IsWindows95() )
         {
            bResult = W32N_PacketReadEx(
                        (pRxPackage->pAdapter)->m_hDevice,
                        &pRxPackage->UserPacketData,
                        &pRxPackage->nBytesReturned,
                        &pRxPackage->OverLapped,
                        (PVOID )ReadCompleteApc95
                        );
         }
         else if( W32N_IsWindowsNT() )
         {
            bResult = W32N_PacketReadEx(
                        (pRxPackage->pAdapter)->m_hDevice,
                        &pRxPackage->UserPacketData,
                        &pRxPackage->nBytesReturned,
                        &pRxPackage->OverLapped,
                        (PVOID )ReadCompleteApcNT
                        );
         }
         else
         {
            // ATTENTION!!! Deal with this case!!!
         }

         if( !bResult )
         {
            nResult = W32N_GetLastError();

            if( nResult != ERROR_IO_PENDING )
            {
               //printf( "W32N_PacketReadEx Failed; Error: 0x%8.8X\n",
               //   nResult );
            }
         }
      }
   }

   return( 0 );
}


/////////////////////////////////////////////////////////////////////////////
//// ReadCompleteApcNT
//
// Purpose
//
// Parameters
//
// Return Value
//
// Remarks
//

VOID WINAPI ReadCompleteApcNT(
   DWORD dwErrorCode,
   DWORD dwNumberOfBytesTransfered,
   LPOVERLAPPED lpOverlapped
   )
{
   PReceivePackage   pRxPackage;
 
   if( g_bShutdown )
   {
      return;
   }

   // ATTENTION!!! Consider using try/except here...
   pRxPackage = (PReceivePackage )lpOverlapped->OffsetHigh;


   HandleReadComplete( pRxPackage );

   return;
}


/////////////////////////////////////////////////////////////////////////////
//// ReadCompleteApc95
//
// Purpose
//
// Parameters
//
// Return Value
//
// Remarks
//

DWORD WINAPI ReadCompleteApc95(
   LPOVERLAPPED lpOverlapped
   )
{
   PReceivePackage   pRxPackage;

   if( g_bShutdown )
   {
      return( 0 );
   }

   // ATTENTION!!! Consider using try/except here...
   pRxPackage = (PReceivePackage )lpOverlapped->OffsetHigh;

   return( HandleReadComplete( pRxPackage ) );

   return( 0 );
}


/////////////////////////////////////////////////////////////////////////////
//// ReceiveProc
//
// Purpose
// HookPeek receive thread Thread Start routine.
//
// Parameters
//
// Return Value
//
// Remarks
//

DWORD WINAPI ReceiveProc( PHookAdapter pAdapter )
{
   HANDLE            hReceiveEvent;
   DWORD             nResult;
   DWORD             i, nNextPackage = 0;
   PReceivePackage   pRxPackage;
   BOOL              bResult;


   hReceiveEvent = CreateEvent(NULL, FALSE, FALSE, NULL );

   
   pAdapter->m_pRxPackageBase = NULL;

   nResult = HP_CreateReceivePackages(
               pAdapter,
               NUM_RECIEVE_PACKAGES,
               FALSE   // Do Not Create Per-Package Event
               );

   if( !nResult || pAdapter->m_nPackageCount == 0 )
      return( 0 );		// Could not create packages


   
   for( i = 0; i < pAdapter->m_nPackageCount; i++ )
   {
      pRxPackage = &pAdapter->m_pRxPackageBase[ i ];

      ResetEvent( pRxPackage->OverLapped.hEvent );

      if( W32N_IsWindows95() )
      {
         bResult = W32N_PacketReadEx(
                     pAdapter->m_hDevice,
                     &pRxPackage->UserPacketData,
                     &pRxPackage->nBytesReturned,
                     &pRxPackage->OverLapped,
                     ReadCompleteApc95
                     );
      }
      else if( W32N_IsWindowsNT() )
      {
         bResult = W32N_PacketReadEx(
                     pAdapter->m_hDevice,
                     &pRxPackage->UserPacketData,
                     &pRxPackage->nBytesReturned,
                     &pRxPackage->OverLapped,
                     ReadCompleteApcNT
                     );
      }
      else
      {
         // ATTENTION!!! Deal with this case!!!
      }

      if( !bResult )
      {
         nResult = W32N_GetLastError();

         if( nResult == ERROR_IO_PENDING )
         {
         }
         else
         {
           // printf( "W32N_PacketReadEx Failed; Error: 0x%8.8X\n",
           //    nResult );
         }
      }
   }

   //
   // Loop Until Shutdown
   //
   while( !g_bShutdown )
   {
      nResult = WaitForSingleObjectEx( hReceiveEvent, 1000, TRUE );

      if( nResult == WAIT_TIMEOUT )
      {
      }
   }

   
   // this used to be commented out
   for( i = 0; i < pAdapter->m_nPackageCount; i++ )
   {
      pRxPackage = &pAdapter->m_pRxPackageBase[ i ];
      W32N_CancelPacketRead(pAdapter->m_hDevice, &pRxPackage->UserPacketData);
   }

   CloseHandle( hReceiveEvent );

   return( 0 );  
}




DWORD WinDis( PVOID ptr )
{
	BOOLEAN		bResult;
	DWORD       nResult;
	char        szBuffer[128];
	HANDLE		g_hReceiveThread = NULL;
	DWORD		g_nReceiveThreadId = 0;


	// NELSON
   // strcpy( g_Adapter.m_szAdapterName, szAdapter );
   strcpy_s( g_Adapter.m_szAdapterName, sizeof(g_Adapter.m_szAdapterName), szAdapter );


   g_Adapter.m_hDevice = W32N_OpenAdapter( g_Adapter.m_szAdapterName );

   if( g_Adapter.m_hDevice == INVALID_HANDLE_VALUE )
   {
	  g_bShutdown = TRUE;
      nResult = W32N_GetLastError();
      wsprintf(szBuffer, "Could Not Open Adapter; Error 0x%8.8X\n", nResult );
      MessageBox(hWndMain, szBuffer, APP_NAME, MB_OK | MB_ICONERROR);  
      return( 0 );     
   }

 
   g_Adapter.m_OverLapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

   if( !g_Adapter.m_OverLapped.hEvent )
   {
      W32N_CloseAdapter( g_Adapter.m_hDevice );
      return( 0 );
   }

   ResetEvent( g_Adapter.m_OverLapped.hEvent );


   //
   // Create The Receive Thread
   //
   g_hReceiveThread = CreateThread(
                        (LPSECURITY_ATTRIBUTES )NULL,   // No Security
                        (DWORD )0,                     // Same Stack Size
                        (LPTHREAD_START_ROUTINE )ReceiveProc,   // Thread Procedure
                        (PVOID )&g_Adapter,            // Parameter Pointer
                        (DWORD )0,                     // Start Immediately
                        &g_nReceiveThreadId                  // Thread ID
                        );

   if( !g_hReceiveThread )
   {
//      printf( "Could Not Start Receive Thread\n" );
   }

   //
   // Call Driver To Start Reception
   // ------------------------------
   // Only allow FIRST instance of HookPeek to start promiscuous
   // operation.
   //
   // Understand that even though the receive thread has been started
   // and packet read operations have been posted, no packets will
   // actually be received until the adapter's NDIS packet filter has
   // been set. In this case, HP_StartPromiscuousReception is the
   // function that sets the adapter's NDIS packet filter.
   //
   
   bResult = HP_StartPromiscuousReception( &g_Adapter );
   
  
	
   if (g_bBufferDump)
		SendDlgItemMessage(hWndMain, 1003, SB_SETTEXT, (WPARAM)0, (LPARAM) "Listening (no display)...");
	else
		SendDlgItemMessage(hWndMain, 1003, SB_SETTEXT, (WPARAM)0, (LPARAM) "Listening...");
	
	EnableMenuItem(GetMenu(hWndMain), IDC_LISTEN, MF_GRAYED);
	SendMessage(hWndToolbar, TB_ENABLEBUTTON, (WPARAM) IDC_LISTEN, (LPARAM) MAKELONG(FALSE, 0));


   if( !bResult )
   {
		wsprintf(szBuffer, "Start Reception Failed!");
		MessageBox(hWndMain, szBuffer, APP_NAME, MB_OK|MB_ICONERROR);
		g_bShutdown = TRUE;

		nResult = WaitForSingleObject( g_hReceiveThread, 10000 );

		CloseHandle( g_hReceiveThread );
		g_hReceiveThread = NULL;

		W32N_CloseAdapter( g_Adapter.m_hDevice );

		HP_DestroyReceivePackages( &g_Adapter );

		return ( 3 );
   }

  
   //
   // The Main Program Loop
   //
   g_bIsRunning = TRUE;
   SetTimer(hWndMain, 1, 1000, NULL);	// timer for stats
   SetTimer(hWndMain, 2, 60000, NULL);	// timer to update rates
   
   if (!isRegistered())
		SetTimer(hWndMain, 3, 180000, NULL); // timer for unregistered version

	while( !g_bShutdown )
	{
		nResult = WaitForSingleObjectEx( g_hReceiveThread, 5000, TRUE );

		if( nResult == WAIT_TIMEOUT )
		{
         // Periodic Functions Can Go Here...
         //
        
		}
		else
		{
			CloseHandle( g_hReceiveThread );
			g_hReceiveThread = NULL;
			break;
		}
	}

   

   //
   // Wait For Receive Thread To Die Or 5-second Timeout
   //
   if( g_hReceiveThread )
   {
      nResult = WaitForSingleObject( g_hReceiveThread, 5000 );

      CloseHandle( g_hReceiveThread );
   }

   g_hReceiveThread = NULL;

  
  
   if( g_Adapter.m_hDevice != INVALID_HANDLE_VALUE )
      W32N_CloseAdapter( g_Adapter.m_hDevice );

   g_Adapter.m_hDevice = INVALID_HANDLE_VALUE;

   HP_DestroyReceivePackages( &g_Adapter );

   if( g_Adapter.m_OverLapped.hEvent )
      CloseHandle( g_Adapter.m_OverLapped.hEvent );

   g_Adapter.m_OverLapped.hEvent = NULL;

	g_bIsRunning = FALSE;

	if (hWndMain == NULL)  return 0;   // Application probably got WM_DESTROY
	

	SendMessage(hWndStatus, SB_SETTEXT, (WPARAM)0, (LPARAM) "Stopped");
	if (count > 65000)
		SendMessage(hWndStatus, SB_SETTEXT, (WPARAM)0, (LPARAM) "Stopped: Max. count reached");

	if (g_bBufferDump)
		SendMessage(hWndMain, MY_CAPTURE_COMPLETE, 0, 0);
	else if (g_bServerMode)
		SendMessage(hWndServer, MY_CAPTURE_COMPLETE, 0, 0);
	
	EndLogging();  // close the open file used for logging

	KillTimer(hWndMain, 1);
	KillTimer(hWndMain, 2);
	KillTimer(hWndMain, 3);

	EnableMenuItem(GetMenu(hWndMain), IDC_LISTEN, MF_ENABLED);
	SendMessage(hWndToolbar, TB_ENABLEBUTTON, (WPARAM) IDC_LISTEN, (LPARAM) MAKELONG(TRUE, 0));

	if (!isRegistered())
	{
		SendMessage(hWndStatus, SB_SETTEXT, (WPARAM) 2, (LPARAM) "Evaluation version: 3 minutes of capture allowed!");
		DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUT), hWndMain, AboutDlgProc);
	}
   return( 0 );
}





