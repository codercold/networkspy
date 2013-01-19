/////////////////////////////////////////////////////////////////////////////
//// INCLUDE FILES

#include <windows.h>
#include <Assert.h>

#include "WinDis.h"
#include "HookUtil.h"

// Copyright And Configuration Management ----------------------------------
//
//                       Win32 NDIS Framework (WinDis 32)
//                                    For
//                          Windows 95 And Windows NT
//
//          HookPeek Packet Receive Common Routines - HPRxUtil.c
//
//      Copyright (c) 1995-1999, Printing Communications Associates, Inc.
//
//                             Thomas F. Divine
//                           4201 Brunswick Court
//                        Smyrna, Georgia 30080 USA
//                              (770) 432-4580
//                            tdivine@pcausa.com
// 
// End ---------------------------------------------------------------------

//
// Comment
// ----------
// All HookPeek samples illustrate receiving packets. Although the
// method used to receive a packet may vary from one example to another,
// all samples can display the contents of the W32N_PACKET on the console.
//
// Since the work of displaying the packet is common to all  HookPeek
// examples, it has been moved to this Common program module instead
// of being duplicated in each HookPeek program directory.
//



/////////////////////////////////////////////////////////////////////////////
//// HP_DestroyReceivePackages
//
// Purpose
// Close event handles and free memory associated with packet packages
// created previously by HP_CreateReceivePackages().
//
// Parameters
//
// Return Value
// None
//
// Remarks
//

void HP_DestroyReceivePackages( PHookAdapter pAdapter )
{
   DWORD               i;
   PReceivePackage     pRxPackage;

   //
   // Sanity Checks
   //
   if( !pAdapter->m_pRxPackageBase )
   {
      return;
   }

   if( pAdapter->m_hDummyReceiveEvent )
   {
      //
      // Close The Special Receive Event
      //
      CloseHandle( pAdapter->m_hDummyReceiveEvent );
      pAdapter->m_hDummyReceiveEvent = NULL;
   }
   else
   {
      //
      // Close Event Handles For Each Package
      //
      for( i = 0; i < pAdapter->m_nPackageCount; i++ )
      {
         pRxPackage = &pAdapter->m_pRxPackageBase[ i ];

         if( pRxPackage->OverLapped.hEvent )
         {
            CloseHandle( pRxPackage->OverLapped.hEvent );
         }

         pRxPackage->OverLapped.hEvent = NULL;
      }
   }

   //
   // Free Memory Allocated For The Packages
   //
   free( pAdapter->m_pRxPackageBase );

   pAdapter->m_pRxPackageBase = NULL;
   pAdapter->m_nPackageCount = 0;
}


/////////////////////////////////////////////////////////////////////////////
//// HP_CreateReceivePackages
//
// Purpose
// Allocate memory and create event handles for the specified number of
// packet "packages". 
//
// Parameters
//   nPackageCount - The number of packet packages to create.
//
// Return Value
//   If successfull, returns pointer to an array of packet packages.
//
// Remarks
// NDISHOOK uses multiple concurrent asynchronous IOCTL_NDISHOOK_PACKET_READ
// calls as a means to reduce packet loss.
//
// Each receive "package" is a data structure (defined elsewhere) which
// contains a W32N_PACKET, OVERLAPPED and other fields needed to
// make one asynchronous call to the NDISHOOK driver.
//
// This function simply allocates and initializes multiple packet packages.
//

DWORD HP_CreateReceivePackages(
   PHookAdapter pAdapter,
   DWORD nPackageCount,
   BOOL bInitOverlappedEvent
   )
{
   DWORD               i;
   DWORD               nReceivePackageSize;
   PReceivePackage   pRxPackage;

   pAdapter->m_pRxPackageBase = NULL;
   pAdapter->m_nPackageCount = 0;

   //
   // Allocate Memory For The Packages
   //
   nReceivePackageSize = sizeof( ReceivePackage );

   pAdapter->m_pRxPackageBase = (PReceivePackage )malloc( nReceivePackageSize * nPackageCount );

   if( !pAdapter->m_pRxPackageBase )
   {
      return( 0 );
   }

   //
   // Possibly Create The Special Windows 9X Receive Event
   // ----------------------------------------------------
   // Asynchronous I/O to Windows 9X VxD's REQUIRES a pointer to an
   // OVERLAPPED structure. In addition, the hEvent field of the
   // OVERLAPPED structure MUST be initialized to a manual reset event.
   //
   // Windows NT does NOT have the same requirement.
   //
   // If bInitOverlappedEvent is TRUE, this function will create
   // an event on a per-package basis. This, of course, limits the
   // number of packages that can be created to the number of events
   // that can be created. This limit is defined as MAXIMUM_WAIT_OBJECTS,
   // which is typically 64.
   //
   // If bInitOverlappedEvent is FALSE, this function will create
   // one special event which is assigned to ALL packages. This scheme
   // is provided to support the Windows 9X W32N_PacketReadEx() function
   // for APC's. When using W32N_PacketReadEx() and APC's on Windows 9X,
   // the special event is actually never used. Instead, the APC is called
   // using the _VWIN32_QueueUserApc() VxD system service. The special
   // receive event serves the sole purpose of satisfying the DeviceIoControl
   // call parameter checking.
   //
   pAdapter->m_hDummyReceiveEvent = NULL;

   if( W32N_IsWindows95() && !bInitOverlappedEvent )
   {
      pAdapter->m_hDummyReceiveEvent = CreateEvent(
                                       NULL,      // Security Attributes
                                       TRUE,      // Manual-Reset
                                       FALSE,   // Initial State Not Signaled
                                       NULL      // Event-object Name
                                       );
   }

   //
   // Initialize Each Receive Package
   //
   for( i = 0; i < nPackageCount; i++ )
   {
      pRxPackage = &pAdapter->m_pRxPackageBase[ i ];

      //
      // Zero The Package Memory
      //
      memset( pRxPackage, 0x00, nReceivePackageSize );

      //
      // Set The Signature
      //
      pRxPackage->nSignature = RX_PACKAGE_SIGN;

      pRxPackage->pAdapter = pAdapter;

      //
      // Initialize The OVERLAPPED Structure
      // -----------------------------------
      // Because we are performing I/O to a device, Windows does not
      // use the Offset or OffsetHigh fields of the OVERLAPPED structure.
      // This means that we can use these fields for our own purposes.
      //
      // The next two lines initialize these fields woth pointers to
      // the HookAdapter and ReceivePackage. Later, when certain types
      // of ascynchronous I/O operations complete, are given a only a
      // pointer to the OVERLAPPED structure in the completion routine.
      //
      // Since the OVERLAPPED fields have been initialized as below,
      // pointers to the ReceivePackage structure can be recovered from
      // the OffsetHigh field.
      //
      // Do not use the Offset field. On the Windows 9X platform Offset
      // is used to return completion status IF the operation does not
      // fail immediately.
      //
      pRxPackage->OverLapped.OffsetHigh = (DWORD )pRxPackage;

      //
      // Create The OVERLAPPED Event To Wait On
      //
      if( bInitOverlappedEvent && i < MAXIMUM_WAIT_OBJECTS )
      {
         pRxPackage->OverLapped.hEvent = CreateEvent(
                                 NULL,      // Security Attributes
//                                 FALSE,   // Auto-Reset
                                 TRUE,      // Manual-Reset
                                 FALSE,   // Initial State Not Signaled
                                 NULL      // Event-object Name
                                 );

         //
         // Verify That The Event Was Created
         //
         if( !pRxPackage->OverLapped.hEvent )
         {
            free( pRxPackage );   // Free This Partailly Built One Only...

            return( pAdapter->m_nPackageCount );
         }
      }
      else
      {
         if( W32N_IsWindows95() )
         {
            pRxPackage->OverLapped.hEvent = pAdapter->m_hDummyReceiveEvent;
         }
         else
         {
            pRxPackage->OverLapped.hEvent = NULL;
         }
      }

      //
      // Setup Allocated Buffer Size
      //
      pRxPackage->UserPacketData.nBufferSize = PACKET_BUFFER_SIZE;

      //
      // Add Handle To Array For Call To WaitForMultipleObjects
      // ------------------------------------------------------
      // This is used for the WaitForMultipleObject asynchronous I/O
      // method only...
      //
      if( i < MAXIMUM_WAIT_OBJECTS )
      {
         pAdapter->m_PackageHandles[ i ] = pRxPackage->OverLapped.hEvent;
      }

      ++pAdapter->m_nPackageCount;
   }

   return( pAdapter->m_nPackageCount );
}


/////////////////////////////////////////////////////////////////////////////
//// HP_IsValidReceivePackage
//
// Purpose
// Verify that the ReceivePackage is valid.
//
// Parameters
//   PReceivePackage pRxPackage - Pointer to the ReceivePackage to be
//      verified.
//
// Return Value
// Returns TRUE if the package is valid. Returns FALSE otherwise.
//
// Remarks
// Structured Exception Handling (SEH) is also used for debug builds.
// SEH is not used in release builds because HP_IsValidReceivePackage()
// can be called fairly often of the same package and the use of SEH
// could introduce a performance penalty.
//

BOOLEAN HP_IsValidReceivePackage( PReceivePackage pRxPackage )
{
   BOOLEAN  bResult = TRUE;

   //
   // Sanity Checks
   //
   if( !pRxPackage )
   {
      return( FALSE );
   }

   //
   // Test Signature
   // --------------
   // Use Structured Exception Handling (SEH) for _DEBUG builds.
   //
#ifdef _DEBUG
   __try
#endif
   {
      //
      // Check Receive Package Signature
      //
      if( pRxPackage->nSignature != RX_PACKAGE_SIGN )
      {
         bResult = FALSE;
      }
   }
#ifdef _DEBUG
   __except(EXCEPTION_EXECUTE_HANDLER)
   {
      //printf( "HP_IsValidReceivePackage: EXCEPTION!!!\n" );
      bResult = FALSE;
   }
#endif

   return( bResult );
}




