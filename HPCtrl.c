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
//         HookPeek Packet Adapter Control Common Routines - HPCtrl.c
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

/////////////////////////////////////////////////////////////////////////////
//// HP_DisableLoopback
//
// This module includes several adapter control and display routines which
// are used by all of the different variations of the HookPeek samples.
//


/////////////////////////////////////////////////////////////////////////////
//// HP_DisableLoopback
//
// Purpose
// Command the NDISHOOK driver to reject loopback packets.
//
// Parameters
//
// Return Value
// Returns TRUE if loopback was successfully disabled.
//
// Remarks
// Loopback packets are rejected by NDISHOOK by comparing the link source
// address against the adapter current. If the address is equal, the packet
// is rejected.
//

BOOLEAN HP_DisableLoopback( PHookAdapter pAdapter )
{
   BOOLEAN  bResult = FALSE;

   switch( pAdapter->m_nMedium )
   {
      case NdisMedium802_3:
      case NdisMediumDix:
         bResult = W32N_DisableLoopback(
                     pAdapter->m_hDevice,
                     MSrcAddr + 0,        // Offset Of Source Address Into Packet
                     ETHER_ADDR_LENGTH,   // Length Of Address
                     pAdapter->m_CurrentAddress    // Address Byte Bytes
                     );
         break;

      case NdisMedium802_5:
         bResult = W32N_DisableLoopback(
                     pAdapter->m_hDevice,
                     MSrcAddr + 2 + 0,    // Offset Of Source Address Into Packet
                     ETHER_ADDR_LENGTH,   // Length Of Address
                     pAdapter->m_CurrentAddress // Address Byte Bytes
                     );
         break;

      case NdisMediumLocalTalk:   // ATTENTION!!! Add This Case!!!
      case NdisMediumFddi:
      case NdisMediumWirelessWan:
      case NdisMediumArcnetRaw:
      case NdisMediumArcnet878_2:
      case NdisMediumAtm:
      case NdisMediumIrda:
      default:
         bResult = FALSE;
         break;
   }

   return( bResult );
}


/////////////////////////////////////////////////////////////////////////////
//// HP_SetPacketFilter
//
// Purpose
// Set the adapter driver's NDIS packet filter.
//
// Parameters
//
// Return Value
//
// Remarks
// Performs most of the mechanics of making the OID_GEN_CURRENT_PACKET_FILTER
// NDIS request.
//

BOOLEAN HP_SetPacketFilter( PHookAdapter pAdapter, ULONG nPacketFilter )
{
   W32N_REQUEST   W32N_Request;
   NDIS_STATUS    nNdisStatus;

   W32N_Request.NdisRequest.RequestType = NdisRequestSetInformation;

   W32N_Request.NdisRequest.DATA.SET_INFORMATION.Oid = OID_GEN_CURRENT_PACKET_FILTER;
   W32N_Request.NdisRequest.DATA.SET_INFORMATION.InformationBuffer = &nPacketFilter;
   W32N_Request.NdisRequest.DATA.SET_INFORMATION.InformationBufferLength = sizeof( ULONG );
   W32N_Request.NdisRequest.DATA.SET_INFORMATION.BytesRead = 0;
   W32N_Request.NdisRequest.DATA.SET_INFORMATION.BytesNeeded = 0;

   nNdisStatus = W32N_MakeNdisRequest(
                     pAdapter->m_hDevice,
                     &W32N_Request,
                     &pAdapter->m_OverLapped,
                     TRUE      // Synchronous
                     );

   if( nNdisStatus )
   {
      return( FALSE );
   }

   return( TRUE );
}


/////////////////////////////////////////////////////////////////////////////
//// HP_StartPromiscuousReception
//
// Purpose
// Start reception by placing the adapter into promiscuous mode.
//
// Parameters
//
// Return Value
//
// Remarks
// As written, this function places the MAC adapter driver into the
// PROMISCUOUS mode of operation.
//
//         NDIS_PACKET_TYPE_PROMISCUOUS
//
// This may not be desirable in all cases.
//
// For example, if you are developing a special purpose protocol, then
// it is likely that you should set the MAC adapter driver to deliver
// only DIRECTED packets; that is, packets which are addressed specifically
// to your adapter. If you do this, then the system does not have to do
// the extra work of passing unneeded packets to your application.
//
//         NDIS_PACKET_TYPE_DIRECTED
//
// In addition to directed packets, some protocols need to receive multicast
// packets. In that case, the filter should be set to include MULTICAST
// packets in addition to DIRECTED packets.
//
//         NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_MULTICAST
//
// If reception of multicast packets is needed by a protocol, then setting
// the MAC packet filter to NDIS_PACKET_TYPE_MULTICAST is not sufficient.
// In addition, you must specifically tell the MAC driver WHICH multicast
// addresses you wish to receive. To do this you must use the NdisRequestSetInformation
// to set the multicast list that you wish to receive. See the DDK for
// more information on how to do this.
//
// If you are implementing a protocol you may wish to disable the loopback
// mechanism. You may also wish to use the BPF mechanism to direct the
// NDISHOOK driver to perform some additional filtering for you at the
// driver.
//

BOOLEAN HP_StartPromiscuousReception( PHookAdapter pAdapter )
{
   BOOLEAN bResult = FALSE;

   pAdapter->m_nReceivedPacketCount = 0;

   pAdapter->m_nLastSequenceNo = 0;
   pAdapter->m_nSequenceErrorCount = 0;
   pAdapter->m_nSequenceErrorPlus = 0;
   pAdapter->m_nSequenceErrorMinus = 0;

   pAdapter->m_nSendPacketCount = 0;
   pAdapter->m_nPendingSendAPCCount = 0;

   pAdapter->m_nProtocolFramesRcvGood = 0;
   pAdapter->m_nRcvMissed_KernelResource = 0;
   pAdapter->m_nRcvMissed_UserResource = 0;

   pAdapter->m_nProtocolFramesXmitGood = 0;
   pAdapter->m_nXmitMissed_KernelResource = 0;

   switch( pAdapter->m_nMedium )
   {
      case NdisMedium802_3:   // Ethernet
      case NdisMediumDix:      // Also Ethernet
         bResult = HP_SetPacketFilter(
                     pAdapter,
                     NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_PROMISCUOUS
                     );
         break;

      case NdisMedium802_5:   // TokenRing
         bResult = HP_SetPacketFilter(
                     pAdapter,
                     NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_PROMISCUOUS
                     );

         // Some TokenRing Adapters Don't Support Promiscuous Operation
         if( !bResult )
         {
            bResult = HP_SetPacketFilter(
                        pAdapter,
                        NDIS_PACKET_TYPE_ALL_LOCAL
                        );

            if( !bResult )
            {
               bResult = HP_SetPacketFilter(
                           pAdapter,
                           NDIS_PACKET_TYPE_DIRECTED
                           );
            }
         }
         break;

      case NdisMediumLocalTalk:
         bResult = HP_SetPacketFilter(
                     pAdapter,
                     NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_BROADCAST
                     );
         break;

      case NdisMediumFddi:
      case NdisMediumWirelessWan:
      case NdisMediumArcnetRaw:
      case NdisMediumArcnet878_2:
      case NdisMediumAtm:
      case NdisMediumIrda:
      default:
         bResult = FALSE;
         break;
   }

   return( bResult );
}


/////////////////////////////////////////////////////////////////////////////
//// HP_StopReception
//
// Purpose
// Stop reception by setting the adapter's NDIS packet filter to 0.
//
// Parameters
//
// Return Value
//
// Remarks
//

BOOLEAN HP_StopReception( PHookAdapter pAdapter )
{
   return( HP_SetPacketFilter( pAdapter, 0 ) );
}


/////////////////////////////////////////////////////////////////////////////
//// HP_UpdateAdapterDescription
//
// Purpose
// Query the adapter for it's vendor description string.
//
// Parameters
//
// Return Value
// Returns TRUE is the vendor description string is determined; description
// string saved in the p_Adapter structure in the m_szAdapterDriverDescription
// member variable.
//
// Remarks
//

BOOLEAN HP_UpdateAdapterDescription( PHookAdapter pAdapter )
{
   W32N_REQUEST   W32N_Request;
   NDIS_STATUS      nNdisStatus;

   // NELSON
   // strcpy( pAdapter->m_szAdapterDriverDescription, "Unknown" );
   strcpy_s( pAdapter->m_szAdapterDriverDescription, sizeof(pAdapter->m_szAdapterDriverDescription), "Unknown" );

   W32N_Request.NdisRequest.RequestType = NdisRequestQueryInformation;

   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.Oid = OID_GEN_VENDOR_DESCRIPTION;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBuffer = pAdapter->m_szAdapterDriverDescription;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBufferLength = sizeof( pAdapter->m_szAdapterDriverDescription );
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesWritten = 0;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesNeeded = 0;

   nNdisStatus = W32N_MakeNdisRequest(
                     pAdapter->m_hDevice,
                     &W32N_Request,
                     &pAdapter->m_OverLapped,
                     TRUE               // Synchronous
                     );

   return( TRUE );
}


/////////////////////////////////////////////////////////////////////////////
//// HP_UpdateAdapterMedium
//
// Purpose
// Query the adapter for it's NDIS medium.
//
// Parameters
//
// Return Value
// Returns TRUE is the medium is determined; medium saved in the
// p_Adapter structure in the m_nMedium member variable.
//
// Remarks
//

BOOLEAN HP_UpdateAdapterMedium( PHookAdapter pAdapter )
{
   W32N_REQUEST   W32N_Request;
   NDIS_STATUS      nNdisStatus;

   //
   // Get Media In Use
   //
   pAdapter->m_nMedium = -1;         // Invalidate

   W32N_Request.NdisRequest.RequestType = NdisRequestQueryInformation;

   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.Oid = OID_GEN_MEDIA_IN_USE;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBuffer = &pAdapter->m_nMedium;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBufferLength = sizeof( pAdapter->m_nMedium );
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesWritten = 0;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesNeeded = 0;

   nNdisStatus = W32N_MakeNdisRequest(
               pAdapter->m_hDevice,
               &W32N_Request,
               &pAdapter->m_OverLapped,
               TRUE               // Synchronous
               );

   if( nNdisStatus )
   {
      return( FALSE );
   }

   return( TRUE );
}

BOOLEAN HP_UpdateAdapterLinkSpeed( PHookAdapter pAdapter )
{
   W32N_REQUEST   W32N_Request;
   NDIS_STATUS      nNdisStatus;

   //
   // Get Media In Use
   //
   pAdapter->m_nLinkSpeed = -1;         // Invalidate

   W32N_Request.NdisRequest.RequestType = NdisRequestQueryInformation;

   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.Oid = OID_GEN_LINK_SPEED;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBuffer = &pAdapter->m_nLinkSpeed;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBufferLength = sizeof( pAdapter->m_nLinkSpeed );
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesWritten = 0;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesNeeded = 0;

   nNdisStatus = W32N_MakeNdisRequest(
               pAdapter->m_hDevice,
               &W32N_Request,
               &pAdapter->m_OverLapped,
               TRUE               // Synchronous
               );

   if( nNdisStatus )
   {
      return( FALSE );
   }

   return( TRUE );
}



BOOLEAN HP_UpdateAdapterMaxFrameSize( PHookAdapter pAdapter )
{
   W32N_REQUEST   W32N_Request;
   NDIS_STATUS      nNdisStatus;

   //
   // Get Media In Use
   //
   pAdapter->m_nMaxFrameSize = -1;         // Invalidate

   W32N_Request.NdisRequest.RequestType = NdisRequestQueryInformation;

   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.Oid = OID_GEN_MAXIMUM_FRAME_SIZE;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBuffer = &pAdapter->m_nMaxFrameSize;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBufferLength = sizeof( pAdapter->m_nMaxFrameSize );
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesWritten = 0;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesNeeded = 0;

   nNdisStatus = W32N_MakeNdisRequest(
               pAdapter->m_hDevice,
               &W32N_Request,
               &pAdapter->m_OverLapped,
               TRUE               // Synchronous
               );

   if( nNdisStatus )
   {
      return( FALSE );
   }

   return( TRUE );
}



/////////////////////////////////////////////////////////////////////////////
//// HP_UpdateAdapterCurrentAddress
//
// Purpose
// Query the adapter for it's current link address.
//
// Parameters
//
// Return Value
// Returns TRUE is the current link address is determined; address saved
// p_Adapter structure in the m_CurrentAddress member variable.
//
// Remarks
// This is a medium-specific call. It needs refinement to work with non-
// Ethernet mediums...
//

BOOLEAN HP_UpdateAdapterCurrentAddress( PHookAdapter pAdapter )
{
   W32N_REQUEST   W32N_Request;
   NDIS_STATUS      nNdisStatus;

	W32N_Request.NdisRequest.RequestType = NdisRequestQueryInformation;


	W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBuffer = pAdapter->m_CurrentAddress;
	W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBufferLength = 32;
	W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesWritten = 0;
	W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesNeeded = 0;

	switch( pAdapter->m_nMedium )
	{
		case NdisMedium802_3:
		case NdisMediumDix:
			W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.Oid = OID_802_3_CURRENT_ADDRESS;
            break;

		case NdisMedium802_5:
            W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.Oid = OID_802_5_CURRENT_ADDRESS;
            break;

		case NdisMediumFddi:
            W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.Oid = OID_FDDI_LONG_CURRENT_ADDR;
            break;

		case NdisMediumWan:
            W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.Oid = OID_WAN_CURRENT_ADDRESS;
            break;

		case NdisMediumWirelessWan:
            W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.Oid = OID_WW_GEN_CURRENT_ADDRESS;
            break;

		case NdisMediumLocalTalk:
            W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.Oid = OID_LTALK_CURRENT_NODE_ID;
            break;

		case NdisMediumArcnetRaw:
		case NdisMediumArcnet878_2:
            W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.Oid = OID_ARCNET_CURRENT_ADDRESS;
            break;

		case NdisMediumAtm:
            W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.Oid = OID_ATM_HW_CURRENT_ADDRESS;
            break;

		case NdisMediumIrda:
		default:
            break;
      }

      nNdisStatus = W32N_MakeNdisRequest(
                     pAdapter->m_hDevice,
                     &W32N_Request,
                     &pAdapter->m_OverLapped,
                     TRUE               // Synchronous
                     );

      if( nNdisStatus )
      {
         return( FALSE );
      }

      pAdapter->m_bCurrentAddressValid = TRUE;
		
	  return( pAdapter->m_bCurrentAddressValid );
}


/////////////////////////////////////////////////////////////////////////////
//// HP_GetProtocolStatistics
//
// Purpose
//
// Parameters
//
// Return Value
//
// Remarks
//

BOOLEAN HP_GetProtocolStatistics( PHookAdapter pAdapter )
{
   W32N_REQUEST   W32N_Request;
   NDIS_STATUS    nNdisStatus;

   //
   // m_nRcvMissed_KernelResource - Receive Error Due Lack Of Kernel Resource
   // -----------------------------------------------------------------------
   // Value maintained by the NDISHOOK protocol driver. Count of packets
   // that the driver received but was not able to pass up to the Win32
   // application because some kernel resource (typically a NDIS_PACKET or
   // NDIS_BUFFER) was not available.
   //
   W32N_Request.NdisRequest.RequestType = NdisRequestQueryInformation;

   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.Oid = OID_PCANDIS_RCV_ERROR_KERNEL_RESOURCE;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBuffer = &pAdapter->m_nRcvMissed_KernelResource;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBufferLength = sizeof( pAdapter->m_nRcvMissed_KernelResource );
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesWritten = 0;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesNeeded = 0;

   nNdisStatus = W32N_MakePrivateRequest(
                     pAdapter->m_hDevice,
                     &W32N_Request,
                     &pAdapter->m_OverLapped,
                     TRUE               // Synchronous
                     );

   if( nNdisStatus )
   {
      pAdapter->m_nRcvMissed_KernelResource = 0xFFFFFFFFL;
   }

   //
   // m_nRcvMissed_UserResource - Receive Error Due Lack Of User Resource
   // -------------------------------------------------------------------
   // Value maintained by the NDISHOOK protocol driver. Count of packets
   // that the driver received but was not able to pass up to the Win32
   // application because no W32N_PACKET was available to be filled.
   //
   W32N_Request.NdisRequest.RequestType = NdisRequestQueryInformation;

   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.Oid = OID_PCANDIS_RCV_ERROR_USER_RESOURCE;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBuffer = &pAdapter->m_nRcvMissed_UserResource;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBufferLength = sizeof( pAdapter->m_nRcvMissed_UserResource );
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesWritten = 0;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesNeeded = 0;

   nNdisStatus = W32N_MakePrivateRequest(
                     pAdapter->m_hDevice,
                     &W32N_Request,
                     &pAdapter->m_OverLapped,
                     TRUE               // Synchronous
                     );

   if( nNdisStatus )
   {
      pAdapter->m_nRcvMissed_UserResource = 0xFFFFFFFFL;
   }

   //
   // m_nProtocolFramesRcvGood - Receive OK Count
   // -------------------------------------------
   // Value maintained by the NDISHOOK protocol driver. Count of packets
   // that the driver believes that it received and passed up to the Win32
   // application.
   //
   W32N_Request.NdisRequest.RequestType = NdisRequestQueryInformation;

   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.Oid = OID_GEN_RCV_OK;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBuffer = &pAdapter->m_nProtocolFramesRcvGood;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBufferLength = sizeof( pAdapter->m_nProtocolFramesRcvGood );
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesWritten = 0;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesNeeded = 0;

   nNdisStatus = W32N_MakePrivateRequest(
                     pAdapter->m_hDevice,
                     &W32N_Request,
                     &pAdapter->m_OverLapped,
                     TRUE               // Synchronous
                     );

   if( nNdisStatus )
   {
      pAdapter->m_nProtocolFramesRcvGood = 0xFFFFFFFFL;
   }

   //
   // m_nXmitMissed_KernelResource - Send Error Due Lack Of Kernel Resource
   // ---------------------------------------------------------------------
   // Value maintained by the NDISHOOK protocol driver. Count of packets
   // that the driver was commanded to send but was not able to pass to
   // the lower-level MAC driver because some kernel resource (typically a
   // NDIS_PACKET or NDIS_BUFFER) was not available.
   //
   W32N_Request.NdisRequest.RequestType = NdisRequestQueryInformation;

   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.Oid = OID_PCANDIS_XMIT_ERROR_KERNEL_RESOURCE;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBuffer = &pAdapter->m_nXmitMissed_KernelResource;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBufferLength = sizeof( pAdapter->m_nXmitMissed_KernelResource );
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesWritten = 0;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesNeeded = 0;

   nNdisStatus = W32N_MakePrivateRequest(
                     pAdapter->m_hDevice,
                     &W32N_Request,
                     &pAdapter->m_OverLapped,
                     TRUE               // Synchronous
                     );

   if( nNdisStatus )
   {
      pAdapter->m_nXmitMissed_KernelResource = 0xFFFFFFFFL;
   }

   //
   // m_nProtocolFramesXmitGood - Send OK Count
   // -----------------------------------------
   // Value maintained by the NDISHOOK protocol driver. Count of packets
   // that the driver believes that it successfully sent.
   //
   W32N_Request.NdisRequest.RequestType = NdisRequestQueryInformation;

   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.Oid = OID_GEN_XMIT_OK;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBuffer = &pAdapter->m_nProtocolFramesXmitGood;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBufferLength = sizeof( pAdapter->m_nProtocolFramesXmitGood );
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesWritten = 0;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesNeeded = 0;

   nNdisStatus = W32N_MakePrivateRequest(
                     pAdapter->m_hDevice,
                     &W32N_Request,
                     &pAdapter->m_OverLapped,
                     TRUE               // Synchronous
                     );

   if( nNdisStatus )
   {
      pAdapter->m_nProtocolFramesXmitGood = 0xFFFFFFFFL;
   }

   //
   // m_szProtocolDriverDescription - Protocol Driver Vendor Description
   // ------------------------------------------------------------------
   //
//   sprintf( pAdapter->m_szProtocolDriverDescription, "Unknown" );

   W32N_Request.NdisRequest.RequestType = NdisRequestQueryInformation;

   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.Oid = OID_GEN_VENDOR_DESCRIPTION;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBuffer = pAdapter->m_szProtocolDriverDescription;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.InformationBufferLength = sizeof( pAdapter->m_szProtocolDriverDescription );
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesWritten = 0;
   W32N_Request.NdisRequest.DATA.QUERY_INFORMATION.BytesNeeded = 0;

   nNdisStatus = W32N_MakePrivateRequest(
                     pAdapter->m_hDevice,
                     &W32N_Request,
                     &pAdapter->m_OverLapped,
                     TRUE               // Synchronous
                     );

   if( nNdisStatus )
   {
      //sprintf( pAdapter->m_szProtocolDriverDescription, "Unknown" );
   }

   return( TRUE );
}
