//
// PING.C -- Ping program using ICMP and RAW Sockets
//

#include <windows.h>

#include "icmp.h"
#include "globals.h"
#include "utility.h"

#define	MAX_WAIT	8000


// Internal Functions
int  WaitForEchoReply(SOCKET s);
u_short in_cksum(u_short *addr, int len);

// ICMP Echo Request/Reply functions
int		SendEchoRequest(SOCKET, LPSOCKADDR_IN);


// Ping()
// Calls SendEchoRequest() and
// RecvEchoReply() and fills pEchoParams
void Ping(PECHOPARAMS pEchoParams)
{
	SOCKET		rawSocket;
	struct		sockaddr_in saDest;
	DWORD		dwTimeSent;
	int			nRet;
	ECHOREPLY	echoReply;
	TIMECAPS	timecap;
	char		str[32];


	// Set dwElapsed time to 9999999 indicating an error condition
	pEchoParams->dwElapsed = 9999999;

	// Create a Raw socket
	rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (rawSocket == SOCKET_ERROR) {
		wsprintf(pEchoParams->error, "Error: Unable to create raw socket");
		return;
	}

	// Set the TTL in IP header
	if (setsockopt(rawSocket, IPPROTO_IP, IP_TTL, (const char*)&pEchoParams->ttl, sizeof(int)) == SOCKET_ERROR)
	{
		wsprintf(pEchoParams->error, "Error: Unable to set Time To Live in IP header");
		return;
	}
	
	// Setup destination socket address
	saDest.sin_addr.s_addr = pEchoParams->lAddr;
	saDest.sin_family = AF_INET;
	saDest.sin_port = htons(0);


	// Enter critical section because we do no want someone else
	// pinging at the same time 
	EnterCriticalSection(&g_csPing);

	// Send ICMP echo request
	SendEchoRequest(rawSocket, &saDest);

	// Set the timer resolution to the minimum possible
	timeGetDevCaps(&timecap, sizeof(TIMECAPS));
	timeBeginPeriod(timecap.wPeriodMin);

	wsprintf(str, "min=%d\r\n", timecap.wPeriodMin);
	debug(str);


	dwTimeSent = timeGetTime();
	
	// Receive reply
	while ((timeGetTime()-dwTimeSent) < MAX_WAIT)
	{
		// Use select() to wait for data to be received
		nRet = WaitForEchoReply(rawSocket);
		if (!nRet || (nRet == SOCKET_ERROR))
		{
			wsprintf(pEchoParams->error, "Error: Response from host timed out");
			break;
		}

		nRet = recvfrom(rawSocket, (LPSTR)&echoReply, sizeof(ECHOREPLY), 0,	0, 0);
		if ((echoReply.echoRequest.icmpHdr.Type == ICMP_TTL_EXPIRE) ||
			(echoReply.echoRequest.icmpHdr.Type == ICMP_ECHO_REPLY))
		{
			pEchoParams->dwElapsed = timeGetTime() - dwTimeSent;
			pEchoParams->replyFrom = echoReply.ipHdr.iaSrc;
			pEchoParams->icmpType = echoReply.echoRequest.icmpHdr.Type;
			break;
		}
	}

	timeEndPeriod(1);

	LeaveCriticalSection(&g_csPing);

	closesocket(rawSocket);
	
}



// SendEchoRequest()
// Fill in echo request header
// and send to destination
int SendEchoRequest(SOCKET s,LPSOCKADDR_IN lpstToAddr) 
{
	static ECHOREQUEST echoReq;
	//static UDPHDR	udphdr;
	static nId = 1;
	static nSeq = 1;
	int nRet;

	// Fill in udp header
	//udphdr.srcport = htons(64000);
	//udphdr.dstport = htons(64001);
	//udphdr.msglen  = 0;
	//udphdr.chksum = in_cksum((u_short *)&udphdr, sizeof(UDPHDR));


	// Fill in echo request
	echoReq.icmpHdr.Type		= ICMP_ECHO_REQUEST;
	echoReq.icmpHdr.Code		= 0;
	echoReq.icmpHdr.Checksum	= 0;
	echoReq.icmpHdr.ID			= (USHORT)GetCurrentProcessId();
	echoReq.icmpHdr.Seq			= nSeq++;

	// Fill in some data to send
	for (nRet = 0; nRet < REQ_DATASIZE; nRet++)
		echoReq.cData[nRet] = ' '+nRet;

	// Save tick count when sent
	echoReq.dwTime				= timeGetTime();

	// Put data in packet and compute checksum
	echoReq.icmpHdr.Checksum = in_cksum((u_short *)&echoReq, sizeof(ECHOREQUEST));

	// Send the echo request  								  
	nRet = sendto(s,						/* socket */
				 (LPSTR)&echoReq,			/* buffer */
				 sizeof(ECHOREQUEST),
				 0,							/* flags */
				 (LPSOCKADDR)lpstToAddr, /* destination */
				 sizeof(SOCKADDR_IN));   /* address length */


	// Send the udp request  								  
	//nRet = sendto(s,						/* socket */
	//			 (LPSTR)&udphdr,			/* buffer */
	//			 sizeof(UDPHDR),
	//			 0,							/* flags */
	//			 (LPSOCKADDR)lpstToAddr, /* destination */
	//			 sizeof(SOCKADDR_IN));   /* address length */

	return (nRet);
}



// WaitForEchoReply()
// Use select() to determine when
// data is waiting to be read
int WaitForEchoReply(SOCKET s)
{
	struct timeval Timeout;
	fd_set readfds;

	readfds.fd_count = 1;
	readfds.fd_array[0] = s;
	Timeout.tv_sec = 4;
    Timeout.tv_usec = 0;

	return(select(1, &readfds, NULL, NULL, &Timeout));
}


//
// Mike Muuss' in_cksum() function
// and his comments from the original
// ping program
//
// * Author -
// *	Mike Muuss
// *	U. S. Army Ballistic Research Laboratory
// *	December, 1983

/*
 *			I N _ C K S U M
 *
 * Checksum routine for Internet Protocol family headers (C Version)
 *
 */
u_short in_cksum(u_short *addr, int len)
{
	register int nleft = len;
	register u_short *w = addr;
	register u_short answer;
	register int sum = 0;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while( nleft > 1 )  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if( nleft == 1 ) {
		u_short	u = 0;

		*(u_char *)(&u) = *(u_char *)w ;
		sum += u;
	}

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}
