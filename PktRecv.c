#include <windows.h>
#include <commctrl.h>

#include "common.h"
#include "structs.h"
#include "globals.h"
#include "utility.h"
#include "rules.h"
#include "logging.h"


VOID GetPacketInfo(unsigned short ptype, unsigned char *szBuffer, int size_framehdr, 
				   char *src, char *dst, char *type, char *info);
BOOL MatchIpFields(RuleNode *, unsigned char *szBuffer);
BOOL MatchIcmpFields(RuleNode *, unsigned char *szBuffer);
BOOL MatchUdpFields(RuleNode *, unsigned char *szBuffer);
BOOL MatchTcpFields(RuleNode *, unsigned char *szBuffer);
int MatchContent(char *, int, char *, int);


char	*ICMP_type[] = { "echo reply",
						"",
						"",
						"destination unreachable",
						"source quench",
						"redirect",
						"alternate host address",
						"",
						"echo request",
						"router advertisement",
						"router selection",
						"time exceeded",
						"parameter problem",
						"timestamp request",
						"timestamp reply",
						"information request",
						"information reply"
};



VOID AddToARP(HWND hWndList, char *ip, char *ha)
{
	int				index, num, count;
	LV_ITEM			lvI;
	char			str[64];
	BOOL			bConflict;


	lvI.iImage = 1;
	lvI.iSubItem = 0;
	bConflict = FALSE;

	num = ListView_GetItemCount(hWndList);

	for (index = 0; index < num; index++)
	{
		ListView_GetItemText(hWndList, index, 2, str, 64);
		if (lstrcmp(str, ip) == 0)
		{
			ListView_GetItemText(hWndList, index, 1, str, 64);
			if (lstrcmp(str, ha) == 0)
			{
				ListView_GetItemText(hWndList, index, 0, str, 64);
				count = atoi(str);
				wsprintf(str, "%d", ++count);
				ListView_SetItemText( hWndList, index, 0, str);
				return;
			}
			//else
			//{
			//	lvI.iImage = 3;
			//	lvI.mask = LVIF_IMAGE;
			//	lvI.iItem = index;
			//	ListView_SetItem(hWndList, &lvI);
			//	bConflict = TRUE;
			//}
		}
	}

	lvI.mask = LVIF_TEXT;// | LVIF_IMAGE ;
	lvI.iItem = ListView_GetItemCount(hWndList);
	lvI.pszText = ""; 
	lvI.cchTextMax = 64;

	index = ListView_InsertItem(hWndList, &lvI);
	ListView_SetItemText( hWndList, index, 2, ip);
	ListView_SetItemText( hWndList, index, 1, ha);
	ListView_SetItemText( hWndList, index, 0, "1");
	
	//if (bConflict)
	//{
	//	SendMessage(hWndStatus, SB_SETTEXT, (WPARAM) 1, (LPARAM) "ALERT: IP Conflict Detected!");
	//	MessageBeep(MB_ICONEXCLAMATION);
	//}

	return;
}




VOID AddToAlert(SYSTEMTIME rTime, unsigned char *buffer, int numbytes, char *col1, char *col2, char *col3, char *col4, char *col5, char *col6)
{
	int				position;
	LV_ITEM			lvI;
	char			str[64];
	struct packet	*pkt;


	++count;
	bytes_used += numbytes;
	wsprintf(str, "%d packets / %d bytes decoded", count, bytes_used);
	SendMessage(hWndStatus, SB_SETTEXT, (WPARAM) 2, (LPARAM) str);

	wsprintf(str, "%.2d:%.2d:%.2d:%.3d", rTime.wHour, rTime.wMinute, rTime.wSecond, rTime.wMilliseconds);

	lvI.mask = LVIF_TEXT | LVIF_PARAM;
	position = ListView_GetItemCount(hWndAlertList);

	lvI.iItem = position;
	lvI.iSubItem = 0;
	lvI.pszText = str; 
	lvI.cchTextMax = 64;

	pkt = malloc(sizeof(struct packet));
	pkt->size = numbytes;
	pkt->data = malloc(numbytes);
	memcpy(pkt->data, buffer, numbytes);
	pkt->time = rTime;
	lvI.lParam = (LPARAM)pkt;

	position = ListView_InsertItem(hWndAlertList, &lvI);
	ListView_SetItemText( hWndAlertList, position, 1, col1);
	ListView_SetItemText( hWndAlertList, position, 2, col2);
	ListView_SetItemText( hWndAlertList, position, 3, col3);
	ListView_SetItemText( hWndAlertList, position, 4, col4);
	ListView_SetItemText( hWndAlertList, position, 5, col5);
	ListView_SetItemText( hWndAlertList, position, 6, col6);
	ListView_EnsureVisible(hWndAlertList, position, FALSE);

	
	if (count > 65000)
	{
		g_bShutdown = TRUE;
		//MessageBox(hWndMain, "Maximum packet count reached. Capture stopped.", APP_NAME, MB_OK | MB_ICONEXCLAMATION);
	}
	return;
}


	
VOID ProcessPacket(SYSTEMTIME rTime, unsigned char *szBuffer, int size, BOOL bFilter)
{
	struct ethernet_802_3	*eth;
	struct iphdr			*ip;
	struct arppkt			*arp;

	int			size_iphdr, size_framehdr, index;
	RuleNode	*alert_node, *log_node, *counter_node;
	BOOL		bMatch = FALSE;

	char			src[32], dst[32], type[64];
	char			info[64], str[128], msg[128], numbytes[12];
	unsigned short  ptype;



	if (size < 42)	// probably a corrupt packet
		return;

	size_framehdr = 14;
	src[0] = '\0'; dst[0] = '\0'; info[0] = '\0'; msg[0] = '\0';

	wsprintf(numbytes, "%d", size);
	wsprintf(type, "Unknown");

	eth = (struct ethernet_802_3 *) szBuffer;

	if (ntohs(eth->length) > 0x05DC)	// its an ethernet_II frame
	{
		ptype = eth->length;	/* length actually is type since its an eth_II frame */
		size_framehdr = 14;
	}
	else							// its an 802.3 frame
	{
		ptype = eth->type;
		size_framehdr = 22;
	}
	ptype = ntohs(ptype);


	/* if rules are NOT to be used, show all captured packets */
	if (bFilter == FALSE)
	{
		GetPacketInfo(ptype, szBuffer, size_framehdr, src, dst, type, info);
		AddToAlert(rTime, szBuffer, size, src, dst, numbytes, type, info, "");
		return;
	}


	if (ptype == 0x0800)
	{
		ip = (struct iphdr *) &szBuffer[size_framehdr];
		size_iphdr = (ip->verlen & 0x0f) * 4;

		switch (ip->prot)
		{
		case R_ICMP:
			alert_node = root.alert.IcmpList;
			log_node = root.log.IcmpList;
			counter_node = root.counter.IcmpList;
			break;

		case R_UDP:
			alert_node = root.alert.UdpList;
			log_node = root.log.UdpList;
			counter_node = root.counter.UdpList;
			break;

		case R_TCP:
			alert_node = root.alert.TcpList;
			log_node = root.log.TcpList;
			counter_node = root.counter.TcpList;
			break;

		default:
			return;
		}

		/*  check for match in the alert chain  */
		while (alert_node != NULL)
		{
			debug("checking alert node\r\n");
			bMatch = MatchIpFields(alert_node, &szBuffer[size_framehdr]);
				if (bMatch)  debug("ip header matches\r\n");
			
			if (bMatch && alert_node->content_set) 
				bMatch = MatchContent(&szBuffer[size_iphdr], 
									  size-size_iphdr, 
									  alert_node->content, 
									  lstrlen(alert_node->content));

			if (bMatch)  
			{
				GetPacketInfo(ptype, szBuffer, size_framehdr, src, dst, type, info);
				AddToAlert(rTime, szBuffer, size, src, dst, numbytes, type, info, alert_node->msg);
				break;
			}
			
			alert_node = alert_node->next;
		}

		/*  check for match in the log chain  */
		while (log_node != NULL)
		{
			bMatch = MatchIpFields(log_node, &szBuffer[size_framehdr]);
		
			if (bMatch && log_node->content_set) 
				bMatch = MatchContent(&szBuffer[size_iphdr], 
									  size-size_iphdr, 
									  log_node->content, 
									  lstrlen(log_node->content));

			if (bMatch)  
			{
				AddToLog(rTime, szBuffer, size, log_node->msg);
				break;
			}
			
			log_node = log_node->next;
		}


		/*  check for all matches in the counter chain  */
		while (counter_node != NULL)
		{
			bMatch = MatchIpFields(counter_node, &szBuffer[size_framehdr]);
			
			if (bMatch && counter_node->content_set) 
				bMatch = MatchContent(&szBuffer[size_iphdr], 
									  size-size_iphdr, 
									  counter_node->content, 
									  lstrlen(counter_node->content));

			if (bMatch && counter_node->counter_id_set) 
			{
				index = counter_node->counter_id;
				counter[index].count += 1;
				counter[index].bytes += size;

				wsprintf(str, "%d", counter[index].count);
				ListView_SetItemText(hWndCounterList, index, 2, str);
				
				FormatByteValue(counter[index].bytes, str);	
				ListView_SetItemText(hWndCounterList, index, 3, str);
			}
			
			counter_node = counter_node->next;
		}
	}

	 /* SPECIAL HANDLING FOR ARP PACKETS */
	else if (ptype == 0x0806) 
	{
		alert_node = root.alert.ArpList;
		if (alert_node != NULL) 
		{
			GetPacketInfo(ptype, szBuffer, size_framehdr, src, dst, type, info);
			AddToAlert(rTime, szBuffer, size, src, dst, numbytes, type, info, alert_node->msg);
		}

		log_node = root.log.ArpList;
		if (log_node != NULL) 
		{
			AddToLog(rTime, szBuffer, size, log_node->msg);
		}


		/* increment counter while here */
		alert_node = root.counter.ArpList;
		if ((alert_node != NULL) && alert_node->counter_id_set) 
		{
			index = alert_node->counter_id;
			counter[index].count += 1;
			counter[index].bytes += size;

			wsprintf(str, "%d", counter[index].count);
			ListView_SetItemText(hWndCounterList, index, 2, str);
			FormatByteValue(counter[index].bytes, str);	
			ListView_SetItemText(hWndCounterList, index, 3, str);
		}

		arp = (struct arppkt *) &szBuffer[size_framehdr];
		wsprintf(dst, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", arp->sender_ha[0], arp->sender_ha[1],arp->sender_ha[2],arp->sender_ha[3],arp->sender_ha[4],arp->sender_ha[5]); 
		wsprintf(src, "%d.%d.%d.%d", arp->sender_ip[0], arp->sender_ip[1], arp->sender_ip[2], arp->sender_ip[3]); 
		AddToARP(hWndARPList, src, dst);

	}

}

	


BOOL MatchIpFields(RuleNode *node, unsigned char *szBuffer)
{
	BOOL bMatch = FALSE;
	struct iphdr	*ip;
	int size_iphdr;

	ip = (struct iphdr *) szBuffer;
	size_iphdr = (ip->verlen & 0x0f) * 4;

	
	bMatch = (node->sip & node->smask) == (ip->sourceip & node->smask);
	if (node->sip_op == '!')  bMatch = !bMatch;
	
	if (bMatch)
	{
		bMatch = (node->dip & node->dmask) == (ip->destip & node->dmask);
		if (node->dip_op == '!')  bMatch = !bMatch;
	}
	
	if ((bMatch == FALSE) && (node->dir == BI_DIR))
	{
		bMatch = (node->sip & node->smask) == (ip->destip & node->smask);
		if (node->sip_op == '!')  bMatch = !bMatch;
		
		if (bMatch)
		{
			bMatch = (node->dip & node->dmask) == (ip->sourceip & node->dmask);
			if (node->dip_op == '!')  bMatch = !bMatch;
		}
	}


	/*
	if (((node->sip & node->smask) == (ip->sourceip & node->smask))  &&
		((node->dip & node->dmask) == (ip->destip   & node->dmask)))
			bMatch = TRUE;
						
	if ((bMatch == FALSE) && (node->dir == BI_DIR))
		if (((node->sip & node->smask) == (ip->destip   & node->smask))  &&
			((node->dip & node->dmask) == (ip->sourceip & node->dmask)))
			bMatch = TRUE;
	*/				
	if (!bMatch)											return FALSE;
	if (node->ttl_set && (node->ttl != ip->ttl))			return FALSE;
	if (node->tos_set && (node->tos != ip->tos))			return FALSE;
	if (node->id_set  && (node->id  != ip->id))				return FALSE;
	if (node->ipopts_set)									return FALSE;	// Huh?
	if (node->fragbits_set && (node->fragbits != ip->frag)) return FALSE;	// ADD op 
	if (node->dsize_set && (node->dsize == ip->verlen))		return FALSE;  // TO BE FIXED


	if (ip->prot == R_ICMP)
		if (!MatchIcmpFields(node, &szBuffer[size_iphdr]))
			return FALSE;

	if (ip->prot == R_UDP)
		if (!MatchUdpFields(node, &szBuffer[size_iphdr]))	
			return FALSE;
		
	if (ip->prot == R_TCP)
		if (!MatchTcpFields(node, &szBuffer[size_iphdr]))
			return FALSE;

	return TRUE;
}


BOOL MatchIcmpFields(RuleNode *node, unsigned char *szBuffer)
{
	struct icmphdr *icmp;

	icmp = (struct icmphdr *) szBuffer;

	if (node->itype_set && (node->itype != icmp->type))			return FALSE;
	if (node->icode_set && (node->icode != icmp->code))			return FALSE;
	if (node->icmp_id_set  && (node->icmp_id  != icmp->id))		return FALSE;
	if (node->icmp_seq_set && (node->icmp_seq != icmp->seqno))	return FALSE;	// Huh?

	return TRUE;
}


BOOL MatchUdpFields(RuleNode *node, unsigned char *szBuffer)
{
	struct udphdr *udp;

	udp = (struct udphdr *) szBuffer;

	if ((node->lsp <= udp->srcport) && 
		(node->hsp >= udp->srcport) &&
		(node->ldp <= udp->dstport) &&
		(node->hdp >= udp->dstport))
		return TRUE;

	if (node->dir == BI_DIR)
	{
		if ((node->lsp <= udp->dstport) && 
			(node->hsp >= udp->dstport) &&
			(node->ldp <= udp->srcport) &&
			(node->hdp >= udp->srcport))
			return TRUE;
	}

	return FALSE;
}


BOOL MatchTcpFields(RuleNode *node, unsigned char *szBuffer)
{
	struct tcphdr *tcp;

	tcp = (struct tcphdr *) szBuffer;

	if (node->flags_set && (node->flags != tcp->flags))		return FALSE;
	if (node->seqnum_set && (node->seqnum != tcp->seqno))	return FALSE;
	if (node->acknum_set && (node->acknum != tcp->ackno))	return FALSE;

	if ((node->lsp <= tcp->srcport) && 
		(node->hsp >= tcp->srcport) &&
		(node->ldp <= tcp->dstport) &&
		(node->hdp >= tcp->dstport))
		return TRUE;

	if (node->dir == BI_DIR)
	{
		if ((node->lsp <= tcp->dstport) && 
			(node->hsp >= tcp->dstport) &&
			(node->ldp <= tcp->srcport) &&
			(node->hdp >= tcp->srcport))
			return TRUE;
	}

	return FALSE;
}




VOID GetPacketInfo(unsigned short ptype, unsigned char *szBuffer, int size_framehdr, 
				   char *src, char *dst, char *type, char *info)
{
	int				size_iphdr; 
	unsigned short  src_port, dst_port;
	char			*service;

	struct ethernet_802_3	*eth;
	struct iphdr	*ip;
	struct udphdr	*udp;
	struct icmphdr	*icmp;
	struct tcphdr	*tcp;
	struct arppkt	*arp;


	if (ptype == 0x0800)	//'tis IP packet
	{
		ip = (struct iphdr *) &szBuffer[size_framehdr];
		size_iphdr = (ip->verlen & 0x0f) * 4;

		lstrcpy(src, IpToString(ip->sourceip));
		lstrcpy(dst, IpToString(ip->destip));

		if (ip->prot == R_UDP) 
		{
			udp = (struct udphdr *) &szBuffer[size_framehdr + size_iphdr];	
			lstrcpy(type, "udp");
			
			src_port = ntohs(udp->srcport);
			dst_port = ntohs(udp->dstport);

			if (service = find_in_table(src_port, 0))		lstrcpy(info, service);
			else if (service = find_in_table(dst_port, 0))	lstrcpy(info, service);
			else			wsprintf(info, "port: %d --> %d", src_port, dst_port);
		}
		else if (ip->prot == R_ICMP) {
			lstrcpy(type, "icmp");
			icmp = (struct icmphdr *) &szBuffer[size_framehdr + size_iphdr];
			if (icmp->type <= 16)	lstrcpy(info, ICMP_type[icmp->type]);

		}
		else if (ip->prot == R_TCP)	
		{
			lstrcpy(type, "tcp");
			tcp = (struct tcphdr *) &szBuffer[size_framehdr + size_iphdr];

			src_port = ntohs(tcp->srcport);
			dst_port = ntohs(tcp->dstport);

			if (service = find_in_table(src_port, 1))		lstrcpy(info, service);
			else if (service = find_in_table(dst_port, 1))	lstrcpy(info, service);
			else			wsprintf(info, "port: %d --> %d", src_port, dst_port);

		}
		else if (ip->prot == R_IGMP)
		{
			lstrcpy(type, "igmp");
		}
		else
			return;			
	}	
	else if (ptype == 0x0806)	// ARP
	{	
		arp = (struct arppkt *) &szBuffer[size_framehdr];
		wsprintf(src, "%d.%d.%d.%d", arp->sender_ip[0], arp->sender_ip[1],arp->sender_ip[2],arp->sender_ip[3]);
		if (ntohs(arp->operation) == 1)
		{
			wsprintf(type, "arp req.");
			wsprintf(dst, "Broadcast");
			wsprintf(info, "%d.%d.%d.%d = ?", arp->target_ip[0], arp->target_ip[1],arp->target_ip[2],arp->target_ip[3]);
		}
		else if (ntohs(arp->operation) == 2)
		{
			wsprintf(type, "arp resp.");
			wsprintf(dst, "%d.%d.%d.%d", arp->target_ip[0], arp->target_ip[1],arp->target_ip[2],arp->target_ip[3]);
			wsprintf(info, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", arp->sender_ha[0], arp->sender_ha[1],arp->sender_ha[2],arp->sender_ha[3],arp->sender_ha[4],arp->sender_ha[5]);
		}
	}
	else if (ptype == 0x8035)	// RARP
	{
		arp = (struct arppkt *) &szBuffer[size_framehdr];
		wsprintf(src, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X = ?", arp->sender_ha[0], arp->sender_ha[1],arp->sender_ha[2],arp->sender_ha[3],arp->sender_ha[4],arp->sender_ha[5]);
		if (ntohs(arp->operation) == 3)
		{
			wsprintf(type, "rarp req.");
			wsprintf(dst, "Broadcast");
			wsprintf(info, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X = ?", arp->sender_ha[0], arp->sender_ha[1],arp->sender_ha[2],arp->sender_ha[3],arp->sender_ha[4],arp->sender_ha[5]);
		}
		else if (ntohs(arp->operation) == 4)
		{
			wsprintf(type, "rarp resp.");
			wsprintf(dst, "%d.%d.%d.%d", arp->target_ip[0], arp->target_ip[1],arp->target_ip[2],arp->target_ip[3]);
			wsprintf(info, "%d.%d.%d.%d", arp->target_ip[0], arp->target_ip[1],arp->target_ip[2],arp->target_ip[3]);
		}

	}
	else // unknown type of packet
	{
		eth = (struct ethernet_802_3 *) szBuffer;

		wsprintf(src, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", szBuffer[6], szBuffer[7], szBuffer[8], szBuffer[9], szBuffer[10], szBuffer[11]);
		wsprintf(dst, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", szBuffer[0], szBuffer[1], szBuffer[2], szBuffer[3], szBuffer[4], szBuffer[5]);
		
		if (size_framehdr == 14)
		{
			wsprintf(type, "ethernet_II frame");
			wsprintf(info, "type = 0x%.4x%", ptype);
		}
		else if ((eth->dsap == 0xf0) && (eth->ssap == 0xf0))
		{
			wsprintf(type, "netbeui");
			wsprintf(info, "type = 0x%.4x", ptype);
		}
		else if ((eth->dsap == 0xff) && (eth->ssap == 0xff))
		{
			wsprintf(type, "ipx");
			lstrcpy(info, "novell");
		}
		else 
		{
			wsprintf(type, "802.3 frame");
			wsprintf(info, "type = 0x%.4x", ptype);
		}
	}	
}




/****************************************************************
 *
 *  Function: mContainsSubstr(char *, int, char *, int)
 *
 *  Purpose: Determines if a string contains a (non-regex)
 *           substring.
 *
 *  Parameters:
 *      buf => data buffer we want to find the data in
 *      b_len => data buffer length
 *      pat => pattern to find
 *      p_len => length of the data in the pattern buffer
 *
 *  Returns:
 *      Integer value, 1 on success (str constains substr), 0 on
 *      failure (substr not in str)
 *
 ****************************************************************/
int MatchContent(char *buf, int b_len, char *pat, int p_len)
{
    char *b_idx;        /* index ptr into the data buffer */
    char *p_idx;        /* index ptr into the pattern buffer */
    char *b_end;        /* ptr to the end of the data buffer */
    int m_cnt = 0;      /* number of pattern matches so far... */
	char str[64];

    unsigned long loopcnt = 0;

    /* mark the end of the strs */
    b_end = (char *) (buf + b_len);

    /* init the index ptrs */
    b_idx = buf;
    p_idx = pat;

    do {
        loopcnt++;

        if(*p_idx == *b_idx)
        {
            if(m_cnt == (p_len - 1))
            {
                wsprintf(str, "contents: %ld compares for match\r\n", loopcnt);
				debug(str);

                return TRUE;
            }
            m_cnt++;
            b_idx++;
            p_idx++;
        }
        else
        {
            if(m_cnt == 0)
                b_idx++;
            else
                b_idx = b_idx - (m_cnt - 1);

            p_idx = pat;
            m_cnt = 0;
        }

    } while (b_idx < b_end);


    /* if we make it here we didn't find what we were looking for */
    return FALSE;
}


