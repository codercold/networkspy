#include <windows.h>
#include <commctrl.h>
#include "common.h"
#include "structs.h"
#include "globals.h"
#include "resource.h"
#include "ui.h"
#include "utility.h"
#include "fileio.h"
#include "qhtm.h"
 
extern char	*ICMP_type[];




/* it is upto the calling procedure to pre-allocate enough memory (ret) */

VOID XML_DecodeSelected(SYSTEMTIME systime, unsigned char *buffer, int size, char *ret)
{
	unsigned char			*data; //[18];
	char					*temp, *temp2;
	struct ethernet_II		*eth_II;
	struct ethernet_802_3	*eth_802_3;
	struct arppkt			*arp;		
	struct iphdr			*ip;
	struct icmphdr			*icmp;
	struct tcphdr			*tcp;
	struct udphdr			*udp;
	struct igmphdr			*igmp;
	unsigned short			ptype; // ptype is the 'type' field in the ethernet frame
	unsigned int			sai;
	int						size_iphdr, size_framehdr;
	

	temp = malloc(2048);
	temp2 = malloc(1024);


	/* First check to see what kind of frame we have captured */

	eth_II = (struct ethernet_II *) buffer;
	if (ntohs(eth_II->type) > 0x05DC)	// it is ethernet_II frame
	{
		size_framehdr = 14;
		ptype = ntohs(eth_II->type);
	}
	else			// its an 802.3 frame
	{
		eth_802_3 = (struct ethernet_802_3 *) buffer;
		size_framehdr = 22;
		ptype = ntohs(eth_802_3->type);
	}
	

	wsprintf(ret, "<packet time=\"%.4d/%.2d/%.2d-%.2d:%.2d:%.2d:%.3d\">\r\n", systime.wYear, systime.wMonth, systime.wDay, systime.wHour, systime.wMinute, systime.wSecond, systime.wMilliseconds);

	lstrcat(ret, "  <frame_hdr>\r\n");
	wsprintf(temp, "    <src>%.2x:%.2x:%.2x:%.2x:%.2x:%.2x</src>\r\n", buffer[6], buffer[7],buffer[8],buffer[9],buffer[10],buffer[11]);
	lstrcat(ret, temp);

	wsprintf(temp, "    <dst>%.2x:%.2x:%.2x:%.2x:%.2x:%.2x</dst>\r\n", buffer[0], buffer[1],buffer[2],buffer[3],buffer[4],buffer[5]);
	lstrcat(ret, temp);
	if (size_framehdr == 22)
	{
		wsprintf(temp, "    <len>%d</len>\r\n", ntohs(eth_802_3->length));
		lstrcat(ret, temp);
		wsprintf(temp, "    <802.2_LLC>\r\n");
		lstrcat(ret, temp);
		wsprintf(temp, "       <dsap>%x</dsap>\r\n", eth_802_3->dsap);
		lstrcat(ret, temp);
		wsprintf(temp, "       <ssap>%x</ssap>\r\n", eth_802_3->ssap);
		lstrcat(ret, temp);
		wsprintf(temp, "       <control>%x</control>\r\n",eth_802_3->cntl);
		lstrcat(ret, temp);
		wsprintf(temp, "    </802.2_LLC>\r\n");
		lstrcat(ret, temp);
		wsprintf(temp, "    <802.2_SNAP>\r\n");
		lstrcat(ret, temp);
		wsprintf(temp, "       <org_code>0x%.2x%.2x%.2x</org_code>\r\n", eth_802_3->orgcode[0], eth_802_3->orgcode[1], eth_802_3->orgcode[2]);
		lstrcat(ret, temp);
		wsprintf(temp, "       <type>0x%.4x</type>\r\n", ntohs(eth_802_3->type));
		lstrcat(ret, temp);
		wsprintf(temp, "    </802.0_SNAP>\r\n");
		lstrcat(ret, temp);
	}
	else
	{
		wsprintf(temp, "    <type>0x%.4X</type>\r\n", ptype);
		lstrcat(ret, temp);
	}
	lstrcat(ret, "  </frame_hdr>\r\n");


	if ((ptype == 0x0806) || (ptype == 0x8035))		// ARP or RARP
	{
		if (ptype == 0x0806)
			lstrcat(ret, "  <arp>\r\n");
		else
			lstrcat(ret, "  <rarp>\r\n");
	
		arp = (struct arppkt *) &buffer[size_framehdr];

		wsprintf(temp, "    <type>0x%.4x</type>\r\n", ntohs(arp->hwtype));
		lstrcat(ret, temp);
		wsprintf(temp, "    <protocol>0x%.4x</protocol>\r\n", ntohs(arp->protocol));
		lstrcat(ret, temp);
		wsprintf(temp, "    <hlen>%d</hlen>\r\n", arp->hlen);
		lstrcat(ret, temp);
		wsprintf(temp, "    <plen>%d</plen>\r\n", arp->plen);
		lstrcat(ret, temp);
		wsprintf(temp, "    <op>0x%.4x</op>\r\n", ntohs(arp->operation));
		lstrcat(ret, temp);
		wsprintf(temp, "    <sender_ha>%.2x:%.2x:%.2x:%.2x:%.2x:%.2x</sender_ha>\r\n", arp->sender_ha[0], arp->sender_ha[1],arp->sender_ha[2],arp->sender_ha[3],arp->sender_ha[4],arp->sender_ha[5]);
		lstrcat(ret, temp);
		wsprintf(temp, "    <sender_ip>%d.%d.%d.%d</sender_ip>\r\n", arp->sender_ip[0], arp->sender_ip[1],arp->sender_ip[2],arp->sender_ip[3]);
		lstrcat(ret, temp);
		wsprintf(temp, "    <dest_ha>%.2X:%.2X:%.2X:%.2X:%.2X:%.2X</dest_ha>\r\n", arp->target_ha[0], arp->target_ha[1],arp->target_ha[2],arp->target_ha[3],arp->target_ha[4],arp->target_ha[5]);
		lstrcat(ret, temp);
		wsprintf(temp, "    <dest_ip>%d.%d.%d.%d</dest_ip>\r\n", arp->target_ip[0], arp->target_ip[1],arp->target_ip[2],arp->target_ip[3]);
		lstrcat(ret, temp);

		if (ptype == 0x0806)
			lstrcat(ret, "  </arp>\r\n");
		else
			lstrcat(ret, "  </rarp>\r\n");
	}

	else if (ptype == 0x0800)  // IP
	{
		lstrcat(ret, "  <ip_hdr>\r\n");

		ip = (struct iphdr *) &buffer[size_framehdr];

		size_iphdr = (ip->verlen & 0x0f) * 4;

		wsprintf(temp, "    <ver>%d</ver>\r\n", ip->verlen >> 4);
		lstrcat(ret, temp);
		wsprintf(temp, "    <len>%d bytes</len>\r\n", size_iphdr);
		lstrcat(ret, temp);
		wsprintf(temp, "    <tos>0x%.2X</tos>\r\n", ip->tos);
		lstrcat(ret, temp);
		wsprintf(temp, "    <tot_len>%d bytes</tot_len>\r\n", ntohs(ip->totlen));
		lstrcat(ret, temp);
		wsprintf(temp, "    <id>%d</id>\r\n", ntohs(ip->id));
		lstrcat(ret, temp);
		wsprintf(temp, "    <flags>0x%X</flags>\r\n", (ip->frag >> 13) & 0x7);
		lstrcat(ret, temp);
		wsprintf(temp, "    <frag_offset>%d</frag_offset>\r\n", ntohs(ip->frag) & 0x1fff);
		lstrcat(ret, temp);
		wsprintf(temp, "    <ttl>%d</ttl>\r\n", ip->ttl);
		lstrcat(ret, temp);
		wsprintf(temp, "    <prot>0x%.2x</prot>\r\n", ip->prot);
		lstrcat(ret, temp);
		wsprintf(temp, "    <checksum>0x%.4x%</checksum>\r\n", ntohs(ip->chksum));
		lstrcat(ret, temp);
		wsprintf(temp, "    <src_ip>%s</src_ip>\r\n", IpToString(ip->sourceip));
		lstrcat(ret, temp);
		wsprintf(temp, "    <dst_ip>%s</dst_ip>\r\n", IpToString(ip->destip));
		lstrcat(ret, temp);


		if (ip->prot == 0x11)		// UDP Packet
		{
			udp = (struct udphdr *) &buffer[size_framehdr + size_iphdr];

			lstrcat(ret, "    <udp>\r\n");
			wsprintf(temp, "      <src_port>%d</src_port>\r\n", ntohs(udp->srcport));
			lstrcat(ret, temp);
			wsprintf(temp, "      <dst_port>%d</dst_port>\r\n", ntohs(udp->dstport));
			lstrcat(ret, temp);
			wsprintf(temp, "      <msg_len>%d bytes</msg_len>\r\n", ntohs(udp->msglen));
			lstrcat(ret, temp);
			wsprintf(temp, "      <checksum>0x%.4x</checksum>\r\n", ntohs(udp->chksum));
			lstrcat(ret, temp);
			lstrcat(ret, "    </udp>\r\n");
		}
		
		else if (ip->prot == 0x06)	// A TCP packet
		{
			tcp = (struct tcphdr *) &buffer[size_framehdr + size_iphdr];

			lstrcat(ret, "    <tcp>\r\n");
			wsprintf(temp, "      <src_port>%d</src_port>\r\n", ntohs(tcp->srcport));
			lstrcat(ret, temp);
			wsprintf(temp, "      <dst_port>%d</dst_port>\r\n", ntohs(tcp->dstport));
			lstrcat(ret, temp);
			
			wsprintf(temp, "      <seq_no>%lu</seq_no>\r\n", ntohl(tcp->seqno));
			lstrcat(ret, temp);
			wsprintf(temp, "      <ack_no>%lu</ack_no>\r\n", ntohl(tcp->ackno));
			lstrcat(ret, temp);
			wsprintf(temp, "      <len>%d bytes</len>\r\n", (tcp->len >> 4) << 2);
			lstrcat(ret, temp);
			temp2[0] = '\0';
			if (tcp->flags & 0x10) lstrcat(temp2, "ACK+");
			if (tcp->flags & 0x02) lstrcat(temp2, "SYN+");
			if (tcp->flags & 0x01) lstrcat(temp2, "FIN+");
			if (tcp->flags & 0x04) lstrcat(temp2, "RST+");
			if (tcp->flags & 0x08) lstrcat(temp2, "PSH+");
			if (tcp->flags & 0x20) lstrcat(temp2, "URG+");
			if (lstrlen(temp2) > 3)
				if (temp2[lstrlen(temp2) - 1] == '+')
					temp2[lstrlen(temp2) - 1] = '\0';
			wsprintf(temp, "      <flags>%s</flags>\r\n", temp2);
			lstrcat(ret, temp);
			wsprintf(temp, "      <win_size>%d</win_size>\r\n", ntohs(tcp->winsize));
			lstrcat(ret, temp);
			wsprintf(temp, "      <checksum>0x%.4x</checksum>\r\n", ntohs(tcp->chksum));
			lstrcat(ret, temp);
			wsprintf(temp, "      <urg_ptr>%d</urg_ptr>\r\n", tcp->urgentptr);
			lstrcat(ret, temp);
			lstrcat(ret, "    </tcp>\r\n");
		}
		else if (ip->prot == 0x01)	// 'tis an ICMP message
		{
			icmp = (struct icmphdr *) &buffer[size_framehdr + size_iphdr];

			lstrcat(ret, "    <icmp>\r\n");
			wsprintf(temp, "      <type>%d</type>\r\n", icmp->type);
			lstrcat(ret, temp);
			wsprintf(temp, "      <code>%d</code>\r\n", icmp->code);
			lstrcat(ret, temp);
			wsprintf(temp, "      <checksum>0x%.4x</checksum>\r\n", ntohs(icmp->chksum));
			lstrcat(ret, temp);
			wsprintf(temp, "      <id>%d</id>\r\n", ntohs(icmp->id));
			lstrcat(ret, temp);
			wsprintf(temp, "      <seq_no>%d</seq_no>\r\n", ntohs(icmp->seqno));
			lstrcat(ret, temp);
			lstrcat(ret, "    </icmp>\r\n");
		}
		else if (ip->prot == 0x02)	// IGMP
		{
			igmp = (struct igmphdr *) &buffer[size_framehdr + size_iphdr];

			lstrcat(ret, "    <igmp>\r\n");
			wsprintf(temp, "      <ver>%d</ver>\r\n", igmp->ver_type >> 4);
			lstrcat(ret, temp);
			wsprintf(temp, "      <type>%d</type>\r\n", igmp->ver_type & 0x0f);
			lstrcat(ret, temp);
			wsprintf(temp, "      <checksum>0x%.4x</checksum>\r\n", ntohs(igmp->checksum));
			lstrcat(ret, temp);
			wsprintf(temp, "      <group>%d.%d.%d.%d</group>\r\n", igmp->ip_address[0], igmp->ip_address[1], igmp->ip_address[2], igmp->ip_address[3]);
			lstrcat(ret, temp);
			lstrcat(ret, "    </igmp>\r\n");

		}
		else if (buffer[23] == 0x32)
		{		
			memcpy(&sai, &buffer[34], sizeof(int));
			data = &buffer[38];

			lstrcat(ret, "    <SIPP-ESP>\r\n");
			wsprintf(temp, "      <security_association_id>%d</security_association_id>\r\n", ntohl(sai));
			lstrcat(ret, temp);
			wsprintf(temp, "      <opaque_transform_data>%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x</opaque_transform_data>\r\n", data[0],data[1],data[2],data[3],data[4],data[5],data[6],data[7],data[8],data[9],data[10],data[11],data[12],data[13],data[14],data[15],data[16],data[17]);
			lstrcat(ret, temp);
			lstrcat(ret, "    </SIPP-ESP>\r\n");
		}

		lstrcat(ret, "  </ip_hdr>\r\n");
	}

	lstrcat(ret, "</packet>\r\n\r\n");
	
	free (temp);
	free (temp2);
	
	return;
}












/* it is upto the calling procedure to pre-allocate enough memory (ret) */

VOID DecodeSelected(SYSTEMTIME systime, unsigned char *buffer, int size, char *ret)
{
	unsigned char	data[18];
	char			*service, *temp, *temp2;
	struct ethernet_II	eth_II;
	struct ethernet_802_3	eth_802_3;
	struct arppkt	arp;		
	struct iphdr	ip;
	struct icmphdr	icmp;
	struct tcphdr	tcp;
	struct udphdr	udp;
	struct igmphdr	igmp;
	unsigned short  ptype; // ptype is the 'type' field in the ethernet frame
	unsigned int	sai;
	int				size_iphdr, size_framehdr;
	

	temp = malloc(2048);
	temp2 = malloc(1024);


	/* First check to see what kind of frame we have captured */

	memcpy(&eth_II, buffer, sizeof(struct ethernet_II));
	if (ntohs(eth_II.type) > 0x05DC)	// it is ethernet_II frame
	{
		size_framehdr = 14;
		ptype = ntohs(eth_II.type);
	}
	else			// its an 802.3 frame
	{
		memcpy(&eth_802_3, buffer, sizeof(struct ethernet_802_3));
		size_framehdr = 22;
		ptype = ntohs(eth_802_3.type);
	}
	


	if (systime.wYear)
		wsprintf(ret, "<BODY BGCOLOR=#ffffff><IMG ALIGN=right SRC=RES:logo.png><FONT SIZE=5>Packet Timestamp: %d:%.2d:%.2d:%.3d</FONT><BR><HR>", systime.wHour, systime.wMinute, systime.wSecond, systime.wMilliseconds);
	else
		wsprintf(ret, "<BODY BGCOLOR=#ffffff><IMG ALIGN=right SRC=RES:logo.png><FONT SIZE=5>Packet Timestamp: Unknown</FONT><BR><HR>");

	if (size_framehdr == 14)
		lstrcat(ret, "<H2><FONT COLOR=red>Ethernet_II Frame Header</FONT></H2>");
	else
		lstrcat(ret, "<H2><FONT COLOR=red>802.3 Frame Header</FONT></H2>");

	wsprintf(temp, "<TABLE WIDTH=460><TR><TD><b>Source Address:</b></TD><TD>%.2X:%.2X:%.2X:%.2X:%.2X:%.2X</TD></TR>", buffer[6], buffer[7],buffer[8],buffer[9],buffer[10],buffer[11]);
	lstrcat(ret, temp);

	wsprintf(temp, "<TR><TD><b>Destination Address:</b></TD><TD>%.2X:%.2X:%.2X:%.2X:%.2X:%.2X</TD></TR>", buffer[0], buffer[1],buffer[2],buffer[3],buffer[4],buffer[5]);
	lstrcat(ret, temp);
	if (size_framehdr == 22)
	{
		wsprintf(temp, "<TR><TD><b>Length:</b></TD><TD>0x%.4x &nbsp; &nbsp; ( %d bytes )</TD></TR>", ntohs(eth_802_3.length), ntohs(eth_802_3.length));
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD><b>802.2 LLC:</b></TD><TD></TD></TR>");
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; DSAP</TD><TD>%x</TD></TR>", eth_802_3.dsap);
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; SSAP</TD><TD>%x</TD></TR>", eth_802_3.ssap);
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Control</b></TD><TD>%x</TD></TR>",eth_802_3.cntl);
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD><b>802.2 SNAP:</b></TD><TD></TD></TR>");
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Organization Code</TD><TD>0x%.2x%.2x%.2x</TD></TR>", eth_802_3.orgcode[0], eth_802_3.orgcode[1], eth_802_3.orgcode[2]);
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Type</TD><TD>0x%.4x</TD></TR><TR><TD>-</TD><TD></TD></TR></TABLE>", ntohs(eth_802_3.type));
		lstrcat(ret, temp);
	}
	else
	{
		wsprintf(temp, "<TR><TD><b>Type:</b></TD><TD>0x%.4X</TD></TR><TR><TD>-</TD><TD></TD></TR></TABLE>", ptype);
		lstrcat(ret, temp);
	}

	if ((ptype == 0x0806) || (ptype == 0x8035))		// ARP or RARP
	{
		if (ptype == 0x0806)
			wsprintf(temp, "<H2><FONT COLOR=red>ARP Packet</H2></FONT>");
		else
			wsprintf(temp, "<H2><FONT COLOR=red>RARP Packet</H2></FONT>");
		lstrcat(ret, temp);
	
		memcpy(&arp, &buffer[size_framehdr], sizeof(arp));

		wsprintf(temp, "<TABLE WIDTH=340><TR><TD><b>Hardware type:</b></TD><TD>0x%.4x</TD></TR>", ntohs(arp.hwtype));
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD><b>Protocol:</b></TD><TD>0x%.4x</TD></TR>", ntohs(arp.protocol));
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD><b>Hardware Address len:</b></TD><TD>%d</TD></TR>", arp.hlen);
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD><b>Protocol Address len:</b></TD><TD>%d</TD></TR>", arp.plen);
		lstrcat(ret, temp);

		if (ntohs(arp.operation) == 0x0001) lstrcpy(temp2, "arp request");
		else if (ntohs(arp.operation) == 0x0002) lstrcpy(temp2, "arp reply");
		else if (ntohs(arp.operation) == 0x0003) lstrcpy(temp2, "rarp request");
		else if (ntohs(arp.operation) == 0x0004) lstrcpy(temp2, "rarp reply");
		else lstrcpy(temp2, "unknown type");
		wsprintf(temp, "<TR><TD><b>Operation:</b></TD><TD>0x%.4x &nbsp;&nbsp; ( %s )</TD></TR>", ntohs(arp.operation), temp2);
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD><b>Sender Hardware Addr:</b></TD><TD>%.2X:%.2X:%.2X:%.2X:%.2X:%.2X</TD></TR>", arp.sender_ha[0], arp.sender_ha[1],arp.sender_ha[2],arp.sender_ha[3],arp.sender_ha[4],arp.sender_ha[5]);
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD><b>Sender IP Address:</b></TD><TD>%d.%d.%d.%d</TD></TR>", arp.sender_ip[0], arp.sender_ip[1],arp.sender_ip[2],arp.sender_ip[3]);
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD><b>Dest Hardware Addr:</b></TD><TD>%.2X:%.2X:%.2X:%.2X:%.2X:%.2X</TD></TR>", arp.target_ha[0], arp.target_ha[1],arp.target_ha[2],arp.target_ha[3],arp.target_ha[4],arp.target_ha[5]);
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD><b>Dest IP Address:</b></TD><TD>%d.%d.%d.%d</TD></TR><TR><TD>-</TD><TD></TD></TR></TABLE>", arp.target_ip[0], arp.target_ip[1],arp.target_ip[2],arp.target_ip[3]);
		lstrcat(ret, temp);
	}
	else if (ptype == 0x0800)  // IP
	{
		wsprintf(temp, "<H2><FONT COLOR=red>IP Header</FONT></H2>");
		lstrcat(ret, temp);

		memcpy (&ip, &buffer[size_framehdr], sizeof(ip));
		size_iphdr = (ip.verlen & 0x0f) * 4;

		wsprintf(temp, "<TABLE WIDTH=440><TR><TD><b>Version:</b></TD><TD>%d</TD></TR>", ip.verlen >> 4);
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD><b>Length:</b>                </TD><TD>%d  &nbsp;&nbsp; (%d bytes)</TD></TR>", ip.verlen & 0x0f, size_iphdr);
		lstrcat(ret, temp);

		temp2[0] = '\0';
		if ((ip.tos >> 5) == 7)  lstrcat(temp2, "Network Control");
		if ((ip.tos >> 5) == 6)  lstrcat(temp2, "Internetwork Control");
		if ((ip.tos >> 5) == 5)  lstrcat(temp2, "CRITIC/ECP");
		if ((ip.tos >> 5) == 4)  lstrcat(temp2, "Flash Override");
		if ((ip.tos >> 5) == 3)  lstrcat(temp2, "Flash");
		if ((ip.tos >> 5) == 2)  lstrcat(temp2, "Immediate");
		if ((ip.tos >> 5) == 1)  lstrcat(temp2, "Priority");
		if ((ip.tos >> 5) == 0)  lstrcat(temp2, "Routine");
		
		wsprintf(temp,	"<TR><TD><b>Type of Service:</b>       </TD><TD>0x%.2X</TD></TR>", ip.tos);
		lstrcat(ret, temp);
		wsprintf(temp,	"<TR><TD>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Precedence</TD><TD>%s</TD></TR>", temp2);
		lstrcat(ret, temp);
		wsprintf(temp,	"<TR><TD>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Minimize Delay</TD><TD>%d</TD></TR>", (ip.tos >> 4) & 0x1);
		lstrcat(ret, temp);
		wsprintf(temp,	"<TR><TD>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Maximize Throughput</TD><TD>%d</TD></TR>", (ip.tos >> 3) & 0x1);
		lstrcat(ret, temp);
		wsprintf(temp,	"<TR><TD>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Maximize Reliability</TD><TD>%d</TD></TR>", (ip.tos >> 2) & 0x1);
		lstrcat(ret, temp);
		wsprintf(temp,	"<TR><TD>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Minimize Monetary cost</TD><TD>%d</TD></TR>", (ip.tos >> 1) & 0x1);
		lstrcat(ret, temp);
		
		wsprintf(temp, "<TR><TD><b>Total Length:</b>          </TD><TD>%d bytes</TD></TR>", ntohs(ip.totlen));
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD><b>Identification:</b>        </TD><TD>%d</TD></TR>", ntohs(ip.id));
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD><b>Flags:</b>         </TD><TD>0x%X</TD></TR>", (ip.frag >> 13) & 0x7);
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  Don't fragment:         </TD><TD>%d</TD></TR>", (ip.frag >> 14) & 0x0001);
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;  More fragments:         </TD><TD>%d</TD></TR>", (ip.frag >> 13) & 0x0001);
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD><b>Fragment Offset:</b>         </TD><TD>%d</TD></TR>", ntohs(ip.frag) & 0x1fff);
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD><b>Time-to-live:</b>          </TD><TD>%d</TD></TR>", ip.ttl);
		lstrcat(ret, temp);
		if (ip.prot == 0x11) lstrcpy(temp2, " ( udp )");
		else if (ip.prot == 0x06) lstrcpy(temp2, " ( tcp )");
		else if (ip.prot == 0x01) lstrcpy(temp2, " ( icmp )");
		else lstrcpy(temp2, " ( unknown )");
		wsprintf(temp, "<TR><TD><b>Protocol:</b>              </TD><TD>0x%.2x &nbsp;&nbsp;%s</TD></TR>", ip.prot, temp2);
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD><b>Checksum:</b>              </TD><TD>0x%.4x%</TD></TR>", ntohs(ip.chksum));
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD><b>Sender IP Address:</b>     </TD><TD>%s</TD></TR>", IpToString(ip.sourceip));
		lstrcat(ret, temp);
		wsprintf(temp, "<TR><TD><b>Dest IP Address:</b>       </TD><TD>%s</TD></TR><TR><TD>-</TD><TD></TD></TR></TABLE>", IpToString(ip.destip));
		lstrcat(ret, temp);

		if (ip.prot == 0x11)		// UDP Packet
		{
			lstrcat(ret, "<H2><FONT COLOR=red>UDP Header</FONT></H2><TABLE WIDTH=340>");

			memcpy(&udp, &buffer[size_framehdr + size_iphdr], sizeof(udp));

			service = find_in_table(ntohs(udp.srcport), UDP);
			if (service)
				wsprintf(temp, "<TR><TD><b>Source Port:</b>    </TD><TD>%d &nbsp;&nbsp; ( %s )</TD></TR>", ntohs(udp.srcport), service);
			else
				wsprintf(temp, "<TR><TD><b>Source Port:</b>    </TD><TD>%d</TD></TR>", ntohs(udp.srcport));
			lstrcat(ret, temp);

			service = find_in_table(ntohs(udp.dstport), UDP);
			if (service)
				wsprintf(temp, "<TR><TD><b>Destination Port:</b>  </TD><TD>%d &nbsp;&nbsp; ( %s )</TD></TR>", ntohs(udp.dstport), service);
			else
				wsprintf(temp, "<TR><TD><b>Destination Port:</b>  </TD><TD>%d</TD></TR>", ntohs(udp.dstport));
			lstrcat(ret, temp);

			wsprintf(temp, "<TR><TD><b>Message Length:</b>       </TD><TD>%d bytes</TD></TR>", ntohs(udp.msglen));
			lstrcat(ret, temp);
			wsprintf(temp, "<TR><TD><b>Checksum:</b>             </TD><TD>0x%.4x</TD></TR><TR><TD>-</TD><TD></TD></TR></TABLE>", ntohs(udp.chksum));
			lstrcat(ret, temp);
		}
		else if (ip.prot == 0x06)	// A TCP packet
		{
			lstrcat(ret, "<H2><FONT COLOR=red>TCP Header</FONT></H2><TABLE WIDTH=340>");

		
			memcpy(&tcp, &buffer[size_framehdr + size_iphdr], sizeof(tcp));
			
			service = find_in_table(ntohs(tcp.srcport), TCP);
			if (service)
				wsprintf(temp, "<TR><TD><b>Source Port:</b>          </TD><TD>%d &nbsp;&nbsp; ( %s )</TD></TR>", ntohs(tcp.srcport), service);
			else
				wsprintf(temp, "<TR><TD><b>Source Port:</b>          </TD><TD>%d</TD></TR>", ntohs(tcp.srcport));
			lstrcat(ret, temp);

			service = find_in_table(ntohs(tcp.dstport), TCP);
			if (service)
				wsprintf(temp, "<TR><TD><b>Destination Port:</b>     </TD><TD>%d &nbsp;&nbsp; ( %s )</TD></TR>", ntohs(tcp.dstport), service);
			else
				wsprintf(temp, "<TR><TD><b>Destination Port:</b>     </TD><TD>%d</TD></TR>", ntohs(tcp.dstport));
			lstrcat(ret, temp);
			
			wsprintf(temp, "<TR><TD><b>Sequence no.:</b>         </TD><TD>%lu</TD></TR>", ntohl(tcp.seqno));
			lstrcat(ret, temp);
			wsprintf(temp, "<TR><TD><b>Acknowledge no.:</b>      </TD><TD>%lu</TD></TR>", ntohl(tcp.ackno));
			lstrcat(ret, temp);
			wsprintf(temp, "<TR><TD><b>Length:</b>               </TD><TD>%d bytes</TD></TR>", (tcp.len >> 4) << 2);
			lstrcat(ret, temp);
			temp2[0] = '\0';
			if (tcp.flags & 0x10) lstrcat(temp2, " ACK +");
			if (tcp.flags & 0x02) lstrcat(temp2, " SYN +");
			if (tcp.flags & 0x01) lstrcat(temp2, " FIN +");
			if (tcp.flags & 0x04) lstrcat(temp2, " RST +");
			if (tcp.flags & 0x08) lstrcat(temp2, " PSH +");
			if (tcp.flags & 0x20) lstrcat(temp2, " URG +");
			if (lstrlen(temp2) > 3)
				if (temp2[lstrlen(temp2) - 1] == '+')
					temp2[lstrlen(temp2) - 1] = '\0';
			wsprintf(temp, "<TR><TD><b>Flags:</b>               </TD><TD>%s</TD></TR>", temp2);
			lstrcat(ret, temp);
			wsprintf(temp, "<TR><TD><b>Window Size:</b>          </TD><TD>%d</TD></TR>", ntohs(tcp.winsize));
			lstrcat(ret, temp);
			wsprintf(temp, "<TR><TD><b>Checksum:</b>             </TD><TD>0x%.4x</TD></TR>", ntohs(tcp.chksum));
			lstrcat(ret, temp);
			wsprintf(temp, "<TR><TD><b>Urgent Pointer:</b>       </TD><TD>%d</TD></TR></TABLE>", tcp.urgentptr);
			lstrcat(ret, temp);
		}
		else if (ip.prot == 0x01)	// 'tis an ICMP message
		{
			lstrcat(ret, "<H2><FONT COLOR=red>ICMP Header</FONT></H2>");
		

			memcpy(&icmp, &buffer[size_framehdr + size_iphdr], sizeof(icmp)); //used to be 34
			wsprintf(temp, "<TABLE WIDTH=340><TR><TD><b>Type:</b></TD><TD>%d  &nbsp;&nbsp; ( %s )</TD></TR>", icmp.type, ICMP_type[icmp.type]);
			lstrcat(ret, temp);

			temp2[0] = '\0';
			if (icmp.type == 3)			/* destination unreachable */
			{
				if (icmp.code == 0)  lstrcpy(temp2, " ( net unreachable )");
				else if (icmp.code == 1)  lstrcpy(temp2, " ( host unreachable )");
				else if (icmp.code == 2)  lstrcpy(temp2, " ( protocol unreachable )");
				else if (icmp.code == 3)  lstrcpy(temp2, " ( port unreachable )");
				else if (icmp.code == 4)  lstrcpy(temp2, " ( fragmentation needed )");
				else if (icmp.code == 5)  lstrcpy(temp2, " ( source route failed )");
				else if (icmp.code == 6)  lstrcpy(temp2, " ( destination network unknown )");
				else if (icmp.code == 7)  lstrcpy(temp2, " ( destination host unknown )");
				else if (icmp.code == 9)  lstrcpy(temp2, " ( destination network administratively prohibited )");
				else if (icmp.code == 10)  lstrcpy(temp2, " ( destination host administratively prohibited )");
				else if (icmp.code == 11)  lstrcpy(temp2, " ( network unreachable for TOS )");
				else if (icmp.code == 12)  lstrcpy(temp2, " ( host unreachable for TOS )");
				else if (icmp.code == 15)  lstrcpy(temp2, " ( precedence cutoff in effect )");
			}
			else if (icmp.type == 5)	/* redirect */
			{
				if (icmp.code == 0)  lstrcpy(temp2, " ( network redirect )");
				else if (icmp.code == 1)  lstrcpy(temp2, " ( host redirect )");
				else if (icmp.code == 2)  lstrcpy(temp2, " ( type of service and network redirect )");
				else if (icmp.code == 3)  lstrcpy(temp2, " ( type of service and host redirect )");
			}
			else if (icmp.type == 11)	/* time exceeded */
			{
				if (icmp.code == 0)  lstrcpy(temp2, " ( TTL Exceeded in transit )");
				else if (icmp.code == 1)  lstrcpy(temp2, " ( fragment reassembly time exceeded )");
			}
			else if (icmp.type == 12)	/* parameter problem */
			{
				if (icmp.code == 0)  lstrcpy(temp2, " ( IP header bad )");
				else if (icmp.code == 1)  lstrcpy(temp2, " ( required option missing )");
			}

			wsprintf(temp, "<TR><TD><b>Code:</b></TD><TD>%d &nbsp;&nbsp; %s</TD></TR>", icmp.code, temp2);
			lstrcat(ret, temp);
			wsprintf(temp, "<TR><TD><b>Checksum:</b></TD><TD>0x%.4x</TD></TR>", ntohs(icmp.chksum));
			lstrcat(ret, temp);
			wsprintf(temp, "<TR><TD><b>Identifier:</b></TD><TD>%d</TD></TR>", ntohs(icmp.id));
			lstrcat(ret, temp);
			wsprintf(temp, "<TR><TD><b>Sequence no.:</b></TD><TD>%d</TD></TR><TR><TD>-</TD><TD></TD></TR></TABLE>", ntohs(icmp.seqno));
			lstrcat(ret, temp);
		}
		else if (ip.prot == 0x02)	// IGMP
		{
			memcpy(&igmp, &buffer[size_framehdr + size_iphdr], sizeof(igmp));

			lstrcat(ret, "<H2><FONT COLOR=red>IGMP Header</FONT></H2><TABLE WIDTH=340>");
			wsprintf(temp, "<TR><TD><b>Version:</b></TD><TD>%d</TD></TR>", igmp.ver_type >> 4);
			lstrcat(ret, temp);
			wsprintf(temp, "<TR><TD><b>Type:</b></TD><TD>%d</TD></TR>", igmp.ver_type & 0x0f);
			lstrcat(ret, temp);
			wsprintf(temp, "<TR><TD><b>Checksum:</b></TD><TD>0x%.4x</TD></TR>", ntohs(igmp.checksum));
			lstrcat(ret, temp);
			wsprintf(temp, "<TR><TD><b>Group Address:</b></TD><TD>%d.%d.%d.%d</TD></TR><TR><TD>-</TD><TD></TD></TR></TABLE>", igmp.ip_address[0], igmp.ip_address[1], igmp.ip_address[2], igmp.ip_address[3]);
			lstrcat(ret, temp);
		}
		else if (buffer[23] == 0x32)
		{
			lstrcat(ret, "<H2><FONT COLOR=red>SIPP-ESP Header</FONT></H2>");
		
			memcpy(&sai, &buffer[34], sizeof(int));
			memcpy(data, &buffer[38], 18);
			wsprintf(temp, "<TABLE WIDTH=500><TR><TD><b>Security Association ID:</b></TD><TD>%d  </TD></TR>", ntohl(sai));
			lstrcat(ret, temp);
			wsprintf(temp, "<TR><TD><b>Opaque Transform Data:</b></TD><TD>%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X</TD></TR><TR><TD>-</TD><TD></TD></TR></TABLE>", data[0],data[1],data[2],data[3],data[4],data[5],data[6],data[7],data[8],data[9],data[10],data[11],data[12],data[13],data[14],data[15],data[16],data[17]);
			lstrcat(ret, temp);
		}
	}

	
	free (temp);
	free (temp2);
	
	return;
}




BOOL CALLBACK DecodeDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	RECT	rect = {50, 50, 600, 560};
	static HCURSOR hCursor;
	static BOOL		bSplitterMoving;
	static DWORD	dwSplitterPos, dwValue;
	static HWND		hWndBar;
	static char		szFile[MAX_PATH], *szBuffer;
	char	str[32], *file_data;
	struct packet	*pkt, *pktl;
	int		size, nScrollPos;
	PRINTPARAMS		*pparams;
	HANDLE			hThread;
	SYSTEMTIME		systime;

	switch (uMsg)
	{
	case WM_INITDIALOG:
		pkt = (struct packet *) GetSelectedItemLParam(hWndAlertList);
		if (pkt == NULL)
		{
			MessageBox(hDlg, "Nothing to decode!", APP_NAME, MB_OK | MB_ICONEXCLAMATION);
			EndDialog(hDlg, 0);
			return FALSE;
		}

		pktl = malloc(sizeof(struct packet));
		pktl->time = pkt->time;
		pktl->size = pkt->size;
		pktl->data = malloc(pkt->size);
		memcpy(pktl->data, pkt->data, pkt->size);

		SetWindowLong(hDlg, DWL_USER, (long) pktl);

		hWndBar = CreateDecoderToolbar(hDlg, hInst);
		hCursor = LoadCursor(NULL, MAKEINTRESOURCE(IDC_SIZENS));
		bSplitterMoving = FALSE;
		

		dwSplitterPos = GetPrivateProfileInt("Packet Capture", "SplitterPos", 350, INI_FILE);
		dwSplitterPos = RANGE(60, dwSplitterPos, rect.bottom - rect.top);

		RestoreWindowPosition(hDlg);

		// output the decoded packet
		szBuffer = malloc(32000);  // free only when destroying dialog
		DecodeSelected(pktl->time, pktl->data, pktl->size, szBuffer);
		SetDlgItemText(hDlg, IDC_HTML, szBuffer);
		InvalidateRect(GetDlgItem(hDlg, IDC_HTML), NULL, FALSE);

		// output the hexadecimal view of the packet
		PrintRawData(pktl->data, pktl->size, szBuffer);
		SetDlgItemText(hDlg, IDC_EDIT_RAWDATA, szBuffer);
		
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

		SendMessage(hWndBar, TB_AUTOSIZE, 0, 0L);
		MoveWindow(GetDlgItem(hDlg, IDC_HTML), 0, 30, LOWORD(lParam), dwSplitterPos - 31, TRUE);
		MoveWindow(GetDlgItem(hDlg, IDC_EDIT_RAWDATA), 0, dwSplitterPos+2, LOWORD(lParam) , HIWORD(lParam) - dwSplitterPos - 2, TRUE);
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
		case ID_SAVE:
			if (PopFileSaveDlg (hDlg, szFile, 3))
			{
				pkt = (struct packet *) GetWindowLong(hDlg, DWL_USER);
				if (pkt == NULL)
				{
					MessageBox(hDlg, "Nothing to save!", APP_NAME, MB_OK | MB_ICONEXCLAMATION);
					return TRUE;
				}

				lstrcpy(str, &szFile[lstrlen(szFile)-3]);
				if (!lstrcmp(str, "tml") || !lstrcmp(str, "htm"))
				{
					DecodeSelected(pkt->time, pkt->data, pkt->size, szBuffer);
					SavePacket(szFile, szBuffer, lstrlen(szBuffer));
				}
				else if (!lstrcmp(str, "txt"))
				{
					PrintRawData(pkt->data, pkt->size, szBuffer);
					SavePacket(szFile, szBuffer, lstrlen(szBuffer));
				}
				else
					SavePacket(szFile, pkt->data, pkt->size);
			}
			return TRUE;


		case ID_OPEN:
			if (PopFileOpenDlg(hDlg, szFile))
			{
				if (LoadFile(szFile, &file_data, &size))
				{
					lstrcpy(str, &szFile[lstrlen(szFile)-3]);
					if (!lstrcmp(str, "pkt"))
					{
						systime.wYear = 0;
						DecodeSelected(systime, file_data, size, szBuffer);
						SetDlgItemText(hDlg, IDC_HTML, szBuffer);
						InvalidateRect(GetDlgItem(hDlg, IDC_HTML), NULL, FALSE);

						PrintRawData(file_data, size, szBuffer);
						SetDlgItemText(hDlg, IDC_EDIT_RAWDATA, szBuffer);

						pktl = (struct packet *) GetWindowLong(hDlg, DWL_USER);
						free(pktl->data);
						pktl->time = systime;
						pktl->size = size;
						pktl->data = malloc(size);
						memcpy(pktl->data, file_data, size);
					}
					else
						MessageBox(hDlg, "Can only decode .pkt files!", APP_NAME, MB_OK | MB_ICONEXCLAMATION);
				
					free(file_data);
				}
				else
					MessageBox(hDlg, "Error loading file!", APP_NAME, MB_OK | MB_ICONEXCLAMATION);
			}
			return TRUE;


		case ID_PRINT:
			pkt = (struct packet *) GetWindowLong(hDlg, DWL_USER);
			if (pkt != NULL)
			{
				DecodeSelected(pkt->time, pkt->data, pkt->size, szBuffer);

				pparams = malloc(sizeof(PRINTPARAMS));
				pparams->mode = 0;
				pparams->hDlg = hDlg;
				pparams->buffer = malloc(lstrlen(szBuffer) + 1);
				lstrcpy(pparams->buffer, szBuffer);

				hThread = CreateThread( NULL, 0,(LPTHREAD_START_ROUTINE)PrintHTML, pparams, 0, &dwValue );
				if( hThread ) CloseHandle( hThread );
			}
			return TRUE;


		case ID_PRINT_DLG:
			pkt = (struct packet *) GetWindowLong(hDlg, DWL_USER);
			if (pkt != NULL)
			{
				DecodeSelected(pkt->time, pkt->data, pkt->size, szBuffer);
			
				pparams = malloc(sizeof(PRINTPARAMS));
				pparams->mode = 1;
				pparams->hDlg = hDlg;
				pparams->buffer = malloc(lstrlen(szBuffer) + 1);
				lstrcpy(pparams->buffer, szBuffer);

				hThread = CreateThread( NULL, 0,(LPTHREAD_START_ROUTINE)PrintHTML, pparams, 0, &dwValue );
				if( hThread ) CloseHandle( hThread );
			}
			return TRUE;


		case ID_CLOSE:
			DestroyWindow(hDlg);
			return TRUE;
		
		case ID_CANCEL:
			DestroyWindow(hDlg);
			return TRUE;

		case ID_PACKET_NEXT:
			pkt = (struct packet *) GetNextItemLParam(hWndAlertList);
			if (pkt != NULL)
			{
				pktl = (struct packet *) GetWindowLong(hDlg, DWL_USER);
				free(pktl->data);
				pktl->time = pkt->time;
				pktl->size = pkt->size;
				pktl->data = malloc(pkt->size);
				memcpy(pktl->data, pkt->data, pkt->size);

				nScrollPos = GetScrollPos(GetDlgItem(hDlg, IDC_HTML), SB_VERT);
				
				// output the decoded packet in html
				DecodeSelected(pkt->time, pkt->data, pkt->size, szBuffer);
				SetDlgItemText(hDlg, IDC_HTML, szBuffer);
				
				// output the packet in hexadecimal
				PrintRawData(pkt->data, pkt->size, szBuffer);
				SetDlgItemText(hDlg, IDC_EDIT_RAWDATA, szBuffer);
								

				SendDlgItemMessage(hDlg, IDC_HTML, WM_VSCROLL, MAKEWPARAM(SB_THUMBTRACK, nScrollPos), (LPARAM) NULL);
				//InvalidateRect(GetDlgItem(hDlg, IDC_HTML), NULL, FALSE);
			}
			return TRUE;

		case ID_PACKET_PREVIOUS:
			pkt = (struct packet *) GetPreviousItemLParam(hWndAlertList);
			if (pkt != NULL)
			{	
				pktl = (struct packet *) GetWindowLong(hDlg, DWL_USER);
				free(pktl->data);
				pktl->time = pkt->time;
				pktl->size = pkt->size;
				pktl->data = malloc(pkt->size);
				memcpy(pktl->data, pkt->data, pkt->size);
				
				nScrollPos = GetScrollPos(GetDlgItem(hDlg, IDC_HTML), SB_VERT);
				
				// output the decoded packet in html
				DecodeSelected(pkt->time, pkt->data, pkt->size, szBuffer);
				SetDlgItemText(hDlg, IDC_HTML, szBuffer);

				// output the packet in hexadecimal
				PrintRawData(pkt->data, pkt->size, szBuffer);
				SetDlgItemText(hDlg, IDC_EDIT_RAWDATA, szBuffer);

				SendDlgItemMessage(hDlg, IDC_HTML, WM_VSCROLL, MAKEWPARAM(SB_THUMBTRACK, nScrollPos), (LPARAM) NULL);
				//InvalidateRect(GetDlgItem(hDlg, IDC_HTML), NULL, FALSE);
			}
			return TRUE;
		}
		break;

	
	case WM_CLOSE:
		DestroyWindow(hDlg);
		return TRUE;


	case WM_DESTROY:
		SaveWindowPosition(hDlg);
		wsprintf(str, "%d", dwSplitterPos);
		WritePrivateProfileString("Packet Capture", "SplitterPos", str, INI_FILE);

		pktl = (struct packet *) GetWindowLong(hDlg, DWL_USER);
		if (pktl)
		{
			free(pktl->data);
			free(pktl);
		}

		hModelessDlg = NULL;
		free(szBuffer);

		return TRUE;
	}
	return FALSE;
}




