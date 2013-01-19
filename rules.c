/*
	NOTES:

  1.  Must preserve the string containing the entire line of rule until 
      populateOptions is called.

  2.  Try to minimize on malloc use.

*/

#include <windows.h>
#include <commctrl.h>
#include "resource.h"
#include "globals.h"
#include "utility.h"
#include "rules.h"

/* this is missing for some reason, so added manually */
#ifndef ListView_SetCheckState
   #define ListView_SetCheckState(hwndLV, i, fCheck) \
      ListView_SetItemState(hwndLV, i, \
      INDEXTOSTATEIMAGEMASK((fCheck)+1), LVIS_STATEIMAGEMASK)
#endif


/* rule header related functions */
char getIPop(char *);
u_long getIP(char *);
u_long getMask(char *);
u_short getPortMin(char *str);
u_short getPortMax(char *str);

u_short getIpOpts(char *options);
u_char getFragbits(char *options, char *op);
u_char getFlags(char *options, char *op);


KeyVal	 *var_list;
char **gettokens(char *str, int *nTokens);
KeyVal *getOptionList(char *optstr);
void DumpRule(RuleNode *rule_node);
void PopulateOptions(RuleNode *options, KeyVal *list);
void AddToVarList(char *var, char *value);
char *getValue(char *var);
void DestroyRulesChain(RulesHead *rules_head);




BOOL GenerateRules()
{
	char **tokens, rule[256];
	int num_tokens,j, i;
	KeyVal *opt_head, *opt_cptr, *opt_pptr;
	RuleNode *new_rule, **node_ptr, *node;
	RulesHead *rules_head;
	BOOL  bError;

	var_list = NULL;

	for (j = 0; j < 256; j++)
	{
		if (rule_text[j].rule[0] == '\0')  break;
		if (rule_text[j].bEnabled == FALSE)  continue;

		bError = FALSE;

		lstrcpy(rule, rule_text[j].rule);

		tokens = gettokens(rule, &num_tokens);

		// Add variables to the Variable linked list
		if (!lstrcmp(tokens[0], "var"))
		{
			tokens[2][lstrlen(tokens[2])-1] = '\0';  // get rid of the semicolon
			AddToVarList(tokens[1], tokens[2]);
			continue;
		}

		/* replace any variable with its actual value */
		for (i = 0; i < num_tokens; i++)
		{
			debug(tokens[i]); debug(" ");
			if (tokens[i][0] == '$')	
				tokens[i] = getValue(tokens[i]);
			
			if (tokens[i] == NULL)  // this variable has not been defined 					
			{
				bError = TRUE;
				break;
			}
		}
		
		// if there was an error, don't add this rule to chain
		if (bError)
		{
			debug(" << ERROR >> \r\n");
			continue;
		}		
		debug("\r\n");

		if (!lstrcmp(tokens[0], "alert"))		  rules_head = &root.alert;
		else if (!lstrcmp(tokens[0], "log"))	  rules_head = &root.log;
		else if (!lstrcmp(tokens[0], "counter"))  rules_head = &root.counter;
		else continue;

		if (!lstrcmp(tokens[1], "icmp"))		  node_ptr = &rules_head->IcmpList;
		else if (!lstrcmp(tokens[1], "udp"))	  node_ptr = &rules_head->UdpList;
		else if (!lstrcmp(tokens[1], "tcp"))	  node_ptr = &rules_head->TcpList;
		else if (!lstrcmp(tokens[1], "arp"))	  node_ptr = &rules_head->ArpList;
		else continue;


		new_rule = (RuleNode *) malloc(sizeof(RuleNode));
		memset(new_rule, 0, sizeof(RuleNode));

		new_rule->sip_op = getIPop(tokens[2]);
		new_rule->sip = getIP(tokens[2]);
		new_rule->smask = getMask(tokens[2]);
		new_rule->dip_op = getIPop(tokens[5]);
		new_rule->dip = getIP(tokens[5]);
		new_rule->dmask = getMask(tokens[5]);
		new_rule->lsp = getPortMin(tokens[3]);
		new_rule->hsp = getPortMax(tokens[3]);
		new_rule->ldp = getPortMin(tokens[6]);
		new_rule->hdp = getPortMax(tokens[6]);
		
		if (tokens[4][0] == '<')		// is '<>'
			new_rule->dir = BI_DIR;
		else							// is '->'
			new_rule->dir = UNI_DIR;


		opt_head = getOptionList(tokens[7]);
		PopulateOptions( new_rule, opt_head);

		DumpRule(new_rule);


		/*  Add the rule to the appropriate linked list (icmp, tcp or udp) */
		if (*node_ptr == NULL)  
			*node_ptr = new_rule;
		else
		{
			node = *node_ptr;
			while (node->next != NULL)  
				node = node->next;
			node->next = new_rule;
		}


		/* delete the keyword/value list (no longer needed) */
		opt_cptr = opt_head;
		while (opt_cptr != NULL)
		{
			opt_pptr = opt_cptr;
			opt_cptr= opt_cptr->next;
			free(opt_pptr);
		}

		free(tokens);

		debug("done generating this rule\r\n");
	}

	/* free up memory allocated for variables */
	while (var_list != NULL)
	{
		free(var_list->keyword);
		free(var_list->value);
		opt_pptr = var_list;
		var_list = var_list->next;
		free(opt_pptr);
	}

	return TRUE;
}


void DestroyRules()
{
	DestroyRulesChain(&root.alert);
	DestroyRulesChain(&root.counter);
	DestroyRulesChain(&root.log);

	memset(&root, 0, sizeof(root));
}


void DestroyRulesChain(RulesHead *rules_head)
{
	RuleNode *prev_rule, *cur_rule;

	/*  free up rule nodes */
	cur_rule = rules_head->IcmpList;
	while (cur_rule != NULL)
	{
		prev_rule = cur_rule;
		cur_rule = cur_rule->next;
		if (prev_rule->msg_set)  free(prev_rule->msg);
		if (prev_rule->content_set)  free(prev_rule->content);
		free(prev_rule);
	}

	cur_rule = rules_head->TcpList;
	while (cur_rule != NULL)
	{
		prev_rule = cur_rule;
		cur_rule = cur_rule->next;
		if (prev_rule->msg_set)  free(prev_rule->msg);
		if (prev_rule->content_set)  free(prev_rule->content);
		free(prev_rule);
	}

	cur_rule = rules_head->UdpList;
	while (cur_rule != NULL)
	{
		prev_rule = cur_rule;
		cur_rule = cur_rule->next;
		if (prev_rule->msg_set)  free(prev_rule->msg);
		if (prev_rule->content_set)  free(prev_rule->content);
		free(prev_rule);
	}

	cur_rule = rules_head->ArpList;
	while (cur_rule != NULL)
	{
		prev_rule = cur_rule;
		cur_rule = cur_rule->next;
		if (prev_rule->msg_set)  free(prev_rule->msg);
		if (prev_rule->content_set)  free(prev_rule->content);
		free(prev_rule);
	}
}



void AddToVarList(char *var, char *value)
{
	KeyVal *node, *ptr;

	node = malloc(sizeof(KeyVal));
	node->keyword = malloc(lstrlen(var) + 1);
	node->value = malloc(lstrlen(value) + 1);
	node->next = NULL;
	lstrcpy(node->keyword, var);
	lstrcpy(node->value, value);

	if (var_list == NULL)
	{
		var_list = node;
		return;
	}

	ptr = var_list;
	while(ptr->next != NULL)  ptr = ptr->next;
	ptr->next = node;
}




int getnumtokens(char *str)
{
	BOOL stop_counting = FALSE;
	int i, len, num_tokens = 1;

	/* first see how many tokens we have */
	len = lstrlen(str);
	for (i = 0; i < len; i++)
	{
		if (str[i] == '(')  stop_counting = TRUE;
		if (str[i] == ')')  stop_counting = FALSE;

		if ((str[i] == ' ') && (stop_counting == FALSE))  
			++num_tokens;
	}

	return num_tokens;
}




/*
	Splits the string 'str' into tokens, i.e replaces spaces with 
	'\0' so that we have separate strings.  
	
	 Returns:
	   Fills num with number of tokens found.
	   An array of char pointers, each pointing to a new token.

	Note:  the original string is destroyed
*/
char **gettokens(char *str, int *num)
{
	BOOL stop_counting = FALSE;
	int i, len, j=0, num_tokens = 1;
	char **tokens;

	num_tokens = getnumtokens(str);
	tokens = malloc(num_tokens * sizeof(char *));

	/* fill the tokens array with pointers to individual tokens */
	tokens[0] = str;
	len = lstrlen(str);
	for (i = 0; i < len; i++)
	{
		if (str[i] == '(')  stop_counting = TRUE;
		if (str[i] == ')')  stop_counting = FALSE;

		if ((str[i] == ' ') && (stop_counting == FALSE))  
		{
			str[i] = '\0';
			tokens[++j] = &str[i+1];
		}
	}

	*num = num_tokens;
	return tokens;
}


/* 
   Creates a linked list of KeyVal, each node containing 
   the keyword and its corresponding value.  Caller must free 
   up the memory when its done using this list
   
	 Note: say bye-bye to the optstr - numerous \0 will be inserted!

   TO DO:  put lots of safe-guards 
*/

KeyVal *getOptionList(char *optstr)
{
	KeyVal *head, *curptr, *prevptr;
	char *start, *end, c, *dead;
	int len;

	head = NULL;
	len = lstrlen(optstr);
	start = optstr;
	end = &optstr[len-1];
	dead = optstr + len;

	/* 
		Get rid of trailing useless stuff like (, ), CR, LF etc 
		Note that if the open or close brackets are missing, the 
		program will bomb.  FIX THIS!
	*/
	while ((*start != '(') && (start < dead))	++start;
	++start;
	while ((*end != ')') && (end > optstr))		--end;
	*end = '\0';

	if (start > end)  return NULL;  // ERROR occurred

	curptr = head;
	prevptr = head;


	while (start != '\0')
	{
		/* get the keyword */
		while ((*start == ' ') && (start < dead))  ++start;
		if (*start == '\0') break;

		curptr = malloc(sizeof(KeyVal));
		curptr->keyword = NULL;
		curptr->value = NULL;
		curptr->next = NULL;
		if (prevptr != NULL)    prevptr->next = curptr;
		if (head == NULL)		head = curptr;
		prevptr = curptr;

		end = start;

		while ((*end != ':') && (*end != ';') && (end < dead))  ++end;
		c = *end;
		*end = '\0';
		curptr->keyword = start;


		start = end + 1;
		
		if (c == ';')  	continue; // this keyword has no value (eg nocase;)
			
		
		/* get the value */
		start = end + 1;
		while ((*start == ' ') && (start < dead))  ++start;
		end = start;
		while ((*end != ';') && (end < dead))  ++end;  // make sure we don't go beyond
		*end = '\0';

		curptr->value = start;
			
		start = end+1;
	}

	return head;
}


char *getValue(char *var)
{
	KeyVal *ptr;

	ptr = var_list;

	while (ptr != NULL)
	{
		if (!lstrcmp(ptr->keyword, &var[1]))  //skip the '$' character
			return ptr->value;

		ptr = ptr->next;
	}

	return NULL;
}


void PopulateOptions(RuleNode *options, KeyVal *list)
{

	while (list != NULL)
	{
		if (list->value && (lstrlen(list->value) > 1)) 
			if (list->value[0] == '$')		// its a var
				list->value = getValue(list->value);

		if (!lstrcmp(list->keyword, "msg"))
		{
			if (list->value != NULL)
			{
				list->value[lstrlen(list->value)-1] = '\0';
				options->msg_set = TRUE;
				options->msg = malloc(lstrlen(list->value));
				lstrcpy(options->msg, &list->value[1]);
			}
		}
		else if (!lstrcmp(list->keyword, "content"))
		{
			if (list->value != NULL)
			{
				list->value[lstrlen(list->value)-1] = '\0';
				options->content_set = TRUE;
				options->content = malloc(lstrlen(list->value));
				lstrcpy(options->content, &list->value[1]);
			}
		}
		else if (!lstrcmp(list->keyword, "counter_id"))
		{
			options->counter_id = atoi(list->value);
			if ((options->counter_id >=0) && (options->counter_id <=255))
				options->counter_id_set = TRUE;
		}
		else if (!lstrcmp(list->keyword, "depth"))
		{
			options->depth_set = TRUE;
			options->depth = atoi(list->value);
		}
		else if (!lstrcmp(list->keyword, "offset"))
		{
			options->offset_set = TRUE;
			options->offset = atoi(list->value);
		}
		else if (!lstrcmp(list->keyword, "ttl"))
		{
			options->ttl_set = TRUE;
			options->ttl = atoi(list->value);
		}
		else if (!lstrcmp(list->keyword, "tos"))
		{
			options->tos_set = TRUE;
			options->tos = atoi(list->value);
		}
		else if (!lstrcmp(list->keyword, "id"))
		{
			options->id_set = TRUE;
			options->id = atoi(list->value);
		}
		else if (!lstrcmp(list->keyword, "ipopts"))
		{
			// WRITE THIS
		}
		else if (!lstrcmp(list->keyword, "fragbits"))
		{
			options->fragbits_set = TRUE;
			options->fragbits = getFragbits(list->value, &options->fragbits_op);
		}
		else if (!lstrcmp(list->keyword, "dsize"))
		{
			options->dsize_set = TRUE;
			options->dsize = atoi(list->value);
		}
		else if (!lstrcmp(list->keyword, "flags"))
		{
			options->flags_set = TRUE;
			options->flags = getFlags(list->value, &options->flags_op);
		}
		else if (!lstrcmp(list->keyword, "seq"))
		{
			options->seqnum_set = TRUE;
			options->seqnum = atoi(list->value);
		}
		else if (!lstrcmp(list->keyword, "ack"))
		{
			options->acknum_set = TRUE;
			options->acknum = atoi(list->value);
		}
		else if (!lstrcmp(list->keyword, "itype"))
		{
			options->itype_set = TRUE;
			options->itype = atoi(list->value);
		}
		else if (!lstrcmp(list->keyword, "icode"))
		{
			options->icode_set = TRUE;
			options->icode = atoi(list->value);
		}
		else if (!lstrcmp(list->keyword, "icmp_id"))
		{
			options->icmp_id_set = TRUE;
			options->icmp_id = atoi(list->value);
		}
		else if (!lstrcmp(list->keyword, "icmp_seq"))
		{
			options->icmp_seq_set = TRUE;
			options->icmp_seq = atoi(list->value);
		}

		list = list->next;
	}
}



void DumpRule(RuleNode *rule_node)
{
	char str[128];

	if (rule_node == NULL) {
		debug("Rule Node is NULL\r\n\r\n");
		return;
	}

	wsprintf(str, "cur ptr:\t %d\r\n", rule_node);
	debug(str);
	wsprintf(str, "next ptr:\t %d\r\n", rule_node->next ? rule_node->next:0);
	debug(str);
	wsprintf(str, "src ip:\t\t %c%s\r\n", rule_node->sip_op, IpToString(rule_node->sip));
	debug(str);
	wsprintf(str, "src mask:\t %s\r\n", IpToString(rule_node->smask));
	debug(str);
	wsprintf(str, "dst ip:\t\t %c%s\r\n", rule_node->dip_op, IpToString(rule_node->dip));
	debug(str);
	wsprintf(str, "dst mask:\t %s\r\n", IpToString(rule_node->dmask));
	debug(str);
	wsprintf(str, "src ports:\t %d - %d\r\n", ntohs(rule_node->lsp), ntohs(rule_node->hsp));
	debug(str);
	wsprintf(str, "dst ports:\t %d - %d\r\n", ntohs(rule_node->ldp), ntohs(rule_node->hdp));
	debug(str);
	if (rule_node->dir == UNI_DIR)  debug("direction:\t '->'\r\n");
	else debug("direction:\t '<>'\r\n");

	if (rule_node->offset_set)  {
		wsprintf(str, "offset:\t\t %d\r\n", rule_node->offset);
		debug(str);
	}
	if (rule_node->depth_set)  {
		wsprintf(str, "depth:\t\t %d\r\n", rule_node->depth);
		debug(str);
	}
	if (rule_node->dsize_set)  {
		wsprintf(str, "dsize:\t\t %s\r\n", rule_node->dsize);
		debug(str);
	}
	if (rule_node->msg_set)  {
		wsprintf(str, "msg:\t\t %s\r\r\n", rule_node->msg);
		debug(str);
	}
	if (rule_node->content_set)  {
		wsprintf(str, "content:\t %s\r\n", rule_node->content);
		debug(str);
	}
	if (rule_node->ttl_set)  {
		wsprintf(str, "ttl:\t\t %d\r\n", rule_node->ttl);
		debug(str);
	}
	if (rule_node->tos_set)  {
		wsprintf(str, "tos:\t\t %d\r\n", rule_node->tos);
		debug(str);
	}
	if (rule_node->id_set)  {
		wsprintf(str, "id:\t\t %d\r\n", rule_node->id);
		debug(str);
	}
	if (rule_node->ipopts_set)  {
		wsprintf(str, "ipopts:\t\t %d\r\n", rule_node->ipopts);
		debug(str);
	}
	if (rule_node->fragbits_set)  {
		wsprintf(str, "fragbits:\t 0x%x\r\n", rule_node->fragbits);
		debug(str);
	}
	if (rule_node->flags_set)  {
		wsprintf(str, "flags:\t\t %x\r\n", rule_node->flags);
		debug(str);
	}
	if (rule_node->seqnum_set)  {
		wsprintf(str, "seq:\t\t %d\r\n", rule_node->seqnum);
		debug(str);
	}
	if (rule_node->acknum_set)  {
		wsprintf(str, "ack:\t\t %d\r\n", rule_node->acknum);
		debug(str);
	}
	if (rule_node->itype_set)  {
		wsprintf(str, "itype:\t\t %d\r\n", rule_node->itype);
		debug(str);
	}
	if (rule_node->icode_set)  {
		wsprintf(str, "icode:\t\t %d\r\n", rule_node->icode);
		debug(str);
	}
	if (rule_node->icmp_id_set)  {
		wsprintf(str, "icmp_id:\t %d\r\n", rule_node->icmp_id);
		debug(str);
	}
	if (rule_node->icmp_seq_set)  {
		wsprintf(str, "icmp_seq:\t %d\r\n", rule_node->icmp_seq);
		debug(str);
	}

	debug("\r\n------------------------------------------------------\r\n\r\n"); 

}





/*
	Takes a string like !192.168.0.1/24 and the operator NOT ('!') if
	specified.  Otherwise, it returns ' '
*/
char getIPop(char *ip)
{
	if (ip[0] == '!')
		return '!';
	
	return (' ');
}



/*
	Takes a string like !192.168.0.1/24 and returns a 32-bit
	IP address
*/
u_long getIP(char *ip)
{
	char *ptr;
	char str[64];

	if (*ip == '!')		// skip this character
		++ip;

	lstrcpy(str, ip);  // copy string into a buffer 

	if (lstrcmp(str, "any") == 0)  return 0;
	
	ptr = str;
	while ((*ptr != '/') && (*ptr != '\0')) 
		++ptr;
	*ptr = '\0';
	
	return (inet_addr(str));
}



/*
	Takes a string like 192.168.0.1/24 and returns a 32-bit
	mask in network byte order.
*/
u_long getMask(char *str)
{
	u_long mask = 0xffffffff;
	char *mask_str;
	int nBits;

	if (lstrcmp(str, "any") == 0)  return 0;
	
	mask_str = str;
	
	while ((*mask_str != '/') && (*mask_str != '\0')) 
		++mask_str;
	++mask_str;

	nBits = atoi(mask_str);

	return (ntohl(mask << (32-nBits)));
}



/*
	Takes a string like 24:66 and returns the lower of the 
	port range in network byte order.  Also handles strings 
	such as :6000 and 6000: and 115.
*/
u_short getPortMin(char *str)
{
	return ntohs((u_short) atoi(str));
}


/*
	Takes a string like 24:66 and returns the upper end of the 
	port range in network byte order.  Also handles strings such 
	as :6000 and 6000: and 115.
*/
u_short getPortMax(char *str)
{
	int i;

	if (lstrcmp(str, "any") == 0)  return ntohs(65535);
	
	for (i = 0; i < lstrlen(str); i++)
		if (str[i] == ':')
			break;

	if (str[i] != ':')  return ntohs((u_short) atoi(str));

	if (str[i+1] == '\0') return ntohs(65535);

	return ntohs((u_short) atoi(&str[i+1]));
}




u_char getFragbits(char *str, char *op)
{
	u_char fragbits =  0x00;
	int i;

	for (i = 0; i < lstrlen(str); i++)
	{
		if (str[i] == 'R')	fragbits |= R_RF;
		if (str[i] == 'D')	fragbits |= R_DF;
		if (str[i] == 'M')	fragbits |= R_MF;

		if ((str[i] == '+') || (str[i] == '*') || (str[i] == '!'))
			*op = str[i];
	}

	return fragbits;
}



u_short getIpOpts(char *str)
{
	u_short ipopt = 0;

	if (!lstrcmp(str, "rr"))
		ipopt = R_RR;
	else if (!lstrcmp(str, "eol"))
		ipopt = R_EOL;
	else if (!lstrcmp(str, "nop"))
		ipopt = R_NOP;
	else if (!lstrcmp(str, "ts"))
		ipopt = R_TS;
	else if (!lstrcmp(str, "sec"))
		ipopt = R_SEC;
	else if (!lstrcmp(str, "lsrr"))
		ipopt = R_LSRR;
	else if (!lstrcmp(str, "ssrr"))
		ipopt = R_SSRR;
	else if (!lstrcmp(str, "satid"))
		ipopt = R_SATID;

	return ipopt;
}



u_char getFlags(char *str, char *op)
{
	u_char flags = 0x00;
	int i;

	for (i = 0; i < lstrlen(str); i++)
	{
		if (str[i] == 'F')	flags |= R_FIN;
		if (str[i] == 'S')	flags |= R_SYN;
		if (str[i] == 'R')	flags |= R_RST;
		if (str[i] == 'P')	flags |= R_PSH;
		if (str[i] == 'A')	flags |= R_ACK;
		if (str[i] == 'U')	flags |= R_URG;
		if (str[i] == '2')	flags |= R_RES2;
		if (str[i] == '1')	flags |= R_RES1;

		if ((str[i] == '+') || (str[i] == '*') || (str[i] == '!'))
			*op = str[i];
	}

	return flags;
}



VOID SetupCounters(HWND hWndList)
{
	RuleNode	*node_ptr;
	RulesHead	*rules_head;
	LV_ITEM		lvI;
	int			index = 0;
	char		str[4];


	lvI.mask = LVIF_TEXT;
	ListView_DeleteAllItems(hWndList);

	rules_head = &root.counter;

	/* Fill tables with blanks first.  We will update these later */
	for (index = 0; index < 256; index++)
	{
		wsprintf(str, "%d", index);

		lvI.iItem = index;
		lvI.iSubItem = 0;
		lvI.pszText = str; 
		lvI.cchTextMax = 64;

		ListView_InsertItem(hWndList, &lvI);
		ListView_SetItemText( hWndList, index, 1, "-");
		ListView_SetItemText( hWndList, index, 2, "-");
		ListView_SetItemText( hWndList, index, 3, "-");
		ListView_SetItemText( hWndList, index, 4, "-");
		ListView_SetItemText( hWndList, index, 5, "-");
	}


	/* zero out the entire counter structure */
	memset(counter, 0, sizeof(counter));


	/* Update rows in the table for which counter rules have been defined */
	node_ptr = rules_head->TcpList;
	while (node_ptr != NULL)
	{
		if (node_ptr->counter_id_set)
		{
			index = node_ptr->counter_id;
			lstrcpy(counter[index].msg, node_ptr->msg);
			ListView_SetItemText( hWndList, index, 1, counter[index].msg);
		}
		node_ptr = node_ptr->next;
	}

	node_ptr = rules_head->UdpList;
	while (node_ptr != NULL)
	{
		if (node_ptr->counter_id_set)
		{
			index = node_ptr->counter_id;	
			lstrcpy(counter[index].msg, node_ptr->msg);
			ListView_SetItemText( hWndList, index, 1, counter[index].msg);
		}
		node_ptr = node_ptr->next;
	}

	node_ptr = rules_head->IcmpList;
	while (node_ptr != NULL)
	{
		if (node_ptr->counter_id_set)
		{
			index = node_ptr->counter_id;
			lstrcpy(counter[index].msg, node_ptr->msg);
			ListView_SetItemText( hWndList, index, 1, counter[index].msg);
		}
		node_ptr = node_ptr->next;
	}

	node_ptr = rules_head->ArpList;
	while (node_ptr != NULL)
	{
		if (node_ptr->counter_id_set)
		{
			index = node_ptr->counter_id;
			lstrcpy(counter[index].msg, node_ptr->msg);
			ListView_SetItemText( hWndList, index, 1, counter[index].msg);
		}
		node_ptr = node_ptr->next;
	}

}



VOID SetupDefaultRules()
{
	memset(&rule_text, 0, sizeof(rule_text));

	lstrcpy(rule_text[0].rule, "alert arp any any -> any any ()");
	rule_text[0].bEnabled = TRUE;
	lstrcpy(rule_text[1].rule, "alert udp any any -> any any ()");
	rule_text[1].bEnabled = TRUE;
	lstrcpy(rule_text[2].rule, "alert tcp any any -> any any ()");
	rule_text[2].bEnabled = TRUE;
	lstrcpy(rule_text[3].rule, "alert icmp any any -> any any ()");
	rule_text[3].bEnabled = TRUE;

	lstrcpy(rule_text[4].rule, "counter arp any any -> any any (counter_id:1; msg:\"arp traffic\";)");
	rule_text[4].bEnabled = TRUE;
	lstrcpy(rule_text[5].rule, "counter udp any any -> any any (counter_id:2; msg:\"udp traffic\";)");
	rule_text[5].bEnabled = TRUE;
	lstrcpy(rule_text[6].rule, "counter tcp any any -> any any (counter_id:3; msg:\"tcp traffic\";)");
	rule_text[6].bEnabled = TRUE;
	lstrcpy(rule_text[7].rule, "counter icmp any any -> any any (counter_id:4; msg:\"icmp traffic\";)");
	rule_text[7].bEnabled = TRUE;
}



void PopulateRulesList(HWND hWndList, int nSelected)
{
	int i;
	LV_ITEM		lvI;
	
	lvI.mask = LVIF_TEXT;
	lvI.iSubItem = 0; 
	lvI.cchTextMax = 255;

	ListView_DeleteAllItems(hWndList);

	for(i = 0; i < 256; i++)
	{
		if (rule_text[i].rule[0] == '\0')  break;
		
		i = ListView_GetItemCount(hWndList);
		lvI.iItem = i;
		lvI.pszText = rule_text[i].rule;
		ListView_InsertItem(hWndList, &lvI);
			
		if (rule_text[i].bEnabled)
			ListView_SetCheckState(hWndList, i, TRUE);

		if (i == nSelected)
			ListView_SetItemState(hWndList, i, LVIS_SELECTED, LVIS_SELECTED);
	}
}




BOOL CALLBACK RulesDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	int			i, iCount;
	char		str[256];
	static HWND	hWndList;
	LV_COLUMN	lvC;
	LV_ITEM		lvI;
	LV_DISPINFO *pItem;
	char		tempString1[256], tempString2[256];

	switch (uMsg)
	{
	case WM_INITDIALOG:
		hWndList = GetDlgItem(hDlg, IDC_LIST);
		ListView_SetExtendedListViewStyleEx(hWndList, LVS_EX_GRIDLINES, LVS_EX_GRIDLINES );
		ListView_SetExtendedListViewStyleEx(hWndList, LVS_EX_CHECKBOXES, LVS_EX_CHECKBOXES  );
		lvC.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT; 
	
		lvC.cx = 525;       
		lvC.pszText = "Rule";
		lvC.iSubItem = 0;
		lvC.fmt = LVCFMT_LEFT;
		ListView_InsertColumn(hWndList, 0, &lvC);

		PopulateRulesList(hWndList, 0);

		SendDlgItemMessage(hDlg, IDC_RULE, EM_SETLIMITTEXT, (WPARAM) 255, 0);

		if (bEnableFilter == TRUE)
			CheckRadioButton(hDlg, IDC_RADIO_FILTER, IDC_RADIO_NOFILTER, IDC_RADIO_FILTER);
		else
		{
			CheckRadioButton(hDlg, IDC_RADIO_FILTER, IDC_RADIO_NOFILTER, IDC_RADIO_NOFILTER);
			SendMessage(hDlg, WM_COMMAND, MAKEWPARAM(IDC_RADIO_NOFILTER, 0), 0);
		}
		
		RestoreWindowPosition(hDlg);

		return TRUE;



	case WM_NOTIFY: 
        switch (((LPNMHDR) lParam)->code) 
		{
        case LVN_ENDLABELEDIT:
            pItem = (LV_DISPINFO *) lParam;
			ListView_SetItemText(hWndList, pItem->item.iItem, 0, pItem->item.pszText);
            return TRUE;
		}
		break;



	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_ADD:
			GetDlgItemText(hDlg, IDC_RULE, str, 255);
			iCount = getnumtokens(str);

			if ((iCount != 8) && (iCount != 3)) 
			{
				MessageBox(hDlg, "Incorrect number of parameters, please correct rule.", APP_NAME, MB_ICONEXCLAMATION | MB_OK);
				return TRUE;
			}
			
			lvI.mask = LVIF_TEXT;
			lvI.iSubItem = 0; 
			lvI.cchTextMax = 255;

			i = ListView_GetItemCount(hWndList);
			lvI.iItem = i;
			lvI.pszText = str;
			ListView_InsertItem(hWndList, &lvI);

			SetDlgItemText(hDlg, IDC_RULE, "");
			ListView_SetCheckState(hWndList, i, TRUE);
			ListView_EnsureVisible(hWndList, i, FALSE);
			return TRUE;


		case IDC_DELETE:
			lvI.mask = LVIF_STATE;
			lvI.stateMask =LVIS_SELECTED;
			lvI.iSubItem = 0;
			
			iCount = ListView_GetItemCount( hWndList );
			for( i = 0; i < iCount; i++ )           
			{        
				lvI.iItem = i;
				ListView_GetItem(hWndList, &lvI);
				if( lvI.state == LVIS_SELECTED )
				{
					ListView_DeleteItem(hWndList, i);
					--iCount;  --i;
				}
			}
			return TRUE;


		case IDC_CANCEL:
			SaveWindowPosition(hDlg);
			EndDialog(hDlg, FALSE);
			return TRUE;


		case IDC_SAVE:
			lvI.mask = LVIF_TEXT;
			lvI.iSubItem = 0; 
			lvI.cchTextMax = 255;

			memset(rule_text, 0, sizeof(rule_text));
			iCount = ListView_GetItemCount(hWndList);
			for (i = 0; i < iCount; i++)
			{
				lvI.iItem = i;
				lvI.pszText = rule_text[i].rule;
				ListView_GetItem(hWndList, &lvI);
				rule_text[i].bEnabled = ListView_GetCheckState(hWndList, i);
			}

			if (SendDlgItemMessage(hDlg, IDC_RADIO_FILTER, BM_GETCHECK, 0, 0) == BST_CHECKED)
				bEnableFilter = TRUE;
			else
				bEnableFilter = FALSE;

			SaveWindowPosition(hDlg);
			EndDialog(hDlg, TRUE);
			return TRUE;


		case IDC_RADIO_NOFILTER:
			EnableWindow(GetDlgItem(hDlg, IDC_ADD), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDC_DELETE), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDC_RULE), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDC_MOVEUP), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDC_MOVEDOWN), FALSE);
			EnableWindow(GetDlgItem(hDlg, IDC_DEFAULT), FALSE);
			EnableWindow(hWndList, FALSE);
			return TRUE;


		case IDC_RADIO_FILTER:
			EnableWindow(GetDlgItem(hDlg, IDC_ADD), TRUE);
			EnableWindow(GetDlgItem(hDlg, IDC_DELETE), TRUE);
			EnableWindow(GetDlgItem(hDlg, IDC_RULE), TRUE);
			EnableWindow(GetDlgItem(hDlg, IDC_MOVEUP), TRUE);
			EnableWindow(GetDlgItem(hDlg, IDC_MOVEDOWN), TRUE);
			EnableWindow(GetDlgItem(hDlg, IDC_DEFAULT), TRUE);
			EnableWindow(hWndList, TRUE);
			return TRUE;


		case IDC_MOVEUP:
			iCount = ListView_GetItemCount( hWndList );
			for( i = 1; i < iCount; i++ )           
			{        
				if( ListView_GetItemState(hWndList, i, LVIS_SELECTED) == LVIS_SELECTED )
				{
					ListView_GetItemText(hWndList, i-1, 0, tempString1, sizeof(tempString1));
					ListView_GetItemText(hWndList, i,   0, tempString2, sizeof(tempString2));
					ListView_SetItemText(hWndList, i-1, 0, tempString2);
					ListView_SetItemText(hWndList, i,   0, tempString1);

					ListView_SetItemState(hWndList, i-1, LVIS_SELECTED, LVIS_SELECTED	);
					ListView_SetItemState(hWndList, i, 0, LVIS_SELECTED);

					break;
				}
			}
			return TRUE;


		case IDC_MOVEDOWN:
			iCount = ListView_GetItemCount( hWndList );
			for( i = iCount-2; i >= 0; i-- )           
			{        
				if( ListView_GetItemState(hWndList, i, LVIS_SELECTED) == LVIS_SELECTED )
				{
					ListView_GetItemText(hWndList, i+1, 0, tempString1, sizeof(tempString1));
					ListView_GetItemText(hWndList, i,   0, tempString2, sizeof(tempString2));
					ListView_SetItemText(hWndList, i+1, 0, tempString2);
					ListView_SetItemText(hWndList, i,   0, tempString1);

					ListView_SetItemState(hWndList, i+1, LVIS_SELECTED, LVIS_SELECTED);
					ListView_SetItemState(hWndList, i, 0, LVIS_SELECTED);
					break;
				}
			}
			return TRUE;


		case IDC_DEFAULT:
			i = MessageBox(hDlg, "This action will erase existing rules.  Proceed with setting up default rules?", "Network Spy", MB_YESNO | MB_ICONWARNING);
			if (i == IDYES)
			{
				SetupDefaultRules();
				PopulateRulesList(hWndList, 0);
			}
			return TRUE;

		}
		break;

	
	case WM_CLOSE:
		SaveWindowPosition(hDlg);
		EndDialog(hDlg, 0);
		return TRUE;
	
	}
	return FALSE;
}


