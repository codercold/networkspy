#include <windows.h>
#include "c-runtime.h"

void * malloc(unsigned int size)
{
	return HeapAlloc(GetProcessHeap(),0,size);
}


void free(void *ptr)
{
	if (ptr)
		HeapFree(GetProcessHeap(),0,ptr);
}

void *realloc(void *ptr, unsigned int size)
{
	return HeapReAlloc(GetProcessHeap(),0,ptr,size);
}

/* NELSON - removed - to use CRT instead - NOTDONE - why are these used instead?
char *strrchr(char *str, char c)
{
	int i, len;

	len = lstrlen(str);
	for (i = len-1; i >= 0; i--)
		if (str[i] == c)
			return (&str[i]);

	return NULL;
}

char *strchr(char *str, char c)
{
	int i, len;

	len = lstrlen(str);
	for (i = 0; i < len; i++)
		if (str[i] == c)
			return (&str[i]);

	return NULL;
}
*/


/* Note: works for unsigned numbers only */

/* NELSON - commented out so we use the CRT built-in function - NOTDONE - why was this here?
int atoi(const char *str)
{
	int i, len, num_len, tens = 1, sum = 0;

	num_len = 0;
	len = lstrlen(str);
	for (i = 0; i < len; i++)
	{
		if ((str[i] < '0') || (str[i] > '9'))
			break;
		++num_len;
	}

	if (num_len == 0)  return 0;

	for (i = num_len - 1; i >= 0; i--)
	{
		sum = sum + (tens * (str[i] - 48));
		tens = tens * 10;
	}

	return sum;
}
*/