#ifndef _C_RUNTIME_H
#define _C_RUNTIME_H

// NELSON - why use these instead of the built-in CRT functions?  NOTDONE

void *malloc(unsigned int size);
void *realloc(void *, unsigned int size);
void free (void *);

/* NELSON - removed - to use CRT instead - NOTDONE - why are these used instead?
char *strrchr(char *str, char c);
char *strchr(char *str, char c);
*/

#endif