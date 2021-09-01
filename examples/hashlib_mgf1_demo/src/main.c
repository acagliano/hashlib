/*
 *--------------------------------------
 * Program Name:
 * Author:
 * License:
 * Description:
 *--------------------------------------
*/

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <hashlib.h>
#include <debug.h>

#define CEMU_CONSOLE ((char*)0xFB0000)
char hexc[16] = "0123456789ABCDEF";
uint8_t str[] = "The daring fox jumped over the dog.";
char mgf1_test[] = {0x5a,0x92,0x18,0xc4,0x5d,0x86,0x62,0xab,0x2b,0x61,0x04,0x70,0x55,0x05,0x14,0x3a,0x04,0x62,0x6f,0xef,0xec,0x94,0x1b,0x49,0x44,0xc3,0xb8,0x21,0x5b,0xcf,0x3b,0x98,0x75,0xd8,0x74,0x34,0x41,0xb6,0x3d,0x33,0xcb,0xe8,0x28,0xd1,0x3b,0xbc,0xc0,0x3b,0x3a,0xf8};



void tohex(char *sbuf, uint8_t *src, size_t len)
{
	int i;
	int j=0;
	for (i=0; i<len; i++) {
		sbuf[j++] = hexc[src[i]>>4];
		sbuf[j++] = hexc[src[i]&15];
	}
	sbuf[j] = 0;
}

int main(void)
{
	char *sbuf;
	char outbuf[50];
    size_t str_len = strlen(str);
	if (!(sbuf = malloc(100 + 1))) return 1;

	// sprintf(CEMU_CONSOLE, "SHA_CTX Addr: %u\nSHA_CTX EndAddr: %u\n", &sha256, (uint24_t)&sha256 + sizeof(sha256)-1);
    // (*(uint8_t*)-1) = 2;

    sprintf(CEMU_CONSOLE, "The string is '%s'.\n", str);
    sprintf(CEMU_CONSOLE, "Its size is: %u\n", str_len);
    
    hashlib_MGF1Hash(str, str_len, outbuf, 50);

	tohex(sbuf, outbuf, 50);
	sprintf(CEMU_CONSOLE, "MGF1:  %s \n", sbuf);
	
	if(hashlib_CompareDigest(outbuf, mgf1_test, 50))
		strcpy(CEMU_CONSOLE, "MGF1 correct");
    strcpy(CEMU_CONSOLE, "\n");
}
