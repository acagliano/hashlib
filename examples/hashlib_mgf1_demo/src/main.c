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
uint8_t str[] = "The daring fox jumped over the dog.";
uint8_t mgf1_test[] = {0x5a,0x92,0x18,0xc4,0x5d,0x86,0x62,0xab,0x2b,0x61,0x04,0x70,0x55,0x05,0x14,0x3a,0x04,0x62,0x6f,0xef,0xec,0x94,0x1b,0x49,0x44,0xc3,0xb8,0x21,0x5b,0xcf,0x3b,0x98,0x75,0xd8,0x74,0x34,0x41,0xb6,0x3d,0x33,0xcb,0xe8,0x28,0xd1,0x3b,0xbc,0xc0,0x3b,0x3a,0xf8};

void hexdump(uint8_t *addr, size_t len, char *label){
    if(label) sprintf(CEMU_CONSOLE, "\n%s\n", label);
    else sprintf(CEMU_CONSOLE, "\n");
    for(size_t rem_len = len, ct=1; rem_len>0; rem_len--, addr++, ct++){
        sprintf(CEMU_CONSOLE, "%02X ", *addr);
        if(!(ct%AES_BLOCKSIZE)) sprintf(CEMU_CONSOLE, "\n");
    }
    sprintf(CEMU_CONSOLE, "\n");
}


int main(void)
{
	char outbuf[50];
    size_t str_len = strlen(str);
    
    hashlib_MGF1Hash(str, str_len, outbuf, 50);

	hexdump(outbuf, sizeof outbuf, "-MGF1 output-");
	
	if(hashlib_CompareDigest(outbuf, mgf1_test, 50))
		strcpy(CEMU_CONSOLE, "MGF1 correct");
    strcpy(CEMU_CONSOLE, "\n");
}
