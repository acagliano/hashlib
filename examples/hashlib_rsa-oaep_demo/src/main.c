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

void hexdump(uint8_t *addr, size_t len, uint8_t *label){
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
	uint8_t encoded[256];
	uint8_t decoded[256];
	sprintf(CEMU_CONSOLE, "\n\n----------------------------------\nHashlib OAEP Demo\n");
	hexdump(str, strlen(str), "---Original String---");
	if(hashlib_RSAEncodeOAEP(str, strlen(str), encoded, 256, NULL))
		hexdump(encoded, 256, "---OAEP Encoded---");
	else sprintf(CEMU_CONSOLE, "encode error");
	if(hashlib_RSADecodeOAEP(encoded, 256, decoded, NULL))
		sprintf(CEMU_CONSOLE, "%s\n", decoded);
	else sprintf(CEMU_CONSOLE, "decode error");
	hexdump(decoded, 256, "---OAEP Decoded---");
}
