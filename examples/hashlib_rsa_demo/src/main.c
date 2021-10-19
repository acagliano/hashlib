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
#define MODSIZE 256
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
	uint8_t padded[MODSIZE];
	uint8_t encrypted[MODSIZE];
    uint8_t pubkey[MODSIZE];
    hashlib_RandomBytes(pubkey, MODSIZE);
	sprintf(CEMU_CONSOLE, "\n\n----------------------------------\nHashlib RSA Demo\n");
	hexdump(str, strlen(str), "---Original String---");
	if(hashlib_RSAEncodeOAEP(str, strlen(str), padded, MODSIZE, NULL))
		hexdump(padded, MODSIZE, "---OAEP Encoded---");
	else sprintf(CEMU_CONSOLE, "encode error");
	if(hashlib_RSAEncrypt(encrypted, padded, MODSIZE, pubkey, MODSIZE))
        hexdump(encrypted, MODSIZE, "---RSA Encrypted---");
    else sprintf(CEMU_CONSOLE, "encryption error");
}
