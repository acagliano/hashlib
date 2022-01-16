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

#define CEMU_CONSOLE ((char*)0xFB0000)
#define MODSIZE 256

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
    uint8_t str[] = "The daring fox jumped over the dog.";
	uint8_t ciphertext[MODSIZE];
    uint8_t pubkey[MODSIZE];
    
    // this is for testing purposes, but this is not how you generate an RSA key.
    // such a key should be odd and prime.
    // may output encryption error
    hashlib_RandomBytes(pubkey, MODSIZE);
    pubkey[MODSIZE-1] |= 1;
    
	sprintf(CEMU_CONSOLE, "\n\n----------------------------------\nHashlib RSA Demo\n");
	hexdump(str, strlen(str), "---Original String---");
	if(hashlib_RSAEncrypt(str, strlen(str), ciphertext, pubkey, MODSIZE)==RSA_OK)
        hexdump(ciphertext, MODSIZE, "---RSA Encrypted---");
    else sprintf(CEMU_CONSOLE, "encryption error");
}
