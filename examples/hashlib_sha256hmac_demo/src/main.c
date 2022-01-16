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
uint8_t* str = "testing12345";
uint8_t* hmac_keystr = "testpass1";

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
    hmac_ctx hmac;
    uint8_t sha256_digest[SHA256_DIGEST_LEN];

    hashlib_HMACSha256Init(&hmac, hmac_keystr, strlen(hmac_keystr));
    hashlib_HMACSha256Update(&hmac, str, strlen(str));
    hashlib_HMACSha256Final(&hmac, sha256_digest);

	hexdump(sha256_digest, sizeof sha256_digest, "-SHA-256 HMAC Output-");
}
