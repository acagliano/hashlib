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
uint8_t str[] = "The daring fox jumped over the rabid kitten and is sleeping inside.";
#define dbg_Debugger() \
    *(volatile unsigned char*)0xFFFFE0 = (unsigned char)~0

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
    size_t str_len = strlen(str);
    hash_ctx ctx;
    uint8_t tmp[64];
    uint8_t sha256_digest[SHA256_DIGEST_LEN];
    uint8_t sha256_hex[(SHA256_DIGEST_LEN<<1)+1];
    
    sprintf(CEMU_CONSOLE, "&ctx: %u\n", &ctx);
    sprintf(CEMU_CONSOLE, "sizeof ctx: %u\n", sizeof ctx);
    sprintf(CEMU_CONSOLE, "sizeof sha256: %u\n", sizeof (sha256_ctx));
    sprintf(CEMU_CONSOLE, "sizeof _hash: %u\n", sizeof (union _hash));
    *(char*)-1=2;
    
    if(!hash_init(&ctx, SHA256));
    hash_update(&ctx, str, str_len);
    hash_final(&ctx, sha256_digest);
   
    digest_tostring(sha256_digest, sizeof sha256_digest, sha256_hex);
    strcpy(CEMU_CONSOLE, sha256_hex);
    strcpy(CEMU_CONSOLE, "\n");
    return 0;
}
