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
    sha256_ctx sha256;
    uint8_t sha256_digest[SHA256_DIGEST_LEN];
    uint8_t sha256_hex[SHA256_HEXDIGEST_LEN];
    size_t str_len = strlen(str);
    
    hash_init(&sha256, SHA256);
    hash_update(&sha256, str, str_len);
    hash_final(&sha256, sha256_digest);
   
    digest_tostring(sha256_digest, sizeof sha256_digest, sha256_hex);
    strcpy(CEMU_CONSOLE, sha256_hex);
    strcpy(CEMU_CONSOLE, "\n");
}
