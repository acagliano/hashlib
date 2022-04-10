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
char *str = "The lazy fox jumped over the dog!";
#define KEYSIZE (256>>3)    // 256 bits converted to bytes

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
    // reserve key schedule and key buffer, IV.
    aes_ctx ctx;
    uint8_t key[KEYSIZE];
    uint8_t iv[AES_IVSIZE];
    
    // compute size of the plaintext
    // return and allocate a few ciphertext-sized buffers
    size_t msg_len = strlen(str);
    size_t padded_len = aes_outsize(msg_len);
    uint8_t *buf = malloc(padded_len);
    uint8_t *stripped = malloc(padded_len);
    
    sprintf(CEMU_CONSOLE, "\n---------------------------\nHASHLIB AES Demo\n");
    sprintf(CEMU_CONSOLE, "\n----- CBC Mode -----\n");
    hexdump(str, msg_len, "-- Original String --");
    
    
    // generate random key and IV
    if(!csrand_init()) return 1;          // <<<----- DONT FORGET THIS
    csrand_fill(key, KEYSIZE);		// this aliases hashlib_RandomBytes()
    csrand_fill(iv, AES_IVSIZE);
    
    // load the key into the key schedule
    aes_loadkey(key, &ctx, KEYSIZE); // requires size in bits, not bytes
    
	sprintf(CEMU_CONSOLE, "CBC encrypt done, exit code %u\n", aes_encrypt(str, msg_len, buf, &ctx, iv, AES_MODE_CBC, SCHM_DEFAULT));
    hexdump(buf, padded_len, "-- Encrypted Message --");
    
	sprintf(CEMU_CONSOLE, "CBC decrypt done, exit code %u\n", aes_decrypt(buf, padded_len, stripped, &ctx, iv, AES_MODE_CBC, SCHM_DEFAULT));
    hexdump(stripped, msg_len, "-- Decrypted Message --");


	// free *buf and *stripped.
	// CTR mode doesn't need them.
    
    sprintf(CEMU_CONSOLE, "CTR encrypt done, exit code %u\n", aes_encrypt(str, msg_len, buf, &ctx, iv, AES_MODE_CTR, 0));
    hexdump(buf, padded_len, "-- Encrypted Message --");
	
	sprintf(CEMU_CONSOLE, "CTR decrypt done, exit code %u\n", aes_decrypt(buf, msg_len, stripped, &ctx, iv, AES_MODE_CTR, 0));
    hexdump(stripped, msg_len, "-- Decrypted Message --");

	free(buf);
    free(stripped);
    
    return 0;
    
}
