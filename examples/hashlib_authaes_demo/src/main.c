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
uint8_t *str = "The lazy fox jumped over the dog!";
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
    size_t stripped_len;
    uint8_t str_packet[40];
    uint8_t auth_cipher_buf[40+32] = {0};
    
    // copy some data we won't encrypt, and the string we will into the buffer
    memset(str_packet, 255, sizeof str_packet);
    strcpy(str_packet+4, str);
    
    sprintf(CEMU_CONSOLE, "\n---------------------------\nHASHLIB Authenticated AES Demo\n");
    sprintf(CEMU_CONSOLE, "\n\n----- CTR Mode -----\n");
    hexdump(str_packet, sizeof str_packet, "-- Unencrypted Buffer --");
    
    // generate random key and IV
    hashlib_AESKeygen(key, KEYSIZE);		// this aliases hashlib_RandomBytes()
    hashlib_RandomBytes(iv, AES_IVSIZE);
    hashlib_AESLoadKey(key, &ctx, KEYSIZE); // requires size in bits, not bytes
    
    sprintf(CEMU_CONSOLE, "CTR encrypt done, exit code %u\n", hashlib_AESAuthEncrypt(str_packet, sizeof str_packet, auth_cipher_buf, &ctx, iv, AES_MODE_CTR, 4, strlen(str)));
    hexdump(auth_cipher_buf, sizeof auth_cipher_buf, "-- Encrypted Message --");
	
	sprintf(CEMU_CONSOLE, "CTR decrypt done, exit code %u\n", hashlib_AESAuthDecrypt(auth_cipher_buf, sizeof auth_cipher_buf, auth_cipher_buf, &ctx, iv, AES_MODE_CTR, 4, strlen(str)));
    hexdump(auth_cipher_buf, sizeof auth_cipher_buf, "-- Original String --");

	
    
    return 0;
    
}
