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
    // reserve key schedule and key buffer, IV.
    aes_ctx ctx;
    uint8_t key[KEYSIZE];
    uint8_t iv[AES_IV_SIZE];
    size_t stripped_len;
    
    // compute size of the plaintext
    // return and allocate a few ciphertext-sized buffers
    size_t msg_len = strlen(str);
    size_t padded_len = hashlib_AESCiphertextSize(msg_len);
    uint8_t *buf = hashlib_MallocContext(padded_len);
    uint8_t *stripped = hashlib_MallocContext(padded_len);
    
    sprintf(CEMU_CONSOLE, "\n---------------------------\nHASHLIB AES Demo\n");
    sprintf(CEMU_CONSOLE, "\n----- CBC Mode -----\n");
    
    // generate random key and IV
    hashlib_AESKeygen(key, KEYSIZE);		// this aliases hashlib_RandomBytes()
    hashlib_RandomBytes(iv, AES_IV_SIZE);
    
    // pad the input message
    hashlib_AESPadMessage(str, msg_len, buf, SCHM_DEFAULT);
    hexdump(buf, padded_len, "-- Padded Message --");
    
    // load the key into the key schedule
    hashlib_AESLoadKey(key, &ctx, KEYSIZE); // requires size in bits, not bytes
    
	if(hashlib_AESEncrypt(buf, padded_len, buf, &ctx, iv, AES_MODE_CBC)) {
		sprintf(CEMU_CONSOLE, "encrypt success\n");
		hexdump(buf, padded_len, "-- Encrypted Message --");
	}
	else sprintf(CEMU_CONSOLE, "encrypt failed\n");
    
	if(hashlib_AESDecrypt(buf, padded_len, buf, &ctx, iv, AES_MODE_CBC)){
		sprintf(CEMU_CONSOLE, "decrypt success\n");
		hexdump(buf, padded_len, "-- Decrypted Message --");
		stripped_len = hashlib_AESStripPadding(buf, padded_len, buf, SCHM_DEFAULT);
		sprintf(CEMU_CONSOLE, "%s", buf);
	}
	else sprintf(CEMU_CONSOLE, "decrypt failed\n");

	// free *buf and *stripped.
	// CTR mode doesn't need them.
    free(buf);
    free(stripped);
    
    sprintf(CEMU_CONSOLE, "\n\n----- CTR Mode -----\n");
    hexdump(str, msg_len, "-- Original String --");
    
    if(hashlib_AESEncrypt(str, msg_len, str, &ctx, iv, AES_MODE_CTR)) {
		sprintf(CEMU_CONSOLE, "encrypt success\n");
		hexdump(str, msg_len, "-- Encrypted Message --");
	}
	else sprintf(CEMU_CONSOLE, "encrypt failed\n");
	
	if(hashlib_AESDecrypt(str, msg_len, str, &ctx, iv, AES_MODE_CTR)){
		sprintf(CEMU_CONSOLE, "decrypt success\n");
		hexdump(str, msg_len, "-- Decrypted Message --");
		sprintf(CEMU_CONSOLE, "%s", str);
	}
	else sprintf(CEMU_CONSOLE, "decrypt failed\n");
	
    
    return 0;
    
}
