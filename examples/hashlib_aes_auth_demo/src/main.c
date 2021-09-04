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
uint8_t str[] = "The lazy fox jumped over the dog!";
#define KEYSIZE (256>>3)    // 256 bits
#define IV_LEN  AES_BLOCKSIZE   // defined <hashlib.h>

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
    // reserve buffers for keys and key schedules, mbuffer, and sha digest
    uint8_t key_encrypt[KEYSIZE];
    uint8_t key_auth[KEYSIZE];
    aes_ctx ks_encrypt, ks_auth;

	// return size of auth mac ciphertext
	// allocate a buffer
	size_t str_len = strlen(str);
	size_t ct_len = hashlib_AESCiphertextSize(str_len);
    size_t ct_auth_len = hashlib_AESAuthMacCiphertextSize(str_len);
    uint8_t *ct = hashlib_MallocContext(ct_auth_len);
    
    strcpy(CEMU_CONSOLE, "\n\nAES MAC-Auth Demo\n----------------\n\n");
    
    // generate random keys
    // one for encrypt, one for mac. anything else is insecure.
    hashlib_AESKeygen(key_encrypt, KEYSIZE);
    hashlib_AESKeygen(key_auth, KEYSIZE);
    
    // generate iv
    hashlib_RandomBytes(ct, AES_IV_SIZE);
    
    // load keys into key schedules
    hashlib_AESLoadKey(key_encrypt, &ks_encrypt, AES256_KEYLEN);
    hashlib_AESLoadKey(key_auth, &ks_auth, AES256_KEYLEN);
    
    if(hashlib_AESEncrypt(str, str_len, &ct[AES_IV_SIZE], &ks_encrypt, ct, AES_MODE_CBC))
		strcpy(CEMU_CONSOLE, "CBC Encrypt successful\n");
    else strcpy(CEMU_CONSOLE, "encryption failed.\n");
    hashlib_AESOutputMac(ct, ct_len + AES_IV_SIZE, &ct[ct_len+AES_IV_SIZE], &ks_auth);
    
    hexdump(ct, ct_auth_len, "-- CBC Encrypted packet -- ");
    
    
    
    return 0;
    
}
