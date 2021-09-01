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
    // reserve buffers for keys, key schedules, and security context
    uint8_t key_encrypt[256>>3];
    uint8_t key_auth[256>>3];
    aes_ctx ks_encrypt, ks_auth;
    aes_security_profile_t profile;
    uint8_t packet[256];
    uint8_t decrypt_buf[256];
    size_t actual_len = hashlib_AESAuthCiphertextSize(strlen(str));
    sha256_ctx ctx;
    uint32_t mbuffer[64];
    size_t str_len = strlen(str);
    uint8_t sha_dig[32];
    
    strcpy(CEMU_CONSOLE, "\n\nAES Packet Construction Demo\n---------------------------\n\n");
    // generate random keys
    hashlib_AESKeygen256(key_encrypt);
    hashlib_AESKeygen256(key_auth);
    
    // load keys into key schedules
    hashlib_AESLoadKey(key_encrypt, &ks_encrypt, AES_256);
    hashlib_AESLoadKey(key_auth, &ks_auth, AES_256);
    
    profile.ks_encrypt = &ks_encrypt;
    profile.ks_auth = &ks_auth;
    profile.ciphermode = AES_MODE_CBC;
    profile.paddingmode = SCHM_DEFAULT;
    profile.authmode = AES_AUTH_CBCMAC;
    
    if(hashlib_AESEncryptPacket(str, str_len, packet, 256, &profile)){
		strcpy(CEMU_CONSOLE, "CBC Encrypt successful\n");
		hexdump(packet, 256, "-- CBC Encrypted packet -- ");
    }
    
    if(hashlib_AESVerifyMac(packet, actual_len, &ks_auth)){
		if(hashlib_AESDecrypt(&packet[AES_BLOCKSIZE], actual_len, decrypt_buf, &ks_encrypt, packet,
    AES_MODE_CBC)){
			strcpy(CEMU_CONSOLE, "Decrypt successful\n");
			hexdump(decrypt_buf, 256, "-- Decrypted packet -- ");
			strncpy(CEMU_CONSOLE, decrypt_buf, strlen(str));
			strcpy(CEMU_CONSOLE, "\n");
		}
		else strcpy(CEMU_CONSOLE, "Decrypt failed\n");
	}
	else strcpy(CEMU_CONSOLE, "MAC verification failed\n");
    
    profile.ciphermode = AES_MODE_CTR;
    profile.authmode = AES_AUTH_SHA256;
    if(hashlib_AESEncryptPacket(str, str_len, packet, 256, &profile)){
		strcpy(CEMU_CONSOLE, "CTR Encrypt successful\n");
		hexdump(packet, 256, "-- CTR Encrypted packet -- ");
    }
    
    hashlib_Sha256Init(&ctx, mbuffer);
    hashlib_Sha256Update(&ctx, packet, str_len + AES_BLOCKSIZE);
    hashlib_Sha256Final(&ctx, sha_dig);
    if(hashlib_CompareDigest(sha_dig, &packet[str_len + AES_BLOCKSIZE], 32)){
		if(hashlib_AESDecrypt(&packet[AES_BLOCKSIZE], str_len, decrypt_buf, &ks_encrypt, packet,
    AES_MODE_CTR)){
			strcpy(CEMU_CONSOLE, "Decrypt successful\n");
			hexdump(decrypt_buf, 256, "-- Decrypted packet -- ");
			strncpy(CEMU_CONSOLE, decrypt_buf, strlen(str));
			strcpy(CEMU_CONSOLE, "\n");
		}
		else strcpy(CEMU_CONSOLE, "Decrypt failed\n");
	}
	else strcpy(CEMU_CONSOLE, "SHA-256 verification failed\n");
    
    return 0;
    
}
