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
char hexc[16] = "0123456789ABCDEF";
uint8_t str[] = "The daring fox jumped over the rabid kitten and is sleeping inside.";

uint8_t sha256_test[] = {0xAE,0x22,0xC1,0x0B,0x43,0xBF,0x7A,0x1F,0x49,0xFF,0xB6,0xA8,0x6C,0x67,0x01,0x45,0x11,0x2C,0x3A,0xAE,0xA3,0xC5,0x06,0x58,0x59,0x28,0x93,0x4E,0x30,0x61,0x3C,0xCD};

void tohex(char *sbuf, uint8_t *src)
{
	int i;
	int j=0;
	for (i=0; i<SHA256_DIGEST_LEN; i++) {
		sbuf[j++] = hexc[src[i]>>4];
		sbuf[j++] = hexc[src[i]&15];
	}
	sbuf[j] = 0;
}

int main(void)
{
	char *sbuf;
	uint32_t *mbuffer;
    sha256_ctx sha256;
    uint8_t sha256_digest[SHA256_DIGEST_LEN];
    size_t str_len = strlen(str);
	if (!(mbuffer = malloc(64*4))) return 1;
	if (!(sbuf = malloc(SHA256_DIGEST_LEN*2 + 1))) return 1;

	// sprintf(CEMU_CONSOLE, "SHA_CTX Addr: %u\nSHA_CTX EndAddr: %u\n", &sha256, (uint24_t)&sha256 + sizeof(sha256)-1);
    // (*(uint8_t*)-1) = 2;

    sprintf(CEMU_CONSOLE, "The string is '%s'.\n", str);
    sprintf(CEMU_CONSOLE, "Its size is: %u\n", str_len);
    
    hashlib_Sha256Init(&sha256, mbuffer);
    hashlib_Sha256Update(&sha256, str, str_len);
    hashlib_Sha256Final(&sha256, sha256_digest);

	tohex(sbuf, sha256_test);
	sprintf(CEMU_CONSOLE, "Expected hash:  %s \n", sbuf);

	tohex(sbuf, sha256_digest);
	sprintf(CEMU_CONSOLE, "Resulting hash: %s \n", sbuf);

	if(!memcmp(sha256_digest, sha256_test, SHA256_DIGEST_LEN))
        strcpy(CEMU_CONSOLE, "SHA-256 match");
    else strcpy(CEMU_CONSOLE, "SHA-256 did not match");
    strcpy(CEMU_CONSOLE, "\n");
}
