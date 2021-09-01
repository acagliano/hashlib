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
#include <debug.h>
#include <tice.h>

#include <hashlib.h>
#include <fileioc.h>

#define CEMU_CONSOLE ((char*)0xFB0000)

#define end_timer() timer_GetSafe(1, TIMER_UP)

void start_timer(void){
	timer_Disable(1);
    timer_Set(1, 0);
    timer_Enable(1, TIMER_32K, TIMER_NOINT, TIMER_UP);
}

char hexc[16] = "0123456789ABCDEF";

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
	ti_var_t fp;
	void *file_ptr;
	size_t file_len;
	int time;
	char *sbuf;
	uint32_t *mbuffer;
    sha256_ctx sha256;
    uint8_t sha256_digest[SHA256_DIGEST_LEN];
	ti_CloseAll();

	if (!(fp = ti_Open("HASHLIB", "r"))){
		return 1;
	}
	file_ptr = ti_GetDataPtr(fp);
	file_len = ti_GetSize(fp);
	ti_Close(fp);

	if (!(mbuffer = malloc(64*4))) return 1;
	if (!(sbuf = malloc(SHA256_DIGEST_LEN*2 + 1))) return 1;

	// sprintf(CEMU_CONSOLE, "SHA_CTX Addr: %u\nSHA_CTX EndAddr: %u\n", &sha256, (uint24_t)&sha256 + sizeof(sha256)-1);
    // (*(uint8_t*)-1) = 2;
	
	start_timer();
    hashlib_Sha256Init(&sha256, mbuffer);
    hashlib_Sha256Update(&sha256, file_ptr, file_len);
    hashlib_Sha256Final(&sha256, sha256_digest);
	time = end_timer();
	sprintf(CEMU_CONSOLE, "Time taken %u/32768 seconds.\n", time);

	tohex(sbuf, sha256_digest);
	sprintf(CEMU_CONSOLE, "Resulting hash: %s \n", sbuf);

	ti_CloseAll();
}
