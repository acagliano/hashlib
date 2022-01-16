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
#include <tice.h>
#include <fileioc.h>

#define CEMU_CONSOLE ((char*)0xFB0000)
#define SALT_LEN 16     // for example, a salt that is an IV for AES is 16 bytes long

int main(void)
{
    // reserve key schedule and key buffer, IV, and encrypt/decrypt buffers
    ti_var_t fp;
    uint8_t salt[SALT_LEN];
    // hashlib_SPRNGInit() is called automatically by SPRNGRandom or RandomBytes
    // no need to call it yourself
    // generate a random uint32_t
	sprintf(CEMU_CONSOLE, "The rand is %lu.\n", hashlib_SPRNGRandom());
    
    // or fill a buffer to size with random
    hashlib_RandomBytes(salt, SALT_LEN);
    strcpy(CEMU_CONSOLE, "The buffer contents are: \n");
    for(uint8_t i=0; i<SALT_LEN; i++)
        sprintf(CEMU_CONSOLE, "%02X ", salt[i]);
    
    return 0;
    
}
