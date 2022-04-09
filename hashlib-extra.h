/**
 *	@file hashlib-dev.h
 *	@brief	Cryptography Library for the TI-84+ CE
 *
 *	Industry-Standard Cryptography for the TI-84+ CE
 *	- Secure Random Number Generator (SRNG)
 *	- hash_sha256, hash_mgf1
 *  - hmac_sha256, hmac_pbkdf2
 *	- cipher_aes
 *	- cipher_rsa
 *  - secure buffer comparison
 *
 *	@author Anthony @e ACagliano Cagliano
 *	@author Adam @e beck Beckingham
 *	@author commandblockguy
 */

#ifndef HASHLIB_DEV_H
#define HASHLIB_DEV_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <hashlib.h>

/*
    #### INTERNAL FUNCTIONS ####
    For advanced users only!!!
    
    If you know what you are doing and want to implement your own cipher modes,
    or signature algorithms, a few internal functions are exposed here.
 */
 
 /******************************************************************************************************************
  * @brief AES single-block ECB mode encryption function
  * @param block_in Block of data to encrypt.
  * @param block_out Buffer to write encrypted block of data.
  * @param ks AES key schedule context to use for encryption.
  * @note @b block_in and @b block_out are aliasable.
  * @warning ECB mode encryption is insecure (see many-time pad vulnerability).
  *     Use ECB-mode block encryptors as a constructor for custom cipher modes only.
  *****************************************************************************************************************/
 void aes_ecb_unsafe_encrypt(const void *block_in, void *block_out, aes_ctx *ks);
 
 /******************************************************************************************************************
  * @brief AES single-block ECB mode decryption function
  * @param block_in Block of data to encrypt.
  * @param block_out Buffer to write encrypted block of data.
  * @param ks AES key schedule context to use for encryption.
  * @note @b block_in and @b block_out are aliasable.
  * @warning ECB mode encryption is insecure (see many-time pad vulnerability).
  *     Use ECB-mode block encryptors as a constructor for custom cipher modes only.
  *****************************************************************************************************************/
 void aes_ecb_unsafe_decrypt(const void *block_in, void *block_out, aes_ctx *ks);
 
 /******************************************************************************************************************
  * @brief Optimal Asymmetric Encryption Padding (OAEP) encoder for RSA
  * @param plaintext Pointer to the plaintext message to encode.
  * @param len Lengfh of the message to encode.
  * @param encoded Pointer to buffer to write encoded message to.
  * @param modulus_len Length of the RSA modulus to encode for.
  * @param auth An authentication string to include in the encoding. Can be NULL to omit.
  * @param hash_alg The numeric ID of the hashing algorithm to use. See @b hash_algorithms.
  * @return Boolean | True if encoding succeeded, False if encoding failed.
  * @note @b plaintext and @b encoded are aliasable.
  *****************************************************************************************************************/
 bool oaep_encode(
        const void *plaintext,
        size_t len,
        void *encoded,
        size_t modulus_len,
        const uint8_t *auth,
        uint8_t hash_alg);

/******************************************************************************************************************
 * @brief OAEP decoder for RSA
 * @param encoded Pointer to the plaintext message to decode.
 * @param len Lengfh of the message to decode.
 * @param plaintext Pointer to buffer to write decoded message to.
 * @param auth An authentication string to include in the encoding. Can be NULL to omit.
 * @param hash_alg The numeric ID of the hashing algorithm to use. See @b hash_algorithms.
 * @return Boolean | True if encoding succeeded, False if encoding failed.
 * @note @b plaintext and @b encoded are aliasable.
 * *****************************************************************************************************************/
 bool oaep_decode(
        const void *encoded,
        size_t len,
        void *plaintext,
        const uint8_t *auth,
        uint8_t hash_alg);
        
/*************************************************************************************************************************
 * @brief Probabilistic Sisgnature Scheme (PSS) encoder for RSA
 * @param plaintext Pointer to the plaintext message to encode.
 * @param len Lengfh of the message to encode.
 * @param encoded Pointer to buffer to write encoded message to.
 * @param modulus_len Length of the RSA modulus to encode for.
 * @param salt A nonce that can be passed to the encryption scheme. Pass NULL to generate internally.
 * @param hash_alg The numeric ID of the hashing algorithm to use. See @b hash_algorithms.
 * @return Boolean | True if encoding succeeded, False if encoding failed.
 * @note Generally, to encode a message, pass NULL as salt.
 *      To verify a message, pass a pointer to the salt field in the message you are looking to verify.
  *************************************************************************************************************************/
 bool pss_encode(
        const void *plaintext,
        size_t len,
        void *encoded,
        size_t modulus_len,
        void *salt,
        uint8_t hash_alg);
  
/*********************************************************************************************************
 * @brief Modular Exponentiation function for RSA (and other implementations)
 * @param size The length, in bytes, of the @b base and @b modulus.
 * @param base Pointer to buffer containing the base, in bytearray (big endian) format.
 * @param exp A 24-bit exponent.
 * @param mod Pointer to buffer containing the modulus, in bytearray (big endian) format.
 * @note For the @b size field, the bounds are [0, 255] with 0 actually meaning 256.
 * @note @b size must not be 1.
 * @note @b exp must be non-zero.
 * @note @b modulus must be odd.
***********************************************************************************************************/
void powmod(
        uint8_t size,
        uint8_t *restrict base,
        uint24_t exp,
        const uint8_t *restrict mod);

#endif
