/**
 *	@file hashlib.h
 *	@brief	Cryptography Library for the TI-84+ CE
 *
 *	Provides several cryptographic implementations for the TI-84+ CE graphing calculator.
 *	- secure random number generator
 *	- SHA-256
 *	- AES: CBC, CTR, CBC-MAC
 *	- AES Padding: PKCS#7, ISO-9797 M2
 *	- RSA public key encryption, modulus <= 2048 bits
 *	- RSA Padding: RSA-OAEP via PKCS#7 v2.2, RSA-PSS via PKCS#7 v1.5
 *
 *	@author Anthony @e ACagliano Cagliano
 *	@author Adam @e beck Beckingham
 *	@author commandblockguy
 */

#ifndef HASHLIB_H
#define HASHLIB_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/****************************************************************************************************************************************
 * @def hashlib_FastMemBufferSafe
 *		Pointer to a region of Fast Memory that is generally safe to use so long as you don't call Libload..
 * @warning Fast Memory gets clobbered by LibLoad. Don't keep long-term storage here if you plan to call LibLoad.
 ****************************************************************************************************************************************/
 #define hashlib_FastMemBufferSafe		((void*)0xE30A04)
 
 /**************************************************************************************************************************************
  * @def hashlib_FastMemBufferUnsafe
  *		Pointer to the start of the region of Fast Memory, including the Safe region
  *		as well as an unsafe region used by the library's SPRNG.
  *	@warning Fast Memory gets clobbered by LibLoad. Don't keep long-term storage here if you plan to call LibLoad.
  *	@warning If the SPRNG is run, anything you have stored here will be destroyed.
  **************************************************************************************************************************************/
#define hashlib_FastMemBufferUnsafe		((void*)0xE30800)


// Secure Psuedorandom Number Generator
/****************************************************************************************************************************
 * @brief Initializes the SPRNG.
 *
 * The SPRNG is initialized by polling the 512-bytes from address 0xD65800 to 0xD66000.
 * This region consists of unmapped memory that contains bus noise.
 * Each bit in that region is polled 1024 times and the address with the bit that is the least biased is selected.
 * That will be the byte the SPRNG uses to generate entropy.
 * @return The unmapped address selected for use generating entropy
 ***************************************************************************************************************************/
void* hashlib_SPRNGInit(void);

/***************************************************************************************************************************
 * @brief Generates a random 32-bit number.
 *
 * - Calls hashlib_SPRNGInit() if it hasn't already been done.
 * - Populates a 119-byte entropy pool by xor'ing 7 distinct reads from the unmapped address together per byte.
 * - Hashes the entropy pool using SHA-256.
 * - Breaks the SHA-256 hash into 8-byte blocks, then xor's all 8 bytes each block together, leaving four (4) composite bytes.
 * - Returns the 4-byte (32-bit) composite as a random number..
 * @return A random unsigned 32-bit integer.
 ****************************************************************************************************************************/
uint32_t hashlib_SPRNGRandom(void);

/****************************************************************************************
 * @brief Fills a buffer to size with random bytes.
 *
 * @param buffer A pointer to a buffer to write random data to.
 * @param size Number of bytes to write.
 * @note @b buffer must be at least @b size bytes large.
 ****************************************************************************************/
bool hashlib_RandomBytes(uint8_t *buffer, size_t size);
 
 
// SHA-256 Cryptographic Hash
/*******************************************************************************************************************
 * @typedef sha256_ctx
 * Defines hash-state data for an instance of SHA-256.
 * @note If you are hashing multiple data streams concurrently, allocate a seperate context for each.
 ********************************************************************************************************************/
typedef struct _sha256_ctx {
	uint8_t data[64];		/**< holds sha-256 block for transformation */
	uint8_t datalen;		/**< holds the current length of data in data[64] */
	uint8_t bitlen[8];		/**< holds the current length of transformed data */
	uint32_t state[8];		/**< holds hash state for transformed data */
} sha256_ctx;

/**************************************************************************************
 * @def SHA256_MBUFFER_LEN
 * Temporary SHA-256 memory buffer.
 * A buffer of this length, in uint32_ts, must be passed to hashlib_Sha256Init().
 * @code
 * uint32_t mbuffer[SHA256_MBUFFER_LEN];
 * @endcode
 **************************************************************************************/
 #define SHA256_MBUFFER_LEN		(64)
 
 /******************************************************
  * @def SHA256_DIGEST_LEN
  * Binary length of the SHA-256 hash output.
  ******************************************************/
 #define SHA256_DIGEST_LEN		32
 
 /************************************************************
  * @def SHA256_HEXSTR_LEN
  * Length of a string containing the SHA-256 hash.
  **********************************************************/
#define SHA256_HEXSTR_LEN		(SHA256_DIGEST_LEN<<1) + 1

/**************************************************************************************************
 *	@brief Context initializer for SHA-256.
 *	Initializes the given context with the starting state for SHA-256.
 *	@param ctx Pointer to a SHA-256 context.
 *	@param mbuffer Pointer to a temporary memory buffer.
 *	@note @b mbuffer must be at least @b SHA256_MBUFFER_LEN bytes large.
 **************************************************************************************************/
void hashlib_Sha256Init(sha256_ctx *ctx, uint32_t *mbuffer);

/******************************************************************************************************
 *	@brief Updates the SHA-256 context for the given data.
 *	@param ctx Pointer to a SHA-256 context.
 *	@param buf Pointer to data to hash.
 *	@param len Number of bytes at @b buf to hash.
 *	@warning You must call hashlib_Sha256Init() first or your hash state will be invalid.
 ******************************************************************************************************/
void hashlib_Sha256Update(sha256_ctx *ctx, const uint8_t *buf, uint32_t len);

/**************************************************************************
 *	@brief Finalize Context and Render Digest for SHA-256
 *	@param ctx Pointer to a SHA-256 context.
 *	@param digest Pointer to a buffer to write the hash to.
 *	@note @b digest must be at least 32 bytes large.
 ***************************************************************************/
void hashlib_Sha256Final(sha256_ctx *ctx, uint8_t *digest);

/**********************************************************************************************************************
 *	@brief Arbitrary Length Hashing Function
 *
 *	Computes SHA-256 of the data with a counter appended to generate a hash of arbitrary length.
 *
 *	@param data Pointer to data to hash.
 *	@param datalen Number of bytes at @b data to hash.
 *	@param outbuf Pointer to buffer to write hash output to.
 *	@param outlen Number of bytes to write to @b outbuf.
 *	@note @b outbuf must be at least @b outlen bytes large.
 **********************************************************************************************************************/
void hashlib_MGF1Hash(uint8_t* data, size_t datalen, uint8_t* outbuf, size_t outlen);


// Advanced Encryption Standard (AES)
/***************************************************************************************************
 * @typedef aes_ctx
 * Stores AES key instance data: key size and round keys generated from an AES key.
 ***************************************************************************************************/
typedef struct _aes_ctx {
    uint24_t keysize;				/**< the size of the key, in bits */
    uint32_t round_keys[60];		/**< round keys */
} aes_ctx;

/************************************************
 * @enum aes_cipher_modes
 * Supported AES cipher modes
 ************************************************/
enum aes_cipher_modes {
	AES_MODE_CBC,		/**< selects CBC mode */
	AES_MODE_CTR		/**< selects CTR mode */
};

/***************************************************
 * @enum aes_padding_schemes
 * Supported AES padding schemes
 ***************************************************/
enum aes_padding_schemes {
    SCHM_PKCS7, 		 		/**< PKCS#7 padding | DEFAULT */
    SCHM_DEFAULT = SCHM_PKCS7,	/**< selects the scheme marked DEFAULT.
									Using this is recommended in case a change to the standards
									would set a stronger padding scheme as default */
    SCHM_ISO2,       	 	/**< ISO-9797 M2 padding */
};


/********************************************************
 * @def AES_BLOCKSIZE
 * Defines the blocksize of the AES cipher.
 ********************************************************/
#define AES_BLOCKSIZE	16

/*****************************************************************
 * @def AES_IVSIZE
 * Defines the length of the AES initalization vector (IV).
 *****************************************************************/
#define AES_IVSIZE		AES_BLOCKSIZE

/******************************************************
 * @def AES128_KEYLEN
 * Defines the byte-length of a 128-bit AES key
 ******************************************************/
#define AES128_KEYLEN	16

/******************************************************
 * @def AES192_KEYLEN
 * Defines the byte-length of a 192-bit AES key
 ******************************************************/
 #define AES192_KEYLEN	24
 
/*****************************************************
 * @def AES256_KEYLEN
 * Defines the byte-length of a 256-bit AES key
 *****************************************************/
#define AES256_KEYLEN	32

/*********************************************************************************************
 * @def hashlib_AESCiphertextSize()
 *
 * Defines a macro to return the size of an AES ciphertext given a plaintext length.
 * Does not include space for  an IV-prepend. See hashlib_AESCiphertextIVLen() for that.
 *
 * @param len The length of the plaintext.
 *********************************************************************************************/
  #define hashlib_AESCiphertextSize(len) \
	((((len)%AES_BLOCKSIZE)==0) ? (len) + AES_BLOCKSIZE : (((len)>>4) + 1)<<4)
	
/************************************************************************************************************************
 * @def hashlib_AESCiphertextIVSize()
 *
 * Defines a macro to return the size of an AES ciphertext with with an extra block added for the IV.
 *
 * @param len The length of the plaintext.
 ************************************************************************************************************************/
 #define hashlib_AESCiphertextIVSize(len)	(hashlib_AESCiphertextSize((len)) + AES_IVSIZE)

/***************************************************************************************
 * @def hashlib_AESKeygen()
 * Defines a macro to generate a pseudorandom AES key of a given length.
 * @param key Pointer to a buffer to write the key into.
 * @param keylen The byte length of the key to generate.
 * @note @b key must be at least @b keylen bytes large.
 ***************************************************************************************/
#define hashlib_AESKeygen(key, keylen)	hashlib_RandomBytes((key), (keylen))

/*********************************************************************************
 * @brief AES import key to key schedule context
 * @param key Pointer to a buffer containing the AES key.
 * @param ks Pointer to an AES key schedule context.
 * @param keylen The size, in bytes, of the key to load.
 * @return True if the key was successfully loaded. False otherwise.
************************************************************************************/
bool hashlib_AESLoadKey(const uint8_t* key, const aes_ctx* ks, size_t keylen);

/**********************************************************************************************************************************
 * @brief AES Single-Block Encryption (ECB mode)
 * @param block_in	Pointer to block of data to encrypt.
 * @param block_out Pointer to buffer to write encrypted block.
 * @param ks Pointer to an AES key schedule context.
 * @note @b block_in and @b block_out are aliasable.
 * @warning ECB-mode ciphers are insecure (see many-time pad vulnerability).
 *          Unless you know what you are doing, use hashlib_AESEncrypt() instead.
 * @warning The ECB mode single-block encryptors lack the buffer leak protections that hashlib_AESEncrypt()
 *          has. If you are writing your own cipher mode, you will need to implement that yourself.
 * @return True if encryption succeeded. False if failed.
 **********************************************************************************************************************************/
bool hashlib_AESEncryptBlock(const uint8_t* block_in,
							 uint8_t* block_out,
							 const aes_ctx* ks);
    
/********************************************************************************************************************************
 *	@brief AES Single-Block Decryption (ECB Mode)
 *	@param block_in Pointer to block of data to decrypt.
 *	@param block_out Pointer to buffer to write decrypted block.
 *	@param ks Pointer to an AES key schedule context.
 *	@note @b block_in and @b block_out are aliasable.
 * @warning ECB-mode ciphers are insecure (see many-time pad vulnerability).
 *          Unless you know what you are doing, use hashlib_AESDecrypt() instead.
 * @warning The ECB mode single-block encryptors lack the buffer leak protections that hashlib_AESDecrypt()
 *          has. If you are writing your own cipher mode, you will need to implement that yourself.
 *	@return True if encryption succeeded. False if an error occured.
 **********************************************************************************************************************************/
bool hashlib_AESDecryptBlock(const uint8_t* block_in,
							 uint8_t* block_out,
							 const aes_ctx* ks);


/***************************************************
 * @enum aes_error_t
 * AES Error Codes
 * (returned by hashlib_AESEncrypt/Decrypt)
 ***************************************************/
typedef enum {
    AES_OK,                             /**< AES operation completed successfully */
    AES_INVALID_ARG,                    /**< AES operation failed, bad argument */
    AES_INVALID_MSG,                    /**< AES operation failed, message invalid */
    AES_INVALID_CIPHERMODE,             /**< AES operation failed, cipher mode undefined */
    AES_INVALID_PADDINGMODE,            /**< AES operation failed, padding mode undefined */
    AES_INVALID_CIPHERTEXT              /**< AES operation failed, ciphertext size error */
} aes_error_t;

/**
 * @brief General-Purpose AES Encryption
 * @param plaintext Pointer to data to encrypt.
 * @param len Length of data at @b plaintext to encrypt. This can be the output of hashlib_AESCiphertextSize().
 * @param ciphertext Pointer to buffer to write encrypted data to.
 * @param ks Pointer to an AES key schedule context.
 * @param iv Pointer to an initialization vector (a nonce of length equal to the block size).
 * @param ciphermode The cipher mode to use. Can be either @e AES_MODE_CBC or @e AES_MODE_CTR.
 * @param paddingmode The padding mode to use. Choose one of the padding modes in @b enum aes_padding_schemes.
 * @note @b ciphertext should large enough to hold the encrypted message.
 *          For CBC mode, this is the smallest multiple of the blocksize that will hold the plaintext,
 *              plus 1 block if the blocksize divides the plaintext evenly.
 *          For CTR mode, this is the same size as the plaintext.
 * @note @b plaintext and @b ciphertext are aliasable.
 * @note @b IV is not written to the ciphertext buffer by this function, only the encrypted message. However, if
 * 		your ciphertext buffer is large enough, you can do the following to get the IV prepended to the ciphertext.
 * 		Otherwise you will have to join the IV and the ciphertext into a single larger buffer before sending it through
 * 		whatever networking protocol you use.
 * 		@code
 * 		hashlib_AESEncrypt(plaintext, len, &ciphertext[AES_IV_SIZE], ks, iv, <cipher_mode>, <padding_mode>);
 * 		memcpy(ciphertext, iv, AES_IV_SIZE);
 * 		send_packet(ciphertext);
 * 		@endcode
 * 		This will require a buffer at least as large as the size returned by hashlib_AESCiphertextIVSize().
 * @return True if the encryption succeded. False if an error occured.
 */
aes_error_t hashlib_AESEncrypt(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* ciphertext,
    const aes_ctx* ks,
    const uint8_t* iv,
    uint8_t ciphermode,
    uint8_t paddingmode);

/**
 * @brief General-Purpose AES Decryption
 * @param ciphertext Pointer to data to decrypt.
 * @param len Length of data at @b ciphertext to decrypt.
 * @param plaintext Pointer to buffer to write decryped data to.
 * @param ks Pointer to an AES key schedule context.
 * @param iv Pointer to an initialization vector (a nonce of length equal to the block size).
 * @param ciphermode The cipher mode to use. Can be either  @e AES_MODE_CBC or  @e AES_MODE_CTR.
 * @param paddingmode The padding mode to use. Choose one of the padding modes in @b enum aes_padding_schemes.
 * @note @b plaintext and @b ciphertext are aliasable.
 * @note @b IV should be the same as what is used for encryption.
 * @return True if the decryption succeded. False if an error occured.
 */
aes_error_t hashlib_AESDecrypt(
    const uint8_t* ciphertext,
    size_t len,
    uint8_t* plaintext,
    const aes_ctx* ks,
    const uint8_t* iv,
    uint8_t ciphermode,
    uint8_t paddingmode);
    

// RSA Public Key Encryption
/*************************************************************************************************
 * @enum ssl_sig_modes
 * SSL signature algorithms
****************************************************************************************************/
enum ssl_sig_modes {
	SSLSIG_RSA_SHA256,		/**< RSA with SHA-256 signature algorithm */
	SSLSIG_ECDSA			/**< ECDSA (unimplemented, likely a long way off) */
};

/***************************************************
 * @enum rsa_error_t
 * RSA Encryption Error Codes
 ***************************************************/
typedef enum {
    RSA_OK,                         /**< RSA encryption completed successfully */
    RSA_INVALID_ARG,                /**< RSA encryption failed, bad argument */
    RSA_INVALID_MSG,                /**< RSA encryption failed, bad msg or msg too long */
    RSA_INVALID_MODULUS,            /**< RSA encryption failed, modulus invalid */
    RSA_ENCODING_ERROR              /**< RSA encryption failed, OAEP encoding error */
} rsa_error_t;
 
/***************************************************************************************************
 * @brief RSA Encryption
 *
 * Performs an in-place RSA encryption of a message
 * over a public modulus \b pubkey and a public exponent, 65537
 * OAEP encoding of the input message is performed automatically.
 *
 * @param msg Pointer to a message to encrypt using RSA.
 * @param msglen The length of the message @b msg.
 * @param ciphertext Pointer a buffer to write the ciphertext to.
 * @param pubkey Pointer to a public key to use for encryption.
 * @param keylen The length of the public key (modulus) to encrypt with.
 * @note The size of @b ciphertext and @b keylen must be equal.
 * @note The @b msg will be encoded using OAEP before encryption.
 * @note msg and pubkey are both treated as byte arrays.
 * @return True if encryption succeeded. False if failed.
 **************************************************************************************************/
rsa_error_t hashlib_RSAEncrypt(
    const uint8_t* msg,
    size_t msglen,
    uint8_t* ciphertext,
    const uint8_t* pubkey,
    size_t keylen);
 
/**********************************************************************************************
 * @brief SSL Certificate Signature Verification
 *
 * Verifies the signature of a given SSL certificate using SSLSIG_RSA_SHA256
 *
 * @param ca_pubkey Pointer to buffer containing the public key of the certificate's certifying authority.
 * @param keysize Length of the public key at @b ca_pubkey.
 * @param cert Pointer to buffer containing the certificate to verify.
 * @param certlen The size of the certificate at @b cert.
 * @param sig_alg The algorithm to use for SSL verification (presently only RSA with SHA-256 supported).
 * @returns True if the SSL certificate signature is valid. False is invalid or user error.
 * *******************************************************************************************/
bool hashlib_SSLVerifySignature(
    const uint8_t *ca_pubkey,
    size_t keysize,
    const uint8_t *cert,
    size_t certlen,
    uint8_t sig_alg);

// Miscellaneous Functions
/**************************************************************************************************************
 * @brief Secure erase context.
 * @param ctx Pointer to any context or buffer you want to erase.
 * @param len Number of bytes at @b ctx to erase.
 * @note It is advised to call this on every cryptographic context and encryption buffer used.
 **************************************************************************************************************/
void hashlib_EraseContext(void *ctx, size_t len);

/*************************************************************************************************
 * @def hashlib_MallocContext()
 *
 * Dynamically allocates a block of memory to be used for a context or buffer.
 *
 * @param size Size of the buffer to malloc.
 * @return Same as @b malloc.
 *************************************************************************************************/
#define hashlib_MallocContext(size)		malloc((size))

/*************************************************************************************************************
 * @brief Secure buffer comparison
 *
 * Evaluates the equality of two buffers using a method that offers resistance to timing attacks.
 *
 * @param digest1 The first buffer to compare.
 * @param digest2 The second buffer to compare.
 * @param len The number of bytes to compare.
 * @return True if the buffers were equal. False if not equal.
 **************************************************************************************************************/
hashlib_CompareDigest(const uint8_t* digest1, const uint8_t* digest2, size_t len);

/*************************************************************************************************************
 * @brief Reverses the endianness of a buffer
 *
 * @param in Pointer to buffer containing data to reverse.
 * @param out Pointer to buffer to write the reversed data.
 * @param len The number of bytes to reverse.
 * @note @b in and @b out are not aliasable.
 **************************************************************************************************************/
bool hashlib_ReverseEndianness(const uint8_t* in, uint8_t* out, size_t len);


/*********************************************************
 * ##### MISCELLANEOUS FUNCTIONS #####
 *********************************************************/

/*****************************************************************************************
 * @brief Pads a plaintext according to the specified AES padding scheme.
 * @param plaintext Pointer to buffer containing the data to pad.
 * @param len Length of data at @b plaintext to pad.
 * @param outbuf Pointer to buffer to write padded data.
 * @param schm The AES padding scheme to use.
 * @note @b plaintext and @b outbuf are aliasable.
 * @note hashlib_AESEncrypt() calls this function automatically.
 *      There is no need to do so yourself.
 * @return The padded length of the message.
 ******************************************************************************************/
size_t hashlib_AESPadMessage(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* outbuf,
    uint8_t schm);

/***************************************************************************************************************
 * @brief Strips the padding from a message according to the specified AES padding scheme.
 * @param plaintext Pointer to buffer containing the data to strip.
 * @param len Length of data at @b plaintext to strip.
 * @param outbuf Pointer to buffer to write stripped data.
 * @param schm The AES padding scheme to use.
 * @note @b plaintext and @b outbuf are aliasable.
 * @note hashlib_AESDecrypt() calls this function automatically.
 *      There is no need to do so yourself.
 * @return The length of the message with padding removed.
 ****************************************************************************************************************/
size_t hashlib_AESStripPadding(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* outbuf,
    uint8_t schm);

/************************************************************************************************************************
 * @brief RSA-OAEP padding scheme
 *
 * Applies the RSA-OAEP padding scheme as indicated in PKCS#1 v2.2.
 * This is intended for use prior to RSA encryption.
 * @code
 * | <-------------------------------- modulus size ---------------------------------> |
 * |-- 0x00 --|-- salt --|-- auth hash --|-- 0x00...padding --|-- 0x01 --|-- message --|
 *	          |          |-------------------------------------------------------------|
 *                 |                                  |
 *                 | --------- MGF1-SHA256 --------> XOR
 *                 |                                  |
 *                XOR <-------- MGF1-SHA256 --------- |
 *                 |                                  |
 * |-- 0x00 --|-- msalt --|---------- masked message, padding, and auth hash ----------|
 * |<-------------------------------- modulus size ----------------------------------> |
 * @endcode
 *
 * @param plaintext Pointer to a buffer containing the data to OAEP-encode.
 * @param len Length of data at @b plaintext to encode.
 * @param outbuf Pointer to buffer large enough to hold the padded data.
 * @param modulus_len The byte length of the modulus to pad for.
 * @param auth Pointer to an authentication string (similar to a password) to include in the encoding.
 * @note @b outbuf must be at least @b modulus_len bytes large.
 * @note hashlib_RSAEncrypt() calls this function automatically. There is no need to do it yourself.
 * @note @b auth both sender and receiver must know this string. Pass NULL to omit.
 * @return The padded length of the plaintext.
 ***********************************************************************************************************************/
size_t hashlib_RSAEncodeOAEP(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* outbuf,
    size_t modulus_len,
    const uint8_t *auth);
    
/************************************************************************************************************************
 * @brief RSA-OAEP padding scheme, reverse algorithm
 *
 * Reverses the RSA-OAEP padding scheme as indicated in PKCS#1 v2.2.
 *
 * @param plaintext Pointer to a buffer containing the data to OAEP-decode.
 * @param len Length of data at @b plaintext to decode.
 * @param outbuf Pointer to buffer large enough to hold the decoded data.
 * @param auth Pointer to an authentication string (similar to a password) to include in the encoding.
 * @note @b outbuf must be at least @b len-34 bytes large.
 * @note @b auth Both sender and reciever must know this string if one is provided. Pass NULL to omit.
 * @return The decoded length of the plaintext.
 ***********************************************************************************************************************/
size_t hashlib_RSADecodeOAEP(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* outbuf,
    const uint8_t *auth);

/************************************************************************************************************************
 * @brief RSA-PSS padding scheme
 *
 * Applies the RSA-PSS padding scheme  as indicated in PKCS#1 v1.5.
 * @code
 * |- Message -|  ---------------------- SHA-256 ---------------------->|
 *                                                                      |
 * |-- 0x00 padding --|-- 0x01 --|-- salt --|  |-- 8 bytes 0x00 --|-- mHash --|-- salt --|
 * |----------------------------------------|  |-----------------------------------------|
 * *DB                  |                      *Mprime              |
 *                      |                                        SHA-256
 *                     XOR <------------ MGF1-SHA256 -------------- |
 *                      |                                           |
 *                      |                           < ------------- |
 *                      |                           |
 * |-------------- masked DB --------------|-- Mprime Hash --|-- 0xbc --|
 * |-------------------------- modulus size ----------------------------|
 * @endcode
 *
 * @param plaintext Pointer to buffer containing data to encode.
 * @param len Length of data at @b plaintext to encode.
 * @param outbuf Pointer to buffer to write encoded plaintext to.
 * @param modulus_len The length of the modulus to pad for.
 * @param salt A nonce equal in length to the SHA-256 digest length.
 * @note @b outbuf must be at least @b modulus_len bytes large.
 * @note @b salt can be NULL to generate a salt automatically. You can also generate it yourself
 * 		 using hashlib_RandomBytes() and pass a pointer to that buffer as @b salt.
 * @note If you are trying to validate a signature, use hashlib_SSLVerifySignature().
 * @return the padded length of the plaintext.
 ***********************************************************************************************************************/
size_t hashlib_RSAEncodePSS(
	const uint8_t *plaintext,
	size_t len,
	uint8_t *outbuf,
	size_t modulus_len,
	uint8_t *salt);
 
 /**********************************************************************************************
  * @brief RSA-PSS verification
  *
  * Reverses the PSS MGF1 masking on @b expected and retrieves the salt,
  * then attempts to PSS pad the input given the retrieved salt.
  *
  * @param in Pointer to buffer containing data to verify PSS padding for.
  * @param len Length of data at @b in.
  * @param expected Pointer to buffer containing expected signature.
  * @param modulus_len The size of the signature at @b expected.
  * @return True if signature match, False if failed to verify.
  * *******************************************************************************************/
 bool hashlib_RSAVerifyPSS(
    const uint8_t *in,
    size_t len,
    const uint8_t *expected,
    size_t modulus_len);
    
    
/**********************************************************************************************************************************
 * @brief Authenticated AES Encryption
 *
 * Performs an authenticated encryption of the given message. Supports partial encryption via the
 * @b encryption_offset and @b encryption_len parameters.
 *
 * @param plaintext Pointer to the data to encrypt and authenticate.
 * @param len The size of the plaintext to encrypt and authenticate.
 * @param ciphertext The buffer to write the authenticated encryption to. Must be large enough to hold
 *                  the ciphertext (including any padding) as well as the SHA-256 hash.
 * @param ks Pointer to an AES key schedule context.
 * @param iv Pointer to an initialization vector (a nonce of length equal to the block size).
 * @param ciphermode The cipher mode to use. Can be either @e AES_MODE_CBC or @e AES_MODE_CTR.
 * @param encryption_offset The offset from the start of the plaintext to begin encryption. This is useful if
 *                          you have control bytes or metadata that should not be encrypted.
 * @param encryption_len The size of the data to be encrypted. This is useful if you have trailing bytes
 *                       that should not be encrypted.
 * @note While this function can encrypt part or all of the message, it hashes it in its entirely. This is because
 *      when sending a packet, only sensitive data need be encrypted but the entire packet should be
 *      authenticated.
 * @note To encrypt the entire message, pass 0 for @b encryption_offset and @b len for @b encryption_len.
 ***********************************************************************************************************************************/
aes_error_t hashlib_AESAuthEncrypt(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* ciphertext,
    aes_ctx* key,
    const uint8_t* iv,
    uint8_t ciphermode,
    size_t encryption_offset,
    size_t encryption_len);
    
    

aes_error_t hashlib_AESAuthDecrypt(const uint8_t* in, size_t in_len, uint8_t* out, aes_ctx* key, const uint8_t* iv, uint8_t ciphermode, size_t encr_start, size_t encr_len);
rsa_error_t hashlib_RSAAuthEncrypt(const uint8_t* msg, size_t msglen, uint8_t *ct, const uint8_t* pubkey, size_t keylen);



#endif
