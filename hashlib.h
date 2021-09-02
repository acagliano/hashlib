/**
 *	@file hashlib.h
 *	@brief	Cryptography Library for the TI-84+ CE
 *
 *	Provides several cryptographic implementations for the TI-84+ CE graphing calculator.
 *	- secure random number generator
 *	- SHA-256
 *	- AES: CBC, CTR, CBC-MAC
 *	- AES Padding: PKCS#7, ISO_M2
 *	- RSA public key encryption, modulus <= 2048 bits
 *	- RSA Padding: RSA-OAEP via PKCS#7 v2.2, RSA-PSS via PKCS#7 v1.5
 *
 *	@author Anthony "ACagliano" Cagliano
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
 * @note #buffer must be at least #size bytes large.
 ****************************************************************************************/
bool hashlib_RandomBytes(uint8_t *buffer, size_t size);
 
 
// SHA-256 Cryptographic Hash
/*******************************************************************************************************************
 * @typedef SHA-256 Context
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
 * A buffer of this length, in bytes, must be passed to hashlib_Sha256Init().
 **************************************************************************************/
 #define SHA256_MBUFFER_LEN	(64 * 4)
 
 /******************************************************
  * @def SHA256_DIGEST_LEN
  * Binary length of the SHA-256 hash output.
  ******************************************************/
 #define SHA256_DIGEST_LEN   32
 
 /************************************************************
  * @def SHA256_HEXSTR_LEN
  * Length of a string containing the SHA-256 hash.
  **********************************************************/
#define SHA256_HEXSTR_LEN   (SHA256_DIGEST_LEN<<1) + 1

/********************************************************************************************
 *	@brief Context initializer for SHA-256.
 *	Initializes the given context with the starting state for SHA-256.
 *	@param ctx Pointer to a SHA-256 context.
 *	@param mbuffer Pointer to a temporary memory buffer.
 *	@note #mbuffer must be at least #SHA256_MBUFFER_LEN bytes large.
 *******************************************************************************************/
void hashlib_Sha256Init(sha256_ctx *ctx, uint32_t *mbuffer);

/******************************************************************************************************
 *	@brief Updates the SHA-256 context for the given data.
 *	@param ctx Pointer to a SHA-256 context.
 *	@param buf Pointer to data to hash.
 *	@param len Number of bytes at @param buf to hash.
 *	@warning You must call hashlib_SHA256Init() first or your hash state will be invalid.
 ******************************************************************************************************/
void hashlib_Sha256Update(sha256_ctx *ctx, const uint8_t *buf, uint32_t len);

/**************************************************************************
 *	@brief Finalize Context and Render Digest for SHA-256
 *	@param ctx Pointer to a SHA-256 context.
 *	@param digest Pointer to a buffer to write the hash to.
 *	@note #digest must be at least 32 bytes large.
 ***************************************************************************/
void hashlib_Sha256Final(sha256_ctx *ctx, uint8_t *digest);

/**********************************************************************************************************************
 *	@brief Arbitrary Length Hashing Function
 *	Computes SHA-256 of the data and with a counter appended to generate a hash of arbitrary length.
 *	@param data Pointer to data to hash.
 *	@param datalen Number of bytes at @param data to hash.
 *	@param outbuf Pointer to buffer to write hash output to.
 *	@param outlen Number of bytes to write to @param outbuf.
 *	@note #outbuf Must be at least #outlen bytes large.
 **********************************************************************************************************************/
void hashlib_MGF1Hash(uint8_t* data, size_t datalen, uint8_t* outbuf, size_t outlen);


// Advanced Encryption Standard (AES)
/***************************************************************************************************
 * @typedef Context Definition for AES key schedule
 * Stores AES key instance data: key size and round keys generated from an AES key.
 ***************************************************************************************************/
typedef struct _aes_ctx {
    uint24_t keysize;
    uint32_t round_keys[60];
} aes_ctx;

/************************************************
 * @enum Supported AES cipher modes
 ************************************************/
enum aes_cipher_modes {
	AES_MODE_CBC,		/**< selects CBC mode */
	AES_MODE_CTR		/**< selects CTR mode */
};

/***************************************************
 * @enum Supported AES padding schemes
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
 * @def AES_IV_SIZE
 * Defines the length of the AES initalization vector (IV).
 *****************************************************************/
#define AES_IV_SIZE		AES_BLOCKSIZE

/************************************************************
 * @def AES_MAC_SIZE
 * Defines the length of the AES CBC-MAC digest.
 ************************************************************/
#define AES_MAC_SIZE	AES_BLOCKSIZE

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

/***************************************************************************
 * @def hashlib_AESPaddedSize()
 * Defines a macro to return the padded size of an AES plaintext.
 * @param len The length of the plaintext.
 ***************************************************************************/
  #define hashlib_AESPaddedSize(len) \
	((((len)%AES_BLOCKSIZE)==0) ? (len) + AES_BLOCKSIZE : (((len)>>4) + 1)<<4)
	
/************************************************************************************************************************
 * @def hashlib_AESCiphertextLen()
 *
 * Defines a macro to return the size of an AES ciphertext.
 *
 * @param len The length of the plaintext.
 * @note This is the padded length of the plaintext, plus an additional block for the IV to be prepended.
 ************************************************************************************************************************/
 #define hashlib_AESCiphertextLen(len)	(hashlib_AESPaddedSize((len)) + AES_IV_SIZE)
 
 /******************************************************************************************************
  * @def hashlib_AESAuthMacCiphertextLen()
  *
  * Defines a macro to return the size of an AES ciphertext with CBC-MAC authentication.
  *
  * @param len The length of the plaintext.
  * @note This is the ciphertext length from the previous macro with an additional block
  * 	for the CBC-MAC of the ciphertext to be appended.
  ******************************************************************************************************/
  #define hashlib_AESAuthMacCiphertextLen(len) \
	(hashlib_AESCiphertextLen((len)) + AES_MAC_SIZE)
	
/******************************************************************************************************
 * @def hashlib_AESAuthSha256CiphertextLen()
 *
 * Defines a macro to return the size of an AES ciphertext with SHA-256 authentication.
 *
 * @param len The length of the plaintext.
 * @note This is the ciphertext length from the previous macro with an additional 32 bytes
 * 		for the SHA-256 of the ciphertext to be appended.
  ******************************************************************************************************/
  #define hashlib_AESAuthSha256CiphertextLen(len) \
	(hashlib_AESCiphertextLen((len)) + SHA256_DIGEST_LEN)

/***************************************************************************************
 * @def hashlib_AESKeygen()
 * Defines a macro to generate a pseudorandom AES key of a given length.
 * @param key Pointer to a buffer to write the key into.
 * @param kelen The byte length of the key to generate.
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
 * @warning ECB-mode ciphers are insecure (see many-time pad vulnerability)
 * 		These functions are exposed in case a user wants to construct a cipher mode other than CBC or CTR.
 * 		Unless you know what you are doing, use hashlib_AESEncrypt() instead.
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
 *	@warning ECB-mode ciphers are insecure (see many-time pad vulnerability)
 *		These functions are exposed in case a user wants to construct a cipher mode other than CBC or CTR.
 *		Unless you know what you are doing, use hashlib_AESDecrypt() instead.
 *	@return True if encryption succeeded. False if an error occured.
 **********************************************************************************************************************************/
bool hashlib_AESDecryptBlock(const uint8_t* block_in,
							 uint8_t* block_out,
							 const aes_ctx* ks);

/**
 * @brief General-Purpose AES Encryption
 * @param plaintext Pointer to data to encrypt.
 * @param len Length of data at @param plaintext to encrypt.
 * @param ciphertext Pointer to buffer to write encrypted data to.
 * @param ks Pointer to an AES key schedule context.
 * @param iv Pointer to an initialization vector (a nonce of length equal to the block size).
 * @param ciphermode The cipher mode to use. Can be either @e AES_MODE_CBC or @e AES_MODE_CTR.
 * @note @b plaintext and @b ciphertext are aliasable.
 * @note If cipher mode CBC is used, @b len must be a multiple of the blocksize.
 * 		You can pass the plaintext through a padding function prior to calling this function.
 * 		@see hashlib_AESPadMessage()
 * @return True if the encryption succeded. False if an error occured.
 */
bool hashlib_AESEncrypt(const uint8_t* plaintext,
						size_t len,
						uint8_t* ciphertext,
						const aes_ctx* ks,
						const uint8_t* iv,
						uint8_t ciphermode);

/**
 * @brief General-Purpose AES Decryption
 * @param ciphertext Pointer to data to decrypt.
 * @param len Length of data at @param ciphertext to decrypt.
 * @param plaintext Pointer to buffer to write decryped data to.
 * @param ks Pointer to an AES key schedule context.
 * @param iv Pointer to an initialization vector (a nonce of length equal to the block size).
 * @param ciphermode The cipher mode to use. Can be either  @e AES_MODE_CBC or  @e AES_MODE_CTR.
 * @note @b plaintext and @b ciphertext are aliasable.
 * @note @b IV should be the same as what is used for encryption.
 * @return True if the encryption succeded. False if an error occured.
 */
bool hashlib_AESDecrypt(const uint8_t* ciphertext,
						size_t len,
						uint8_t* plaintext,
						const aes_ctx* ks,
						const uint8_t* iv,
						uint8_t ciphermode);
    
/*************************************************************************************************************************************
 * @brief Returns a message authentication code for an AES message.
 *
 * The MAC is a tag equal in length to the AES block size computed by passing the plaintext
 * through the CBC-MAC algorithm with a constant IV.
 *
 * @param plaintext Pointer to data to generate a MAC for.
 * @param len Length of data at @param plaintext to generate a MAC for.
 * @param mac Pointer to a buffer to write the MAC to.
 * @note CBC-MAC requires padding, as it uses CBC mode. You can use the hashlib_AESPadMessage()
 * 	padding function. Padding mode ISO-9791 M2 is preferred for CBC-MAC, but either can be used.
 * @warning Do not use the same AES key/key schedule for authentication and encryption. This exposes
 * 	attack vectors. Use different key schedules.
 * @warning For the most secure authenticated encryption scheme,  use "encrypt-then-MAC".
 * 		This means that you encrypt first, then you return a MAC or hash of the ciphertext
 *		and any associated un-encrypted metadata (such as the IV).
 *		While some authentication schemes do use "MAC-then-encrypt", there are more attack vectors against that.
 * @return True if the MAC generation succeeded. False if an error occured.
 ***************************************************************************************************************************************/
bool hashlib_AESOutputMac(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* mac,
    const aes_ctx* ks);

/*****************************************************************************************
 * @brief Pads a plaintext according to the specified AES padding scheme.
 * @param plaintext Pointer to buffer containing the data to pad.
 * @param len Length of data at @param plaintext to pad.
 * @param outbuf Pointer to buffer to write padded data.
 * @param schm The AES padding scheme to use.
 * @note @b plaintext and @b outbuf are aliasable.
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
 * @param len Length of data at @param plaintext to strip.
 * @param outbuf Pointer to buffer to write stripped data.
 * @param schm The AES padding scheme to use.
 * @note @b plaintext and @b outbuf are aliasable.
 * @return The length of the message with padding removed.
 ****************************************************************************************************************/
size_t hashlib_AESStripPadding(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* outbuf,
    uint8_t schm);

// RSA Public Key Encryption
/*************************************************************************************************
 * @enum SSL signature algorithms
****************************************************************************************************/
enum _ssl_sig_modes {
	SSLSIG_RSA_SHA256,		/**< RSA with SHA-256 signature algorithm */
	SSLSIG_ECDSA			/**< ECDSA (unimplemented, likely a long way off) */
};

/************************************************************************************************************************
 * @brief RSA-OAEP padding scheme
 *
 * Applies the RSA-OAEP padding scheme as indicated in PKCS#1 v2.2.
 * This is intended for use prior to RSA encryption.
 * | <------------------------------------- modulus size ---------------------------------------> |	\n
 * |-- 0x00 --|-- salt --|-- auth hash --|-- 0x00...padding --|-- 0x01 --|-- message --|	\n
 *		     |     |---------------------------------------|-------------------------------------|	\n
 *			 |	     					  |						\n
 *			 | -------- MGF1-SHA256 ------->  XOR						\n
 *			 |					      	  |						\n
 *		   XOR <-------- MGF1-SHA256 ---------|						\n
 *			 |					           |						\n
 * |-- 0x00 --|- msalt -|-------- masked message, padding, and auth hash --------|	\n
 * |<------------------------------------- modulus size ---------------------------------------> |	\n
 *
 * @param plaintext Pointer to a buffer containing the data to OAEP-encode.
 * @param len Length of data at @param plaintext to encode.
 * @param outbuf Pointer to buffer large enough to hold the padded data.
 * @param modulus_len The byte length of the modulus to pad for.
 * @param auth Pointer to an authentication string (similar to a password) to include in the encoding.
 * @note @b outbuf must be at least @b modulus_len bytes large.
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
 * @param len Length of data at @param plaintext to decode.
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
 * |----- Message -----|  ------------------------- SHA-256 ------------------------->|				\n
 * 									  				 |				\n
 * |-- 0x00... padding --|-- 0x01 --|-- salt --|		|-- 8 bytes 0x00 --|-- mHash --|-- salt --|		\n
 * |--------------------------------------------------|		|--------------------------------------------------|		\n
 *	*DB			|					 *M'			    |					\n
 *				|					      		     SHA-256				\n
 *			  XOR <----------------- MGF1-SHA256 ------------------|					\n
 *				|								    |					\n
 *				|				     < ------------------------- |					\n
 *				|			     	     |									\n
 * |---------------- masked DB ----------------|-- M' Hash --|-- 0xbc --|						\n
 * |----------------------------- modulus size -------------------------------|						\n
 *
 * @param plaintext Pointer to buffer containing data to encode.
 * @param len Length of data at @param plaintext to encode.
 * @param outbuf Pointer to buffer to write encoded plaintext to.
 * @param modulus_len The length of the modulus to pad for.
 * @param salt A buffer filled with random bytes.
 * @note @b outbuf must be at least @b modulus_len bytes large.
 * @note If you are trying to generate a signature, pass NULL to generate a new salt.
 * @note If you are trying to validate a signature, use hashlib_SSLVerifySignature().
 * @return the padded length of the plaintext.
 ***********************************************************************************************************************/
size_t hashlib_RSAEncodePSS(
	const uint8_t *plaintext,
	size_t len,
	uint8_t *outbuf,
	size_t modulus_len,
	uint8_t *salt);
	
	
// Miscellaneous Functions
/**************************************************************************************************************
 * @brief Secure erase context.
 * @param ctx Pointer to any context or buffer you want to erase.
 * @param len Number of bytes at @b ctx to erase.
 * @note It is advised to call this on every cryptographic context and encryption buffer used.
 **************************************************************************************************************/
void hashlib_EraseContext(void *ctx, size_t len);

/*************************************************************************************************
 * @def Dynamically allocates a block of memory to be used for a context or buffer.
 * @param size Size of the buffer to malloc.
 * @return Same as @b malloc()
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


#endif
