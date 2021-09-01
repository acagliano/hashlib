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
#define hashlib_FastMemBufferUnSafe		((void*)0xE30800)


/**********************************************************************************
 *  Secure Psuedorandom Number Generator (SPRNG)
 *  =========================================
 *
 * 	An entropy-based, non-deterministic secure PRNG.
 * 	Generates 96.51 bits of entropy per 32-bit number generated
 *********************************************************************************/
 
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


/**************************************************************
 * Cryptographic Hashes
 * ==================
 *
 * Implements the following cryptographic hashes:
 *	SHA-256
 * 	MGF1-SHA256
 **************************************************************/
 
/** @struct SHA-256 Hash State Context */
typedef struct _sha256_ctx {
	uint8_t data[64];		/**< holds sha-256 block for transformation */
	uint8_t datalen;		/**< holds the current length of data in data[64] */
	uint8_t bitlen[8];		/**< holds the current length of transformed data */
	uint32_t state[8];		/**< holds hash state for transformed data */
} sha256_ctx;

/******************************************************
 * @def SHA256_MBUFFER_LEN
 * Temporary memory buffer.
 * Must be passed to hashlib_Sha256Init().
 ******************************************************/
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

/********************************************************************************************
 * @brief Advanced Encryption Standard (AES) Implementation
 *
 *	Supports 128, 192, and 256 bit keys.
 *	Implements the following cipher modes:
 *		CBC mode
 *		CTR mode
 *		CBC-MAC authentication
 */

/** Context Definition for AES key schedule */
typedef struct _aes_ctx {
    uint24_t keysize;
    uint32_t round_keys[60];
} aes_ctx;

/**
 *	@brief AES Defines and Equates
 *
 *	@def AES_BLOCKSIZE Defines the blocksize of the AES cipher.
 *	@def AES_IV_SIZE	Defines the length of the AES iniitalization vector (IV).
 *	@def AES_MAC_SIZE Defines the length of the AES CBC-MAC digest.
 *	@def AES128_KEYLEN Defines the byte-length of a 128-bit AES key.
 *	@def AES192_KEYLEN Defines the byte-length of a 192-bit AES key.
 *	@def AES256_KEYLEN Defines the byte-length of a 256-bit AES key.
 *	@def hashlib_AESPaddedSize() Defines the padded size of an AES plaintext.
 *	@def hashlib_AESCiphertextLen() Defines the length of an AES ciphertext with prepended IV.
 *	@def hashlib_AESAuthCiphertextLen() Defines the length of an AES ciphertext with prepended IV and appended CBC-MAC.
 */
#define AES_BLOCKSIZE	16
#define AES_IV_SIZE		AES_BLOCKSIZE
#define AES_MAC_SIZE	AES_BLOCKSIZE

#define AES128_KEYLEN	16
#define AES192_KEYLEN	24
#define AES256_KEYLEN	32

#define hashlib_AESPaddedSize(len) \
	((((len)%AES_BLOCKSIZE)==0) ? (len) + AES_BLOCKSIZE : (((len)>>4) + 1)<<4)

#define hashlib_AESCiphertextLen(len)	(hashlib_AESPaddedSize((len)) + AES_IV_SIZE)

#define hashlib_AESAuthCiphertextLen(len) \
	(hashlib_AESCiphertextLen((len)) + AES_MAC_SIZE)
	
/** @brief AES cipher modes */
enum aes_cipher_modes {
	AES_MODE_CBC,
	AES_MODE_CTR
};

/** @brief AES padding schemes */
enum aes_padding_schemes {
    SCHM_PKCS7, 		 		/**< PKCS#7 padding | DEFAULT */
    SCHM_DEFAULT = SCHM_PKCS7,	/**< selects the scheme marked DEFAULT.
									Using this is recommended in case a change to the standards
									would set a stronger padding scheme as default */
    SCHM_ISO2,       	 	/**< ISO-9797 M2 padding */
    
};

/**
 *	@brief AES key generation function.
 *
 *	@param key Pointer to a buffer to write the AES key.
 *	@param keylen Size, in bytes, of the key to generate.
 */
#define hashlib_AESKeygen(key, keylen)	hashlib_RandomBytes((key), (keylen))


/**
 * @brief AES import key to key schedule context
 *
 * @param key Pointer to a buffer containing the AES key.
 * @param ks Pointer to an AES key schedule context.
 * @param keylen The size, in bytes, of the key to load.
 * @return True if the key was successfully loaded. False otherwise.
*/
bool hashlib_AESLoadKey(const uint8_t* key, const aes_ctx* ks, size_t keylen);

/**
 *	@brief AES Single-Block Encryption (ECB mode)
 *	@warning ECB-mode ciphers are insecure (see many-time pad vulnerability)
		These functions are exposed in case a user wants to construct a cipher mode other than CBC or CTR.
		Unless you know what you are doing, use hashlib_AESEncrypt() instead.
	
 *	@param block_in	Pointer to block of data to encrypt.
 *	@param block_out Pointer to buffer to write encrypted block.
 *	@param ks Pointer to an AES key schedule context.
 *	@note @param block_in and @param block_out are aliasable.
	@return True if encryption succeeded. False if failed.
 */
bool hashlib_AESEncryptBlock(const uint8_t* block_in,
							 uint8_t* block_out,
							 const aes_ctx* ks);
    
/**
 *	@brief AES Single-Block Decryption (ECB Mode)
 *	@warning ECB-mode ciphers are insecure (see many-time pad vulnerability)
		These functions are exposed in case a user wants to construct a cipher mode other than CBC or CTR.
		Unless you know what you are doing, use hashlib_AESDecrypt() instead.
 *
 *	@param block_in Pointer to block of data to decrypt.
 *	@param block_out Pointer to buffer to write decrypted block.
 *	@param ks Pointer to an AES key schedule context.
 *	@return True if encryption succeeded. False if an error occured.
 */
bool hashlib_AESDecryptBlock(const uint8_t* block_in,
							 uint8_t* block_out,
							 const aes_ctx* ks);

/**
 * @brief AES Encryptor Function
 *
 * @param plaintext Pointer to data to encrypt.
 * @param len Length of data at @param plaintext to encrypt.
 * @param ciphertext Pointer to buffer to write encrypted data to.
 * @param ks Pointer to an AES key schedule context.
 * @param iv Pointer to an initialization vector (a nonce of length equal to the block size).
 * @param ciphermode The cipher mode to use. Can be either AES_MODE_CBC or AES_MODE_CTR.
 * @note If cipher mode CBC is used, @param len must be a multiple of the blocksize.
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
 * @brief AES Decryptor Function
 *
 * @param ciphertext Pointer to data to decrypt.
 * @param len Length of data at @param ciphertext to decrypt.
 * @param plaintext Pointer to buffer to write decryped data to.
 * @param ks Pointer to an AES key schedule context.
 * @param iv Pointer to an initialization vector (a nonce of length equal to the block size).
 * @param ciphermode The cipher mode to use. Can be either AES_MODE_CBC or AES_MODE_CTR.
 * @note the IV should be the same as what is used for encryption.
 * @return True if the encryption succeded. False if an error occured.
 */
bool hashlib_AESDecrypt(const uint8_t* ciphertext,
						size_t len,
						uint8_t* plaintext,
						const aes_ctx* ks,
						const uint8_t* iv,
						uint8_t ciphermode);
    
/**
 * @brief Returns a message authentication code (MAC) for an AES message.
 *
 * The MAC is a tag equal in length to the AES block size computed by passing the plaintext
 * through the CBC-MAC algorithm with a constant IV (filled with zeroes in this implementation).
 *
 * 	@param plaintext Pointer to data to generate a MAC for.
 * 	@param len Length of data at @param plaintext to generate a MAC for.
 * 	@param mac Pointer to a buffer to write the MAC to.
 * 	@return True if the MAC generation succeeded. False if an error occured.
 * 	@note CBC-MAC requires padding, as it uses CBC mode. You can use the hashlib_AESPadMessage()
 * 	padding function. Padding mode ISO-9791 M2 is preferred for CBC-MAC, but either can be used.
 *  @warning Do not use the same AES key/key schedule for authentication and encryption. This exposes
 * 	attack vectors. Use different key schedules.
 */
bool hashlib_AESOutputMac(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* mac,
    const aes_ctx* ks);

/**
 * @brief Pads a plaintext according to the specified AES padding scheme.
 *
 * @param plaintext Pointer to buffer containing the data to pad.
 * @param len Length of data at @param plaintext to pad.
 * @param outbuf Pointer to buffer to write padded data.
 * 	@note @param outbuf and @param plaintext are aliasable.
 * @param schm The AES padding scheme to use.
 * @return The padded length of the message.
 */
size_t hashlib_AESPadMessage(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* outbuf,
    uint8_t schm);

/**
 * @brief Strips the padding from a message according to the specified AES padding scheme.
 *
 * @param plaintext Pointer to buffer containing the data to strip.
 * @param len Length of data at @param plaintext to strip.
 * @param outbuf Pointer to buffer to write stripped data.
 * 	@note @param outbuf and @param plaintext are aliasable.
 * @param schm The AES padding scheme to use.
 * @return The length of the message with padding removed.
 */
size_t hashlib_AESStripPadding(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* outbuf,
    uint8_t schm);


/********************************************************************************************
 * @brief RSA Pubkey and SSL Verification Implementation
 *
 * work-in-progress
 * supports modulus size from 1024 to 2048 bits
 * public exponent e = 65537, hardcoded
 *
 * For compatibility with server-side decryption/decode, please make sure
 * your encoding algorithm specs on the host match those hardcoded by this library.
 * 	- Hashing oracle where applicable: SHA-256.
 * 	- Mask Generation Function where applicable: MGF1, using SHA-256
*/

/** SSL Signature Algorithms */
enum _ssl_sig_modes {
	SSLSIG_RSA_SHA256,
	SSLSIG_ECDSA		// will likely be a long way off
};

/**
 * @brief RSA-OAEP padding scheme
 *
 * Applies the RSA-OAEP padding scheme as indicated in PKCS#1 v2.2.
 * This is intended for use prior to RSA encryption.
 *
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
 * 	@note Buffer must be at least equal to @param modulus_len.
 * @param modulus_len The byte length of the modulus to pad for.
 * @param auth Pointer to an authentication string (similar to a password) to include in the encoding.
 * 	@note Both sender and reciever must know this string if one is provided.
 * 	@note Pass NULL to omit.
 * @return The padded length of the plaintext.
 */
size_t hashlib_RSAEncodeOAEP(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* outbuf,
    size_t modulus_len,
    const uint8_t *auth);
    
/**
 * @brief RSA-OAEP padding scheme, reverse algorithm
 *
 * Reverses the RSA-OAEP padding scheme as indicated in PKCS#1 v2.2.
 *
 * @param plaintext Pointer to a buffer containing the data to OAEP-decode.
 * @param len Length of data at @param plaintext to decode.
 * @param outbuf Pointer to buffer large enough to hold the decoded data.
 * 	@note Buffer should be equal to @param len minus 34, in bytes.
 * @param auth Pointer to an authentication string (similar to a password) to include in the encoding.
 * 	@note Both sender and reciever must know this string if one is provided.
 * 	@note Pass NULL to omit.
 * @return The decoded length of the plaintext.
*/
size_t hashlib_RSADecodeOAEP(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* outbuf,
    const uint8_t *auth);

/**
 * @brief RSA-PSS padding scheme
 *
 * Applies the RSA-PSS padding scheme  as indicated in PKCS#1 v1.5.
 *
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
 * 	@note Must be at least equal to @param modulus_len.
 * @param modulus_len The length of the modulus to pad for.
 * @param salt A buffer filled with random bytes.
 * 	@note If you are trying to generate a signature, pass NULL to generate a new salt.
 * 	@note If you are trying to validate a signature, you should be using hashlib_SSLVerifySignature() instead.
 * 		@see hashlib_SSLVerifySignature
 * @return the padded length of the plaintext.
 */
size_t hashlib_RSAEncodePSS(
	const uint8_t *plaintext,
	size_t len,
	uint8_t *outbuf,
	size_t modulus_len,
	uint8_t *salt);
	
	
	

// ###################################
// ##### MISCELLANEOUS FUNCTIONS #####
// ###################################

/*
    Erases the data in a context, ensuring that no traces of cryptographic arithmetic remain.
    
    # Inputs #
    <> ctx = pointer to an arbitrary context type from this library
    <> len = length in bytes to zero
    
    Example: hashlib_EraseContext(&sha1_ctx, sizeof(sha1_ctx));
    * It is advised to call this on every context declared in your program before exiting or freeing that region
 */
void hashlib_EraseContext(void *ctx, size_t len);


/*
    A helper macro that allocates bytes for a context or data buffer.
	Uses malloc.
 */
#define hashlib_AllocContext(size)		malloc((size))


/*
    Compares the pointed buffers digest1 and digest2 for size len.
    This function is resistant to timing attacks.
    
    # Input #
    <> digest1 = pointer to first buffer to compare
    <> digest2 = pointer to second buffer to compare
    <> len = number of bytes to compare
 */
hashlib_CompareDigest(const uint8_t* digest1, const uint8_t* digest2, size_t len);


#endif
