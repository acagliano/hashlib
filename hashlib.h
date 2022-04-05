/**
 *	@file hashlib.h
 *	@brief	Cryptography Library for the TI-84+ CE
 *
 *	Provides several cryptographic implementations for the TI-84+ CE graphing calculator.
 *	- secure random number generator
 *	- SHA-256, SHA-256 (HMAC)
 *  - PBKDF2_HMAC
 *	- AES: CBC and CTR cipher modes
 *	- AES Padding: PKCS#7, ISO-9797 M2
 *	- RSA public key encryption, 1024 bits <= modulus <= 2048 bits
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


/*
Secure Psuedorandom Number Generator (SPRNG)

Many of the psuedorandom number generators (PRNGs) you find in computers and
even the one within the C toolchain for the CE are insecure for cryptographic
purposes. They produce statistical randomness, but the state is generally seeded
using a value such as rtc_Time(). If an adversary reconstructs the seed, every
output of the PRNG becomes computable with little effort. These types of PRNGs
are called deterministic algorithms--given the input, the output is predictable.
These PRNGs work for games and other applications where the illusion of randomness
is sufficient, but they are not safe for cryptography.

A secure PRNG is an random number generator that is not only statistically random, but
also passes the next-bit and state compromise tests. The _next-bit test_ is defined like so:
given the prior output of the PRNG (bits 0=>i), the next bit (i+1) of the output cannot be
predicted by a polynomial-time statistical test with a probability non-negligibly greater than 50%.
In simpler terms, a secure PRNG must be unpredictable, or "entropic".
The _state compromise test_ means that an adversary gaining knowledge of the initial state of
the PRNG does not gain any information about its output.

The PRNG previded by HASHLIB solves both tests like so:
(next-bit)
    <>  The PRNG's output is derived from a 119-byte entropy pool created by reading
        data from the most entropic byte located within floating memory on the device.
    <>  The "entropic byte" is a byte containing a bit that that, out of 1024 test reads,
        has the closest to a 50/50 split between 1's and 0's.
    <>  The byte containing that bit is read in xor mode seven times per byte to offset
        any hardware-based correlation between subsequent reads from the entropic byte.
    <>  The entropy pool is then run through a cryptographic hash to spread that entropy
        evenly through the returned random value.
    <>  The PRNG produces 96.51 bits of entropy per 32 bit number returned.
    <>  Assertion: A source of randomness with sufficient entropy passed through a cryptographic hash
        will produce output that passes all statistical randomness tests as well as the next-bit test.
(state compromise)
    <>  The entropy pool is discarded after it is used once, and a new pool is
        generated for the next random number.
    <>  ^ This means that the prior state has no bearing on the next output of the PRNG.
    <>  The PRNG destroys its own state after the random number is generated so that
        the state used to generate it does not persist in memory.
*/
/****************************************************************************************************************************
 * @brief Initializes the crypto-safe random number generator.
 *
 * The SPRNG is initialized by polling the 512-bytes from address 0xD65800 to 0xD66000.
 * This region consists of unmapped memory that contains bus noise.
 * Each bit in that region is polled 1024 times and the address with the bit that is the least biased is selected.
 * That will be the byte the SPRNG uses to generate entropy.
 ***************************************************************************************************************************/
bool csrand_init(void);

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
uint32_t csrand_get(void);

/****************************************************************************************
 * @brief Fills a buffer to size with random bytes.
 *
 * @param buffer A pointer to a buffer to write random data to.
 * @param size Number of bytes to write.
 * @note @b buffer must be at least @b size bytes large.
 ****************************************************************************************/
bool csrand_fill(void* buffer, size_t size);
 
 
/*
SHA-256 Cryptographic Hash
 
A cryptographic hash is used to validate that data is unchanged between two endpoints.
It is similar to a checksum, but checksums can be easily fooled; cryptographic hashes
are a lot harder to fool due to how they distribute the bits in a data stream.
The general use of a hash is as follows: the party sending a message hashes it and
includes that hash as part of the message. The recipient hashes the message (except the hash)
themselves and then compares that hash to the one included in the message. If the hashes match,
the message is complete and unaltered. If the hashes do not match, the message is incomplete
or has been tampered with.
*/
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
 
 /******************************************************
  * @def SHA256_DIGEST_LEN
  * Binary length of the SHA-256 hash output.
  ******************************************************/
#define SHA256_DIGEST_LEN		32
 
 /************************************************************
  * @def SHA256_HEXDIGEST_LEN
  * Length of a string containing the SHA-256 hash.
  **********************************************************/
#define SHA256_HEXDIGEST_LEN		(SHA256_DIGEST_LEN<<1) + 1

/**************************************************************************************************
 *	@brief Context initializer for SHA-256.
 *	Initializes the given context with the starting state for SHA-256.
 *	@param ctx Pointer to a SHA-256 context.
 **************************************************************************************************/
void hash_sha256_init(sha256_ctx* ctx);

/******************************************************************************************************
 *	@brief Updates the SHA-256 context for the given data.
 *	@param ctx Pointer to a SHA-256 context.
 *	@param data Pointer to data to hash.
 *	@param len Number of bytes at @b data to hash.
 *	@warning You must call hashlib_Sha256Init() first or your hash state will be invalid.
 ******************************************************************************************************/
void hash_sha256_update(sha256_ctx* ctx, const void* data, size_t len);

/**************************************************************************
 *	@brief Finalize Context and Render Digest for SHA-256
 *	@param ctx Pointer to a SHA-256 context.
 *	@param digest Pointer to a buffer to write the hash to.
 *	@note @b digest must be at least 32 bytes large.
 ***************************************************************************/
void hash_sha256_final(sha256_ctx* ctx, void* digest);

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
void hash_mgf1(const void* data, size_t datalen, void* outbuf, size_t outlen);


/*
SHA-256 HMAC Cryptographic Hash (Hash-Based Message Authentication Code)

HMAC generates a more secure hash by using a key known only to authorized
parties as part of the hash initialization. Thus, while normal SHA-256 can be
verified by anyone, only the parties with the key can validate using a HMAC hash.
*/
/*******************************************************************************************************************
 * @typedef hmac_ctx
 * Defines hash-state data for an instance of SHA-256-HMAC.
 * @note If you are hashing multiple data streams concurrently, allocate a seperate context for each.
 ********************************************************************************************************************/
typedef struct _hmac_ctx {
    uint8_t ipad[64];       /**< holds the key xored with a magic value to be hashed with the inner digest */
    uint8_t opad[64];       /**< holds the key xored with a magic value to be hashed with the outer digest */
    sha256_ctx ctx;         /**< holds the SHA-256 context used by the HMAC function */
} hmac_ctx;

/**********************************************************************************************************************
 *	@brief Context Initializer for SHA-256 HMAC
 *
 *	Initializes the given context with the starting state for SHA-256 HMAC.
 *
 *	@param ctx Pointer to a SHA-256 HMAC context.
 *	@param key Pointer to an authentication key used to initialize the base SHA-256 context.
 *	@param keylen Length of @b key, in bytes.
 **********************************************************************************************************************/
void hmac_sha256_init(hmac_ctx* ctx, const void* key, size_t keylen);

/*************************************************************************************************************
 *	@brief Updates the SHA-256 HMAC context for the given data.
 *	@param ctx Pointer to a SHA-256 HMAC context.
 *	@param data Pointer to data to hash.
 *	@param len Number of bytes at @b data to hash.
 *	@warning You must call hashlib_HMACSha256Init() first or your hash state will be invalid.
 **************************************************************************************************************/
void hmac_sha256_update(hmac_ctx* ctx, const void* data, size_t len);

/***********************************************************************************
 *	@brief Finalize Context and Render Digest for SHA-256 HMAC
 *	@param ctx Pointer to a SHA-256 HMAC context.
 *	@param digest Pointer to a buffer to write the hash to.
 *	@note @b digest must be at least 32 bytes large.
 ***************************************************************************/
void hmac_sha256_final(hmac_ctx* ctx, void* output);

/*************************************************************************************************************************
 *	@brief Resets the SHA-256 HMAC context to its state after a call to hashlib_HMACSha256Init()
 *	@param ctx Pointer to a SHA-256 HMAC context.
 *	@note Calls the SHA-256 Init function, then Updates() the context with the ipad.
 *************************************************************************************************************************/
void hmac_sha256_reset(hmac_ctx* ctx);

/*********************************************************************************************************************************
 * @brief Password-Based Key Derivation Function (via SHA-256 HMAC)
 *
 * Computes a key derived from a password, a 16-byte salt, and a given number of rounds.
 *
 * @param password Pointer to a string containing the password to derive a key from.
 * @param passlen The length of the password (in bytes).
 * @param key The buffer to write the key to. Must be at least @b keylen bytes large.
 * @param keylen The length of the key to generate (in bytes).
 * @param salt A psuedo-random string to use when computing the key.
 * @param saltlen The length of the salt to use (in bytes).
 * @param rounds The number of times to iterate the SHA-256 function per 32-byte block of @b keylen.
 * @note Standards recommend a salt of at least 128 bits (16 bytes).
 * @note @b rounds is used to increase the cost (computational time) of generating a key. What makes password-
 * hashing algorithms secure is the time needed to generate a rainbow table attack against it. More rounds means
 * a more secure key, but more time spent generating it. Current cryptography standards recommend in excess of 1000
 * rounds but that may not be feasible on the CE.
*/
bool hmac_pbkdf2(
    const char* password,
    size_t passlen,
    void* key,
    size_t keylen,
    const void* salt,
    size_t saltlen,
    size_t rounds);


/*
Advanced Encryption Standard (AES)
 
AES is a form of symmetric encryption, and also is a form of block cipher.
Symmetric encryption means that the same key works in both directions.
A block cipher is an encryption algorithm that operates on data in segments (for AES, 16 bytes),
moving through it one segment at a time.
 
Symmetric encryption is usually fast, and is generally more secure for smaller key sizes.
AES is one of the most secure encryption systems in use today.
The most secure version of the algorithm is AES-256 (uses a 256-bit key).
AES is one of the open-source encryption schemes believed secure enough to withstand even
the advent of quantum computing.
*/
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
#define cipher_aes_outsize(len) \
	((((len)%AES_BLOCKSIZE)==0) ? (len) + AES_BLOCKSIZE : (((len)>>4) + 1)<<4)
	
/************************************************************************************************************************
 * @def hashlib_AESCiphertextIVSize()
 *
 * Defines a macro to return the size of an AES ciphertext with with an extra block added for the IV.
 *
 * @param len The length of the plaintext.
 ************************************************************************************************************************/
#define cipher_aes_extoutsize(len) \
	(cipher_aes_outsize((len)) + AES_IVSIZE)

/*********************************************************************************************************************
 * @brief AES import key to key schedule context
 * @param key Pointer to a buffer containing the AES key.
 * @param ks Pointer to an AES key schedule context.
 * @param keylen The size, in bytes, of the key to load.
 * @return True if the key was successfully loaded. False otherwise.
 * @note It is recommended to cycle your key after encrypting 2^64 blocks of data with the same key.
***********************************************************************************************************************/
bool cipher_aes_loadkey(const void* key, const aes_ctx* ks, size_t keylen);

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
    AES_INVALID_CIPHERTEXT              /**< AES operation failed, ciphertext error */
} aes_error_t;

/**********************************************************************************************************************************************************************
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
 * 		cipher_aes_encrypt(plaintext, len, &ciphertext[AES_IV_SIZE], ks, iv, <cipher_mode>, <padding_mode>);
 * 		memcpy(ciphertext, iv, AES_IV_SIZE);
 * 		send_packet(ciphertext);
 * 		@endcode
 * 		This will require a buffer at least as large as the size returned by hashlib_AESCiphertextIVSize().
 * @return aes_error_t
 *************************************************************************************************************************************************************************/
aes_error_t cipher_aes_encrypt(
    const void* plaintext,
    size_t len,
    void* ciphertext,
    const aes_ctx* ks,
    const void* iv,
    uint8_t ciphermode,
    uint8_t paddingmode);

/**************************************************************************************************************************************************
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
 * @return aes_error_t
 **************************************************************************************************************************************************/
aes_error_t cipher_aes_decrypt(
    const void* ciphertext,
    size_t len,
    void* plaintext,
    const aes_ctx* ks,
    const void* iv,
    uint8_t ciphermode,
    uint8_t paddingmode);

/*
 RSA Public Key Encryption
 
 Public key encryption is a form of asymmetric encryption.
 This means that a key only works in one direction, and both parties need a public key
 and a private key. The private key is used to decrypt a message and the public key is
 used to encrypt.
 In RSA, the public and private keys are modular inverses of each other, such that:
 encrypted = message ** public exponent % public key, and
 message = encrypted ** private exponent % private modulus
 ** means power, % means modulus
 
 65537 (and a few other Fermat primes) are commonly used as public exponents.
 The public key (modulus) is sent in the clear and is known to to everyone.
 The cryptographic strength of RSA comes from the difficulty of factoring the modulus.
 Asymmetric encryption is generally VERY slow. Using even RSA-1024 on the TI-84+ CE will
 take several seconds. For this reason, you usually do not use RSA for sustained encrypted
 communication. Use RSA to share a symmetric key, and then use AES for future messages.
 
 */

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
 * @return rsa_error_t
 **************************************************************************************************/
rsa_error_t cipher_rsa_encrypt(
    const void* msg,
    size_t msglen,
    void* ciphertext,
    const void* pubkey,
    size_t keylen);
    

// Miscellaneous Functions

/**************************************************************************************************************
 * @brief Convert a digest to a valid hex string.
 * @param digest Pointer to a buffer or digest to convert.
 * @param len Number of bytes at @b digest to convert.
 * @param hexstr A buffer to write the output hex string to. Must be at least 2 * len + 1 bytes large.
 **************************************************************************************************************/
bool digest_fromstring(const void* digest, size_t len, char* hexstr);


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
bool digest_compare(const void* digest1, const void* digest2, size_t len);


#endif
