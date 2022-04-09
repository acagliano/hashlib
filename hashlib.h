/**
 *	@file hashlib.h
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

#ifndef HASHLIB_H
#define HASHLIB_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/****************************************************************************************************************************************
 * @def fastRam_Safe
 *		Pointer to a region of fast RAM that is generally safe to use so long as you don't call Libload.
 * @warning Fast Memory gets clobbered by LibLoad. Don't keep long-term storage here if you plan to call LibLoad.
 ****************************************************************************************************************************************/
#define fastRam_Safe		((void*)0xE30A04)
 
 /**************************************************************************************************************************************
  * @def fastRam_Unsafe
  *		Pointer to the start of the region of fast RAM, including the safe region above as well as
  *		a region used by the library's csrng.
  *	@warning Fast Memory gets clobbered by LibLoad. Don't keep long-term storage here if you plan to call LibLoad.
  *	@warning If the CSRNG is run, anything you have stored here will be destroyed.
  **************************************************************************************************************************************/
#define fastRam_Unsafe		((void*)0xE30800)


/*
Cryptographically-Secure Random Number Generator (CS-RNG)

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

The SRNG previded by HASHLIB solves both tests like so:
(next-bit)
    <>  The SRNG's output is derived from a 119-byte entropy pool created by reading
        data from the most entropic byte located within floating memory on the device.
    <>  The "entropic byte" is a byte containing a bit that that, out of 1024 test reads,
        has the closest to a 50/50 split between 1's and 0's.
    <>  The byte containing that bit is read in xor mode seven times per byte to offset
        any hardware-based correlation between subsequent reads from the entropic byte.
    <>  The entropy pool is then run through a cryptographic hash to spread that entropy
        evenly through the returned random value.
    <>  The SRNG produces 96.51 bits of entropy per 32 bit number returned.
    <>  Assertion: A source of randomness with sufficient entropy passed through a cryptographic hash
        will produce output that passes all statistical randomness tests as well as the next-bit test.
(state compromise)
    <>  The entropy pool is discarded after it is used once, and a new pool is
        generated for the next random number.
    <>  ^ This means that the prior state has no bearing on the next output of the PRNG.
    <>  The SRNG destroys its own state after the random number is generated so that
        the state used to generate it does not persist in memory.
        
*   Due to the derivation of entropy from subtle variations in the electrical state of
    unmapped memory, this SRNG can also be considered a _hardware-based RNG_ (HWRNG).
*/
/****************************************************************************************************************************
 * @brief Initializes the crypto-safe random number generator.
 *
 * The SRNG is initialized by polling the 512-bytes from address 0xD65800 to 0xD66000.
 * This region consists of unmapped memory that contains bus noise.
 * Each bit in that region is polled 1024 times and the address with the bit that is the least biased is selected.
 * That will be the byte the SRNG uses to generate entropy.
 * @return boolean: True if a sufficient entropy source was identified. False otherwise.
 * @note Catch and respond to a @b False return from this function. Do not proceed with generating nonces
 *      and encryption keys without ensuring the initialization was successful.
 * @note It may be a good idea to call this function in any program that uses hashlib functions for good measure.
 ***************************************************************************************************************************/
bool csrand_init(void);

/***************************************************************************************************************************
 * @brief Generates a random 32-bit number.
 *
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
Cryptographic Hashes
 
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
 * @note This is internal to the struct hash_ctx. You should never need to use this.
 ********************************************************************************************************************/
typedef struct _sha256_ctx {
	uint8_t data[64];		/**< holds sha-256 block for transformation */
	uint8_t datalen;		/**< holds the current length of data in data[64] */
	uint8_t bitlen[8];		/**< holds the current length of transformed data */
	uint32_t state[8];		/**< holds hash state for transformed data */
} sha256_ctx;

/****************************************************************************************************************
 * @typedef hash_ctx
 * Defines universal hash-state data, including pointer to algorithm-specific handling methods and
 * a union of computational states for various hashes.
 * @note Allocate a seperate context for each seperate data stream you are hashing.
 *****************************************************************************************************************/
typedef struct _hash_ctx {
    bool (*fn_init)(void* ctx);                                     /**< pointer to an initialization method for the given hash algorithm */
    void (*fn_update)(void* ctx, const void* data, size_t len);     /**< pointer to the update method for the given hash algorithm */
    void (*fn_final)(void* ctx, void* output);                      /**< pointer to the digest output method for the given hash algorithm */
    union _hash {           /**< a union of computational states for various hashes */
        sha256_ctx sha256;
    } Hash;
} hash_ctx;
 
 /***************************************************
  * @enum hash_algorithms
  * Idenitifiers for selecting hash types.
  * see hash_init()
  ***************************************************/
enum hash_algorithms {
    SHA256,             /**< algorithm type identifier for SHA-256 */
};

/******************************************************
 * @def SHA256_DIGEST_LEN
 * Binary length of the SHA-256 hash output.
 * ****************************************************/
#define SHA256_DIGEST_LEN   32

/*********************************************************************************************************************
 *	@brief Generic hash initializer.
 *	Initializes the given context with the starting state for the given hash algorithm and
 *  populates pointers to the methods for update and final for the given hash..
 *	@param ctx Pointer to a hash context (hash_ctx).
 *  @param hash_alg The numeric ID of the hashing algorithm to use. See @b hash_algorithms.
 *  @return Boolean. True if hash initialization succeeded. False if hash ID invalid.
 *********************************************************************************************************************/
bool hash_init(hash_ctx* ctx, uint8_t hash_alg);

/******************************************************************************************************
 *	@brief Updates the hash context for the given data.
 *	@param ctx Pointer to a hash context.
 *	@param data Pointer to data to hash.
 *	@param len Number of bytes at @b data to hash.
 *  @note You can use @b ctx.update() as an alternative to this function.
 *      If doing so, you must pass @b &ctx.Hash instead of @b &ctx.
 *	@warning You must have an initialized hash context or a crash will ensue.
 ******************************************************************************************************/
void hash_update(hash_ctx* ctx, const void* data, size_t len);

/**********************************************************************************************
 *	@brief Finalize context and render digest for hash
 *	@param ctx Pointer to a hash context.
 *	@param digest Pointer to a buffer to write the hash to.
 *	@note @b digest must be at large enough to hold the hash digest.
 *  @note You can use @b ctx.final() as an alternative to this function.
 *      If doing so, you must pass @b &ctx.Hash instead of @b &ctx.
 *  @warning You must have an initialized hash context or a crash will ensue.
 *********************************************************************************************/
void hash_final(hash_ctx* ctx, void* digest);

/**********************************************************************************************************************
 *	@brief Arbitrary Length Hashing Function
 *
 *	Computes SHA-256 of the data with a counter appended to generate a hash of arbitrary length.
 *
 *	@param data Pointer to data to hash.
 *	@param datalen Number of bytes at @b data to hash.
 *	@param outbuf Pointer to buffer to write hash output to.
 *	@param outlen Number of bytes to write to @b outbuf.
 *  @param hash_alg The numeric ID of the hashing algorithm to use. See @b hash_algorithms.
 *	@note @b outbuf must be at least @b outlen bytes large.
 **********************************************************************************************************************/
bool hash_mgf1(const void* data, size_t datalen, void* outbuf, size_t outlen, uint8_t hash_alg);


/*
SHA-256 HMAC Cryptographic Hash (Hash-Based Message Authentication Code)

HMAC generates a more secure hash by using a key known only to authorized
parties as part of the hash initialization. Thus, while normal SHA-256 can be
verified by anyone, only the parties with the key can validate using a HMAC hash.
*/

/*******************************************************************************************************************
 * @typedef sha256hmac_ctx
 * Defines hash-state data for an instance of SHA-256.
 * @note This is internal to the struct hmac_ctx. You should never need to use this.
 ********************************************************************************************************************/
typedef struct _sha256hmac_ctx {
    uint8_t ipad[64];       /**< holds the key xored with a magic value to be hashed with the inner digest */
    uint8_t opad[64];       /**< holds the key xored with a magic value to be hashed with the outer digest */
    uint8_t data[64];		/**< holds sha-256 block for transformation */
	uint8_t datalen;		/**< holds the current length of data in data[64] */
	uint8_t bitlen[8];		/**< holds the current length of transformed data */
	uint32_t state[8];		/**< holds hash state for transformed data */
} sha256hmac_ctx;

/*******************************************************************************************************************
 * @typedef hmac_ctx
 * Defines hash-state data for an instance of SHA-256-HMAC.
 * @note If you are hashing multiple data streams concurrently, allocate a seperate context for each.
 ********************************************************************************************************************/
typedef struct _hmac_ctx {
    bool (*fn_init)(void* ctx, const void* key, size_t keylen);     /**< pointer to an initialization method for the given hash algorithm */
    void (*fn_update)(void* ctx, const void* data, size_t len);     /**< pointer to the update method for the given hash algorithm */
    void (*fn_final)(void* ctx, void* output);                      /**< pointer to the digest output method for the given hash algorithm */
    union _hmac {           /**< a union of computational states for various hashes */
        sha256hmac_ctx sha256hmac;
    } Hmac;
} hmac_ctx;

/**********************************************************************************************************************
 *	@brief Context Initializer for SHA-256 HMAC
 *
 *	Initializes the given context with the starting state for SHA-256 HMAC.
 *
 *	@param ctx Pointer to a SHA-256 HMAC context.
 *	@param key Pointer to an authentication key used to initialize the base SHA-256 context.
 *	@param keylen Length of @b key, in bytes.
 *  @param hash_alg The numeric ID of the hashing algorithm to use. See @b hash_algorithms.
 *  @return Boolean. True if hash initialization succeeded. False if hash ID invalid.
 **********************************************************************************************************************/
bool hmac_init(hmac_ctx* ctx, const void* key, size_t keylen, uint8_t hash_alg);

/*************************************************************************************************************
 *	@brief Updates the SHA-256 HMAC context for the given data.
 *	@param ctx Pointer to a SHA-256 HMAC context.
 *	@param data Pointer to data to hash.
 *	@param len Number of bytes at @b data to hash.
 *  @note You may use @b ctx.update() as an alternative to this function.
 *      If doing so, you must pass @b &ctx.Hmac instead of @b &ctx.
 *	@warning You must have an initialized hash context or a crash will ensue.
 **************************************************************************************************************/
void hmac_update(hmac_ctx* ctx, const void* data, size_t len);

/*********************************************************************************************
 *	@brief Finalize Context and Render Digest for SHA-256 HMAC
 *	@param ctx Pointer to a SHA-256 HMAC context.
 *	@param digest Pointer to a buffer to write the hash to.
 *	@note @b digest must be large enough to hold the hash digest.
 *  @note You may use @b ctx.final() as an alternative to this function.
 *      If doing so, you must pass @b &ctx.Hmac instead of @b &ctx.
 *  @warning You must have an initialized hash context or a crash will ensue.
 *********************************************************************************************/
void hmac_final(hmac_ctx* ctx, void* output);

/*********************************************************************************************************************************
 * @brief Password-Based Key Derivation Function
 *
 * Computes a key derived from a password, a 16-byte salt, and a given number of rounds.
 *
 * @param password Pointer to a string containing the password to derive a key from.
 * @param passlen The length of the password (in bytes).
 * @param key The buffer to write the key to. Must be at least @b keylen bytes large.
 * @param keylen The length of the key to generate (in bytes).
 * @param salt A psuedo-random string to use when computing the key.
 * @param saltlen The length of the salt to use (in bytes).
 * @param rounds The number of times to iterate the hash function per block of @b keylen.
 * @param hash_alg The numeric ID of the hashing algorithm to use. See @b hash_algorithms.
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
    size_t rounds,
    uint8_t hash_alg);


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

/*********************************************************************************************
 * @def aes_outsize()
 *
 * Defines a macro to return the size of an AES ciphertext given a plaintext length.
 * Does not include space for  an IV-prepend. See hashlib_AESCiphertextIVLen() for that.
 *
 * @param len The length of the plaintext.
 *********************************************************************************************/
#define aes_outsize(len) \
	((((len)%AES_BLOCKSIZE)==0) ? (len) + AES_BLOCKSIZE : (((len)>>4) + 1)<<4)
	
/************************************************************************************************************************
 * @def aes_extoutsize()
 *
 * Defines a macro to return the size of an AES ciphertext with with an extra block added for the IV.
 *
 * @param len The length of the plaintext.
 ************************************************************************************************************************/
#define aes_extoutsize(len) \
	(aes_outsize((len)) + AES_IVSIZE)

/*********************************************************************************************************************
 * @brief AES import key to key schedule context
 * @param key Pointer to a buffer containing the AES key.
 * @param ks Pointer to an AES key schedule context.
 * @param keylen The size, in bytes, of the key to load.
 * @return True if the key was successfully loaded. False otherwise.
 * @note It is recommended to cycle your key after encrypting 2^64 blocks of data with the same key.
***********************************************************************************************************************/
bool aes_init(const void* key, const aes_ctx* ks, size_t keylen);

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
 * 		aes_encrypt(plaintext, len, &ciphertext[AES_IV_SIZE], ks, iv, <cipher_mode>, <padding_mode>);
 * 		memcpy(ciphertext, iv, AES_IV_SIZE);
 * 		send_packet(ciphertext);
 * 		@endcode
 * 		This will require a buffer at least as large as the size returned by cipher_aes_extoutsize().
 * @return aes_error_t
 *************************************************************************************************************************************************************************/
aes_error_t aes_encrypt(
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
aes_error_t aes_decrypt(
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
 * @param oaep_hash_alg The numeric ID of the hashing algorithm to use within OAEP encoding.
 *      See @b hash_algorithms.
 * @note The size of @b ciphertext and @b keylen must be equal.
 * @note The @b msg will be encoded using OAEP before encryption.
 * @note msg and pubkey are both treated as byte arrays.
 * @return rsa_error_t
 **************************************************************************************************/
rsa_error_t rsa_encrypt(
    const void* msg,
    size_t msglen,
    void* ciphertext,
    const void* pubkey,
    size_t keylen,
    uint8_t oaep_hash_alg);
    

// Miscellaneous Functions

/**************************************************************************************************************
 * @brief Convert a digest to a valid hex string.
 * @param digest Pointer to a buffer or digest to convert.
 * @param len Number of bytes at @b digest to convert.
 * @param hexstr A buffer to write the output hex string to. Must be at least 2 * len + 1 bytes large.
 **************************************************************************************************************/
bool digest_tostring(const void* digest, size_t len, char* hexstr);


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


#ifdef HASHLIB_ENABLE_ADVANCED_MODE

/*
    #### INTERNAL FUNCTIONS ####
    For advanced users only!!!
    
    To enable advanced mode place the directive:
        #define HASHLIB_ENABLE_ADVANCED_MODE
    above any inclusion of this header file.
    
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

#endif
