#ifndef HASHLIB_H
#define HASHLIB_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// INCLUDE FILE FOR HASHLIB

// ###################################################
// ## Context Definitions for Hashes and Encryption ##
// ###################################################

typedef struct _sha256_ctx {
	uint8_t data[64];
	uint8_t datalen;
	uint8_t bitlen[8];
	uint32_t state[8];
} sha256_ctx;

typedef struct {
    uint24_t keysize;
    uint32_t round_keys[60];
} aes_ctx;


// ###############################
// ##### DEFINES and EQUATES #####
// ###############################

/* SHA Size Defines */
#define SHA256_DIGEST_LEN   32
#define SHA256_HEXSTR_LEN   (SHA256_DIGEST_LEN<<1) + 1      // 2x digest len, plus null
#define SHA256_MBUFFER_LEN	(64 * 4)

/* AES Size Defines */
#define AES_BLOCKSIZE	16
#define AES_IV_SIZE		AES_BLOCKSIZE
#define AES_MAC_SIZE	AES_BLOCKSIZE

/* AES Padded Size - Data only */
#define hashlib_AESPaddedSize(len) \
	((((len)%AES_BLOCKSIZE)==0) ? (len) + AES_BLOCKSIZE : (((len)>>4) + 1)<<4)

/* AES Ciphertext Size - Padded Size + IV Size */
#define hashlib_AESCiphertextSize(len)	\
	(hashlib_AESPaddedSize((len)) + AES_IV_SIZE)
	
/* Ciphertext Size with Authenticated Encryption (MAC) - Padded Size + IV Size + MAC Size */
#define hashlib_AESAuthCiphertextSize(len)	\
	(hashlib_AESCiphertextSize((len)) + AES_MAC_SIZE)

/* Returns the OAEP-padded size of an RSA plaintext - simply equal to modulus size */
#define hashlib_RSAPaddedSize(modulus_len)   (modulus_len)

/*
	## Fast Memory Defines ##
	
	You can use FastMem to make some of the write-heavy routines run a bit faster
	
	* NOTE This region gets clobbered by LIBLOAD
	If Libload runs, any contexts in use will be destroyed
	
	***************************************************************************************
		NOTE: The first 525 bytes of FastMem are reserved for use by the SPRNG to
		accelerate the entropy pool and SHA functions it uses. If you are using the
		SPRNG for anything in your program, start addressing fast memory
		buffers at `hashlib_FastMemBufferSafe`.
		If you are NOT using the SPRNG at all in your program, you can safely start
		addressing your buffers at `hashlib_FastMemBufferUnsafe`.
	***************************************************************************************
*/

#define hashlib_FastMemBufferUnsafe		((void*)0xE30800)	// DO NOT USE IF USING THE SPRNG
#define hashlib_FastMemBufferSafe		((void*)0xE30A04)


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
    A helper macro that returns a hashlib context (see defines above)
    Can also be used to malloc buffers for encryption/decryption/padding/etc.
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


    
/*
    Pads input data in an RSA plaintext according to the Optimal Asymmetric Encryption Padding (OAEP) scheme.
    
    |---------|--------------------------|-----------------|
    | Message | 0x00, 0x00,... (Padding) | Salt (16 bytes) |    == modulus len
    |---------|--------------------------|-----------------|
                         |                        |
                        XOR  <------SHA-256--------
                         |                        |
                         |-------SHA-256-------> XOR
                         |                        |
    |------------------------------------|-----------------|
    |     Encoded Message + Padding      |  Encoded Salt   |
    |------------------------------------|-----------------|
    
    # Inputs #
    <> plaintext = pointer to buffer containing data to pad
    <> len = size of data to pad, in bytes
    <> outbuf = pointer to buffer large enough to hold padded data (see macros below)
    <> modulus_len = the bit-length of the modulus, used to determine the padded message length
 */
size_t hashlib_RSAPadMessage(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* outbuf,
    size_t modulus_len);
    
/*
    Reverses the padding on an RSA plaintext according to the OAEP padding scheme.
    
    # Inputs #
    <> plaintext = pointer to buffer containing data to pad
    <> len = size of data to pad, in bytes (real size, not block-aligned size)
    <> outbuf = pointer to buffer large enough to hold padded data (see macros below)
*/
size_t hashlib_RSAStripPadding(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* outbuf);
    
/*
####################################################
### Secure Psuedorandom Number Generator (SPRNG) ###
####################################################

    This PRNG utilizes an internal state that is controlled by the lib.
    While users can read from it and add entropy to it manually, they cannot modify it
        directly.
    The CSPRNG consists of a single `volatile uint8_t*`, internally called `eread` as well as
        a 119-byte entropy pool.
   
    ### Polling for Most Entropic Bit ###
        * hashlib_SPRNGInit();
        <> For each byte in the memory region affected by bus noise, read each bit 1024 times
        <> If the bit was set, increment a counter
        <> Set initial minimum deviation to +/- 1/4 of the read count from absolute 50/50 split.
            For example, out of 1024 tests, a bit is considered to be of sufficient entropy
            if it deviates from 256-768 1's, with values closer to 512 being preferred.
        <> Select the byte with the bit that deviates from 512 the least.
    
    ** hashlib_SPRNGInit() will return NULL if it was unable to find a bit of sufficient
        entropy on your device. While this is unlikely, if this does occur, it may help to run it a few times. Like so:
        
        `for(uint8_t ctr = 5; ctr>0 && !hashlib_SPRNGInit(); ctr--);`
        
    ### Generation of Random Numbers ###
        * hashlib_SPRNGRandom()
        <> Allocate a uint32_t in FastMem
        <> Call hashlib_SPRNGAddEntropy()
        <> SHA-256 hash the entropy pool, then XOR the hash with the partial rand in 4-byte blocks.
        <> Return the uint32_t
        
    * hashlib_SPRNGAddEntropy() may be called by the user in a loop to provide a more dynamic SPRNG state than can be provided internally.
        
    * This SPRNG passes all dieharder tests for a sample size of 16,384 bytes or more *
*/


//  Initialize the cryptographic RNG by finding the byte of most entropy on the current device
//  Returns the address selected as a (void*)
void* hashlib_SPRNGInit(void);

/*
	Repairs the entropy state of the SPRNG if it happens to get clobbered with predictable data in certain rare cases.
	
	** YOU SHOULD NEVER HAVE TO USE THIS UNLESS FOR SOME REASON LIBLOAD RUNS AND CLOBBERS THE ENTROPY POOL. **
	If Libload alters the entropy pool, the next output of the RNG will become predictable.
	Call this function after Libload runs but before the next call to RandomBytes or SPRNGRandom.
	It will zero out the entropy pool to remove the predictable data and then add entropy.
*/
#define hashlib_SPRNGRepairState() \
	memset(hashlib_FastMemBufferUnsafe, 0, 119)

//  Reads from byte selected 128 times, XORing new reads with existing data in the entropy pool
bool hashlib_SPRNGAddEntropy(void);
 
//  Returns a 32-bit integer, derived from the entropy pool
uint32_t hashlib_SPRNGRandom(void);

/*
    Fills a buffer to (size) with random bytes using the internal CSPRNG
    
    # Inputs #
    <> buffer = buffer to fill with random data
    <> size = how many bytes to write
    
    # Outputs #
    <> True if no errors encountered
    <> False if buffer was NULL or size was 0
 */
bool hashlib_RandomBytes(uint8_t *buffer, size_t size);


// ####################
// ### SHA-256 HASH ###
// ####################

/*
    Init Context for SHA-256

    # Inputs #
    <> ctx = pointer to an sha256_ctx
    <> mbuffer = pointer to 64*4 bytes of temporary ram used internally by hashlib_Sha256Update. It may be 0 if it's been set before, and if the memory it's been set to is still valid.
    ** SHA-256 will be invalid if this function is not called before hashing
    ** contexts are specific to a hash-stream. If there is another block of data you
        want to hash concurrently, you will need to init a new context
*/
void hashlib_Sha256Init(sha256_ctx *ctx, uint32_t *mbuffer);
/*
    Update Context for SHA-256

    # Inputs #
    <> ctx = pointer to an SHA256_CTX
    <> buf = ptr to a block of data to hash
    <> len = size of the block of data to hash
    ** Remember, if hashlib_Sha256Init is not called first, your hash will be wrong
*/
void hashlib_Sha256Update(sha256_ctx *ctx, const uint8_t *buf, uint32_t len);

/*
    Finalize Context and Render Digest for SHA-256

    # Inputs #
    <> ctx = pointer to an SHA256_CTX
    <> digest = pointer to buffer to write digest
*/
void hashlib_Sha256Final(sha256_ctx *ctx, uint8_t *digest);

/*
	Arbitrary Output Length Hashing Function
	* computes SHA-256 of the data and a counter to generate a hash of length outlen
	
	# Inputs #
	<> data = pointer to data to hash (SHA-256)
	<> datalen = size of data to hash
	<> outbuf = pointer to buffer to write arbitrary length hash
	<> outlen = length of hash needed
	
	# Outputs #
	<> hash written to *outbuf
 */
void hashlib_MGF1Hash(uint8_t* data, size_t datalen, uint8_t* outbuf, size_t outlen);

// ##########################################
// ### ADVANCED ENCRYPTION STANDARD (AES) ###
// ##########################################
// 32-bit implementation
// 128, 192, or 256 bit keys
// 10, 12, or 14 rounds
// CBC, CBC-MAC
        
/*
	Helper macros to generate AES keys for the 3 possible keylengths.
	
	# Inputs #
	<> buffer = A pointer to a buffer to write the key to
	
	# Outputs #
	An AES key of the correct length is written to buffer
 */
#define hashlib_AESKeygen128(buffer)	hashlib_RandomBytes((buffer), (128>>3))
#define hashlib_AESKeygen192(buffer)	hashlib_RandomBytes((buffer), (192>>3))
#define hashlib_AESKeygen256(buffer)	hashlib_RandomBytes((buffer), (256>>3))


/*
    AES Import Key
    ** The key can be a user-generated byte sequence, ranging from 32 bits to 448 bits
    
    # Inputs #
    <> key = pointer to a 128, 192, or 256 bit key
    <> ks = pointer to an AES key schedule context
    <> bitlen = the bit length of the AES key supplied. You can use the defines below.
     */
bool hashlib_AESLoadKey(const uint8_t* key, const aes_ctx* ks, size_t bitlen);

enum _aes_key_sizes {
	AES_128 = 128,
	AES_192 = 192,
	AES_256 = 256
};

/*
	AES Single Block ECB-Mode Encryptor
	* ECB-mode ciphers are insecure (see many-time pad)
	* These functions are exposed in case a user wants to construct a cipher mode other than CBC.
	* Unless you know what you are doing, please do not use this function.
			Use hashlib_AESEncrypt() or hashlib_AESAuthEncrypt() below instead.
	
	# Inputs #
	<> block_in = pointer to block of data to encrypt
	<> block_out = pointer to buffer to write encrypted block
	<> ks = pointer to AES key schedule context
 */
bool hashlib_AESEncryptBlock(
    const uint8_t* block_in,
    uint8_t* block_out,
    const aes_ctx* ks);
    
/*
	AES Single Block ECB-Mode Decryptor
	* ECB-mode ciphers are insecure (see many-time pad)
	* These functions are exposed in case a user wants to construct a cipher mode other than CBC.
	* Unless you know what you are doing, please do not use this function.
			Use hashlib_AESEncrypt() or hashlib_AESAuthEncrypt() below instead.
	
	# Inputs #
	<> block_in = pointer to block of data to decrypt
	<> block_out = pointer to buffer to write decrypted block
	<> ks = pointer to AES key schedule context
 */
bool hashlib_AESDecryptBlock(
    const uint8_t* block_in,
    uint8_t* block_out,
    const aes_ctx* ks);

/*
    AES-CBC Encrypt
    
    # Inputs #
    <> plaintext = pointer to data to encrypt (pass through padding helper func first)
    <> len = size of data to encrypt
    <> ciphertext = pointer to buffer to write encrypted output
    <> ks = pointer to ks schedule initialized with AESLoadKey
    <> iv = pointer to initialization vector (psuedorandom 16-byte field)
    * input and output buffers may safely alias, so long as out <= in.
    
    # Outputs #
    False is len not a multiple of the block size
    True if encryption succeeded
 */
bool hashlib_AESEncrypt(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* ciphertext,
    const aes_ctx* ks,
    const uint8_t* iv);
    
/*
	AES-CBC Decrypt
	
    <> ciphertext = pointer to data to decrypt
    <> len = size of data to decrypt
    <> plaintext = pointer to buffer to write decompressed output (can be the same as ciphertext)
    <> ks = pointer to initialized key schedule
    <> iv = pointer to initialization vector
    * input and output buffers may safely alias, so long as out <= in.
    
    # Outputs #
    False is len not a multiple of the block size
    True if encryption succeeded
 */
size_t hashlib_AESDecrypt(
    const uint8_t* ciphertext,
    size_t len,
    uint8_t* plaintext,
    const aes_ctx* ks,
    const uint8_t* iv);

/*
    Returns a Message Authentication Code (MAC) for an AES message.
    This MAC is a tag equal in size to the AES block size computed by passing the plaintext
        through the AES CBC algorithm for an IV = 0 with a unique key schedule.
        If you do use a unique key, you must be sure to exchange this second key
        with the host to be able to verify the message.
    
    # Inputs #
    <> plaintext = pointer to data to encrypt (pass through padding helper func first)
    <> len = size of data to encrypt
    <> mac = pointer to buffer to write MAC. Must be equal to the AES blocksize.
    <> ks = pointer to ks schedule initialized with AESLoadKey
    
    # NOTICES #
    ** DO NOT use the same key schedule for hashlib_AESOutputMAC() as you would for
        hashlib_AESEncrypt(). This exposes your message to attacks. Generate two keys,
        load them into separate key schedules, and use one for MAC and one for encryption. **
 */
bool hashlib_AESOutputMAC(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* mac,
    const aes_ctx* ks);

/*
    This function verifies the MAC for a given ciphertext. Use this function to verify the integrity of the message prior to Decryption
    This function expects the IPsec standard for concatenating the ciphertext and the MAC
    
    # Inputs #
    <> ciphertext = pointer to ciphertext to verify. Ciphertext should be formated [IV, encrypted_msg, MAC],
        where MAC = MAC(IV, encrypted_msg)
    <> len = size of the ciphertext to verify (should be equal to padded message + 1 block for MAC)
    <> ks_mac = the key schedule with which to verify the MAC
    * Compares the CBC encryption of the ciphertext (excluding the last block) over ks_mac with the last block of the ciphertext
    
    # Ouputs #
    True if last block of ciphertext matches MAC of ciphertext (excluding last block)
    False otherwise

 */
bool hashlib_AESVerifyMAC(const uint8_t *ciphertext, size_t len, const aes_ctx *ks_mac);


//	************************************
//	*** AES Authenticated Encryption ***
//	************************************

/*
    Encrypts a pre-padded plaintext using AES-CBC and CBC-MAC as designated in # Outputs #
    * The input plaintext should already be padded. See padding functions below. *
    * If len is not a multiple of the block size, the function will return False and fail to encrypt
    
    # Inputs #
    <> padded_plaintext = pointer to data to encrypt. Should be pre-padded.
    <> len = size of data to encrypt. Must be a multiple of the block size.
    <> ciphertext = pointer to buffer to write encrypted message. Should be equal to len + 2 blocks.
    <> ks_encrypt = pointer to the key schedule to use for encryption.
    <> ks_mac = pointer to the key schedule to use for the MAC  ** MUST BE DIFFERENT THAN KS_ENCRYPT **
    <> iv = the initialization vector (random buffer of size AES_BLOCKSIZE) to use for encryption.
    * input and output buffers may safely alias, so long as out <= in.
		** you can write the padded plaintext to &ciphertext[AES_BLOCKSIZE],
			and then pass that as *padded_plaintext and ciphertext as *ciphertext
    
    # Outputs #
    <> A full ciphertext in ciphertext containing:
        - 1-block IV
        - N-block encrypted message
        - 1-block MAC of IV+ciphertext
 */
bool hashlib_AESAuthEncrypt(
	const uint8_t *padded_plaintext,
	size_t len,
	uint8_t *ciphertext,
	aes_ctx *ks_encrypt,
	aes_ctx *ks_mac,
	uint8_t *iv);

/*
    Decrypts an AES ciphertext using AES-CBC and CBC-MAC. Will fail to decrypt if:
		(1) The length of the message to decrypt is not longer than 2 blocks.
		(2) The MAC of the IV+ciphertext does not match the MAC appended as the last block of the message.
    * The input plaintext should already be passed. See padding functions below. *
    * If len is not a multiple of the block size, the function will return False and fail to encrypt
    
    # Inputs #
    <> ciphertext = pointer to data to decrypt (ciphertext should be in same format as returned from AESAuthEncrypt() above).
    <> len = size of data to decrypt.
    <> plaintext = pointer to buffer to write decrypted message. Can be 2 blocks less than len.
    <> ks_decrypt = pointer to the key schedule to use for decryption.
    <> ks_mac = pointer to the key schedule to use for the MAC  ** MUST BE DIFFERENT THAN KS_ENCRYPT **
    * IV is not passed here, it should be the first block of the ciphertext *
    * input and output buffers may safely alias, so long as out <= in.
    
    # Outputs #
    <> False if len is not greater than 2 times the AES blocksize.
    <> False if the MAC of the IV and ciphertext failed to match the MAC appended to the ciphertext.
    <> True and *plaintext containing the decrypted message otherwise.
 */

bool hashlib_AESAuthDecrypt(
	const uint8_t *ciphertext,
	size_t len,
	uint8_t *plaintext,
	aes_ctx *ks_decrypt,
	aes_ctx *ks_mac);

/*
    Pads input data for AES encryption according to a selection of standard padding schemes.
    
    # Inputs #
    <> plaintext = pointer to buffer containing data to pad
    <> len = size of data to pad, in bytes (real size, not block-aligned size)
    <> outbuf = pointer to buffer large enough to hold padded data (see macros below)
    <> schm = padding scheme to pad with (see enumerations below)
    * input and output buffers may safely alias, so long as out <= in.
    
    # Outputs #
    The padded size of the message
 */
 
size_t hashlib_AESPadMessage(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* outbuf,
    uint8_t schm);

/*
    Reverses the padding on an AES plaintext according to a selection of standard padding schemes.
    
    # Inputs #
    <> plaintext = pointer to buffer containing data to pad
    <> len = size of data to pad, in bytes (real size, not block-aligned size)
    <> outbuf = pointer to buffer large enough to hold padded data (see macros below)
    <> schm = padding scheme to pad with (see enumerations below)
    * input and output buffers may safely alias, so long as out <= in.
    
    * If input SCHM mode is SCHM_ANSIX923, size returned is the same as input size.
        You will need to maintain your own expected unpadded data length
        
	# Outputs #
	The unpadded message size
 */
size_t hashlib_AESStripPadding(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* outbuf,
    uint8_t schm);
    
// AES Padding Scheme Defines
enum _aes_padding_schemes {
    SCHM_DEFAULT,
    SCHM_PKCS7,         // Pad with padding size        |   *Default*
    SCHM_ISO_M2,        // Pad with 0x80,0x00...0x00
    SCHM_ANSIX923,      // Pad with randomness
};

// ###############################
// #### BASE 64 ENCODE/DECODE ####
// ###############################
// Helper functions for bcrypt, but may be useful

/*
    Encode a byte string into a base-64 string
    
    # Inputs #
    <> b64buffer = pointer to a buffer to write base-64 output
    <> data = pointer to buffer containing data to encode
    <> len = length of data to encode
 */
bool hashlib_b64encode(char *b64buffer, const uint8_t *data, size_t len);

/*
    Decode a base-64 string
    
    # Inputs #
    <> buffer = pointer to buffer to write decoded output
    <> len = size of data to output (this is output length, not input length)
    <> b64data = pointer to buffer containing data to decode
 */
bool hashlib_b64decode(uint8_t *buffer, size_t len, const char *b64data);

#endif
