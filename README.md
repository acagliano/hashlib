# hashlib-stable

This is the stable branch of the TI-84+ CE toolchain library HASHLIB.  
To build this library yourself, navigate into the `src` directory of the CE C toolchain.  
Once in there, run `git clone https://github.com/acagliano/hashlib.git hashlib`.  
cd into that directory and run `make`. HASHLIB should be created.  

Of course there's no need to actually do this, because an up to date build of HASHLIB is provided in this repository.  
To use it with the toolchain, simply send `HASHLIB.8xv` to your device, move `hashlib.lib` into `$CEDEV/lib/libload` and then `hashlib.h` into `$CEDEV/include`.  
Once that is done, simply `#include <hashlib.h>` in your project source and you can use all the cryptography functions in the library.  

This library provides the following implementations tested and working on the TI-84+ CE.  
You can view the C codebase by running `git checkout dev`.  

<> A Secure PRNG with a calculated entropy of ~107.1 bits per 32-bit random number and an evaluated advantage negligibly greater than zero. The statistics included in the repo are for 1 MB of random output.  
<> A 128, 192, and 256 bit AES implementation, in CBC mode.  
<> ** Work in Progress ** 1024-bit RSA, encryption-only.  
<> SHA-1 and SHA-256 cryptographic hashes (these guys are a bit on the slow side).  
<> A helper function to pad plaintexts for encryption. Pass plaintext, an output buffer of appropriate size (macros to return that size included), the algorithm, and a padding spec (or SCHM_DEFAULT). The following padding methods are available:  
    - SCHM_PKCS7 : AES padding, Pad with padding size [DEFAULT FOR AES].  
    - SCHM_ISO_M2 : AES padding, Pad with [0x80, 0x00, ..., 0x00].  
    - SCHM_ISO_M1 : AES padding, Pad with [0x00, ..., 0x00].  
    - SCHM_ANSIX923 : AES padding, Pad with [randbytes].  
    - SCHM_RSA_OAEP : RSA padding, uses the OAEP padding scheme. SHA-256 is the hash used, and it is applied cyclically to the plaintext.  
<> A function to zero out a context that you no longer are using to prevent state leak.  
<> Base64 encoding and decoding functions.  

Credits:  
Some algorithms sourced at least in part from https://github.com/B-Con/crypto-algorithms.  
Cemetech user Zeroko - information on CE randomness.  
beckadamtheinventor & commandblockguy - coding assistance, conversion of some C routines to assembly for speed.  
