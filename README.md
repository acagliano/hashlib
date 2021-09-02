# Cryptography Library for the TI-84+ CE

This library is written as a libload-compatibile C (and ASM) library. To install the lib
into the toolchain, simply navigate into the hashlib directory within a terminal of your
choice and type `make install`. Alternatively, you can manually move `hashlib.h`
into `$CEDEV/include` and `hashlib.lib` into `$CEDEV/lib/loadload`. Also, be
sure to send `HASHLIB.8xv` to your TI-84+ CE.

For detailed documentation, head to [C header documentation](https://acagliano.github.io/hashlib/html/hashlib_8h.html).

For even more detailed documentation head to [Documentation PDF](https://github.com/acagliano/hashlib/blob/stable/Hashlib%20Documentation.pdf).

Credits:  
Some algorithms sourced at least in part from https://github.com/B-Con/crypto-algorithms.  
Cemetech user Zeroko - information on CE randomness.  
beckadamtheinventor & commandblockguy - coding assistance, conversion of some C routines to assembly for speed.  
