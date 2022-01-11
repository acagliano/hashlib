;------------------------------------------
include '../include/library.inc'
;include_library 'bigintce.asm'

;------------------------------------------
library "HASHLIB", 8

;------------------------------------------

;v6 functions
    export hashlib_SPRNGInit
    export hashlib_SPRNGRandom
    export hashlib_RandomBytes
    
    export hashlib_Sha256Init
	export hashlib_Sha256Update
	export hashlib_Sha256Final
	export hashlib_MGF1Hash
 
    export hashlib_AESLoadKey
    export hashlib_AESEncryptBlock
    export hashlib_AESDecryptBlock
    export hashlib_AESEncrypt
    export hashlib_AESDecrypt
    export hashlib_AESPadMessage
    export hashlib_AESStripPadding
    
	export hashlib_RSAEncodeOAEP
	export hashlib_RSADecodeOAEP
	export hashlib_RSAEncodePSS
    export hashlib_RSAEncrypt
    export hashlib_RSAVerifyPSS
    export hashlib_SSLVerifySignature

    export hashlib_EraseContext
    export hashlib_CompareDigest
    export hashlib_ReverseEndianness
    
    export hashlib_AESAuthEncrypt
    export hashlib_AESAuthDecrypt
    export hashlib_RSAAuthEncrypt
    

;------------------------------------------
; defines

_indcallhl:
; Calls HL
; Inputs:
;  HL : Address to call
	jp	(hl)
 
_indcall:
; Calls IY
    jp  (iy)


;number of times to test each bit
_num_tests := 1024
_max_deviation := _num_tests/4
;------------------------------------------
; structures
virtual at 0
	offset_data     rb 64
	offset_bitlen   rb 8
	offset_datalen  rb 1
	offset_state    rb 4*8
	_sha256ctx_size:
end virtual
_sha256_m_buffer_length := 64*4

; probably better to just add the one u64 function used by hashlib rather than screw with dependencies
u64_addi:
	pop bc,hl,de
	push de,hl,bc
	xor a,a
	ld bc,(hl)
	ex hl,de
	adc hl,bc
	ex hl,de
	ld (hl),de
	inc hl
	inc hl
	inc hl
	ld b,5
	ld c,a
.loop:
	ld a,(hl)
	adc a,c
	ld (hl),a
	inc hl
	djnz .loop
	ret
 
 
?stackBot		:= 0D1987Eh
; use to erase the stack to prevent buffer leak side-channel attack
stack_clear:
    
    ; save a, hl, e
    ld (.smc_a), a
    ld (.smc_hl), hl
    ld a, e
    ld (.smc_e), a
    
    ; set from stackBot + 4 to ix - 1 to 0
    lea de, ix - 2
    ld hl, -(stackBot + 3)
    add hl, de
    push hl
    pop bc
    lea hl, ix - 1
    ld (hl), 0
    lddr
    
    ; restore a, hl, e
    ld e, 0
.smc_e:=$-1
    ld a, 0
.smc_a:=$-1
    ld hl, 0
.smc_hl:=$-3
    ld sp, ix
    pop ix
    ret
 
;------------------------------------------
    

hashlib_SPRNGInit:
; ix = selected byte
; de = current deviation
; hl = starting address
; bc = bytes to check
; outputs: hl = address
    push ix
    ld ix, 0
    ld de, _max_deviation
    ld hl, $D65800
    ld bc, 513
.test_range_loop:
    push bc
    push hl
    call _test_byte
    pop hl
    pop bc
    inc hl
    dec bc
    ld a,c
    or a,b
    jq nz,.test_range_loop
    push ix
    pop hl
    ld (_sprng_read_addr), hl
	push hl
    ld hl,$E30800 ;zero 192 bytes at $E30800
    ld (hl),l
    push hl
    pop de
    inc de
    ld bc,192
    ldir
    ;call hashlib_SPRNGAddEntropy
    pop hl
    pop ix
    ret

_test_byte:
; inputs: hl = byte
; outputs: none, but de should be edited if address contains less deviant bit
; outputs: none, but ix should be edited to this address if contains less deviant bit
; destroys: bc, af, hl
; modifies: de, ix
    push iy
    push hl
    ld b, 8
    ld c, 0
.test_byte_bitloop:
    push bc
    push de
    ld a,c
    call _test_bit  ; HL = bits set
    pop de
    pop bc
    or a,a
    sbc hl, de
    jq nc, .skip_next_bit    ; IF HL < DE
    add hl,de
    ex hl, de
    pop ix
    push ix
.skip_next_bit:
    inc c
    djnz .test_byte_bitloop
    pop iy
    pop iy
    ret

_test_bit:
; inputs: a = bit
; inputs: hl = byte
; outputs: hl = hit count
; destroys: af, bc, de, hl
    add a,a
    add a,a
    add a,a
    add a,$46 ;bit 0,(hl)
    ld (.smc1),a
    ld (.smc2),a
    ld (.smc3),a
    ld (.smc4),a
    ld bc,$ff
    ld de,0
.loop:
    bit 0,(hl)
.smc1:=$-1
    jq z,.next1
    inc de
.next1:
    bit 0,(hl)
.smc2:=$-1
    jq z,.next2
    inc de
.next2:
    bit 0,(hl)
.smc3:=$-1
    jq z, .next3
    inc de
.next3:
    bit 0,(hl)
.smc4:=$-1
    jq z, .next4
    inc de
.next4:
    djnz .loop
    ld hl,_num_tests/2
    or a,a
    sbc hl,de
    ret nc
    ex hl,de
    or a,a
    sbc hl,hl
    sbc hl,de
    ret
    
	
hashlib_SPRNGAddEntropy:
    ld hl, (_sprng_read_addr)
    add	hl,de
	or	a,a
	sbc	hl,de
    ret z
    ld de, _sprng_entropy_pool
    ld b, 119
.byte_read_loop:
	ld a, (hl)
	xor a, (hl)
	xor a, (hl)
	xor a, (hl)
	xor a, (hl)
	xor a, (hl)
	xor a, (hl)
	ld (de), a
	inc de
    djnz .byte_read_loop
    ret
    
 
hashlib_SPRNGRandom:
	ld e,5+1
	scf
.init:
	dec e
	ret z
	push de
	call nc, hashlib_SPRNGInit
	pop de
	ld hl, (_sprng_read_addr)
	add hl,de
	or a,a
	sbc hl,de
	jq z,.init
	
.have_addr:
; set rand to 0
	ld hl, 0
	ld a, l
	ld (_sprng_rand), hl
	ld (_sprng_rand), a
	call hashlib_SPRNGAddEntropy
; hash entropy pool
	ld hl, _sprng_sha_mbuffer
	push hl
	ld hl, _sprng_sha_ctx
	push hl
	call hashlib_Sha256Init
	pop bc, hl
	ld hl, 119
	push hl
	ld hl, _sprng_entropy_pool
	push hl
	push bc
	call hashlib_Sha256Update
	pop bc, hl, hl
	ld hl, _sprng_sha_digest
	push hl
	push bc
	call hashlib_Sha256Final
	pop bc, hl
	
; xor hash cyclically into _rand
	ld hl,_sprng_sha_digest
	ld de,_sprng_rand
	ld c,4
.outer:
	xor a,a
	ld b,8
.inner:
	xor a,(hl)
	inc hl
	djnz .inner
	ld (de),a
	inc de
	dec c
	jq nz,.outer
	
; add entropy
	call hashlib_SPRNGAddEntropy
	ld hl, (_sprng_rand)
	ld a, (_sprng_rand+3)
	ld e, a
	ret
	
 
 L_.str2:
	db	"%lu",012o,000o
 
hashlib_RandomBytes:
	ld	hl, -10
	call	ti._frameset
	ld	de, (ix + 9)
	ld	iy, 0
	ld	(ix + -7), de
.lbl1:
	lea	hl, iy + 0
	or	a, a
	sbc	hl, de
	jq	nc, .lbl2
	ld	(ix + -10), iy
	call	hashlib_SPRNGRandom
	ld	(ix + -4), hl
	ld	(ix + -1), e
	ld	de, (ix + -10)
	ld	iy, (ix + 6)
	add	iy, de
	ld	bc, (ix + -7)
	push	bc
	pop	hl
	ld	de, 4
	or	a, a
	sbc	hl, de
	jq	c, .lbl5
	ld	bc, 4
.lbl5:
	push	bc
	pea	ix + -4
	push	iy
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	iy, (ix + -10)
	ld	de, 4
	add	iy, de
	ld	de, -4
	ld	hl, (ix + -7)
	add	hl, de
	ld	(ix + -7), hl
	ld	de, (ix + 9)
	jq	.lbl1
.lbl2:
	ld	sp, ix
	pop	ix
	ret
	
	
; void hashlib_Sha256Init(SHA256_CTX *ctx, uint32_t *mbuffer);
hashlib_Sha256Init:
	pop bc,de
	ex (sp),hl
	push de,bc
	add hl,bc
	or a,a
	sbc hl,bc
	jr z,.dont_set_buffer
	ld (_sha256_m_buffer_ptr),hl
.dont_set_buffer:
	ld hl,$FF0000		   ; 64k of 0x00 bytes
	ld bc,offset_state
	ldir ;de should point to ctx->data + offsetof ctx->state which is ctx->state
	ld c,8*4				; bc=0 prior to this, due to ldir
	ld hl,_sha256_state_init
	ldir
	ret

; void hashlib_Sha256Update(SHA256_CTX *ctx, const BYTE data[], size_t len);
hashlib_Sha256Update:
	call ti._frameset0
	; (ix + 0) RV
	; (ix + 3) old IX
	; (ix + 6) arg1: ctx
	; (ix + 9) arg2: data
	; (ix + 12) arg3: len

	ld iy, (ix + 6)			; iy = context, reference

		; start writing data to the right location in the data block
	ld a, (iy + offset_datalen)
	ld bc, 0
	ld c, a

	; scf
	; sbc hl,hl
	; ld (hl),2

	; get pointers to the things
	ld de, (ix + 9)			; de = source data
	ld hl, (ix + 6)			; hl = context, data ptr
	add hl, bc
	ex de, hl ;hl = source data, de = context / data ptr

	ld bc, (ix + 12)		   ; bc = len

	call _sha256_update_loop
	cp a,64
	call z,_sha256_update_apply_transform

	ld iy, (ix + 6)
	ld (iy + offset_datalen), a		   ;save current datalen
	pop ix
	ret

_sha256_update_loop:
	inc a
	ldi ;ld (de),(hl) / inc de / inc hl / dec bc
	ret po ;return if bc==0 (ldi decrements bc and updates parity flag)
	cp a,64
	call z,_sha256_update_apply_transform
	jq _sha256_update_loop
_sha256_update_apply_transform:
	push hl, de, bc
	ld bc, (ix + 6)
	push bc
	call _sha256_transform	  ; if we have one block (64-bytes), transform block
	pop iy
	ld bc, 512				  ; add 1 blocksize of bitlen to the bitlen field
	push bc
	pea iy + offset_bitlen
	call u64_addi
	pop bc, bc, bc, de, hl
	xor a,a
	ld de, (ix + 6)
	ret

; void hashlib_Sha256Final(SHA256_CTX *ctx, BYTE hash[]);
hashlib_Sha256Final:
	call ti._frameset0
	; (ix + 0) Return address
	; (ix + 3) saved IX
	; (ix + 6) arg1: ctx
	; (ix + 9) arg2: outbuf
	
	; scf
	; sbc hl,hl
	; ld (hl),2

	ld iy, (ix + 6)					; iy =  context block

	ld bc, 0
	ld c, (iy + offset_datalen)     ; data length
	ld hl, (ix + 6)					; ld hl, context_block_cache_addr
	add hl, bc						; hl + bc (context_block_cache_addr + bytes cached)

	ld a,55
	sub a,c ;c is set to datalen earlier
	ld (hl),$80
	jq c,_sha256_final_over_56
	inc a
_sha256_final_under_56:
	ld b,a
	xor a,a
_sha256_final_pad_loop2:
	inc hl
	ld (hl),a
	djnz _sha256_final_pad_loop2
	jq _sha256_final_done_pad
_sha256_final_over_56:
	ld a,64
	sub a,c
	ld b,a
	xor a,a
_sha256_final_pad_loop1:
	inc hl
	ld (hl),a
	djnz _sha256_final_pad_loop1
	push iy
	call _sha256_transform
	pop de
	ld hl,$FF0000
	ld bc,56
	ldir
_sha256_final_done_pad:
	ld iy, (ix + 6)
	ld c, (iy + offset_datalen)
	ld b,8
	mlt bc ;multiply 8-bit datalen by 8-bit value 8
	push bc
	pea iy + offset_bitlen
	call u64_addi
	pop bc,bc

	ld iy, (ix + 6) ;ctx
	lea hl,iy + offset_bitlen
	lea de,iy + offset_data + 63

	ld b,8
_sha256_final_pad_message_len_loop:
	ld a,(hl)
	ld (de),a
	inc hl
	dec de
	djnz _sha256_final_pad_message_len_loop

	push iy ;ctx
	call _sha256_transform
	pop iy

	ld hl, (ix + 9)
	lea iy, iy + offset_state
	ld b, 8

	pop ix
	; continue running into _sha256_reverse_endianness

; reverse b longs endianness from iy to hl
_sha256_reverse_endianness:
	ld a, (iy + 0)
	ld c, (iy + 1)
	ld d, (iy + 2)
	ld e, (iy + 3)
	ld (hl), e
	inc hl
	ld (hl), d
	inc hl
	ld (hl), c
	inc hl
	ld (hl), a
	inc hl
	lea iy, iy + 4
	djnz _sha256_reverse_endianness
	ret

; helper macro to xor [B,C] with [R1,R2] storing into [R1,R2]
; destroys: af
macro _xorbc? R1,R2
	ld a,b
	xor a,R1
	ld R1,a
	ld a,c
	xor a,R2
	ld R2,a
end macro

; helper macro to add [B,C] with [R1,R2] storing into [R1,R2]
; destroys: af
; note: this will add including the carry flag, so be sure of what the carry flag is before this
; note: if you're chaining this into a number longer than 16 bits, the order must be low->high
macro _addbclow? R1,R2
	ld a,c
	add a,R2
	ld R2,a
	ld a,b
	adc a,R1
	ld R1,a
end macro
macro _addbchigh? R1,R2
	ld a,c
	adc a,R2
	ld R2,a
	ld a,b
	adc a,R1
	ld R1,a
end macro

; helper macro to move [d,e,h,l] <- [l,e,d,h] therefore shifting 8 bits right.
; destroys: af
macro _rotright8?
	ld a,l
	ld l,h
	ld h,e
	ld e,d
	ld d,a
end macro

; helper macro to move [d,e,h,l] <- [e,h,l,d] therefore shifting 8 bits left.
; destroys: af
macro _rotleft8?
	ld a,d
	ld d,e
	ld e,h
	ld h,l
	ld l,a
end macro


; #define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
;input: [d,e,h,l], b
;output: [d,e,h,l]
;destroys: af, b
_ROTLEFT:
	xor a,a
	rl l
	rl h
	rl e
	rl d
	adc a,l
	ld l,a
	djnz .
	ret

; #define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
;input: [d,e,h,l], b
;output: [d,e,h,l]
;destroys: af, b
_ROTRIGHT:
	xor a,a
	rr d
	rr e
	rr h
	rr l
	rra
	or a,d
	ld d,a
	djnz .
	ret

; #define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
;input [d,e,h,l]
;output [d,e,h,l]
;destroys af, bc
_SIG0:
	ld b,3
	call _ROTRIGHT  ;rotate long accumulator 3 bits right
	push hl,de	  ;save value for later
	ld b,4
	call _ROTRIGHT  ;rotate long accumulator another 4 bits right for a total of 7 bits right
	push hl,de	  ;save value for later
	_rotright8      ;rotate long accumulator 8 bits right
	ld b,3
	call _ROTRIGHT  ;rotate long accumulator another 3 bits right for a total of 18 bits right
	pop bc
	_xorbc d,e  ;xor third ROTRIGHT result with second ROTRIGHT result (upper 16 bits)
	pop bc
	_xorbc h,l  ;xor third ROTRIGHT result with second ROTRIGHT result (lower 16 bits)
	pop bc
	ld a,b
	and a,$1F   ;cut off the upper 3 bits from the result of the first ROTRIGHT call
	xor a,d	 ;xor first ROTRIGHT result with result of prior xor (upper upper 8 bits)
	ld d,a
	ld a,c
	xor a,e	 ;xor first ROTRIGHT result with result of prior xor (lower upper 8 bits)
	ld e,a
	pop bc
	_xorbc h,l  ;xor first ROTRIGHT result with result of prior xor (lower 16 bits)
	ret

; #define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))
;input: [d,e,h,l]
;output: [d,e,h,l]
;destroys: af, bc
_SIG1:
	_rotright8      ;rotate long accumulator 8 bits right
	ld b,2
	call _ROTRIGHT  ;rotate long accumulator 2 bits right for a total of 10 bits right
	push hl,de	    ;save value for later
	_rotright8      ;rotate long accumulator 8 bits right for a total of 18 bits right
	ld b,1
	call _ROTLEFT  ;rotate long accumulator a bit left for a total of 17 bits right
	push hl,de	  ;save value for later
	ld b,2
	call _ROTRIGHT  ;rotate long accumulator another 2 bits right
	pop bc
	_xorbc d,e  ;xor third ROTRIGHT result with second ROTRIGHT result (upper 16 bits)
	pop bc
	_xorbc h,l  ;xor third ROTRIGHT result with second ROTRIGHT result (lower 16 bits)

	;we're cutting off upper 10 bits of first ROTRIGHT result meaning we're xoring by zero, so we can just keep the value of d.
	pop bc
	ld a,c
	and a,$3F   ;cut off the upper 2 bits from the lower upper byte of the first ROTRIGHT result.
	xor a,e	 ;xor first ROTRIGHT result with result of prior xor (lower upper upper 8 bits)
	ld e,a
	pop bc
	_xorbc h,l  ;xor first ROTRIGHT result with result of prior xor (lower 16 bits)
	ret


; void _sha256_transform(SHA256_CTX *ctx);
_sha256_transform:
._h := -4
._g := -8
._f := -12
._e := -16
._d := -20
._c := -24
._b := -28
._a := -32
._state_vars := -32
._tmp1 := -36
._tmp2 := -40
._i := -41
._frame_offset := -41
	ld hl,._frame_offset
	call ti._frameset
	ld hl,0
_sha256_m_buffer_ptr:=$-3
	add hl,bc
	or a,a
	sbc hl,bc
	jq z,._exit
	ld iy,(ix + 6)
	ld b,16
	call _sha256_reverse_endianness ;first loop is essentially just reversing the endian-ness of the data into m (both represented as 32-bit integers)

	ld iy,(_sha256_m_buffer_ptr)
	lea iy, iy + 16*4
	ld b, 64-16
._loop2:
	push bc
; m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
	ld hl,(iy + -2*4 + 0)
	ld de,(iy + -2*4 + 2)
	call _SIG1
	push de,hl
	ld hl,(iy + -15*4 + 0)
	ld de,(iy + -15*4 + 2)
	call _SIG0

; SIG0(m[i - 15]) + m[i - 16]
	ld bc, (iy + -16*4 + 0)
	_addbclow h,l
	ld bc, (iy + -16*4 + 2)
	_addbchigh d,e

; + SIG1(m[i - 2])
	pop bc
	_addbclow h,l
	pop bc
	_addbchigh d,e

; + m[i - 7]
	ld bc, (iy + -7*4)
	_addbclow h,l
	ld bc, (iy + -7*4 + 2)
	_addbchigh d,e

; --> m[i]
	ld (iy + 3), d
	ld (iy + 2), e
	ld (iy + 1), h
	ld (iy + 0), l

	lea iy, iy + 4
	pop bc
	djnz ._loop2


	ld iy, (ix + 6)
	lea hl, iy + offset_state
	lea de, ix + ._state_vars
	ld bc, 8*4
	ldir				; copy the ctx state to scratch stack memory (uint32_t a,b,c,d,e,f,g,h)

	ld (ix + ._i), c
._loop3:
; tmp1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
; CH(e,f,g)
; #define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
	lea iy,ix
	ld b,4
._loop3inner1:
	ld a, (iy + ._e)
	xor a,$FF
	and a, (iy + ._g)
	ld c,a
	ld a, (iy + ._e)
	and a, (iy + ._f)
	xor a,c
	ld (iy + ._tmp1),a
	inc iy
	djnz ._loop3inner1

	; scf
	; sbc hl,hl
	; ld (hl),2

; EP1(e)
; #define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
	ld hl,(ix + ._e + 0)
	ld de,(ix + ._e + 2)
	ld b,6    ;rotate e 6 bits right
	call _ROTRIGHT
	push de,hl
	ld b,5    ;rotate accumulator another 5 bits for a total of 11
	call _ROTRIGHT
	push de,hl
	_rotright8 ;rotate accumulator another 8 bits for a total of 19
	ld b,6
	call _ROTRIGHT ;rotate accumulator another 6 bits for a total of 25
	pop bc         ;ROTRIGHT(x,11) ^ ROTRIGHT(x,25)
	_xorbc h,l
	pop bc
	_xorbc d,e
	pop bc         ; ^ ROTRIGHT(x,6)
	_xorbc h,l
	pop bc
	_xorbc d,e

; EP1(e) + h
	ld bc, (ix + ._h)
	_addbclow h,l
	ld bc, (ix + ._h + 2)
	_addbchigh d,e

; h + EP1(e) + CH(e,f,g)
	ld bc, (ix + ._tmp1)
	_addbclow h,l
	ld bc, (ix + ._tmp1 + 2)
	_addbchigh d,e

; B0ED BDD0
	push de,hl
	ld hl,(_sha256_m_buffer_ptr)
	ld b,4
	ld c,(ix + ._i)
	mlt bc
	add hl,bc
	ld de,(hl)
	inc hl
	inc hl
	ld hl,(hl)
	push hl,de
	ld hl,_sha256_k
	add hl,bc
	ld de,(hl)
	inc hl
	inc hl
	ld hl,(hl)

; m[i] + k[i]
	pop bc
	_addbclow d,e
	pop bc
	_addbchigh h,l

; m[i] + k[i] + h + EP1(e) + CH(e,f,g)
	pop bc
	_addbclow d,e
	pop bc
	_addbchigh h,l

; --> tmp1
	ld (ix + ._tmp1 + 3),h
	ld (ix + ._tmp1 + 2),l
	ld (ix + ._tmp1 + 1),d
	ld (ix + ._tmp1 + 0),e

; tmp2 = EP0(a) + MAJ(a,b,c);
; MAJ(a,b,c)
; #define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
	lea iy,ix
	ld b,4
._loop3inner2:
	ld a, (iy + ._a)
	and a, (iy + ._b)
	ld c,a
	ld a, (iy + ._a)
	and a, (iy + ._c)
	xor a,c
	ld c,a
	ld a, (iy + ._b)
	and a, (iy + ._c)
	xor a,c
	ld (iy + ._tmp2), a
	inc iy
	djnz ._loop3inner2

; EP0(a)
; #define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
	ld hl,(ix + ._a + 0)
	ld de,(ix + ._a + 2)
	ld b,2
	call _ROTRIGHT     ; x >> 2
	push de,hl
	_rotright8         ; x >> 10
	ld b,3
	call _ROTRIGHT     ; x >> 13
	push de,hl
	_rotright8         ; x >> 21
	inc b ;_ROTRIGHT sets b to zero
	call _ROTRIGHT     ; x >> 22
	pop bc             ; (x >> 22) ^ (x >> 13)
	_xorbc h,l
	pop bc
	_xorbc d,e
	pop bc             ; (x >> 2) ^ (x >> 22) ^ (x >> 13)
	_xorbc h,l
	pop bc
	_xorbc d,e

	ld bc, (ix + ._tmp2)  ; EP0(a) + MAJ(a,b,c)
	_addbclow h,l
	ld bc, (ix + ._tmp2 + 2)
	_addbchigh d,e
	ld (ix + ._tmp2 + 3), d
	ld (ix + ._tmp2 + 2), e
	ld (ix + ._tmp2 + 1), h
	ld (ix + ._tmp2 + 0), l

; h = g;
	ld hl, (ix + ._g + 0)
	ld a,  (ix + ._g + 3)
	ld (ix + ._h + 0), hl
	ld (ix + ._h + 3), a

; g = f;
	ld hl, (ix + ._f + 0)
	ld a,  (ix + ._f + 3)
	ld (ix + ._g + 0), hl
	ld (ix + ._g + 3), a

; f = e;
	ld hl, (ix + ._e + 0)
	ld a,  (ix + ._e + 3)
	ld (ix + ._f + 0), hl
	ld (ix + ._f + 3), a

; e = d + tmp1;
	ld hl, (ix + ._d + 0)
	ld a,  (ix + ._d + 3)
	ld de, (ix + ._tmp1 + 0)
	or a,a
	adc hl,de
	adc a, (ix + ._tmp1 + 3)
	ld (ix + ._e + 0), hl
	ld (ix + ._e + 3), a

; d = c;
	ld hl, (ix + ._c + 0)
	ld a,  (ix + ._c + 3)
	ld (ix + ._d + 0), hl
	ld (ix + ._d + 3), a

; c = b;
	ld hl, (ix + ._b + 0)
	ld a,  (ix + ._b + 3)
	ld (ix + ._c + 0), hl
	ld (ix + ._c + 3), a

; b = a;
	ld hl, (ix + ._a + 0)
	ld a,  (ix + ._a + 3)
	ld (ix + ._b + 0), hl
	ld (ix + ._b + 3), a

; a = tmp1 + tmp2;
	ld hl, (ix + ._tmp1 + 0)
	ld a,  (ix + ._tmp1 + 3)
	ld de, (ix + ._tmp2 + 0)
	or a,a
	adc hl,de
	adc a, (ix + ._tmp2 + 3)
	ld (ix + ._a + 0), hl
	ld (ix + ._a + 3), a
	ld a,(ix + ._i)
	inc a
	ld (ix + ._i),a
	cp a,64
	jq c,._loop3

	push ix
	ld iy, (ix + 6)
	lea iy, iy + offset_state
	lea ix, ix + ._state_vars
	ld b,8
._loop4:
	ld hl, (iy + 0)
	ld de, (ix + 0)
	ld a, (iy + 3)
	or a,a
	adc hl,de
	adc a,(ix + 3)
	ld (iy + 0), hl
	ld (iy + 3), a
	lea ix, ix + 4
	lea iy, iy + 4
	djnz ._loop4

	pop ix
._exit:
	ld sp,ix
	pop ix
	ret

    
 
 
 ; hashlib_EraseContext(void* ptr, size_t len);
 ; throw this in at the end of cryptofunctions to wipe the context when you are done with them
 ; input hl = (void*) PTR
 ; input de = len to zero
 hashlib_EraseContext:
    pop de,hl,bc
    push bc
.eraseloop:
    ld (hl),0
    inc hl
    dec bc
    ld a,b
    or a,c
    jq nz,.eraseloop
    ex hl,de
    jp (hl)
    
    
_xor_buf:
	ld	hl, -3
	call	ti._frameset
	ld	de, (ix + 6)
	ld	iy, (ix + 9)
	ld	bc, (ix + 12)
.lbl1:
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl3
	ld	a, (iy)
	ld	(ix + -3), iy
	ex	de, hl
	xor	a, (hl)
	ld	iy, (ix + -3)
	ld	(iy), a
	dec	bc
	inc	hl
	ex	de, hl
	ld	iy, (ix + -3)
	inc	iy
	jq	.lbl1
.lbl3:
	pop	hl
	pop	ix
	ret
	
_aes_SubWord:
	ld	hl, -9
	call	ti._frameset
	ld	bc, (ix + 6)
	ld	a, (ix + 9)
	ld	iy, 15
	ld	l, 4
	call	ti._lshru
	push	bc
	pop	hl
	lea	bc, iy + 0
	call	ti._iand
	push	hl
	pop	de
	ld	hl, (ix + 6)
	call	ti._iand
	push	hl
	pop	iy
	ex	de, hl
	ld	c, 4
	call	ti._ishl
	push	hl
	pop	de
	ld	hl, _aes_sbox
	add	hl, de
	lea	de, iy + 0
	add	hl, de
	ld	a, (hl)
	or	a, a
	sbc	hl, hl
	ld	l, a
	ld	(ix + -3), hl
	ld	l, 12
	ld	bc, (ix + 6)
	ld	e, (ix + 9)
	ld	a, e
	call	ti._lshru
	push	bc
	pop	hl
	ld	iy, 15
	lea	bc, iy + 0
	call	ti._iand
	ld	(ix + -6), hl
	ld	l, 8
	ld	bc, (ix + 6)
	ld	a, e
	call	ti._lshru
	push	bc
	pop	hl
	lea	bc, iy + 0
	call	ti._iand
	push	hl
	pop	de
	ld	hl, (ix + -6)
	ld	c, 4
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	bc, 0
	ld	c, a
	ld	d, 0
	ld	a, d
	ld	l, 8
	call	ti._lshl
	push	bc
	pop	hl
	ld	e, a
	ld	bc, (ix + -3)
	ld	a, d
	call	ti._ladd
	ld	(ix + -3), hl
	ld	(ix + -6), e
	ld	l, 20
	ld	iy, (ix + 6)
	lea	bc, iy + 0
	ld	a, (ix + 9)
	call	ti._lshru
	push	bc
	pop	hl
	ld	de, 15
	push	de
	pop	bc
	call	ti._iand
	ld	(ix + -9), hl
	ld	l, 16
	lea	bc, iy + 0
	ld	a, (ix + 9)
	ld	iyl, a
	ex	de, hl
	ld	iyh, e
	ex	de, hl
	call	ti._lshru
	push	bc
	pop	hl
	push	de
	pop	bc
	call	ti._iand
	push	hl
	pop	de
	ld	hl, (ix + -9)
	ld	c, 4
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	bc, 0
	ld	c, a
	xor	a, a
	ex	de, hl
	ld	e, iyh
	ex	de, hl
	call	ti._lshl
	ld	hl, (ix + -3)
	ld	e, (ix + -6)
	call	ti._ladd
	ld	(ix + -3), hl
	ld	(ix + -6), e
	ld	l, 28
	ld	de, (ix + 6)
	push	de
	pop	bc
	ex	de, hl
	ld	d, iyl
	ex	de, hl
	ld	a, h
	call	ti._lshru
	push	bc
	pop	iy
	ld	l, 24
	push	de
	pop	bc
	ld	a, h
	call	ti._lshru
	push	bc
	pop	hl
	ld	bc, 15
	call	ti._iand
	push	hl
	pop	de
	lea	hl, iy + 0
	ld	c, 4
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	bc, 0
	ld	c, a
	xor	a, a
	ld	l, 24
	call	ti._lshl
	ld	hl, (ix + -3)
	ld	e, (ix + -6)
	call	ti._ladd
	ld	sp, ix
	pop	ix
	ret
	
hashlib_AESLoadKey:
	ld	hl, -25
	call	ti._frameset
	ld	hl, (ix + 12)
	xor	a, a
	ld	c, 3
	call	ti._ishl
	push	hl
	pop	de
	ld	bc, 128
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_2
	ld	(ix + -19), a
	ld	bc, 4
	ld	hl, 44
	ld	(ix + -9), hl
	jq	.lbl_6
.lbl_2:
	ld	bc, 192
	push	de
	pop	hl
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_4
	ld	(ix + -19), a
	ld	hl, 52
	ld	(ix + -9), hl
	ld	bc, 6
	jq	.lbl_6
.lbl_4:
	ld	bc, 256
	push	de
	pop	hl
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_20
	ld	bc, 8
	ld	hl, 60
	ld	(ix + -9), hl
	ld	a, 1
	ld	(ix + -19), a
.lbl_6:
	ld	iy, (ix + 9)
	ld	(iy), de
	ld	(ix + -3), iy
	lea	hl, iy + 3
	ld	(ix + -12), hl
	ld	iy, (ix + 6)
	lea	iy, iy + 3
	push	bc
	pop	de
	ld	(ix + -6), bc
.lbl_7:
	push	de
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_9
	ld	a, (iy + -3)
	ld	bc, 0
	ld	c, a
	ld	h, 0
	ld	a, h
	ld	l, 24
	call	ti._lshl
	ld	(ix + -18), bc
	ld	(ix + -15), de
	ld	d, a
	ld	a, (iy + -2)
	ld	bc, 0
	ld	c, a
	ld	a, h
	ld	l, 16
	call	ti._lshl
	push	bc
	pop	hl
	ld	e, a
	ld	bc, (ix + -18)
	ld	a, d
	call	ti._ladd
	ld	(ix + -18), hl
	ld	a, (iy + -1)
	ld	bc, 0
	ld	c, a
	xor	a, a
	ld	l, 8
	call	ti._lshl
	ld	hl, (ix + -18)
	call	ti._ladd
	ld	a, (iy)
	ld	bc, 0
	ld	c, a
	xor	a, a
	call	ti._ladd
	lea	bc, iy + 0
	ld	iy, (ix + -12)
	ld	(iy), hl
	ld	(iy + 3), e
	ld	de, (ix + -15)
	dec	de
	lea	iy, iy + 4
	ld	(ix + -12), iy
	push	bc
	pop	iy
	lea	iy, iy + 4
	jq	.lbl_7
.lbl_9:
	ld	c, 2
	ld	hl, (ix + -6)
	call	ti._ishl
	ld	bc, (ix + -6)
	dec	hl
	ld	(ix + -15), hl
	push	bc
	pop	de
	ld	hl, (ix + -9)
.lbl_10:
	or	a, a
	sbc	hl, de
	jq	z, .lbl_19
	ld	iy, (ix + -3)
	ex	de, hl
	ld	de, (ix + -15)
	add	iy, de
	ld	de, (iy)
	ld	a, (iy + 3)
	ld	(ix + -12), hl
	call	ti._iremu
	add	hl, bc
	or	a, a
	sbc	hl, bc
	ld	(ix + -18), iy
	jq	nz, .lbl_13
	ld	hl, (ix + -12)
	dec	hl
	ld	(ix + -22), hl
	push	de
	pop	bc
	ld	h, a
	ld	l, 8
	call	ti._lshl
	ld	(ix + -25), bc
	ld	iyl, a
	push	de
	pop	bc
	ld	a, h
	ld	l, 24
	call	ti._lshru
	ld	hl, (ix + -25)
	ld	e, iyl
	call	ti._lor
	push	de
	push	hl
	call	_aes_SubWord
	ld	(ix + -25), hl
	ld	a, e
	pop	hl
	pop	hl
	ld	hl, (ix + -22)
	ld	bc, (ix + -6)
	call	ti._idivu
	ld	c, 2
	call	ti._ishl
	push	hl
	pop	de
	ld	iy, L___const.hashlib_AESLoadKey.Rcon
	add	iy, de
	ld	hl, (iy)
	ld	e, (iy + 3)
	ld	bc, (ix + -25)
	call	ti._lxor
	push	hl
	pop	bc
	ld	a, e
	jq	.lbl_18
.lbl_13:
	ld	(ix + -25), a
	ld	(ix + -22), de
	ld	a, (ix + -19)
	ld	e, 1
	xor	a, e
	bit	0, a
	jq	nz, .lbl_17
	ld	bc, 4
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_17
	ld	a, (ix + -25)
	ld	l, a
	push	hl
	ld	hl, (ix + -22)
	push	hl
	call	_aes_SubWord
	push	hl
	pop	bc
	ld	a, e
	pop	hl
	pop	hl
	jq	.lbl_18
.lbl_17:
	ld	bc, (ix + -22)
	ld	a, (ix + -25)
.lbl_18:
	ld	iy, (ix + -3)
	ld	hl, (iy + 3)
	ld	e, (iy + 6)
	call	ti._lxor
	ld	bc, (ix + -18)
	push	bc
	pop	iy
	ld	(iy + 4), hl
	ld	(iy + 7), e
	ld	de, (ix + -12)
	inc	de
	ld	iy, (ix + -3)
	lea	iy, iy + 4
	ld	(ix + -3), iy
	ld	bc, (ix + -6)
	ld	hl, (ix + -9)
	jq	.lbl_10
.lbl_19:
	ld	a, 1
.lbl_20:
	ld	sp, ix
	pop	ix
	ret
	
_aes_AddRoundKey:
	ld	hl, -3
	call	ti._frameset
	ld	iy, (ix + 9)
	ld	de, (iy)
	ld	h, (iy + 3)
	ld	l, 24
	push	de
	pop	bc
	ld	a, h
	call	ti._lshru
	ld	(ix + -3), bc
	ld	l, 16
	push	de
	pop	bc
	ld	a, h
	call	ti._lshru
	ld	iy, (ix + 6)
	ld	a, (iy)
	ld	hl, (ix + -3)
	xor	a, l
	ld	(iy), a
	ld	a, (iy + 4)
	xor	a, c
	ld	(iy + 4), a
	ld	a, (iy + 8)
	xor	a, d
	ld	(iy + 8), a
	ld	a, (iy + 12)
	xor	a, e
	ld	(iy + 12), a
	ld	hl, (ix + 9)
	push	hl
	pop	iy
	ld	de, (iy + 4)
	ld	h, (iy + 7)
	push	de
	pop	bc
	ld	a, h
	ld	l, 24
	call	ti._lshru
	ld	(ix + -3), bc
	push	de
	pop	bc
	ld	a, h
	ld	l, 16
	call	ti._lshru
	ld	iy, (ix + 6)
	ld	a, (iy + 1)
	ld	hl, (ix + -3)
	xor	a, l
	ld	(iy + 1), a
	ld	a, (iy + 5)
	xor	a, c
	ld	(iy + 5), a
	ld	a, (iy + 9)
	xor	a, d
	ld	(iy + 9), a
	ld	a, (iy + 13)
	xor	a, e
	ld	(iy + 13), a
	ld	hl, (ix + 9)
	push	hl
	pop	iy
	ld	de, (iy + 8)
	ld	h, (iy + 11)
	push	de
	pop	bc
	ld	a, h
	ld	l, 24
	call	ti._lshru
	ld	(ix + -3), bc
	push	de
	pop	bc
	ld	a, h
	ld	l, 16
	call	ti._lshru
	ld	iy, (ix + 6)
	ld	a, (iy + 2)
	ld	hl, (ix + -3)
	xor	a, l
	ld	(iy + 2), a
	ld	a, (iy + 6)
	xor	a, c
	ld	(iy + 6), a
	ld	a, (iy + 10)
	xor	a, d
	ld	(iy + 10), a
	ld	a, (iy + 14)
	xor	a, e
	ld	(iy + 14), a
	ld	hl, (ix + 9)
	push	hl
	pop	iy
	ld	de, (iy + 12)
	ld	h, (iy + 15)
	push	de
	pop	bc
	ld	a, h
	ld	l, 24
	call	ti._lshru
	ld	(ix + -3), bc
	push	de
	pop	bc
	ld	a, h
	ld	l, 16
	call	ti._lshru
	ld	iy, (ix + 6)
	ld	a, (iy + 3)
	ld	hl, (ix + -3)
	xor	a, l
	ld	(iy + 3), a
	ld	a, (iy + 7)
	xor	a, c
	ld	(iy + 7), a
	ld	a, (iy + 11)
	xor	a, d
	ld	(iy + 11), a
	ld	a, (iy + 15)
	xor	a, e
	ld	(iy + 15), a
	pop	hl
	pop	ix
	ret
	
_aes_SubBytes:
	call	ti._frameset0
	ld	hl, (ix + 6)
	ld	iy, _aes_sbox
	ld	a, (hl)
	ld	de, 0
	ld	e, a
	ld	b, 4
	push	de
	pop	hl
	ld	c, b
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	lea	hl, iy + 0
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy), a
	ld	a, (iy + 1)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 1), a
	ld	a, (iy + 2)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 2), a
	ld	a, (iy + 3)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 3), a
	ld	a, (iy + 4)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	iy, _aes_sbox
	lea	hl, iy + 0
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 4), a
	ld	a, (iy + 5)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 5), a
	ld	a, (iy + 6)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 6), a
	ld	a, (iy + 7)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	iy, _aes_sbox
	lea	hl, iy + 0
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 7), a
	ld	a, (iy + 8)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 8), a
	ld	a, (iy + 9)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 9), a
	ld	a, (iy + 10)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 10), a
	ld	a, (iy + 11)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 11), a
	ld	a, (iy + 12)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 12), a
	ld	a, (iy + 13)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 13), a
	ld	a, (iy + 14)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	ld	b, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	ld	c, b
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 14), a
	ld	a, (iy + 15)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_sbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 15), a
	pop	ix
	ret
	
_aes_InvSubBytes:
	call	ti._frameset0
	ld	hl, (ix + 6)
	ld	iy, _aes_invsbox
	ld	a, (hl)
	ld	de, 0
	ld	e, a
	ld	b, 4
	push	de
	pop	hl
	ld	c, b
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	lea	hl, iy + 0
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy), a
	ld	a, (iy + 1)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 1), a
	ld	a, (iy + 2)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 2), a
	ld	a, (iy + 3)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 3), a
	ld	a, (iy + 4)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	iy, _aes_invsbox
	lea	hl, iy + 0
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 4), a
	ld	a, (iy + 5)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 5), a
	ld	a, (iy + 6)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 6), a
	ld	a, (iy + 7)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	iy, _aes_invsbox
	lea	hl, iy + 0
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 7), a
	ld	a, (iy + 8)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 8), a
	ld	a, (iy + 9)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 9), a
	ld	a, (iy + 10)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 10), a
	ld	a, (iy + 11)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 11), a
	ld	a, (iy + 12)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 12), a
	ld	a, (iy + 13)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 13), a
	ld	a, (iy + 14)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	ld	b, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	ld	c, b
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 14), a
	ld	a, (iy + 15)
	ld	e, a
	push	de
	pop	hl
	ld	c, 4
	call	ti._ishru
	and	a, 15
	ld	e, a
	call	ti._ishl
	push	hl
	pop	bc
	ld	hl, _aes_invsbox
	add	hl, bc
	add	hl, de
	ld	a, (hl)
	ld	(iy + 15), a
	pop	ix
	ret
	
_aes_ShiftRows:
	call	ti._frameset0
	ld	iy, (ix + 6)
	ld	a, (iy + 4)
	ld	l, (iy + 5)
	ld	(iy + 4), l
	ld	l, (iy + 6)
	ld	(iy + 5), l
	ld	l, (iy + 7)
	ld	(iy + 6), l
	ld	(iy + 7), a
	ld	a, (iy + 8)
	ld	l, (iy + 10)
	ld	(iy + 8), l
	ld	(iy + 10), a
	ld	a, (iy + 9)
	ld	l, (iy + 11)
	ld	(iy + 9), l
	ld	(iy + 11), a
	ld	a, (iy + 12)
	ld	l, (iy + 15)
	ld	(iy + 12), l
	ld	l, (iy + 14)
	ld	(iy + 15), l
	ld	l, (iy + 13)
	ld	(iy + 14), l
	ld	(iy + 13), a
	pop	ix
	ret
	
_aes_InvShiftRows:
	call	ti._frameset0
	ld	iy, (ix + 6)
	ld	a, (iy + 7)
	ld	l, (iy + 6)
	ld	(iy + 7), l
	ld	l, (iy + 5)
	ld	(iy + 6), l
	ld	l, (iy + 4)
	ld	(iy + 5), l
	ld	(iy + 4), a
	ld	a, (iy + 11)
	ld	l, (iy + 9)
	ld	(iy + 11), l
	ld	(iy + 9), a
	ld	a, (iy + 10)
	ld	l, (iy + 8)
	ld	(iy + 10), l
	ld	(iy + 8), a
	ld	a, (iy + 15)
	ld	l, (iy + 12)
	ld	(iy + 15), l
	ld	l, (iy + 13)
	ld	(iy + 12), l
	ld	l, (iy + 14)
	ld	(iy + 13), l
	ld	(iy + 14), a
	pop	ix
	ret

_aes_MixColumns:
	ld	hl, -13
	call	ti._frameset
	ld	iy, (ix + 6)
	ld	e, (iy)
	ld	(ix + -2), e
	ld	a, (iy + 4)
	ld	(ix + -1), a
	ld	l, (iy + 8)
	ld	(ix + -3), l
	ld	l, (iy + 12)
	ld	(ix + -6), l
	or	a, a
	sbc	hl, hl
	ld	l, e
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	de
	ld	iy, _gf_mul
	lea	hl, iy + 0
	add	hl, de
	ld	(ix + -9), hl
	ld	l, (hl)
	ld	(ix + -13), l
	or	a, a
	sbc	hl, hl
	ld	l, a
	call	ti._imulu
	push	hl
	pop	de
	add	iy, de
	ld	bc, 0
	push	bc
	pop	hl
	ld	e, (ix + -3)
	ld	l, e
	ld	a, (ix + -6)
	ld	c, a
	ld	(ix + -12), bc
	xor	a, e
	xor	a, (ix + -13)
	xor	a, (iy + 1)
	lea	de, iy + 0
	ld	iy, (ix + 6)
	ld	(iy), a
	push	de
	pop	iy
	ld	a, (iy)
	xor	a, (ix + -2)
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	push	hl
	pop	iy
	add	iy, de
	xor	a, (ix + -6)
	xor	a, (iy + 1)
	lea	hl, iy + 0
	ld	iy, (ix + 6)
	ld	(iy + 4), a
	ld	a, (ix + -1)
	xor	a, (ix + -2)
	ld	e, a
	ld	a, (hl)
	xor	a, e
	ld	(ix + -2), a
	ld	hl, (ix + -12)
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	push	hl
	pop	iy
	add	iy, de
	ld	a, (iy + 1)
	lea	hl, iy + 0
	xor	a, (ix + -2)
	ld	iy, (ix + 6)
	ld	(iy + 8), a
	ld	a, (ix + -3)
	xor	a, (ix + -1)
	ld	iy, (ix + -9)
	xor	a, (iy + 1)
	xor	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 12), a
	ld	e, (iy + 1)
	ld	(ix + -2), e
	ld	a, (iy + 5)
	ld	(ix + -1), a
	ld	l, (iy + 9)
	ld	(ix + -3), l
	ld	l, (iy + 13)
	ld	(ix + -6), l
	ld	iy, 0
	lea	hl, iy + 0
	ld	l, e
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	add	hl, de
	ld	(ix + -9), hl
	ld	l, (hl)
	ld	(ix + -13), l
	lea	hl, iy + 0
	ld	l, a
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	add	hl, de
	push	hl
	pop	iy
	ld	bc, 0
	push	bc
	pop	hl
	ld	e, (ix + -3)
	ld	l, e
	ld	a, (ix + -6)
	ld	c, a
	ld	(ix + -12), bc
	xor	a, e
	xor	a, (ix + -13)
	xor	a, (iy + 1)
	lea	de, iy + 0
	ld	iy, (ix + 6)
	ld	(iy + 1), a
	push	de
	pop	iy
	ld	a, (iy)
	xor	a, (ix + -2)
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	push	hl
	pop	iy
	add	iy, de
	xor	a, (ix + -6)
	xor	a, (iy + 1)
	lea	hl, iy + 0
	ld	iy, (ix + 6)
	ld	(iy + 5), a
	ld	a, (ix + -1)
	xor	a, (ix + -2)
	ld	e, a
	ld	a, (hl)
	xor	a, e
	ld	(ix + -2), a
	ld	hl, (ix + -12)
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	push	hl
	pop	iy
	add	iy, de
	ld	a, (iy + 1)
	lea	hl, iy + 0
	xor	a, (ix + -2)
	ld	iy, (ix + 6)
	ld	(iy + 9), a
	ld	a, (ix + -3)
	xor	a, (ix + -1)
	ld	iy, (ix + -9)
	xor	a, (iy + 1)
	xor	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 13), a
	ld	e, (iy + 2)
	ld	(ix + -2), e
	ld	a, (iy + 6)
	ld	(ix + -1), a
	ld	l, (iy + 10)
	ld	(ix + -3), l
	ld	l, (iy + 14)
	ld	(ix + -6), l
	ld	iy, 0
	lea	hl, iy + 0
	ld	l, e
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	add	hl, de
	ld	(ix + -9), hl
	ld	l, (hl)
	ld	(ix + -13), l
	lea	hl, iy + 0
	ld	l, a
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	add	hl, de
	push	hl
	pop	iy
	ld	bc, 0
	push	bc
	pop	hl
	ld	e, (ix + -3)
	ld	l, e
	ld	a, (ix + -6)
	ld	c, a
	ld	(ix + -12), bc
	xor	a, e
	xor	a, (ix + -13)
	xor	a, (iy + 1)
	lea	de, iy + 0
	ld	iy, (ix + 6)
	ld	(iy + 2), a
	push	de
	pop	iy
	ld	a, (iy)
	xor	a, (ix + -2)
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	push	hl
	pop	iy
	add	iy, de
	xor	a, (ix + -6)
	xor	a, (iy + 1)
	lea	hl, iy + 0
	ld	iy, (ix + 6)
	ld	(iy + 6), a
	ld	a, (ix + -1)
	xor	a, (ix + -2)
	ld	e, a
	ld	a, (hl)
	xor	a, e
	ld	(ix + -2), a
	ld	hl, (ix + -12)
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	push	hl
	pop	iy
	add	iy, de
	ld	a, (iy + 1)
	lea	hl, iy + 0
	xor	a, (ix + -2)
	ld	iy, (ix + 6)
	ld	(iy + 10), a
	ld	a, (ix + -3)
	xor	a, (ix + -1)
	ld	iy, (ix + -9)
	xor	a, (iy + 1)
	xor	a, (hl)
	ld	iy, (ix + 6)
	ld	(iy + 14), a
	ld	e, (iy + 3)
	ld	(ix + -1), e
	ld	a, (iy + 7)
	ld	(ix + -9), a
	ld	l, (iy + 11)
	ld	(ix + -2), l
	ld	l, (iy + 15)
	ld	(ix + -3), l
	ld	iy, 0
	lea	hl, iy + 0
	ld	l, e
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	add	hl, de
	ld	(ix + -6), hl
	ld	l, (hl)
	ld	(ix + -13), l
	lea	hl, iy + 0
	ld	l, a
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	add	hl, de
	push	hl
	pop	iy
	ld	de, 0
	push	de
	pop	bc
	ld	l, (ix + -2)
	ld	c, l
	ld	a, (ix + -3)
	ld	e, a
	ld	(ix + -12), de
	xor	a, l
	xor	a, (ix + -13)
	xor	a, (iy + 1)
	lea	hl, iy + 0
	ld	iy, (ix + 6)
	ld	(iy + 3), a
	ld	a, (hl)
	xor	a, (ix + -1)
	push	bc
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	de
	ld	hl, _gf_mul
	push	hl
	pop	iy
	add	iy, de
	xor	a, (ix + -3)
	xor	a, (iy + 1)
	lea	bc, iy + 0
	ld	iy, (ix + 6)
	ld	(iy + 7), a
	ld	d, (ix + -9)
	ld	a, d
	xor	a, (ix + -1)
	ld	e, a
	push	bc
	pop	hl
	ld	a, (hl)
	xor	a, e
	ld	e, a
	ld	hl, (ix + -12)
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	a, (iy + 1)
	lea	hl, iy + 0
	xor	a, e
	ld	iy, (ix + 6)
	ld	(iy + 11), a
	lea	bc, iy + 0
	ld	a, (ix + -2)
	xor	a, d
	ld	iy, (ix + -6)
	xor	a, (iy + 1)
	xor	a, (hl)
	push	bc
	pop	iy
	ld	(iy + 15), a
	ld	sp, ix
	pop	ix
	ret
	
_aes_InvMixColumns:
	ld	hl, -11
	call	ti._frameset
	ld	iy, (ix + 6)
	ld	l, (iy)
	ld	a, (iy + 4)
	ld	e, (iy + 8)
	ld	(ix + -9), e
	ld	e, (iy + 12)
	ld	(ix + -10), e
	ld	de, 0
	ld	e, l
	ld	bc, 6
	push	de
	pop	hl
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -3), iy
	ld	l, (iy + 5)
	ld	(ix + -11), l
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -6), iy
	ld	a, (iy + 3)
	xor	a, (ix + -11)
	ld	(ix + -11), a
	ld	a, (ix + -9)
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -9), iy
	ld	a, (iy + 4)
	xor	a, (ix + -11)
	ld	(ix + -11), a
	ld	a, (ix + -10)
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	hl, _gf_mul
	push	hl
	pop	iy
	add	iy, bc
	ld	a, (iy + 2)
	lea	bc, iy + 0
	xor	a, (ix + -11)
	ld	hl, (ix + 6)
	ld	(hl), a
	ld	iy, (ix + -6)
	ld	a, (iy + 5)
	ld	iy, (ix + -3)
	xor	a, (iy + 2)
	ld	l, a
	ld	iy, (ix + -9)
	ld	a, (iy + 3)
	xor	a, l
	ld	l, a
	push	bc
	pop	iy
	ld	a, (iy + 4)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 4), a
	ld	iy, (ix + -6)
	ld	a, (iy + 2)
	ld	iy, (ix + -3)
	xor	a, (iy + 4)
	ld	l, a
	ld	iy, (ix + -9)
	ld	a, (iy + 5)
	xor	a, l
	ld	l, a
	push	bc
	pop	iy
	ld	a, (iy + 3)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 8), a
	ld	iy, (ix + -6)
	ld	a, (iy + 4)
	ld	iy, (ix + -3)
	xor	a, (iy + 3)
	ld	l, a
	ld	iy, (ix + -9)
	ld	a, (iy + 2)
	xor	a, l
	ld	l, a
	push	bc
	pop	iy
	ld	a, (iy + 5)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 12), a
	ld	l, (iy + 1)
	ld	a, (iy + 5)
	ld	c, (iy + 9)
	ld	(ix + -9), c
	ld	c, (iy + 13)
	ld	(ix + -10), c
	ld	e, l
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -3), iy
	ld	l, (iy + 5)
	ld	(ix + -11), l
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -6), iy
	ld	a, (iy + 3)
	xor	a, (ix + -11)
	ld	(ix + -11), a
	ld	a, (ix + -9)
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -9), iy
	ld	a, (iy + 4)
	xor	a, (ix + -11)
	ld	(ix + -11), a
	ld	a, (ix + -10)
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	hl, _gf_mul
	push	hl
	pop	iy
	add	iy, bc
	ld	a, (iy + 2)
	lea	bc, iy + 0
	xor	a, (ix + -11)
	ld	iy, (ix + 6)
	ld	(iy + 1), a
	ld	iy, (ix + -6)
	ld	a, (iy + 5)
	ld	iy, (ix + -3)
	xor	a, (iy + 2)
	ld	l, a
	ld	iy, (ix + -9)
	ld	a, (iy + 3)
	xor	a, l
	ld	l, a
	push	bc
	pop	iy
	ld	a, (iy + 4)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 5), a
	ld	iy, (ix + -6)
	ld	a, (iy + 2)
	ld	iy, (ix + -3)
	xor	a, (iy + 4)
	ld	l, a
	ld	iy, (ix + -9)
	ld	a, (iy + 5)
	xor	a, l
	ld	l, a
	push	bc
	pop	iy
	ld	a, (iy + 3)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 9), a
	ld	iy, (ix + -6)
	ld	a, (iy + 4)
	ld	iy, (ix + -3)
	xor	a, (iy + 3)
	ld	l, a
	ld	iy, (ix + -9)
	ld	a, (iy + 2)
	xor	a, l
	ld	l, a
	push	bc
	pop	iy
	ld	a, (iy + 5)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 13), a
	ld	l, (iy + 2)
	ld	a, (iy + 6)
	ld	c, (iy + 10)
	ld	(ix + -9), c
	ld	c, (iy + 14)
	ld	(ix + -10), c
	ld	e, l
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -3), iy
	ld	l, (iy + 5)
	ld	(ix + -11), l
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -6), iy
	ld	a, (iy + 3)
	xor	a, (ix + -11)
	ld	(ix + -11), a
	ld	a, (ix + -9)
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -9), iy
	ld	a, (iy + 4)
	xor	a, (ix + -11)
	ld	(ix + -11), a
	ld	a, (ix + -10)
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	hl, _gf_mul
	push	hl
	pop	iy
	add	iy, bc
	ld	a, (iy + 2)
	lea	bc, iy + 0
	xor	a, (ix + -11)
	ld	iy, (ix + 6)
	ld	(iy + 2), a
	ld	iy, (ix + -6)
	ld	a, (iy + 5)
	ld	iy, (ix + -3)
	xor	a, (iy + 2)
	ld	l, a
	ld	iy, (ix + -9)
	ld	a, (iy + 3)
	xor	a, l
	ld	l, a
	push	bc
	pop	iy
	ld	a, (iy + 4)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 6), a
	ld	iy, (ix + -6)
	ld	a, (iy + 2)
	ld	iy, (ix + -3)
	xor	a, (iy + 4)
	ld	l, a
	ld	iy, (ix + -9)
	ld	a, (iy + 5)
	xor	a, l
	ld	l, a
	push	bc
	pop	iy
	ld	a, (iy + 3)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 10), a
	ld	iy, (ix + -6)
	ld	a, (iy + 4)
	ld	iy, (ix + -3)
	xor	a, (iy + 3)
	ld	l, a
	ld	iy, (ix + -9)
	ld	a, (iy + 2)
	xor	a, l
	ld	l, a
	push	bc
	pop	iy
	ld	a, (iy + 5)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 14), a
	ld	l, (iy + 3)
	ld	a, (iy + 7)
	ld	c, (iy + 11)
	ld	(ix + -6), c
	ld	c, (iy + 15)
	ld	(ix + -10), c
	ld	e, l
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -9), iy
	ld	l, (iy + 5)
	ld	(ix + -11), l
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -3), iy
	ld	a, (iy + 3)
	xor	a, (ix + -11)
	ld	(ix + -11), a
	ld	a, (ix + -6)
	ld	e, a
	push	de
	pop	hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	bc
	ld	iy, _gf_mul
	add	iy, bc
	ld	(ix + -6), iy
	ld	a, (iy + 4)
	xor	a, (ix + -11)
	ld	(ix + -11), a
	ld	a, (ix + -10)
	ld	e, a
	ex	de, hl
	ld	bc, 6
	call	ti._imulu
	push	hl
	pop	de
	ld	iy, _gf_mul
	add	iy, de
	ld	a, (iy + 2)
	lea	de, iy + 0
	xor	a, (ix + -11)
	ld	iy, (ix + 6)
	ld	(iy + 3), a
	ld	iy, (ix + -3)
	ld	a, (iy + 5)
	ld	iy, (ix + -9)
	xor	a, (iy + 2)
	lea	bc, iy + 0
	ld	l, a
	ld	iy, (ix + -6)
	ld	a, (iy + 3)
	xor	a, l
	ld	l, a
	push	de
	pop	iy
	ld	a, (iy + 4)
	xor	a, l
	ld	hl, (ix + 6)
	push	hl
	pop	iy
	ld	(iy + 7), a
	ld	iy, (ix + -3)
	ld	a, (iy + 2)
	push	bc
	pop	iy
	xor	a, (iy + 4)
	ld	l, a
	ld	iy, (ix + -6)
	ld	a, (iy + 5)
	xor	a, l
	ld	l, a
	push	de
	pop	iy
	ld	a, (iy + 3)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 11), a
	ld	iy, (ix + -3)
	ld	a, (iy + 4)
	push	bc
	pop	iy
	xor	a, (iy + 3)
	ld	l, a
	ld	iy, (ix + -6)
	ld	a, (iy + 2)
	xor	a, l
	ld	l, a
	push	de
	pop	iy
	ld	a, (iy + 5)
	xor	a, l
	ld	iy, (ix + 6)
	ld	(iy + 15), a
	ld	sp, ix
	pop	ix
	ret
	
_increment_iv:
	ld	hl, -9
	call	ti._frameset
	ld	de, (ix + 9)
	ld	hl, 16
	ld	iy, 1
	ld	bc, 0
	or	a, a
	sbc	hl, de
	ld	(ix + -3), hl
	lea	hl, iy + 0
	or	a, a
	sbc	hl, de
	ld	(ix + -6), hl
	ld	iy, (ix + 6)
	lea	hl, iy + 15
	ld	(ix + -9), hl
.loop:
	push	bc
	pop	hl
	ld	de, 15
	add	hl, de
	ld	de, (ix + -3)
	or	a, a
	sbc	hl, de
	jq	c, .exit_loop
	ld	iy, (ix + -9)
	add	iy, bc
	inc	(iy)
	ld	hl, (ix + -6)
	or	a, a
	sbc	hl, bc
	jq	z, .exit_loop
	ld	a, (iy)
	dec	bc
	or	a, a
	jq	z, .loop
.exit_loop:
	ld	sp, ix
	pop	ix
	ret
	
	
hashlib_AESEncryptBlock:
	ld	hl, -22
	call	ti._frameset
	ld	iy, (ix + 6)
	lea	de, ix + -16
	ld	(ix + -19), de
	ld	hl, (ix + 12)
	ld	hl, (hl)
	ld	(ix + -22), hl
	ld	a, (iy)
	ld	(ix + -16), a
	ld	a, (iy + 1)
	ld	(ix + -12), a
	ld	a, (iy + 2)
	ld	(ix + -8), a
	ld	a, (iy + 3)
	ld	(ix + -4), a
	ld	a, (iy + 4)
	ld	(ix + -15), a
	ld	a, (iy + 5)
	ld	(ix + -11), a
	ld	a, (iy + 6)
	ld	(ix + -7), a
	ld	a, (iy + 7)
	ld	(ix + -3), a
	ld	a, (iy + 8)
	ld	(ix + -14), a
	ld	a, (iy + 9)
	ld	(ix + -10), a
	ld	a, (iy + 10)
	ld	(ix + -6), a
	ld	a, (iy + 11)
	ld	(ix + -2), a
	ld	a, (iy + 12)
	ld	(ix + -13), a
	ld	a, (iy + 13)
	ld	(ix + -9), a
	ld	a, (iy + 14)
	ld	(ix + -5), a
	ld	a, (iy + 15)
	ld	(ix + -1), a
	ld	iy, (ix + 12)
	pea	iy + 3
	push	de
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 19
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 35
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 51
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 67
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 83
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 99
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 115
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	de, 131
	ld	iy, (ix + 12)
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	de, 147
	ld	iy, (ix + 12)
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	de, 128
	ld	hl, (ix + -22)
	or	a, a
	sbc	hl, de
	jq	nz, .lbl2
	ld	de, 163
	jq	.lbl4
.lbl2:
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	de, 163
	ld	hl, (ix + 12)
	push	hl
	pop	iy
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	de, 179
	ld	iy, (ix + 12)
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	de, 192
	ld	hl, (ix + -22)
	or	a, a
	sbc	hl, de
	jq	nz, .lbl5
	ld	de, 195
.lbl4:
	ld	iy, (ix + 12)
	jq	.lbl6
.lbl5:
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	de, 195
	ld	hl, (ix + 12)
	push	hl
	pop	iy
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_MixColumns
	pop	hl
	ld	de, 211
	ld	iy, (ix + 12)
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_SubBytes
	ld	iy, (ix + 12)
	pop	hl
	ld	a, (ix + -12)
	ld	l, (ix + -11)
	ld	(ix + -12), l
	ld	l, (ix + -10)
	ld	(ix + -11), l
	ld	l, (ix + -9)
	ld	(ix + -10), l
	ld	(ix + -9), a
	ld	a, (ix + -8)
	ld	l, (ix + -6)
	ld	(ix + -8), l
	ld	(ix + -6), a
	ld	a, (ix + -7)
	ld	l, (ix + -5)
	ld	(ix + -7), l
	ld	(ix + -5), a
	ld	a, (ix + -4)
	ld	l, (ix + -1)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -2), l
	ld	(ix + -3), a
	ld	de, 227
.lbl6:
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	a, (ix + -16)
	ld	iy, (ix + 9)
	ld	(iy), a
	ld	a, (ix + -12)
	ld	(iy + 1), a
	ld	a, (ix + -8)
	ld	(iy + 2), a
	ld	a, (ix + -4)
	ld	(iy + 3), a
	ld	a, (ix + -15)
	ld	(iy + 4), a
	ld	a, (ix + -11)
	ld	(iy + 5), a
	ld	a, (ix + -7)
	ld	(iy + 6), a
	ld	a, (ix + -3)
	ld	(iy + 7), a
	ld	a, (ix + -14)
	ld	(iy + 8), a
	ld	a, (ix + -10)
	ld	(iy + 9), a
	ld	a, (ix + -6)
	ld	(iy + 10), a
	ld	a, (ix + -2)
	ld	(iy + 11), a
	ld	a, (ix + -13)
	ld	(iy + 12), a
	ld	a, (ix + -9)
	ld	(iy + 13), a
	ld	a, (ix + -5)
	ld	(iy + 14), a
	ld	a, (ix + -1)
	ld	(iy + 15), a
	ld	sp, ix
	pop	ix
	ret
	
hashlib_AESDecryptBlock:
	ld	hl, -19
	call	ti._frameset
	ld	iy, (ix + 6)
	ld	hl, (ix + 12)
	lea	de, ix + -16
	ld	(ix + -19), de
	ld	de, (hl)
	ld	a, (iy)
	ld	(ix + -16), a
	ld	a, (iy + 1)
	ld	(ix + -12), a
	ld	a, (iy + 2)
	ld	(ix + -8), a
	ld	a, (iy + 3)
	ld	(ix + -4), a
	ld	a, (iy + 4)
	ld	(ix + -15), a
	ld	a, (iy + 5)
	ld	(ix + -11), a
	ld	a, (iy + 6)
	ld	(ix + -7), a
	ld	a, (iy + 7)
	ld	(ix + -3), a
	ld	a, (iy + 8)
	ld	(ix + -14), a
	ld	a, (iy + 9)
	ld	(ix + -10), a
	ld	a, (iy + 10)
	ld	(ix + -6), a
	ld	a, (iy + 11)
	ld	(ix + -2), a
	ld	a, (iy + 12)
	ld	(ix + -13), a
	ld	a, (iy + 13)
	ld	(ix + -9), a
	ld	a, (iy + 14)
	ld	(ix + -5), a
	ld	a, (iy + 15)
	ld	(ix + -1), a
	ld	bc, 129
	push	de
	pop	hl
	or	a, a
	sbc	hl, bc
	call	ti._setflag
	jq	m, .lbl3
	ld	bc, (ix + -19)
	ld	iy, 193
	ex	de, hl
	lea	de, iy + 0
	or	a, a
	sbc	hl, de
	call	ti._setflag
	ld	hl, (ix + 12)
	jq	m, .lbl4
	ld	de, 227
	push	hl
	pop	iy
	add	iy, de
	push	iy
	push	bc
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	de, 211
	ld	iy, (ix + 12)
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	de, 195
	ld	iy, (ix + 12)
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	jq	.lbl5
.lbl3:
	ld	de, 163
	ld	iy, (ix + 12)
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	jq	.lbl7
.lbl4:
	ld	de, 195
	push	hl
	pop	iy
	add	iy, de
	push	iy
	push	bc
	call	_aes_AddRoundKey
	pop	hl
.lbl5:
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	de, 179
	ld	hl, (ix + 12)
	push	hl
	pop	iy
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	de, 163
	ld	iy, (ix + 12)
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
.lbl7:
	pop	hl
	ld	de, (ix + -19)
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	push	de
	call	_aes_InvSubBytes
	pop	hl
	ld	de, 147
	ld	iy, (ix + 12)
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	de, 131
	ld	iy, (ix + 12)
	add	iy, de
	push	iy
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 115
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 99
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 83
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 67
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 51
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 35
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 19
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvMixColumns
	pop	hl
	ld	a, (ix + -9)
	ld	l, (ix + -10)
	ld	(ix + -9), l
	ld	l, (ix + -11)
	ld	(ix + -10), l
	ld	l, (ix + -12)
	ld	(ix + -11), l
	ld	(ix + -12), a
	ld	a, (ix + -5)
	ld	l, (ix + -7)
	ld	(ix + -5), l
	ld	(ix + -7), a
	ld	a, (ix + -6)
	ld	l, (ix + -8)
	ld	(ix + -6), l
	ld	(ix + -8), a
	ld	a, (ix + -1)
	ld	l, (ix + -4)
	ld	(ix + -1), l
	ld	l, (ix + -3)
	ld	(ix + -4), l
	ld	l, (ix + -2)
	ld	(ix + -3), l
	ld	(ix + -2), a
	ld	hl, (ix + -19)
	push	hl
	call	_aes_InvSubBytes
	pop	hl
	ld	iy, (ix + 12)
	pea	iy + 3
	ld	hl, (ix + -19)
	push	hl
	call	_aes_AddRoundKey
	pop	hl
	pop	hl
	ld	a, (ix + -16)
	ld	iy, (ix + 9)
	ld	(iy), a
	ld	a, (ix + -12)
	ld	(iy + 1), a
	ld	a, (ix + -8)
	ld	(iy + 2), a
	ld	a, (ix + -4)
	ld	(iy + 3), a
	ld	a, (ix + -15)
	ld	(iy + 4), a
	ld	a, (ix + -11)
	ld	(iy + 5), a
	ld	a, (ix + -7)
	ld	(iy + 6), a
	ld	a, (ix + -3)
	ld	(iy + 7), a
	ld	a, (ix + -14)
	ld	(iy + 8), a
	ld	a, (ix + -10)
	ld	(iy + 9), a
	ld	a, (ix + -6)
	ld	(iy + 10), a
	ld	a, (ix + -2)
	ld	(iy + 11), a
	ld	a, (ix + -13)
	ld	(iy + 12), a
	ld	a, (ix + -9)
	ld	(iy + 13), a
	ld	a, (ix + -5)
	ld	(iy + 14), a
	ld	a, (ix + -1)
	ld	(iy + 15), a
	ld	sp, ix
	pop	ix
	ret
	
hashlib_AESEncrypt:
	ld	hl, -95
	call	ti._frameset
	ld	de, (ix + 6)
	ld	bc, 1
	push	de
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_1
	jq	.lbl_21
.lbl_1:
	ld	iy, (ix + 12)
	lea	hl, iy + 0
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_2
	jq	.lbl_21
.lbl_2:
	ld	hl, (ix + 15)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_3
	jq	.lbl_21
.lbl_3:
	ld	hl, (ix + 18)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_21
	ld	bc, (ix + 9)
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_6
	ld	bc, 2
.lbl_21:
	push	bc
	pop	hl
	jp stack_clear
.lbl_6:
	ld	l, (ix + 21)
	ld	a, l
	or	a, a
	jq	nz, .lbl_7
	ld	a, (ix + 24)
	cp	a, 2
	jq	c, .lbl_11
	ld	bc, 4
	jq	.lbl_21
.lbl_7:
	ld	a, l
	cp	a, 1
	jq	nz, .lbl_8
	lea	hl, ix + -64
	ld	(ix + -86), hl
	push	de
	pop	hl
	lea	bc, iy + 0
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_16
	ld	hl, (ix + 9)
	push	hl
	push	de
	push	iy
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
.lbl_16:
	lea	hl, ix + -80
	ld	(ix + -83), hl
	ld	hl, 16
	push	hl
	ld	hl, (ix + 18)
	push	hl
	ld	hl, (ix + -86)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 9)
	push	hl
	pop	iy
	ld	de, -16
	add	iy, de
	ld	de, 17
	or	a, a
	sbc	hl, de
	ld	hl, 0
	push	hl
	pop	bc
	ld	de, (ix + 15)
	jq	c, .lbl_20
	lea	bc, iy + 0
	push	hl
	pop	iy
.lbl_18:
	lea	hl, iy + 0
	or	a, a
	sbc	hl, bc
	jq	nc, .lbl_22
	push	de
	ld	hl, (ix + -83)
	push	hl
	ld	hl, (ix + -86)
	push	hl
	ld	(ix + -89), iy
	ld	(ix + -92), bc
	call	hashlib_AESEncryptBlock
	pop	hl
	pop	hl
	pop	hl
	ld	de, (ix + -89)
	ld	hl, (ix + 12)
	add	hl, de
	ld	de, 16
	push	de
	push	hl
	ld	hl, (ix + -83)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix + -86)
	push	hl
	call	_increment_iv
	ld	bc, (ix + -92)
	ld	iy, (ix + -89)
	pop	hl
	pop	hl
	ld	de, 16
	add	iy, de
	ld	de, (ix + 15)
	jq	.lbl_18
.lbl_11:
	lea	hl, ix + -16
	ld	(ix + -83), hl
	lea	hl, ix + -32
	ld	(ix + -86), hl
	lea	hl, ix + -48
	ld	(ix + -89), hl
	ld	l, a
	push	hl
	push	iy
	push	bc
	push	de
	call	hashlib_AESPadMessage
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	c, 4
	ld	hl, (ix + 9)
	call	ti._ishru
	ld	(ix + -92), hl
	ld	hl, 16
	push	hl
	ld	hl, (ix + 18)
	push	hl
	ld	hl, (ix + -89)
	push	hl
	call	ti._memcpy
	ld	de, (ix + -92)
	ld	iy, (ix + 12)
	ld	bc, 0
	pop	hl
	pop	hl
	pop	hl
	inc	de
.lbl_12:
	push	de
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_26
	ld	hl, 16
	push	hl
	push	iy
	ld	hl, (ix + -83)
	push	hl
	ld	(ix + -95), iy
	ld	(ix + -92), de
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix + -83)
	push	hl
	ld	hl, (ix + -89)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 15)
	push	hl
	ld	hl, (ix + -86)
	push	hl
	ld	hl, (ix + -83)
	push	hl
	call	hashlib_AESEncryptBlock
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix + -86)
	push	hl
	ld	hl, (ix + -95)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix + -86)
	push	hl
	ld	hl, (ix + -89)
	push	hl
	call	ti._memcpy
	ld	de, (ix + -92)
	ld	iy, (ix + -95)
	ld	bc, 0
	pop	hl
	pop	hl
	pop	hl
	dec	de
	lea	iy, iy + 16
	jq	.lbl_12
.lbl_8:
	ld	bc, 3
	jq	.lbl_21
.lbl_26:
	jq	.lbl_21
.lbl_22:
	lea	bc, iy + 0
.lbl_20:
	ld	(ix + -89), bc
	push	de
	ld	hl, (ix + -83)
	push	hl
	ld	hl, (ix + -86)
	push	hl
	call	hashlib_AESEncryptBlock
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 12)
	push	hl
	pop	iy
	ld	de, (ix + -89)
	add	iy, de
	ld	hl, (ix + 9)
	or	a, a
	sbc	hl, de
	push	hl
	push	iy
	ld	hl, (ix + -83)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	bc, 0
	jq	.lbl_21
	
hashlib_AESDecrypt:
	ld	hl, -66
	call	ti._frameset
	ld	hl, (ix + 6)
	ld	de, 1
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_9
	ld	hl, (ix + 12)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_9
	ld	hl, (ix + 15)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_9
	ld	iy, (ix + 18)
	lea	hl, iy + 0
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_9
	ld	hl, (ix + 9)
	ld	de, 5
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_9
	ld	l, (ix + 21)
	ld	a, l
	or	a, a
	jq	nz, .lbl_13
	ld	a, (ix + 24)
	cp	a, 2
	jq	c, .lbl_15
	ld	de, 4
	jq	.lbl_9
.lbl_13:
	ld	a, l
	cp	a, 1
	jq	nz, .lbl_19
	or	a, a
	sbc	hl, hl
	push	hl
	inc	hl
	push	hl
	push	iy
	ld	hl, (ix + 15)
	push	hl
	ld	hl, (ix + 12)
	push	hl
	ld	hl, (ix + 9)
	push	hl
	ld	hl, (ix + 6)
	push	hl
	call	hashlib_AESEncrypt
	ld	hl, 21
	add	hl, sp
	ld	sp, hl
	jq	.lbl_21
.lbl_15:
	ld	hl, (ix + 9)
	ld	a, l
	and	a, 15
	or	a, a
	jq	nz, .lbl_9
	lea	de, ix + -16
	ld	(ix + -51), de
	lea	de, ix + -32
	ld	(ix + -54), de
	lea	de, ix + -48
	ld	c, 4
	call	ti._ishru
	ld	(ix + -57), hl
	ld	hl, 16
	push	hl
	push	iy
	ld	(ix + -60), de
	push	de
	call	ti._memcpy
	ld	de, (ix + -57)
	pop	hl
	pop	hl
	pop	hl
	ld	iy, 0
.lbl_17:
	push	de
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	ld	hl, (ix + 6)
	jq	z, .lbl_20
	lea	bc, iy + 0
	ld	(ix + -66), bc
	add	hl, bc
	ld	(ix + -57), de
	ld	de, 16
	push	de
	push	hl
	ld	hl, (ix + -51)
	push	hl
	ld	(ix + -63), iy
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 15)
	push	hl
	ld	hl, (ix + -54)
	push	hl
	ld	hl, (ix + -51)
	push	hl
	call	hashlib_AESDecryptBlock
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix + -54)
	push	hl
	ld	hl, (ix + -60)
	push	hl
	call	_xor_buf
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 12)
	ld	de, (ix + -66)
	add	hl, de
	ld	de, 16
	push	de
	ld	de, (ix + -54)
	push	de
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 16
	push	hl
	ld	hl, (ix + -51)
	push	hl
	ld	hl, (ix + -60)
	push	hl
	call	ti._memcpy
	ld	iy, (ix + -63)
	ld	de, (ix + -57)
	pop	hl
	pop	hl
	pop	hl
	dec	de
	ld	bc, 16
	add	iy, bc
	jq	.lbl_17
.lbl_19:
	ld	de, 3
	jq	.lbl_9
.lbl_20:
	ld	a, (ix + 24)
	ld	l, a
	push	hl
	ld	hl, (ix + 12)
	push	hl
	ld	de, (ix + 9)
	push	de
	push	hl
	call	hashlib_AESStripPadding
	pop	hl
	pop	hl
	pop	hl
	pop	hl
.lbl_21:
	ld	de, 0
.lbl_9:
	ex	de, hl
	jp stack_clear
	
	
 hashlib_AESPadMessage:
  	ld	hl, -6
	call	ti._frameset
	ld	bc, (ix + 9)
	ld	de, 0
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_1
	jq	.lbl_10
.lbl_1:
	ld	hl, (ix + 6)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_2
	jq	.lbl_10
.lbl_2:
	ld	hl, (ix + 12)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_3
	jq	.lbl_10
.lbl_3:
	push	bc
	pop	hl
	ld	bc, 16
	ld	iy, -16
	ld	a, l
	and	a, 15
	add	hl, bc
	ld	(ix + -3), hl
	lea	bc, iy + 0
	call	ti._iand
	or	a, a
	jq	z, .lbl_5
	ld	(ix + -3), hl
.lbl_5:
	ld	l, (ix + 15)
	ld	a, l
	or	a, a
	ld	iy, (ix + 12)
	jq	nz, .lbl_6
	ld	hl, (ix + 9)
	ex	de, hl
	add	iy, de
	ld	hl, (ix + -3)
	or	a, a
	sbc	hl, de
	push	hl
	push	hl
	push	iy
	call	ti._memset
	pop	hl
	pop	hl
	pop	hl
	jq	.lbl_9
.lbl_6:
	ld	a, l
	cp	a, 1
	ld	bc, (ix + 9)
	jq	nz, .lbl_10
	add	iy, bc
	ld	(ix + -6), iy
	ld	hl, (ix + -3)
	or	a, a
	sbc	hl, bc
	push	hl
	or	a, a
	sbc	hl, hl
	push	hl
	push	iy
	call	ti._memset
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + -6)
	set	7, (hl)
.lbl_9:
	ld	hl, (ix + 9)
	push	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, (ix + 12)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	de, (ix + -3)
.lbl_10:
	ex	de, hl
	ld	sp, ix
	pop	ix
	ret
 
hashlib_RSAEncodeOAEP:
	ld	hl, -615
	call	ti._frameset
	ld	bc, (ix + 9)
	ld	iy, (ix + 15)
	lea	hl, iy + 0
	push	bc
	pop	de
	or	a, a
	sbc	hl, de
	push	ix
	ld	de, -600
	add	ix, de
	ld	(ix + 0), hl
	pop	ix
	ld	de, -66
	add	hl, de
	push	ix
	ld	de, -603
	add	ix, de
	ld	(ix + 0), hl
	pop	ix
	lea	hl, iy + 0
	ld	de, -33
	add	hl, de
	push	ix
	ld	de, -597
	add	ix, de
	ld	(ix + 0), hl
	pop	ix
	push	bc
	pop	hl
	ld	de, 66
	add	hl, de
	ex	de, hl
	lea	bc, iy + 0
	lea	hl, iy + 0
	or	a, a
	sbc	hl, de
	jq	nc, .lbl_1
	ld	de, 0
	jq	.lbl_13
.lbl_1:
	ld	de, 257
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	ld	de, 0
	jq	c, .lbl_2
	jq	.lbl_13
.lbl_2:
	ld	hl, (ix + 9)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_3
	jq	.lbl_13
.lbl_3:
	ld	hl, (ix + 6)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_4
	jq	.lbl_13
.lbl_4:
	ld	iy, (ix + 12)
	lea	hl, iy + 0
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_5
	jq	.lbl_13
.lbl_5:
	ld	de, 32
	lea	hl, ix + -114
	push	ix
	ld	bc, -609
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	bc, -594
	lea	hl, ix + 0
	add	hl, bc
	push	ix
	ld	bc, -606
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	(iy), 0
	inc	iy
	push	de
	ld	bc, -612
	lea	hl, ix + 0
	add	hl, bc
	ld	(hl), iy
	push	iy
	call	hashlib_RandomBytes
	pop	hl
	pop	hl
	ld	bc, -370
	lea	hl, ix + 0
	add	hl, bc
	push	hl
	ld	bc, -609
	lea	iy, ix + 0
	add	iy, bc
	ld	hl, (iy + 0)
	push	hl
	call	hashlib_Sha256Init
	pop	hl
	pop	hl
	ld	hl, (ix + 18)
	push	hl
	pop	de
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_7
	push	de
	call	ti._strlen
	pop	de
	ld	de, 0
	push	de
	push	hl
	ld	hl, (ix + 18)
	push	hl
	ld	bc, -609
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Update
	pop	hl
	pop	hl
	pop	hl
	pop	hl
.lbl_7:
	ld	hl, (ix + 12)
	push	hl
	pop	iy
	lea	hl, iy + 33
	ld	bc, -615
	lea	iy, ix + 0
	add	iy, bc
	ld	(iy + 0), hl
	push	hl
	ld	bc, -609
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Final
	pop	hl
	pop	hl
	ld	bc, -603
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	iy, (ix + 12)
	pea	iy + 65
	call	ti._memset
	pop	hl
	pop	hl
	pop	hl
	ld	de, -600
	lea	hl, ix + 0
	add	hl, de
	ld	bc, (hl)
	push	bc
	pop	de
	dec	de
	ld	iy, (ix + 12)
	add	iy, de
	ld	(iy), 1
	ld	iy, (ix + 12)
	add	iy, bc
	ld	hl, (ix + 9)
	push	hl
	ld	hl, (ix + 6)
	push	hl
	push	iy
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -597
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -606
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	hl, 32
	push	hl
	ld	bc, -612
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_MGF1Hash
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	iy, (ix + 15)
	ld	de, -33
	add	iy, de
	ld	de, 0
.lbl_8:
	lea	hl, iy + 0
	or	a, a
	sbc	hl, de
	jq	z, .lbl_9
	ld	bc, -606
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	add	hl, de
	lea	bc, iy + 0
	ld	(ix + -3), bc
	ld	bc, -615
	lea	iy, ix + 0
	add	iy, bc
	ld	iy, (iy + 0)
	add	iy, de
	ld	a, (iy)
	xor	a, (hl)
	ld	(iy), a
	ld	bc, (ix + -3)
	push	bc
	pop	iy
	inc	de
	jq	.lbl_8
.lbl_9:
	ld	hl, 32
	push	hl
	ld	bc, -606
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -597
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -615
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_MGF1Hash
	ld	bc, 0
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	de, 32
.lbl_11:
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	ld	hl, (ix + 15)
	jq	z, .lbl_19
	ld	(ix + -3), de
	ld	de, -606
	lea	hl, ix + 0
	add	hl, de
	ld	hl, (hl)
	add	hl, bc
	ld	de, -612
	lea	iy, ix + 0
	add	iy, de
	ld	iy, (iy + 0)
	add	iy, bc
	inc	bc
	ld	a, (iy)
	xor	a, (hl)
	ld	(iy), a
	ld	de, (ix + -3)
	jq	.lbl_11
.lbl_19:
	ex	de, hl
.lbl_13:
	ex	de, hl
	jp stack_clear
	
 
hashlib_AESStripPadding:
 	ld	hl, -3
	call	ti._frameset
	ld	bc, (ix + 9)
	ld	de, 0
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_1
	jq	.lbl_10
.lbl_1:
	ld	iy, (ix + 6)
	lea	hl, iy + 0
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_2
	jq	.lbl_10
.lbl_2:
	ld	hl, (ix + 12)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_3
	jq	.lbl_10
.lbl_3:
	ld	l, (ix + 15)
	ld	a, l
	or	a, a
	jq	nz, .lbl_4
	push	bc
	pop	de
	dec	de
	lea	hl, iy + 0
	add	hl, de
	ld	a, (hl)
	ld	de, 0
	ld	e, a
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	push	hl
	pop	bc
	jq	.lbl_9
.lbl_4:
	ld	a, l
	cp	a, 1
	jq	nz, .lbl_10
	lea	hl, iy + 0
	dec	hl
	ld	(ix + -3), hl
.lbl_7:
	ld	hl, (ix + -3)
	add	hl, bc
	dec	bc
	ld	a, (hl)
	cp	a, -128
	jq	nz,	.lbl_7
	inc	bc
.lbl_9:
	ld	(ix + -3), bc
	push	bc
	push	iy
	ld	hl, (ix + 12)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	de, (ix + -3)
	ld	iy, (ix + 12)
	add	iy, de
	ld	hl, (ix + 9)
	ld	de, (ix + -3)
	or	a, a
	sbc	hl, de
	push	hl
	or	a, a
	sbc	hl, hl
	push	hl
	push	iy
	call	ti._memset
	ld	de, (ix + -3)
	pop	hl
	pop	hl
	pop	hl
.lbl_10:
	ex	de, hl
	ld	sp, ix
	pop	ix
	ret
 
hashlib_RSADecodeOAEP:
	ld	hl, -900
	call	ti._frameset
	ld	de, (ix + 9)
	ld	iy, 0
	dec	de
	ld	bc, 256
	ex	de, hl
	or	a, a
	sbc	hl, bc
	jq	nc, .lbl_28
	ld	de, (ix + 6)
	push	de
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_28
	ld	hl, (ix + 12)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_28
	ld	bc, -370
	lea	iy, ix + 0
	add	iy, bc
	ld	hl, 65
	push	ix
	ld	bc, -900
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	lea	hl, ix + -38
	push	ix
	ld	bc, -894
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	lea	hl, iy + 108
	push	ix
	ld	bc, -885
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	lea	hl, iy + 0
	ld	bc, -891
	lea	iy, ix + 0
	add	iy, bc
	ld	(iy + 0), hl
	ld	bc, -882
	lea	iy, ix + 0
	add	iy, bc
	ld	bc, -888
	lea	hl, ix + 0
	add	hl, bc
	ld	(hl), iy
	ld	hl, (ix + 9)
	ld	bc, -33
	add	hl, bc
	push	ix
	ld	bc, -897
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	hl, (ix + 9)
	push	hl
	push	de
	push	iy
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, 32
	push	hl
	ld	bc, -885
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -897
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -888
	lea	hl, ix + 0
	add	hl, bc
	ld	iy, (hl)
	pea	iy + 33
	call	hashlib_MGF1Hash
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -888
	lea	hl, ix + 0
	add	hl, bc
	ld	iy, (hl)
	inc	iy
	ld	de, 0
.lbl_7:
	push	de
	pop	hl
	ld	bc, 32
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_9
	ld	bc, -885
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	add	hl, de
	lea	bc, iy + 0
	add	iy, de
	inc	de
	ld	a, (iy)
	xor	a, (hl)
	ld	(iy), a
	push	bc
	pop	iy
	jq	.lbl_7
.lbl_9:
	ld	bc, -897
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -885
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	hl, 32
	push	hl
	push	iy
	call	hashlib_MGF1Hash
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 9)
	ld	de, -33
	add	hl, de
	ld	bc, -888
	lea	iy, ix + 0
	add	iy, bc
	ld	iy, (iy + 0)
	lea	de, iy + 33
	ld	bc, -897
	lea	iy, ix + 0
	add	iy, bc
	ld	(iy + 0), de
	ld	de, 0
.lbl_10:
	push	hl
	pop	bc
	or	a, a
	sbc	hl, de
	jq	z, .lbl_12
	ld	(ix + -3), bc
	ld	bc, -885
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	add	hl, de
	ld	bc, -897
	lea	iy, ix + 0
	add	iy, bc
	ld	iy, (iy + 0)
	add	iy, de
	ld	a, (iy)
	xor	a, (hl)
	ld	(iy), a
	inc	de
	ld	bc, (ix + -3)
	push	bc
	pop	hl
	jq	.lbl_10
.lbl_12:
	ld	bc, -626
	lea	hl, ix + 0
	add	hl, bc
	push	hl
	ld	bc, -891
	lea	iy, ix + 0
	add	iy, bc
	ld	hl, (iy + 0)
	push	hl
	call	hashlib_Sha256Init
	pop	hl
	pop	hl
	ld	hl, (ix + 15)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_14
	push	hl
	call	ti._strlen
	pop	de
	ld	de, 0
	push	de
	push	hl
	ld	hl, (ix + 15)
	push	hl
	ld	bc, -891
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Update
	pop	hl
	pop	hl
	pop	hl
	pop	hl
.lbl_14:
	ld	bc, -894
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -891
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Final
	pop	hl
	pop	hl
	ld	hl, 32
	push	hl
	ld	hl, (ix + 12)
	push	hl
	ld	bc, -894
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_CompareDigest
	pop	hl
	pop	hl
	pop	hl
	ld	l, 1
	xor	a, l
	bit	0, a
	jq	nz, .lbl_21
	ld	de, 66
	ld	bc, (ix + 9)
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	ld	iy, 0
	jq	nc, .lbl_18
	ld	bc, 65
	jq	.lbl_18
.lbl_21:
	ld	iy, 0
	jq	.lbl_28
.lbl_19:
	ld	(ix + -3), bc
	ld	bc, -888
	lea	hl, ix + 0
	add	hl, bc
	ld	iy, (hl)
	add	iy, de
	ld	a, (iy)
	cp	a, 1
	ld	bc, (ix + -3)
	jq	z, .lbl_23
	inc	de
	ld	(ix + -3), bc
	ld	bc, -900
	lea	hl, ix + 0
	add	hl, bc
	ld	(hl), de
	ld	iy, 0
	ld	bc, (ix + -3)
.lbl_18:
	push	bc
	pop	hl
	ld	(ix + -3), bc
	push	ix
	ld	bc, -900
	add	ix, bc
	ld	de, (ix + 0)
	pop	ix
	or	a, a
	sbc	hl, de
	ld	bc, (ix + -3)
	jq	z, .lbl_24
	jq	.lbl_19
.lbl_23:
	push	de
	pop	bc
	ld	iy, 0
.lbl_24:
	ld	de, (ix + 9)
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	jq	z, .lbl_28
	inc	bc
	ld	(ix + -3), de
	ld	de, -888
	lea	hl, ix + 0
	add	hl, de
	ld	iy, (hl)
	add	iy, bc
	ld	de, (ix + -3)
	ex	de, hl
	or	a, a
	sbc	hl, bc
	push	ix
	ld	bc, -885
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	push	hl
	push	iy
	ld	hl, (ix + 12)
	push	hl
	call	ti._memcpy
	ld	bc, -885
	lea	hl, ix + 0
	add	hl, bc
	ld	iy, (hl)
	pop	hl
	pop	hl
	pop	hl
.lbl_28:
	lea	hl, iy + 0
	jp stack_clear
    
hashlib_RSAEncodePSS:
	ld	hl, -681
	call	ti._frameset
	ld	de, 72
	or	a, a
	sbc	hl, hl
	lea	bc, ix + -78
	push	de
	push	hl
	ld	de, -669
	lea	hl, ix + 0
	add	hl, de
	ld	(hl), bc
	push	bc
	call	ti._memset
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 15)
	push	hl
	pop	iy
	ld	de, -33
	add	iy, de
	ld	de, 257
	or	a, a
	sbc	hl, de
	jq	c, .lbl_2
	ld	de, 0
	jq	.lbl_16
.lbl_2:
	ld	hl, (ix + 9)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	ld	de, 0
	jq	z, .lbl_16
	ld	hl, (ix + 6)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_16
	ld	hl, (ix + 12)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_16
	ld	bc, -186
	lea	hl, ix + 0
	add	hl, bc
	push	ix
	ld	bc, -672
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	bc, -442
	lea	hl, ix + 0
	add	hl, bc
	push	hl
	pop	de
	ld	bc, -666
	lea	hl, ix + 0
	add	hl, bc
	push	ix
	ld	bc, -678
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	bc, -675
	lea	hl, ix + 0
	add	hl, bc
	ld	(hl), iy
	ld	bc, -681
	lea	iy, ix + 0
	add	iy, bc
	ld	(iy + 0), de
	push	de
	push	ix
	ld	bc, -672
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	push	hl
	call	hashlib_Sha256Init
	pop	hl
	pop	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	hl, (ix + 9)
	push	hl
	ld	hl, (ix + 6)
	push	hl
	ld	bc, -672
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Update
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -669
	lea	hl, ix + 0
	add	hl, bc
	ld	iy, (hl)
	pea	iy + 8
	ld	bc, -672
	lea	iy, ix + 0
	add	iy, bc
	ld	hl, (iy + 0)
	push	hl
	call	hashlib_Sha256Final
	ld	bc, (ix + 18)
	pop	hl
	pop	hl
	ld	de, -669
	lea	hl, ix + 0
	add	hl, de
	ld	iy, (hl)
	lea	de, iy + 40
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_10
	ld	hl, 32
	push	hl
	push	de
	call	hashlib_RandomBytes
	jq	.lbl_11
.lbl_10:
	ld	hl, 32
	push	hl
	push	bc
	push	de
	call	ti._memcpy
	pop	hl
.lbl_11:
	pop	hl
	pop	hl
	ld	hl, (ix + 15)
	push	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	hl, (ix + 12)
	push	hl
	call	ti._memset
	pop	hl
	pop	hl
	pop	hl
	ld	bc, (ix + 15)
	push	bc
	pop	hl
	ld	de, -66
	add	hl, de
	ex	de, hl
	ld	iy, (ix + 12)
	lea	hl, iy + 0
	add	hl, de
	ld	(hl), 1
	push	bc
	pop	hl
	ld	de, -65
	add	hl, de
	ex	de, hl
	lea	hl, iy + 0
	add	hl, de
	ld	de, 32
	push	de
	ld	bc, -669
	lea	iy, ix + 0
	add	iy, bc
	ld	iy, (iy + 0)
	pea	iy + 40
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -681
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -672
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Init
	pop	hl
	pop	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	hl, 72
	push	hl
	ld	bc, -669
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -672
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Update
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 12)
	ld	bc, -675
	lea	iy, ix + 0
	add	iy, bc
	ld	de, (iy + 0)
	add	hl, de
	push	ix
	ld	bc, -669
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	push	hl
	ld	bc, -672
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Final
	pop	hl
	pop	hl
	ld	de, (ix + 15)
	dec	de
	ld	hl, (ix + 12)
	add	hl, de
	ld	(hl), -68
	ld	bc, -675
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -678
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	hl, 32
	push	hl
	ld	bc, -669
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_MGF1Hash
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	iy, (ix + 15)
	ld	de, -33
	add	iy, de
	ld	de, 0
.lbl_13:
	lea	hl, iy + 0
	or	a, a
	sbc	hl, de
	jq	z, .lbl_15
	ld	bc, -678
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	add	hl, de
	lea	bc, iy + 0
	ld	iy, (ix + 12)
	add	iy, de
	ld	a, (iy)
	xor	a, (hl)
	ld	(iy), a
	push	bc
	pop	iy
	inc	de
	jq	.lbl_13
.lbl_15:
	ld	de, (ix + 15)
.lbl_16:
	ex	de, hl
	jp stack_clear

 hashlib_CompareDigest:
    pop	iy, de, hl, bc
	push	bc, hl, de, iy
	xor	a, a
.loop:
	ld	iyl, a
	ld	a, (de)
	inc	de
	xor	a, (hl)
	or	a, iyl
	cpi
	jq	pe, .loop
	add	a, -1
	sbc	a, a
	inc	a
	ret
	
hashlib_MGF1Hash:
	ld	hl, -539
	call	ti._frameset
	ld	bc, -298
	lea	iy, ix + 0
	add	iy, bc
	ld	bc, -514
	lea	hl, ix + 0
	add	hl, bc
	push	hl
	pop	de
	lea	hl, iy + 4
	lea	bc, iy + 0
	ld	(ix + -3), bc
	ld	bc, -526
	lea	iy, ix + 0
	add	iy, bc
	ld	(iy + 0), hl
	push	de
	pop	iy
	lea	de, iy + 108
	ld	bc, -529
	lea	hl, ix + 0
	add	hl, bc
	ld	(hl), de
	lea	hl, iy + 0
	ld	bc, -520
	lea	iy, ix + 0
	add	iy, bc
	ld	(iy + 0), hl
	ld	bc, (ix + -3)
	push	bc
	pop	iy
	ld	bc, -523
	lea	hl, ix + 0
	add	hl, bc
	ld	(hl), iy
	pea	iy + 36
	push	de
	call	hashlib_Sha256Init
	pop	hl
	pop	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	hl, (ix + 9)
	push	hl
	ld	hl, (ix + 6)
	push	hl
	ld	bc, -529
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Update
	ld	de, (ix + 15)
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	push	de
	pop	iy
	xor	a, a
	or	a, a
	sbc	hl, hl
	push	ix
	ld	bc, -517
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	ld	bc, 0
.lbl1:
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	jq	nc, .lbl2
	ld	de, -532
	lea	hl, ix + 0
	add	hl, de
	ld	(hl), bc
	lea	hl, iy + 0
	ld	de, 32
	or	a, a
	sbc	hl, de
	ld	bc, -536
	lea	hl, ix + 0
	push	af
	add	hl, bc
	pop	af
	ld	(hl), iy
	ld	hl, 32
	jq	c, .lbl5
	push	hl
	pop	iy
.lbl5:
	ld	bc, -539
	lea	hl, ix + 0
	add	hl, bc
	ld	(hl), iy
	ld	bc, -517
	lea	iy, ix + 0
	add	iy, bc
	ld	de, (iy + 0)
	push	de
	pop	bc
	ld	(ix + -3), de
	push	ix
	ld	de, -533
	add	ix, de
	ld	(ix + 0), a
	pop	ix
	ld	l, 24
	call	ti._lshru
	ld	a, c
	push	ix
	ld	bc, -523
	add	ix, bc
	ld	iy, (ix + 0)
	pop	ix
	ld	(iy + 0), a
	ld	de, (ix + -3)
	push	de
	pop	bc
	ld	(ix + -3), de
	push	ix
	ld	de, -533
	add	ix, de
	ld	a, (ix + 0)
	pop	ix
	ld	l, 16
	call	ti._lshru
	ld	a, c
	ld	(iy + 1), a
	ld	de, (ix + -3)
	push	ix
	ld	bc, -517
	add	ix, bc
	ld	(ix + 0), de
	pop	ix
	ld	a, d
	ld	(iy + 2), a
	ld	a, e
	ld	(iy + 3), a
	ld	hl, 108
	push	hl
	ld	bc, -529
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -520
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	hl, 4
	push	hl
	ld	bc, -523
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -520
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Update
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -526
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -520
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Final
	pop	hl
	pop	hl
	ld	bc, -532
	lea	hl, ix + 0
	add	hl, bc
	ld	de, (hl)
	ld	hl, (ix + 12)
	add	hl, de
	ld	bc, -539
	lea	iy, ix + 0
	add	iy, bc
	ld	de, (iy + 0)
	push	de
	push	ix
	ld	bc, -526
	add	ix, bc
	ld	de, (ix + 0)
	pop	ix
	push	de
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	de, 32
	ld	bc, -532
	lea	hl, ix + 0
	add	hl, bc
	ld	iy, (hl)
	add	iy, de
	push	ix
	ld	bc, -517
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	push	ix
	ld	bc, -533
	add	ix, bc
	ld	e, (ix + 0)
	pop	ix
	ld	bc, 1
	xor	a, a
	call	ti._ladd
	ld	(ix + -3), de
	push	ix
	ld	de, -517
	add	ix, de
	ld	(ix + 0), hl
	pop	ix
	lea	bc, iy + 0
	ld	de, (ix + -3)
	ld	a, e
	ld	de, -32
	ld	(ix + -3), bc
	ld	bc, -536
	lea	iy, ix + 0
	add	iy, bc
	ld	iy, (iy + 0)
	add	iy, de
	ld	de, (ix + 15)
	ld	bc, (ix + -3)
	jq	.lbl1
.lbl2:
	jp stack_clear
	
hashlib_ReverseEndianness:
	ld	hl, -6
	call	ti._frameset
	ld	hl, (ix + 6)
	ld	de, (ix + 9)
	ld	(ix + -6), hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	ld	iyl, 1
	ld	iyh, 0
	ld	a, iyl
	jq	z, .lbl_2
	ld	a, iyh
.lbl_2:
	ld	bc, (ix + 12)
	push	de
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	ex	de, hl
	ld	e, iyl
	ex	de, hl
	jq	z, .lbl_4
	ex	de, hl
	ld	e, iyh
	ex	de, hl
.lbl_4:
	ld	(ix + -3), de
	or	a, l
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_6
	ld	iyl, iyh
.lbl_6:
	ld	e, 1
	or	a, iyl
	bit	0, a
	jq	z, .lbl_7
.lbl_10:
	xor	a, e
	ld	sp, ix
	pop	ix
	ret
.lbl_7:
	ld	hl, (ix + -3)
	dec	hl
	ld	(ix + -3), hl
.lbl_8:
	push	bc
	pop	hl
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_10
	ld	iy, (ix + -6)
	ld	d, (iy)
	ld	hl, (ix + -3)
	add	hl, bc
	ld	(hl), d
	dec	bc
	inc	iy
	ld	(ix + -6), iy
	jq	.lbl_8
 
	
hashlib_RSAEncrypt:
	ld	hl, -6
	call	ti._frameset
	ld	hl, (ix + 12)
	ld	iyl, 0
	ld	de, 1
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_1
	jq	.lbl_12
.lbl_1:
	ld	hl, (ix + 6)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_2
	jq	.lbl_12
.lbl_2:
	ld	hl, (ix + 15)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_12
	ld	hl, (ix + 18)
	ld	de, 3
	ld	bc, -128
	add	hl, bc
	ld	bc, 129
	or	a, a
	sbc	hl, bc
	jq	c, .lbl_4
	jq	.lbl_12
.lbl_4:
	ld	bc, (ix + 18)
	dec	bc
	ld	hl, (ix + 15)
	add	hl, bc
	ld	a, (hl)
	and	a, 1
	ld	l, 1
	xor	a, l
	bit	0, a
	jq	nz, .lbl_12
	ld	de, 2
.lbl_6:
	ld	bc, 0
	ld	c, iyl
	ld	hl, (ix + 15)
	add	hl, bc
	ld	a, (hl)
	or	a, a
	jq	nz, .lbl_8
	inc	iyl
	ld	hl, (ix + 12)
	add	hl, bc
	ld	(hl), 0
	jq	.lbl_6
.lbl_8:
	ld	iy, (ix + 9)
	lea	hl, iy + 0
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_9
	jq	.lbl_12
.lbl_9:
	push	bc
	pop	iy
	ld	bc, 66
	add	hl, bc
	lea	bc, iy + 0
	push	hl
	pop	iy
	ld	hl, (ix + 18)
	ld	(ix + -3), bc
	or	a, a
	sbc	hl, bc
	ld	(ix + -6), hl
	lea	bc, iy + 0
	or	a, a
	sbc	hl, bc
	jq	c, .lbl_12
	ld	hl, (ix + 12)
	ld	de, (ix + -3)
	add	hl, de
	ld	de, 0
	push	de
	ld	de, (ix + -6)
	push	de
	push	hl
	ld	hl, (ix + 9)
	push	hl
	ld	hl, (ix + 6)
	push	hl
	call	hashlib_RSAEncodeOAEP
	pop	de
	pop	de
	pop	de
	pop	de
	pop	de
	add	hl, bc
	or	a, a
	sbc	hl, bc
	ld	de, 4
	jq	z, .lbl_12
	ld	hl, (ix + 15)
	push	hl
	ld	hl, 65537
	push	hl
	ld	hl, (ix + 12)
	push	hl
	ld	hl, (ix + 18)
	push	hl
	call	_powmod
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	de, 0
.lbl_12:
	ex	de, hl
	jp stack_clear
 
 hashlib_RSAVerifyPSS:
	ld	hl, -529
	call	ti._frameset
	ld	de, -517
	lea	iy, ix + 0
	add	iy, de
	ld	bc, (ix + 15)
	ld	de, -229
	lea	hl, ix + 0
	add	hl, de
	push	ix
	ld	de, -526
	add	ix, de
	ld	(ix + 0), hl
	pop	ix
	lea	de, iy + 32
	ld	(ix + -3), bc
	ld	bc, -520
	lea	hl, ix + 0
	add	hl, bc
	ld	(hl), de
	lea	hl, iy + 0
	ld	bc, -523
	lea	iy, ix + 0
	add	iy, bc
	ld	(iy + 0), hl
	ld	bc, (ix + -3)
	push	bc
	pop	hl
	push	bc
	pop	iy
	ld	bc, -33
	add	hl, bc
	push	ix
	ld	bc, -529
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	push	iy
	ld	hl, (ix + 12)
	push	hl
	push	de
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -520
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	ld	bc, -529
	lea	iy, ix + 0
	add	iy, bc
	ld	de, (iy + 0)
	add	hl, de
	push	de
	push	ix
	ld	bc, -526
	add	ix, bc
	ld	de, (ix + 0)
	pop	ix
	push	de
	ld	de, 32
	push	de
	push	hl
	call	hashlib_MGF1Hash
	ld	de, -529
	lea	hl, ix + 0
	add	hl, de
	ld	bc, (hl)
	ld	de, 0
	pop	hl
	pop	hl
	pop	hl
	pop	hl
.lbl_1:
	push	bc
	pop	hl
	or	a, a
	sbc	hl, de
	jq	z, .lbl_2
	ld	(ix + -3), bc
	ld	bc, -526
	lea	hl, ix + 0
	add	hl, bc
	ld	iy, (hl)
	add	iy, de
	push	ix
	ld	bc, -520
	add	ix, bc
	ld	hl, (ix + 0)
	pop	ix
	add	hl, de
	ld	a, (hl)
	xor	a, (iy)
	ld	(hl), a
	inc	de
	ld	bc, (ix + -3)
	jq	.lbl_1
.lbl_2:
	ld	hl, (ix + 15)
	ld	de, -65
	add	hl, de
	ex	de, hl
	ld	bc, -520
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	add	hl, de
	ld	de, 32
	push	de
	push	hl
	ld	bc, -523
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -523
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	hl, (ix + 15)
	push	hl
	ld	bc, -520
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	hl, (ix + 9)
	push	hl
	ld	hl, (ix + 6)
	push	hl
	call	hashlib_RSAEncodePSS
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 15)
	push	hl
	ld	hl, (ix + 12)
	push	hl
	ld	bc, -520
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_CompareDigest
	jp stack_clear
	
hashlib_SSLVerifySignature:
	ld	hl, -670
	call	ti._frameset
	ld	hl, (ix + 6)
	ld	e, 0
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_6
	ld	hl, (ix + 12)
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_7
	ld	hl, (ix + 9)
	ld	bc, (ix + 15)
	or	a, a
	sbc	hl, bc
	jq	nc, .lbl_8
	ld	a, (ix + 18)
	or	a, a
	jq	nz, .lbl_5
	ld	de, -402
	lea	iy, ix + 0
	add	iy, de
	push	bc
	pop	de
	ld	(ix + -3), de
	ld	de, -262
	lea	hl, ix + 0
	add	hl, de
	push	hl
	pop	bc
	push	ix
	ld	de, -667
	add	ix, de
	ld	(ix + 0), bc
	pop	ix
	lea	hl, iy + 108
	push	ix
	ld	de, -664
	add	ix, de
	ld	(ix + 0), hl
	pop	ix
	lea	hl, iy + 0
	ld	de, -661
	lea	iy, ix + 0
	add	iy, de
	ld	(iy + 0), hl
	ld	de, (ix + -3)
	ex	de, hl
	ld	de, (ix + 9)
	or	a, a
	sbc	hl, de
	push	de
	pop	iy
	push	ix
	ld	de, -670
	add	ix, de
	ld	(ix + 0), hl
	pop	ix
	ex	de, hl
	dec	de
	ld	hl, (ix + 12)
	add	hl, de
	push	iy
	push	hl
	push	bc
	call	ti._memcpy
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 6)
	push	hl
	ld	hl, 65537
	push	hl
	ld	bc, -667
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	hl, (ix + 9)
	push	hl
	call	_powmod
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -658
	lea	hl, ix + 0
	add	hl, bc
	push	hl
	ld	bc, -661
	lea	iy, ix + 0
	add	iy, bc
	ld	hl, (iy + 0)
	push	hl
	call	hashlib_Sha256Init
	pop	hl
	pop	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	bc, -670
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	hl, (ix + 12)
	push	hl
	ld	bc, -661
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Update
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -664
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -661
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Final
	pop	hl
	pop	hl
	ld	hl, (ix + 9)
	push	hl
	ld	bc, -667
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	hl, 32
	push	hl
	ld	bc, -664
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_RSAVerifyPSS
	ld	e, a
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	jq	.lbl_5
.lbl_6:
	jq	.lbl_5
.lbl_7:
	jq	.lbl_5
.lbl_8:
.lbl_5:
	ld	a, e
	jp stack_clear
 
;void powmod(uint8_t size, uint8_t *restrict base, uint24_t exp, const uint8_t *restrict mod);
_powmod:
   push   ix
   ld   ix, 0
   lea   bc, ix
   add   ix, sp
.ret  := ix    + long
.size := .ret  + long
.base := .size + long
.exp  := .base + long
.mod  := .exp  + long
.acc  := ix    - long
.tmp  := .acc  - long
.end  := .tmp  - byte
   ld   c, (.size)
   dec   c
   ld   hl, .end - ix
   add   hl, sp
   push   hl
;   scf
   sbc   hl, bc
   push   hl
;   or   a, a
   sbc   hl, bc
   ld   sp, hl
   ld   hl, (.mod)
   add   hl, bc
   ld   (.mod), hl
   ld   b, bsr 8
   ld   e, b
;   ld   e, 1
.nmi.loop:
   ld   a, e
   ld   d, (hl)
   mlt   de
   inc   de
   inc   de
   ld   d, a
   mlt   de
   djnz   .nmi.loop ; leaks size
   ld   a, e
   ld   (.nmi), a
   ld   hl, (.base)
   add   hl, bc
   ld   (.base), hl
   ld   c, 8
.mod.outer:
   ld   b, (.size)
.mod.inner:
   push   bc, hl
   ld   b, (.size)
;   or   a, a
.shift:
   rl   (hl)
   dec   hl
   djnz   .shift ; leaks size
   pop   hl
   push   hl
   call   .reduce
   pop   hl, bc
   djnz   .mod.inner ; leaks size
   dec   c
   jq   nz, .mod.outer ; leaks constant
   ld   c, (.size)
   dec   c
   inc   bc
   ld   de, (.acc)
   lddr ; leaks size
   ld   hl, (.exp)
   scf
.normalize:
   adc   hl, hl
   jq   nc, .normalize ; leaks exp
   xor   a, a
.loop:
   push   hl, af
   ld   hl, (.acc)
   call   nz, .mul ; leaks exp
   pop   af
   ld   hl, (.base)
   call   c, .mul ; leaks exp
   pop   hl
;   or   a, a
   adc   hl, hl
   jq   nz, .loop ; leaks exp
   ld   de, (.tmp)
   add   hl, de
   dec   de
;   ld   bc, 0
   ld   c, (.size)
   dec   c
   ld   (hl), b
   push   hl
   lddr ; leaks size
   pop   hl
   inc   (hl)
   ld   iy, (.base)
   call   .mul.alt
   ld   sp, ix
   pop   ix
   ret
   ; vi(acc) = vi(acc) * vi(hl) % vi(mod)
   ; assumes bc = 0
   ; destroys vi(tmp)
   ; returns bc = 0, cf = 0
.mul:
   ld   iy, (.tmp)
.mul.alt:
   push   hl
   lea   hl, iy - 0
   lea   de, iy - 1
   ld   c, (.size)
   dec   c
   ld   (hl), b
   lddr ; leaks size
   ld   de, (.acc)
   ld   (.acc), iy
   ld   (.tmp), de
   pop   hl
   ld   c, (.size)
   or   a, a
.mul.outer:
   ld   a, (de)
   ld   (.cur), a
   dec   de
   push   de, hl, ix, iy, af
   ld   e, (hl)
   ld   d, a
   mlt   de
   push   hl
   ld   l, (iy)
   ld   h, 0
   add   hl, de
   ld   e, l
   ld   d, 0
.nmi := $ - byte
   mlt   de
   ld   a, e
   ld   (.adj), a
   ld   b, (.size)
   dec   b
   ld   ix, (.mod)
   ld   d, (ix)
   mlt   de
   add.s   hl, de
   ld   e, h
   ld   d, l
;   ld   d, 0
   rl   d
   pop   hl
.mul.inner:
   dec   hl
   push   hl
   ld   l, (hl)
   ld   h, 0
.cur := $ - byte
   mlt   hl
   adc   hl, de
   dec   ix
   ld   e, (ix)
   ld   d, 0
.adj := $ - byte
   mlt   de
   add.s   hl, de
   ld   e, h
   ld   d, 0
   rl   d
   ld   a, l
   dec   iy
   add   a, (iy)
   ld   (iy + 1), a
   pop   hl
   djnz   .mul.inner ; leaks size
   ld   l, b
   rl   l
   ld   h, b
   pop   af
   adc   hl, de
   ld   (iy + 0), l
   sra   h
   pop   iy, ix, hl, de
   dec   c
   jq   nz, .mul.outer ; leaks size
   lea   hl, iy
   ; if (cf:vi(hl) >= vi(mod)) cf:vi(hl) -= vi(mod)
   ; assumes bcu = 0
   ; destroys vi(tmp)
   ; returns bc = 0, cf = 0
.reduce:
   ccf
   sbc   a, a
   ld   c, a
   ld   b, (.size)
   ld   de, (.tmp)
   ld   iy, (.mod)
   or   a, a
   push   hl, de
.reduce.sub:
   ld   a, (hl)
   dec   hl
   sbc   a, (iy)
   dec   iy
   ld   (de), a
   dec   de
   djnz   .reduce.sub ; leaks size
   sbc   a, a
   and   a, c
   and   a, long
   sbc   hl, hl
   ld   l, a
   add   hl, sp
   ld   hl, (hl)
   pop   de, de
   ld   c, (.size)
   dec   c
   inc   bc
   lddr ; leaks size, assuming that base and stack are in normal ram
   ret
 
 
 hashlib_AESAuthEncrypt:
	ld	hl, -376
	call	ti._frameset
	ld	iy, (ix + 6)
	ld	de, (ix + 12)
	ld	a, (ix + 21)
	lea	hl, iy + 0
	push	de
	pop	bc
	or	a, a
	sbc	hl, bc
	jq	z, .lbl_2
	ld	hl, (ix + 9)
	push	hl
	push	iy
	push	de
	call	ti._memcpy
	ld	a, (ix + 21)
	ld	de, (ix + 12)
	pop	hl
	pop	hl
	pop	hl
.lbl_2:
	ex	de, hl
	ld	de, (ix + 24)
	add	hl, de
	ld	de, 0
	push	de
	ld	e, a
	push	de
	ld	de, (ix + 18)
	push	de
	ld	de, (ix + 15)
	push	de
	push	hl
	ld	de, (ix + 27)
	push	de
	push	hl
	call	hashlib_AESEncrypt
	ld	iy, 21
	add	iy, sp
	ld	sp, iy
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_4
	lea	de, ix + -114
	ld	bc, -373
	lea	iy, ix + 0
	add	iy, bc
	ld	(iy + 0), de
	push	ix
	ld	bc, -370
	add	ix, bc
	ex	(sp), ix
	push	de
	push	ix
	ld	bc, -376
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	call	hashlib_Sha256Init
	pop	hl
	pop	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	hl, (ix + 9)
	push	hl
	ld	hl, (ix + 12)
	push	hl
	ld	bc, -373
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Update
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 12)
	ld	de, (ix + 9)
	add	hl, de
	push	hl
	ld	bc, -373
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Final
	ld	bc, -376
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	pop	de
	pop	de
.lbl_4:
	ld	sp, ix
	pop	ix
	ret
	
hashlib_AESAuthDecrypt:
	ld	hl, -408
	call	ti._frameset
	ld	bc, -402
	lea	iy, ix + 0
	add	iy, bc
	lea	de, ix + -114
	ld	bc, -408
	lea	hl, ix + 0
	add	hl, bc
	ld	(hl), de
	lea	hl, iy + 0
	push	ix
	ld	bc, -405
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	pea	iy + 32
	push	de
	call	hashlib_Sha256Init
	pop	hl
	pop	hl
	ld	hl, (ix + 9)
	ld	de, -32
	add	hl, de
	ld	de, 0
	push	de
	push	hl
	ld	hl, (ix + 6)
	push	hl
	ld	bc, -408
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Update
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	bc, -405
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	ld	bc, -408
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Final
	pop	hl
	pop	hl
	ld	hl, (ix + 9)
	ld	de, -32
	add	hl, de
	ex	de, hl
	ld	hl, (ix + 6)
	add	hl, de
	ld	de, 32
	push	de
	ld	bc, -405
	lea	iy, ix + 0
	add	iy, bc
	ld	de, (iy + 0)
	push	de
	push	hl
	call	hashlib_CompareDigest
	pop	hl
	pop	hl
	pop	hl
	ld	l, 1
	xor	a, l
	bit	0, a
	jq	nz, .lbl_1
	ld	de, (ix + 12)
	ld	a, (ix + 21)
	ld	bc, (ix + 24)
	ld	hl, (ix + 6)
	push	hl
	pop	iy
	or	a, a
	sbc	hl, de
	push	bc
	pop	de
	jq	z, .lbl_4
	ld	de, 0
.lbl_4:
	add	iy, bc
	lea	bc, iy + 0
	ld	iy, (ix + 12)
	add	iy, de
	or	a, a
	sbc	hl, hl
	push	hl
	ld	l, a
	push	hl
	ld	hl, (ix + 18)
	push	hl
	ld	hl, (ix + 15)
	push	hl
	push	iy
	ld	hl, (ix + 27)
	push	hl
	push	bc
	call	hashlib_AESDecrypt
	ld	iy, 21
	add	iy, sp
	ld	sp, iy
	jq	.lbl_5
.lbl_1:
	ld	hl, 5
.lbl_5:
	ld	sp, ix
	pop	ix
	ret
 
 hashlib_RSAAuthEncrypt:
	ld	hl, -376
	call	ti._frameset
	ld	iy, (ix + 9)
	ld	de, (ix + 12)
	ld	bc, (ix + 15)
	ld	hl, (ix + 18)
	push	hl
	push	bc
	push	de
	push	iy
	ld	hl, (ix + 6)
	push	hl
	call	hashlib_RSAEncrypt
	pop	de
	pop	de
	pop	de
	pop	de
	pop	de
	add	hl, bc
	or	a, a
	sbc	hl, bc
	jq	nz, .lbl_2
	lea	de, ix + -114
	ld	bc, -373
	lea	iy, ix + 0
	add	iy, bc
	ld	(iy + 0), de
	push	ix
	ld	bc, -370
	add	ix, bc
	ex	(sp), ix
	push	de
	push	ix
	ld	bc, -376
	add	ix, bc
	ld	(ix + 0), hl
	pop	ix
	call	hashlib_Sha256Init
	pop	hl
	pop	hl
	or	a, a
	sbc	hl, hl
	push	hl
	ld	hl, (ix + 18)
	push	hl
	ld	hl, (ix + 12)
	push	hl
	ld	bc, -373
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Update
	pop	hl
	pop	hl
	pop	hl
	pop	hl
	ld	hl, (ix + 12)
	ld	de, (ix + 18)
	add	hl, de
	push	hl
	ld	bc, -373
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	push	hl
	call	hashlib_Sha256Final
	ld	bc, -376
	lea	hl, ix + 0
	add	hl, bc
	ld	hl, (hl)
	pop	de
	pop	de
.lbl_2:
	ld	sp, ix
	pop	ix
	ret
 
 
 
_sprng_read_addr:		rb 3
_sprng_entropy_pool		:=	$E30800
_sprng_rand				:=	_sprng_entropy_pool + 119
_sprng_sha_digest		:=	_sprng_rand + 4
_sprng_sha_mbuffer		:=	_sprng_sha_digest + 32
_sprng_sha_ctx			:=	_sprng_sha_mbuffer + (64*4)




 _aes_sbox:
	db	"c|w{",362o,"ko",305o,"0",001o,"g+",376o,327o,253o,"v"
	db	"",312o,202o,311o,"}",372o,"YG",360o,255o,324o,242o,257o,234o,244o,"r",300o
	db	"",267o,375o,223o,"&6?",367o,314o,"4",245o,345o,361o,"q",330o,"1",025o
	db	"",004o,307o,"#",303o,030o,226o,005o,232o,007o,022o,200o,342o,353o,"'",262o,"u"
	db	"",011o,203o,",",032o,033o,"nZ",240o,"R;",326o,263o,")",343o,"/",204o
	db	"S",321o,000o,355o," ",374o,261o,"[j",313o,276o,"9JLX",317o
	db	"",320o,357o,252o,373o,"CM3",205o,"E",371o,002o,177o,"P<",237o,250o
	db	"Q",243o,"@",217o,222o,235o,"8",365o,274o,266o,332o,"!",020o,377o,363o,322o
	db	"",315o,014o,023o,354o,"_",227o,"D",027o,304o,247o,"~=d]",031o,"s"
	db	"`",201o,"O",334o,"""*",220o,210o,"F",356o,270o,024o,336o,"^",013o,333o
	db	"",340o,"2:",012o,"I",006o,"$\",302o,323o,254o,"b",221o,225o,344o,"y"
	db	"",347o,310o,"7m",215o,325o,"N",251o,"lV",364o,352o,"ez",256o,010o
	db	"",272o,"x%.",034o,246o,264o,306o,350o,335o,"t",037o,"K",275o,213o,212o
	db	"p>",265o,"fH",003o,366o,016o,"a5W",271o,206o,301o,035o,236o
	db	"",341o,370o,230o,021o,"i",331o,216o,224o,233o,036o,207o,351o,316o,"U(",337o
	db	"",214o,241o,211o,015o,277o,346o,"BhA",231o,"-",017o,260o,"T",273o,026o
 
 L___const.hashlib_AESLoadKey.Rcon:
	dd	16777216
	dd	33554432
	dd	67108864
	dd	134217728
	dd	268435456
	dd	536870912
	dd	1073741824
	dd	2147483648
	dd	452984832
	dd	905969664
	dd	1811939328
	dd	3623878656
	dd	2868903936
	dd	1291845632
	dd	2583691264
 
 _aes_invsbox:
	db	"R",011o,"j",325o,"06",245o,"8",277o,"@",243o,236o,201o,363o,327o,373o
	db	"|",343o,"9",202o,233o,"/",377o,207o,"4",216o,"CD",304o,336o,351o,313o
	db	"T{",224o,"2",246o,302o,"#=",356o,"L",225o,013o,"B",372o,303o,"N"
	db	"",010o,".",241o,"f(",331o,"$",262o,"v[",242o,"Im",213o,321o,"%"
	db	"r",370o,366o,"d",206o,"h",230o,026o,324o,244o,"\",314o,"]e",266o,222o
	db	"lpHP",375o,355o,271o,332o,"^",025o,"FW",247o,215o,235o,204o
	db	"",220o,330o,253o,000o,214o,274o,323o,012o,367o,344o,"X",005o,270o,263o,"E",006o
	db	"",320o,",",036o,217o,312o,"?",017o,002o,301o,257o,275o,003o,001o,023o,212o,"k"
	db	":",221o,021o,"AOg",334o,352o,227o,362o,317o,316o,360o,264o,346o,"s"
	db	"",226o,254o,"t""",347o,255o,"5",205o,342o,371o,"7",350o,034o,"u",337o,"n"
	db	"G",361o,032o,"q",035o,")",305o,211o,"o",267o,"b",016o,252o,030o,276o,033o
	db	"",374o,"V>K",306o,322o,"y ",232o,333o,300o,376o,"x",315o,"Z",364o
	db	"",037o,335o,250o,"3",210o,007o,307o,"1",261o,022o,020o,"Y'",200o,354o,"_"
	db	"`Q",177o,251o,031o,265o,"J",015o,"-",345o,"z",237o,223o,311o,234o,357o
	db	"",240o,340o,";M",256o,"*",365o,260o,310o,353o,273o,"<",203o,"S",231o,"a"
	db	"",027o,"+",004o,"~",272o,"w",326o,"&",341o,"i",024o,"cU!",014o,"}"
 
 _gf_mul:
	db	6 dup 0
	db	"",002o,003o,011o,013o,015o,016o
	db	"",004o,006o,022o,026o,032o,034o
	db	"",006o,005o,033o,035o,027o,022o
	db	"",010o,014o,"$,48"
	db	"",012o,017o,"-'96"
	db	"",014o,012o,"6:.$"
	db	"",016o,011o,"?1#*"
	db	"",020o,030o,"HXhp"
	db	"",022o,033o,"ASe~"
	db	"",024o,036o,"ZNrl"
	db	"",026o,035o,"SE",177o,"b"
	db	"",030o,024o,"lt\H"
	db	"",032o,027o,"e",177o,"QF"
	db	"",034o,022o,"~bFT"
	db	"",036o,021o,"wiKZ"
	db	" 0",220o,260o,320o,340o
	db	"""3",231o,273o,335o,356o
	db	"$6",202o,246o,312o,374o
	db	"&5",213o,255o,307o,362o
	db	"(<",264o,234o,344o,330o
	db	"*?",275o,227o,351o,326o
	db	",:",246o,212o,376o,304o
	db	".9",257o,201o,363o,312o
	db	"0(",330o,350o,270o,220o
	db	"2+",321o,343o,265o,236o
	db	"4.",312o,376o,242o,214o
	db	"6-",303o,365o,257o,202o
	db	"8$",374o,304o,214o,250o
	db	":'",365o,317o,201o,246o
	db	"<""",356o,322o,226o,264o
	db	">!",347o,331o,233o,272o
	db	"@`;{",273o,333o
	db	"Bc2p",266o,325o
	db	"Df)m",241o,307o
	db	"Fe f",254o,311o
	db	"Hl",037o,"W",217o,343o
	db	"Jo",026o,"\",202o,355o
	db	"Lj",015o,"A",225o,377o
	db	"Ni",004o,"J",230o,361o
	db	"Pxs#",323o,253o
	db	"R{z(",336o,245o
	db	"T~a5",311o,267o
	db	"V}h>",304o,271o
	db	"XtW",017o,347o,223o
	db	"Zw^",004o,352o,235o
	db	"\rE",031o,375o,217o
	db	"^qL",022o,360o,201o
	db	"`P",253o,313o,"k;"
	db	"bS",242o,300o,"f5"
	db	"dV",271o,335o,"q'"
	db	"fU",260o,326o,"|)"
	db	"h\",217o,347o,"_",003o
	db	"j_",206o,354o,"R",015o
	db	"lZ",235o,361o,"E",037o
	db	"nY",224o,372o,"H",021o
	db	"pH",343o,223o,003o,"K"
	db	"rK",352o,230o,016o,"E"
	db	"tN",361o,205o,031o,"W"
	db	"vM",370o,216o,024o,"Y"
	db	"xD",307o,277o,"7s"
	db	"zG",316o,264o,":}"
	db	"|B",325o,251o,"-o"
	db	"~A",334o,242o," a"
	db	"",200o,300o,"v",366o,"m",255o
	db	"",202o,303o,177o,375o,"`",243o
	db	"",204o,306o,"d",340o,"w",261o
	db	"",206o,305o,"m",353o,"z",277o
	db	"",210o,314o,"R",332o,"Y",225o
	db	"",212o,317o,"[",321o,"T",233o
	db	"",214o,312o,"@",314o,"C",211o
	db	"",216o,311o,"I",307o,"N",207o
	db	"",220o,330o,">",256o,005o,335o
	db	"",222o,333o,"7",245o,010o,323o
	db	"",224o,336o,",",270o,037o,301o
	db	"",226o,335o,"%",263o,022o,317o
	db	"",230o,324o,032o,202o,"1",345o
	db	"",232o,327o,023o,211o,"<",353o
	db	"",234o,322o,010o,224o,"+",371o
	db	"",236o,321o,001o,237o,"&",367o
	db	"",240o,360o,346o,"F",275o,"M"
	db	"",242o,363o,357o,"M",260o,"C"
	db	"",244o,366o,364o,"P",247o,"Q"
	db	"",246o,365o,375o,"[",252o,"_"
	db	"",250o,374o,302o,"j",211o,"u"
	db	"",252o,377o,313o,"a",204o,"{"
	db	"",254o,372o,320o,"|",223o,"i"
	db	"",256o,371o,331o,"w",236o,"g"
	db	"",260o,350o,256o,036o,325o,"="
	db	"",262o,353o,247o,025o,330o,"3"
	db	"",264o,356o,274o,010o,317o,"!"
	db	"",266o,355o,265o,003o,302o,"/"
	db	"",270o,344o,212o,"2",341o,005o
	db	"",272o,347o,203o,"9",354o,013o
	db	"",274o,342o,230o,"$",373o,031o
	db	"",276o,341o,221o,"/",366o,027o
	db	"",300o,240o,"M",215o,326o,"v"
	db	"",302o,243o,"D",206o,333o,"x"
	db	"",304o,246o,"_",233o,314o,"j"
	db	"",306o,245o,"V",220o,301o,"d"
	db	"",310o,254o,"i",241o,342o,"N"
	db	"",312o,257o,"`",252o,357o,"@"
	db	"",314o,252o,"{",267o,370o,"R"
	db	"",316o,251o,"r",274o,365o,"\"
	db	"",320o,270o,005o,325o,276o,006o
	db	"",322o,273o,014o,336o,263o,010o
	db	"",324o,276o,027o,303o,244o,032o
	db	"",326o,275o,036o,310o,251o,024o
	db	"",330o,264o,"!",371o,212o,">"
	db	"",332o,267o,"(",362o,207o,"0"
	db	"",334o,262o,"3",357o,220o,""""
	db	"",336o,261o,":",344o,235o,","
	db	"",340o,220o,335o,"=",006o,226o
	db	"",342o,223o,324o,"6",013o,230o
	db	"",344o,226o,317o,"+",034o,212o
	db	"",346o,225o,306o," ",021o,204o
	db	"",350o,234o,371o,021o,"2",256o
	db	"",352o,237o,360o,032o,"?",240o
	db	"",354o,232o,353o,007o,"(",262o
	db	"",356o,231o,342o,014o,"%",274o
	db	"",360o,210o,225o,"en",346o
	db	"",362o,213o,234o,"nc",350o
	db	"",364o,216o,207o,"st",372o
	db	"",366o,215o,216o,"xy",364o
	db	"",370o,204o,261o,"IZ",336o
	db	"",372o,207o,270o,"BW",320o
	db	"",374o,202o,243o,"_@",302o
	db	"",376o,201o,252o,"TM",314o
	db	"",033o,233o,354o,367o,332o,"A"
	db	"",031o,230o,345o,374o,327o,"O"
	db	"",037o,235o,376o,341o,300o,"]"
	db	"",035o,236o,367o,352o,315o,"S"
	db	"",023o,227o,310o,333o,356o,"y"
	db	"",021o,224o,301o,320o,343o,"w"
	db	"",027o,221o,332o,315o,364o,"e"
	db	"",025o,222o,323o,306o,371o,"k"
	db	"",013o,203o,244o,257o,262o,"1"
	db	"",011o,200o,255o,244o,277o,"?"
	db	"",017o,205o,266o,271o,250o,"-"
	db	"",015o,206o,277o,262o,245o,"#"
	db	"",003o,217o,200o,203o,206o,011o
	db	"",001o,214o,211o,210o,213o,007o
	db	"",007o,211o,222o,225o,234o,025o
	db	"",005o,212o,233o,236o,221o,033o
	db	";",253o,"|G",012o,241o
	db	"9",250o,"uL",007o,257o
	db	"?",255o,"nQ",020o,275o
	db	"=",256o,"gZ",035o,263o
	db	"3",247o,"Xk>",231o
	db	"1",244o,"Q`3",227o
	db	"7",241o,"J}$",205o
	db	"5",242o,"Cv)",213o
	db	"+",263o,"4",037o,"b",321o
	db	")",260o,"=",024o,"o",337o
	db	"/",265o,"&",011o,"x",315o
	db	"-",266o,"/",002o,"u",303o
	db	"#",277o,020o,"3V",351o
	db	"!",274o,031o,"8[",347o
	db	"'",271o,002o,"%L",365o
	db	"%",272o,013o,".A",373o
	db	"[",373o,327o,214o,"a",232o
	db	"Y",370o,336o,207o,"l",224o
	db	"_",375o,305o,232o,"{",206o
	db	"]",376o,314o,221o,"v",210o
	db	"S",367o,363o,240o,"U",242o
	db	"Q",364o,372o,253o,"X",254o
	db	"W",361o,341o,266o,"O",276o
	db	"U",362o,350o,275o,"B",260o
	db	"K",343o,237o,324o,011o,352o
	db	"I",340o,226o,337o,004o,344o
	db	"O",345o,215o,302o,023o,366o
	db	"M",346o,204o,311o,036o,370o
	db	"C",357o,273o,370o,"=",322o
	db	"A",354o,262o,363o,"0",334o
	db	"G",351o,251o,356o,"'",316o
	db	"E",352o,240o,345o,"*",300o
	db	"{",313o,"G<",261o,"z"
	db	"y",310o,"N7",274o,"t"
	db	"",177o,315o,"U*",253o,"f"
	db	"}",316o,"\!",246o,"h"
	db	"s",307o,"c",020o,205o,"B"
	db	"q",304o,"j",033o,210o,"L"
	db	"w",301o,"q",006o,237o,"^"
	db	"u",302o,"x",015o,222o,"P"
	db	"k",323o,017o,"d",331o,012o
	db	"i",320o,006o,"o",324o,004o
	db	"o",325o,035o,"r",303o,026o
	db	"m",326o,024o,"y",316o,030o
	db	"c",337o,"+H",355o,"2"
	db	"a",334o,"""C",340o,"<"
	db	"g",331o,"9^",367o,"."
	db	"e",332o,"0U",372o," "
	db	"",233o,"[",232o,001o,267o,354o
	db	"",231o,"X",223o,012o,272o,342o
	db	"",237o,"]",210o,027o,255o,360o
	db	"",235o,"^",201o,034o,240o,376o
	db	"",223o,"W",276o,"-",203o,324o
	db	"",221o,"T",267o,"&",216o,332o
	db	"",227o,"Q",254o,";",231o,310o
	db	"",225o,"R",245o,"0",224o,306o
	db	"",213o,"C",322o,"Y",337o,234o
	db	"",211o,"@",333o,"R",322o,222o
	db	"",217o,"E",300o,"O",305o,200o
	db	"",215o,"F",311o,"D",310o,216o
	db	"",203o,"O",366o,"u",353o,244o
	db	"",201o,"L",377o,"~",346o,252o
	db	"",207o,"I",344o,"c",361o,270o
	db	"",205o,"J",355o,"h",374o,266o
	db	"",273o,"k",012o,261o,"g",014o
	db	"",271o,"h",003o,272o,"j",002o
	db	"",277o,"m",030o,247o,"}",020o
	db	"",275o,"n",021o,254o,"p",036o
	db	"",263o,"g.",235o,"S4"
	db	"",261o,"d'",226o,"^:"
	db	"",267o,"a<",213o,"I("
	db	"",265o,"b5",200o,"D&"
	db	"",253o,"sB",351o,017o,"|"
	db	"",251o,"pK",342o,002o,"r"
	db	"",257o,"uP",377o,025o,"`"
	db	"",255o,"vY",364o,030o,"n"
	db	"",243o,177o,"f",305o,";D"
	db	"",241o,"|o",316o,"6J"
	db	"",247o,"yt",323o,"!X"
	db	"",245o,"z}",330o,",V"
	db	"",333o,";",241o,"z",014o,"7"
	db	"",331o,"8",250o,"q",001o,"9"
	db	"",337o,"=",263o,"l",026o,"+"
	db	"",335o,">",272o,"g",033o,"%"
	db	"",323o,"7",205o,"V8",017o
	db	"",321o,"4",214o,"]5",001o
	db	"",327o,"1",227o,"@""",023o
	db	"",325o,"2",236o,"K/",035o
	db	"",313o,"#",351o,"""dG"
	db	"",311o," ",340o,")iI"
	db	"",317o,"%",373o,"4~["
	db	"",315o,"&",362o,"?sU"
	db	"",303o,"/",315o,016o,"P",177o
	db	"",301o,",",304o,005o,"]q"
	db	"",307o,")",337o,030o,"Jc"
	db	"",305o,"*",326o,023o,"Gm"
	db	"",373o,013o,"1",312o,334o,327o
	db	"",371o,010o,"8",301o,321o,331o
	db	"",377o,015o,"#",334o,306o,313o
	db	"",375o,016o,"*",327o,313o,305o
	db	"",363o,007o,025o,346o,350o,357o
	db	"",361o,004o,034o,355o,345o,341o
	db	"",367o,001o,007o,360o,362o,363o
	db	"",365o,002o,016o,373o,377o,375o
	db	"",353o,023o,"y",222o,264o,247o
	db	"",351o,020o,"p",231o,271o,251o
	db	"",357o,025o,"k",204o,256o,273o
	db	"",355o,026o,"b",217o,243o,265o
	db	"",343o,037o,"]",276o,200o,237o
	db	"",341o,034o,"T",265o,215o,221o
	db	"",347o,031o,"O",250o,232o,203o
	db	"",345o,032o,"F",243o,227o,215o
 
 _aes_padding:
	db	128
	db	14 dup 0
 
 _sha256_state_init:
	dl 648807
	db 106
	dl 6794885
	db -69
	dl 7271282
	db 60
	dl 5240122
	db -91
	dl 938623
	db 81
	dl 354444
	db -101
	dl -8136277
	db 31
	dl -2044647
	db 91
 
_sha256_k:
	dd	1116352408
	dd	1899447441
	dd	3049323471
	dd	3921009573
	dd	961987163
	dd	1508970993
	dd	2453635748
	dd	2870763221
	dd	3624381080
	dd	310598401
	dd	607225278
	dd	1426881987
	dd	1925078388
	dd	2162078206
	dd	2614888103
	dd	3248222580
	dd	3835390401
	dd	4022224774
	dd	264347078
	dd	604807628
	dd	770255983
	dd	1249150122
	dd	1555081692
	dd	1996064986
	dd	2554220882
	dd	2821834349
	dd	2952996808
	dd	3210313671
	dd	3336571891
	dd	3584528711
	dd	113926993
	dd	338241895
	dd	666307205
	dd	773529912
	dd	1294757372
	dd	1396182291
	dd	1695183700
	dd	1986661051
	dd	2177026350
	dd	2456956037
	dd	2730485921
	dd	2820302411
	dd	3259730800
	dd	3345764771
	dd	3516065817
	dd	3600352804
	dd	4094571909
	dd	275423344
	dd	430227734
	dd	506948616
	dd	659060556
	dd	883997877
	dd	958139571
	dd	1322822218
	dd	1537002063
	dd	1747873779
	dd	1955562222
	dd	2024104815
	dd	2227730452
	dd	2361852424
	dd	2428436474
	dd	2756734187
	dd	3204031479
	dd	3329325298

