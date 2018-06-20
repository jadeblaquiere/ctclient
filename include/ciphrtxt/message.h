//BSD 3-Clause License
//
//Copyright (c) 2018, jadeblaquiere
//All rights reserved.
//
//Redistribution and use in source and binary forms, with or without
//modification, are permitted provided that the following conditions are met:
//
//* Redistributions of source code must retain the above copyright notice, this
//  list of conditions and the following disclaimer.
//
//* Redistributions in binary form must reproduce the above copyright notice,
//  this list of conditions and the following disclaimer in the documentation
//  and/or other materials provided with the distribution.
//
//* Neither the name of the copyright holder nor the names of its
//  contributors may be used to endorse or promote products derived from
//  this software without specific prior written permission.
//
//THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
//FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
//CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
//OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef _CIPHRTXT_MESSAGE_H_INCLUDED_
#define _CIPHRTXT_MESSAGE_H_INCLUDED_

#include <sodium.h>
#include <fspke.h>
#include <ciphrtxt/keys.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Implementation of ciphrtxt  */ 

// Message = (Header) || (Payload)
//
// NOTE: all contents NETWORK BYTE ORDER (Big Endian)
//
// Header (240 bytes -> 320 Base64 Characters):
//  AS 00  03 ( 3 bytes) Message Type Magic Number (0x09 0x33 0x17) => "CTMX" in Base64
//  AS 03  08 ( 5 bytes) Message Format Version (initial version = 0x0001000000)
//  AS 08  10 ( 8 bytes) Time (microseconds since 1/1/70)
//  AS 10  18 ( 8 bytes) Expiration (microseconds since 1/1/70)
//  AS 18  38 (32 bytes) Address "I" Value (point)
//  AS 38  58 (32 bytes) Address "J" Value (point)
//  AS 58  78 (32 bytes) ECDHE exchange (point)
//  AS 78  80 ( 8 bytes) Payload Block Count (256 byte blocks)
//   S 80  A0 (32 bytes) Payload Hash
//     A0  E0 (64 bytes) EdDSA Signature
//     E0  E8 ( 8 bytes) reserved, zero
//     E8  F0 ( 8 bytes) Header Nonce
//
// Fields with A prefix are authenticated in AEAD
// Fields with S prefix are signed by EdDSA Signature

// Payload = Len(FSKey) (2 bytes) || FSKey (?? Bytes) || Encryption Nonce || AEAD_Ciphertext
// (Len(FSKey) and FS Key are also authenticated in AEAD)
//
// AEAD_Ciphertext = AEAD_ENC ( (Inner Header || Message_Plaintext) || pad )
// 
// Inner Header
//     00  20 (32 bytes) i Value (EC Discrete Log of I)
//     20  40 (32 bytes) EdDSA Pubkey (ECDH point)
//     40  48 ( 8 bytes) Message length in bytes (Lm)
//     48  4C ( 4 bytes) MIME type Length (m, maximum = 180)
//     4C  ?? ( m bytes) MIME type
//     ?? 100 ( 180-m bytes) pad (zeroes)
//    100  ?? ( L bytes) Message
//     ??  ?? ( P bytes) pad (to result in complete block after enc)
//
// NOTE: ciphrtxt uses libsodium's XChaCha20-Poly1305 authenticated encryption
// which implies a 192-bit (24 byte) nonce + auth tag of 128-bits (16 bytes)
// so the required pad length is -(((Lm + 2 + Lk) + 24 + 16) % 256) % 256
//

typedef struct {
    char            magic[3];
    unsigned char   version[5];
    uint64_t        msgtime_msec;
    uint64_t        expire_sec;
    _ed25519pk      I_point;
    _ed25519pk      J_point;
    _ed25519pk      ECDHE_point;
    uint64_t        payload_blocks;
    unsigned char   payload_hash[crypto_generichash_BYTES];
    unsigned char   header_signature[crypto_sign_BYTES];
    unsigned char   reserved[8];
    uint64_t        nonce;
} _CtMessageHeader;

typedef _CtMessageHeader CtMessageHeader[1];
typedef _CtMessageHeader *CtMessageHeader_ptr;

typedef struct {
    _ed25519sk      i_scalar;
    _ed25519pk      SIG_point;
    uint64_t        msglen;
    uint32_t        mimelen;
    char            mime[180];
} _CtMessageInnerHeader;

typedef _CtMessageInnerHeader *CtMessageInnerHeader_ptr;

#ifdef __cplusplus
}
#endif

#endif // _CIPHRTXT_MESSAGE_H_INCLUDED_
