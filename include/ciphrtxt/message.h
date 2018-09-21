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

#include <ciphrtxt/keys.h>
#include <ciphrtxt/postage.h>
#include <ciphrtxt/utime.h>
#include <fspke.h>
#include <sodium.h>

#ifdef __cplusplus
extern "C" {
#endif

#define _CT_MAX_MIME_LEN    (256)
#define _CT_BLKSZ           (240)
#define _CT_AUTH_HDR_SZ     (0x80)
#define _CT_HDR_SIGD_SZ     (0xA0)
#define _CT_MAGIC_BYTES     (3)
#define _CT_VERSION_BYTES   (5)

/* Implementation of ciphrtxt  */ 

// Message = (Header) || (Payload)
//
// NOTE: all integer contents are transferred in HOST BYTE ORDER (Little Endian)
//
// Header (240 bytes -> 320 Base64 Characters):
//  AS 00  03 ( 3 bytes) Message Type Magic Number (0x09 0x33 0x17) => "CTMX" in Base64
//  AS 03  08 ( 5 bytes) Message Format Version (initial version = 0x0001000000)
//  AS 08  10 ( 8 bytes) Time (microseconds since 1/1/70)
//  AS 10  18 ( 8 bytes) Expiration (microseconds since 1/1/70)
//  AS 18  20 ( 8 bytes) Payload Block Count (240 byte blocks binary/320 in b64)
//  AS 20  40 (32 bytes) Address "I" Value (point)
//  AS 40  60 (32 bytes) Address "J" Value (point)
//  AS 60  80 (32 bytes) ECDHE exchange (point)
//   S 80  A0 (32 bytes) Payload Hash
//     A0  E0 (64 bytes) EdDSA Signature
//     E0  E8 ( 8 bytes) reserved, zero
//     E8  F0 ( 8 bytes) Header Nonce
//
// Fields with A prefix are authenticated in AEAD
// Fields with S prefix are signed by EdDSA Signature

// Preamble = Len(FSKey) (4 bytes) || FSKey (?? Bytes) || Encryption Nonce 
// the preamble is authenticated in AEAD
//
// AEAD_Data = Header[0x00:0x80] || Preamble
//
// Payload = Preamble || AEAD_Ciphertext
//
// AEAD_Ciphertext = AEAD_ENC ( (Inner Header || Message_Plaintext) || pad )
//
// Inner Header (sent encrypted)
//      0  20 (32 bytes) EdDSA Pubkey (ECDH point)
//     20  28 ( 8 bytes) Message length in bytes (Lm)
//     28  2C ( 4 bytes) MIME type Length (m, maximum = 180)
//     2C  ?? ( m bytes) MIME type
//
// NOTE: ciphrtxt uses libsodium's XChaCha20-Poly1305 authenticated encryption
// which implies a 192-bit (24 byte) nonce + auth tag of 128-bits (16 bytes)
// so the required pad length is -(((Lm + 4 + Lk) + 24 + 16) % 240) % 240
//

typedef struct {
    char            magic[_CT_MAGIC_BYTES];
    unsigned char   version[_CT_VERSION_BYTES];
    utime_t        msgtime_usec;
    utime_t        expire_usec;
    uint64_t        payload_blocks;
    _ed25519pk      I_point;
    _ed25519pk      J_point;
    _ed25519pk      ECDHE_point;
    unsigned char   payload_hash[crypto_generichash_BYTES];
    unsigned char   header_signature[crypto_sign_BYTES];
    unsigned char   reserved[8];
    uint64_t        nonce;
} _ctMessageHeader_t;

typedef _ctMessageHeader_t ctMessageHeader_t[1];
typedef _ctMessageHeader_t *ctMessageHeader_ptr;

typedef struct {
    _ed25519pk      SIG_point;
    uint64_t        msglen;
    uint32_t        mimelen;
    char            mime[_CT_MAX_MIME_LEN];
} _ctMessageInnerHeader_t;

typedef _ctMessageInnerHeader_t ctMessageInnerHeader_t[1];
typedef _ctMessageInnerHeader_t *ctMessageInnerHeader_ptr;

typedef struct {
    _ed25519sk      addr_sec;
    _ed25519sk      ephem_sec;
    _ed25519sk      sig_sec;
    unsigned char   sym_key[crypto_stream_xchacha20_KEYBYTES];
} _ctMessageSecrets_t;

typedef _ctMessageSecrets_t ctMessageSecrets_t[1];
typedef _ctMessageSecrets_t *ctMessageSecrets_ptr;

typedef struct {
    ctMessageHeader_t         hdr;
    unsigned char           *fsk;
    uint32_t                fsksz;
    unsigned char           nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    ctMessageInnerHeader_t    inner;
    size_t                  innersz;
    unsigned char           *ctext;
    size_t                  ctextsz;
    unsigned char           *ptext;
    size_t                  ptextsz;
    ctMessageSecrets_t        secrets;
} _ctMessage_t;

typedef _ctMessage_t  ctMessage_t[1];
typedef _ctMessage_t  *ctMessage_ptr;

// encrypt a plaintext message for a single recipient toK. toK, plaintext and p_sz
// are required inputs. If fromK is NULL, a random origination address will be
// used (resulting in an anonymous message). If timestamp is 0, the current 
// system time will be used (converted to UTC as all times are UTC in ciphrtxt)
// the resulting message is signed and stored in msg. if ttl is zero the default
// ttl (1 week) will be used. If mime is NULL then the default (text/plain) will
// be used.
unsigned char *ctMessage_init_Enc(ctMessage_t msg, ctPublicKey_t toK, ctSecretKey_t fromK, 
  utime_t timestamp, utime_t ttl, char *mime, unsigned char *plaintext,
  size_t p_sz, ctPostageRate_t rate, size_t *sz);

// decrypt an encrypted message (ciphertext) using the key toK. The resulting
// message structure contains the plaintext along with message metadata. The
// decrypion process validates the ciphertext and additional data (AEAD). Any
// error in authentication signature or padding results in msg remaining
// uninitialized and a nonzero return status.
int ctMessage_init_Dec(ctMessage_t msg, ctSecretKey_t toK, unsigned char *ctext, size_t ctextsz);

// clear message and clear/free all allocated data.
void ctMessage_clear(ctMessage_t msg);

// find a nonce which satisfies postage requirement
int ctMessage_rehash(ctMessage_t msg, ctPostageRate_t rate);

// NOTE :: for the following convenience routines, the data returned is
// embedded in other structured data. You should not write to these locations
// nor do you need to call free() on the data (to clear and release all memory
// for the message please call ctMessage_clear())

// return a pointer and length for the message plaintext.
unsigned char *ctMessage_plaintext_ptr(ctMessage_t msg, size_t *ptsz);

// return a pointer and length for the message plaintext. The mime type is 
// null terminated and expected to contain ascii text
char *ctMessage_mime_ptr(ctMessage_t msg, size_t *mimesz);

// return a pointer and length for the message plaintext. 
unsigned char *ctMessage_ciphertext_ptr(ctMessage_t msg, size_t *ctsz);

#ifdef __cplusplus
}
#endif

#endif // _CIPHRTXT_MESSAGE_H_INCLUDED_
