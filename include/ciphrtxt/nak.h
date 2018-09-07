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

#ifndef _CIPHRTXT_NAK_H_INCLUDED_
#define _CIPHRTXT_NAK_H_INCLUDED_

#include <ecc.h>
#include <ciphrtxt/utime.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Network Access Keys */ 

typedef struct {
    mpFp_t  secret_key;
    //mpFp_t  secret_key_inv;
    utime_t not_valid_before;
    utime_t not_valid_after;
} _ctNAKSecretKey_t;

typedef _ctNAKSecretKey_t ctNAKSecretKey_t[1];
typedef _ctNAKSecretKey_t *ctNAKSecretKey_ptr;

typedef struct {
    mpECP_t public_key;
    utime_t not_valid_before;
    utime_t not_valid_after;
} _ctNAKPublicKey_t;

typedef _ctNAKPublicKey_t ctNAKPublicKey_t[1];
typedef _ctNAKPublicKey_t *ctNAKPublicKey_ptr;

// create, delete, import export for SECRET Key
void ctNAKSecretKey_init_Gen(ctNAKSecretKey_t sN, utime_t nvb, utime_t nva);
void ctNAKSecretKey_clear(ctNAKSecretKey_t sN);
unsigned char *ctNAKSecretKey_export_DER(ctNAKSecretKey_t sN, size_t *sz);
int ctNAKSecretKey_init_import_DER(ctNAKSecretKey_t sN, unsigned char *der, size_t sz);

// create, delete, import export for PUBLIC Key
void ctNAKPublicKey_init_ctNAKSecretKey(ctNAKPublicKey_t pN, ctNAKSecretKey_t sN);
void ctNAKPublicKey_clear(ctNAKPublicKey_t pN);
unsigned char *ctNAKPublicKey_export_DER(ctNAKPublicKey_t pN, size_t *sz);
int ctNAKPublicKey_init_import_DER(ctNAKPublicKey_t pN, unsigned char *der, size_t sz);

// ECDSA Signatures
int ctNAKSignature_init_Sign(mpECDSASignature_t sig, ctNAKSecretKey_t sN, unsigned char *msg, size_t sz);
int ctNAKSignature_verify_cmp(mpECDSASignature_t sig, ctNAKPublicKey_t pN, unsigned char *msg, size_t sz);
unsigned char *ctNAKSignature_export_bytes(mpECDSASignature_t sig, size_t *sz);
int ctNAKSignature_init_import_bytes(mpECDSASignature_t sig, unsigned char *bsig, size_t sz);
void ctNAKSignature_clear(mpECDSASignature_t sig);

// signed PUBLIC Key (as present in blockchain xactions)
// format is:
// 0x00 - 0x20 (33 bytes) public key (EC Point)
// 0x21 - 0x29 (8 bytes) not before
// 0x29 - 0x30 (8 bytes) not after
// 0x31 - 0x50 (32 bytes) signature "r"
// 0x51 - 0x70 (32 bytes) signature "s"

#define CTNAK_SIGNED_KEY_LENGTH  (0x71)

unsigned char *ctNAKSignedPublicKey_init_ctNAKSecretKey(ctNAKSecretKey_t sN, size_t *sz);
int ctNAKSignedPublicKey_init_import(ctNAKPublicKey_t pN, unsigned char *bin, size_t sz);
int ctNAKSignedPublicKey_validate_cmp(unsigned char *bin, size_t sz);

// anonymous authentication methods (based on model proposed by Daniel Slamanig
// in Anonymous Authentication from Public-Key Encryption Revisited)

// The challenge is a list of encryptions with their associated public key
// points and a single public key used for response

typedef struct {
    int n;
    mpECElgamalCiphertext_t *ctxt;
    mpECP_t *pK;
    mpECP_t session_pK;
    utime_t session_expire;
} _ctNAKAuthChallenge_t;

typedef _ctNAKAuthChallenge_t ctNAKAuthChallenge_t[1];
typedef _ctNAKAuthChallenge_t *ctNAKAuthChallenge_ptr;

int ctNAKAuthChallenge_init(ctNAKAuthChallenge_t c, int n, ctNAKPublicKey_t *pN, mpECP_t session_pK, utime_t expire, mpECP_t ptxt);
unsigned char *ctNAKAuthChallenge_export_DER(ctNAKAuthChallenge_t c, size_t *sz);
int ctNAKAuthChallenge_init_import_DER(ctNAKAuthChallenge_t c, unsigned char *der, size_t sz);
void ctNAKAuthChallenge_clear(ctNAKAuthChallenge_t c);

typedef struct {
    mpECP_t session_pK;
    mpECElgamalCiphertext_t ctxt;
} _ctNAKAuthResponse_t;

typedef _ctNAKAuthResponse_t ctNAKAuthResponse_t[1];
typedef _ctNAKAuthResponse_t *ctNAKAuthResponse_ptr;

int ctNAKAuthResponse_init(ctNAKAuthResponse_t r, ctNAKAuthChallenge_t c, ctNAKSecretKey_t sN);
int ctNAKAuthResponse_validate_cmp(ctNAKAuthResponse_t r, mpFp_t session_sK, mpECP_t ptxt);
unsigned char *ctNAKAuthResponse_export_DER(ctNAKAuthResponse_t r, size_t *sz);
int ctNAKAuthResponse_init_import_DER(ctNAKAuthResponse_t, unsigned char *der, size_t sz);
void ctNAKAuthResponse_clear(ctNAKAuthResponse_t r);

#ifdef __cplusplus
}
#endif

#endif // _CIPHRTXT_NAK_H_INCLUDED_
