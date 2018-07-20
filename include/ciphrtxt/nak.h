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
    utime_t not_valid_before;
    utime_t not_valid_after;
} _ctNAKSecretKey;

typedef _ctNAKSecretKey ctNAKSecretKey[1];
typedef _ctNAKSecretKey *ctNAKSecretKey_ptr;

typedef struct {
    mpECP_t public_key;
    utime_t not_valid_before;
    utime_t not_valid_after;
} _ctNAKPublicKey;

typedef _ctNAKPublicKey ctNAKPublicKey[1];
typedef _ctNAKPublicKey *ctNAKPublicKey_ptr;

typedef struct {
    mpFp_t  r;
    mpFp_t  s;
} _ctNAKSignature;

typedef _ctNAKSignature ctNAKSignature[1];
typedef _ctNAKSignature *ctNAKSignature_ptr;

// create, delete, import export for SECRET Key
void ctNAKSecretKey_init_Gen(ctNAKSecretKey sN, utime_t nvb, utime_t nva);
void ctNAKSecretKey_clear(ctNAKSecretKey sN);
unsigned char *ctNAKSecretKey_export_DER(ctNAKSecretKey sN, size_t *sz);
int ctNAKSecretKey_init_import_DER(ctNAKSecretKey sN, unsigned char *der, size_t sz);

// create, delete, import export for PUBLIC Key
void ctNAKPublicKey_init_ctNAKSecretKey(ctNAKPublicKey pN, ctNAKSecretKey sN);
void ctNAKPublicKey_clear(ctNAKPublicKey pN);
unsigned char *ctNAKPublicKey_export_DER(ctNAKPublicKey pN, size_t *sz);
int ctNAKPublicKey_init_import_DER(ctNAKPublicKey sN, unsigned char *der, size_t sz);

// ECDSA Signatures
int ctNAKSignature_init_Sign(ctNAKSignature sig, ctNAKSecretKey sN, unsigned char *msg, size_t sz);
int ctNAKSignature_verify_cmp(ctNAKSignature sig, ctNAKPublicKey sN, unsigned char *msg, size_t sz);
unsigned char *ctNAKSignature_export_bytes(ctNAKSignature sig, size_t *sz);
int ctNAKSignature_init_import_bytes(ctNAKSignature sig, unsigned char *bsig, size_t sz);
void ctNAKSignature_clear(ctNAKSignature sig);

// signed PUBLIC Key (as present in blockchain xactions)
unsigned char *ctNAKSignedPublicKey_init_ctNAKSecretKey(ctNAKSecretKey sN, size_t *sz);
int ctNAKSignedPublicKey_init_import(ctNAKPublicKey pN, unsigned char *bin, size_t sz);
int ctNAKSignedPublicKey_validate_cmp(unsigned char *bin, size_t sz);

#ifdef __cplusplus
}
#endif

#endif // _CIPHRTXT_NAK_H_INCLUDED_
