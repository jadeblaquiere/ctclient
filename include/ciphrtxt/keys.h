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

#ifndef _CIPHRTXT_KEYS_H_INCLUDED_
#define _CIPHRTXT_KEYS_H_INCLUDED_

#include <sodium.h>
#include <fspke.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Implementation of ciphrtxt  */ 

typedef unsigned char _ed25519sk[crypto_scalarmult_ed25519_SCALARBYTES];
typedef unsigned char _ed25519pk[crypto_scalarmult_ed25519_BYTES];

typedef struct {
    _ed25519sk  addr_priv;
    _ed25519sk  enc_priv;
    _ed25519sk  sign_priv;
    CHKPKE_t    chk_priv;
    int64_t     t0;
    int64_t     tStep;
} _ctPrivateKey;

typedef _ctPrivateKey ctPrivateKey[1];
typedef _ctPrivateKey *ctPrivateKey_ptr;

typedef struct {
    _ed25519pk  addr_pub;
    _ed25519pk  enc_pub;
    _ed25519pk  sign_pub;
    CHKPKE_t    chk_pub;
    int64_t     t0;
    int64_t     tStep;
} _ctPublicKey;

typedef _ctPublicKey ctPublicKey[1];
typedef _ctPublicKey *ctPublicKey_ptr;

void ctPrivateKey_init_GEN(ctPrivateKey pvK, ctPublicKey pbK, int qbits, int rbits, int depth, int order, int64_t tStep);

#ifdef __cplusplus
}
#endif

#endif // _CIPHRTXT_KEYS_H_INCLUDED_
