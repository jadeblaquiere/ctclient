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

#include <ciphrtxt/utime.h>
#include <fspke.h>
#include <sodium.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Implementation of ciphrtxt  */ 

typedef unsigned char _ed25519sk[crypto_scalarmult_ed25519_SCALARBYTES];
typedef unsigned char _ed25519pk[crypto_scalarmult_ed25519_BYTES];

typedef struct {
    _ed25519sk      addr_sec;
    _ed25519sk      enc_sec;
    _ed25519sk      sign_sec;
    CHKPKE_t        chk_sec;
    utime_t         t0;
    utime_t         tStep;
    int64_t         _intervalMin;
    int64_t         _intervalMax;
} _ctSecretKey;

typedef _ctSecretKey ctSecretKey[1];
typedef _ctSecretKey *ctSecretKey_ptr;

typedef struct {
    _ed25519pk      addr_pub;
    _ed25519pk      enc_pub;
    _ed25519pk      sign_pub;
    CHKPKE_t        chk_pub;
    utime_t         t0;
    utime_t         tStep;
} _ctPublicKey;

typedef _ctPublicKey ctPublicKey[1];
typedef _ctPublicKey *ctPublicKey_ptr;

void ctSecretKey_init_Gen(ctSecretKey sK, int qbits, int rbits, int depth, int order, int64_t tStep);
void ctSecretKey_clear(ctSecretKey sK);

// export a binary (ASN.1 DER Encoded) representation of the secret key
// valid for time including tStart and after (cannot decode older messages)
unsigned char *ctSecretKey_Export_FS_DER(ctSecretKey sK, utime_t tStart, size_t *sz);

// export a key which is valid for time interval [tStart, tEnd] (inclusive of limits)
// returns NULL on error (i.e. if tStart, tEnd are outside capabilities of key)
// the intent of this API is to support producing "delegate" keys which are only valid
// for a short interval. Therefore if the device with that key is compromised the
// risk exposure is limited both forward and backwards in time.
unsigned char *ctSecretKey_Export_FS_Delegate_DER(ctSecretKey sK, utime_t tStart, utime_t tEnd, size_t *sz);

// import (decode) a DER key as a secret key
int ctSecretKey_init_decode_DER(ctSecretKey sK, unsigned char *der, size_t dsz);

// initialize a public key from a secret key
void ctPublicKey_init_ctSecretKey(ctPublicKey pK, ctSecretKey sK);
void ctPublicKey_clear(ctPublicKey pK);

// export a binary (ASN.1 DER Encoded) representation of the public key
// public keys are valid for all time periods (though clearly encoding 
// messages for times in the past is of questionable value)
unsigned char *ctPublicKey_Export_DER(ctPublicKey pK, size_t *sz);

// import (decode) a DER key as a public key
int ctPublicKey_init_decode_DER(ctPublicKey pK, unsigned char *der, size_t dsz);

// internal libary routines for handling time/interval conversion
int64_t _ctSecretKey_interval_for_time(ctSecretKey sK, utime_t t);
utime_t _ctSecretKey_time_for_interval(ctSecretKey sK, int64_t i);
int64_t _ctPublicKey_interval_for_time(ctPublicKey pK, utime_t t);
utime_t _ctPublicKey_time_for_interval(ctPublicKey pK, int64_t i);

#ifdef __cplusplus
}
#endif

#endif // _CIPHRTXT_KEYS_H_INCLUDED_
