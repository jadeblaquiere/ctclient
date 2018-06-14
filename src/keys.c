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

#include <ciphrtxt/keys.h>
#include <fspke.h>
#include <sodium.h>
#include <stdint.h>
#include <time.h>

//The default configuration parameters provide for 512 bit prime field with
//384 bit group order. 

#define CT_DEFAULT_QBITS    (512)
#define CT_DEFAULT_RBITS    (384)

//The default configuration parameters provide forward security with granularity
//of 1 minute (60 seconds) for 16 million (16**6) intervals... or >31 years

#define CT_DEFAULT_DEPTH    (6)
#define CT_DEFAULT_ORDER    (16)
#define CT_DEFAULT_TSTEP    (60)

//typedef struct {
//    _ed25519sk  addr_priv;
//    _ed25519sk  enc_priv;
//    _ed25519sk  sign_priv;
//    CHKPKE_t    chk_priv;
//    int64_t     t0;
//    int64_t     tStep;
//} _ctPrivateKey;

void ctPrivateKey_init_GEN(ctPrivateKey pvK, ctPublicKey pbK, int qbits, int rbits, int depth, int order, int64_t tStep) {
    time_t systime;
    int qb, rb, d, o;
    char *chkder;
    int chkdersz;

    assert(sizeof(pvK->addr_priv) == crypto_scalarmult_ed25519_SCALARBYTES);
    randombytes_buf(pvK->addr_priv, sizeof(pvK->addr_priv));
    crypto_scalarmult_base(pbK->addr_pub, pvK->addr_priv);
    randombytes_buf(pvK->enc_priv, sizeof(pvK->enc_priv));
    crypto_scalarmult_base(pbK->enc_pub, pvK->enc_priv);
    randombytes_buf(pvK->sign_priv, sizeof(pvK->sign_priv));
    crypto_scalarmult_base(pbK->sign_pub, pvK->sign_priv);

    if (qbits > 0) {
        qb = qbits;
    } else {
        qb = CT_DEFAULT_QBITS;
    }

    if (rbits > 0) {
        rb = rbits;
    } else {
        rb = CT_DEFAULT_RBITS;
    }

    if (depth > 0) {
        d = depth;
    } else {
        d = CT_DEFAULT_DEPTH;
    }

    if (order > 0) {
        o = order;
    } else {
        o = CT_DEFAULT_ORDER;
    }
    
    CHKPKE_init_Gen(pvK->chk_priv, qb, rb, d, o);
    chkder = CHKPKE_pubkey_encode_DER(pvK->chk_priv, &chkdersz);
    CHKPKE_init_pubkey_decode_DER(pbK->chk_pub, chkder, chkdersz);
    free(chkder);

    // key is not defined for time before t0
    systime = time(NULL);
    pvK->t0 = (int64_t)systime;
    pbK->t0 = (int64_t)systime;
    
    if (tStep > 0) {
        pvK->tStep = tStep;
        pbK->tStep = tStep;
    } else {
        pvK->tStep = CT_DEFAULT_TSTEP;
    }
}
