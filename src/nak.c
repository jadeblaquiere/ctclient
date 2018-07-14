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

#include <ciphrtxt/nak.h>
#include <ciphrtxt/utime.h>
#include <ecc.h>
#include <inttypes.h>
#include <stdlib.h>

static mpECurve_ptr _secp265k1 = NULL;
static mpECP_ptr _secp265k1_base = NULL;

static void _secp265k1_curve_clear(void) {
    assert(_secp265k1 != NULL);
    mpECP_clear(_secp265k1_base);
    mpECurve_clear(_secp265k1);
    free(_secp265k1_base);
    free(_secp265k1);
    _secp265k1 = NULL;
    return;
}

static void _secp265k1_curve_init(void) {
    int status;

    _secp265k1 = (mpECurve_ptr)malloc(sizeof(mpECurve_t));
    mpECurve_init(_secp265k1);
    status = mpECurve_set_named(_secp265k1, "secp256k1");
    assert(status == 0);
    _secp265k1_base = (mpECP_ptr)malloc(sizeof(mpECP_t));
    mpECP_init(_secp265k1_base, _secp265k1);
    mpECP_set_mpz(_secp265k1_base, _secp265k1->G[0], _secp265k1->G[1], _secp265k1);
    mpECP_scalar_base_mul_setup(_secp265k1_base);
    atexit(&_secp265k1_curve_clear);
    return;
}

// create, delete, import export for SECRET Key
void ctNAKSecretKey_init_Gen(ctNAKSecretKey snak, utime_t nvb, utime_t nva) {
    if (_secp265k1 == NULL) _secp265k1_curve_init();
    snak->not_valid_before = nvb;
    snak->not_valid_after = nva;
    mpFp_init(snak->secret_key, _secp265k1->n);
    mpFp_urandom(snak->secret_key, _secp265k1->n);
    return;
}

void ctNAKSecretKey_clear(ctNAKSecretKey snak) {
    snak->not_valid_before = 0;
    snak->not_valid_after = 0;
    mpFp_clear(snak->secret_key);
    return;
}

//unsigned char *ctNAKSecretKey_export_DER(ctNAKSecretKey snak, size_t *sz);
//int ctNAKSecretKey_init_import_DER(ctNAKSecretKey snak, unsigned char *der, size_t sz);

void ctNAKPublicKey_init_ctNAKSecretKey(ctNAKPublicKey pnak, ctNAKSecretKey snak) {
    if (_secp265k1 == NULL) _secp265k1_curve_init();
    pnak->not_valid_before = snak->not_valid_before;
    pnak->not_valid_after = snak->not_valid_after;
    mpECP_init(pnak->public_key, _secp265k1);
    mpECP_scalar_base_mul(pnak->public_key, _secp265k1_base, snak->secret_key);
    return;
}

void ctNAKPublicKey_clear(ctNAKPublicKey pnak) {
    pnak->not_valid_before = 0;
    pnak->not_valid_after = 0;
    mpECP_clear(pnak->public_key);
    return;
}

//unsigned char *ctNAKPublicKey_export_DER(ctNAKPublicKey pnak, size_t *sz);
//int ctNAKPublicKey_init_import_DER(ctNAKPublicKey snak, unsigned char *der, size_t sz);

// ECDSA Signatures
//void ctNAKSign(ctNAKSignature sig, ctNAKSecretKey snak, unsigned char *msg, size_t sz);
//int ctNAKVerify(ctNAKSignature sig, ctNAKPublicKey snak, unsigned char *msg, size_t sz)

// signed PUBLIC Key (as present in blockchain xactions)
//unsigned char *ctNAKSignedPublicKey_init_ctNAKSecretKey(ctNAKSecretKey snak, size_t *sz);
//int ctNAKSignedPublicKey_init_import(ctNAKPublicKey pnak, unsigned char *bin, size_t sz);
