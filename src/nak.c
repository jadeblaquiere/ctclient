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

#include <asn1.h>
#include <ciphrtxt/nak.h>
#include <ciphrtxt/utime.h>
#include <ecc.h>
#include <gmp.h>
#include <inttypes.h>
#include <libtasn1.h>
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

static mpECurve_ptr _secp265k1 = NULL;
static mpECP_ptr _secp265k1_base = NULL;

extern const asn1_static_node ciphrtxt_asn1_tab[];

#define _SECP256_N_BYTES    (32U)

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
void ctNAKSecretKey_init_Gen(ctNAKSecretKey sN, utime_t nvb, utime_t nva) {
    if (_secp265k1 == NULL) _secp265k1_curve_init();
    sN->not_valid_before = nvb;
    sN->not_valid_after = nva;
    mpFp_init(sN->secret_key, _secp265k1->n);
    mpFp_urandom(sN->secret_key, _secp265k1->n);
    return;
}

void ctNAKSecretKey_clear(ctNAKSecretKey sN) {
    sN->not_valid_before = 0;
    sN->not_valid_after = 0;
    mpFp_clear(sN->secret_key);
    return;
}

unsigned char *ctNAKSecretKey_export_DER(ctNAKSecretKey sN, size_t *sz) {
    ASN1_TYPE ct_asn1 = ASN1_TYPE_EMPTY;
    ASN1_TYPE sN_asn1 = ASN1_TYPE_EMPTY;
    char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    unsigned char *buffer;
    int status;
    size_t length;
    int sum;
    mpz_t tmpz;

    sum = 0;

    status = asn1_array2tree(ciphrtxt_asn1_tab, &ct_asn1, asnError);
    if (status != 0) return NULL;

    status = asn1_create_element(ct_asn1, "Ciphrtxt.CTNAKSecretKey",
        &sN_asn1);
    if (status != 0) {
        asn1_delete_structure(&ct_asn1);
        return NULL;
    }

    mpz_init(tmpz);

    //printf("-----------------\n");
    //asn1_print_structure(stdout, sN_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    sum += _asn1_write_int64_as_integer(sN_asn1, "version", 1);
    mpz_set_mpFp(tmpz, sN->secret_key);
    sum += _asn1_write_mpz_as_octet_string(sN_asn1, "secret_key", tmpz);
    sum += _asn1_write_int64_as_integer(sN_asn1, "not_before", (int64_t)(sN->not_valid_before));
    sum += _asn1_write_int64_as_integer(sN_asn1, "not_after", (int64_t)(sN->not_valid_after));

    mpz_clear(tmpz);

    //printf("-----------------\n");
    //asn1_print_structure(stdout, sN_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    sum += 256;  // pad for DER header + some extra just in case
    length = sum;
    buffer = (unsigned char *)malloc((sum) * sizeof(char));
    assert(buffer != NULL);
    {
        int isz = length;
        status = asn1_der_coding(sN_asn1, "", (char *)buffer, &isz, asnError);
        length = isz;
    }

    asn1_delete_structure(&sN_asn1);
    asn1_delete_structure(&ct_asn1);

    if (status != 0) {
        return NULL;
    }
    assert(length < sum);

    *sz = length;
    return buffer;
}

int ctNAKSecretKey_init_import_DER(ctNAKSecretKey sN, unsigned char *der, size_t dsz) {
    ASN1_TYPE ct_asn1 = ASN1_TYPE_EMPTY;
    ASN1_TYPE sN_asn1 = ASN1_TYPE_EMPTY;
    char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    int status;
    mpz_t tmpz;

    if (_secp265k1 == NULL) _secp265k1_curve_init();

    status = asn1_array2tree(ciphrtxt_asn1_tab, &ct_asn1, asnError);
    if (status != 0) return -1;

    status = asn1_create_element(ct_asn1, "Ciphrtxt.CTNAKSecretKey",
        &sN_asn1);
    if (status != 0) {
        asn1_delete_structure(&ct_asn1);
        return -1;
    }

    //printf("-----------------\n");
    //asn1_print_structure(stdout, sN_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    // read DER into ASN1 structure
    status = asn1_der_decoding(&sN_asn1, (char *)der, (int)dsz, asnError);
    if (status != ASN1_SUCCESS) return -1;

    //printf("-----------------\n");
    //asn1_print_structure(stdout, sN_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    {
        int64_t ver;
        status = _asn1_read_int64_from_integer(&ver, sN_asn1, "version");
        // version 1 is only known version at this time
        if ((status != 0) || (ver != 1)) goto error_cleanup3;
    }

    // Read secret key from ASN1 structure

    mpz_init(tmpz);
    mpFp_init(sN->secret_key, _secp265k1->n);
    status = _asn1_read_mpz_from_octet_string(tmpz, sN_asn1, "secret_key");
    if (status != 0) {
        mpz_clear(tmpz);
        goto error_cleanup2;
    }
    mpFp_set_mpz(sN->secret_key, tmpz, _secp265k1->n);
    mpz_clear(tmpz);

    status = _asn1_read_int64_from_integer(&(sN->not_valid_before), sN_asn1, "not_before");
    if (status != 0) goto error_cleanup2;

    status = _asn1_read_int64_from_integer(&(sN->not_valid_after), sN_asn1, "not_after");
    if (status != 0) goto error_cleanup2;

    asn1_delete_structure(&sN_asn1);
    asn1_delete_structure(&ct_asn1);
    return 0;

error_cleanup2:
    mpFp_clear(sN->secret_key);
    sN->not_valid_before = 0;
    sN->not_valid_after = 0;
    asn1_delete_structure(&sN_asn1);
    asn1_delete_structure(&ct_asn1);
    return -1;

error_cleanup3:
    asn1_delete_structure(&sN_asn1);
    asn1_delete_structure(&ct_asn1);
    return -1;
}

void ctNAKPublicKey_init_ctNAKSecretKey(ctNAKPublicKey pN, ctNAKSecretKey sN) {
    if (_secp265k1 == NULL) _secp265k1_curve_init();
    pN->not_valid_before = sN->not_valid_before;
    pN->not_valid_after = sN->not_valid_after;
    mpECP_init(pN->public_key, _secp265k1);
    mpECP_scalar_base_mul(pN->public_key, _secp265k1_base, sN->secret_key);
    return;
}

void ctNAKPublicKey_clear(ctNAKPublicKey pN) {
    pN->not_valid_before = 0;
    pN->not_valid_after = 0;
    mpECP_clear(pN->public_key);
    return;
}

unsigned char *ctNAKPublicKey_export_DER(ctNAKPublicKey pN, size_t *sz) {
    ASN1_TYPE ct_asn1 = ASN1_TYPE_EMPTY;
    ASN1_TYPE pN_asn1 = ASN1_TYPE_EMPTY;
    char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    unsigned char *buffer;
    int status;
    size_t length;
    int sum;
    mpz_t tmpz;

    sum = 0;

    status = asn1_array2tree(ciphrtxt_asn1_tab, &ct_asn1, asnError);
    if (status != 0) return NULL;

    status = asn1_create_element(ct_asn1, "Ciphrtxt.CTNAKPublicKey",
        &pN_asn1);
    if (status != 0) {
        asn1_delete_structure(&ct_asn1);
        return NULL;
    }

    mpz_init(tmpz);

    //printf("-----------------\n");
    //asn1_print_structure(stdout, pN_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    sum += _asn1_write_int64_as_integer(pN_asn1, "version", 1);
    {
        unsigned char *buffer;
        size_t bsz;
        bsz = mpECP_out_bytelen(pN->public_key, 1);
        buffer = (unsigned char *)malloc(bsz * sizeof(unsigned char));
        mpECP_out_bytes(buffer, pN->public_key, 1);
        sum += _asn1_write_uchar_string_as_octet_string(pN_asn1, "public_key", buffer, bsz);
    }
    sum += _asn1_write_int64_as_integer(pN_asn1, "not_before", (int64_t)(pN->not_valid_before));
    sum += _asn1_write_int64_as_integer(pN_asn1, "not_after", (int64_t)(pN->not_valid_after));

    mpz_clear(tmpz);

    //printf("-----------------\n");
    //asn1_print_structure(stdout, pN_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    sum += 256;  // pad for DER header + some extra just in case
    length = sum;
    buffer = (unsigned char *)malloc((sum) * sizeof(char));
    assert(buffer != NULL);
    {
        int isz = length;
        status = asn1_der_coding(pN_asn1, "", (char *)buffer, &isz, asnError);
        length = isz;
    }

    asn1_delete_structure(&pN_asn1);
    asn1_delete_structure(&ct_asn1);

    if (status != 0) {
        return NULL;
    }
    assert(length < sum);

    *sz = length;
    return buffer;
}

int ctNAKPublicKey_init_import_DER(ctNAKPublicKey pN, unsigned char *der, size_t dsz) {
    ASN1_TYPE ct_asn1 = ASN1_TYPE_EMPTY;
    ASN1_TYPE pN_asn1 = ASN1_TYPE_EMPTY;
    char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    int status;

    if (_secp265k1 == NULL) _secp265k1_curve_init();

    status = asn1_array2tree(ciphrtxt_asn1_tab, &ct_asn1, asnError);
    if (status != 0) return -1;

    status = asn1_create_element(ct_asn1, "Ciphrtxt.CTNAKPublicKey",
        &pN_asn1);
    if (status != 0) {
        asn1_delete_structure(&ct_asn1);
        return -1;
    }

    //printf("-----------------\n");
    //asn1_print_structure(stdout, pN_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    // read DER into ASN1 structure
    status = asn1_der_decoding(&pN_asn1, (char *)der, (int)dsz, asnError);
    if (status != ASN1_SUCCESS) return -1;

    //printf("-----------------\n");
    //asn1_print_structure(stdout, pN_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    {
        int64_t ver;
        status = _asn1_read_int64_from_integer(&ver, pN_asn1, "version");
        // version 1 is only known version at this time
        if ((status != 0) || (ver != 1)) goto error_cleanup3;
    }

    // Read secret key from ASN1 structure

    {
        unsigned char *buffer;
        size_t sz;

        mpECP_init(pN->public_key, _secp265k1);
        buffer = _asn1_read_octet_string_as_uchar(pN_asn1, "public_key", &sz);
        if (status != 0) {
            memset(buffer,0,sz);
            free(buffer);
            goto error_cleanup2;
        }
        mpECP_set_bytes(pN->public_key, buffer, sz, _secp265k1);
        memset(buffer,0,sz);
        free(buffer);
    }

    status = _asn1_read_int64_from_integer(&(pN->not_valid_before), pN_asn1, "not_before");
    if (status != 0) goto error_cleanup2;

    status = _asn1_read_int64_from_integer(&(pN->not_valid_after), pN_asn1, "not_after");
    if (status != 0) goto error_cleanup2;

    asn1_delete_structure(&pN_asn1);
    asn1_delete_structure(&ct_asn1);
    return 0;

error_cleanup2:
    mpECP_clear(pN->public_key);
    pN->not_valid_before = 0;
    pN->not_valid_after = 0;
    asn1_delete_structure(&pN_asn1);
    asn1_delete_structure(&ct_asn1);
    return -1;

error_cleanup3:
    asn1_delete_structure(&pN_asn1);
    asn1_delete_structure(&ct_asn1);
    return -1;
}

// ECDSA Signatures
int ctNAKSignature_init_Sign(ctNAKSignature sig, ctNAKSecretKey sN, unsigned char *msg, size_t sz) {
    unsigned char hash[crypto_hash_sha256_BYTES];
    mpFp_t k_n;
    mpFp_t r_n;
    mpFp_t s_n;
    mpFp_t e_n;
    mpz_t e;
    mpz_t r;
    mpECP_t R;
    int status;

    if (_secp265k1 == NULL) _secp265k1_curve_init();

    if (sz == 0) return -1;

    mpFp_init(k_n, _secp265k1->n);
    mpFp_init(r_n, _secp265k1->n);
    mpFp_init(s_n, _secp265k1->n);
    mpFp_init(e_n, _secp265k1->n);
    mpz_init(r);
    mpz_init(e);
    mpECP_init(R, _secp265k1);

    crypto_hash_sha256(hash, msg, sz);
    mpz_import (e, crypto_hash_sha256_BYTES, 1, 1, 1, 0, hash);
    mpFp_set_mpz(e_n, e, _secp265k1->n);
new_random:
    mpFp_urandom(k_n, _secp265k1->n);
    if (__GMP_UNLIKELY(mpFp_cmp_ui(k_n, 0) == 0)) goto new_random;

    mpECP_scalar_base_mul(R, _secp265k1_base, k_n);
    mpz_set_mpECP_affine_x(r, R);
    if (__GMP_UNLIKELY(mpz_cmp_ui(r, 0) == 0)) goto new_random;

    mpFp_set_mpz(r_n, r, _secp265k1->n);
    mpFp_mul(s_n, r_n, sN->secret_key);
    mpFp_add(s_n, s_n, e_n);
    status = mpFp_inv(e_n, k_n);
    if (status != 0) goto new_random;
    mpFp_mul(s_n, s_n, e_n);
    if (__GMP_UNLIKELY(mpFp_cmp_ui(s_n, 0) == 0)) goto new_random;

    mpFp_init(sig->r, _secp265k1->n);
    mpFp_init(sig->s, _secp265k1->n);

    mpFp_set(sig->r, r_n);
    mpFp_set(sig->s, s_n);

    mpECP_clear(R);
    mpz_clear(e);
    mpz_clear(r);
    mpFp_clear(e_n);
    mpFp_clear(s_n);
    mpFp_clear(r_n);
    mpFp_clear(k_n);
    return 0;
}

int ctNAKSignature_verify_cmp(ctNAKSignature sig, ctNAKPublicKey sN, unsigned char *msg, size_t sz) {
    unsigned char hash[crypto_hash_sha256_BYTES];
    mpFp_t w;
    mpFp_t u1;
    mpFp_t u2;
    mpFp_t e_n;
    mpFp_t p_n;
    mpz_t e;
    mpECP_t P;
    mpECP_t Pq;
    int status;

    if (_secp265k1 == NULL) _secp265k1_curve_init();

    if (sz == 0) return -1;

    // validate signature input, presume public key was validated at import
    if ((mpz_cmp(sig->r->fp->p, _secp265k1->n) != 0) || 
        (mpz_cmp(sig->s->fp->p, _secp265k1->n) != 0)) {
        return -1;
    }

    if ((mpFp_cmp_ui(sig->r, 0) == 0) || (mpFp_cmp_ui(sig->s, 0) == 0)) {
        return -1;
    }

    mpz_init(e);
    mpFp_init_fp(p_n, _secp265k1->fp);
    mpFp_init(e_n, _secp265k1->n);
    mpFp_init(w, _secp265k1->n);
    mpFp_init(u1, _secp265k1->n);
    mpFp_init(u2, _secp265k1->n);
    mpECP_init(P, _secp265k1);
    mpECP_init(Pq, _secp265k1);

    crypto_hash_sha256(hash, msg, sz);
    mpz_import (e, crypto_hash_sha256_BYTES, 1, 1, 1, 0, hash);
    mpFp_set_mpz(e_n, e, _secp265k1->n);
    mpFp_inv(w, sig->s);
    mpFp_mul(u1, e_n, w);
    mpFp_mul(u2, sig->r, w);
    mpECP_scalar_base_mul(P, _secp265k1_base, u1);
    mpECP_scalar_mul(Pq, sN->public_key, u2);
    mpECP_add(P, P, Pq);
    mpz_set_mpECP_affine_x(e, P);
    mpFp_set_mpz(p_n, e, _secp265k1->n);

    status = mpFp_cmp(p_n, sig->r);

    mpECP_clear(Pq);
    mpECP_clear(P);
    mpFp_clear(u2);
    mpFp_clear(u1);
    mpFp_clear(w);
    mpFp_clear(e_n);
    mpFp_clear(p_n);
    mpz_clear(e);

    return status;
}

static void _shift_right_and_zero_pad(unsigned char *buffer, size_t len, size_t shift) {
    int i;

    for (i = len-1; i >= shift; i--) {
        buffer[i] = buffer[i-shift];
    }
    for (i = shift - 1; i >= 0; i--) {
        buffer[i] = 0;
    }
    return;
}

unsigned char *ctNAKSignature_export_bytes(ctNAKSignature sig, size_t *sz) {
    mpz_t r;
    mpz_t s;
    unsigned char *buffer;
    unsigned char *br;
    unsigned char *bs;
    size_t bsz;

    mpz_init(r);
    mpz_init(s);

    if (_secp265k1 == NULL) _secp265k1_curve_init();

    buffer = (unsigned char *)malloc((_SECP256_N_BYTES << 1) * sizeof(char));
    br = buffer;
    bs = buffer + _SECP256_N_BYTES;
    assert(buffer != NULL);

    mpz_set_mpFp(r, sig->r);
    mpz_set_mpFp(s, sig->s);

    mpz_export(br, &bsz, 1, sizeof(char), 0, 0, r);
    assert(bsz <= _SECP256_N_BYTES);
    if (bsz < _SECP256_N_BYTES) {
        _shift_right_and_zero_pad(br, _SECP256_N_BYTES, _SECP256_N_BYTES - bsz);
    }

    mpz_export(bs, &bsz, 1, sizeof(char), 0, 0, s);
    assert(bsz <= _SECP256_N_BYTES);
    if (bsz < _SECP256_N_BYTES) {
        _shift_right_and_zero_pad(bs, _SECP256_N_BYTES, _SECP256_N_BYTES - bsz);
    }

    mpz_clear(s);
    mpz_clear(r);

    *sz = (_SECP256_N_BYTES << 1);
    return buffer;
}

int ctNAKSignature_init_import_bytes(ctNAKSignature sig, unsigned char *bsig, size_t sz) {
    mpz_t r;
    mpz_t s;
    unsigned char *br;
    unsigned char *bs;

    if (sz != (_SECP256_N_BYTES << 1)) {
        return -1;
    }

    br = bsig;
    bs = bsig + _SECP256_N_BYTES;

    mpz_init(r);
    mpz_init(s);

    mpz_import (r, _SECP256_N_BYTES, 1, sizeof(char), 0, 0, br);
    mpz_import (s, _SECP256_N_BYTES, 1, sizeof(char), 0, 0, bs);

    if ((mpz_cmp_ui(r, 0) <= 0) || (mpz_cmp_ui(s, 0) <= 0) ||
        (mpz_cmp(r, _secp265k1->n) >= 0) || (mpz_cmp(s, _secp265k1->n) >= 0)) {
        mpz_clear(s);
        mpz_clear(r);
        return -1;
    }

    mpFp_init(sig->r, _secp265k1->n);
    mpFp_set_mpz(sig->r, r, _secp265k1->n);
    mpFp_init(sig->s, _secp265k1->n);
    mpFp_set_mpz(sig->s, s, _secp265k1->n);
    mpz_clear(s);
    mpz_clear(r);
    return 0;
}

void ctNAKSignature_clear(ctNAKSignature sig) {
    mpFp_clear(sig->r);
    mpFp_clear(sig->s);
}

// signed PUBLIC Key (as present in blockchain xactions)
//unsigned char *ctNAKSignedPublicKey_init_ctNAKSecretKey(ctNAKSecretKey sN, size_t *sz);
//int ctNAKSignedPublicKey_init_import(ctNAKPublicKey pN, unsigned char *bin, size_t sz);
//int ctNAKSignedPublicKey_validate_cmp(unsigned char *bin, size_t sz);
