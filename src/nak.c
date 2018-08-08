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

static mpECurve_ptr _secp256k1 = NULL;
static mpECDSAHashfunc_ptr _sha256 = NULL;
static mpECDSASignatureScheme_ptr _sscheme = NULL;

extern const asn1_static_node ciphrtxt_asn1_tab[];

#define _SECP256_N_BYTES    (32U)

static void _wrap_libsodium_sha256(unsigned char *hash, unsigned char *msg, size_t sz) {
    int status;
    status = crypto_hash_sha256(hash, msg, (unsigned long long)sz);
    assert(status == 0);
    return;
}

static void _sscheme_clear(void) {
    assert(_sscheme != NULL);
    mpECDSASignatureScheme_clear(_sscheme);
    free(_sscheme);
    _sscheme = NULL;
    mpECDSAHashfunc_clear(_sha256);
    free(_sha256);
    _sha256 = NULL;
    mpECurve_clear(_secp256k1);
    free(_secp256k1);
    _secp256k1 = NULL;
    return;
}

static void _sscheme_init(void) {
    int status;

    _secp256k1 = (mpECurve_ptr)malloc(sizeof(mpECurve_t));
    assert(_secp256k1 != NULL);
    mpECurve_init(_secp256k1);
    status = mpECurve_set_named(_secp256k1, "secp256k1");
    assert(status == 0);
    _sha256 = (mpECDSAHashfunc_ptr)malloc(sizeof(mpECDSAHashfunc_t));
    assert(_sha256 != NULL);
    mpECDSAHashfunc_init(_sha256);
    _sha256->dohash = _wrap_libsodium_sha256;
    _sha256->hsz = crypto_hash_sha256_BYTES;
    _sscheme = (mpECDSASignatureScheme_ptr)malloc(sizeof(mpECDSASignatureScheme_t));
    assert(_sscheme != NULL);
    mpECDSASignatureScheme_init(_sscheme, _secp256k1, _sha256);
    atexit(&_sscheme_clear);
    return;
}

// create, delete, import export for SECRET Key
void ctNAKSecretKey_init_Gen(ctNAKSecretKey sN, utime_t nvb, utime_t nva) {
    if (_sscheme == NULL) _sscheme_init();
    sN->not_valid_before = nvb;
    sN->not_valid_after = nva;
    mpFp_init(sN->secret_key, _sscheme->cvp->n);
    mpFp_urandom(sN->secret_key, _sscheme->cvp->n);
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

    if (_sscheme == NULL) _sscheme_init();

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
    mpFp_init(sN->secret_key, _sscheme->cvp->n);
    status = _asn1_read_mpz_from_octet_string(tmpz, sN_asn1, "secret_key");
    if (status != 0) {
        mpz_clear(tmpz);
        goto error_cleanup2;
    }
    mpFp_set_mpz(sN->secret_key, tmpz, _sscheme->cvp->n);
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
    if (_sscheme == NULL) _sscheme_init();
    pN->not_valid_before = sN->not_valid_before;
    pN->not_valid_after = sN->not_valid_after;
    mpECP_init(pN->public_key, _sscheme->cvp);
    mpECP_scalar_base_mul(pN->public_key, _sscheme->cv_G, sN->secret_key);
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

    if (_sscheme == NULL) _sscheme_init();

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

        mpECP_init(pN->public_key, _sscheme->cvp);
        buffer = _asn1_read_octet_string_as_uchar(pN_asn1, "public_key", &sz);
        if (status != 0) {
            memset(buffer,0,sz);
            free(buffer);
            goto error_cleanup2;
        }
        mpECP_set_bytes(pN->public_key, buffer, sz, _sscheme->cvp);
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
int ctNAKSignature_init_Sign(mpECDSASignature_t sig, ctNAKSecretKey sN, unsigned char *msg, size_t sz) {
    if (_sscheme == NULL) _sscheme_init();
    return mpECDSASignature_init_Sign(sig, _sscheme, sN->secret_key, msg, sz);
}

int ctNAKSignature_verify_cmp(mpECDSASignature_t sig, ctNAKPublicKey pN, unsigned char *msg, size_t sz) {
    return mpECDSASignature_verify_cmp(sig, pN->public_key, msg, sz);
}

unsigned char *ctNAKSignature_export_bytes(mpECDSASignature_t sig, size_t *sz) {
    return mpECDSASignature_export_bytes(sig, sz);
}

int ctNAKSignature_init_import_bytes(mpECDSASignature_t sig, unsigned char *bsig, size_t sz) {
    if (_sscheme == NULL) _sscheme_init();
    return mpECDSASignature_init_import_bytes(sig, _sscheme, bsig, sz);
}

void ctNAKSignature_clear(mpECDSASignature_t sig) {
    mpECDSASignature_clear(sig);
    return;
}

// signed PUBLIC Key (as present in blockchain xactions)
//unsigned char *ctNAKSignedPublicKey_init_ctNAKSecretKey(ctNAKSecretKey sN, size_t *sz);
//int ctNAKSignedPublicKey_init_import(ctNAKPublicKey pN, unsigned char *bin, size_t sz);
//int ctNAKSignedPublicKey_validate_cmp(unsigned char *bin, size_t sz);
