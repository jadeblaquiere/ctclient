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
#include <fspke/cwhash.h>
#include <gmp.h>
#include <inttypes.h>
#include <libtasn1.h>
#include <portable_endian.h>
#include <sodium.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static mpECurve_ptr _curve = NULL;
static mpECP_ptr _G = NULL;
static mpECDSAHashfunc_ptr _hash = NULL;
static mpECDSASignatureScheme_ptr _sscheme = NULL;
static cwHash_ptr _aa_cwhash = NULL;

static char *_curvename = "secp256k1";
#define _CURVE_N_BYTES    (32U)
#define _CURVE_P_BYTES    (32U)

// constants for carter-wegman universal hash
// p = 2**414 - 17;
// q = order of secp256k1
// a = int(SHA512.new("Satoshi".encode()).hexdigest(),16) % p
// b = int(SHA512.new("Nakamoto".encode()).hexdigest(),16) % p
static char *_aa_cw_phex = "0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF";
static char *_aa_cw_qhex = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
static char *_aa_cw_ahex = "0x0B482D32C46A556562FE79AD8402820D52EB7D562463C021F23E33D6274E60845C19D6DC2989108474B45576E2B4F527BF9BCFBD";
static char *_aa_cw_bhex = "0x2CE9197AC7E9C5F81479E5C311F24362A4BFBE6C6BE45BF95031A5370762B69D6F915DE001ED04F5C6D6144F16074D0291D9623F";

extern const asn1_static_node ciphrtxt_asn1_tab[];


static void _wrap_libsodium_hash(unsigned char *hash, unsigned char *msg, size_t sz) {
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
    mpECDSAHashfunc_clear(_hash);
    free(_hash);
    _hash = NULL;
    mpECP_clear(_G);
    free(_G);
    _G = NULL;
    mpECurve_clear(_curve);
    free(_curve);
    _curve = NULL;
    cwHash_clear(_aa_cwhash);
    free(_aa_cwhash);
    _aa_cwhash = NULL;
    return;
}

static void _sscheme_init(void) {
    int status;

    _curve = (mpECurve_ptr)malloc(sizeof(mpECurve_t));
    assert(_curve != NULL);
    mpECurve_init(_curve);
    status = mpECurve_set_named(_curve, _curvename);
    assert(status == 0);
    _G = (mpECP_ptr)malloc(sizeof(mpECP_t));
    assert(_G != NULL);
    mpECP_init(_G, _curve);
    mpECP_set_mpz(_G, _curve->G[0], _curve->G[1], _curve);
    mpECP_scalar_base_mul_setup(_G);
    _hash = (mpECDSAHashfunc_ptr)malloc(sizeof(mpECDSAHashfunc_t));
    assert(_hash != NULL);
    mpECDSAHashfunc_init(_hash);
    _hash->dohash = _wrap_libsodium_hash;
    _hash->hsz = crypto_hash_sha256_BYTES;
    _sscheme = (mpECDSASignatureScheme_ptr)malloc(sizeof(mpECDSASignatureScheme_t));
    assert(_sscheme != NULL);
    mpECDSASignatureScheme_init(_sscheme, _curve, _hash);
    _aa_cwhash = (cwHash_ptr)malloc(sizeof(cwHash_t));
    assert(_aa_cwhash != NULL);
    {
        mpz_t a, b, p, q;
        mpz_init(a);
        mpz_init(b);
        mpz_init(p);
        mpz_init(q);

        mpz_set_str(a, _aa_cw_ahex, 0);
        mpz_set_str(b, _aa_cw_bhex, 0);
        mpz_set_str(p, _aa_cw_phex, 0);
        mpz_set_str(q, _aa_cw_qhex, 0);
        cwHash_init(_aa_cwhash, p);
        cwHash_set_mpz(_aa_cwhash, q, p, a, b);
        mpz_clear(q);
        mpz_clear(p);
        mpz_clear(b);
        mpz_clear(a);
    }

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
    mpFp_init(sN->secret_key_inv, _sscheme->cvp->n);
    mpFp_inv(sN->secret_key_inv, sN->secret_key);
    return;
}

void ctNAKSecretKey_clear(ctNAKSecretKey sN) {
    sN->not_valid_before = 0;
    sN->not_valid_after = 0;
    mpFp_clear(sN->secret_key);
    mpFp_clear(sN->secret_key_inv);
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
    mpFp_init(sN->secret_key_inv, _sscheme->cvp->n);
    mpFp_inv(sN->secret_key_inv, sN->secret_key);
    mpz_clear(tmpz);

    status = _asn1_read_int64_from_integer(&(sN->not_valid_before), sN_asn1, "not_before");
    if (status != 0) goto error_cleanup2;

    status = _asn1_read_int64_from_integer(&(sN->not_valid_after), sN_asn1, "not_after");
    if (status != 0) goto error_cleanup2;

    asn1_delete_structure(&sN_asn1);
    asn1_delete_structure(&ct_asn1);
    return 0;

error_cleanup2:
    mpFp_clear(sN->secret_key_inv);
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

static void _ctNak_mpFp_out_bytes(unsigned char *b, mpFp_t a) {
    size_t bsz = _CURVE_P_BYTES;
    size_t wsz;
    mpz_t ampz;

    mpz_init(ampz);
    mpz_set_mpFp(ampz, a);
    wsz = bsz;
    mpz_export(b, &wsz, 1, 1, 1, 0, ampz);
    if (wsz == bsz) return;

    assert(wsz < bsz);
    // if wsz < bsz we have a short write. shift right as required
    {
        int i;
        size_t shift = bsz - wsz;
        for (i = (wsz - 1); i >= 0; i--) {
            b[i+shift] = b[i];
        }
        for (i = 0; i < shift; i++) {
            b[i] = 0;
        }
    }
    return;
}

// signed PUBLIC Key (as present in blockchain xactions)
unsigned char *ctNAKSignedPublicKey_init_ctNAKSecretKey(ctNAKSecretKey sN, size_t *sz) {
    ctNAKPublicKey pN;
    mpECDSASignature_t sig;
    unsigned char *buffer;
    unsigned char *b;
    size_t bsz;
    int status;

    ctNAKPublicKey_init_ctNAKSecretKey(pN, sN);
    bsz = CTNAK_SIGNED_KEY_LENGTH;
    buffer = (unsigned char *)malloc(bsz * sizeof(char));

    b = buffer;
    mpECP_out_bytes(b, pN->public_key, 1);
    b += (1 + _CURVE_P_BYTES);
    *((int64_t *)b) = htole64((int64_t) sN->not_valid_before);
    b += sizeof(int64_t);
    *((int64_t *)b) = htole64((int64_t) sN->not_valid_after);
    b += sizeof(int64_t);

    assert((b - buffer) == (17 + _CURVE_P_BYTES));
    status = ctNAKSignature_init_Sign(sig, sN, buffer, 17 + _CURVE_P_BYTES);
    if (status != 0) {
        ctNAKSignature_clear(sig);
        ctNAKPublicKey_clear(pN);
        free(buffer);
        return NULL;
    }

    _ctNak_mpFp_out_bytes(b, sig->r);
    b += _CURVE_P_BYTES;
    _ctNak_mpFp_out_bytes(b, sig->s);
    b += _CURVE_P_BYTES;
    assert((b - buffer) == CTNAK_SIGNED_KEY_LENGTH);

    ctNAKSignature_clear(sig);
    ctNAKPublicKey_clear(pN);
    *sz = CTNAK_SIGNED_KEY_LENGTH;
    return buffer;
}

static void _ctNak_mpFp_set_bytes(mpFp_t a, unsigned char *b) {
    mpz_t ampz;

    mpz_init(ampz);
    mpz_import(ampz, _CURVE_P_BYTES, 1, sizeof(char), 1, 0, b);

    mpFp_set_mpz(a, ampz, _curve->n);
    mpz_clear(ampz);
    return;
}

int ctNAKSignedPublicKey_init_import(ctNAKPublicKey pN, unsigned char *bin, size_t sz) {
    unsigned char *b = bin;
    int result;

    if (_sscheme == NULL) _sscheme_init();

    // wrong length -> invalid
    if (sz != CTNAK_SIGNED_KEY_LENGTH) return -1;

    mpECP_init(pN->public_key, _curve);
    result = mpECP_set_bytes(pN->public_key, b, (1 + _CURVE_P_BYTES), _curve);
    // invalid curve point -> invalid
    if (result != 0) {
        mpECP_clear(pN->public_key);
        return -1;
    }
    b += (1 + _CURVE_P_BYTES);

    pN->not_valid_before = le64toh(*((utime_t *)b));
    b += sizeof(utime_t);
    pN->not_valid_after = le64toh(*((utime_t *)b));
    return 0;
}

int ctNAKSignedPublicKey_validate_cmp(unsigned char *bin, size_t sz) {
    unsigned char *b = bin;
    ctNAKPublicKey pN;
    mpECDSASignature_t sig;
    int result;

    result = ctNAKSignedPublicKey_init_import(pN, bin, sz);
    if (result != 0) return -1;

    b = bin + (17 + _CURVE_P_BYTES);
    sig->sscheme = _sscheme;
    mpFp_init(sig->r, _sscheme->cvp->n);
    _ctNak_mpFp_set_bytes(sig->r, b);
    b += _CURVE_P_BYTES;
    mpFp_init(sig->s, _sscheme->cvp->n);
    _ctNak_mpFp_set_bytes(sig->s, b);

    result = ctNAKSignature_verify_cmp(sig, pN, bin, (17 + _CURVE_P_BYTES));

    mpECDSASignature_clear(sig);
    ctNAKPublicKey_clear(pN);
    return result;
}

// Slamanig's Anonymous Authentication method requires deterministic encryption
// but can leverage probablistic encryption models using a subtitution for
// the random value. The method used is based on the model proposed and
// analyzed in "Deterministic and Efficiently Searchable Encryption" (Bellare,
// Boldyreva, O'Neill 2006), which uses a hash function H(pk || ptxt) in place
// of the random value k, assuming ptxt is itself a random value this method
// is only negligibly less secure than using a pure random k

// 1 + 32 + 32 to include the format tag (0x04) and x,y coordinates
#define secp256k1_uncompressed_BYTES    (65U)

int _mpECElgamal_init_encrypt_deterministic(mpECElgamalCiphertext_t ctxt, mpECP_t pK, mpECP_t ptxt) {
    mpFp_t k;

    if (_sscheme == NULL) _sscheme_init();
    if (mpECurve_cmp(pK->cvp, ptxt->cvp) != 0) {
        return -1;
    }
    mpFp_init(k, pK->cvp->n);

    // for uniform hashing, H() = CWHash(SHA512(pKx || pKy || pTx || pTy))
    {
        unsigned char shash[crypto_hash_sha512_BYTES];
        unsigned char pKpT[(secp256k1_uncompressed_BYTES * 2)];
        mpz_t t;
        int status;

        assert(mpECP_out_bytelen(pK, 0) == secp256k1_uncompressed_BYTES);
        mpECP_out_bytes(pKpT, pK, 0);
        mpECP_out_bytes(pKpT + secp256k1_uncompressed_BYTES, pK, 0);
        status = crypto_hash_sha512(shash, pKpT, secp256k1_uncompressed_BYTES * 2);
        assert(status == 0);
        mpz_init(t);
        mpz_import(t, crypto_hash_sha512_BYTES, 1, 1, 1, 0, shash);
        cwHash_hashval(t, _aa_cwhash, t);
        mpFp_set_mpz(k, t, pK->cvp->n);
        mpz_clear(t);
    }
    if (mpFp_cmp_ui(k, 0) == 0) {
        mpFp_clear(k);
        return -1;
    }

    mpECP_init(ctxt->C, pK->cvp);
    mpECP_init(ctxt->D, pK->cvp);
    mpECP_set_mpz(ctxt->C, pK->cvp->G[0], pK->cvp->G[1], pK->cvp);
    mpECP_scalar_mul(ctxt->C, ctxt->C, k);

    mpECP_scalar_mul(ctxt->D, pK, k);
    mpECP_add(ctxt->D, ctxt->D, ptxt);

    mpFp_clear(k);
    return 0;
}

//typedef struct {
//    int n;
//    mpECElgamalCiphertext_t *ctxt;
//    mpECP_t *pK;
//    mpECP_t session_pK;
//    utime_t session_expire;
//} _ctNAKAuthChallenge;

int ctNAKAuthChallenge_init(ctNAKAuthChallenge_t c, int n, ctNAKPublicKey *pN, mpECP_t session_pK, utime_t expire, mpECP_t ptxt) {
    int i;

    if (_sscheme == NULL) _sscheme_init();

    // validate input
    if (mpECurve_cmp(session_pK->cvp, _curve) != 0) {
        return -1;
    }
    // validate curve of pK[i], ensure session_pK not in set
    for (i = 0; i < n; i++) {
        if ((mpECurve_cmp(pN[i]->public_key->cvp, session_pK->cvp) != 0) || 
            (mpECP_cmp(pN[i]->public_key, session_pK) == 0)) {
            return -1;
        }
    }
    c->ctxt = (mpECElgamalCiphertext_t *)malloc(n * sizeof(mpECElgamalCiphertext_t));
    assert(c->ctxt != NULL);
    c->pK = (mpECP_t *)malloc(n * sizeof(mpECP_t));
    assert(c->ctxt != NULL);

    // encrypt random value r with each pK
    for (i = 0; i < n; i++) {
        int status;

        mpECP_init(c->pK[i], _curve);
        mpECP_set(c->pK[i], pN[i]->public_key);
        status = _mpECElgamal_init_encrypt_deterministic(c->ctxt[i], c->pK[i], ptxt);
        if (status != 0) {
            mpECP_clear(c->pK[i]);
            i--;
            while (i >= 0) {
                mpECElgamal_clear(c->ctxt[i]);
                mpECP_clear(c->pK[i]);
                i--;
            }
            free(c->pK);
            free(c->ctxt);
            return -1;
        }
    }
    mpECP_init(c->session_pK, _curve);
    mpECP_set(c->session_pK, session_pK);
    c->n = n;
    c->session_expire = expire;

    return 0;
}

void ctNAKAuthChallenge_clear(ctNAKAuthChallenge_t c) {
    int i;

    mpECP_clear(c->session_pK);
    for (i = 0; i < c->n; i++) {
        mpECP_clear(c->pK[i]);
        mpECElgamal_clear(c->ctxt[i]);
    }
    free(c->pK);
    free(c->ctxt);
    mpECP_clear(c->session_pK);
    c->session_expire = 0;
    c->n = 0;
    return;
}

unsigned char *ctNAKAuthChallenge_export_DER(ctNAKAuthChallenge_t c, size_t *sz) {
    ASN1_TYPE ct_asn1 = ASN1_TYPE_EMPTY;
    ASN1_TYPE nach_asn1 = ASN1_TYPE_EMPTY;
    char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    unsigned char *buffer;
    size_t bsz;
    int result;
    size_t length;
    int sum;
    int i;

    // refuse to export a degenerate (n = 0) challenge
    if (c->n < 1) return NULL;

    sum = 0;

    result = asn1_array2tree(ciphrtxt_asn1_tab, &ct_asn1, asnError);
    if (result != 0) return NULL;

    result = asn1_create_element(ct_asn1, "Ciphrtxt.CTNAKAuthChallenge",
        &nach_asn1);
    if (result != 0) {
        asn1_delete_structure(&ct_asn1);
        return NULL;
    }

    //printf("-----------------\n");
    //asn1_print_structure(stdout, nach_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    bsz = mpECP_out_bytelen(c->session_pK, 1);
    buffer = (unsigned char *)malloc(bsz*sizeof(char));

    sum += _asn1_write_int64_as_integer(nach_asn1, "version", 1);
    for (i = 0; i < c->n; i++) {
            result = asn1_write_value (nach_asn1, "challenge", "NEW", 1);
            assert(result == 0);
            sum += 12;

            mpECP_out_bytes(buffer, c->pK[i], 1);
            sum += _asn1_write_uchar_string_as_octet_string(nach_asn1, "challenge.?LAST.public_key", buffer, bsz);
            mpECP_out_bytes(buffer, c->ctxt[i]->C, 1);
            sum += _asn1_write_uchar_string_as_octet_string(nach_asn1, "challenge.?LAST.ctxt.c", buffer, bsz);
            mpECP_out_bytes(buffer, c->ctxt[i]->D, 1);
            sum += _asn1_write_uchar_string_as_octet_string(nach_asn1, "challenge.?LAST.ctxt.d", buffer, bsz);
    }
    mpECP_out_bytes(buffer, c->session_pK, 1);
    sum += _asn1_write_uchar_string_as_octet_string(nach_asn1, "session_pk", buffer, bsz);
    free(buffer);
    sum += _asn1_write_int64_as_integer(nach_asn1, "expire", (int64_t)c->session_expire);

    sum += 256;  // pad for DER header + some extra just in case
    length = sum;
    buffer = (unsigned char *)malloc((sum) * sizeof(char));
    assert(buffer != NULL);
    {
        int isz = length;
        result = asn1_der_coding(nach_asn1, "", (char *)buffer, &isz, asnError);
        length = isz;
    }
    if (result != 0) {
        asn1_delete_structure(&nach_asn1);
        asn1_delete_structure(&ct_asn1);
        return NULL;
    }
    assert(length < sum);

    asn1_delete_structure(&nach_asn1);
    asn1_delete_structure(&ct_asn1);
    *sz = length;
    return buffer;
}

int ctNAKAuthChallenge_init_import_DER(ctNAKAuthChallenge_t c, unsigned char *der, size_t dsz) {
    ASN1_TYPE ct_asn1 = ASN1_TYPE_EMPTY;
    ASN1_TYPE nach_asn1 = ASN1_TYPE_EMPTY;
    char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    unsigned char *buffer;
    size_t  bsz;
    size_t  sz;
    int result;
    int i,n;

    if (_sscheme == NULL) _sscheme_init();

    result = asn1_array2tree(ciphrtxt_asn1_tab, &ct_asn1, asnError);
    if (result != 0) return -1;

    result = asn1_create_element(ct_asn1, "Ciphrtxt.CTNAKAuthChallenge",
        &nach_asn1);
    if (result != 0) {
        asn1_delete_structure(&ct_asn1);
        return -1;
    }

    //printf("-----------------\n");
    //asn1_print_structure(stdout, nach_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    // read DER into ASN1 structure
    result = asn1_der_decoding(&nach_asn1, (char *)der, (int)dsz, asnError);
    if (result != ASN1_SUCCESS) return -1;

    //printf("-----------------\n");
    //asn1_print_structure(stdout, nach_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    {
        int64_t ver;
        result = _asn1_read_int64_from_integer(&ver, nach_asn1, "version");
        // version 1 is only known version at this time
        if ((result != 0) || (ver != 1)) goto error_cleanup3;
    }

    bsz = mpECP_out_bytelen(_G, 1);

    // Read secret key from ASN1 structure
    buffer = _asn1_read_octet_string_as_uchar(nach_asn1, "session_pk", &sz);
    if ((buffer == NULL) || (sz != bsz)) goto error_cleanup3;
    mpECP_init(c->session_pK, _curve);
    result = mpECP_set_bytes(c->session_pK, buffer, sz, _curve);
    if (result != 0) goto error_cleanup2;
    memset((void *)buffer, 0, sz);
    free(buffer);

    result = _asn1_read_int64_from_integer(&(c->session_expire), nach_asn1, "expire");
    if (result != 0) goto error_cleanup2;

    n = 0;
    // first time through just count the number of keys
    while(true) {
        char abuffer[256];

        sprintf(abuffer, "challenge.?%d.public_key", n+1);
        buffer = _asn1_read_octet_string_as_uchar(nach_asn1, abuffer, &sz);
        if (buffer == NULL) break;
        memset((void *)buffer, 0, sz);
        free(buffer);

        n += 1;
    }

    if (n == 0) goto error_cleanup2;

    c->pK = (mpECP_t *)malloc(n*sizeof(mpECP_t));
    c->ctxt = (mpECElgamalCiphertext_t *)malloc(n*sizeof(mpECElgamalCiphertext_t));

    for (i = 0; i < n; i++) {
        char abuffer[256];

        sprintf(abuffer, "challenge.?%d.public_key", i+1);
        buffer = _asn1_read_octet_string_as_uchar(nach_asn1, abuffer, &sz);
        if (buffer == NULL) goto error_cleanup1;
        mpECP_init(c->pK[i], _curve);
        result = mpECP_set_bytes(c->pK[i], buffer, sz, _curve);
        if (result != 0) {
            mpECP_clear(c->pK[i]);
            goto error_cleanup1;
        }
        memset((void *)buffer, 0, sz);
        free(buffer);

        sprintf(abuffer, "challenge.?%d.ctxt.c", i+1);
        buffer = _asn1_read_octet_string_as_uchar(nach_asn1, abuffer, &sz);
        if (buffer == NULL) {
            mpECP_clear(c->pK[i]);
            goto error_cleanup1;
        }
        mpECP_init(c->ctxt[i]->C, _curve);
        result = mpECP_set_bytes(c->ctxt[i]->C, buffer, sz, _curve);
        if (result != 0) {
            mpECP_clear(c->pK[i]);
            mpECP_clear(c->ctxt[i]->C);
            goto error_cleanup1;
        }
        memset((void *)buffer, 0, sz);
        free(buffer);

        sprintf(abuffer, "challenge.?%d.ctxt.d", i+1);
        buffer = _asn1_read_octet_string_as_uchar(nach_asn1, abuffer, &sz);
        if (buffer == NULL) {
            mpECP_clear(c->pK[i]);
            mpECP_clear(c->ctxt[i]->C);
            goto error_cleanup1;
        }
        mpECP_init(c->ctxt[i]->D, _curve);
        result = mpECP_set_bytes(c->ctxt[i]->D, buffer, sz, _curve);
        if (result != 0) {
            i += 1;
            goto error_cleanup1;
        }
        memset((void *)buffer, 0, sz);
        free(buffer);
    }

    c->n = n;
    return 0;

error_cleanup1:
    for (n = 0; n < i; n++) {
        mpECP_clear(c->pK[i]);
        mpECP_clear(c->ctxt[i]->C);
        mpECP_clear(c->ctxt[i]->D);
    }
    free(c->pK);
    c->pK = NULL;
    free(c->ctxt);
    c->ctxt = NULL;

error_cleanup2:
    c->session_expire = 0;
    mpECP_clear(c->session_pK);

error_cleanup3:
    asn1_delete_structure(&nach_asn1);
    asn1_delete_structure(&ct_asn1);
    return -1;
}

int ctNAKAuthResponse_init(ctNAKAuthResponse_t r, ctNAKAuthChallenge_t c, ctNAKSecretKey sN) {
    ctNAKPublicKey pN;
    int i;

    if (_sscheme == NULL) _sscheme_init();

    // validate input challenge, all on the same curve, session key not in set
    if (mpECurve_cmp(c->session_pK->cvp, _curve) != 0) {
        return -1;
    }
    for (i = 0; i < c->n; i++) {
        if (mpECurve_cmp(c->pK[i]->cvp, _curve) != 0) {
            return -1;
        }
        if (mpECP_cmp(c->pK[i], c->session_pK) == 0) {
            return -1;
        }
        if (mpECurve_cmp(c->ctxt[i]->C->cvp, _curve) != 0) {
            return -1;
        }
        if (mpECurve_cmp(c->ctxt[i]->D->cvp, _curve) != 0) {
            return -1;
        }
    }

    ctNAKPublicKey_init_ctNAKSecretKey(pN, sN);
    
    for (i = 0; i < c->n; i++) {
        if (mpECP_cmp(c->pK[i], pN->public_key) == 0) {
            mpECP_t rpt;
            int status;
            int j;
            
            status = mpECElgamal_init_decrypt(rpt, sN->secret_key, c->ctxt[i]);
            if (status != 0) goto cleanup1;

            // validate that the server hasn't tried to compromise privacy
            for (j = 0; j < c->n; j++) {
                mpECElgamalCiphertext_t ct;

                if (j == i) continue;
                status = _mpECElgamal_init_encrypt_deterministic(ct, c->pK[j], rpt);
                if ((mpECP_cmp(ct->C, c->ctxt[j]->C) != 0) ||
                    (mpECP_cmp(ct->D, c->ctxt[j]->D) != 0)) {
                    mpECP_clear(rpt);
                    mpECElgamal_clear(ct);
                    ctNAKPublicKey_clear(pN);
                    return -1;
                }
                mpECElgamal_clear(ct);
            }
            ctNAKPublicKey_clear(pN);
            // copy session key from challenge
            mpECP_init(r->session_pK, c->session_pK->cvp);
            mpECP_set(r->session_pK, c->session_pK);
            // encrypt secret (r) for session key
            status = mpECElgamal_init_encrypt(r->ctxt, c->session_pK, rpt);
            mpECP_clear(rpt);
            if (status != 0) {
                mpECP_clear(r->session_pK);
                return -1;
            }
            return 0;
        }
    }

cleanup1:
    ctNAKPublicKey_clear(pN);
    return -1;
}


int ctNAKAuthResponse_validate_cmp(ctNAKAuthResponse_t r, mpFp_t session_sK, mpECP_t ptxt) {
    //mpECurve_ptr cvp;
    mpECP_t pchk;
    //mpECP_t session_pK;
    int status;
    
    if (_sscheme == NULL) _sscheme_init();

    // validate input
    mpECP_init(pchk, _curve);
    mpECP_scalar_base_mul(pchk, _G, session_sK);
    if (mpECP_cmp(pchk, r->session_pK) != 0) {
        mpECP_clear(pchk);
        return -1;
    }
    mpECP_clear(pchk);
    if ((mpECurve_cmp(r->ctxt->C->cvp, _curve) != 0) ||
        (mpECurve_cmp(r->ctxt->D->cvp, _curve) != 0)) {
        return -1;
    }

    status = mpECElgamal_init_decrypt(pchk, session_sK, r->ctxt);
    if (status != 0) {
        return -1;
    }
    status = mpECP_cmp(pchk, ptxt);
    mpECP_clear(pchk);

    return status;
}

unsigned char *ctNAKAuthResponse_export_DER(ctNAKAuthResponse_t r, size_t *sz) {
    ASN1_TYPE ct_asn1 = ASN1_TYPE_EMPTY;
    ASN1_TYPE nar_asn1 = ASN1_TYPE_EMPTY;
    char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    unsigned char *buffer;
    size_t bsz;
    int result;
    size_t length;
    int sum;

    sum = 0;

    result = asn1_array2tree(ciphrtxt_asn1_tab, &ct_asn1, asnError);
    if (result != 0) return NULL;

    result = asn1_create_element(ct_asn1, "Ciphrtxt.CTNAKAuthResponse",
        &nar_asn1);
    if (result != 0) {
        asn1_delete_structure(&ct_asn1);
        return NULL;
    }

    //printf("-----------------\n");
    //asn1_print_structure(stdout, nar_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    bsz = mpECP_out_bytelen(r->session_pK, 1);
    buffer = (unsigned char *)malloc(bsz*sizeof(char));

    sum += _asn1_write_int64_as_integer(nar_asn1, "version", 1);
    mpECP_out_bytes(buffer, r->session_pK, 1);
    sum += _asn1_write_uchar_string_as_octet_string(nar_asn1, "session_pk", buffer, bsz);
    mpECP_out_bytes(buffer, r->ctxt->C, 1);
    sum += _asn1_write_uchar_string_as_octet_string(nar_asn1, "ctxt.c", buffer, bsz);
    mpECP_out_bytes(buffer, r->ctxt->D, 1);
    sum += _asn1_write_uchar_string_as_octet_string(nar_asn1, "ctxt.d", buffer, bsz);
    free(buffer);

    sum += 256;  // pad for DER header + some extra just in case
    length = sum;
    buffer = (unsigned char *)malloc((sum) * sizeof(char));
    assert(buffer != NULL);
    {
        int isz = length;
        result = asn1_der_coding(nar_asn1, "", (char *)buffer, &isz, asnError);
        length = isz;
    }
    if (result != 0) {
        asn1_delete_structure(&nar_asn1);
        asn1_delete_structure(&ct_asn1);
        return NULL;
    }
    assert(length < sum);

    asn1_delete_structure(&nar_asn1);
    asn1_delete_structure(&ct_asn1);
    *sz = length;
    return buffer;
}

int ctNAKAuthResponse_init_import_DER(ctNAKAuthResponse_t r, unsigned char *der, size_t dsz) {
    ASN1_TYPE ct_asn1 = ASN1_TYPE_EMPTY;
    ASN1_TYPE nar_asn1 = ASN1_TYPE_EMPTY;
    char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    unsigned char *buffer;
    size_t  bsz;
    size_t  sz;
    int result;

    if (_sscheme == NULL) _sscheme_init();

    result = asn1_array2tree(ciphrtxt_asn1_tab, &ct_asn1, asnError);
    if (result != 0) return -1;

    result = asn1_create_element(ct_asn1, "Ciphrtxt.CTNAKAuthResponse",
        &nar_asn1);
    if (result != 0) {
        asn1_delete_structure(&ct_asn1);
        return -1;
    }

    //printf("-----------------\n");
    //asn1_print_structure(stdout, nar_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    // read DER into ASN1 structure
    result = asn1_der_decoding(&nar_asn1, (char *)der, (int)dsz, asnError);
    if (result != ASN1_SUCCESS) return -1;

    //printf("-----------------\n");
    //asn1_print_structure(stdout, nar_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    {
        int64_t ver;
        result = _asn1_read_int64_from_integer(&ver, nar_asn1, "version");
        // version 1 is only known version at this time
        if ((result != 0) || (ver != 1)) goto error_cleanup3;
    }

    bsz = mpECP_out_bytelen(_G, 1);

    // Read secret key from ASN1 structure
    buffer = _asn1_read_octet_string_as_uchar(nar_asn1, "session_pk", &sz);
    if ((buffer == NULL) || (sz != bsz)) goto error_cleanup3;
    mpECP_init(r->session_pK, _curve);
    result = mpECP_set_bytes(r->session_pK, buffer, sz, _curve);
    if (result != 0) goto error_cleanup2;
    memset((void *)buffer, 0, sz);
    free(buffer);

    // Read secret key from ASN1 structure
    buffer = _asn1_read_octet_string_as_uchar(nar_asn1, "ctxt.c", &sz);
    if ((buffer == NULL) || (sz != bsz)) goto error_cleanup2;
    mpECP_init(r->ctxt->C, _curve);
    result = mpECP_set_bytes(r->ctxt->C, buffer, sz, _curve);
    if (result != 0) goto error_cleanup1;
    memset((void *)buffer, 0, sz);
    free(buffer);

    // Read secret key from ASN1 structure
    buffer = _asn1_read_octet_string_as_uchar(nar_asn1, "ctxt.d", &sz);
    if ((buffer == NULL) || (sz != bsz)) goto error_cleanup1;
    mpECP_init(r->ctxt->D, _curve);
    result = mpECP_set_bytes(r->ctxt->D, buffer, sz, _curve);
    if (result != 0) goto error_cleanup0;
    memset((void *)buffer, 0, sz);
    free(buffer);

    return 0;

error_cleanup0:
    mpECP_clear(r->ctxt->D);

error_cleanup1:
    mpECP_clear(r->ctxt->C);

error_cleanup2:
    mpECP_clear(r->session_pK);

error_cleanup3:
    asn1_delete_structure(&nar_asn1);
    asn1_delete_structure(&ct_asn1);
    return -1;
}

void ctNAKAuthResponse_clear(ctNAKAuthResponse_t r) {
    mpECP_clear(r->session_pK);
    mpECElgamal_clear(r->ctxt);
    return;
}
