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
#include <ciphrtxt/keys.h>
#include <ciphrtxt/utime.h>
#include <fspke.h>
#include <inttypes.h>
#include <libtasn1.h>
//#include <portable_endian.h>
#include <sodium.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

extern const asn1_static_node ciphrtxt_asn1_tab[];

//The default configuration parameters provide for 512 bit prime field with
//384 bit group order. 

#define CT_DEFAULT_QBITS    (512U)
#define CT_DEFAULT_RBITS    (384U)

//The default configuration parameters provide forward security with granularity
//of 1 minute (60 seconds) for 16 million (16**6) intervals... or >31 years

#define CT_DEFAULT_DEPTH    (6U)
#define CT_DEFAULT_ORDER    (16U)
#define CT_DEFAULT_TSTEP    ((60U)*1000000)

// calculate x**e
static int64_t _pow_i64(int64_t x, int64_t e) {
    int64_t r = 1;
    int64_t i;

    assert(e < 64);
    for (i = 0; i < e; i++) {
        r *= x;
    }
    return r;
}

// negative intervals are always invalid... doesn't matter how negative

int64_t _ctSecretKey_interval_for_time(ctSecretKey_t sK, utime_t t) {
    if (t >= sK->t0) {
        return (int64_t)((t - sK->t0) / sK->tStep);
    } else {
        return -1;
    }
}

utime_t _ctSecretKey_time_for_interval(ctSecretKey_t sK, int64_t i) {
    return sK->t0 + (utime_t)(i * sK->tStep);
}

int64_t _ctPublicKey_interval_for_time(ctPublicKey_t pK, utime_t t) {
    if (t >= pK->t0) {
        return (int64_t)((t - pK->t0) / pK->tStep);
    } else {
        return -1;
    }
}

utime_t _ctPublicKey_time_for_interval(ctPublicKey_t pK, int64_t i) {
    return pK->t0 + (utime_t)(i * pK->tStep);
}

void ctSecretKey_init_Gen(ctSecretKey_t sK, int qbits, int rbits, int depth, int order, utime_t tStep) {
    int qb, rb, d, o;
    _ed25519pk test_mul;

    assert(sizeof(sK->addr_sec) == crypto_scalarmult_ed25519_SCALARBYTES);

    do {
        randombytes_buf(sK->addr_sec, sizeof(sK->addr_sec));
    } while (crypto_scalarmult_ed25519_base(test_mul, sK->addr_sec) != 0);

    do {
        randombytes_buf(sK->enc_sec, sizeof(sK->enc_sec));
    } while (crypto_scalarmult_ed25519_base(test_mul, sK->enc_sec) != 0);

    do {
        randombytes_buf(sK->sign_sec, sizeof(sK->sign_sec));
    } while (crypto_scalarmult_ed25519_base(test_mul, sK->sign_sec) != 0);

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
    
    CHKPKE_init_Gen(sK->chk_sec, qb, rb, d, o);

    // key is not defined for time before t0
    sK->t0 = getutime();

    if (tStep > 0) {
        sK->tStep = tStep;
    } else {
        sK->tStep = CT_DEFAULT_TSTEP;
    }

    sK->_intervalMin = 0;
    sK->_intervalMax = _pow_i64((int64_t)o, (int64_t)d);
}

void ctSecretKey_clear(ctSecretKey_t sK) {
    CHKPKE_clear(sK->chk_sec);
}

unsigned char *ctSecretKey_Export_FS_Delegate_DER(ctSecretKey_t sK, utime_t tStart, utime_t tEnd, size_t *sz) {
    ASN1_TYPE ct_asn1 = ASN1_TYPE_EMPTY;
    ASN1_TYPE sK_asn1 = ASN1_TYPE_EMPTY;
    char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    unsigned char *buffer;
    int result;
    size_t length;
    int sum;

    int64_t iStart, iEnd;

    iStart = _ctSecretKey_interval_for_time(sK, tStart);
    if (iStart < sK->_intervalMin) return NULL;
    iEnd = _ctSecretKey_interval_for_time(sK, tEnd);
    if (iEnd >= sK->_intervalMax) return NULL;
    if (iEnd < iStart) return NULL;

    sum = 0;

    result = asn1_array2tree(ciphrtxt_asn1_tab, &ct_asn1, asnError);
    if (result != 0) return NULL;

    result = asn1_create_element(ct_asn1, "Ciphrtxt.CTSecretKey",
        &sK_asn1);
    if (result != 0) {
        asn1_delete_structure(&ct_asn1);
        return NULL;
    }

    //printf("-----------------\n");
    //asn1_print_structure(stdout, sK_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    sum += _asn1_write_int64_as_integer(sK_asn1, "version", 1);
    sum += _asn1_write_uchar_string_as_octet_string(sK_asn1, "addr_sec", sK->addr_sec, sizeof(sK->addr_sec));
    sum += _asn1_write_uchar_string_as_octet_string(sK_asn1, "enc_sec", sK->enc_sec, sizeof(sK->enc_sec));
    sum += _asn1_write_uchar_string_as_octet_string(sK_asn1, "sign_sec", sK->sign_sec, sizeof(sK->sign_sec));
    buffer = CHKPKE_privkey_encode_delegate_DER(sK->chk_sec, iStart, iEnd, &length);
    if (buffer == NULL) {
        asn1_delete_structure(&sK_asn1);
        asn1_delete_structure(&ct_asn1);
        return NULL;
    }
    sum += _asn1_write_uchar_string_as_octet_string(sK_asn1, "chk_sec", buffer, length);
    sum += _asn1_write_int64_as_integer(sK_asn1, "t0", (int64_t)(sK->t0));
    sum += _asn1_write_int64_as_integer(sK_asn1, "tStep", (int64_t)(sK->tStep));

    //printf("-----------------\n");
    //asn1_print_structure(stdout, sK_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    sum += 256;  // pad for DER header + some extra just in case
    length = sum;
    buffer = (unsigned char *)malloc((sum) * sizeof(char));
    assert(buffer != NULL);
    {
        int isz = length;
        result = asn1_der_coding(sK_asn1, "", (char *)buffer, &isz, asnError);
        length = isz;
    }
    if (result != 0) {
        asn1_delete_structure(&sK_asn1);
        asn1_delete_structure(&ct_asn1);
        return NULL;
    }
    assert(length < sum);

    asn1_delete_structure(&sK_asn1);
    asn1_delete_structure(&ct_asn1);
    *sz = length;
    return buffer;
}

unsigned char *ctSecretKey_Export_FS_DER(ctSecretKey_t sK, utime_t tStart, size_t *sz) {
    utime_t tEnd;
    
    tEnd = _ctSecretKey_time_for_interval(sK, sK->_intervalMax - 1);
    return ctSecretKey_Export_FS_Delegate_DER(sK, tStart, tEnd, sz);
}

int ctSecretKey_init_decode_DER(ctSecretKey_t sK, unsigned char *der, size_t dsz) {
    ASN1_TYPE ct_asn1 = ASN1_TYPE_EMPTY;
    ASN1_TYPE sK_asn1 = ASN1_TYPE_EMPTY;
    char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    unsigned char *buffer;
    size_t  sz;
    int result;

    result = asn1_array2tree(ciphrtxt_asn1_tab, &ct_asn1, asnError);
    if (result != 0) return -1;

    result = asn1_create_element(ct_asn1, "Ciphrtxt.CTSecretKey",
        &sK_asn1);
    if (result != 0) {
        asn1_delete_structure(&ct_asn1);
        return -1;
    }

    //printf("-----------------\n");
    //asn1_print_structure(stdout, sK_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    // read DER into ASN1 structure
    result = asn1_der_decoding(&sK_asn1, (char *)der, (int)dsz, asnError);
    if (result != ASN1_SUCCESS) return -1;

    //printf("-----------------\n");
    //asn1_print_structure(stdout, sK_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    {
        int64_t ver;
        result = _asn1_read_int64_from_integer(&ver, sK_asn1, "version");
        // version 1 is only known version at this time
        if ((result != 0) || (ver != 1)) goto error_cleanup3;
    }

    // Read secret key from ASN1 structure
    buffer = _asn1_read_octet_string_as_uchar(sK_asn1, "addr_sec", &sz);
    if (sz != sizeof(sK->addr_sec)) goto error_cleanup1;
    memcpy((void *)sK->addr_sec, (void *)buffer, sz);
    memset((void *)buffer, 0, sz);
    free(buffer);

    buffer = _asn1_read_octet_string_as_uchar(sK_asn1, "enc_sec", &sz);
    if (sz != sizeof(sK->enc_sec)) goto error_cleanup1;
    memcpy((void *)sK->enc_sec, (void *)buffer, sz);
    memset((void *)buffer, 0, sz);
    free(buffer);

    buffer = _asn1_read_octet_string_as_uchar(sK_asn1, "sign_sec", &sz);
    if (sz != sizeof(sK->sign_sec)) goto error_cleanup1;
    memcpy((void *)sK->sign_sec, (void *)buffer, sz);
    memset((void *)buffer, 0, sz);
    free(buffer);

    buffer = _asn1_read_octet_string_as_uchar(sK_asn1, "chk_sec", &sz);
    result = CHKPKE_init_privkey_decode_DER(sK->chk_sec, buffer, sz);
    if (result != 0) goto error_cleanup1;
    memset((void *)buffer, 0, sz);
    free(buffer);

    result = _asn1_read_int64_from_integer(&(sK->t0), sK_asn1, "t0");
    if (result != 0) goto error_cleanup2;

    result = _asn1_read_int64_from_integer(&(sK->tStep), sK_asn1, "tStep");
    if (result != 0) goto error_cleanup2;
    
    sK->_intervalMin = CHKPKE_privkey_min_interval(sK->chk_sec);
    sK->_intervalMax = CHKPKE_privkey_max_interval(sK->chk_sec) + 1;
    if ((sK->_intervalMin == -1) || (sK->_intervalMax == -1)) goto error_cleanup2;

    asn1_delete_structure(&sK_asn1);
    asn1_delete_structure(&ct_asn1);
    return 0;

error_cleanup2:
    CHKPKE_clear(sK->chk_sec);
    asn1_delete_structure(&sK_asn1);
    asn1_delete_structure(&ct_asn1);
    return -1;

error_cleanup1:
    memset((void *)buffer, 0, sz);
    memset((void *)sK, 0, sizeof(*sK));

error_cleanup3:
    asn1_delete_structure(&sK_asn1);
    asn1_delete_structure(&ct_asn1);
    return -1;
}

void ctPublicKey_init_ctSecretKey(ctPublicKey_t pK, ctSecretKey_t sK) {
    unsigned char *chkder;
    size_t chkdersz;

    crypto_scalarmult_ed25519_base(pK->addr_pub, sK->addr_sec);
    crypto_scalarmult_ed25519_base(pK->enc_pub, sK->enc_sec);
    crypto_scalarmult_ed25519_base(pK->sign_pub, sK->sign_sec);
    chkder = CHKPKE_pubkey_encode_DER(sK->chk_sec, &chkdersz);
    CHKPKE_init_pubkey_decode_DER(pK->chk_pub, chkder, chkdersz);
    memset((void *)chkder, 0, chkdersz);
    free(chkder);
    pK->t0 = sK->t0;
    pK->tStep = sK->tStep;
}

void ctPublicKey_clear(ctPublicKey_t pK) {
    CHKPKE_clear(pK->chk_pub);
    memset((void *)pK, 0, sizeof(*pK));
}

unsigned char *ctPublicKey_Export_DER(ctPublicKey_t pK, size_t *sz) {
    ASN1_TYPE ct_asn1 = ASN1_TYPE_EMPTY;
    ASN1_TYPE pK_asn1 = ASN1_TYPE_EMPTY;
    char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    unsigned char *buffer;
    int result;
    size_t length;
    int sum;

    sum = 0;

    result = asn1_array2tree(ciphrtxt_asn1_tab, &ct_asn1, asnError);
    if (result != 0) return NULL;

    result = asn1_create_element(ct_asn1, "Ciphrtxt.CTPublicKey",
        &pK_asn1);
    if (result != 0) {
        asn1_delete_structure(&ct_asn1);
        return NULL;
    }

    //printf("-----------------\n");
    //asn1_print_structure(stdout, pK_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    sum += _asn1_write_int64_as_integer(pK_asn1, "version", 1);
    sum += _asn1_write_uchar_string_as_octet_string(pK_asn1, "addr_pub", pK->addr_pub, sizeof(pK->addr_pub));
    sum += _asn1_write_uchar_string_as_octet_string(pK_asn1, "enc_pub", pK->enc_pub, sizeof(pK->enc_pub));
    sum += _asn1_write_uchar_string_as_octet_string(pK_asn1, "sign_pub", pK->sign_pub, sizeof(pK->sign_pub));
    buffer = CHKPKE_pubkey_encode_DER(pK->chk_pub, &length);
    if (buffer == NULL) {
        asn1_delete_structure(&pK_asn1);
        asn1_delete_structure(&ct_asn1);
        return NULL;
    }
    sum += _asn1_write_uchar_string_as_octet_string(pK_asn1, "chk_pub", buffer, length);
    sum += _asn1_write_int64_as_integer(pK_asn1, "t0", (int64_t)(pK->t0));
    sum += _asn1_write_int64_as_integer(pK_asn1, "tStep", (int64_t)(pK->tStep));

    //printf("-----------------\n");
    //asn1_print_structure(stdout, pK_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    sum += 256;  // pad for DER header + some extra just in case
    length = sum;
    buffer = (unsigned char *)malloc((sum) * sizeof(char));
    assert(buffer != NULL);
    {
        int isz = length;
        result = asn1_der_coding(pK_asn1, "", (char *)buffer, &isz, asnError);
        length = isz;
    }
    if (result != 0) {
        asn1_delete_structure(&pK_asn1);
        asn1_delete_structure(&ct_asn1);
        return NULL;
    }
    assert(length < sum);

    asn1_delete_structure(&pK_asn1);
    asn1_delete_structure(&ct_asn1);
    *sz = length;
    return buffer;
}

int ctPublicKey_init_decode_DER(ctPublicKey_t pK, unsigned char *der, size_t dsz) {
    ASN1_TYPE ct_asn1 = ASN1_TYPE_EMPTY;
    ASN1_TYPE pK_asn1 = ASN1_TYPE_EMPTY;
    char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    unsigned char *buffer;
    size_t  sz;
    int result;

    result = asn1_array2tree(ciphrtxt_asn1_tab, &ct_asn1, asnError);
    if (result != 0) return -1;

    result = asn1_create_element(ct_asn1, "Ciphrtxt.CTPublicKey",
        &pK_asn1);
    if (result != 0) {
        asn1_delete_structure(&ct_asn1);
        return -1;
    }

    //printf("-----------------\n");
    //asn1_print_structure(stdout, pK_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    // read DER into ASN1 structure
    result = asn1_der_decoding(&pK_asn1, der, dsz, asnError);
    if (result != ASN1_SUCCESS) return -1;

    //printf("-----------------\n");
    //asn1_print_structure(stdout, pK_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    {
        int64_t ver;
        result = _asn1_read_int64_from_integer(&ver, pK_asn1, "version");
        // version 1 is only known version at this time
        if ((result != 0) || (ver != 1)) goto error_cleanup3;
    }

    // Read public key from ASN1 structure
    buffer = _asn1_read_octet_string_as_uchar(pK_asn1, "addr_pub", &sz);
    if (sz != sizeof(pK->addr_pub)) goto error_cleanup1;
    memcpy((void *)pK->addr_pub, (void *)buffer, sz);
    memset((void *)buffer, 0, sz);
    free(buffer);

    buffer = _asn1_read_octet_string_as_uchar(pK_asn1, "enc_pub", &sz);
    if (sz != sizeof(pK->enc_pub)) goto error_cleanup1;
    memcpy((void *)pK->enc_pub, (void *)buffer, sz);
    memset((void *)buffer, 0, sz);
    free(buffer);

    buffer = _asn1_read_octet_string_as_uchar(pK_asn1, "sign_pub", &sz);
    if (sz != sizeof(pK->sign_pub)) goto error_cleanup1;
    memcpy((void *)pK->sign_pub, (void *)buffer, sz);
    memset((void *)buffer, 0, sz);
    free(buffer);

    buffer = _asn1_read_octet_string_as_uchar(pK_asn1, "chk_pub", &sz);
    result = CHKPKE_init_pubkey_decode_DER(pK->chk_pub, buffer, sz);
    if (result != 0) goto error_cleanup1;
    memset((void *)buffer, 0, sz);
    free(buffer);

    result = _asn1_read_int64_from_integer(&(pK->t0), pK_asn1, "t0");
    if (result != 0) goto error_cleanup2;

    result = _asn1_read_int64_from_integer(&(pK->tStep), pK_asn1, "tStep");
    if (result != 0) goto error_cleanup2;
    
    asn1_delete_structure(&pK_asn1);
    asn1_delete_structure(&ct_asn1);
    return 0;

error_cleanup2:
    CHKPKE_clear(pK->chk_pub);
    asn1_delete_structure(&pK_asn1);
    asn1_delete_structure(&ct_asn1);
    return -1;

error_cleanup1:
    memset((void *)buffer, 0, sz);
    memset((void *)pK, 0, sizeof(*pK));
error_cleanup3:
    asn1_delete_structure(&pK_asn1);
    asn1_delete_structure(&ct_asn1);
    return -1;
}
