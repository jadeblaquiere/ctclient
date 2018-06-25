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
#include <inttypes.h>
#include <libtasn1.h>
//#include <portable_endian.h>
#include <sodium.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

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

int64_t _ctSecretKey_interval_for_time(ctSecretKey sK, int64_t t) {
    if (t >= sK->t0) {
        return (t - sK->t0) / sK->tStep;
    } else {
        return -1;
    }
}

int64_t _ctSecretKey_time_for_interval(ctSecretKey sK, int64_t i) {
    return sK->t0 + (i * sK->tStep);
}

int64_t _ctPublicKey_interval_for_time(ctPublicKey pK, int64_t t) {
    if (t >= pK->t0) {
        return (t - pK->t0) / pK->tStep;
    } else {
        return -1;
    }
}

int64_t _ctPublicKey_time_for_interval(ctPublicKey pK, int64_t i) {
    return pK->t0 + (i * pK->tStep);
}

void ctSecretKey_init_GEN(ctSecretKey sK, int qbits, int rbits, int depth, int order, int64_t tStep) {
    struct timeval tv;
    int qb, rb, d, o;

    assert(sizeof(sK->addr_sec) == crypto_scalarmult_ed25519_SCALARBYTES);
    randombytes_buf(sK->addr_sec, sizeof(sK->addr_sec));
    randombytes_buf(sK->enc_sec, sizeof(sK->enc_sec));
    randombytes_buf(sK->sign_sec, sizeof(sK->sign_sec));

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
    gettimeofday(&tv, NULL);
    sK->t0 = (1000000 * ((int64_t)tv.tv_sec)) + ((int64_t)tv.tv_usec);

    if (tStep > 0) {
        sK->tStep = tStep;
    } else {
        sK->tStep = CT_DEFAULT_TSTEP;
    }

    sK->_intervalMin = 0;
    sK->_intervalMax = _pow_i64((int64_t)o, (int64_t)d);
}

void ctSecretKey_clear(ctSecretKey sK) {
    CHKPKE_clear(sK->chk_sec);
}

static int _asn1_write_uchar_string_as_octet_string(asn1_node root, char *attribute, unsigned char *buffer, int len) {
    int result;

    result = asn1_write_value(root, attribute, buffer, len);
    //if (result != ASN1_SUCCESS) {
    //    int i;
    //    printf("error writing ");
    //    for (i = 0; i < lwrote; i++) {
    //        printf("%02X", buffer[i]);
    //    }
    //    printf(" to tag : %s\n", attribute);
    //}
    assert(result == ASN1_SUCCESS);
    return 5 + len;
}

static int _asn1_write_int64_as_integer(asn1_node root, char *attribute, int64_t value) {
    int nbytes;
    int result;
    char *buffer;
    if (value < 0) {
        if (value > (-((1ll << 7 ) - 1))) {
            nbytes = 1;
        } else if (value > (-((1ll << 15) - 1))) {
            nbytes = 2;
        } else if (value > (-((1ll << 31) - 1))) {
            nbytes = 4;
        } else {
            nbytes = 8;
        }
    } else {
        if (value < (1 << 7)) {
            nbytes = 1;
        } else if (value < (1ll << 15)) {
            nbytes = 2;
        } else if (value < (1ll << 31)) {
            nbytes = 4;
        } else {
            nbytes = 8;
        }
    }
    buffer = (char *)malloc((nbytes + 2) * sizeof(char));
    assert(buffer != NULL);
    sprintf(buffer,"%" PRId64, value);
    //printf("writing %ld (%s), length %d to %s\n", value, buffer, nbytes, attribute);
    result = asn1_write_value(root, attribute, buffer, 0);
    //printf("returned %d\n", result);
    assert(result == ASN1_SUCCESS);
    memset((void *)buffer, 0, nbytes);
    free(buffer);
    return 5 + nbytes;
}

extern const asn1_static_node ciphrtxt_asn1_tab[];

unsigned char *ctSecretKey_Export_FS_Delegate_DER(ctSecretKey sK, int64_t tStart, int64_t tEnd, size_t *sz) {
    ASN1_TYPE ct_asn1 = ASN1_TYPE_EMPTY;
    ASN1_TYPE sK_asn1 = ASN1_TYPE_EMPTY;
    char asnError[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    unsigned char *buffer;
    int result;
    int length;
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

    sum += _asn1_write_uchar_string_as_octet_string(sK_asn1, "addr_sec", sK->addr_sec, sizeof(sK->addr_sec));
    sum += _asn1_write_uchar_string_as_octet_string(sK_asn1, "enc_sec", sK->enc_sec, sizeof(sK->enc_sec));
    sum += _asn1_write_uchar_string_as_octet_string(sK_asn1, "sign_sec", sK->sign_sec, sizeof(sK->sign_sec));
    buffer = (unsigned char *)CHKPKE_privkey_encode_delegate_DER(sK->chk_sec, iStart, iEnd, &length);
    if (buffer == NULL) {
        asn1_delete_structure(&sK_asn1);
        asn1_delete_structure(&ct_asn1);
        return NULL;
    }
    sum += _asn1_write_uchar_string_as_octet_string(sK_asn1, "chk_sec", buffer, length);
    sum += _asn1_write_int64_as_integer(sK_asn1, "t0", sK->t0);
    sum += _asn1_write_int64_as_integer(sK_asn1, "tStep", sK->tStep);

    //printf("-----------------\n");
    //asn1_print_structure(stdout, sK_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    sum += 256;  // pad for DER header + some extra just in case
    length = sum;
    buffer = (unsigned char *)malloc((sum) * sizeof(char));
    assert(buffer != NULL);
    result = asn1_der_coding(sK_asn1, "", (char *)buffer, &length, asnError);
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

unsigned char *ctSecretKey_Export_FS_DER(ctSecretKey sK, int64_t tStart, size_t *sz) {
    int64_t tEnd;
    
    tEnd = _ctSecretKey_time_for_interval(sK, sK->_intervalMax - 1);
    return ctSecretKey_Export_FS_Delegate_DER(sK, tStart, tEnd, sz);
}

static unsigned char *_asn1_read_octet_string(asn1_node root, char *attribute, size_t *sz) {
    int result, length, lread;
    unsigned char *buffer;

    // call read_value with NULL buffer to get length
    length = 0;
    result = asn1_read_value(root, attribute, NULL, &length);
    //printf("result = %d\n", result);
    if (result != ASN1_MEM_ERROR) return NULL;
    //assert(result == ASN1_MEM_ERROR);
    if (length <= 0) return NULL;
    //assert(length > 0);
    // allocate
    buffer = (unsigned char *)malloc((length+1)*sizeof(char));
    assert(buffer != NULL);
    lread = length + 1;
    result = asn1_read_value(root, attribute, (char *)buffer, &lread);
    if (result != ASN1_SUCCESS) goto cleanup_on_error;
    //assert(result == 0);
    if (lread != length) goto cleanup_on_error;
    //assert(lread == length);
    *sz = lread;
    return buffer;
    
cleanup_on_error:
    free(buffer);
    return NULL;
}

static int _asn1_read_int64_from_integer(int64_t *value, asn1_node root, char *attribute) {
    int result, length, lread;
    uint64_t uvalue = 0;
    //char *buffer;

    assert(sizeof(int64_t) == 8);
    // call read_value with NULL buffer to get length
    length = 0;
    result = asn1_read_value(root, attribute, NULL, &length);
    //printf("result = %d\n", result);
    if (result != ASN1_MEM_ERROR) return -1;
    //assert(result == ASN1_MEM_ERROR);
    if (length <= 0) return -1;
    //assert(length > 0);
    if (length > sizeof(int64_t)) return -1;
    lread = sizeof(int64_t);
    result = asn1_read_value(root, attribute, &uvalue, &lread);
    if (result != ASN1_SUCCESS) return -1;
    //assert(result == 0);
    if (lread != length) return -1;
    //assert(lread == length);
    //{
    //    unsigned char *bytes;
    //    int i;
    //
    //    printf("read %d byte integer as ", length);
    //    bytes = (unsigned char *)&uvalue;
    //    for (i = 0; i < length; i++) {
    //        printf("%02X ", bytes[i]);
    //    }
    //    printf(" = %ld\n", (int64_t)uvalue);
    //}
    *value = (int64_t)be64toh(uvalue);
    //printf("value = 0x%016lX\n", *value);
    if (length < sizeof(int64_t)) {
        *value >>= ((sizeof(int64_t) - length) * 8) ;
    }
    //printf("adjusted value = %ld\n", *value);
    return 0;
}

int ctSecretKey_init_decode_DER(ctSecretKey sK, unsigned char *der, size_t dsz) {
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
    result = asn1_der_decoding(&sK_asn1, der, dsz, asnError);
    if (result != ASN1_SUCCESS) return -1;

    //printf("-----------------\n");
    //asn1_print_structure(stdout, sK_asn1, "", ASN1_PRINT_ALL);
    //printf("-----------------\n");

    // Read secret key from ASN1 structure
    buffer = _asn1_read_octet_string(sK_asn1, "addr_sec", &sz);
    if (sz != sizeof(sK->addr_sec)) goto error_cleanup1;
    memcpy((void *)sK->addr_sec, (void *)buffer, sz);
    memset((void *)buffer, 0, sz);
    free(buffer);

    buffer = _asn1_read_octet_string(sK_asn1, "enc_sec", &sz);
    if (sz != sizeof(sK->enc_sec)) goto error_cleanup1;
    memcpy((void *)sK->enc_sec, (void *)buffer, sz);
    memset((void *)buffer, 0, sz);
    free(buffer);

    buffer = _asn1_read_octet_string(sK_asn1, "sign_sec", &sz);
    if (sz != sizeof(sK->sign_sec)) goto error_cleanup1;
    memcpy((void *)sK->sign_sec, (void *)buffer, sz);
    memset((void *)buffer, 0, sz);
    free(buffer);

    buffer = _asn1_read_octet_string(sK_asn1, "chk_sec", &sz);
    result = CHKPKE_init_privkey_decode_DER(sK->chk_sec, (char *)buffer, sz);
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
    asn1_delete_structure(&sK_asn1);
    asn1_delete_structure(&ct_asn1);
    return -1;
}

void ctPublicKey_init_ctSecretKey(ctPublicKey pK, ctSecretKey sK) {
    char *chkder;
    int chkdersz;

    crypto_scalarmult_base(pK->addr_pub, sK->addr_sec);
    crypto_scalarmult_base(pK->enc_pub, sK->enc_sec);
    crypto_scalarmult_base(pK->sign_pub, sK->sign_sec);
    chkder = CHKPKE_pubkey_encode_DER(sK->chk_sec, &chkdersz);
    CHKPKE_init_pubkey_decode_DER(pK->chk_pub, chkder, chkdersz);
    memset((void *)chkder, 0, chkdersz);
    free(chkder);
    pK->t0 = sK->t0;
    pK->tStep = sK->tStep;
}

void ctPublicKey_clear(ctPublicKey pK) {
    CHKPKE_clear(pK->chk_pub);
    memset((void *)pK, 0, sizeof(*pK));
}
