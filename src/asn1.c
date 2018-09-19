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
#include <assert.h>
#include <gmp.h>
#include <inttypes.h>
#include <libtasn1.h>
#include <portable_endian.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

int _asn1_write_uchar_string_as_octet_string(asn1_node root, char *attribute, unsigned char *buffer, int sz) {
    int result;

    result = asn1_write_value(root, attribute, buffer, (int)sz);
    //if (result != ASN1_SUCCESS) {
    //    int i;
    //    printf("error writing ");
    //    for (i = 0; i < lwrote; i++) {
    //        printf("%02X", buffer[i]);
    //    }
    //    printf(" to tag : %s\n", attribute);
    //}
    assert(result == ASN1_SUCCESS);
    return 5 + sz;
}

int _asn1_write_int64_as_integer(asn1_node root, char *attribute, int64_t value) {
    int nbytes = 256;
    int result;
    char buffer[256];
    sprintf(buffer,"%" PRId64, value);
    //printf("writing %ld (%s), length %d to %s\n", value, buffer, nbytes, attribute);
    result = asn1_write_value(root, attribute, buffer, 0);
    //printf("returned %d\n", result);
    assert(result == ASN1_SUCCESS);
    memset((void *)buffer, 0, nbytes);
    return 5 + nbytes;
}

unsigned char *_asn1_read_octet_string_as_uchar(asn1_node root, char *attribute, size_t *sz) {
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

int _asn1_read_int64_from_integer(int64_t *value, asn1_node root, char *attribute) {
    int result, length, lread;
    uint64_t uvalue = 0;
    //char *buffer;

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

int _asn1_write_mpz_as_octet_string(asn1_node root, char *attribute, mpz_t value) {
    size_t length;
    int result;
    size_t lwrote;
    char *buffer;

    length = (mpz_sizeinbase(value, 2) + 7) >> 3;
    //printf("trying to alloc %ld bytes\n", length + 1);
    buffer = (char *)malloc((length+1)*sizeof(char));
    assert(buffer != NULL);
    mpz_export(buffer, &lwrote, 1, sizeof(char), 0, 0, value);
    assert(lwrote == length);
    result = asn1_write_value(root, attribute, buffer, lwrote);
    //if (result != ASN1_SUCCESS) {
    //    int i;
    //    printf("error writing ");
    //    for (i = 0; i < lwrote; i++) {
    //        printf("%02X", buffer[i]);
    //    }
    //    printf(" to tag : %s\n", attribute);
    //}
    assert(result == ASN1_SUCCESS);
    free(buffer);
    return 5 + length;
}

int _asn1_read_mpz_from_octet_string(mpz_t value, asn1_node root, char *attribute) {
    int result, length, lread;
    char *buffer;

    // call read_value with NULL buffer to get length
    length = 0;
    result = asn1_read_value(root, attribute, NULL, &length);
    //printf("result = %d\n", result);
    if (result != ASN1_MEM_ERROR) return -1;
    //assert(result == ASN1_MEM_ERROR);
    if (length <= 0) return -1;
    //assert(length > 0);
    // allocate
    buffer = (char *)malloc((length+1)*sizeof(char));
    assert(buffer != NULL);
    lread = length + 1;
    result = asn1_read_value(root, attribute, buffer, &lread);
    if (result != ASN1_SUCCESS) goto cleanup_on_error;
    //assert(result == 0);
    if (lread != length) goto cleanup_on_error;
    //assert(lread == length);
    mpz_import(value, lread, 1, sizeof(char), 0, 0, buffer);
    free(buffer);
    return 0;
    
cleanup_on_error:
    free(buffer);
    return -1;
}
