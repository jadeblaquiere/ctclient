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

#include <assert.h>
#include <ciphrtxt/message.h>
#include <ciphrtxt/postage.h>
#include <gmp.h>
#include <inttypes.h>
#include <math.h>
#include <check.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

START_TEST(test_hash_targets)
    ctPostageRate_t pr;
    int i, j;
    int status;
    uint64_t blocks;
    
    // base value = 10 + (1 / 65536)
    pr->base_whole = 10;
    pr->base_fraction = (65536U);
    // block rate = 1 / 256
    pr->l2blocks_whole = 1;
    pr->l2blocks_fraction = (64 * 16777216U);

    blocks = 1;
    for (i = 0; i < 40; i++ ) {
        uint64_t bytes;
        ctPostageHash_t phash;

        bytes = blocks * _CT_BLKSZ;
        if (bytes > 1024) {
            bytes /= 1024;
            if (bytes > 1024) {
                bytes /= 1024;
                if (bytes > 1024) {
                    bytes /= 1024;
                    if (bytes > 1024) {
                        bytes /= 1024;
                        printf("%" PRId64 " blocks, %" PRId64" Tbytes, hash = ", blocks, bytes);
                    } else {
                        printf("%" PRId64 " blocks, %" PRId64" Gbytes, hash = ", blocks, bytes);
                    }
                } else {
                    printf("%" PRId64 " blocks, %" PRId64" Mbytes, hash = ", blocks, bytes);
                }
            } else {
                printf("%" PRId64 " blocks, %" PRId64" kbytes, hash = ", blocks, bytes);
            }
        } else {
            printf("%" PRId64 " blocks, %" PRId64" bytes, hash = ", blocks, bytes);
        }
        status = ctPostage_hash_target(phash, pr, blocks);
        assert(status == 0);
        for (j = 0; j < _CT_HASHTARGET_SZ; j++) {
            printf("%02X", ((unsigned char *)phash)[j]);
        }
        printf("\n");
        blocks *= 2;
    }
END_TEST

START_TEST(test_hash_compare)
    ctPostageRate_t pr;
    int i;
    int status;
    ctPostageHash_t ptgt;
    ctPostageHash_t random;
    ctPostageHash_t hash;
    
    // base value = 10 + (1 / 65536)
    pr->base_whole = 10;
    pr->base_fraction = (65536U);
    // block rate = 1 + 1 / 4
    pr->l2blocks_whole = 1;
    pr->l2blocks_fraction = (64 * 16777216U);
    
    // hash target for 1 block message
    status = ctPostage_hash_target(ptgt, pr, 1);
    printf("1 block target = ");
    for (i = 0; i < sizeof(ptgt); i++) {
        printf("%02X", ((unsigned char *)ptgt)[i]);
    }
    printf("\n");
    assert(status == 0);
    i = 0; 
    do {
        randombytes_buf(random, sizeof(random));
        crypto_generichash(hash, sizeof(hash), random, sizeof(random), NULL, 0);
        status = ctPostage_hash_cmp(hash, ptgt);
        i++;
    } while (status >= 0);
    printf("%d iterations, hash = ", i);
    for (i = 0; i < sizeof(hash); i++) {
        printf("%02X", ((unsigned char *)hash)[i]);
    }
    printf("\n");
    
    // hash target for 256 block message
    status = ctPostage_hash_target(ptgt, pr, 256);
    printf("256 block target = ");
    for (i = 0; i < sizeof(ptgt); i++) {
        printf("%02X", ((unsigned char *)ptgt)[i]);
    }
    printf("\n");
    assert(status == 0);
    i = 0; 
    do {
        randombytes_buf(random, sizeof(random));
        crypto_generichash(hash, sizeof(hash), random, sizeof(random), NULL, 0);
        status = ctPostage_hash_cmp(hash, ptgt);
        i++;
    } while (status >= 0);
    printf("%d iterations, hash = ", i);
    for (i = 0; i < sizeof(hash); i++) {
        printf("%02X", ((unsigned char *)hash)[i]);
    }
    printf("\n");
END_TEST

START_TEST(test_zero_postage)
    ctPostageRate_t pr;
    int i;
    int status;
    ctPostageHash_t ptgt;
    
    // base value = 0
    pr->base_whole = 0;
    pr->base_fraction = 0;
    // block rate = 0
    pr->l2blocks_whole = 0;
    pr->l2blocks_fraction = 0;
    
    // hash target for 1 block message
    status = ctPostage_hash_target(ptgt, pr, 1);
    printf("zero postage 1 block target = ");
    for (i = 0; i < sizeof(ptgt); i++) {
        printf("%02X", ((unsigned char *)ptgt)[i]);
        assert(((unsigned char *)ptgt)[i] == 0xFF);
    }
    printf("\n");
    assert(status == 0);
    
    // hash target for 256 block message
    status = ctPostage_hash_target(ptgt, pr, 256);
    printf("zero postage 256 block target = ");
    for (i = 0; i < sizeof(ptgt); i++) {
        printf("%02X", ((unsigned char *)ptgt)[i]);
        assert(((unsigned char *)ptgt)[i] == 0xFF);
    }
    printf("\n");
    assert(status == 0);
END_TEST

static Suite *mpCT_test_suite(void) {
    Suite *s;
    TCase *tc;

    s = suite_create("Ciphrtxt message interface");
    tc = tcase_create("postage");

    tcase_add_test(tc, test_hash_targets);
    tcase_add_test(tc, test_hash_compare);
    tcase_add_test(tc, test_zero_postage);

     // set no timeout instead of default 4
    tcase_set_timeout(tc, 0.0);

    suite_add_tcase(s, tc);
    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = mpCT_test_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
