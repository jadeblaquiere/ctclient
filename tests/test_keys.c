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
#include <ciphrtxt/keys.h>
#include <gmp.h>
#include <inttypes.h>
#include <math.h>
#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

// NOTE : While good to avoid hardcoded constants (instead it should
// use sizeof() and sizes defined in library code), there are some basic
// security assumptions related to the encryption code which rely on ECDLP
// and similar assumptions to be valid (and hence we assume ~256-bit types).
START_TEST(test_sizes)
    ctSecretKey sK;
    ctPublicKey pK;
    
    assert(sizeof(sK->addr_sec) == (32U));
    assert(sizeof(sK->enc_sec) == (32U));
    assert(sizeof(sK->sign_sec) == (32U));
    assert(sizeof(sK->t0) == (8U));
    assert(sizeof(sK->tStep) == (8U));

    assert(sizeof(pK->addr_pub) == (32U));
    assert(sizeof(pK->enc_pub) == (32U));
    assert(sizeof(pK->sign_pub) == (32U));
    assert(sizeof(pK->t0) == (8U));
    assert(sizeof(pK->tStep) == (8U));
END_TEST

START_TEST(test_init_key)
    ctSecretKey sK;
    ctPublicKey pK;
    _ed25519sk  sZero;
    
    memset(sZero, 0, sizeof(sZero));

    ctSecretKey_init_Gen(sK, 0, 0, 0, 0, 0);
    ctPublicKey_init_ctSecretKey(pK, sK);

    assert(memcmp(sZero, sK->addr_sec, sizeof(sZero)) != 0);
    assert(memcmp(sZero, sK->enc_sec, sizeof(sZero)) != 0);
    assert(memcmp(sZero, sK->sign_sec, sizeof(sZero)) != 0);

    assert(crypto_core_ed25519_is_valid_point(pK->addr_pub));
    assert(crypto_core_ed25519_is_valid_point(pK->enc_pub));
    assert(crypto_core_ed25519_is_valid_point(pK->sign_pub));

    ctPublicKey_clear(pK);
    ctSecretKey_clear(sK);
END_TEST

START_TEST(test_key_intervals)
    ctSecretKey sK;
    int64_t maxInterval;
    int64_t maxTime;

    ctSecretKey_init_Gen(sK, 0, 0, 0, 0, 0);

    assert (_ctSecretKey_interval_for_time(sK, sK->t0 - 1) == -1);
    assert (_ctSecretKey_interval_for_time(sK, sK->t0) == 0);
    assert (_ctSecretKey_interval_for_time(sK, sK->t0 + 59999999) == 0);
    assert (_ctSecretKey_interval_for_time(sK, sK->t0 + 60000000) == 1);

    assert (_ctSecretKey_time_for_interval(sK, 0) == sK->t0);
    assert (_ctSecretKey_time_for_interval(sK, 1) == (sK->t0 + 60000000));

    // semantic note... the key is defined for all time less than maxTime (or maxInterval)
    maxInterval = _pow_i64(sK->chk_sec->order, sK->chk_sec->depth);
    maxTime = (sK->t0) + (sK->tStep * maxInterval);
    
    assert (_ctSecretKey_time_for_interval(sK, maxInterval) == maxTime);
    assert (_ctSecretKey_interval_for_time(sK, maxTime) == maxInterval);
    assert (_ctSecretKey_interval_for_time(sK, maxTime - 1) == (maxInterval - 1));
    assert (_ctSecretKey_time_for_interval(sK, maxInterval - 1) == (maxTime - 60000000));

    ctSecretKey_clear(sK);
END_TEST

START_TEST(test_key_export_import)
    ctSecretKey sK1, sK2;
    unsigned char *der1, *der2, *chkder1, *chkder2;
    size_t sz1, sz2;
    size_t chksz1, chksz2;
    int result;

    ctSecretKey_init_Gen(sK1, 0, 0, 0, 0, 0);

    der1 = ctSecretKey_Export_FS_DER(sK1, sK1->t0, &sz1);
    assert(der1 != NULL);
    assert(sz1 > 0);
    //{
    //    int i;
    //    printf("export DER (SECRET) (%zd bytes) = \n", sz1);
    //    for (i = 0; i < sz1; i++) {
    //        printf("%02X", der1[i]);
    //    }
    //    printf("\n");
    //}
    
    result = ctSecretKey_init_decode_DER(sK2, der1, sz1);
    assert(result == 0);
    assert(memcmp(sK1->addr_sec, sK2->addr_sec, sizeof(sK1->addr_sec)) == 0);
    assert(memcmp(sK1->enc_sec, sK2->enc_sec, sizeof(sK1->enc_sec)) == 0);
    assert(memcmp(sK1->sign_sec, sK2->sign_sec, sizeof(sK1->sign_sec)) == 0);
    assert(sK1->t0 == sK2->t0);
    assert(sK1->tStep == sK2->tStep);
    assert(sK1->_intervalMin == sK2->_intervalMin);
    assert(sK1->_intervalMax == sK2->_intervalMax);
    
    chkder1 = CHKPKE_privkey_encode_delegate_DER(sK1->chk_sec, sK1->_intervalMin, sK1->_intervalMax - 1, &chksz1);
    chkder2 = CHKPKE_privkey_encode_delegate_DER(sK2->chk_sec, sK2->_intervalMin, sK2->_intervalMax - 1, &chksz2);
    assert(chksz1 == chksz2);
    assert(memcmp(chkder1, chkder2, chksz1) == 0);

    der2 = ctSecretKey_Export_FS_DER(sK2, sK2->t0, &sz2);
    assert(der2 != NULL);
    assert(sz2 > 0);
    assert(sz2 == sz1);
    assert(memcmp(der1, der2, sz1) == 0);

    ctSecretKey_clear(sK2);
    ctSecretKey_clear(sK1);
END_TEST

START_TEST(test_key_export_pubkey_import)
    ctSecretKey sK1;
    ctPublicKey pK1, pK2;
    unsigned char *der1, *der2;
    size_t sz1, sz2;
    int result;

    ctSecretKey_init_Gen(sK1, 0, 0, 0, 0, 0);
    ctPublicKey_init_ctSecretKey(pK1, sK1);
    
    der1 = ctPublicKey_Export_DER(pK1, &sz1);
    assert(der1 != NULL);
    //{
    //    int i;
    //    printf("export DER (PUBLIC) (%zd bytes) = \n", sz1);
    //    for (i = 0; i < sz1; i++) {
    //        printf("%02X", der1[i]);
    //    }
    //    printf("\n");
    //}

    result = ctPublicKey_init_decode_DER(pK2, der1, sz1);
    assert(result == 0);

    der2 = ctPublicKey_Export_DER(pK2, &sz2);
    assert(der2 != NULL);
    assert(sz1 == sz2);
    assert(memcmp(der1, der2, sz1) == 0);

    ctPublicKey_clear(pK2);
    ctPublicKey_clear(pK1);
    ctSecretKey_clear(sK1);
END_TEST

static Suite *mpCT_test_suite(void) {
    Suite *s;
    TCase *tc;

    s = suite_create("Ciphrtxt key interface");
    tc = tcase_create("keys");

    tcase_add_test(tc, test_init_key);
    tcase_add_test(tc, test_key_intervals);
    tcase_add_test(tc, test_sizes);
    tcase_add_test(tc, test_key_export_import);
    tcase_add_test(tc, test_key_export_pubkey_import);

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
