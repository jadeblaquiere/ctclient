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
#include <math.h>
#include <check.h>
#include <stdio.h>
#include <stdlib.h>
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

START_TEST(test_init_key)
    ctSecretKey sK;
    ctPublicKey pK;

    ctSecretKey_init_GEN(sK, 0, 0, 0, 0, 0);
    ctPublicKey_init_ctSecretKey(pK, sK);

    ctPublicKey_clear(pK);
    ctSecretKey_clear(sK);
END_TEST

START_TEST(test_key_intervals)
    ctSecretKey sK;
    int64_t maxInterval;
    int64_t maxTime;

    ctSecretKey_init_GEN(sK, 0, 0, 0, 0, 0);

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

// NOTE : While there should be no hardcoded constants (instead it should
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

static Suite *mpCT_test_suite(void) {
    Suite *s;
    TCase *tc;

    s = suite_create("Ciphrtxt key interface");
    tc = tcase_create("keys");

    tcase_add_test(tc, test_init_key);
    tcase_add_test(tc, test_key_intervals);
    tcase_add_test(tc, test_sizes);

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
