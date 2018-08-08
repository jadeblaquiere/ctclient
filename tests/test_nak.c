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
#include <ciphrtxt/nak.h>
#include <gmp.h>
#include <inttypes.h>
#include <check.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TEST_ITERATIONS (1000)

START_TEST(test_init_clear)
    ctNAKSecretKey sN;
    ctNAKPublicKey pN;
    utime_t not_valid_before;
    utime_t not_valid_after;

    not_valid_before = getutime();
    not_valid_after = not_valid_before + (52 * UTIME_WEEKS);

    ctNAKSecretKey_init_Gen(sN, not_valid_before, not_valid_after);
    ctNAKPublicKey_init_ctNAKSecretKey(pN, sN);
    ctNAKPublicKey_clear(pN);
    ctNAKSecretKey_clear(sN);
END_TEST

START_TEST(test_sign_verify)
    ctNAKSecretKey sN;
    ctNAKPublicKey pN;
    mpECDSASignature_t sig;
    utime_t not_valid_before;
    utime_t not_valid_after;
    int i;
    int status;

    not_valid_before = getutime();
    not_valid_after = not_valid_before + (52 * UTIME_WEEKS);

    ctNAKSecretKey_init_Gen(sN, not_valid_before, not_valid_after);
    ctNAKPublicKey_init_ctNAKSecretKey(pN, sN);

    for (i = 0; i < TEST_ITERATIONS; i++) {
        unsigned char random_data[512];
        unsigned char *bsig;
        size_t bssz;
        mpECDSASignature_t sigcp;

        randombytes_buf(random_data, 512);
        status = ctNAKSignature_init_Sign(sig, sN, random_data, 512);
        assert(status == 0);
        status = ctNAKSignature_verify_cmp(sig, pN, random_data, 512);
        assert(status == 0);

        bsig = ctNAKSignature_export_bytes(sig, &bssz);
        status = ctNAKSignature_init_import_bytes(sigcp, bsig, bssz);
        assert(status == 0);
        assert(mpFp_cmp(sigcp->r, sig->r) == 0);
        assert(mpFp_cmp(sigcp->s, sig->s) == 0);
        free(bsig);
    }

    ctNAKPublicKey_clear(pN);
    ctNAKSecretKey_clear(sN);
END_TEST

START_TEST(test_export_import)
    ctNAKSecretKey sN;
    ctNAKSecretKey sNcp;
    ctNAKPublicKey pN;
    ctNAKPublicKey pNcp;
    utime_t not_valid_before;
    utime_t not_valid_after;
    unsigned char *der;
    size_t sz;
    int status;

    not_valid_before = getutime();
    not_valid_after = not_valid_before + (52 * UTIME_WEEKS);

    ctNAKSecretKey_init_Gen(sN, not_valid_before, not_valid_after);
    der = ctNAKSecretKey_export_DER(sN, &sz);
    assert(der != NULL);
    printf("NAK SECRET der (%zd bytes) =", sz);
    {
        int i;
        for (i = 0; i < sz; i++) {
            printf("%02X", der[i]);
        }
    }
    printf("\n");
    status = ctNAKSecretKey_init_import_DER(sNcp, der, sz);
    assert (status == 0);
    assert(mpFp_cmp(sN->secret_key, sNcp->secret_key) == 0);
    assert(sN->not_valid_before == sNcp->not_valid_before);
    assert(sN->not_valid_after == sNcp->not_valid_after);
    memset(der, 0, sz);
    free(der);

    ctNAKPublicKey_init_ctNAKSecretKey(pN, sN);
    der = ctNAKPublicKey_export_DER(pN, &sz);
    assert(der != NULL);
    printf("NAK PUBLIC der (%zd bytes) =", sz);
    {
        int i;
        for (i = 0; i < sz; i++) {
            printf("%02X", der[i]);
        }
    }
    printf("\n");
    status = ctNAKPublicKey_init_import_DER(pNcp, der, sz);
    assert (status == 0);
    assert(mpECP_cmp(pN->public_key, pNcp->public_key) == 0);
    assert(pN->not_valid_before == pNcp->not_valid_before);
    assert(pN->not_valid_after == pNcp->not_valid_after);
    memset(der, 0, sz);
    free(der);

    ctNAKPublicKey_clear(pN);
    ctNAKPublicKey_clear(pNcp);
    ctNAKSecretKey_clear(sN);
    ctNAKSecretKey_clear(sNcp);
END_TEST

static Suite *mpCT_test_suite(void) {
    Suite *s;
    TCase *tc;

    s = suite_create("Ciphrtxt Network Access Key (NAK) interface");
    tc = tcase_create("nak");

    tcase_add_test(tc, test_init_clear);
    tcase_add_test(tc, test_sign_verify);
    tcase_add_test(tc, test_export_import);

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