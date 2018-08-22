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

START_TEST(test_auth_challenge)
    ctNAKSecretKey sN;
    ctNAKPublicKey pN;
    ctNAKAuthChallenge_t ch;
    ctNAKAuthChallenge_t ch_cp;
    ctNAKAuthResponse_t rs;
    mpECurve_ptr cvp;
    mpFp_t session_sK;
    mpECP_t Gpt;
    mpECP_t session_pK;
    mpECP_t r_ptxt;
    utime_t not_valid_before;
    utime_t not_valid_after;
    utime_t session_expire;
    ctNAKSecretKey *c_sN;
    ctNAKPublicKey *c_pN;
    int n = 50;
    int i;
    int status;
    unsigned char *buffer;
    size_t bsz;

    not_valid_before = getutime();
    not_valid_after = not_valid_before + (52 * UTIME_WEEKS);

    ctNAKSecretKey_init_Gen(sN, not_valid_before, not_valid_after);
    ctNAKPublicKey_init_ctNAKSecretKey(pN, sN);

    cvp = pN->public_key->cvp;

    mpFp_init(session_sK, cvp->n);
    mpFp_urandom(session_sK, cvp->n);
    mpECP_init(Gpt, cvp);
    mpECP_set_mpz(Gpt, cvp->G[0], cvp->G[1], cvp);
    mpECP_init(session_pK, cvp);
    mpECP_scalar_mul(session_pK, Gpt, session_sK);

    c_sN = (ctNAKSecretKey *)malloc(n * sizeof(ctNAKSecretKey));
    c_pN = (ctNAKPublicKey *)malloc(n * sizeof(ctNAKPublicKey));

    for (i = 0; i < n; i++) {
        ctNAKSecretKey_init_Gen(c_sN[i], not_valid_before, not_valid_after);
        ctNAKPublicKey_init_ctNAKSecretKey(c_pN[i], c_sN[i]);
    }

    session_expire = getutime() + (1 * UTIME_HOURS);

    mpECP_init(r_ptxt, cvp);
    mpECP_urandom(r_ptxt, cvp);

    status = ctNAKAuthChallenge_init(ch, n, c_pN, session_pK, session_expire, r_ptxt);
    assert(status == 0);

    buffer = ctNAKAuthChallenge_export_DER(ch, &bsz);
    assert(buffer != NULL);

    printf("challenge der (%zd bytes) = ", bsz);
    for (i =  0; i < bsz; i++) {
        printf("%02X", buffer[i]);
    }
    printf("\n");

    status = ctNAKAuthChallenge_init_import_DER(ch_cp, buffer, bsz);
    assert(status == 0);

    assert(ch->session_expire == ch_cp->session_expire);
    assert(mpECP_cmp(ch->session_pK, ch_cp->session_pK) == 0);
    assert(ch->n == ch_cp->n);
    for (i = 0; i < ch->n; i++) {
        assert(mpECP_cmp(ch->pK[i], ch_cp->pK[i]) == 0);
        assert(mpECP_cmp(ch->ctxt[i]->C, ch_cp->ctxt[i]->C) == 0);
        assert(mpECP_cmp(ch->ctxt[i]->D, ch_cp->ctxt[i]->D) == 0);
    }

    free(buffer);
    ctNAKAuthChallenge_clear(ch_cp);

    for (i = 0; i < n; i++) {
        ctNAKAuthResponse_t rs_cp;

        status = ctNAKAuthResponse_init(rs, ch, c_sN[i]);
        assert(status == 0);
        
        buffer = ctNAKAuthResponse_export_DER(rs, &bsz);
        assert(buffer != NULL);

        if (i == 0) {
            printf("response der (%zd bytes) = ", bsz);
            for (i =  0; i < bsz; i++) {
                printf("%02X", buffer[i]);
            }
            printf("\n");
        }

        status = ctNAKAuthResponse_init_import_DER(rs_cp, buffer, bsz);
        assert(status == 0);
        
        assert(mpECP_cmp(rs->session_pK, rs_cp->session_pK) == 0);
        assert(mpECP_cmp(rs->ctxt->C, rs_cp->ctxt->C) == 0);
        assert(mpECP_cmp(rs->ctxt->D, rs_cp->ctxt->D) == 0);

        free(buffer);
        ctNAKAuthResponse_clear(rs_cp);

        status = ctNAKAuthResponse_validate_cmp(rs, session_sK, r_ptxt);
        assert(status == 0);

        ctNAKAuthResponse_clear(rs);
    }

    ctNAKAuthChallenge_clear(ch);
    for (i = 0; i < n; i++) {
        ctNAKPublicKey_clear(c_pN[i]);
        ctNAKSecretKey_clear(c_sN[i]);
    }
    free(c_pN);
    free(c_sN);
    mpECP_clear(session_pK);
    mpECP_clear(Gpt);
    mpFp_clear(session_sK);
    ctNAKPublicKey_clear(pN);
    ctNAKSecretKey_clear(sN);
END_TEST

static Suite *mpCT_test_suite(void) {
    Suite *s;
    TCase *tc;

    s = suite_create("Ciphrtxt Network Access Key (NAK) interface");
    tc = tcase_create("nak");

    tcase_add_test(tc, test_init_clear);
    tcase_add_test(tc, test_sign_verify);
    tcase_add_test(tc, test_export_import);
    tcase_add_test(tc, test_auth_challenge);

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
