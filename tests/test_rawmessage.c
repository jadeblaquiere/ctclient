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
#include <ciphrtxt/message.h>
#include <ciphrtxt/postage.h>
#include <ciphrtxt/rawmessage.h>
#include <gmp.h>
#include <inttypes.h>
#include <math.h>
#include <check.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

START_TEST(test_write_read)
    ctMessage_t m_e, m_d;
    ctMessageFile_ptr mf_e, mf_d;
    ctSecretKey_t a_sK;
    ctSecretKey_t b_sK;
    ctPublicKey_t b_pK;
    ctPostageRate_t prate;
    char *msg = "Hello Bob!";
    unsigned char *ptext;
    size_t ptextsz;
    unsigned char *ctext;
    size_t ctextsz;
    int status;

    // base value = 10 + (1 / 65536)
    prate->base_whole = 10;
    prate->base_fraction = (65536U);
    // block rate = 1 + 1 / 4
    prate->l2blocks_whole = 1;
    prate->l2blocks_fraction = (64 * 16777216U);

    ctSecretKey_init_Gen(a_sK, 0, 0, 0, 0, 0);

    ctSecretKey_init_Gen(b_sK, 0, 0, 0, 0, 0);
    ctPublicKey_init_ctSecretKey(b_pK, b_sK);

    ctext = ctMessage_init_Enc(m_e, b_pK, NULL, 0, 0, NULL, (unsigned char *)msg, strlen(msg), prate, &ctextsz);
    assert(ctext != NULL);
    if (ctMessageHeader_is_valid(m_e->hdr) == 0) {
        assert(0);
    }

    // {TMPDIR}/messageXXXXXX{NULL}
    char *tmpnm = "/messageXXXXXX";
    size_t psz = strlen(P_tmpdir) + strlen(tmpnm) + 1;
    char *tmpfile = (char *)malloc(psz*sizeof(char));
    strcpy(tmpfile, P_tmpdir);
    strcat(tmpfile, tmpnm);
    mktemp(tmpfile);
    assert(strlen(tmpfile) > 0);

    printf("writing to %s\n", tmpfile);
    mf_e = ctMessage_write_to_file(m_e, tmpfile);
    assert(mf_e != NULL);
    mf_d = ctMessageFile_read_from_file(tmpfile);
    assert(mf_d != NULL);

    size_t ctsz = 0;
    unsigned char *ct = ctMessageFile_ciphertext(mf_d, &ctsz);
    assert(ct != NULL);
    assert(ctsz == ctextsz);
    assert(memcmp(ctext, ct, ctsz) == 0);

    status = ctMessage_init_Dec(m_d, b_sK, ct, ctsz);
    assert(status == 0);
    ptext = ctMessage_plaintext_ptr(m_d, &ptextsz);
    assert(ptextsz == strlen(msg));
    assert(0 == strncmp(msg, (char *)ptext, ptextsz));

    assert(unlink(tmpfile) == 0);
END_TEST

static Suite *mpCT_test_suite(void) {
    Suite *s;
    TCase *tc;

    s = suite_create("Ciphrtxt message interface");
    tc = tcase_create("rawmessage");

    tcase_add_test(tc, test_write_read);

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
