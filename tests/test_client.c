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
#include <ciphrtxt/client.h>
#include <check.h>
#include <stdio.h>
#include <unistd.h>

START_TEST(test_init_client)
    ctConnection_t conn;

    ctConnection_init(conn, "127.0.0.1", 17764);

    int msgCount;
    char **msgIDs = ctConnection_get_message_ids(conn, &msgCount);
    assert(msgIDs != NULL);
    printf("received %d message IDs:\n", msgCount);
    int i;
    for (i = 0; i < msgCount; i++) {
        printf("%s\n", msgIDs[i]);

        char *tmpnm = "/message";
        assert(strlen(msgIDs[i]) == 64);
        size_t psz = strlen(P_tmpdir) + strlen(tmpnm) + strlen(msgIDs[i]) + 1;
        char *tmpfile = (char *)malloc(psz*sizeof(char));
        strcpy(tmpfile, P_tmpdir);
        strcat(tmpfile, tmpnm);
        strcat(tmpfile, msgIDs[i]);
        assert(strlen(tmpfile) > 0);

        printf("writing to %s\n", tmpfile);
        ctMessageFile_ptr mf = ctConnection_get_message(conn, msgIDs[i], tmpfile);
        assert(mf != NULL);
        unlink(tmpfile);
    }

    ctConnection_clear(conn);
END_TEST

START_TEST(test_post_message)
    ctMessage_t m;
    ctSecretKey_t a_sK;
    ctSecretKey_t b_sK;
    ctPublicKey_t b_pK;
    ctPostageRate_t prate;
    char *msg = "Hello Bob!";
    unsigned char *ctext;
    size_t ctextsz;

    // base value = 10 + (1 / 65536)
    prate->base_whole = 10;
    prate->base_fraction = (65536U);
    // block rate = 1 + 1 / 4
    prate->l2blocks_whole = 1;
    prate->l2blocks_fraction = (64 * 16777216U);

    ctSecretKey_init_Gen(a_sK, 0, 0, 0, 0, 0);

    ctSecretKey_init_Gen(b_sK, 0, 0, 0, 0, 0);
    ctPublicKey_init_ctSecretKey(b_pK, b_sK);

    ctext = ctMessage_init_Enc(m, b_pK, a_sK, 0, 0, NULL, (unsigned char *)msg, strlen(msg), prate, &ctextsz);
    assert(ctext != NULL);

    ctConnection_t conn;
    ctConnection_init(conn, "127.0.0.1", 17764);
    int status = ctConnection_post_message(conn, m);
    assert(status == 0);

    ctMessage_clear(m);
END_TEST

static Suite *mpCT_test_suite(void) {
    Suite *s;
    TCase *tc;

    s = suite_create("Ciphrtxt key interface");
    tc = tcase_create("client");

    tcase_add_test(tc, test_init_client);
    tcase_add_test(tc, test_post_message);

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
