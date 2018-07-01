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
#include <gmp.h>
#include <inttypes.h>
#include <math.h>
#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// NOTE : While good to avoid hardcoded constants (instead it should
// use sizeof() and sizes defined in library code), there are some basic
// security assumptions related to the encryption code which rely on ECDLP
// and similar assumptions to be valid (and hence we assume ~256-bit types).
START_TEST(test_sizes)
    ctMessage m;
    
    assert(sizeof(m->hdr->magic) == (3U));
    assert(sizeof(m->hdr->version) == (5U));
    assert(sizeof(m->hdr->msgtime_usec) == (8U));
    assert(sizeof(m->hdr->expire_usec) == (8U));
    assert(sizeof(m->hdr->payload_blocks) == (8U));
    assert(sizeof(m->hdr->I_point) == (32U));
    assert(sizeof(m->hdr->J_point) == (32U));
    assert(sizeof(m->hdr->ECDHE_point) == (32U));
    assert(sizeof(m->hdr->payload_hash) == (32U));
    assert(sizeof(m->hdr->header_signature) == (64U));
    assert(sizeof(m->hdr->reserved) == (8U));
    assert(sizeof(m->hdr->nonce) == (8U));
    
    // validate header block size (240) and authenticated portion (128)
    assert(sizeof(m->hdr) == (240U));
    assert(((void *)m->hdr->payload_hash - (void *)m->hdr) == (128U));
END_TEST

static Suite *mpCT_test_suite(void) {
    Suite *s;
    TCase *tc;

    s = suite_create("Ciphrtxt key interface");
    tc = tcase_create("message");

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
