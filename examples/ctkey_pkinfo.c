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
#include <b64file.h>
#include <check.h>
#include <ciphrtxt.h>
#include <inttypes.h>
#include <limits.h>
#include <popt.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

static void print_utime(int64_t ustime) {
    struct timeval tv;
    struct tm *ltm;
    char buffer[256];
    char *next;
    
    tv.tv_sec = (time_t)(ustime / 1000000);
    tv.tv_usec = (suseconds_t)(ustime % 1000000);
    
    ltm = localtime(&(tv.tv_sec));
    next = strftime(buffer, sizeof(buffer), "%F %T %Z", ltm);
    assert(next != NULL);
    printf(buffer);
    return;
}

int main(int argc, char **argv) {
    char *filename = NULL;
    FILE *fPtr = stdin;
    poptContext pc;
    struct poptOption po[] = {
        {"file", 'f', POPT_ARG_STRING, &filename, 0, "read input from filepath instead of stdin", "file path"},
        POPT_AUTOHELP
        {NULL}
    };
    ctPublicKey pK;
    unsigned char *der;
    size_t sz;
    int result;
    int i;
    unsigned char pK_hash[crypto_generichash_BYTES];

    // pc is the context for all popt-related functions
    pc = poptGetContext(NULL, argc, (const char **)argv, po, 0);
    //poptSetOtherOptionHelp(pc, "[ARG...]");

    {
        // process options and handle each val returned
        int val;
        while ((val = poptGetNextOpt(pc)) >= 0) {
        //printf("poptGetNextOpt returned val %d\n", val);
        }
        if (val != -1) {
            fprintf(stderr,"<Error processing args>\n");
            poptPrintUsage(pc, stderr, 0);
            exit(1);
        }
    }

    if (filename != NULL) {
        fPtr = fopen(filename, "r");
        if (fPtr == NULL) {
            fprintf(stderr,"<Error>: Unable to open input file %s\n", filename);
            exit(1);
        }
    }

    // HERE IS WHERE THE ACTUAL EXAMPLE STARTS... everything before is
    // processing and very limited validation of command line options
    der = (unsigned char *)read_b64wrapped_from_file(fPtr, "CIPHRTXT PUBLIC KEY", &sz);
    if (der == NULL) {
        fprintf(stderr,"<ParseError>: unable to decode b64 data\n");
        exit(1);
    }

    result = ctPublicKey_init_decode_DER(pK, der, sz);
    assert(result == 0);

    crypto_generichash_blake2b(pK_hash, sizeof(pK_hash), der, (unsigned long long)sz, NULL, 0);

    printf("ciphrtxt public key, hash(blake2b) = ");
    for (i = 0; i < sizeof(pK_hash); i++) {
        printf("%02X", pK_hash[i]);
    }
    printf("\n");
    
    printf("Initial key time: ");
    print_utime(pK->t0);
    printf("\n");

    printf("Forward Secure Resolution : %" PRId64 " microseconds\n", pK->tStep);

    free(der);
    ctPublicKey_clear(pK);

    return 0;
}
