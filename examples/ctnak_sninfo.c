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
#include <limits.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>

static void print_utime(utime_t utm) {
    char buffer[256];
    size_t written;

    written = utime_strftime(buffer, sizeof(buffer), "%a %b %d %T.%Q %Z %Y", utm);
    assert(written > 0);
    printf("%s", buffer);
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
    ctNAKSecretKey sN;
    ctNAKPublicKey pN;
    mpz_t smpz;
    unsigned char *der;
    size_t sz;
    int result;

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
    der = (unsigned char *)read_b64wrapped_from_file(fPtr, "CIPHRTXT SECRET NETWORK ACCESS KEY", &sz);
    if (der == NULL) {
        fprintf(stderr,"<ParseError>: unable to decode b64 data\n");
        exit(1);
    }
 
    result = ctNAKSecretKey_init_import_DER(sN, der, sz);
    if (result != 0) {
        fprintf(stderr,"<ParseError>: unable to import SECRET NAK data\n");
        exit(1);
    }
    
    ctNAKPublicKey_init_ctNAKSecretKey(pN, sN);

    mpz_init(smpz);
    mpz_set_mpFp(smpz, sN->secret_key);
    gmp_printf("secret key value : %064ZX\n", smpz);
    mpz_clear(smpz);
    
    {
        char *buffer;
        size_t bsz;

        bsz = mpECP_out_strlen(pN->public_key, 1);
        buffer = (char *)malloc((bsz + 1)*sizeof(char));
        mpECP_out_str(buffer, pN->public_key, 1);
        printf("public key value : %s\n", buffer);
        free(buffer);
    }

    printf("Not valid before: ");
    print_utime(sN->not_valid_before);
    printf("\n");

    printf("Not valid after : ");
    print_utime(sN->not_valid_after);
    printf("\n");

    free(der);
    ctNAKPublicKey_clear(pN);
    ctNAKSecretKey_clear(sN);

    return 0;
}
