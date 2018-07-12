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

#define _XOPEN_SOURCE
#include <time.h>

#include <assert.h>
#include <b64file.h>
#include <check.h>
#include <ciphrtxt.h>
#include <limits.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

int main(int argc, char **argv) {
    char *filename = NULL;
    char *to = NULL;
    FILE *fPtr = stdin;
    FILE *toPtr = NULL;
    poptContext pc;
    struct poptOption po[] = {
        {"file", 'f', POPT_ARG_STRING, &filename, 0, "read input from filepath instead of stdin", "message file path"},
        {"recipient", 'r', POPT_ARG_STRING, &to, 0, "recipient secret key (mandatory)", "recipient secret key file path"},
        POPT_AUTOHELP
        {NULL}
    };
    ctSecretKey sK;
    ctMessage ctM;
    unsigned char *der;
    size_t sz;
    unsigned char *ctext;
    size_t ctsz;
    unsigned char *ptext;
    size_t ptsz;
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

    if (to == NULL) {
        fprintf(stderr,"<Error>: recipient option (--recipient/-r) is mandatory\n");
        exit(1);
    }
    toPtr = fopen(to, "r");
    if (toPtr == NULL) {
        fprintf(stderr,"<Error>: Unable to open recipient secret key file %s\n", to);
        exit(1);
    }

    // HERE IS WHERE THE ACTUAL EXAMPLE STARTS... everything before is
    // processing and very limited validation of command line options
    der = (unsigned char *)read_b64wrapped_from_file(toPtr, "CIPHRTXT SECRET KEY", &sz);
    if (der == NULL) {
        fprintf(stderr,"<ParseError>: unable to decode b64 data\n");
        exit(1);
    }
 
    result = ctSecretKey_init_decode_DER(sK, der, sz);
    assert(result == 0);
    
    free(der);

    ctext = (unsigned char *)read_b64wrapped_from_file(fPtr, "CIPHRTXT ENCRYPTED MESSAGE", &ctsz);
    if (ctext == NULL) {
        fprintf(stderr,"<ParseError>: unable to decode b64 data\n");
        exit(1);
    }
 
    result = ctMessage_init_Dec(ctM, sK, ctext, ctsz);
    if (result != 0) {
        fprintf(stderr,"<Error>: Unable to decode message\n");
        exit(1);
    }

    memset(ctext, 0, ctsz);
    free(ctext);
    
    ptext = ctMessage_plaintext_ptr(ctM, &ptsz);

    fwrite(ptext, sizeof(unsigned char), ptsz, stdout);
    
    ctMessage_clear(ctM);
    ctSecretKey_clear(sK);

    return 0;
}
