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
#include <sys/time.h>

static int64_t usec_time(char *tstr) {
    int64_t ustime;

    if (tstr != NULL) {
        char *next;
        struct tm tms;
        time_t tt;

        next = strptime(tstr, "%Y%m%d%H%M%S", &tms);
        if (next == NULL) {
            fprintf(stderr,"<Error>: time must be in YYYYMMDDHHMMSS format");
            exit(1);
        }
        tt = mktime(&tms);
        assert(tt != -1);
        ustime = 1000000 * ((int64_t)tt);
    } else {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        ustime = (1000000 * ((int64_t)tv.tv_sec)) + ((int64_t)tv.tv_usec);
    }
    return ustime;
}

int main(int argc, char **argv) {
    char *filename = NULL;
    char *stime = NULL;
    char *etime = NULL;
    FILE *fPtr = stdin;
    poptContext pc;
    struct poptOption po[] = {
        {"file", 'f', POPT_ARG_STRING, &filename, 0, "read input from filepath instead of stdin", "file path"},
        {"starttime", 's', POPT_ARG_STRING, &stime, 0, "use this date time (YYYYMMDDHHMMSS) as not-before time, default=now", "start time"},
        {"endtime", 'e', POPT_ARG_STRING, &etime, 0, "use this date time (YYYYMMDDHHMMSS) as not-after time, default=MAX", "end time"},
        POPT_AUTOHELP
        {NULL}
    };
    ctSecretKey sK;
    unsigned char *der;
    size_t sz;
    int result;
    int64_t sstime = 0;
    int64_t eetime = 0;

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
    der = (unsigned char *)read_b64wrapped_from_file(fPtr, "CIPHRTXT SECRET KEY", &sz);
    if (der == NULL) {
        fprintf(stderr,"<ParseError>: unable to decode b64 data\n");
        exit(1);
    }
 
    result = ctSecretKey_init_decode_DER(sK, der, sz);
    assert(result == 0);
    
    sstime = usec_time(stime);
    if (etime != NULL) {
        eetime = usec_time(etime);
    } else {
        eetime = sK->t0 + (sK->tStep * (sK->_intervalMax - 1));
    }
    
    //printf("exporting key\n");
    der = ctSecretKey_Export_FS_Delegate_DER(sK, sstime, eetime, &sz);
    assert(der != NULL);

    result = write_b64wrapped_to_file(stdout, der, sz, "CIPHRTXT SECRET KEY");
    if (result != 0) {
        fprintf(stderr, "<WriteError>: Error writing output\n");
        exit(1);
    }

    free(der);
    ctSecretKey_clear(sK);

    return 0;
}
