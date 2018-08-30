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
    char *btime = NULL;
    char *atime = NULL;
    poptContext pc;
    struct poptOption po[] = {
        {"nvb", 'b', POPT_ARG_STRING, &btime, 0, "not valid before time (optional)", "timestr YYYYMMDDHHMMSS"},
        {"nva", 'a', POPT_ARG_STRING, &atime, 0, "not valid after time (optional)", "timestr YYYYMMDDHHMMSS"},
        POPT_AUTOHELP
        {NULL}
    };
    ctNAKSecretKey_t sN;
    utime_t nvbtime;
    utime_t nvatime;
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
    
    if (btime != NULL) {
        nvbtime = usec_time(btime);
    } else {
        nvbtime = getutime();
    }

    if (atime != NULL) {
        nvatime = usec_time(atime);
    } else {
        nvatime = nvbtime + (365 * UTIME_DAYS);
    }

    if (nvatime < nvbtime) {
        fprintf(stderr,"<Error>: negative time interval\n");
        exit(1);
    }

    if (nvatime == nvbtime) {
        fprintf(stderr,"<Error>: zero time interval\n");
        exit(1);
    }

    // HERE IS WHERE THE ACTUAL EXAMPLE STARTS... everything before is
    // processing and very limited validation of command line options
    ctNAKSecretKey_init_Gen(sN, nvbtime, nvatime);

     //printf("exporting key\n");
    der = ctNAKSecretKey_export_DER(sN, &sz);
    assert(der != NULL);

    result = write_b64wrapped_to_file(stdout, der, sz, "CIPHRTXT SECRET NETWORK ACCESS KEY");
    if (result != 0) {
        fprintf(stderr, "<WriteError>: Error writing output\n");
        exit(1);
    }

    free(der);
    ctNAKSecretKey_clear(sN);

    return 0;
}
