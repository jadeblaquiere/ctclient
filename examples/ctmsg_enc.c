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

typedef struct _readbuf {
    char    buffer[16000];
    struct _readbuf *next;
    int     sz;
} _readbuf_t;

static void _free_readbuf(_readbuf_t *next) {
    if (next->next != NULL) _free_readbuf(next->next);
    free(next);
    return;
}

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
    char *to = NULL;
    char *from = NULL;
    char *stime = NULL;
    char *etime = NULL;
    FILE *fPtr = stdin;
    FILE *toPtr = NULL;
    FILE *fmPtr = NULL;
    poptContext pc;
    struct poptOption po[] = {
        {"file", 'f', POPT_ARG_STRING, &filename, 0, "read input from filepath instead of stdin", "message file path"},
        {"recipient", 'r', POPT_ARG_STRING, &to, 0, "recipient public key (mandatory)", "recipient public key file path"},
        {"sender", 's', POPT_ARG_STRING, &from, 0, "sender secret key (optional)", "sender secret key file path"},
        {"time", 't', POPT_ARG_STRING, &stime, 0, "message sent time (optional)", "timestr YYYYMMDDHHMMSS"},
        {"expire", 'e', POPT_ARG_STRING, &etime, 0, "message expire time", "timestr YYYYMMDDHHMMSS"},
        POPT_AUTOHELP
        {NULL}
    };
    ctSecretKey_ptr sK = NULL;
    ctPublicKey pK;
    ctMessage ctM;
    ctPostageRate pr;
    unsigned char *der;
    size_t sz;
    unsigned char *ctext;
    size_t ctsz;
    int result;
    int64_t sstime = 0;
    int64_t eetime = 0;
    int64_t ttl = 0;

    unsigned char *msg;
    size_t msglen;

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
        fprintf(stderr,"<Error>: Unable to open recipient public key file %s\n", to);
        exit(1);
    }

    if (from != NULL) {
        fmPtr = fopen(from, "r");
        if (fmPtr == NULL) {
            fprintf(stderr,"<Error>: Unable to open input file %s\n", from);
            exit(1);
        }
    }

    sstime = usec_time(stime);
    if (etime != NULL) {
        eetime = usec_time(etime);
        ttl = eetime - sstime;
        if (ttl <= 0) {
            fprintf(stderr,"<Error>: negative time interval\n");
        }
    } else {
        eetime = 0;
    }
    
    // read entire plaintext input into memory
    {
        size_t len, rlen;
        _readbuf_t *head;
        _readbuf_t *next;
        unsigned char *buf;

        // read file into linked list of chunks
        head = (_readbuf_t *)malloc(sizeof(_readbuf_t));
        next = head;
        next->next = (_readbuf_t *)NULL;
        len = 0;

        while(1) {
            rlen = fread(next->buffer, sizeof(char), 16000, fPtr);
            len += rlen;
            next->sz = rlen;
            if (feof(fPtr)) {
                break;
            }
            next->next = (_readbuf_t *)malloc(sizeof(_readbuf_t));
            next = next->next;
            next->next = NULL;
        }
        if (len == 0) {
            fprintf(stderr,"<Error>: plaintext input zero length");
            exit(1);
        }

        // concatenate chunks into a single buffer
        msg = (unsigned char *)malloc((len + 1) * sizeof(char));
        next = head;
        buf = msg;
        while (next != NULL) {
            memcpy(buf, next->buffer, next->sz);
            buf += next->sz;
            next = next->next;
        }
        msg[len] = 0;
        msglen = len;
        _free_readbuf(head);
    }
    fclose(fPtr);

    // HERE IS WHERE THE ACTUAL EXAMPLE STARTS... everything before is
    // processing and very limited validation of command line options
    der = (unsigned char *)read_b64wrapped_from_file(toPtr, "CIPHRTXT PUBLIC KEY", &sz);
    if (der == NULL) {
        fprintf(stderr,"<ParseError>: unable to decode b64 data\n");
        exit(1);
    }
 
    result = ctPublicKey_init_decode_DER(pK, der, sz);
    if (result != 0) {
        fprintf(stderr,"<ParseError>: unable to import PUBLIC KEY data\n");
        exit(1);
    }
    
    free(der);

    if (from != NULL) {
        sK = (ctSecretKey_ptr)malloc(sizeof(ctSecretKey));
        der = (unsigned char *)read_b64wrapped_from_file(fmPtr, "CIPHRTXT SECRET KEY", &sz);
        if (der == NULL) {
            fprintf(stderr,"<ParseError>: unable to decode b64 data\n");
            exit(1);
        }
     
        result = ctSecretKey_init_decode_DER(sK, der, sz);
        if (result != 0) {
            fprintf(stderr,"<ParseError>: unable to import SECRET KEY data\n");
            exit(1);
        }
    }

    // postage rate = 0 during encryption. Will need to query network to get
    // actual postage rate and re-hash prior to posting
    pr->base_whole = 0;
    pr->base_fraction = 0;
    pr->l2blocks_whole = 0;
    pr->l2blocks_fraction = 0;

    ctext = ctMessage_init_Enc(ctM, pK, sK, sstime, ttl, NULL, msg, msglen, pr, &ctsz);

    assert(ctext != NULL);

    result = write_b64wrapped_to_file(stdout, ctext, ctsz, "CIPHRTXT ENCRYPTED MESSAGE");
    if (result != 0) {
        fprintf(stderr, "<WriteError>: Error writing output\n");
        exit(1);
    }

    ctMessage_clear(ctM);
    ctPublicKey_clear(pK);
    if (sK != NULL) ctSecretKey_clear(sK);

    return 0;
}
