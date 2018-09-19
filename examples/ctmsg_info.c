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
#include <portable_endian.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

static void print_bytes(void *b, size_t bsz) {
    unsigned char *bb;
    int i;
    
    bb = (unsigned char *)b;
    for (i = 0; i < bsz; i++) {
        printf("%02X", bb[i]);
    }
    return;
}

typedef struct {
    uint16_t minor;
    uint16_t major;
} _version_t;

int main(int argc, char **argv) {
    char *filename = NULL;
    FILE *fPtr = stdin;
    poptContext pc;
    struct poptOption po[] = {
        {"file", 'f', POPT_ARG_STRING, &filename, 0, "read input from filepath instead of stdin", "message file path"},
        POPT_AUTOHELP
        {NULL}
    };
    ctMessageHeader_t ctMH;
    unsigned char *ctext;
    size_t ctsz;
    char buffer[256];
    size_t bsz;
    int status;

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
    ctext = (unsigned char *)read_b64wrapped_from_file(fPtr, "CIPHRTXT ENCRYPTED MESSAGE", &ctsz);
    if (ctext == NULL) {
        fprintf(stderr,"<ParseError>: unable to decode b64 data\n");
        exit(1);
    }

    assert(ctsz >= _CT_BLKSZ);
    memcpy(ctMH, ctext, sizeof(ctMH));
    ctMH->msgtime_usec = le64toh(ctMH->msgtime_usec);
    ctMH->expire_usec = le64toh(ctMH->expire_usec);
    ctMH->payload_blocks = le64toh(ctMH->payload_blocks);

    printf("Message ID (payload hash) = ");
    print_bytes(ctMH->payload_hash, sizeof(ctMH->payload_hash));
    printf("\n");

    {
        _version_t *vp;

        vp = (_version_t *)(((unsigned char *)ctMH) + 4);
        printf("Message format version %d.%d\n", vp->major, vp->minor);
    }

    bsz = utime_strftime(buffer, sizeof(buffer), "%a %b %d %T.%Q %Z %Y", ctMH->msgtime_usec);
    assert(bsz > 0);
    printf("sent    : %s\n", buffer);

    bsz = utime_strftime(buffer, sizeof(buffer), "%a %b %d %T.%Q %Z %Y", ctMH->expire_usec);
    assert(bsz > 0);
    printf("expires : %s\n", buffer);

    printf("payload : %" PRId64 " blocks ( %" PRId64 " bytes)\n", ctMH->payload_blocks, ctMH->payload_blocks * _CT_BLKSZ);

    printf("I point   = ");
    print_bytes(ctMH->I_point, sizeof(ctMH->I_point));
    printf("\n");

    printf("J point   = ");
    print_bytes(ctMH->J_point, sizeof(ctMH->J_point));
    printf("\n");

    printf("ECDHE pt  = ");
    print_bytes(ctMH->ECDHE_point, sizeof(ctMH->ECDHE_point));
    printf("\n");

    printf("Signature = ");
    print_bytes(ctMH->header_signature, sizeof(ctMH->header_signature));
    printf("\n");

    printf("Header nonce = %08" PRIX64 "\nHeader hash  = ", ctMH->nonce);

    {
        unsigned char hhash[crypto_generichash_BYTES];
        status = crypto_generichash(hhash, sizeof(hhash), (unsigned char *)ctMH, sizeof(ctMH), NULL, 0);
        assert(status == 0);
        print_bytes(hhash, sizeof(hhash));
        printf("\n");
    }

    if (ctsz == _CT_BLKSZ) {
        return 0;
    }

    {
        uint32_t *fsksz;
        unsigned char *fsk;
        unsigned char *nonce;
        
        fsksz = (uint32_t *)(ctext + _CT_BLKSZ);
        fsk = (unsigned char *)(ctext + _CT_BLKSZ + sizeof(*fsksz));
        nonce = (unsigned char *)(ctext + _CT_BLKSZ + sizeof(*fsksz) + fsksz[0]);
        printf("forward-secure (CHK) encrypted key = ");
        print_bytes(fsk, fsksz[0]);
        printf("\n");

        printf("symmetric encryption nonce = ");
        print_bytes(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        printf("\n");
    }

    return 0;
}
