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
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

int main(int argc, char **argv) {
    char *msgid = NULL;
    char *hostname = NULL;
    int port = 17764;
    poptContext pc;
    struct poptOption po[] = {
        {"msgid", 'm', POPT_ARG_STRING, &msgid, 0, "ID(hash) to retreive", "message ID"},
        {"server", 's', POPT_ARG_STRING, &hostname, 0, "hostname for ciphrtxt service", "server hostname"},
        {"port", 'p', POPT_ARG_INT, &port, 17764, "port number for ciphrtxt service (default 17764)", "server port"},
        POPT_AUTOHELP
        {NULL}
    };
    //ctMessage_t ctM;
    //ctPostageRate_t pr;
    unsigned char *ctext;
    size_t ctsz;
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

    if (hostname == NULL) {
        fprintf(stderr,"<Error>: --server/-s is mandatory\n");
        exit(1);
    }

    if (msgid == NULL) {
        fprintf(stderr,"<Error>: --msgid/-m is mandatory\n");
        exit(1);
    }

    // HERE IS WHERE THE ACTUAL EXAMPLE STARTS... everything before is
    // processing and very limited validation of command line options
    ctConnection_t conn;
    ctConnection_init(conn, hostname, port);
    ctext = ctConnection_get_messagectxt(conn, msgid, &ctsz);

    // cheat #1, rather than parsing the whole message, just copy header
    //memcpy(ctM->hdr, ctext, _CT_BLKSZ);

    // convert number of (possibly fractional) zeros to ctPostageRate
    // cheat #2 is to only use the base portion
    //pr->base_whole = (uint32_t)(zeros);
    //pr->base_fraction = (uint32_t)(((double)zeros - (double)(pr->base_whole)) *
    //    4294967296.0);
    //pr->l2blocks_whole = 0;
    //pr->l2blocks_fraction = 0;

    //ctMessage_rehash(ctM, pr);

    // copy it back
    //memcpy(ctext, ctM->hdr, _CT_BLKSZ);

    status = write_b64wrapped_to_file(stdout, ctext, ctsz, "CIPHRTXT ENCRYPTED MESSAGE");
    if (status != 0) {
        fprintf(stderr, "<WriteError>: Error writing output\n");
        exit(1);
    }

    free(ctext);
    return 0;
}
