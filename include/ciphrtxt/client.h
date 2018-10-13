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

#ifndef _CIPHRTXT_CLIENT_H_INCLUDED_
#define _CIPHRTXT_CLIENT_H_INCLUDED_

#include <ciphrtxt/rawmessage.h>
#include <libdill.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *host;
    struct ipaddr addr;
} _ctConnection_t;

typedef _ctConnection_t ctConnection_t[1];
typedef _ctConnection_t *ctConnection_ptr;

int ctConnection_init(ctConnection_t conn, char *host, int port);
void ctConnection_clear(ctConnection_t conn);

char **ctConnection_get_message_ids(ctConnection_t conn, int *count);
ctMessageFile_ptr ctConnection_get_message(ctConnection_t conn, char *msgid, char *filename);
unsigned char *ctConnection_get_messagectxt(ctConnection_t conn, char *msgid, size_t *ctsz);
int ctConnection_post_message(ctConnection_t conn, ctMessage_t m);
int ctConnection_post_messagefile(ctConnection_t conn, ctMessageFile_t mf);
int ctConnection_post_messagectxt(ctConnection_t conn, unsigned char *ctext, size_t ctsz);

#ifdef __cplusplus
}
#endif

#endif // _CIPHRTXT_CLIENT_H_INCLUDED_
