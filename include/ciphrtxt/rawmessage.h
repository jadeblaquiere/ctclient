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

#ifndef _CIPHRTXT_RAWMSG_H_INCLUDED_
#define _CIPHRTXT_RAWMSG_H_INCLUDED_

#include <ciphrtxt/message.h>
#include <ciphrtxt/utime.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    ctMessageHeader_t hdr;
    unsigned char *payload;
    size_t psz;
} _ctRawMessage_t;

typedef _ctRawMessage_t ctRawMessage_t[1];
typedef _ctRawMessage_t *ctRawMessage_ptr;

typedef struct {
    ctMessageHeader_t hdr;
    size_t msz;
    utime_t serverTime;
    char *filename;
} _ctMessageFile_t;

typedef _ctMessageFile_t ctMessageFile_t[1];
typedef _ctMessageFile_t *ctMessageFile_ptr;

ctMessageFile_ptr ctMessage_write_to_file(ctMessage_t msg, char *filename);
ctMessageFile_ptr ctMessageFile_read_from_file(char *filename);

unsigned char *ctMessageFile_ciphertext(ctMessageFile_t mf, size_t *ctsz);

void ctMessageFile_clear(ctMessageFile_t mf);

#ifdef __cplusplus
}
#endif

#endif // _CIPHRTXT_RAWMSG_H_INCLUDED_
