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

#ifndef _CIPHRTXT_POSTAGE_H_INCLUDED_
#define _CIPHRTXT_POSTAGE_H_INCLUDED_

#include <stdint.h>
#include <sodium.h>

#ifdef __cplusplus
extern "C" {
#endif

// postage uses a variable "cost" Hashcash model - all messages "pay" a 
// base postage with a linear-work scaling per-block of message (work scales
// as exp(postage) and postage is based on log(blksz), so the net effect
// is linear increase in the variable cost. 
//

typedef struct {
    uint32_t    base_whole;
    uint32_t    base_fraction;
    uint32_t    l2blocks_whole;
    uint32_t    l2blocks_fraction;
} _ctPostageRate;

typedef _ctPostageRate ctPostageRate[1];
typedef _ctPostageRate *ctPostageRate_ptr;

#define _CT_HASHTARGET_SZ   (crypto_generichash_BYTES)

typedef unsigned char    ctPostageHash[_CT_HASHTARGET_SZ];

int ctPostage_hash_target(ctPostageHash hash, ctPostageRate rate, uint64_t blocksz);
int ctPostage_hash_cmp(ctPostageHash hash, ctPostageHash target);

#ifdef __cplusplus
}
#endif

#endif // _CIPHRTXT_POSTAGE_H_INCLUDED_
