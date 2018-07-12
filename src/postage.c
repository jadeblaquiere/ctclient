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
#include <ciphrtxt/postage.h>
#include <gmp.h>
#include <limits.h>
#include <math.h>
#include <string.h>

int ctPostage_hash_target(ctPostageHash hash, ctPostageRate rate, uint64_t blocksz) {
    mpz_t numer, denom;
    double frac;
    size_t hsz;

    // domain error check
    if (blocksz < 1) return -1;

    //gmp_printf("\nrate = %X, %X, %X\n", rate->base_whole, rate->base_fraction, rate->l2blocks_fraction);

    mpz_init(numer);
    mpz_init(denom);

    frac = (double)rate->l2blocks_whole + ((double)rate->l2blocks_fraction * (1.0 / 4294967296.0));
    frac *= log2((double)blocksz);
    frac += (double)rate->base_whole + ((double)rate->base_fraction * (1.0 / 4294967296.0));

    //gmp_printf("exponent = %lf\n", frac);

    frac = exp2(frac);

    //gmp_printf("divisor = %lf\n", frac);
    
    frac *= 4294967296.0;

    //gmp_printf("scaled = %lf\n", frac);
    
    mpz_init(numer);
    mpz_init(denom);

    // below here basically a fixed point calculation with 256.32 bits

    mpz_set_ui(numer, 0);
    mpz_setbit(numer, (_CT_HASHTARGET_SZ * 8) + 32);
    mpz_sub_ui(numer, numer, 1);
    
    //gmp_printf("numer = %ZX\n", numer);

    mpz_set_d(denom, frac);

    //gmp_printf("denom = %ZX\n", denom);

    // division results in rescaled value (the *2**32 factors cancel)
    mpz_div(numer, numer, denom);
    
    //gmp_printf("ratio = %064ZX\n", numer);

    hsz = _CT_HASHTARGET_SZ;
    memset((void *)hash, 0, _CT_HASHTARGET_SZ);
    mpz_export((void *)hash, &hsz, -1, sizeof(unsigned char), -1, 0, numer);
    assert(hsz <= _CT_HASHTARGET_SZ);
    mpz_clear(denom);
    mpz_clear(numer);
    return 0;
}

int ctPostage_hash_cmp(ctPostageHash hash, ctPostageHash target) {
    int i;
    
    for (i = (_CT_HASHTARGET_SZ - 1); i >= 0; i--) {
        if (((unsigned char *)hash)[i] > ((unsigned char*)target)[i]) {
            return 1;
        }
        if (((unsigned char *)hash)[i] < ((unsigned char*)target)[i]) {
            return -1;
        }
    }
    return 0;
}