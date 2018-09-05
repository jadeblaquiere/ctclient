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

package ctgo

// #cgo CFLAGS: -I/usr/local/include/pbc -I/usr/include/pbc
// #cgo LDFLAGS: -lecc -lgmp
// #include <ciphrtxt/postage.h>
// #include <stdlib.h>
//
// ctPostageRate_ptr malloc_ctPostageRate() {
//     return (ctPostageRate_ptr)malloc(sizeof(ctPostageRate_t));
// }
//
// void free_ctPostageRate(ctPostageRate_ptr e) {
//     free(e);
// }
//
import "C"

import (
	//"bytes"
	//"encoding/base64"
	//"encoding/hex"
	//"encoding/binary"
	//"errors"
	//"fmt"
	//"io/ioutil"
	//"math/big"
	//"os"
	//"reflect"
	"runtime"
	//"strconv"
	//"strings"
	//"time"
	//"unsafe"
)

type PostageRate struct {
	pR *C._ctPostageRate_t
}

// unsigned char *ctMessage_init_Enc(ctMessage_t msg, ctPublicKey_t toK, ctSecretKey_t fromK,
//   utime_t timestamp, utime_t ttl, char *mime, unsigned char *plaintext,
//   size_t p_sz, ctPostageRate_t rate, size_t *sz);

func NewPostageRate(baseWhole, baseFrac, l2whole, l2frac uint32) (z *PostageRate) {

	z = new(PostageRate)
	z.pR = C.malloc_ctPostageRate()
	z.pR.base_whole = C.uint32_t(baseWhole)
	z.pR.base_fraction = C.uint32_t(baseFrac)
	z.pR.l2blocks_whole = C.uint32_t(l2whole)
	z.pR.l2blocks_fraction = C.uint32_t(l2frac)

	runtime.SetFinalizer(z, postageRate_clear)
	return z
}

func postageRate_clear(z *PostageRate) {
	C.free_ctPostageRate(z.pR)
}
