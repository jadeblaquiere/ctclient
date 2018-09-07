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
// #include <ciphrtxt/nak.h>
// #include <ciphrtxt/utime.h>
// #include <ecc/ecdsa.h>
// #include <stdlib.h>
// #include <string.h>
//
// ctNAKSecretKey_ptr malloc_ctNAKSecretKey() {
//     return (ctNAKSecretKey_ptr)malloc(sizeof(ctNAKSecretKey_t));
// }
//
// void free_ctNAKSecretKey(ctNAKSecretKey_ptr e) {
//     free(e);
// }
//
// ctNAKPublicKey_ptr malloc_ctNAKPublicKey() {
//     return (ctNAKPublicKey_ptr)malloc(sizeof(ctNAKPublicKey_t));
// }
//
// void free_ctNAKPublicKey(ctNAKPublicKey_ptr e) {
//     free(e);
// }
//
// ctNAKAuthChallenge_ptr malloc_ctNAKAuthChallenge() {
//     return (ctNAKAuthChallenge_ptr)malloc(sizeof(ctNAKAuthChallenge_t));
// }
//
// void free_ctNAKAuthChallenge(ctNAKAuthChallenge_ptr e) {
//     free(e);
// }
//
// ctNAKAuthResponse_ptr malloc_ctNAKAuthResponse() {
//     return (ctNAKAuthResponse_ptr)malloc(sizeof(ctNAKAuthResponse_t));
// }
//
// void free_ctNAKAuthResponse(ctNAKAuthResponse_ptr e) {
//     free(e);
// }
//
// mpECDSASignature_ptr malloc_ECDSASignature() {
//     return (mpECDSASignature_ptr)malloc(sizeof(_mpECDSASignature_t));
// }
//
// void free_ECDSASignature(mpECDSASignature_ptr csig) {
//     free(csig);
// }
//
// unsigned char *unsafeptr_to_ucharptr(void *in);
//
import "C"

import (
	//"bytes"
	//"encoding/base64"
	//"encoding/hex"
	//"encoding/binary"
	"errors"
	//"fmt"
	//"io/ioutil"
	//"math/big"
	//"os"
	//"reflect"
	"runtime"
	//"strconv"
	//"strings"
	"time"
	"unsafe"
)

type NAKSecretKey struct {
	sN *C._ctNAKSecretKey_t
}

type NAKPublicKey struct {
	pN *C._ctNAKPublicKey_t
}

func NewNAKSecretKey(notValidBefore, notValidAfter time.Time) (z *NAKSecretKey) {

	z = new(NAKSecretKey)
	z.sN = C.malloc_ctNAKSecretKey()
	C.ctNAKSecretKey_init_Gen(z.sN, TimeToUTime(notValidBefore), TimeToUTime(notValidAfter))

	runtime.SetFinalizer(z, secretNAK_clear)
	return z
}

func secretNAK_clear(z *NAKSecretKey) {
	C.ctNAKSecretKey_clear(z.sN)
	C.free_ctNAKSecretKey(z.sN)
}

func (z *NAKSecretKey) Export() (key []byte, err error) {
	//var pke *C._CHKPKE_t
	var der *C.uchar
	l := C.size_t(0)

	der, _ = C.ctNAKSecretKey_export_DER(z.sN, &l)
	if der == nil {
		return nil, errors.New("NAKSecretKey.Export: Unable to export secret key")
	}

	defer C.free(unsafe.Pointer(der))
	return C.GoBytes(unsafe.Pointer(der), C.int(l)), nil
}

func ImportNAKSecretKey(key []byte) (z *NAKSecretKey) {

	z = new(NAKSecretKey)
	z.sN = C.malloc_ctNAKSecretKey()
	ckey := C.CBytes(key)
	status := C.ctNAKSecretKey_init_import_DER(z.sN, C.unsafeptr_to_ucharptr(ckey), C.size_t(len(key)))
	defer C.free(ckey)
	if status != C.int(0) {
		C.free_ctNAKSecretKey(z.sN)
		return nil
	}
	runtime.SetFinalizer(z, secretNAK_clear)
	return z
}

func (a *NAKSecretKey) NotValidBefore() (nvbt time.Time) {
	return UTimeToTime(a.sN.not_valid_before)
}

func (a *NAKSecretKey) NotValidAfter() (nvbt time.Time) {
	return UTimeToTime(a.sN.not_valid_after)
}

func (a *NAKSecretKey) ECDSASign(msg []byte) (sig []byte) {
	var lsig *C._mpECDSASignature_t
	l := C.size_t(0)
	cmsg := C.CBytes(msg)

	lsig = C.malloc_ECDSASignature()
	status := C.ctNAKSignature_init_Sign(lsig, a.sN, C.unsafeptr_to_ucharptr(cmsg), C.size_t(len(msg)))
	defer C.free(cmsg)
	defer C.free_ECDSASignature(lsig)
	if status != C.int(0) {
		return nil
	}
	csig := C.ctNAKSignature_export_bytes(lsig, &l)
	C.mpECDSASignature_clear(lsig)
	defer C.free(unsafe.Pointer(csig))
	return C.GoBytes(unsafe.Pointer(csig), C.int(l))
}

func (a *NAKSecretKey) NAKSignedPublicKey() (spn []byte) {
	l := C.size_t(0)
	cspn := C.ctNAKSignedPublicKey_init_ctNAKSecretKey(a.sN, &l)
	defer C.free(unsafe.Pointer(cspn))
	return C.GoBytes(unsafe.Pointer(cspn), C.int(l))
}

func (a *NAKSecretKey) NAKPublicKey() (z *NAKPublicKey) {

	z = new(NAKPublicKey)
	z.pN = C.malloc_ctNAKPublicKey()
	C.ctNAKPublicKey_init_ctNAKSecretKey(z.pN, a.sN)
	runtime.SetFinalizer(z, publicNAK_clear)
	return z
}

func publicNAK_clear(z *NAKPublicKey) {
	C.ctNAKPublicKey_clear(z.pN)
	C.free_ctNAKPublicKey(z.pN)
}

func (a *NAKPublicKey) Export() (key []byte, err error) {
	//var pke *C._CHKPKE_t
	var der *C.uchar
	l := C.size_t(0)

	der, _ = C.ctNAKPublicKey_export_DER(a.pN, &l)
	if der == nil {
		return nil, errors.New("NAKPublicKey.Export: Unable to export public key")
	}

	defer C.free(unsafe.Pointer(der))
	return C.GoBytes(unsafe.Pointer(der), C.int(l)), nil
}

func ImportNAKPublicKey(key []byte) (z *NAKPublicKey) {

	z = new(NAKPublicKey)
	z.pN = C.malloc_ctNAKPublicKey()
	ckey := C.CBytes(key)
	status := C.ctNAKPublicKey_init_import_DER(z.pN, C.unsafeptr_to_ucharptr(ckey), C.size_t(len(key)))
	defer C.free(ckey)
	if status != C.int(0) {
		C.free_ctNAKPublicKey(z.pN)
		return nil
	}
	runtime.SetFinalizer(z, publicNAK_clear)
	return z
}

func ImportNAKSignedPublicKey(spn []byte) (z *NAKPublicKey) {

	z = new(NAKPublicKey)
	z.pN = C.malloc_ctNAKPublicKey()
	cspn := C.CBytes(spn)
	status := C.ctNAKSignedPublicKey_init_import(z.pN, C.unsafeptr_to_ucharptr(cspn), C.size_t(len(spn)))
	defer C.free(cspn)
	if status != C.int(0) {
		C.free_ctNAKPublicKey(z.pN)
		return nil
	}
	runtime.SetFinalizer(z, publicNAK_clear)
	return z
}

func (a *NAKPublicKey) NotValidBefore() (nvbt time.Time) {
	return UTimeToTime(a.pN.not_valid_before)
}

func (a *NAKPublicKey) NotValidAfter() (nvbt time.Time) {
	return UTimeToTime(a.pN.not_valid_after)
}

func (a *NAKPublicKey) ECDSAVerify(msg, sig []byte) (valid bool) {
	var lsig *C._mpECDSASignature_t
	cmsg := C.CBytes(msg)
	csig := C.CBytes(sig)
	lsig = C.malloc_ECDSASignature()
	status := C.ctNAKSignature_init_import_bytes(lsig, C.unsafeptr_to_ucharptr(csig), C.size_t(len(sig)))
	defer C.free(csig)
	defer C.free(cmsg)
	defer C.free_ECDSASignature(lsig)
	if status != 0 {
		return false
	}

	status = C.ctNAKSignature_verify_cmp(lsig, a.pN, C.unsafeptr_to_ucharptr(cmsg), C.size_t(len(msg)))
	C.mpECDSASignature_clear(lsig)
	return (status == 0)
}

func ValidateNAKSignedPublicKey(spn []byte) (valid bool) {
	cspn := C.CBytes(spn)
	status := C.ctNAKSignedPublicKey_validate_cmp(C.unsafeptr_to_ucharptr(cspn), C.size_t(len(spn)))
	defer C.free(cspn)
	return (status == 0)
}
