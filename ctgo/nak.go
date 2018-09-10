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
// ctNAKPublicKey_ptr malloc_array_ctNAKPublicKey(int n) {
//     return (ctNAKPublicKey_ptr)malloc(n * sizeof(_ctNAKPublicKey_t));
// }
//
// ctNAKPublicKey_ptr index_array_ctNAKPublicKey(ctNAKPublicKey_ptr p, int n) {
//     return p + n;
// }
//
// void free_array_ctNAKPublicKey(ctNAKPublicKey_ptr e) {
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
// mpECDSASignature_ptr malloc_nak_ECDSASignature() {
//     return (mpECDSASignature_ptr)malloc(sizeof(_mpECDSASignature_t));
// }
//
// void free_nak_ECDSASignature(mpECDSASignature_ptr csig) {
//     free(csig);
// }
//
// char *nak_mpECP_alloc_out_bytes(mpECP_t pt, int compress) {
//     int leng;
//     char *buf;
//
//     leng = mpECP_out_bytelen(pt, compress);
//     buf = (char *)malloc(leng*sizeof(char));
//     assert(buf != NULL);
//     mpECP_out_bytes(buf, pt, compress);
//     return buf;
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
	"github.com/jadeblaquiere/ecclib/ecgo"
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

var nakCurve *ecgo.Curve

func init() {
	nakCurve = ecgo.NamedCurve("secp256k1")
}

func NAKCurve() (cv *ecgo.Curve) {
	return nakCurve
}

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

	lsig = C.malloc_nak_ECDSASignature()
	status := C.ctNAKSignature_init_Sign(lsig, a.sN, C.unsafeptr_to_ucharptr(cmsg), C.size_t(len(msg)))
	defer C.free(cmsg)
	defer C.free_nak_ECDSASignature(lsig)
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
	lsig = C.malloc_nak_ECDSASignature()
	status := C.ctNAKSignature_init_import_bytes(lsig, C.unsafeptr_to_ucharptr(csig), C.size_t(len(sig)))
	defer C.free(csig)
	defer C.free(cmsg)
	defer C.free_nak_ECDSASignature(lsig)
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

type NAKAuthChallenge struct {
	ch *C._ctNAKAuthChallenge_t
}

// this local point type is a mirror of the internals of ecgo's Point
// so that we can pass the contained C struct pointer on to C routines
type point struct {
	ecp *C._mpECP_t
	cv  *ecgo.Curve
}

func (z *point) bytesUncompressed() []byte {
	blen := C.mpECP_out_bytelen(z.ecp, C.int(0))
	cstr := C.nak_mpECP_alloc_out_bytes(z.ecp, C.int(0))
	gstr := C.GoBytes(unsafe.Pointer(cstr), blen)
	C.free(unsafe.Pointer(cstr))
	return gstr
}

func NewNAKAuthChallenge(PNAKlist [](*NAKPublicKey), sessionPK *ecgo.Point, expire time.Time, sessionSecret *ecgo.Point) (ch *NAKAuthChallenge) {
	var localSessionPK *point
	var localSessionSecret *point
	var lpN *NAKPublicKey

	clen := len(PNAKlist)
	cnaklist := C.malloc_array_ctNAKPublicKey(C.int(clen))
	defer C.free_array_ctNAKPublicKey(cnaklist)
	for i := 0; i < clen; i++ {
		//fmt.Println("i = ", i)
		lpN = PNAKlist[i]
		C.ctNAKPublicKey_init_set(C.index_array_ctNAKPublicKey(cnaklist, C.int(i)), lpN.pN)
	}
	ch = new(NAKAuthChallenge)
	ch.ch = C.malloc_ctNAKAuthChallenge()
	localSessionPK = (*point)(unsafe.Pointer(sessionPK))
	localSessionSecret = (*point)(unsafe.Pointer(sessionSecret))
	status := C.ctNAKAuthChallenge_init(ch.ch, C.int(clen), cnaklist, localSessionPK.ecp, TimeToUTime(expire), localSessionSecret.ecp)
	if status != 0 {
		C.free_ctNAKAuthChallenge(ch.ch)
		return nil
	}
	runtime.SetFinalizer(ch, nakAuthChallenge_clear)
	return ch
}

func nakAuthChallenge_clear(z *NAKAuthChallenge) {
	C.ctNAKAuthChallenge_clear(z.ch)
	C.free_ctNAKAuthChallenge(z.ch)
}

func (a *NAKAuthChallenge) Export() (key []byte, err error) {
	var der *C.uchar
	l := C.size_t(0)

	der, _ = C.ctNAKAuthChallenge_export_DER(a.ch, &l)
	if der == nil {
		return nil, errors.New("NAKAuthChallenge.Export: Unable to export challenge")
	}

	defer C.free(unsafe.Pointer(der))
	return C.GoBytes(unsafe.Pointer(der), C.int(l)), nil
}

func ImportNAKAuthChallenge(chbytes []byte) (z *NAKAuthChallenge) {

	z = new(NAKAuthChallenge)
	z.ch = C.malloc_ctNAKAuthChallenge()
	ckey := C.CBytes(chbytes)
	status := C.ctNAKAuthChallenge_init_import_DER(z.ch, C.unsafeptr_to_ucharptr(ckey), C.size_t(len(chbytes)))
	defer C.free(ckey)
	if status != C.int(0) {
		C.free_ctNAKAuthChallenge(z.ch)
		return nil
	}
	runtime.SetFinalizer(z, nakAuthChallenge_clear)
	return z
}

type NAKAuthResponse struct {
	rs *C._ctNAKAuthResponse_t
}

func NewNAKAuthResponse(ch *NAKAuthChallenge, sN *NAKSecretKey) (rs *NAKAuthResponse) {

	rs = new(NAKAuthResponse)
	rs.rs = C.malloc_ctNAKAuthResponse()
	status := C.ctNAKAuthResponse_init(rs.rs, ch.ch, sN.sN)
	if status != C.int(0) {
		C.free_ctNAKAuthResponse(rs.rs)
		return nil
	}
	runtime.SetFinalizer(rs, nakAuthResponse_clear)
	return rs
}

func nakAuthResponse_clear(z *NAKAuthResponse) {
	C.ctNAKAuthResponse_clear(z.rs)
	C.free_ctNAKAuthResponse(z.rs)
}

type fieldElement struct {
	fe *C._mpFp_struct
}

func (a *NAKAuthResponse) Validate(sessionSK *ecgo.FieldElement, sessionSecret *ecgo.Point) (valid bool) {
	localSessionSK := (*fieldElement)(unsafe.Pointer(sessionSK))
	localSessionSecret := (*point)(unsafe.Pointer(sessionSecret))
	status := C.ctNAKAuthResponse_validate_cmp(a.rs, localSessionSK.fe, localSessionSecret.ecp)
	return (status == 0)
}

func (a NAKAuthResponse) Export() (key []byte, err error) {
	var der *C.uchar
	l := C.size_t(0)

	der, _ = C.ctNAKAuthResponse_export_DER(a.rs, &l)
	if der == nil {
		return nil, errors.New("NAKAuthResponse.Export: Unable to export response")
	}

	defer C.free(unsafe.Pointer(der))
	return C.GoBytes(unsafe.Pointer(der), C.int(l)), nil
}

func ImportNAKAuthResponse(chbytes []byte) (z *NAKAuthResponse) {

	z = new(NAKAuthResponse)
	z.rs = C.malloc_ctNAKAuthResponse()
	ckey := C.CBytes(chbytes)
	status := C.ctNAKAuthResponse_init_import_DER(z.rs, C.unsafeptr_to_ucharptr(ckey), C.size_t(len(chbytes)))
	defer C.free(ckey)
	if status != C.int(0) {
		C.free_ctNAKAuthResponse(z.rs)
		return nil
	}
	runtime.SetFinalizer(z, nakAuthResponse_clear)
	return z
}
