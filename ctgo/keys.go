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
// #include <ciphrtxt/keys.h>
// #include <ciphrtxt/utime.h>
// #include <stdlib.h>
//
// ctSecretKey_ptr malloc_ctSecretKey() {
//     return (ctSecretKey_ptr)malloc(sizeof(_ctSecretKey_t));
// }
//
// void free_ctSecretKey(ctSecretKey_ptr e) {
//     free(e);
// }
//
// ctPublicKey_ptr malloc_ctPublicKey() {
//     return (ctPublicKey_ptr)malloc(sizeof(_ctPublicKey_t));
// }
//
// void free_ctPublicKey(ctPublicKey_ptr e) {
//     free(e);
// }
//
// unsigned char *unsafeptr_to_ucharptr(void *in) {
//     return (unsigned char *)in;
// }
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

func init() {
	C._enable_gmp_safe_clean()
}

// SecretKey is a composite key containing individual secret keys for anonymous
// addressing, signing and encryption. The encryption keys include a forward
// secure component which enables the keyholder to update the secret key
// such that past messages can no longer be decrypted.
type SecretKey struct {
	sK *C._ctSecretKey_t
}

// PublicKey is a composite key containing individual public keys for anonymous
// authentication, signing and encryption.
type PublicKey struct {
	pK *C._ctPublicKey_t
}

// NewSecretKey creates a new (random) secret key. The values for qbits, rbits
// determine the field size and the prime order of the underlying curves. Depth
// and order determine the number of key intervals (the implementation uses a
// btree so the number of intervals is order**depth). tStep determines the
// resolution of forward secrecy. Supplying a zero value for any input will
// select the default values (512, 384, 6, 16, 60 Seconds, respectively)
func NewSecretKey(qbits, rbits, depth, order int, tStep time.Duration) (z *SecretKey) {

	z = new(SecretKey)
	z.sK = C.malloc_ctSecretKey()
	C.ctSecretKey_init_Gen(z.sK, C.int(qbits), C.int(rbits), C.int(depth), C.int(order), DurationToUTime(tStep))

	runtime.SetFinalizer(z, secretKey_clear)
	return z
}

func secretKey_clear(z *SecretKey) {
	C.ctSecretKey_clear(z.sK)
	C.free_ctSecretKey(z.sK)
}

// Export serializes a binary representation of the key which is able to
// decrypt messages for the specified time and later (older messages cannot
// be decrypted as the key implements forward secrecy). If the Secret Key is
// newer that the time t then an error is returned as it is not possible to
// derive keys "from the past". The key is serialized using (binary) ASN.1 DER
// encoding.
func (z *SecretKey) Export(t time.Time) (key []byte, err error) {
	//var pke *C._CHKPKE_t
	var der *C.uchar
	l := C.size_t(0)

	der, _ = C.ctSecretKey_Export_FS_DER(z.sK, TimeToUTime(t), &l)
	if der == nil {
		return nil, errors.New("SecretKey.Export: Unable to export secret key")
	}

	defer C.free(unsafe.Pointer(der))
	return C.GoBytes(unsafe.Pointer(der), C.int(l)), nil
}

// ExportDelegate serializes a binary representation of the key which is able to
// decrypt messages for the specified window of time (only messages from the
// period between notBefore and notAfter can be decrypted). The key is
// serialized using (binary) ASN.1 DER encoding.
func (z *SecretKey) ExportDelegate(notBefore, notAfter time.Time) (key []byte, err error) {
	//var pke *C._CHKPKE_t
	var der *C.uchar
	l := C.size_t(0)

	der, _ = C.ctSecretKey_Export_FS_Delegate_DER(z.sK, TimeToUTime(notBefore), TimeToUTime(notAfter), &l)
	if der == nil {
		return nil, errors.New("SecretKey.Export: Unable to export secret key")
	}

	defer C.free(unsafe.Pointer(der))
	return C.GoBytes(unsafe.Pointer(der), C.int(l)), nil
}

func ImportSecretKey(key []byte) (z *SecretKey) {

	z = new(SecretKey)
	z.sK = C.malloc_ctSecretKey()
	ckey := C.CBytes(key)
	status := C.ctSecretKey_init_decode_DER(z.sK, C.unsafeptr_to_ucharptr(ckey), C.size_t(len(key)))
	defer C.free(ckey)
	if status != C.int(0) {
		C.free_ctSecretKey(z.sK)
		return nil
	}
	runtime.SetFinalizer(z, secretKey_clear)
	return z
}

func (z *SecretKey) NotValidBefore() (t time.Time) {
	minI := z.sK._intervalMin
	minU := C._ctSecretKey_time_for_interval(z.sK, minI)
	return UTimeToTime(minU)
}

func (z *SecretKey) NotValidAfter() (t time.Time) {
	maxI := z.sK._intervalMax
	maxU := C._ctSecretKey_time_for_interval(z.sK, maxI)
	return UTimeToTime(maxU)
}

func (z *SecretKey) PublicKey() (a *PublicKey) {
	a = new(PublicKey)
	a.pK = C.malloc_ctPublicKey()
	C.ctPublicKey_init_ctSecretKey(a.pK, z.sK)

	runtime.SetFinalizer(a, publicKey_clear)
	return a
}

func publicKey_clear(a *PublicKey) {
	C.ctPublicKey_clear(a.pK)
	C.free_ctPublicKey(a.pK)
}

// Export serializes a binary representation of the key which is able to
// encrypt messages addressed to the corresponding secret key.
func (z *PublicKey) Export() (key []byte, err error) {
	//var pke *C._CHKPKE_t
	var der *C.uchar
	l := C.size_t(0)

	der, _ = C.ctPublicKey_Export_DER(z.pK, &l)
	if der == nil {
		return nil, errors.New("PublicKey.Export: Unable to export public key")
	}

	defer C.free(unsafe.Pointer(der))
	return C.GoBytes(unsafe.Pointer(der), C.int(l)), nil
}

func ImportPublicKey(key []byte) (z *PublicKey) {

	z = new(PublicKey)
	z.pK = C.malloc_ctPublicKey()
	ckey := C.CBytes(key)
	status := C.ctPublicKey_init_decode_DER(z.pK, C.unsafeptr_to_ucharptr(ckey), C.size_t(len(key)))
	defer C.free(ckey)
	if status != C.int(0) {
		C.free_ctPublicKey(z.pK)
		return nil
	}
	runtime.SetFinalizer(z, publicKey_clear)
	return z
}
