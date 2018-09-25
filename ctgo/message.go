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
// #include <ciphrtxt/message.h>
// #include <ciphrtxt/postage.h>
// #include <ciphrtxt/utime.h>
// #include <stdlib.h>
//
// ctMessage_ptr malloc_ctMessage() {
//     return (ctMessage_ptr)malloc(sizeof(_ctMessage_t));
// }
//
// void free_ctMessage(ctMessage_ptr e) {
//     free(e);
// }
//
// unsigned char *unsafeptr_to_ucharptr(void *in);
//
// ctMessageHeader_ptr ctMessageHeader_adopt_bytes(unsigned char *mbytes);
//
// extern int _cgh_hashlen;
// extern int _hdrlen;
//
import "C"

import (
	//"bytes"
	//"encoding/base64"
	//"encoding/hex"
	//"encoding/binary"
	"errors"
	//"fmt"
	"io/ioutil"
	//"math/big"
	"os"
	//"reflect"
	"runtime"
	//"strconv"
	//"strings"
	"time"
	"unsafe"
)

type Message struct {
	m *C._ctMessage_t
}

// unsigned char *ctMessage_init_Enc(ctMessage_t msg, ctPublicKey_t toK, ctSecretKey_t fromK,
//   utime_t timestamp, utime_t ttl, char *mime, unsigned char *plaintext,
//   size_t p_sz, ctPostageRate_t rate, size_t *sz);

func EncryptMessage(to *PublicKey, from *SecretKey, timestamp time.Time, ttl time.Duration, mime string, ptxt []byte, postage *PostageRate) (z *Message) {
	var fm *C._ctSecretKey_t
	var cciphersz C.size_t

	if to == nil {
		return nil
	}

	if from == nil {
		fm = nil
	} else {
		fm = from.sK
	}

	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	z = new(Message)
	z.m = C.malloc_ctMessage()
	cmime := C.CString(mime)
	if len(mime) == 0 {
		cmime = nil
	}
	cptxt := C.CBytes(ptxt)
	cptlen := C.size_t(len(ptxt))
	cctxt := C.ctMessage_init_Enc(z.m, to.pK, fm, TimeToUTime(timestamp), DurationToUTime(ttl), cmime, C.unsafeptr_to_ucharptr(cptxt), cptlen, postage.pR, &cciphersz)
	C.memset(cptxt, 0, C.size_t(len(ptxt)))
	C.free(cptxt)
	C.memset(unsafe.Pointer(cmime), 0, C.size_t(len(mime)))
	C.free(unsafe.Pointer(cmime))
	if cctxt == nil {
		C.free_ctMessage(z.m)
		return nil
	}

	runtime.SetFinalizer(z, message_clear)
	return z
}

func message_clear(z *Message) {
	C.ctMessage_clear(z.m)
	C.free_ctMessage(z.m)
}

// int ctMessage_init_Dec(ctMessage_t msg, ctSecretKey_t toK, unsigned char *ctext, size_t ctextsz);

func DecryptMessage(sK *SecretKey, ctxt []byte) (z *Message) {
	ctsz := C.size_t(len(ctxt))
	cctxt := C.CBytes(ctxt)
	z = new(Message)
	z.m = C.malloc_ctMessage()
	status := C.ctMessage_init_Dec(z.m, sK.sK, C.unsafeptr_to_ucharptr(cctxt), ctsz)
	C.memset(cctxt, 0, C.size_t(len(ctxt)))
	C.free(cctxt)
	if status != C.int(0) {
		C.free_ctMessage(z.m)
		return nil
	}
	runtime.SetFinalizer(z, message_clear)
	return z
}

func (z *Message) Ciphertext() []byte {
	var ctsz C.size_t

	ctxt := C.ctMessage_ciphertext_ptr(z.m, &ctsz)
	if ctxt == nil {
		return nil
	}
	if ctsz == C.size_t(0) {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(ctxt), C.int(ctsz))
}

func (z *Message) Plaintext() []byte {
	var ptsz C.size_t

	ptxt := C.ctMessage_plaintext_ptr(z.m, &ptsz)
	if ptxt == nil {
		return nil
	}
	if ptsz == C.size_t(0) {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(ptxt), C.int(ptsz))
}

func (a *Message) WriteToFile(filename string) (z *MessageFile, err error) {
	rdFile, err := os.Open(filename)
	if err == nil {
		rdFile.Close()
		return nil, errors.New("WriteToFile: File Already Exists")
	}

	ct := a.Ciphertext()
	err = ioutil.WriteFile(filename, ct, 0644)
	if err != nil {
		return nil, err
	}
	z = new(MessageFile)
	cby := C.CBytes(ct[0:int(C._hdrlen)])
	z.hdr = C.ctMessageHeader_adopt_bytes(C.unsafeptr_to_ucharptr(cby))
	z.size = uint64(len(ct))
	z.serverTime = time.Now()
	z.filename = filename
	return z, nil
}

func (m *Message) MessageTime() (t time.Time) {
	return UTimeToTime(m.m.hdr[0].msgtime_usec)
}

func (m *Message) ExpireTime() (t time.Time) {
	return UTimeToTime(m.m.hdr[0].expire_usec)
}

func (m *Message) PayloadBlocks() (blocks uint64) {
	return uint64(m.m.hdr[0].payload_blocks)
}

func (m *Message) PayloadHash() (h []byte) {
	return C.GoBytes(unsafe.Pointer(&m.m.hdr[0].payload_hash[0]), C._cgh_hashlen)
}
