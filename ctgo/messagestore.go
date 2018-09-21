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
// #include <../include/portable_endian.h>
// #include <sodium.h>
// #include <stdlib.h>
// #include <string.h>
//
// int _cgh_hashlen = crypto_generichash_BYTES;
// int _hdrlen = _CT_BLKSZ;
//
// ctMessageHeader_ptr malloc_ctMessageHeader() {
//     return (ctMessageHeader_ptr)malloc(sizeof(_ctMessageHeader_t));
// }
//
// ctMessageHeader_ptr ctMessageHeader_adopt_bytes(unsigned char *mbytes) {
//     return (ctMessageHeader_ptr)mbytes;
// }
//
// void free_ctMessageHeader(ctMessageHeader_ptr e) {
//     free(e);
// }
//
// int64_t int64_from_LE(int64_t in) {
//     return le64toh(in);
// }
//
// uint64_t uint64_from_LE(uint64_t in) {
//     return le64toh(in);
// }
//
// utime_t utime_from_LE(utime_t in) {
//     return le64toh(in);
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

type MessageHeader struct {
	// NOTE : inside MessageHeader the ctMessageHeader_t is in raw wire format
	// unlike ctMessage_t.hdr which tranforms for endianness. In most
	// cases these are equivalent as ciphrtxt uses litte-endian in the wire
	// format, however on big-endian targets they will not be the same
	hdr *C._ctMessageHeader_t
}

func (m *MessageHeader) MessageTime() (t time.Time) {
	return UTimeToTime(C.utime_from_LE(m.hdr.msgtime_usec))
}

func (m *MessageHeader) ExpireTime() (t time.Time) {
	return UTimeToTime(C.utime_from_LE(m.hdr.expire_usec))
}

func (m *MessageHeader) PayloadBlocks() (blocks uint64) {
	return uint64(C.uint64_from_LE(m.hdr.payload_blocks))
}

func (m *MessageHeader) PayloadHash() (h []byte) {
	return C.GoBytes(unsafe.Pointer(&m.hdr.payload_hash[0]), C._cgh_hashlen)
}

func NewMessageHeader(hbytes []byte) (h *MessageHeader) {
	if len(hbytes) < int(C._hdrlen) {
		return nil
	}
	h = new(MessageHeader)
	cby := C.CBytes(hbytes[0:int(C._hdrlen)])
	h.hdr = C.ctMessageHeader_adopt_bytes(C.unsafeptr_to_ucharptr(cby))
	runtime.SetFinalizer(h, header_clear)
	return h
}

func header_clear(h *MessageHeader) {
	C.free_ctMessageHeader(h.hdr)
}

// MessageFile represents the stored binary format of a message. MessageFile
// generally treats the content as opaque data for performance.
type MessageFile struct {
	MessageHeader
	Size       uint64
	ServerTime time.Time
	Filename   string
}

func NewMessageFile(filename string) (mf *MessageFile, err error) {
	finfo, err := os.Stat(filename)
	if err != nil {
		return nil, errors.New("NewMessageFile: File stat failed")
	}
	mFile, err := os.Open(filename)
	if err != nil {
		return nil, errors.New("NewMessageFile: Unable to open file for read")
	}
	defer mFile.Close()
	hbytes := make([]byte, int(C._hdrlen))
	_, err = mFile.Read(hbytes)
	if err != nil {
		return nil, errors.New("NewMessageFile: Short read importing header")
	}
	mf = new(MessageFile)
	cby := C.CBytes(hbytes)
	mf.hdr = C.ctMessageHeader_adopt_bytes(C.unsafeptr_to_ucharptr(cby))
	mf.Size = uint64(finfo.Size())
	mf.ServerTime = finfo.ModTime()
	mf.Filename = filename
	return mf, nil
}

func (a *MessageFile) isSizeValid() (valid bool) {
	return a.Size == ((a.MessageHeader.PayloadBlocks() + 1) * uint64(C._hdrlen))
}

func (a *MessageFile) Decrypt(sK *SecretKey) (z *Message) {
	ctext, err := ioutil.ReadFile(a.Filename)
	if err != nil {
		return nil
	}
	return DecryptMessage(sK, ctext)
}
