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
//
// void ctMessageHeader_copy_to_host(ctMessageHeader_ptr host, ctMessageHeader_ptr wire) {
// 	   memcpy(host, wire, sizeof(_ctMessageHeader_t));
// 	   host->msgtime_usec = le64toh(wire->msgtime_usec);
//	   host->expire_usec = le64toh(wire->expire_usec);
// 	   host->payload_blocks = le64toh(wire->payload_blocks);
// 	   return;
// }
//
// unsigned char *ctMessageHeader_as_bytes(ctMessageHeader_ptr mh) {
//     return (unsigned char *)mh;
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
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/goleveldb/leveldb"
	"github.com/btcsuite/goleveldb/leveldb/util"
	"io/ioutil"
	//"math/big"
	"os"
	//"reflect"
	"runtime"
	//"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"
)

const pruneMaxBatch = (32)

var zeroHash []byte = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

var zeroTime []byte = []byte{0, 0, 0, 0, 0, 0, 0, 0}

type MessageOrHeader interface {
	MessageTime() time.Time
	ExpireTime() time.Time
	PayloadBlocks() uint64
	PayloadHash() []byte
}

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
	runtime.SetFinalizer(h, clearMessageHeader)
	return h
}

func (m *MessageHeader) IsValid() bool {
	var hcp C._ctMessageHeader_t
	C.ctMessageHeader_copy_to_host(&hcp, m.hdr)
	if C.ctMessageHeader_is_valid(&hcp) == 0 {
		return false
	}
	return true
}

func clearMessageHeader(h *MessageHeader) {
	C.free_ctMessageHeader(h.hdr)
}

// MessageFile represents the stored binary format of a message. MessageFile
// generally treats the content as opaque data for performance.
type MessageFile struct {
	MessageHeader
	size       uint64
	serverTime time.Time
	filename   string
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
	mf.size = uint64(finfo.Size())
	mf.serverTime = finfo.ModTime()
	mf.filename = filename
	return mf, nil
}

func (a *MessageFile) Size() uint64 {
	return a.size
}

func (a *MessageFile) ServerTime() time.Time {
	return a.serverTime
}

func (a *MessageFile) Filename() string {
	return a.filename
}

func (a *MessageFile) IsValid() bool {
	if a.MessageHeader.IsValid() {
		return a.isSizeValid()
	}
	return false
}

func (a *MessageFile) isSizeValid() (valid bool) {
	return a.size == ((a.MessageHeader.PayloadBlocks() + 1) * uint64(C._hdrlen))
}

func (a *MessageFile) Decrypt(sK *SecretKey) (z *Message) {
	ctext, err := ioutil.ReadFile(a.filename)
	if err != nil {
		return nil
	}
	return DecryptMessage(sK, ctext)
}

func (a *MessageFile) Ciphertext() []byte {
	ctext, err := ioutil.ReadFile(a.filename)
	if err != nil {
		return nil
	}
	return ctext
}

func (a *MessageFile) CiphertextFile() (cfile *os.File, err error) {
	cfile, err = os.Open(a.filename)
	if err != nil {
		return nil, errors.New("MessageFile.CiphertextFile: error opening file: " + err.Error())
	}
	return cfile, nil
}

func (a *MessageFile) Rename(newpath string) (err error) {
	_, err = os.Stat(a.filename)
	if err != nil {
		return errors.New("MessageFile.Rename: File not found? Deleted out of band?")
	}
	_, err = os.Stat(newpath)
	if err == nil {
		return errors.New("MessageFile.Rename: New file already exists, cowardly refusing to overwrite")
	}
	err = os.Rename(a.filename, newpath)
	if err != nil {
		return errors.New("MessageFile.Rename: error renaming : " + err.Error())
	}
	a.filename = newpath
	return nil
}

type MessageStore struct {
	db      *leveldb.DB
	rootdir string
	count   int64
	cchan   chan int
	wg      sync.WaitGroup
}

// msCounter handles updating counter based on insert and delete actions
// for MessageFile objects. All writes to the message count occur in this
// goroutine, which serializes changes through a buffered channel, thereby
// avoiding locks on the counter as only a single goroutine writes to the
// counter
func msCounter(ms *MessageStore) {
	defer ms.wg.Done()
	for {
		select {
		case x := <-ms.cchan:
			if x == 0 {
				return
			}
			ms.count += int64(x)
		}
	}
}

func OpenMessageStore(rootdir string) (ms *MessageStore, err error) {
	finfo, err := os.Stat(rootdir)
	if err != nil {
		// error on stat, try creating dir
		err = os.MkdirAll(rootdir, 0700)
		if err != nil {
			return nil, errors.New("cannot create root directory")
		}
		finfo, err = os.Stat(rootdir)
		if err != nil {
			return nil, errors.New("cannot stat created directoy")
		}
	}

	if finfo.IsDir() != true {
		return nil, errors.New("rootdir is not a directory")
	}

	db, err := leveldb.OpenFile(rootdir+"/msgdb", nil)
	if err != nil {
		return nil, errors.New("open DB failed : " + err.Error())
	}

	ms = new(MessageStore)
	ms.db = db
	ms.rootdir = rootdir
	dbtag := append([]byte{0xFF}, zeroHash...)
	dbcount, err := ms.db.Get(dbtag, nil)
	if err == nil {
		ms.count = int64(binary.LittleEndian.Uint64(dbcount))
	} else {
		ms.count = 0
	}
	ms.cchan = make(chan int, 256)
	go msCounter(ms)
	db.Delete(dbtag, nil)

	for i := 0x000; i < 0x1000; i++ {
		var phash [2]byte

		phash[0] = byte((i >> 8) & 0xFF)
		phash[1] = byte(i & 0xFF)
		phstr := hex.EncodeToString(phash[:])
		err = os.MkdirAll(rootdir+"/msg/"+phstr, 0700)
		if err != nil {
			ms.Close()
			return nil, errors.New("unable to write directory: " + phstr)
		}
	}

	return ms, nil
}

func (ms *MessageStore) Close() {
	ms.wg.Add(1)
	ms.cchan <- 0
	ms.wg.Wait()
	dbcount := make([]byte, 8)
	binary.LittleEndian.PutUint64(dbcount[0:], uint64(ms.count))
	dbtag := append([]byte{0xFF}, zeroHash...)
	// ignore errors at this point as we're closing, so no recovery
	ms.db.Put(dbtag, dbcount, nil)
	ms.db.Close()
	return
}

func (ms *MessageStore) RescanRecount() (err error) {
	ecount := 0
	// zero count
	if ms.count != 0 {
		ms.cchan <- int(-(ms.count))
	}
	for i := 0x000; i < 0x1000; i++ {
		var phash [2]byte

		phash[0] = byte((i >> 8) & 0xFF)
		phash[1] = byte(i & 0xFF)
		phstr := hex.EncodeToString(phash[:])
		msgdir := ms.rootdir + "/msg/" + phstr
		f, err := os.Open(msgdir)
		if err != nil {
			fmt.Println("unable to open directory: " + phstr)
			ecount += 1
			continue
		}
		names, err := f.Readdirnames(0)
		for _, name := range names {
			mf, err := NewMessageFile(msgdir + "/" + name)
			if err != nil {
				fmt.Println("error reading file: " + phstr + "/" + name)
				ecount += 1
				continue
			}
			ms.IngestMessageFile(mf)
		}
	}
	if ecount > 0 {
		return errors.New("RescanRecount: error count: " + string(ecount))
	}
	return nil
}

func (ms *MessageStore) Count() (c int64) {
	return ms.count
}

func (ms *MessageStore) msgPath(mh MessageOrHeader) string {
	phash := mh.PayloadHash()
	pdir := ms.rootdir + "/msg/0" + hex.EncodeToString(phash[:2])[0:3] + "/"
	return pdir + hex.EncodeToString(phash[:])
}

type msgTags struct {
	htag []byte
	etag []byte
}

func (ms *MessageStore) msgTags(mh MessageOrHeader) (mt *msgTags) {
	mhash := mh.PayloadHash()
	etime := uint64(TimeToUTime(mh.ExpireTime()))
	etbytes := make([]byte, 8)
	binary.BigEndian.PutUint64(etbytes[0:], etime)
	mt = new(msgTags)
	mt.htag = append([]byte{0x01}, mhash...)
	mt.etag = append(append([]byte{0x02}, etbytes...), mhash...)
	return mt
}

func (mf *MessageFile) dbSerialize() []byte {
	chbytes := C.ctMessageHeader_as_bytes(mf.hdr)
	ser1 := C.GoBytes(unsafe.Pointer(chbytes), C._hdrlen)
	ser2 := make([]byte, 16)
	binary.LittleEndian.PutUint64(ser2[0:], mf.size)
	stime := uint64(TimeToUTime(mf.serverTime))
	binary.LittleEndian.PutUint64(ser2[8:], stime)
	return append(ser1, ser2...)
}

func (ms *MessageStore) IngestMessage(m *Message) (err error) {
	mpath := ms.msgPath(m)
	mf, err := m.WriteToFile(mpath)
	if err != nil {
		return errors.New("MessageStore.Ingest failed to write to file: " + err.Error())
	}
	return ms.insertMessageFile(mf)
}

func (ms *MessageStore) IngestMessageFile(mf *MessageFile) (err error) {
	mpath := ms.msgPath(mf)
	if strings.Compare(mpath, mf.filename) != 0 {
		err = mf.Rename(mpath)
		if err != nil {
			return errors.New("MessageStore.IngestMessageFile rename failed: " + err.Error())
		}
	}
	//fmt.Println("calling insert")
	return ms.insertMessageFile(mf)
}

func (ms *MessageStore) insertMessageFile(mf *MessageFile) (err error) {
	if mf.IsValid() == false {
		return errors.New("Refusing to Ingest malformed message")
	}
	mt := ms.msgTags(mf)
	mdata := mf.dbSerialize()
	batch := new(leveldb.Batch)
	batch.Put(mt.htag, mdata)
	batch.Put(mt.etag, mdata)
	err = ms.db.Write(batch, nil)
	if err == nil {
		ms.cchan <- 1
	}
	return err
}

func (ms *MessageStore) HasMessage(phash []byte) bool {
	_, err := ms.db.Get(append([]byte{0x01}, phash...), nil)
	if err != nil {
		return false
	}
	return true
}

func (ms *MessageStore) GetMessage(phash []byte) (mf *MessageFile) {
	mdata, err := ms.db.Get(append([]byte{0x01}, phash...), nil)
	if err != nil {
		return nil
	}
	mf = new(MessageFile)
	cby := C.CBytes(mdata[0:int(C._hdrlen)])
	mf.hdr = C.ctMessageHeader_adopt_bytes(C.unsafeptr_to_ucharptr(cby))
	mf.filename = ms.msgPath(mf)
	mf.size = binary.LittleEndian.Uint64(mdata[int(C._hdrlen):])
	stime := binary.LittleEndian.Uint64(mdata[int(C._hdrlen)+8:])
	mf.serverTime = UTimeToTime(C.utime_t(stime))
	return mf
}

func (ms *MessageStore) pruneExpired() (err error) {
	now := uint64(TimeToUTime(time.Now()))
	nowb := make([]byte, 8)
	binary.LittleEndian.PutUint64(nowb[0:], now)
	// start of drop time = 0 (1 Jan 1970)
	sdrop := append(append([]byte{0x02}, zeroTime...), zeroHash...)
	// end of drop time = now
	edrop := append(append([]byte{0x02}, nowb...), zeroHash...)
	iter := ms.db.NewIterator(&util.Range{Start: sdrop, Limit: edrop}, nil)
	ndrop := 0
	batch := new(leveldb.Batch)
	mf := new(MessageFile)
	for iter.Next() {
		val := iter.Value()
		cby := C.CBytes(val[0:int(C._hdrlen)])
		mf.hdr = C.ctMessageHeader_adopt_bytes(C.unsafeptr_to_ucharptr(cby))
		mt := ms.msgTags(mf)
		C.free(cby)
		batch.Delete(mt.htag)
		batch.Delete(mt.etag)
		ndrop += 1
		if ndrop == pruneMaxBatch {
			err = ms.db.Write(batch, nil)
			if err != nil {
				return errors.New("MessageStore.pruneEpired: Write Error:" + err.Error())
			}
			ms.cchan <- ndrop
			ndrop = 0
			batch = new(leveldb.Batch)
		}
	}
	if ndrop > 0 {
		err := ms.db.Write(batch, nil)
		if err != nil {
			return errors.New("MessageStore.pruneEpired: Write Error:" + err.Error())
		}
		ms.cchan <- ndrop
	}
	return nil
}

func (ms *MessageStore) ListHashesForInterval(start, end time.Time) (hlist [][]byte, err error) {
	startb := make([]byte, 8)
	binary.LittleEndian.PutUint64(startb[0:], uint64(TimeToUTime(start)))
	endb := make([]byte, 8)
	binary.LittleEndian.PutUint64(endb[0:], uint64(TimeToUTime(end))+1)
	stag := append(append([]byte{0x02}, startb...), zeroHash...)
	etag := append(append([]byte{0x02}, endb...), zeroHash...)
	iter := ms.db.NewIterator(&util.Range{Start: stag, Limit: etag}, nil)
	hlist = [][]byte{}
	mf := new(MessageFile)
	for iter.Next() {
		val := iter.Value()
		cby := C.CBytes(val[0:int(C._hdrlen)])
		mf.hdr = C.ctMessageHeader_adopt_bytes(C.unsafeptr_to_ucharptr(cby))
		hlist = append(hlist, mf.PayloadHash())
	}
	if len(hlist) == 0 {
		return nil, nil
	}
	return hlist, nil
}
