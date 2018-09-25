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

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestWriteMessage(t *testing.T) {
	sKA := NewSecretKey(0, 0, 0, 0, 0)
	sKB := NewSecretKey(0, 0, 0, 0, 0)
	pKA := sKA.PublicKey()
	//pKB := sKB.PublicKey()

	ptxt := []byte("Hello, Alice")
	fmt.Println("Encrypting \"" + string(ptxt) + "\"")
	// base value = 10 + (1 / 65536)
	prate := NewPostageRate(10, 65536, 1, (64 * 16777216))
	//prate := NewPostageRate(0, 0, 0, 0)
	ctmsg := EncryptMessage(pKA, sKB, time.Now(), time.Duration(7*24*time.Hour), "", ptxt, prate)
	if ctmsg == nil {
		fmt.Println("ctmsg is nil!")
		t.FailNow()
	}

	tfilename := hex.EncodeToString(ctmsg.PayloadHash())
	mf, err := ctmsg.WriteToFile(tfilename)
	if err != nil {
		fmt.Println("Error writing temp file!")
		t.FailNow()
	}
	defer os.Remove(tfilename)

	if mf.isSizeValid() != true {
		fmt.Println("mf size mismatch!")
		t.FailNow()
	}

	mf2, err := NewMessageFile(tfilename)
	if err != nil {
		fmt.Println("Error reading temp file!")
		t.FailNow()
	}

	if mf2.isSizeValid() != true {
		fmt.Println("mf2 size mismatch!")
		t.FailNow()
	}

	if mf.MessageTime().Sub(mf2.MessageTime()) != 0 {
		fmt.Println("MessageTime mismatch!")
		t.FailNow()
	}

	if mf.ExpireTime().Sub(mf2.ExpireTime()) != 0 {
		fmt.Println("ExpireTime mismatch!")
		t.FailNow()
	}

	if mf.PayloadBlocks() != mf2.PayloadBlocks() {
		fmt.Println("PayloadBlocks mismatch!")
		t.FailNow()
	}

	if bytes.Compare(mf.PayloadHash(), mf2.PayloadHash()) != 0 {
		fmt.Println("PayloadHash mismatch!")
		t.FailNow()
	}

	if bytes.Compare(mf2.Ciphertext(), ctmsg.Ciphertext()) != 0 {
		fmt.Println("Ciphertext mismatch!")
		t.FailNow()
	}

	ctmsgcp := mf2.Decrypt(sKA)
	if ctmsgcp == nil {
		fmt.Println("ctmsgcp is nil!")
		t.FailNow()
	}
	ptxtcp := ctmsgcp.Plaintext()
	fmt.Println("decrypted (", len(ptxtcp), " bytes) = ", string(ptxtcp))
	if bytes.Compare(ptxt, ptxtcp) != 0 {
		fmt.Println("TestEncryptDecryptMessage: Decrypt(Encrypt(msg)) != msg")
		t.FailNow()
	}
}

func TestOpenMessageStore(t *testing.T) {
	// force GC - ensure db is closed before opening
	//runtime.GC()
	ms, err := OpenMessageStore("mstore")
	if err != nil {
		fmt.Println("TestOpenMessageStore: OpenMessageStore Failed : ", err.Error())
		t.FailNow()
	}
	ms.Close()
}

func TestMessageStoreIngestGet(t *testing.T) {
	// force GC - ensure db is closed before opening
	runtime.GC()
	sK := make([]*SecretKey, 10)
	pK := make([]*PublicKey, len(sK))
	m := make([]*Message, len(sK)*len(sK))
	for i := 0; i < len(sK); i++ {
		sK[i] = NewSecretKey(0, 0, 0, 0, 0)
		pK[i] = sK[i].PublicKey()
	}

	prate := NewPostageRate(10, 65536, 1, (64 * 16777216))
	ptxt := []byte("Hello, Alice")

	ms, err := OpenMessageStore("mstore")
	if err != nil {
		fmt.Println("TestMessageStoreIngestGet: OpenMessageStore Failed : ", err.Error())
		t.FailNow()
	}

	for i := 0; i < len(sK); i++ {
		for j := 0; j < len(sK); j++ {
			if i == j {
				continue
			}
			m[(i*len(sK))+j] = EncryptMessage(pK[j], sK[i], time.Now(), time.Duration(7*24*time.Hour), "", ptxt, prate)
			err = ms.IngestMessage(m[(i*len(sK))+j])
			if err != nil {
				fmt.Println("TestMessageStoreIngestGet: ms.IngestMessage Failed : ", err.Error())
				t.FailNow()
			}
		}
	}
	ms.Close()
}
