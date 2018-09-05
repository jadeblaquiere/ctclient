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
	"testing"
	"time"
)

func TestEncryptDecryptMessage(t *testing.T) {
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

	ctext := ctmsg.Ciphertext()
	if ctext == nil {
		fmt.Println("Ctext output is nil!")
		t.FailNow()
	}
	fmt.Println("encrypted (", len(ctext), " bytes) = ", hex.EncodeToString(ctext))

	ctmsgcp := DecryptMessage(sKA, ctext)
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
