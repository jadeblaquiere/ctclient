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
	"github.com/jadeblaquiere/ecclib/ecgo"
	"testing"
	"time"
	"unsafe"
)

func TestExportImportNAKSecretKey(t *testing.T) {

	nvbt := time.Now()
	oneday, _ := time.ParseDuration("24h")
	nvat := nvbt.Add(oneday)

	sN := NewNAKSecretKey(nvbt, nvat)

	sNder, err := sN.Export()
	if err != nil {
		fmt.Println("Error exporting NAKSecretKey")
		t.FailNow()
	}
	fmt.Println("NAKSecretKey = ", hex.EncodeToString(sNder))

	sN2 := ImportNAKSecretKey(sNder)
	if sN2 == nil {
		fmt.Println("Error importing NAKSecretKey")
		t.FailNow()
	}

	sN2der, err := sN2.Export()
	if err != nil {
		fmt.Println("Error exporting NAKSecretKey")
		t.FailNow()
	}
	if bytes.Compare(sNder, sN2der) != 0 {
		fmt.Println("TestExportImportNAKSecretKey: Export/Import/Export != Export")
		t.FailNow()
	}
}

func TestExportImportNAKPublicKey(t *testing.T) {

	nvbt := time.Now()
	oneday, _ := time.ParseDuration("24h")
	nvat := nvbt.Add(oneday)

	sN := NewNAKSecretKey(nvbt, nvat)
	pN := sN.NAKPublicKey()

	pNder, err := pN.Export()
	if err != nil {
		fmt.Println("Error exporting NAKPublicKey")
		t.FailNow()
	}
	fmt.Println("NAKPublicKey = ", hex.EncodeToString(pNder))

	pN2 := ImportNAKPublicKey(pNder)
	if pN2 == nil {
		fmt.Println("Error importing NAKPublicKey")
		t.FailNow()
	}

	pN2der, err := pN2.Export()
	if err != nil {
		fmt.Println("Error exporting NAKPublicKey")
		t.FailNow()
	}
	if bytes.Compare(pNder, pN2der) != 0 {
		fmt.Println("TestExportImportNAKPublicKey: Export/Import/Export != Export")
		t.FailNow()
	}
}

func TestNAKSignVerify(t *testing.T) {

	nvbt := time.Now()
	oneday, _ := time.ParseDuration("24h")
	nvat := nvbt.Add(oneday)

	sN := NewNAKSecretKey(nvbt, nvat)
	pN := sN.NAKPublicKey()

	pNder, err := pN.Export()
	if err != nil {
		fmt.Println("Error exporting NAKPublicKey")
		t.FailNow()
	}
	fmt.Println("NAKPublicKey = ", hex.EncodeToString(pNder))

	sig := sN.ECDSASign(pNder)
	if sig == nil {
		fmt.Println("TestNAKSignVerify: signature is nil")
		t.FailNow()
	}
	fmt.Println("Signature = ", hex.EncodeToString(sig))

	if pN.ECDSAVerify(pNder, sig) != true {
		fmt.Println("TestNAKSignVerify: signature verfify false")
		t.FailNow()
	}
}

func TestNAKExportImportVerifySignedPublicKey(t *testing.T) {

	nvbt := time.Now()
	oneday, _ := time.ParseDuration("24h")
	nvat := nvbt.Add(oneday)

	sN := NewNAKSecretKey(nvbt, nvat)
	pN := sN.NAKPublicKey()

	spn := sN.NAKSignedPublicKey()
	if spn == nil {
		fmt.Println("TestNAKExportImportVerifySignedPublicKey: spn is nil")
		t.FailNow()
	}

	if ValidateNAKSignedPublicKey(spn) != true {
		fmt.Println("TestNAKExportImportVerifySignedPublicKey: spn validate failed")
		t.FailNow()
	}

	pN2 := ImportNAKSignedPublicKey(spn)
	if pN2 == nil {
		fmt.Println("TestNAKExportImportVerifySignedPublicKey: pN2 is nil")
		t.FailNow()
	}

	pNe, _ := pN.Export()
	pN2e, _ := pN.Export()
	if bytes.Compare(pNe, pN2e) != 0 {
		fmt.Println("TestNAKExportImportVerifySignedPublicKey: Import(Export(nak)) != nak")
		t.FailNow()
	}
}

func TestNAKAuthChallenge(t *testing.T) {
	var nakSKlist []*NAKSecretKey
	var nakPKlist []*NAKPublicKey
	var test_count int = 32

	cv := NAKCurve()
	cvG := ecgo.NewPointGenerator(cv)
	n := cv.GetAttr("n")
	sessionSK := ecgo.NewFieldElementURandom(n)
	sessionPK := ecgo.NewPointNeutral(cv)
	sessionPK.Mul(cvG, sessionSK.AsInt())
	sessionSecret := ecgo.NewPointURandom(cv)

	nvbt := time.Now()
	oneday, _ := time.ParseDuration("24h")
	nvat := nvbt.Add(oneday)

	nakSKlist = make([](*NAKSecretKey), test_count)
	nakPKlist = make([](*NAKPublicKey), test_count)

	for i := 0; i < test_count; i++ {
		nakSKlist[i] = NewNAKSecretKey(nvbt, nvat)
		nakPKlist[i] = nakSKlist[i].NAKPublicKey()
	}
	ch := NewNAKAuthChallenge(nakPKlist, sessionPK, nvat, sessionSecret)
	if ch == nil {
		fmt.Println("TestNAKAuthChallenge: NewNAKAuthChallenge() == nil")
		t.FailNow()
	}
	der, _ := ch.Export()
	if der == nil {
		fmt.Println("TestNAKAuthChallenge: Export() failed")
		t.FailNow()
	}
	ch2 := ImportNAKAuthChallenge(der)
	if ch2 == nil {
		fmt.Println("TestNAKAuthChallenge: Import() failed")
		t.FailNow()
	}
	der2, _ := ch2.Export()
	if der2 == nil {
		fmt.Println("TestNAKAuthChallenge: Export() failed")
		t.FailNow()
	}
	if bytes.Compare(der, der2) != 0 {
		fmt.Println("TestNAKAuthChallenge: Export(Import(Export())) != Export()")
		t.FailNow()
	}

	for i := 0; i < test_count; i++ {
		rs := NewNAKAuthResponse(ch, nakSKlist[i])
		if rs == nil {
			fmt.Println("TestNAKAuthChallenge: Response(good sN) == nil!")
			t.FailNow()
		}
		randSN := NewNAKSecretKey(nvbt, nvat)
		nrs := NewNAKAuthResponse(ch, randSN)
		if nrs != nil {
			fmt.Println("TestNAKAuthChallenge: Response(bad sN) != nil!")
			t.FailNow()
		}
		rsder, _ := rs.Export()
		if rsder == nil {
			fmt.Println("TestNAKAuthChallenge: Response DER export == nil!")
			t.FailNow()
		}
		rscp := ImportNAKAuthResponse(rsder)
		if rscp == nil {
			fmt.Println("TestNAKAuthChallenge: Response DER import failed!")
			t.FailNow()
		}
		if rscp.Validate(sessionSK, sessionSecret) != true {
			fmt.Println("TestNAKAuthChallenge: Response(good sN) failed Validate()")
			t.FailNow()
		}
	}
}

func TestLocalPointISEcclibPoint(t *testing.T) {
	cv := NAKCurve()
	cvG := ecgo.NewPointGenerator(cv)
	n := cv.GetAttr("n")
	sessionSK := ecgo.NewFieldElementURandom(n)
	sessionPK := ecgo.NewPointNeutral(cv)
	sessionPK.Mul(cvG, sessionSK.AsInt())
	localSessionPK := (*point)(unsafe.Pointer(sessionPK))
	lcv := localSessionPK.cv
	if cv != lcv {
		fmt.Println("TestNAKAuthChallenge: NewNAKAuthChallenge() == nil")
		t.FailNow()
	}
	if unsafe.Sizeof(localSessionPK) != unsafe.Sizeof(sessionPK) {
		fmt.Println("TestLocalPointISEcclibPoint: size mismatch!")
		t.FailNow()
	}
	lbytes := localSessionPK.bytesUncompressed()
	ebytes := sessionPK.BytesUncompressed()
	if bytes.Compare(lbytes, ebytes) != 0 {
		fmt.Println("TestLocalPointISEcclibPoint: coordinates mismatch!")
		t.FailNow()
	}
}
