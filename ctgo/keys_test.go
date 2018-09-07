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

func TestExportSecretKey(t *testing.T) {
	sK := NewSecretKey(0, 0, 0, 0, 0)

	nvbt := sK.NotValidBefore()
	fmt.Println("Key as of ", nvbt.String())

	sKder, err := sK.Export(nvbt)
	if err != nil {
		fmt.Println("Error exporting SecretKey")
		t.FailNow()
	}
	fmt.Println("SecretKey = ", hex.EncodeToString(sKder))

	oneday, _ := time.ParseDuration("24h")
	nvbt = nvbt.Add(oneday)
	fmt.Println("Key as of ", nvbt.String())

	sKder, err = sK.Export(nvbt)
	if err != nil {
		fmt.Println("Error exporting SecretKey")
		t.FailNow()
	}
	fmt.Println("SecretKey = ", hex.EncodeToString(sKder))
}

func TestExportImportSecretKey(t *testing.T) {
	sK := NewSecretKey(0, 0, 0, 0, 0)

	nvbt := sK.NotValidBefore()
	fmt.Println("Key as of ", nvbt.String())

	sKder, err := sK.Export(nvbt)
	if err != nil {
		fmt.Println("Error exporting SecretKey")
		t.FailNow()
	}
	fmt.Println("SecretKey = ", hex.EncodeToString(sKder))

	sK2 := ImportSecretKey(sKder)
	if sK2 == nil {
		fmt.Println("Error importing SecretKey")
		t.FailNow()
	}

	sK2der, err := sK2.Export(nvbt)
	if err != nil {
		fmt.Println("Error exporting SecretKey")
		t.FailNow()
	}
	if bytes.Compare(sKder, sK2der) != 0 {
		fmt.Println("TestExportImportSecretKey: Export/Import/Export != Export")
		t.FailNow()
	}
}

func TestExportSecretKeyDelegate(t *testing.T) {
	sK := NewSecretKey(0, 0, 0, 0, 0)

	nvbt := sK.NotValidBefore()

	oneday, _ := time.ParseDuration("24h")
	nvbt = nvbt.Add(oneday)
	nvat := nvbt.Add(oneday)
	fmt.Println("Key valid between ", nvbt.String(), " and ", nvat.String())

	sKder, err := sK.ExportDelegate(nvbt, nvat)
	if err != nil {
		fmt.Println("Error exporting SecretKey")
		t.FailNow()
	}
	fmt.Println("SecretKey = ", hex.EncodeToString(sKder))
	fmt.Println("Key generated between ", nvbt.String(), " and ", nvat.String())
	sK2 := ImportSecretKey(sKder)
	fmt.Println("Key valid between ", sK2.NotValidBefore(), " and ", sK2.NotValidAfter())
}

func TestExportImportPublicKey(t *testing.T) {
	sK := NewSecretKey(0, 0, 0, 0, 0)
	pK := sK.PublicKey()

	pKder, err := pK.Export()
	if err != nil {
		fmt.Println("Error exporting PublicKey")
		t.FailNow()
	}
	fmt.Println("PublicKey = ", hex.EncodeToString(pKder))

	pK2 := ImportPublicKey(pKder)

	pK2der, err := pK2.Export()
	if err != nil {
		fmt.Println("Error exporting PublicKey")
		t.FailNow()
	}
	if bytes.Compare(pKder, pK2der) != 0 {
		fmt.Println("TestExportImportPublicKey: Export/Import/Export != Export")
		t.FailNow()
	}
}
