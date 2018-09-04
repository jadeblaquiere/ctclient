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

// #cgo LDFLAGS: -lciphrtxt -lfspke -lecc -lgmp
// #include <ciphrtxt/utime.h>
// #include <stdlib.h>
//
import "C"

import (
	//"fmt"
	"time"
)

func DurationToUTime(d time.Duration) (u C.utime_t) {
	return C.utime_t(d / 1000)
}

func UTimeToDuration(u C.utime_t) (d time.Duration) {
	return time.Duration(int64(u * 1000))
}

func TimeToUTime(t time.Time) (u C.utime_t) {
	var usec int64
	var sec int64

	sec = t.Unix()
	usec = int64(t.Nanosecond() / 1000)
	u = C.utime_t(usec + (sec * 1000000))

	return u
}

func UTimeToTime(u C.utime_t) (t time.Time) {
	var nsec int64
	var sec int64

	sec = int64(u) / 1000000
	nsec = (int64(u) % 1000000) * 1000
	t = time.Unix(sec, nsec)

	return t
}
