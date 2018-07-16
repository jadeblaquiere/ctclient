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

#ifndef _CIPHRTXT_UTIME_H_INCLUDED_
#define _CIPHRTXT_UTIME_H_INCLUDED_

#include <time.h>
#include <inttypes.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Handling and conversions for time in microseconds */ 

typedef int64_t utime_t;

// get current time in microseconds (UTC)
utime_t getutime(void);

// convert time
utime_t utime_from_timeval(struct timeval *tv);
void timeval_from_utime(struct timeval *tv, utime_t utm);

utime_t utime_from_tm(struct tm *tm);
void tm_from_utime(struct tm *tm, utime_t utm);

utime_t utime_from_time_t(time_t tmt);
time_t time_t_from_utime(utime_t utm);

// formatted i/o for utime

// works just like strftime but adds %Q tag for 6 digit milliseconds
size_t utime_strftime(char *s, size_t max, char *format, utime_t utm);

// handy constants for larger time units

#define UTIME_SECONDS   (1000000U)
#define UTIME_MINUTES   (60 * UTIME_SECONDS)
#define UTIME_HOURS     (60 * UTIME_MINUTES)
#define UTIME_DAYS      (24 * UTIME_HOURS)
#define UTIME_WEEKS     (7 * UTIME_MINUTES)

#ifdef __cplusplus
}
#endif

#endif // _CIPHRTXT_UTIME_H_INCLUDED_
