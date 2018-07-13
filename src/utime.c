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

#define _XOPEN_SOURCE
#include <time.h>

#include <assert.h>
#include <ciphrtxt/utime.h>
#include <inttypes.h>
#define __USE_ISOC99
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

utime_t getutime(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((1000000) * ((int64_t)tv.tv_sec)) + ((int64_t)tv.tv_usec);
}

utime_t utime_from_timeval(struct timeval *tv) {
    return ((1000000) * ((int64_t)tv->tv_sec)) + ((int64_t)tv->tv_usec);
}

void timeval_from_utime(struct timeval *tv, utime_t utm) {
    tv->tv_usec = (uint32_t)(utm % (1000000));
    tv->tv_sec = (uint32_t)(utm / (1000000));
    return;
}

// NOTE: struct tm precision is only to seconds... microseconds == 0
utime_t utime_from_tm(struct tm *tm) {
    time_t tt;

    tt = mktime(tm);
    assert(tt != -1);
    return (1000000) * ((int64_t)tt);
}

void tm_from_utime(struct tm *tm, utime_t utm) {
    time_t tt;

    tt = (time_t)(utm / (1000000));
    gmtime_r(&tt, tm);
    return;
}

utime_t utime_from_time_t(time_t tt) {
    return (1000000) * ((utime_t)tt);
}

time_t time_t_from_utime(utime_t utm) {
    return (time_t)(utm / (1000000));
}

size_t utime_strftime(char *s, size_t max, char *format, utime_t utm) {
    char *fmt;
    char *qtag;
    struct tm tm;
    size_t sz;
    size_t rsz;

    tm_from_utime(&tm, utm);
    
    fmt = (char *)malloc(strlen(format)+1);
    strcpy(fmt, format);

    qtag = strstr(fmt, "%Q");
    if (qtag == NULL) return strftime(s, max, format, &tm);
    
    *qtag = 0;
    sz = strftime(s, max, fmt, &tm);
    *qtag = '%';
    rsz = max - sz;
    sz += snprintf(s + sz, rsz, "%06d", (int)(utm % (1000000)));
    rsz = max - sz;
    if (strlen(qtag) > 2) {
        sz += strftime(s + sz, rsz, qtag + 2, &tm);
    }
    return sz;
}
