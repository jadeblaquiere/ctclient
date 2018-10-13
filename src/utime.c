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

#ifndef _BSD_SOURCE
#define _BSD_SOURCE  1
#define _REVERT_BSD_SOURCE
#endif

#ifndef _SVID_SOURCE
#define _SVID_SOURCE  1
#define _REVERT_SVID_SOURCE
#endif

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE   1
#define _REVERT_XOPEN_SOURCE    1
#endif

#include <time.h>

#ifdef _REVERT_XOPEN_SOURCE
#undef _REVERT_XOPEN_SOURCE
#undef _XOPEN_SOURCE
#endif

#ifdef _REVERT_SVID_SOURCE
#undef _REVERT_SVID_SOURCE
#undef _SVID_SOURCE
#endif

#ifdef _REVERT_BSD_SOURCE
#undef _REVERT_BSD_SOURCE
#undef _BSD_SOURCE
#endif

#ifndef __USE_ISOC99
#define __USE_ISOC99    1
#include <stdio.h>
#undef __USE_ISOC99
#else
#include <stdio.h>
#endif

#include <assert.h>
#include <ciphrtxt/utime.h>
#include <inttypes.h>
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

    tt = timegm(tm);
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

utime_t utime_from_timespec(struct timespec *ts) {
    return utime_from_time_t(ts->tv_sec) + ((ts->tv_nsec)/1000);
}

void timespec_from_utime(struct timespec *ts, utime_t utm) {
    ts->tv_sec = time_t_from_utime(utm);
    ts->tv_nsec = (utm % (1000000)) * 1000;
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
