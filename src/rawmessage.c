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

#include <assert.h>
#include <ciphrtxt/rawmessage.h>
#include <ciphrtxt/utime.h>
#include <errno.h>
#include <fcntl.h>
#include <libdill.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

ctMessageFile_ptr ctMessage_write_to_file(ctMessage_t msg, char *filename) {
    struct stat statbuf;
    // check if file already exists - cowardly refusing to overwrite
    if (stat(filename, &statbuf) == 0) { return NULL; }

    int fd = open(filename, O_RDWR | O_CREAT, 0600);
    if (fd < 0) { return NULL; }

    size_t ctsz;
    unsigned char *ct = ctMessage_ciphertext_ptr(msg, &ctsz);

    // wait for writable
    //int status = fdout(fd, -1);
    //while ((status == -1) && (errno == EBUSY)) {
    //    yield();
    //    status = fdout(fd, -1);
    //}
    //if (status != 0) { return NULL; }

    int status = write(fd, ct, ctsz);
    if (status < 0) { return NULL; }

    ctMessageFile_ptr mf = (ctMessageFile_ptr)malloc(sizeof(_ctMessageFile_t));
    assert(mf != NULL);
    memcpy(mf->hdr, msg->hdr, sizeof(_ctMessageHeader_t));
    mf->msz = ctsz;
    mf->filename = malloc((strlen(filename) + 1) * sizeof(char));
    strcpy(mf->filename, filename);
    mf->serverTime = getutime();
    close(fd);
    return mf;
}

ctMessageFile_ptr ctMessageFile_read_from_file(char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) { return NULL; }

    //get file info
    struct stat statbuf;
    if (fstat(fd, &statbuf) != 0) { return NULL; }

    ctMessageFile_ptr mf = (ctMessageFile_ptr)malloc(sizeof(_ctMessageFile_t));
    assert(mf != NULL);

    // wait for readable
    //int status = fdin(fd, -1);
    //while ((status == -1) && (errno == EBUSY)) {
    //    yield();
    //    status = fdin(fd, -1);
    //}
    //if (status != 0) { return NULL; }

    int status = read(fd, mf->hdr, sizeof(_ctMessageHeader_t));
    if (status < 0) { free(mf); return NULL; }

    mf->msz = (size_t)statbuf.st_size;
    mf->filename = malloc((strlen(filename) + 1) * sizeof(char));
    strcpy(mf->filename, filename);
    mf->serverTime = utime_from_time_t(statbuf.st_mtime);
    close(fd);
    return mf;
}

unsigned char *ctMessageFile_ciphertext(ctMessageFile_t mf, size_t *ctsz) {
    int fd = open(mf->filename, O_RDONLY);
    if (fd < 0) { return NULL; }

    unsigned char* ct = (unsigned char *)malloc(mf->msz * sizeof(char));
    assert(ct != NULL);

    // wait for readable
    //int status = fdin(fd, -1);
    //while (status == EBUSY) {
    //    yield();
    //    status = fdin(fd, -1);
    //}
    //if (status != 0) { return NULL; }

    int status = read(fd, ct, mf->msz);
    if (status < 0) { free(ct); return NULL; }

    close(fd);
    *ctsz = mf->msz;
    return ct;
}

//void ctMessageFile_clear(ctMessageFile *mf);
