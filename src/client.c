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
#include <ciphrtxt/client.h>
#include <errno.h>
#include <fcntl.h>
#include <libdill.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

static char *_api_v1_messages = "/api/v1/messages/";

int ctConnection_init(ctConnection_t conn, char *host, int port) {
    size_t hlen = strlen(host);
    conn->host = malloc((hlen + 1) * sizeof(char));
    assert(conn->host != NULL);
    strncpy(conn->host, host, hlen);
    conn->host[hlen] = 0;

    int status = ipaddr_remote(&(conn->addr), host, port, IPADDR_PREF_IPV4, -1);
    return status;
}

void ctConnection_clear(ctConnection_t conn) {
    free(conn->host);
    return;
}

#define _CCLIENT_CHUNKSZ	(4000)

typedef struct __chunkdata_t {
    unsigned char *chunk;
    struct __chunkdata_t *next;
    size_t chunksz;
} _chunkdata_t;

// like brecv, but tolerates short reads and returns length read
size_t _crecv(int sock, void *buf, size_t len, int64_t deadline) {
    size_t rd = 0;
    void *bptr = buf;
    while (rd < len) {
        int status = brecv(sock, bptr, 1, deadline);
        if ((status == -1) && (errno == EPIPE)) break;
        if (status != 0) {
            // leave errno set and return
            return -1;
        }
        rd += 1;
        bptr += 1;
    }
    //printf("crecv: read %zd bytes\n", rd);
    return rd;
}

void _chunk_free(_chunkdata_t *ch) {
    _chunkdata_t *nch = ch;
    while (nch != NULL) {
        _chunkdata_t *lch = nch;
        free(nch->chunk);
        nch = nch->next;
        free(lch);
    }
    return;
}

unsigned char *_chunk_recv(int sock, int64_t deadline, size_t *rsz) {
    size_t sz = 0;
    _chunkdata_t *ch = (_chunkdata_t *)malloc(sizeof(_chunkdata_t));
    assert(ch != NULL);
    ch->chunk = (unsigned char *)malloc(_CCLIENT_CHUNKSZ * sizeof(char));
    ch->next = NULL;
    _chunkdata_t *nch = ch;
    while (1) {
        int st = _crecv(sock, nch->chunk, _CCLIENT_CHUNKSZ, deadline);
        if ((st == -1) && (errno == EPIPE)) {
            nch->chunksz = 0;
            break;
        }
        if (st < 0) {
            _chunk_free(ch);
            return NULL;
        }
        nch->chunksz = st;
        sz += st;
        if (st < _CCLIENT_CHUNKSZ) break;

        nch->next = (_chunkdata_t *)malloc(sizeof(_chunkdata_t));
        assert(nch->next != NULL);
        nch->next->chunk = (unsigned char *)malloc(_CCLIENT_CHUNKSZ * sizeof(char));
        nch->next->next = NULL;
        nch = nch->next;
    }
    // only condition where sz == 0 is errno = EPIPE, which is correct
    *rsz = sz;
    if (sz == 0) return NULL;
    // +1 allows for NULL termination
    unsigned char *r = (unsigned char *)malloc((sz + 1) * sizeof(char));
    assert(r != NULL);
    unsigned char *rr = r;
    nch = ch;
    while (nch != NULL) {
        if (nch->chunksz > 0) {
            memcpy(rr, nch->chunk, nch->chunksz);
        }
        rr += nch->chunksz;
        nch = nch->next;
    }
    // ensure NULL termination
    *rr = 0;
    _chunk_free(ch);
    return r;
}

int _chunk_recv_write(int sock, int fd, int64_t deadline) {
    unsigned char chunk[_CCLIENT_CHUNKSZ];

    while (1) {
        int st = _crecv(sock, chunk, _CCLIENT_CHUNKSZ, deadline);
        if ((st == -1) && (errno == EPIPE)) {
            break;
        }
        if (st < 0) { return -1; }

        // wait for writable
        //int status = fdout(fd, -1);
        //while (status -1 && errno == EBUSY) {
        //    yield();
        //    status = fdout(fd, -1);
        //}
        //if (status != 0) { printf("2 %d\n", status); return NULL; }

        int wlen = write(fd, chunk, st);
        if (wlen != st) { return -1; }

        if (st < _CCLIENT_CHUNKSZ) break;
    }
    return 0;
}

typedef struct __header_list_t {
    char *name;
    char *value;
    struct __header_list_t *next;
} _header_list_t;

static void _header_list_free(_header_list_t *hlist) {
    while (hlist != NULL) {
        _header_list_t *nhl = hlist->next;
        free(hlist->name);
        free(hlist->value);
        free(hlist);
        hlist = nhl;
    }
    return;
}

static char* _header_list_lookup(_header_list_t *hlist, char *name) {
    while (hlist != NULL) {
        if (strcmp(hlist->name, name) == 0) {
            return hlist->value;
        }
        hlist = hlist->next;
    }
    return NULL;
}

static unsigned char *_rest_get_body(ctConnection_t conn, char *resource, int *status, _header_list_t **hlist, size_t *sz) {
    int sock = tcp_connect(&(conn->addr), -1);
    if (sock < 0) {errno = ECONNREFUSED; return NULL;}

    sock = tls_attach_client(sock, -1);
    if (sock < 0) {errno = EPROTO; return NULL;}

    sock = http_attach(sock);
    if (sock < 0) {errno = EPROTO; return NULL;}

    //printf("requesting resource %s\n", resource);

    int st = http_sendrequest(sock, "GET", resource, -1);
    if (st != 0) {errno = ENOENT; return NULL;}

    st = http_sendfield(sock, "Host", conn->host, -1);
    if (st != 0) {errno = ENOENT; return NULL;}

    st = http_sendfield(sock, "Connection", "close", -1);
    if (st != 0) {errno = ENOENT; return NULL;}

    st = http_done(sock, -1);
    if (st != 0) {errno = EPROTO; return NULL;}

    // start receive
    char reason[256];
    int hstatus = http_recvstatus(sock, reason, sizeof(reason), -1);
    if (hstatus < 0) {errno = ENODATA; return NULL;}

    // receive headers
    _header_list_t *hl = NULL;
    _header_list_t *nhl = NULL;
    while(1) {
        char name[256];
        char value[4096];
        st = http_recvfield(sock, name, sizeof(name), value, sizeof(value), -1);
        if (st == -1 && errno == EPIPE) break;
        if (st != 0) {errno = EPROTO; return NULL;}
        if (hlist != NULL) {
            if (hl == NULL) {
                hl = (_header_list_t *)malloc(sizeof(_header_list_t));
                nhl = hl;
            } else {
                nhl->next = (_header_list_t *)malloc(sizeof(_header_list_t));
                nhl = nhl->next;
            }
            size_t nlen = strlen(name);
            nhl->name = (char *)malloc((nlen + 1)*sizeof(char));
            memcpy(nhl->name, name, nlen);
            nhl->name[nlen] = 0;
            size_t vlen = strlen(value);
            nhl->value = (char *)malloc((vlen + 1)*sizeof(char));
            memcpy(nhl->value, value, vlen);
            nhl->value[vlen] = 0;
            nhl->next = NULL;
        }
    }

    // drop back to tls only and receive body
    sock = http_detach(sock, -1);
    if (sock < 0) {errno = EPROTO; goto cleanup1;}

    size_t bsz;
    unsigned char *body = _chunk_recv(sock, -1, &bsz);
    if (body == NULL) {errno = ENODATA; goto cleanup1;}

    // accept ECONNRESET as server will also be disconnecting
    sock = tls_detach(sock, -1);
    if (sock < 0) {
        if (errno != ECONNRESET) {errno = EPROTO; goto cleanup2;}
    } else {
      sock = tcp_close(sock, -1);
      if (sock < 0) {
          if (errno != ECONNRESET) {errno = EPROTO; goto cleanup2;}
      }
    }

    // response complete, write output
    *status = hstatus;
    *sz = bsz;
    if (hlist != NULL) *hlist = hl;
    return body;

cleanup2:
    free(body);
cleanup1:
    if (hl != NULL) _header_list_free(hl);
    return NULL;
}

static int _rest_get_body_to_file(ctConnection_t conn, char *resource, int *status, _header_list_t **hlist, char *filename) {
    struct stat statbuf;
    // check if file already exists - cowardly refusing to overwrite
    if (stat(filename, &statbuf) == 0) { return -1; }

    int fd = open(filename, O_RDWR | O_CREAT, 0600);
    if (fd < 0) { printf("1\n"); return -1; }

    // receive headers
    _header_list_t *hl = NULL;
    _header_list_t *nhl = NULL;

    int sock = tcp_connect(&(conn->addr), -1);
    if (sock < 0) {errno = ECONNREFUSED; goto cleanup1;}

    sock = tls_attach_client(sock, -1);
    if (sock < 0) {errno = EPROTO; goto cleanup1;}

    sock = http_attach(sock);
    if (sock < 0) {errno = EPROTO; goto cleanup1;}

    int st = http_sendrequest(sock, "GET", resource, -1);
    if (st != 0) {errno = ENOENT; goto cleanup1;}

    st = http_sendfield(sock, "Host", conn->host, -1);
    if (st != 0) {errno = ENOENT; goto cleanup1;}

    st = http_sendfield(sock, "Connection", "close", -1);
    if (st != 0) {errno = ENOENT; goto cleanup1;}

    st = http_done(sock, -1);
    if (st != 0) {errno = EPROTO; goto cleanup1;}

    // start receive
    char reason[256];
    int hstatus = http_recvstatus(sock, reason, sizeof(reason), -1);
    if (hstatus < 0) {errno = ENODATA; goto cleanup1;}

    while(1) {
        char name[256];
        char value[4096];
        st = http_recvfield(sock, name, sizeof(name), value, sizeof(value), -1);
        if (st == -1 && errno == EPIPE) break;
        if (st != 0) {errno = EPROTO; goto cleanup1;}
        if (hlist != NULL) {
            if (hl == NULL) {
                hl = (_header_list_t *)malloc(sizeof(_header_list_t));
                nhl = hl;
            } else {
                nhl->next = (_header_list_t *)malloc(sizeof(_header_list_t));
                nhl = nhl->next;
            }
            size_t nlen = strlen(name);
            nhl->name = (char *)malloc((nlen + 1)*sizeof(char));
            memcpy(nhl->name, name, nlen);
            nhl->name[nlen] = 0;
            size_t vlen = strlen(value);
            nhl->value = (char *)malloc((vlen + 1)*sizeof(char));
            memcpy(nhl->value, value, vlen);
            nhl->value[vlen] = 0;
            nhl->next = NULL;
        }
    }

    // drop back to tls only and receive body
    sock = http_detach(sock, -1);
    if (sock < 0) {errno = EPROTO; goto cleanup1;}

    st = _chunk_recv_write(sock, fd, -1);
    if (st != 0) {errno = ENODATA; goto cleanup1;}

    // accept ECONNRESET as server will also be disconnecting
    sock = tls_detach(sock, -1);
    if (sock < 0) {
        if (errno != ECONNRESET) {errno = EPROTO; goto cleanup1;}
    } else {
      sock = tcp_close(sock, -1);
      if (sock < 0) {
          if (errno != ECONNRESET) {errno = EPROTO; goto cleanup1;}
      }
    }

    // response complete, write output
    *status = hstatus;
    if (hlist != NULL) *hlist = hl;
    close(fd);
    return 0;

cleanup1:
    close(fd);
    unlink(filename);
    if (hl != NULL) _header_list_free(hl);
    return -1;
}

static int _rest_post_body(ctConnection_t conn, char *resource, int *status, _header_list_t **hlist, unsigned char *body, size_t bsz) {
    // receive headers
    _header_list_t *hl = NULL;
    _header_list_t *nhl = NULL;

    int sock = tcp_connect(&(conn->addr), -1);
    if (sock < 0) {errno = ECONNREFUSED; goto cleanup1;}

    sock = tls_attach_client(sock, -1);
    if (sock < 0) {errno = EPROTO; goto cleanup1;}

    sock = http_attach(sock);
    if (sock < 0) {errno = EPROTO; goto cleanup1;}

    int st = http_sendrequest(sock, "POST", resource, -1);
    if (st != 0) {errno = ENOENT; goto cleanup1;}

    st = http_sendfield(sock, "Host", conn->host, -1);
    if (st != 0) {errno = ENOENT; goto cleanup1;}

    char conlen[256];
    sprintf(conlen,"%zd", bsz);
    st = http_sendfield(sock, "Content-Length", conlen, -1);
    if (st != 0) {errno = ENOENT; goto cleanup1;}

    st = http_sendfield(sock, "Content-Type", "application/x-www-form-urlencoded", -1);
    if (st != 0) {errno = ENOENT; goto cleanup1;}

    st = http_sendfield(sock, "Expect", "100-continue", -1);
    if (st != 0) {errno = ENOENT; goto cleanup1;}

    //st = http_sendfield(sock, "Connection", "close", -1);
    //if (st != 0) {errno = ENOENT; goto cleanup1;}

    st = http_done(sock, -1);
    if (st != 0) {errno = EPROTO; goto cleanup1;}

    // look for continue
    char reason[256];
    int hstatus = http_recvstatus(sock, reason, sizeof(reason), -1);
    if (hstatus < 0) {errno = ENODATA; goto cleanup1;}

    if (hstatus != 100) {errno = EPROTO; goto cleanup1;}

    // drop back to tls only and send body
    sock = http_detach(sock, -1);
    if (sock < 0) {errno = EPROTO; goto cleanup1;}

    st = bsend(sock, body, bsz, -1);

    // back to http to get response
    sock = http_attach(sock);
    if (sock < 0) {errno = EPROTO; goto cleanup1;}

    // start receive
    hstatus = http_recvstatus(sock, reason, sizeof(reason), -1);
    if (hstatus < 0) {errno = ENODATA; goto cleanup1;}

    while(1) {
        char name[256];
        char value[4096];
        st = http_recvfield(sock, name, sizeof(name), value, sizeof(value), -1);
        if (st == -1 && errno == EPIPE) break;
        if (st != 0) {errno = EPROTO; goto cleanup1;}
        if (hlist != NULL) {
            if (hl == NULL) {
                hl = (_header_list_t *)malloc(sizeof(_header_list_t));
                nhl = hl;
            } else {
                nhl->next = (_header_list_t *)malloc(sizeof(_header_list_t));
                nhl = nhl->next;
            }
            size_t nlen = strlen(name);
            nhl->name = (char *)malloc((nlen + 1)*sizeof(char));
            memcpy(nhl->name, name, nlen);
            nhl->name[nlen] = 0;
            size_t vlen = strlen(value);
            nhl->value = (char *)malloc((vlen + 1)*sizeof(char));
            memcpy(nhl->value, value, vlen);
            nhl->value[vlen] = 0;
            nhl->next = NULL;
        }
    }

    // drop back to tls only and receive body
    sock = http_detach(sock, -1);
    if (sock < 0) {
        if (errno != ECONNRESET) {errno = EPROTO; goto cleanup1;}
    } else {
        // accept ECONNRESET as server will also be disconnecting
        sock = tls_detach(sock, -1);
        if (sock < 0) {
            if (errno != ECONNRESET) {errno = EPROTO; goto cleanup1;}
        } else {
            sock = tcp_close(sock, -1);
            if (sock < 0) {
                if (errno != ECONNRESET) {errno = EPROTO; goto cleanup1;}
            }
        }
    }

    // response complete, write output
    *status = hstatus;
    if (hlist != NULL) *hlist = hl;
    return 0;

cleanup1:
    if (hl != NULL) _header_list_free(hl);
    return -1;
}

typedef struct __str_list_t {
    char *str;
    size_t strsz;
    struct __str_list_t *next;
} _str_list_t;

static char *_parse_str(char *body, size_t *sz) {
    char *start = strstr(body, "\"");
    if (start == NULL) {
        return NULL;
    }
    start += 1;
    char *end = strstr(start, "\"");
    if (end == NULL) {
        return NULL;
    }
    size_t len = end - start;
    char *copy = (char *)malloc((len + 1) * sizeof(char));
    memcpy(copy, start, len);
    copy[len] = 0;
    *sz = len;
    return copy;
}

static _str_list_t *_parse_str_list(char *body, int *count) {
    int ct = 0;
    char *start = strstr(body, "[");
    if (start == NULL) {
        return NULL;
    }
    start += 1;
    char *end = strstr(start, "]");
    if (end == NULL) {
        return NULL;
    }
    end -= 1;
    char *cursor = start;
    _str_list_t *sl = NULL;
    _str_list_t *hd = NULL;
    while (cursor < end) {
        size_t ssz;
        char *sstr = _parse_str(cursor, &ssz);
        if (sstr == NULL) break;
        if (sl == NULL) {
            sl = (_str_list_t *)malloc(sizeof(_str_list_t));
            hd = sl;
        } else {
            hd->next = (_str_list_t *)malloc(sizeof(_str_list_t));
            hd = hd->next;
        }
        ct += 1;
        hd->str = sstr;
        hd->strsz = ssz;
        hd->next = NULL;
        cursor += ssz;
        if (cursor < end) {
            cursor = strstr(cursor, ",");
            if (cursor == NULL) break;
            cursor += 1;
        }
    }
    if (count != NULL) *count = ct;
    return sl;
}

static void _str_list_free(_str_list_t *sl) {
    while (sl != NULL) {
        _str_list_t *sn = sl->next;
        free(sl->str);
        free(sl);
        sl = sn;
    }
    return;
}

char **ctConnection_get_message_ids(ctConnection_t conn, int *count) {
    _header_list_t *hlist = NULL;
    size_t bsz;
    int status;
    char *body = (char *)_rest_get_body(conn, _api_v1_messages, &status, &hlist, &bsz);
    if (body == NULL) {
        //printf("error requesting /messages/\n");
        return NULL;
    }
    //printf("status = %d\n", status);
    assert(hlist != NULL);
    //_header_list_t *hl = hlist;
    //while (hl != NULL) {
    //    printf("HDR(%s) = %s\n", hl->name, hl->value);
    //    hl = hl->next;
    //}
    //printf("BODY = \"%s\"\n", body);
    int msgct = 0;
    _str_list_t *msgids = _parse_str_list(body, &msgct);
    if (msgct == 0) {
        *count = 0;
        return NULL;
    }
    //printf("Found %d messages:\n", msgct);
    char **plist = (char **)malloc(msgct * sizeof(void *));
    _str_list_t *m = msgids;
    int i = 0;
    while (m != NULL) {
        _str_list_t *mn = m->next;
        //printf("%s\n", m->str);
        plist[i] = m->str;
        free(m);
        m = mn;
        i += 1;
    }
    _header_list_free(hlist);
    free(body);
    *count = msgct;
    return plist;
}


ctMessageFile_ptr ctConnection_get_message(ctConnection_t conn, char *msgid, char *filename) {
    _header_list_t *hlist = NULL;
    int status;
    size_t reslen = strlen(_api_v1_messages) + strlen(msgid) + 1;
    char *resource = (char *)malloc(reslen * sizeof(char));
    assert(resource != NULL);
    strcpy(resource, _api_v1_messages);
    strcat(resource, msgid);
    int st = _rest_get_body_to_file(conn, resource, &status, &hlist, filename);
    if (st != 0) {
        //printf("error requesting /messages/\n");
        return NULL;
    }

    return ctMessageFile_read_from_file(filename);
}

unsigned char *ctConnection_get_messagectxt(ctConnection_t conn, char *msgid, size_t *ctsz) {
    _header_list_t *hlist = NULL;
    int status;
    size_t reslen = strlen(_api_v1_messages) + strlen(msgid) + 1;
    char *resource = (char *)malloc(reslen * sizeof(char));
    assert(resource != NULL);
    strcpy(resource, _api_v1_messages);
    strcat(resource, msgid);
    size_t bsz;
    unsigned char *body = _rest_get_body(conn, resource, &status, &hlist, &bsz);
    if (body == NULL) {
        //printf("error requesting /messages/\n");
        return NULL;
    }

    *ctsz = bsz;
    return body;
}

int ctConnection_post_message(ctConnection_t conn, ctMessage_t m) {
    size_t bsz;
    unsigned char *body = ctMessage_ciphertext_ptr(m, &bsz);

    return ctConnection_post_messagectxt(conn, body, bsz);
}

int ctConnection_post_messagefile(ctConnection_t conn, ctMessageFile_t mf) {
    size_t bsz;
    unsigned char *body = ctMessageFile_ciphertext(mf, &bsz);

    int st = ctConnection_post_messagectxt(conn, body, bsz);

    //_header_list_free(hlist);
    free(body);

    return st;
}

int ctConnection_post_messagectxt(ctConnection_t conn, unsigned char *ctext, size_t ctsz) {

    int hstatus;
    //_header_list_t *hlist;
    //int st = _rest_post_body(conn, _api_v1_messages, &hstatus, &hlist, body, bsz);
    int st = _rest_post_body(conn, _api_v1_messages, &hstatus, NULL, ctext, ctsz);

    //_header_list_free(hlist);
    if ((st != 0) || (hstatus != 200)) {
        return -1;
    }
    return 0;
}

//int ctConnection_post_messagefile(ctConnection_t conn, ctMessageFile_t mf);
