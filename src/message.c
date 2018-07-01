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

#include <ciphrtxt/keys.h>
#include <ciphrtxt/message.h>
#include <fspke.h>
#include <inttypes.h>
#include <libtasn1.h>
#include <limits.h>
#include <pbc.h>
#include <portable_endian.h>
#include <sodium.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

// if somebody fed us a weak point, will fail to generate a valid ECDH key
#define _CT_MSG_MAX_KEY_ATTEMPTS    (10U)

static char *_ct_msg_magic = "\x09\x33\x17";
static size_t _ct_msg_magic_sz = _CT_MAGIC_BYTES;

static unsigned char *_ct_msg_version = (unsigned char *)"\x00\x01\x00\x00\x00";
static size_t _ct_msg_version_sz = _CT_VERSION_BYTES;

static char *_ct_msg_default_mime = "text/plain";

// default message time-to-live - 1 week
#define _CT_DEFAULT_MSG_TTL (7*24*60*60*(1000000ULL))

// minimum message time-to-live - 1 minute
#define _CT_MINIMUM_MSG_TTL (60*1000000)
// minimum message time-to-live - 2x default (2 weeks)
#define _CT_MAXIMUM_MSG_TTL (2*_CT_DEFAULT_MSG_TTL)

static unsigned char *_ctMessage_compose_preamble(ctMessage msg, size_t *psz) {
    uint32_t fsksz;
    unsigned char *preamble;
    size_t preamblesz;
    
    preamblesz = sizeof(msg->fsksz) + ((size_t)msg->fsksz) + sizeof(msg->nonce);
    preamble = (unsigned char *)malloc(preamblesz);
    fsksz = htole32(msg->fsksz);
    memcpy(preamble, &(fsksz), sizeof(fsksz));
    memcpy(preamble + sizeof(msg->fsksz), msg->fsk, msg->fsksz);
    memcpy(preamble + sizeof(msg->fsksz) + msg->fsksz, msg->nonce, sizeof(msg->nonce));
    *psz = preamblesz;
    return preamble;
}

static unsigned char *_ctMessage_compose_auth_data(ctMessage msg, size_t *asz) {
    ctMessageHeader hdr;
    unsigned char *preamble, *adata;
    size_t preamblesz, adatasz;
    
    preamble = _ctMessage_compose_preamble(msg, &preamblesz);
    
    memcpy(hdr, msg->hdr, sizeof(hdr));
    hdr->msgtime_usec = htole64(hdr->msgtime_usec);
    hdr->expire_usec = htole64(hdr->expire_usec);
    hdr->payload_blocks = htole64(hdr->payload_blocks);

    adatasz = _CT_AUTH_HDR_SZ + preamblesz;
    adata = (unsigned char *)malloc(adatasz);
    memcpy(adata, hdr, _CT_AUTH_HDR_SZ);
    memcpy(adata + _CT_AUTH_HDR_SZ, preamble, preamblesz);
    memset(preamble, 0, preamblesz);
    free(preamble);
    *asz = adatasz;
    return adata;
}

int ctMessage_init_Enc(ctMessage msg, ctPublicKey toK, ctSecretKey fromK, 
  int64_t timestamp, int64_t ttl, char *mime, unsigned char *plaintext,
  size_t p_sz) {
    element_t       random_e;
    _ed25519pk      ephem_ecdh;
    int             status;
    size_t          preamblesz;
    size_t          payloadsz;
    size_t          ptextsz;
    unsigned char   padsz;
    
    /////////////////////////////////// input checks

    // bounds checking time-to-live
    if (ttl != 0) {
        if ((ttl < _CT_MINIMUM_MSG_TTL) || (ttl > _CT_MAXIMUM_MSG_TTL)) {
            return -1;
        }
    }

    if ((timestamp > 0 ) && (timestamp < toK->t0)) {
        return -1;
    }

    if (mime != NULL) {
        if(strlen(mime) >= _CT_MAX_MIME_LEN) {
            return -1;
        }
    }

    // fail to accept weak points
    if ((!crypto_core_ed25519_is_valid_point(toK->addr_pub)) || 
        (!crypto_core_ed25519_is_valid_point(toK->enc_pub)) ||
        (!crypto_core_ed25519_is_valid_point(toK->sign_pub))) {
        return -1;
    }

    /////////////////////////////////// compose top of header

    memcpy(msg->hdr->magic, _ct_msg_magic, _ct_msg_magic_sz);
    memcpy(msg->hdr->version, _ct_msg_version, _ct_msg_version_sz);

    if (timestamp > 0) {
        msg->hdr->msgtime_usec = timestamp;
    } else {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        msg->hdr->msgtime_usec = (1000000 * ((int64_t)tv.tv_sec)) + ((int64_t)tv.tv_usec);
    }

    if (ttl > 0) {
        msg->hdr->expire_usec = msg->hdr->msgtime_usec + ttl;
    } else {
        msg->hdr->expire_usec = msg->hdr->msgtime_usec + _CT_DEFAULT_MSG_TTL;
    }

    // choose a random secret key for addressing
    do {
        randombytes_buf(msg->secrets->addr_sec, sizeof(msg->secrets->addr_sec));
    } while (crypto_scalarmult_ed25519_base(msg->hdr->I_point, msg->secrets->addr_sec) != 0);

    status = crypto_scalarmult_ed25519(msg->hdr->J_point, msg->secrets->addr_sec, toK->addr_pub);
    // if addr_pub is a valid point and addr_sec != 0 then there should be no failure case
    assert(status == 0);

    // choose a random (ephemeral) secret key for message
    do {
        randombytes_buf(msg->secrets->ephem_sec, sizeof(msg->secrets->ephem_sec));
    } while (crypto_scalarmult_ed25519_base(msg->hdr->ECDHE_point, msg->secrets->ephem_sec) != 0);

    status = crypto_scalarmult_ed25519(ephem_ecdh, msg->secrets->ephem_sec, toK->enc_pub);
    // if enc_pub is a valid point and ephem_sec != 0 then there should be no failure case
    assert(status == 0);

    /////////////////////////////////// inner header

    if (fromK != NULL) {
        memcpy(msg->secrets->sig_sec, fromK->sign_sec, sizeof(msg->secrets->sig_sec));
        status = crypto_scalarmult_ed25519_base(msg->inner->SIG_point, msg->secrets->sig_sec);
        // bad input - zero sig key?
        if (status == 0) goto error_cleanup1;
    } else {
        do {
            randombytes_buf(msg->secrets->sig_sec, sizeof(msg->secrets->sig_sec));
        } while (crypto_scalarmult_ed25519_base(msg->inner->SIG_point, msg->secrets->sig_sec) != 0);
    }
    
    msg->inner->msglen = (int64_t)p_sz;
    {
        char *mime_s;
        if (mime != NULL) {
            mime_s = mime;
        } else {
            mime_s = _ct_msg_default_mime;
        }
        
        msg->inner->mimelen = strlen(mime_s);
        memcpy(msg->inner->mime, mime_s, msg->inner->mimelen);
    }
    msg->innersz = sizeof(msg->inner->SIG_point) + sizeof(msg->inner->msglen) +
        sizeof(msg->inner->mimelen) + ((size_t)msg->inner->mimelen);

    /////////////////////////////////// payload authenticated data
    
    // select a random E(Fp2) element for CHK forward-secure key exchange
    CHKPKE_init_random_element(random_e, toK->chk_pub);
    {
        unsigned char *fs_bytes;
        unsigned char *buffer;
        size_t fssz, bsz;

        // compose ECDH key with CHK key to generate a shared key for symmetric encryption
        fs_bytes = CHKPKE_element_to_bytes(random_e, &fssz);
        bsz = sizeof(ephem_ecdh) + (fssz * sizeof(char));
        buffer = (unsigned char *)malloc(bsz);
        memcpy(buffer, ephem_ecdh, sizeof(ephem_ecdh));
        memcpy(buffer + sizeof(ephem_ecdh), fs_bytes, fssz);
        
        // hash composite key
        crypto_generichash(msg->secrets->sym_key, sizeof(msg->secrets->sym_key), buffer, bsz, NULL, 0);
        memset(buffer, 0, bsz);
        free(buffer);
        memset(ephem_ecdh, 0, sizeof(ephem_ecdh));
    }

    // Encrypt forward-secure key for recipient
    {
        size_t fsksz_s;
        int64_t interval;
        interval = _ctPublicKey_interval_for_time(toK, msg->hdr->msgtime_usec);
        msg->fsk = CHKPKE_Enc_DER(toK->chk_pub, random_e, interval, &fsksz_s);
        if (msg->fsk == NULL) goto error_cleanup2;
        assert(fsksz_s > 0);
        assert(fsksz_s < UINT_MAX);
        msg->fsksz = (uint32_t)fsksz_s;
    }

    // message nonce
    randombytes_buf(msg->nonce, sizeof(msg->nonce));
    
    // calculate payload length () 
    // preamble is unencrypted, authenticated payload
    preamblesz = sizeof(msg->fsksz) + ((size_t)msg->fsksz) + sizeof(msg->nonce);
    // encrypted payload includes inner header and message plaintext
    ptextsz = msg->innersz + ((size_t)msg->inner->msglen);
    // total payload is preable + encrypted payload + authentication tag
    payloadsz = preamblesz + ptextsz + ((size_t)crypto_aead_xchacha20poly1305_ietf_ABYTES);
    
    // calculate pad size
    {
        size_t padsize_s;
        padsize_s = (_CT_BLKSZ - (payloadsz % _CT_BLKSZ)) % _CT_BLKSZ;
        padsz = (unsigned char)padsize_s;
    }
    
    msg->hdr->payload_blocks = ((payloadsz + padsz) / _CT_BLKSZ);
    assert((msg->hdr->payload_blocks * _CT_BLKSZ) == (payloadsz + padsz));
    ptextsz += padsz;

    // symmetric encryption
    {
        ctMessageInnerHeader inner;
        unsigned char *ptext;
        unsigned char *adata;
        unsigned char *pad;
        unsigned long long clen;
        size_t adatasz;
        int i;
        crypto_generichash_state state;

        memcpy(inner, msg->inner, msg->innersz);

        inner->msglen = htole64(msg->inner->msglen);
        inner->mimelen = htole32(msg->inner->mimelen);

        // append inner header and message plaintext
        ptext = (unsigned char *)malloc(ptextsz);
        assert(ptext != NULL);
        memcpy(ptext, (void *)msg->inner, msg->innersz);
        memcpy(ptext + msg->innersz, plaintext, ((size_t)msg->inner->msglen));
        pad = ptext + msg->innersz + ((size_t)msg->inner->msglen);
        for (i = 0; i < padsz; i++) {
            pad[i] = padsz;
        }

        adata = _ctMessage_compose_auth_data(msg, &adatasz);
        
        msg->ctextsz = ptextsz + crypto_aead_xchacha20poly1305_ietf_ABYTES;
        msg->ctext = (unsigned char *)malloc(msg->ctextsz);
        
        status = crypto_aead_xchacha20poly1305_ietf_encrypt(msg->ctext, &clen, 
            ptext, (unsigned long long)(ptextsz),
            adata, (unsigned long long)adatasz, NULL, msg->nonce, msg->secrets->sym_key);
        msg->ctextsz = (size_t)clen;
        memset(ptext, 0, ptextsz);
        free(ptext);
        memset((void *)inner, 0, msg->innersz);
        if (status != 0)
        {
            memset(adata, 0, adatasz);
            free(adata);
            goto error_cleanup2;
        }

        crypto_generichash_init(&state, NULL, 0, sizeof(msg->hdr->payload_hash));
        crypto_generichash_update(&state, adata+_CT_AUTH_HDR_SZ, adatasz - _CT_AUTH_HDR_SZ);
        crypto_generichash_update(&state, msg->ctext, msg->ctextsz);
        crypto_generichash_final(&state, msg->hdr->payload_hash, sizeof(msg->hdr->payload_hash));
        
        memset(adata, 0, adatasz);
        free(adata);
    }

    return 0;
    
error_cleanup2:
    CHKPKE_element_clear(random_e);
error_cleanup1:
    memset(msg->secrets, 0, sizeof(*msg->secrets));
    //memset(ephem_ecdh, 0, sizeof(ephem_ecdh));
    //memset(msg, 0, sizeof(msg));
    return -1;
}
