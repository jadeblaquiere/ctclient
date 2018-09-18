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
#include <ciphrtxt/keys.h>
#include <ciphrtxt/message.h>
#include <ciphrtxt/postage.h>
#include <ciphrtxt/utime.h>
#include <fspke.h>
#include <inttypes.h>
#include <libtasn1.h>
#include <limits.h>
#include <pbc.h>
#include <portable_endian.h>
#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

// if somebody fed us a weak point, will fail to generate a valid ECDH key
#define _CT_MSG_MAX_KEY_ATTEMPTS    (10U)

static char *_ct_msg_magic = "\x09\x33\x17";
static size_t _ct_msg_magic_sz = _CT_MAGIC_BYTES;

// little endian representation of 0x0001 0000 00 (for 1.0.0)
static unsigned char *_ct_msg_version = (unsigned char *)"\x00\x00\x00\x01\x00";
static size_t _ct_msg_version_sz = _CT_VERSION_BYTES;

static char *_ct_msg_default_mime = "text/plain";

// default message time-to-live - 1 week
#define _CT_DEFAULT_MSG_TTL (7*24*60*60*(1000000ULL))

// minimum message time-to-live - 1 minute
#define _CT_MINIMUM_MSG_TTL (60*1000000)
// minimum message time-to-live - 2x default (2 weeks)
#define _CT_MAXIMUM_MSG_TTL (2*_CT_DEFAULT_MSG_TTL)

static unsigned char *_ctMessage_compose_preamble(ctMessage_t msg, size_t *psz) {
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

static unsigned char *_ctMessage_compose_auth_data(ctMessage_t msg, size_t *asz) {
    ctMessageHeader_t hdr;
    unsigned char *preamble, *adata;
    size_t preamblesz, adatasz;
    
    preamble = _ctMessage_compose_preamble(msg, &preamblesz);
    
    memcpy(hdr, msg->hdr, _CT_AUTH_HDR_SZ);
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

unsigned char *ctMessage_init_Enc(ctMessage_t msg, ctPublicKey_t toK, ctSecretKey_t fromK, 
  utime_t timestamp, utime_t ttl, char *mime, unsigned char *plaintext,
  size_t p_sz, ctPostageRate_t rate, size_t *sz) {
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
            //printf("TTL bounds check failed\n");
            return NULL;
        }
    }

    if ((timestamp > 0 ) && (timestamp < toK->t0)) {
        //printf("timestamp bounds check failed\n");
        return NULL;
    }

    if (mime != NULL) {
        if(strlen(mime) >= _CT_MAX_MIME_LEN) {
            //printf("mime_len bounds check failed\n");
            return NULL;
        }
    }

    // fail to accept weak points
    if ((crypto_core_ed25519_is_valid_point(toK->addr_pub) == 0) || 
        (crypto_core_ed25519_is_valid_point(toK->enc_pub) == 0) ||
        (crypto_core_ed25519_is_valid_point(toK->sign_pub) == 0)) {
        //printf("weak point check failed\n");
        return NULL;
    }

    /////////////////////////////////// compose top of header

    memcpy(msg->hdr->magic, _ct_msg_magic, _ct_msg_magic_sz);
    memcpy(msg->hdr->version, _ct_msg_version, _ct_msg_version_sz);

    if (timestamp > 0) {
        msg->hdr->msgtime_usec = timestamp;
    } else {
        msg->hdr->msgtime_usec = getutime();
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
        if (status != 0) goto error_cleanup1;
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
        msg->inner->mime[msg->inner->mimelen] = 0;
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
        memset(fs_bytes, 0, fssz);
        free(fs_bytes);

        // hash composite key
        crypto_generichash(msg->secrets->sym_key, sizeof(msg->secrets->sym_key), buffer, bsz, NULL, 0);
        memset(buffer, 0, bsz);
        free(buffer);
        memset(ephem_ecdh, 0, sizeof(ephem_ecdh));
    }

    /////////////////////////////////// generate sym. encryption nonce, keys

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
    // total payload is preable + encrypted payload + authentication tag + pad
    // (pad size added below)
    payloadsz = preamblesz + ptextsz + ((size_t)crypto_aead_xchacha20poly1305_ietf_ABYTES);

    // calculate pad size
    {
        size_t padsize_s;
        padsize_s = (_CT_BLKSZ - (payloadsz % _CT_BLKSZ)) % _CT_BLKSZ;
        padsz = (unsigned char)padsize_s;
    }
    payloadsz += padsz;

    msg->hdr->payload_blocks = (payloadsz / _CT_BLKSZ);
    assert((msg->hdr->payload_blocks * _CT_BLKSZ) == (payloadsz));
    ptextsz += padsz;

    /////////////////////////////////// encrypt

    // symmetric encryption
    {
        ctMessageInnerHeader_t inner;
        unsigned char *ptext;
        unsigned char *adata;
        unsigned char *pad;
        unsigned long long clen;
        size_t adatasz;
        size_t ciphersz;
        int i;

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
        msg->ptext = ptext;
        msg->ptextsz = ptextsz;

        adata = _ctMessage_compose_auth_data(msg, &adatasz);
        ciphersz = ptextsz + crypto_aead_xchacha20poly1305_ietf_ABYTES;

        msg->ctextsz = _CT_BLKSZ + preamblesz + ciphersz ;
        msg->ctext = (unsigned char *)malloc(msg->ctextsz);

        status = crypto_aead_xchacha20poly1305_ietf_encrypt(msg->ctext + _CT_BLKSZ + preamblesz, &clen, 
            ptext, (unsigned long long)(ptextsz),
            adata, (unsigned long long)adatasz, NULL, msg->nonce, msg->secrets->sym_key);
        assert(clen == (ciphersz));
        //msg->ctextsz = (size_t)clen;

        // Copy preamble into encoded ciphertext message
        memcpy(msg->ctext + _CT_BLKSZ, adata + _CT_AUTH_HDR_SZ, preamblesz);

        // Clear and free temporary data
        memset((void *)inner, 0, msg->innersz);
        memset(adata, 0, adatasz);
        free(adata);
        if (status != 0)
        {
            goto error_cleanup2;
        }

        // Calculate hash of payload (authenticated preamble + ciphertext)
        crypto_generichash(msg->hdr->payload_hash, sizeof(msg->hdr->payload_hash), msg->ctext + _CT_BLKSZ, preamblesz + clen, NULL, 0);
    }

    // reserved data
    memset(msg->hdr->reserved, 0, sizeof(msg->hdr->reserved));

    /////////////////////////////////// sign

    // sign with a shared secret key (intentionally forgeable by recipient)
    {
        unsigned char shared_seed[crypto_sign_SEEDBYTES];
        unsigned char shared_sign_sec[crypto_sign_SECRETKEYBYTES];
        unsigned char shared_sign_pub[crypto_sign_PUBLICKEYBYTES];
        _ed25519pk      sig_ecdh;
        _ed25519pk      sZero;
        
        memset(sZero, 0, sizeof(sZero));
        assert(memcmp(msg->secrets->sig_sec, sZero, sizeof(sZero)) != 0);

        status = crypto_scalarmult_ed25519(sig_ecdh, msg->secrets->sig_sec, toK->sign_pub);
        // have already checked sign_pub and sig_sec, so shouldn't encounter error here
        assert(status == 0);
        crypto_generichash(shared_seed, sizeof(shared_seed), sig_ecdh, sizeof(sig_ecdh), NULL, 0);
        crypto_sign_seed_keypair(shared_sign_pub, shared_sign_sec, shared_seed);

        do {
            // sign ... signature is probablistic, so in theory if no nonce could satisfy the postage target
            // then simply generating a new signature adds bits to the nonce. Nevertheless the nonce is a 64-bit
            // value and the postage rate should not in practice be that high
            status = crypto_sign_detached(msg->hdr->header_signature, NULL, (unsigned char *)msg->hdr, _CT_HDR_SIGD_SZ, shared_sign_sec);
            // key previously validated, should be no failure case
            assert(status == 0);

            // calculate postage hash target (hashcash style)
            status = ctMessage_rehash(msg, rate);
        } while (status != 0);
    }

    // copy now-complete single-block header into message
    memcpy(msg->ctext, (void *)msg->hdr, _CT_BLKSZ);

    // size = 1 block header + payload
    *sz = _CT_BLKSZ + payloadsz;
    return msg->ctext;
    
error_cleanup2:
    //printf("cleanup2\n");
    CHKPKE_element_clear(random_e);
error_cleanup1:
    //printf("cleanup1\n");
    memset(msg->secrets, 0, sizeof(*msg->secrets));
    //memset(msg, 0, sizeof(msg));
    return NULL;
}

int ctMessage_init_Dec(ctMessage_t msg, ctSecretKey_t toK, unsigned char *ctext, size_t ctextsz) {
    ctMessageHeader_t thdr;
    _ed25519pk addr_point;
    _ed25519pk ephem_ecdh;
    unsigned char payload_hash[crypto_generichash_BYTES];
    unsigned char sym_key[crypto_stream_xchacha20_KEYBYTES];
    unsigned char shared_seed[crypto_sign_SEEDBYTES];
    unsigned char shared_sign_sec[crypto_sign_SECRETKEYBYTES];
    unsigned char shared_sign_pub[crypto_sign_PUBLICKEYBYTES];
    unsigned char *preamble;
    unsigned char *fskey_der;
    unsigned char *nonce;
    uint32_t fskey_dersz;
    size_t preamble_sz;
    element_t fsk_e;
    int64_t interval;
    int status;
    _ed25519pk      sig_ecdh;
    unsigned char *buffer;
    unsigned long long blen;
    unsigned char *ad;
    unsigned long long adlen;
    unsigned long long clen;
    size_t padsz, innersz;
    unsigned char pad;
    ctMessageInnerHeader_ptr iptr;

    /////////////////////////////////// validate input

    // check magic and version
    if (memcmp(ctext, _ct_msg_magic, _ct_msg_magic_sz) != 0) return -1;
    if (memcmp(ctext + _ct_msg_magic_sz, _ct_msg_version, _ct_msg_version_sz) != 0) return -1;

    // copy header and convert byte order
    memcpy(thdr, ctext, sizeof(thdr));
    thdr->msgtime_usec = le64toh(thdr->msgtime_usec);
    thdr->expire_usec = le64toh(thdr->expire_usec);
    thdr->payload_blocks = le64toh(thdr->payload_blocks);

    // validate no degenerate points input
    if ((crypto_core_ed25519_is_valid_point(thdr->I_point) == 0) || 
        (crypto_core_ed25519_is_valid_point(thdr->J_point) == 0) ||
        (crypto_core_ed25519_is_valid_point(thdr->ECDHE_point) == 0)) {
        //printf("weak point check failed\n");
        return -1;
    }

    // validate addressing matches key
    status = crypto_scalarmult_ed25519(addr_point, toK->addr_sec, thdr->I_point);
    if ((status != 0) || (memcmp(addr_point, thdr->J_point, sizeof(addr_point)) != 0)) {
        return -1;
    }

    // validate payload hash
    crypto_generichash(payload_hash, sizeof(payload_hash), ctext + _CT_BLKSZ, ctextsz - _CT_BLKSZ, NULL, 0);
    if (memcmp(payload_hash, thdr->payload_hash, sizeof(payload_hash)) != 0) return -1;

    /////////////////////////////////// calculate shared key

    preamble = ctext + _CT_BLKSZ;
    fskey_der = preamble + sizeof(fskey_dersz);
    fskey_dersz = le32toh(*((uint32_t *)preamble));

    // decrypt forward-secure key

    CHKPKE_init_element(fsk_e, toK->chk_sec);
    interval = _ctSecretKey_interval_for_time(toK, thdr->msgtime_usec);
    status = CHKPKE_Dec_DER(fsk_e, toK->chk_sec, fskey_der, fskey_dersz, interval);
    if (status != 0) return -1;

    // calculate ecdh point

    status = crypto_scalarmult_ed25519(ephem_ecdh, toK->enc_sec, thdr->ECDHE_point);
    if (status != 0) return -1;

    // hash to secret key
    {
        unsigned char *fs_bytes;
        unsigned char *buffer;
        size_t fssz, bsz;

        // compose ECDH key with CHK key to generate a shared key for symmetric encryption
        fs_bytes = CHKPKE_element_to_bytes(fsk_e, &fssz);
        bsz = sizeof(ephem_ecdh) + (fssz * sizeof(char));
        buffer = (unsigned char *)malloc(bsz);
        memcpy(buffer, ephem_ecdh, sizeof(ephem_ecdh));
        memcpy(buffer + sizeof(ephem_ecdh), fs_bytes, fssz);
        memset(fs_bytes, 0, fssz);
        free(fs_bytes);

        // hash composite key
        crypto_generichash(sym_key, sizeof(sym_key), buffer, bsz, NULL, 0);
        memset(buffer, 0, bsz);
        free(buffer);
        memset(ephem_ecdh, 0, sizeof(ephem_ecdh));
    }

    /////////////////////////////////// decrypt symmetric

    nonce = preamble + sizeof(fskey_dersz) + fskey_dersz;
    preamble_sz = sizeof(fskey_dersz) + fskey_dersz + sizeof(msg->nonce);

    // ciphertext = payload - preamble
    clen = (thdr->payload_blocks * _CT_BLKSZ) - preamble_sz;
    //  plaintext length = ciphertext - authentication tag
    blen = clen - crypto_aead_xchacha20poly1305_ietf_ABYTES;
    buffer = (unsigned char *)malloc(blen * sizeof(unsigned char));
    assert(buffer != NULL);

    // compose AD
    adlen = _CT_AUTH_HDR_SZ + preamble_sz;
    ad = (unsigned char *)malloc(adlen * sizeof(unsigned char));
    assert(ad != NULL);
    memcpy(ad, ctext, _CT_AUTH_HDR_SZ);
    memcpy(ad + _CT_AUTH_HDR_SZ, preamble, preamble_sz);

    status = crypto_aead_xchacha20poly1305_ietf_decrypt(buffer, &blen, NULL,
        ctext + _CT_BLKSZ + preamble_sz, clen, ad, adlen, nonce, sym_key);
    if ((status != 0) || (blen != (clen - crypto_aead_xchacha20poly1305_ietf_ABYTES))) {
        memset(ad, 0, adlen);
        free(ad);
        goto error_cleanup1;
    }

    memset(ad, 0, adlen);
    free(ad);

    // convert inner header from wire format
    iptr = (ctMessageInnerHeader_ptr)buffer;
    iptr->msglen = le64toh(iptr->msglen);
    iptr->mimelen = le32toh(iptr->mimelen);

    // validate pad
    innersz = sizeof(iptr->SIG_point) + sizeof(iptr->msglen) +
        sizeof(iptr->mimelen) + ((size_t)iptr->mimelen);

    if (blen < (innersz + ((size_t)iptr->msglen))) goto error_cleanup1;
    padsz = blen - (innersz + ((size_t)iptr->msglen));
    if (padsz >= _CT_BLKSZ) goto error_cleanup1;

    pad = (unsigned char)padsz;
    
    // check the pad values
    {
        unsigned char *padbytes;
        int i;
        
        padbytes = buffer + blen - padsz;
        for (i = 0; i < padsz; i++) {
            if (padbytes[i] != pad) goto error_cleanup1;
        }
    }

    // validate signature
    status = crypto_scalarmult_ed25519(sig_ecdh, toK->sign_sec, iptr->SIG_point);
    // an error is possible if SIG_point is degenerate
    if (status != 0) goto error_cleanup1;

    crypto_generichash(shared_seed, sizeof(shared_seed), sig_ecdh, sizeof(sig_ecdh), NULL, 0);
    crypto_sign_seed_keypair(shared_sign_pub, shared_sign_sec, shared_seed);

    status = crypto_sign_verify_detached(thdr->header_signature, ctext, _CT_HDR_SIGD_SZ, shared_sign_pub);
    if (status != 0) goto error_cleanup1;

    // once signature is verified, copy message out

    msg->ptext = buffer;
    msg->ptextsz = blen;
    memcpy(msg->inner, iptr, innersz);
    msg->innersz = innersz;
    // ensure null termination of mime type
    msg->inner->mime[msg->inner->mimelen] = 0;

    memcpy(msg->hdr, thdr, _CT_BLKSZ);
    msg->ctext = (unsigned char *)malloc(ctextsz * sizeof(unsigned char));
    msg->ctextsz = ctextsz;
    msg->fsk = (unsigned char *)malloc(fskey_dersz * sizeof(unsigned char));
    memcpy(msg->fsk, fskey_der, fskey_dersz);
    msg->fsksz = fskey_dersz;
    memcpy(nonce, msg->nonce, sizeof(msg->nonce));
    memcpy(msg->secrets->sym_key, sym_key, sizeof(msg->secrets->sym_key));

    return 0;

error_cleanup1:
    CHKPKE_element_clear(fsk_e);
    memset(buffer, 0, blen);
    free(buffer);
    return -1;
}

void ctMessage_clear(ctMessage_t msg) {
    memset(msg->ptext, 0, msg->ptextsz);
    memset(msg->ctext, 0, msg->ctextsz);
    memset(msg->fsk, 0, msg->fsksz);
    free(msg->ctext);
    free(msg->ptext);
    free(msg->fsk);
    memset(msg, 0, sizeof(msg[0]));
}

int ctMessage_rehash(ctMessage_t msg, ctPostageRate_t rate) {
    ctPostageHash_t ptgt;
    ctPostageHash_t hash;
    int status;

    status = ctPostage_hash_target(ptgt, rate, msg->hdr->payload_blocks + 1);
    // calculate postage hash target (hashcash style)
    for (msg->hdr->nonce = 0; msg->hdr->nonce < ULLONG_MAX; msg->hdr->nonce++) {
        crypto_generichash(hash, sizeof(hash), (void *)msg->hdr, sizeof(msg->hdr), NULL, 0);
        status = ctPostage_hash_cmp(hash, ptgt);
        if (status < 0) return 0;
    }

    return -1;
}

// return a pointer and length for the message plaintext.
unsigned char *ctMessage_plaintext_ptr(ctMessage_t msg, size_t *ptsz) {
    *ptsz = msg->inner->msglen;
    return msg->ptext + msg->innersz;
}

// return a pointer and length for the message mime type. The mime type is 
// null terminated and expected to contain ascii text
char *ctMessage_mime_ptr(ctMessage_t msg, size_t *mimesz) {
    *mimesz = msg->inner->mimelen;
    return msg->inner->mime;
}

// return a pointer and length for the message plaintext. 
unsigned char *ctMessage_ciphertext_ptr(ctMessage_t msg, size_t *ctsz) {
    *ctsz = msg->ctextsz;
    return msg->ctext;
}
