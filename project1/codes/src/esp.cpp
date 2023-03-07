#include "esp.h"

#include <linux/pfkeyv2.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "hmac.h"
#include "transport.h"

EspHeader esp_hdr_rec;

void get_ik(int type, uint8_t* key) {
    // [TODO]: Dump authentication key from security association database (SADB)
    // (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10)
}

void Esp::get_key() { get_ik(SADB_SATYPE_ESP, this->esp_key); }

uint8_t* Esp::set_padpl() {
    // [TODO]: Fiill up self->pad and self->pad_len (Ref. RFC4303 Section 2.4)
    return this->pad;
}

uint8_t* Esp::set_auth(HmacFn hmac) {
    if (!hmac) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }

    uint8_t buff[BUFSIZE];
    size_t esp_keylen = 16;
    size_t nb = 0;  // Number of bytes to be hashed
    ssize_t ret;

    // [TODO]: Put everything needed to be authenticated into buff and add up nb

    ret = hmac(this->esp_key, esp_keylen, buff, nb, this->auth);

    if (ret == -1) {
        fprintf(stderr, "Error occurs when try to compute authentication data");
        return NULL;
    }

    this->authlen = ret;
    return this->auth;
}

uint8_t* Esp::dissect(uint8_t* esp_pkt, size_t esp_len) {
    // [TODO]: Collect information from esp_pkt.
    // Return payload of ESP
}

Esp* Esp::fmt_rep(Proto p) {
    // [TODO]: Fill up ESP header and trailer (prepare to send)
}

Esp::Esp() {
    this->pl = (uint8_t*)malloc(MAXESPPLEN * sizeof(uint8_t));
    this->pad = (uint8_t*)malloc(MAXESPPADLEN * sizeof(uint8_t));
    this->auth = (uint8_t*)malloc(HMAC96AUTHLEN * sizeof(uint8_t));
    this->authlen = HMAC96AUTHLEN;
    this->esp_key = (uint8_t*)malloc(BUFSIZE * sizeof(uint8_t));
}
