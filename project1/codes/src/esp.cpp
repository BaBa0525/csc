#include "esp.h"

#include <linux/pfkeyv2.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "hmac.h"
#include "transport.h"

EspHeader esp_hdr_rec;

void get_ik(int type, uint8_t* key) {
    // TODO: Dump authentication key from security association database (SADB)
    // (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10)
}

void Esp::get_key() { get_ik(SADB_SATYPE_ESP, this->esp_key.data()); }

uint8_t* Esp::set_padpl() {
    // TODO: Fiill up self->pad and self->pad_len (Ref. RFC4303 Section 2.4)
    return this->pad.data();
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

    // TODO: Put everything needed to be authenticated into buff and add up nb

    ret = hmac(this->esp_key.data(), esp_keylen, buff, nb, this->auth.data());

    if (ret == -1) {
        fprintf(stderr, "Error occurs when try to compute authentication data");
        return NULL;
    }

    this->authlen = ret;
    return this->auth.data();
}
/**
 * @brief Collect information from esp_pkt
 * @param esp_pkt pointer to esp data
 * @param esp_len length of esp packet data
 *
 * @returns payload of ESP
 */
uint8_t* Esp::dissect(uint8_t* esp_pkt, size_t esp_len) {
    this->hdr.spi = ntohl(((uint32_t*)esp_pkt)[0]);
    this->hdr.seq = ntohl(((uint32_t*)esp_pkt)[1]);
    uint8_t* payload_start = esp_pkt + sizeof(EspHeader);

    // Store authentication data (length: 12)
    uint8_t* current_position = esp_pkt + esp_len - HMAC96AUTHLEN;
    memcpy(this->auth.data(), current_position, HMAC96AUTHLEN);

    // Store ESP trailer
    current_position -= 2;
    this->tlr.pad_len = current_position[0];
    this->tlr.nxt = current_position[1];

    // Store padding (?)
    current_position -= this->tlr.pad_len;
    memcpy(this->pad.data(), current_position, this->tlr.pad_len);

    this->plen = current_position - payload_start;
    memcpy(this->pl.data(), payload_start, this->plen);

    return this->pl.data();
}

Esp* Esp::fmt_rep(Proto p) {
    // TODO: Fill up ESP header and trailer (prepare to send)
    return this;
}

Esp::Esp() : authlen{HMAC96AUTHLEN} {}
