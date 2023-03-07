#ifndef _ESP_H
#define _ESP_H

#include <linux/pfkeyv2.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <array>
#include <functional>

#include "constants.h"
#include "net.h"

struct EspHeader {
    uint32_t spi;
    uint32_t seq;
};

struct EspTrailer {
    uint8_t pad_len;
    uint8_t nxt;
};

using HmacFn = std::function<ssize_t(uint8_t const*, size_t, uint8_t const*,
                                     size_t, uint8_t*)>;

struct Esp {
    EspHeader hdr;

    std::array<uint8_t, MAXESPPLEN> pl;  // ESP payload
    size_t plen;                         // ESP payload length

    std::array<uint8_t, MAXESPPADLEN> pad;  // ESP padding

    EspTrailer tlr;

    std::array<uint8_t, HMAC96AUTHLEN> auth;
    size_t authlen;

    std::array<uint8_t, BUFSIZE> esp_key;

    Esp();
    uint8_t* set_padpl();
    uint8_t* set_auth(HmacFn hmac);

    void get_key();
    uint8_t* dissect(uint8_t* esp_pkt, size_t esp_len);
    Esp* fmt_rep(Proto p);
};

void get_ik(int type, uint8_t* key);

#endif
