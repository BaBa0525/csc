#ifndef _ESP_H
#define _ESP_H

#include <linux/pfkeyv2.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <functional>

#include "net.h"

/* Authentication data length of HMAC-SHA1-96 is 96 bits */
#define MAXESPPADLEN 3
#define MAXESPPLEN \
    IP_MAXPACKET - sizeof(EspHeader) - sizeof(EspTrailer) - HMAC96AUTHLEN

typedef struct esp_header {
    uint32_t spi;
    uint32_t seq;
} EspHeader;

typedef struct esp_trailer {
    uint8_t pad_len;
    uint8_t nxt;
} EspTrailer;

using HmacFn = std::function<ssize_t(uint8_t const*, size_t, uint8_t const*,
                                     size_t, uint8_t*)>;

struct Esp {
    EspHeader hdr;

    uint8_t* pl;  // ESP payload
    size_t plen;  // ESP payload length

    uint8_t* pad;  // ESP padding

    EspTrailer tlr;

    uint8_t* auth;
    size_t authlen;

    uint8_t* esp_key;

    Esp();
    uint8_t* set_padpl();
    uint8_t* set_auth(HmacFn hmac);

    void get_key();
    uint8_t* dissect(uint8_t* esp_pkt, size_t esp_len);
    Esp* fmt_rep(Proto p);
};

void get_ik(int type, uint8_t* key);

#endif
