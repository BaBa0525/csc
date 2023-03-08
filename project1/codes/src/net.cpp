#include "net.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "esp.h"
#include "transport.h"

uint16_t cal_ipv4_cksm(iphdr iphdr) {
    // TODO: Finish IP checksum calculation
    return 0;
}

/**
 * @returns payload of network layer
 */
uint8_t* Net::dissect(uint8_t* pkt, size_t pkt_len) {
    // TODO: Collect information from pkt.
    // Return payload of network layer
    ip4hdr = *(iphdr*)pkt;
    hdrlen = ip4hdr.ihl * 4;
    plen = pkt_len - hdrlen;

    switch (ip4hdr.protocol) {
        case IPPROTO_IP:
        case IPPROTO_ESP:
        case IPPROTO_TCP:
            pro = (Proto)ip4hdr.protocol;
            break;
        default:
            pro = UNKN_PROTO;
            break;
    }

    return nullptr;
}

Net* Net::fmt_rep() {
    // TODO: Fill up self->ip4hdr (prepare to send)

    return this;
}

Net::Net() : hdrlen{sizeof(iphdr)} {}
