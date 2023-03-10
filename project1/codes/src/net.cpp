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
 * @brief Collect ip information from pkt
 * @returns payload of network layer
 */
uint8_t* Net::dissect(uint8_t* pkt, size_t pkt_len) {
    this->ip4hdr = *reinterpret_cast<iphdr*>(pkt);
    this->hdrlen = this->ip4hdr.ihl * 4;
    this->plen = pkt_len - this->hdrlen;

    if (inet_ntop(AF_INET, &this->ip4hdr.saddr, this->src_ip.data(),
                  this->src_ip.size()) == nullptr) {
        perror("inet_ntop()");
        exit(EXIT_FAILURE);
    };

    if (inet_ntop(AF_INET, &this->ip4hdr.daddr, this->dst_ip.data(),
                  this->dst_ip.size()) == nullptr) {
        perror("inet_ntop()");
        exit(EXIT_FAILURE);
    };

    switch (this->ip4hdr.protocol) {
        case IPPROTO_IP:
        case IPPROTO_ESP:
        case IPPROTO_TCP:
            pro = (Proto)this->ip4hdr.protocol;
            break;
        default:
            pro = UNKN_PROTO;
            break;
    }

    return pkt + this->hdrlen;
}

Net* Net::fmt_rep() {
    // TODO: Fill up self->ip4hdr (prepare to send)

    return this;
}

Net::Net() : hdrlen{sizeof(iphdr)} {}
