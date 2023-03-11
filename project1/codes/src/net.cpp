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

#include <numeric>

#include "esp.h"
#include "transport.h"

namespace net {
constexpr int BYTES_PER_WORD = 2;
}

uint16_t cal_ipv4_cksm(iphdr iphdr) {
    // Finish IP checksum calculation
    uint16_t* cursor = reinterpret_cast<uint16_t*>(&iphdr);
    size_t hdrlen = iphdr.ihl * 4;

    uint32_t sum =
        std::accumulate(cursor, cursor + hdrlen / net::BYTES_PER_WORD, 0u);

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~sum;
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
    // Fill up self->ip4hdr (prepare to send)
    int ret = inet_pton(AF_INET, this->x_src_ip.data(), &this->ip4hdr.saddr);
    if (ret < 0) {
        perror("inet_pton()");
        exit(EXIT_FAILURE);
    }

    ret = inet_pton(AF_INET, this->x_dst_ip.data(), &this->ip4hdr.daddr);
    if (ret < 0) {
        perror("inet_pton()");
        exit(EXIT_FAILURE);
    }

    this->ip4hdr.tot_len = htons(this->plen + this->hdrlen);
    this->ip4hdr.check = 0;
    this->ip4hdr.check = cal_ipv4_cksm(this->ip4hdr);

    return this;
}

Net::Net() : hdrlen{sizeof(iphdr)} {}
