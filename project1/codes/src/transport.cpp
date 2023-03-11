#include "transport.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "net.h"

struct PseudoHeader {
    uint32_t source_addr;
    uint32_t dest_addr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_length;
};

namespace transport {
constexpr int BYTES_PER_WORD = 2;
}  // namespace transport

uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t* pl,
                      int plen) {
    PseudoHeader pseudo_header{
        .source_addr = iphdr.saddr,
        .dest_addr = iphdr.daddr,
        .protocol = TCP,
        .tcp_length = htons(static_cast<uint16_t>(sizeof(tcphdr) + plen)),
    };

    uint32_t chksum = 0;
    int pseudo_words = sizeof(PseudoHeader) / transport::BYTES_PER_WORD;
    uint16_t* pseudo_cursor = reinterpret_cast<uint16_t*>(&pseudo_header);

    for (int i = 0; i < pseudo_words; i++) {
        chksum += pseudo_cursor[i];
    }

    int tcp_words = sizeof(tcphdr) / transport::BYTES_PER_WORD;
    uint16_t* tcphdr_cursor = reinterpret_cast<uint16_t*>(&tcphdr);
    for (int i = 0; i < tcp_words; i++) {
        chksum += tcphdr_cursor[i];
    }

    // round down the result of division
    int tcp_pl_words = plen / transport::BYTES_PER_WORD;
    uint16_t* tcp_pl_cursor = reinterpret_cast<uint16_t*>(pl);

    for (int i = 0; i < tcp_pl_words; i++) {
        chksum += tcp_pl_cursor[i];
    }

    // if the payload length is an odd number,
    // we need to pad the last byte with zeros
    if (plen % transport::BYTES_PER_WORD != 0) {
        uint8_t last_byte = reinterpret_cast<uint8_t*>(pl)[plen - 1];
        chksum += static_cast<uint16_t>(last_byte);
    }

    while (chksum >> 16) {
        chksum = (chksum >> 16) + (chksum & 0xffff);
    }

    return ~chksum;
}
/**
 * @brief Collect information from segm
 * @note Check IP addr & port to determine the next seq and ack value
 * @returns payload of TCP
 */
uint8_t* Txp::dissect(Net* net, uint8_t* segm, size_t segm_len) {
    this->pl.fill(0);
    this->thdr = *reinterpret_cast<tcphdr*>(segm);

    this->hdrlen = this->thdr.doff * 4;
    this->plen = segm_len - this->hdrlen;
    memcpy(this->pl.data(), segm + net->hdrlen, this->plen);

    if (strcmp(net->x_src_ip.data(), net->dst_ip.data()) == 0) {
        this->x_tx_seq = ntohl(this->thdr.th_ack);
        this->x_tx_ack = ntohl(this->thdr.th_seq) + this->plen;
        this->x_src_port = ntohs(this->thdr.th_dport);
        this->x_dst_port = ntohs(this->thdr.th_sport);
    }

    return this->pl.data();
}

Txp* Txp::fmt_rep(struct iphdr iphdr, uint8_t* data, size_t dlen) {
    this->thdr.seq = htonl(this->x_tx_seq);
    this->thdr.ack_seq = htonl(this->x_tx_ack);
    this->thdr.th_sport = htons(this->x_src_port);
    this->thdr.th_dport = htons(this->x_dst_port);

    if (dlen == 0) {
        this->thdr.psh = 0;
        this->thdr.ack = 1;
    } else {
        this->thdr.psh = 1;
        this->thdr.ack = 1;
    }

    this->plen = dlen;
    memcpy(this->pl.data(), data, dlen);

    this->thdr.check = 0;
    this->thdr.check =
        cal_tcp_cksm(iphdr, this->thdr, this->pl.data(), this->plen);

    return this;
}

Txp::Txp() : hdrlen{sizeof(tcphdr)} {}
