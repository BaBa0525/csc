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
    unsigned int sourceAddr;
    unsigned int destAddr;
    unsigned char zero;
    unsigned char protocol;
    unsigned short tcpLength;
};

namespace transport {
constexpr int BYTES_PER_WORD = 2;
}  // namespace transport

uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t* pl,
                      int plen) {
    // TODO: Finish TCP checksum calculation
    PseudoHeader pseudo_header{
        .sourceAddr = iphdr.saddr,
        .destAddr = iphdr.daddr,
        .protocol = iphdr.protocol,
        .tcpLength = (uint16_t)(iphdr.tot_len - (iphdr.ihl * 4)),
    };

    uint chksum = 0;
    int pseudo_words = sizeof(PseudoHeader) / transport::BYTES_PER_WORD;
    uint16_t* pseudo_cursor = (uint16_t*)&pseudo_header;

    for (int i = 0; i < pseudo_words; i++) {
        chksum += pseudo_cursor[i];
    }

    int tcp_words = sizeof(tcphdr) / transport::BYTES_PER_WORD;
    uint16_t* tcphdr_cursor = (uint16_t*)&tcphdr;
    for (int i = 0; i < tcp_words; i++) {
        chksum += tcphdr_cursor[i];
    }

    int tcp_pl_words = plen / transport::BYTES_PER_WORD;
    uint16_t* tcp_pl_cursor = (uint16_t*)pl;

    for (int i = 0; i < tcp_pl_words; i++) {
        chksum += tcp_pl_cursor[i];
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
    this->thdr = *(tcphdr*)segm;

    this->hdrlen = this->thdr.doff * 4;
    this->plen = segm_len - this->hdrlen;
    memcpy(this->pl.data(), segm + net->hdrlen, this->plen);

    if (this->thdr.psh) printf("Seq: %u\n", ntohl(this->thdr.seq));

    return this->pl.data();
}

Txp* Txp::fmt_rep(struct iphdr iphdr, uint8_t* data, size_t dlen) {
    // TODO: Fill up self->tcphdr (prepare to send)
    printf("Expected seq: %u\n", this->x_tx_seq);
    this->thdr.seq = htonl(this->x_tx_seq);
    this->thdr.check = 0;
    this->thdr.check =
        cal_tcp_cksm(iphdr, this->thdr, this->pl.data(), this->plen);

    return this;
}

Txp::Txp() : hdrlen{sizeof(tcphdr)} {}
