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

uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t* pl,
                      int plen) {
    // TODO: Finish TCP checksum calculation
    return 0;
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

    return this->pl.data();
}

Txp* Txp::fmt_rep(struct iphdr iphdr, uint8_t* data, size_t dlen) {
    // TODO: Fill up self->tcphdr (prepare to send)
    // this->thdr.=

    return this;
}

Txp::Txp() : hdrlen{sizeof(tcphdr)} {}
