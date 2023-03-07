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
    // [TODO]: Finish TCP checksum calculation
    return 0;
}

uint8_t* Txp::dissect(Net* net, uint8_t* segm, size_t segm_len) {
    // [TODO]: Collect information from segm
    // (Check IP addr & port to determine the next seq and ack value)
    // Return payload of TCP
    return nullptr;
}

Txp* Txp::fmt_rep(struct iphdr iphdr, uint8_t* data, size_t dlen) {
    // [TODO]: Fill up self->tcphdr (prepare to send)

    return this;
}

Txp::Txp() : hdrlen{sizeof(tcphdr)} {}
