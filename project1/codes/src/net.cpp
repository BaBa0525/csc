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

uint16_t cal_ipv4_cksm(struct iphdr iphdr) {
    // [TODO]: Finish IP checksum calculation
}

uint8_t* Net::dissect(uint8_t* pkt, size_t pkt_len) {
    // [TODO]: Collect information from pkt.
    // Return payload of network layer
}

Net* Net::fmt_rep() {
    // [TODO]: Fill up self->ip4hdr (prepare to send)

    return this;
}

Net::Net() {
    this->src_ip = (char*)malloc(INET_ADDRSTRLEN * sizeof(char));
    this->dst_ip = (char*)malloc(INET_ADDRSTRLEN * sizeof(char));
    this->x_src_ip = (char*)malloc(INET_ADDRSTRLEN * sizeof(char));
    this->x_dst_ip = (char*)malloc(INET_ADDRSTRLEN * sizeof(char));
    this->hdrlen = sizeof(struct iphdr);

    // self->dissect = dissect_ip;
    // self->fmt_rep = fmt_net_rep;
}
