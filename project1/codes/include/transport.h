#ifndef _TRANSPORT_H
#define _TRANSPORT_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>

#include <array>

#include "net.h"

// Transport Layer
struct Txp {
    uint16_t x_src_port; /* Expected src port to CSCF */
    uint16_t x_dst_port; /* Expected dst port to CSCF */

    uint32_t x_tx_seq; /* Expected tx sequence number */
    uint32_t x_tx_ack; /* Expected tx acknowledge number */

    tcphdr thdr;
    uint8_t hdrlen;

    std::array<uint8_t, IP_MAXPACKET> pl;
    uint16_t plen;

    Txp();

    uint8_t* dissect(Net* net, uint8_t* txp_data, size_t txp_len);
    Txp* fmt_rep(iphdr iphdr, uint8_t* data, size_t dlen);
};

uint16_t cal_tcp_cksm(iphdr iphdr, tcphdr tcphdr, uint8_t* pl, int plen);

#endif
