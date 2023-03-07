#ifndef _Net_H
#define _Net_H

#include <netdb.h>
#include <netinet/ip.h>

#include <array>

enum Proto {
    UNKN_PROTO = 0,

    IPv4 = IPPROTO_IP,

    ESP = IPPROTO_ESP,

    TCP = IPPROTO_TCP,
};

struct Net {
    std::array<char, INET_ADDRSTRLEN> src_ip;
    std::array<char, INET_ADDRSTRLEN> dst_ip;

    std::array<char, INET_ADDRSTRLEN> x_src_ip; /* Expected src IP addr */
    std::array<char, INET_ADDRSTRLEN> x_dst_ip; /* Expected dst IP addr */

    iphdr ip4hdr;

    size_t hdrlen;
    uint16_t plen;
    Proto pro;

    uint8_t* dissect(uint8_t* pkt, size_t pkt_len);
    Net* fmt_rep();

    Net();
};

uint16_t cal_ipv4_cksm(iphdr iphdr);

#endif
