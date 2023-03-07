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
    // [TODO]: Finish IP checksum calculation
    return 0;
}

uint8_t* Net::dissect(uint8_t* pkt, size_t pkt_len) {
    // [TODO]: Collect information from pkt.
    // Return payload of network layer
    return nullptr;
}

Net* Net::fmt_rep() {
    // [TODO]: Fill up self->ip4hdr (prepare to send)

    return this;
}

Net::Net() : hdrlen{sizeof(iphdr)} {}
