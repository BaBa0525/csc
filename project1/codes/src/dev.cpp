#include "dev.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#include "esp.h"
#include "if_nameindex.h"
#include "net.h"
#include "replay.h"
#include "transport.h"

inline static int get_ifr_mtu(ifreq* ifr) {
    int fd;

    if ((fd = socket(PF_PACKET, SOCK_RAW, 0)) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    if (ioctl(fd, SIOCGIFMTU, ifr) < 0) {
        perror("ioctl()");
        close(fd);
        exit(EXIT_FAILURE);
    }

    return ifr->ifr_mtu;
}

// Fill up struct sockaddr_ll addr which will be used to bind in
// func set_sock_fd
inline static sockaddr_ll init_addr(const std::string& name) {
    // https://man7.org/linux/man-pages/man7/packet.7.html
    // To get packets only from a specific
    //        interface use bind(2) specifying an address in a struct
    //        sockaddr_ll to bind the packet socket to an interface.
    // Fields used for binding are sll_family (should be AF_PACKET),
    //        sll_protocol, and sll_ifindex.

    sockaddr_ll addr{
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
    };

    for (auto index : IfNameIndex()) {
        if (index.if_name == name) {
            addr.sll_ifindex = index.if_index;
        }
    }

    if (addr.sll_ifindex == 0) {
        perror("if_nameindex()");
        exit(EXIT_FAILURE);
    }

    return addr;
}

inline static int set_sock_fd(sockaddr_ll dev) {
    int fd;

    if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    bind(fd, (sockaddr*)&dev, sizeof(dev));

    return fd;
}

#define MEMCPY(dest, src, nbytes)  \
    do {                           \
        memcpy(dest, src, nbytes); \
        dest += nbytes;            \
    } while (0)

void Dev::fmt_frame(Net net, Esp esp, Txp txp) {
    // store the whole frame into self->frame
    // and store the length of the frame into self->framelen
    this->frame.fill(0);
    uint8_t* cursor = this->frame.data();

    MEMCPY(cursor, this->linkhdr.data(), LINKHDRLEN);
    MEMCPY(cursor, &net.ip4hdr, sizeof(iphdr));
    MEMCPY(cursor, &esp.hdr, sizeof(EspHeader));
    MEMCPY(cursor, &txp.thdr, txp.hdrlen);
    MEMCPY(cursor, txp.pl.data(), txp.plen);
    MEMCPY(cursor, esp.pad.data(), esp.tlr.pad_len);
    MEMCPY(cursor, &esp.tlr, sizeof(EspTrailer));
    MEMCPY(cursor, esp.auth.data(), esp.authlen);

    this->framelen = cursor - this->frame.data();
}

ssize_t Dev::tx_frame() {
    ssize_t nb;
    socklen_t addrlen = sizeof(this->addr);

    nb = sendto(this->fd, this->frame.data(), this->framelen, 0,
                reinterpret_cast<sockaddr*>(&this->addr), addrlen);

    if (nb <= 0) perror("sendto()");

    return nb;
}

/**
 * rx stands for receive
 * Receive packet from Dev::addr and store in Dev::frame
 * @returns the number of bytes
 */
ssize_t Dev::rx_frame() {
    ssize_t nb;
    socklen_t addrlen = sizeof(this->addr);

    nb = recvfrom(this->fd, this->frame.data(), this->mtu, 0,
                  reinterpret_cast<sockaddr*>(&this->addr), &addrlen);
    if (nb <= 0) perror("recvfrom()");

    return nb;
}

Dev::Dev(const std::string& dev_name) {
    if (dev_name.length() + 1 > IFNAMSIZ) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    ifreq ifr;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev_name.c_str());

    this->mtu = get_ifr_mtu(&ifr);

    this->addr = init_addr(dev_name);
    this->fd = set_sock_fd(this->addr);

    this->framelen = 0;
}
