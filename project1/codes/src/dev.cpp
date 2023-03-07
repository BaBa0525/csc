#include "dev.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#include "esp.h"
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
    sockaddr_ll addr;
    bzero(&addr, sizeof(addr));

    struct if_nameindex* if_ni = if_nameindex();

    for (auto i = if_ni; !(i->if_index == 0 && i->if_name == NULL); i++) {
        printf("%u: %s\n", i->if_index, i->if_name);
        if (i->if_name == name) {
            addr.sll_ifindex = i->if_index;
        }
    }

    if_freenameindex(if_ni);

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

void Dev::fmt_frame(Net net, Esp esp, Txp txp) {
    // [TODO]: store the whole frame into self->frame
    // and store the length of the frame into self->framelen
}

ssize_t Dev::tx_frame() {
    ssize_t nb;
    socklen_t addrlen = sizeof(this->addr);

    nb = sendto(this->fd, this->frame.data(), this->framelen, 0,
                (sockaddr*)&this->addr, addrlen);
    if (nb <= 0) perror("sendto()");

    return nb;
}

ssize_t Dev::rx_frame() {
    ssize_t nb;
    socklen_t addrlen = sizeof(this->addr);

    nb = recvfrom(this->fd, this->frame.data(), this->mtu, 0,
                  (sockaddr*)&this->addr, &addrlen);
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
