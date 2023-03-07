#ifndef _DEV_H
#define _DEV_H

#include <linux/if_packet.h>
#include <net/if.h>
#include <stdint.h>

#include <string>

struct Dev {
    int mtu;

    struct sockaddr_ll addr;
    int fd;

    uint8_t* frame;
    uint16_t framelen;

    uint8_t* linkhdr;

    Dev(const std::string& dev_name);
    void fmt_frame(Net net, Esp esp, Txp txp);
    ssize_t tx_frame();
    ssize_t rx_frame();
};

#endif
