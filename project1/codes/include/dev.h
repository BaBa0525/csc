#ifndef _DEV_H
#define _DEV_H

#include <linux/if_packet.h>
#include <net/if.h>
#include <stdint.h>

#include <array>
#include <string>

#include "constants.h"
#include "esp.h"
#include "transport.h"

struct Dev {
    int mtu;

    sockaddr_ll addr;
    int fd;

    std::array<uint8_t, BUFSIZE> frame;
    uint16_t framelen;

    std::array<uint8_t, LINKHDRLEN> linkhdr;

    Dev(const std::string& dev_name);
    void fmt_frame(Net net, Esp esp, Txp txp);
    ssize_t tx_frame();
    ssize_t rx_frame();
};

#endif
