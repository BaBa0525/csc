#ifndef _REPLAY_H
#define _REPLAY_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define WAIT_PKT 0
#define WAIT_SECRET 1
#define SEND_ACK 2

#define LINKHDRLEN 14

#define ENA_TCP_ACK true
#define DISABLE_TCP_ACK false

#define MAXBUFCOUNT 8

struct frame_arr {
    uint8_t frame[MAXBUFCOUNT][65535];
    uint16_t framelen[MAXBUFCOUNT];
    long msec[MAXBUFCOUNT];

    ssize_t count;
};

extern struct frame_arr frame_buf;

void tx_esp_rep(Dev dev, Net net, Esp esp, Txp txp, uint8_t* data, ssize_t dlen,
                long msec);

ssize_t send_msg(Dev* dev, Net* net, Esp* esp, Txp* txp, char* str);

bool dissect_rx_data(Dev* dev, Net* net, Esp* esp, Txp* txp, int* state,
                     char* victim_ip, char* server_ip, bool* test_for_dissect);

uint8_t* wait(Dev* dev, Net* net, Esp* esp, Txp* txp, int* state,
              char* victim_ip, char* server_ip, bool* test_for_dissect);

void record_txp(Net* net, Esp* esp, Txp* txp);

void get_info(Dev* dev, Net* net, Esp* esp, Txp* txp, int* state,
              char* victim_ip, char* server_ip, bool* test_for_dissect);

#endif
