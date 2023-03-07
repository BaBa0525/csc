#ifndef _REPLAY_H
#define _REPLAY_H

#include <stdint.h>
#include <stdlib.h>

#include "constants.h"
#include "dev.h"
#include "esp.h"
#include "net.h"
#include "transport.h"

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
