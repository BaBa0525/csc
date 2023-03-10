# Project 1: IPsec Session Hijacking

## TODO

### Initializing

- [x] Fill up struct `sockaddr_ll` addr which will be used to bind in func `set_sock_fd` (`dev.cpp:init_addr`)

### Parsing

- [x] Collect information from `pkt`. Return payload of network layer (`net.cpp:dissect`)
- [x] Collect information from `esp_pkt`. Return payload of ESP (`esp.cpp:dissect`)
- [x] Collect information from `segm` (Check IP addr & port to determine the next seq and ack value) Return payload of TCP (`transport.cpp:dissect`)

### ESP Key

- [x] Dump authentication key from security association database (SADB) (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10) (`esp.cpp:get_ik`)
- [x] Fill up `self->pad` and `self->pad_len` (Ref. RFC4303 Section 2.4) (`esp.cpp:set_padpl`)
- [x] Put everything needed to be authenticated into `buff` and add up `nb` (`esp.cpp:set_auth`)

### Checksum

- [x] Finish TCP checksum calculation (`transport.cpp:cal_tcp_cksm`)
- [x] Finish IP checksum calculation (`net.cpp:cal_ip_cksm`)

### Send Preparation

- [x] Fill up `self->tcphdr` (prepare to send) (`transport.cpp:fmt_rep`)
- [x] Fill up ESP header and trailer (prepare to send) (`esp.cpp:fmt_rep`)
- [x] Fill up `self->ip4hdr` (prepare to send) (`net.cpp:fmt_rep`)
- [x] Store the whole frame into `self->frame` and store the length of the frame into `self->framelen` (`dev.cpp:fmt_frame`)

### Call Sequence

1. `Dev::init_addr`
2. `Net::dissect`
3. `Esp::dissect`
4. `Txp::dissect`
5. `Esp::get_key` => `get_ik`
6. `Txp::fmt_rep` => `cal_tcp_cksm`
7. `Esp::fmt_rep`
8. `Esp::set_padpl`
9. `Esp::set_auth`
10. `Net::fmt_rep` => `cal_ipv4_cksm`
11. `Dev::fmt_frame`
