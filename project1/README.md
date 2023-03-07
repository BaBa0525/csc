# Project 1: IPsec Session Hijacking

## TODO

- [ ] `dev.c`

  - [ ] Fill up struct `sockaddr_ll` addr which will be used to bind in func `set_sock_fd`
  - [ ] Store the whole frame into `self->frame` and store the length of the frame into `self->framelen`

- [ ] `esp.c`

  - [ ] Dump authentication key from security association database (SADB) (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10)
  - [ ] Fiill up `self->pad` and `self->pad_len` (Ref. RFC4303 Section 2.4)
  - [ ] Put everything needed to be authenticated into `buff` and add up `nb`
  - [ ] Collect information from `esp_pkt`. Return payload of ESP
  - [ ] Fill up ESP header and trailer (prepare to send)

- [ ] `net.c`

  - [ ] Finish IP checksum calculation
  - [ ] Collect information from `pkt`. Return payload of network layer
  - [ ] Fill up `self->ip4hdr` (prepare to send)

- [ ] `transport.c`

  - [ ] Finish TCP checksum calculation
  - [ ] Collect information from `segm` (Check IP addr & port to determine the next seq and ack value) Return payload of TCP
  - [ ] Fill up `self->tcphdr` (prepare to send)
