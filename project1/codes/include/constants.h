#ifndef _CONSTANTS_H
#define _CONSTANTS_H

#ifndef IP_MAXPACKET
#include <netinet/ip.h>
#endif

#define HMAC96AUTHLEN 12

/* Authentication data length of HMAC-SHA1-96 is 96 bits */
#define MAXESPPADLEN 3
#define MAXESPPLEN \
    IP_MAXPACKET - sizeof(EspHeader) - sizeof(EspTrailer) - HMAC96AUTHLEN

#define WAIT_PKT 0
#define WAIT_SECRET 1
#define SEND_ACK 2

#define LINKHDRLEN 14

#define ENA_TCP_ACK true
#define DISABLE_TCP_ACK false

#define MAXBUFCOUNT 8

#define BUFSIZE 65535

#endif
