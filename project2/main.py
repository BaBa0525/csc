import netifaces
from scapy.all import ARP, Ether, srp

def scan():
    interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    ip_address = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    network = ip_address + "/24"

    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=False)[0]
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

def arp_request(ip: str):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff::ff::ff::ff::ff::ff")
    req = ether / arp
    res = srp(req, timeout=3, verbose=False)[0]
    print(res)


def main():
    arp_request("10.0.3.7")


if __name__ == "__main__":

    main()