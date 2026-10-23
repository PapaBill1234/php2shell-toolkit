#!/usr/bin/env python3
"""proxy_local.py - local HTTP CONNECT forwarder with upstream proxy auth.

Chrome cannot take proxy credentials on the command line, so point Chrome at
this (http://127.0.0.1:8899) and it authenticates upstream for us.

  UPSTREAM=YOUR_PROXY_HOST:PORT UP_USER=YOUR_USER UP_PASS=YOUR_PASS python3 proxy_local.py
"""
import base64
import os
import select
import socket
import sys
import threading

LISTEN = int(os.environ.get("LOCAL_PORT", "8899"))
UP = os.environ["UPSTREAM"]                    # host:port
UH, UPORT = UP.split(":")
AUTH = base64.b64encode(("%s:%s" % (os.environ["UP_USER"], os.environ["UP_PASS"])).encode()).decode()


def pipe(a, b):
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 60)
            if not r:
                break
            for s in r:
                d = s.recv(65536)
                if not d:
                    return
                (b if s is a else a).sendall(d)
    except OSError:
        pass
    finally:
        a.close(); b.close()


def handle(cli):
    try:
        head = b""
        while b"\r\n\r\n" not in head:
            d = cli.recv(4096)
            if not d:
                return cli.close()
            head += d
        first, _, rest = head.partition(b"\r\n")
        method, target, ver = first.split()
        up = socket.create_connection((UH, UPORT), timeout=30)
        if method == b"CONNECT":
            up.sendall(("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n"
                        % (target.decode(), target.decode(), AUTH)).encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                d = up.recv(4096)
                if not d:
                    return cli.close()
                resp += d
            cli.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n" if resp.startswith(b"HTTP/1.1 200") else resp)
        else:
            up.sendall(("%s %s %s\r\nProxy-Authorization: Basic %s\r\n" %
                        (method.decode(), target.decode(), ver.decode(), AUTH)).encode() + rest)
        if rest and method == b"CONNECT":
            pass
        pipe(cli, up)
    except Exception:
        try:
            cli.close()
        except OSError:
            pass


def main():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", LISTEN))
    s.listen(64)
    print("local proxy on 127.0.0.1:%d -> %s" % (LISTEN, UP), flush=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
