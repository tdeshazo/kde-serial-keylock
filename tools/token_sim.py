#!/usr/bin/env python3
"""
A tiny serial-token simulator for development.

Usage:
  1. Create a pair of virtual serial ports with socat, e.g.
       socat -d -d pty,raw,echo=0 pty,raw,echo=0
  2. Put one pty path in keylock config.json as serial.port.
  3. Run this script against the other pty:
       KEYLOCK_SECRET='change me' ./tools/token_sim.py /dev/pts/7
"""
import hashlib
import hmac
import os
import sys
import time

SECRET = os.environ.get("KEYLOCK_SECRET", "").encode()
TEST_VECTOR_MESSAGE = b"KEYLOCK-TEST-NONCE"
if not SECRET:
    raise SystemExit("KEYLOCK_SECRET is empty")
debug = False
args = sys.argv[1:]
if "--debug" in args:
    debug = True
    args.remove("--debug")
if len(args) != 1:
    raise SystemExit("usage: token_sim.py [--debug] /dev/tty-or-pty")

path = args[0]
if debug:
    key_hash = hashlib.sha256(SECRET).hexdigest()
    print(f"token_sim: key hash: sha256={key_hash}", file=sys.stderr)

with open(path, "r+b", buffering=0) as f:
    while True:
        line = f.readline().decode(errors="replace").strip()
        if not line:
            time.sleep(0.05)
            continue
        parts = line.split()
        if len(parts) == 2 and parts[0] == "KEYLOCK/1":
            nonce_hex = parts[1]
            digest = hmac.new(SECRET, nonce_hex.encode(), hashlib.sha256).hexdigest()
            if debug:
                print(
                    f"token_sim: nonce_hex={nonce_hex} response_hmac={digest}",
                    file=sys.stderr,
                )
            f.write(f"HMAC-SHA256 {digest}\n".encode())
        elif len(parts) == 1 and parts[0] == "KEYLOCK-DIAG/1":
            key_hash = hashlib.sha256(SECRET).hexdigest()
            test_mac = hmac.new(SECRET, TEST_VECTOR_MESSAGE, hashlib.sha256).hexdigest()
            if debug:
                print(
                    f"token_sim: diagnostic key_hash={key_hash} test_hmac={test_mac}",
                    file=sys.stderr,
                )
            f.write(f"KEY-SHA256 {key_hash}\n".encode())
            f.write(f"TEST-HMAC-SHA256 {test_mac}\n".encode())
