# MicroPython/CircuitPython-style serial token example.
# Put this on a microcontroller that exposes a USB CDC serial port.
# Set SECRET to the same value as KEYLOCK_SECRET on the host.

import adafruit_hashlib as hashlib
import sys
import time

SECRET = b"1"
BLOCK = 64
TEST_VECTOR_MESSAGE = b"KEYLOCK-TEST-NONCE"
ENABLE_DIAGNOSTICS = False


def hmac_sha256(key, msg):
    if len(key) > BLOCK:
        key = hashlib.sha256(key).digest()
    if len(key) < BLOCK:
        key = key + (b"\x00" * (BLOCK - len(key)))
    outer = bytes([b ^ 0x5C for b in key])
    inner = bytes([b ^ 0x36 for b in key])
    return hashlib.sha256(outer + hashlib.sha256(inner + msg).digest()).hexdigest()


def write_line(line):
    sys.stdout.write(line + "\n")
    try:
        sys.stdout.flush()
    except AttributeError:
        pass


while True:
    line = sys.stdin.readline()
    if not line:
        time.sleep(0.05)
        continue
    parts = line.strip().split()
    if len(parts) == 2 and parts[0] == "KEYLOCK/1":
        nonce_hex = parts[1]
        digest = hmac_sha256(SECRET, nonce_hex.encode())
        write_line("HMAC-SHA256 {}".format(digest))
    elif len(parts) == 1 and parts[0] == "KEYLOCK-DIAG/1":
        if ENABLE_DIAGNOSTICS:
            write_line("KEY-SHA256 {}".format(hashlib.sha256(SECRET).hexdigest()))
            write_line("TEST-HMAC-SHA256 {}".format(hmac_sha256(SECRET, TEST_VECTOR_MESSAGE)))
        else:
            write_line("ERR diagnostics disabled")
