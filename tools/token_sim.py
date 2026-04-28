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
TIMER_COMMAND = "KEYLOCK-TIMER/1"
TIMER_WARNING_SECONDS = 300
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

timer = {
    "state": "unset",
    "remaining": 0,
    "persist": "ok",
    "store": "memory",
}
last_tick = time.monotonic()
timer_warning_sent = timer["remaining"] <= TIMER_WARNING_SECONDS
pending_warning = False


def timer_status():
    return timer["state"]


def timer_warning_line():
    return f"KEYLOCK-WARNING/1 remaining={timer['remaining']}\n"


def update_timer():
    global last_tick, pending_warning, timer_warning_sent
    now = time.monotonic()
    elapsed = int(now - last_tick)
    if elapsed <= 0:
        return
    last_tick = now
    if timer["state"] == "running":
        previous_remaining = timer["remaining"]
        timer["remaining"] = max(0, timer["remaining"] - elapsed)
        if (
            not timer_warning_sent
            and previous_remaining > TIMER_WARNING_SECONDS
            and 0 < timer["remaining"] <= TIMER_WARNING_SECONDS
        ):
            pending_warning = True
            timer_warning_sent = True
        if timer["remaining"] == 0:
            timer["state"] = "expired"


def timer_status_line(prefix="TIMER/1"):
    return (
        f"{prefix} state={timer_status()} remaining={timer['remaining']} "
        f"persist={timer['persist']} store={timer['store']}\n"
    )


def timer_hmac(parts):
    return hmac.new(SECRET, " ".join(parts).encode(), hashlib.sha256).hexdigest()


def handle_timer(parts):
    global timer_warning_sent
    if len(parts) == 2 and parts[1] == "STATUS":
        return timer_status_line().encode()
    if len(parts) == 4 and parts[1] == "SET":
        command_parts = parts[:3]
        try:
            seconds = int(parts[2])
        except ValueError:
            return b"ERR timer seconds must be an integer\n"
        if not hmac.compare_digest(parts[3].lower(), timer_hmac(command_parts).lower()):
            return b"ERR timer command authentication failed\n"
        timer["remaining"] = max(0, seconds)
        timer["state"] = "paused" if seconds > 0 else "unset"
        timer_warning_sent = timer["remaining"] <= TIMER_WARNING_SECONDS
        return timer_status_line("OK TIMER/1").encode()
    if len(parts) == 4 and parts[1] == "ADD":
        command_parts = parts[:3]
        try:
            seconds = int(parts[2])
        except ValueError:
            return b"ERR timer seconds must be an integer\n"
        if not hmac.compare_digest(parts[3].lower(), timer_hmac(command_parts).lower()):
            return b"ERR timer command authentication failed\n"
        update_timer()
        timer["remaining"] = timer["remaining"] + max(0, seconds)
        if timer["remaining"] > TIMER_WARNING_SECONDS:
            timer_warning_sent = False
        if timer["remaining"] > 0 and timer["state"] in {"unset", "expired"}:
            timer["state"] = "paused"
        return timer_status_line("OK TIMER/1").encode()
    if len(parts) == 3 and parts[1] in {"PAUSE", "RESUME", "LOCKED", "UNLOCKED", "CLEAR"}:
        command_parts = parts[:2]
        if not hmac.compare_digest(parts[2].lower(), timer_hmac(command_parts).lower()):
            return b"ERR timer command authentication failed\n"
        if parts[1] in {"PAUSE", "LOCKED"}:
            if timer["state"] == "running":
                timer["state"] = "paused" if timer["remaining"] > 0 else "expired"
        elif parts[1] in {"RESUME", "UNLOCKED"}:
            if timer["remaining"] > 0 and timer["state"] != "expired":
                timer["state"] = "running"
        elif parts[1] == "CLEAR":
            timer["remaining"] = 0
            timer["state"] = "unset"
            timer_warning_sent = True
        return timer_status_line("OK TIMER/1").encode()
    return b"ERR unsupported timer command\n"


with open(path, "r+b", buffering=0) as f:
    while True:
        update_timer()
        if pending_warning:
            f.write(timer_warning_line().encode())
            pending_warning = False
        line = f.readline().decode(errors="replace").strip()
        if not line:
            time.sleep(0.05)
            continue
        parts = line.split()
        if len(parts) == 2 and parts[0] == "KEYLOCK/1":
            if timer["state"] == "expired":
                f.write(b"ERR timer expired\n")
                continue
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
        elif parts and parts[0] == TIMER_COMMAND:
            f.write(handle_timer(parts))
