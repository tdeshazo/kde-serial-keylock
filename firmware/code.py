# MicroPython/CircuitPython-style serial token example.
# Put this on a microcontroller that exposes a USB CDC serial port.
# Set SECRET to the same value as KEYLOCK_SECRET on the host.

import adafruit_hashlib as hashlib
import json
import sys
import time

try:
    import microcontroller
except ImportError:
    microcontroller = None

try:
    import supervisor
except ImportError:
    supervisor = None

SECRET = b"1"
BLOCK = 64
TEST_VECTOR_MESSAGE = b"KEYLOCK-TEST-NONCE"
ENABLE_DIAGNOSTICS = False

TIMER_STATE_PATH = "/timer_state.json"
TIMER_CHECKPOINT_SECONDS = 60
TIMER_SIGNAL_INTERVAL_SECONDS = 5
TIMER_WARNING_SECONDS = 300
NVM_MAGIC = b"KLT1"
NVM_RECORD_LEN = 10
STATE_CODES = {
    "unset": 0,
    "running": 1,
    "paused": 2,
    "expired": 3,
}
CODE_STATES = ("unset", "running", "paused", "expired")


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


def monotonic_seconds():
    return int(time.monotonic())


def default_timer_state():
    return {
        "state": "unset",
        "remaining": 0,
    }


def checksum(data):
    total = 0
    for b in data:
        total = (total + b) & 0xFF
    return total


def int_to_u32(value):
    value = max(0, min(0xFFFFFFFF, int(value)))
    return bytes(
        [
            (value >> 24) & 0xFF,
            (value >> 16) & 0xFF,
            (value >> 8) & 0xFF,
            value & 0xFF,
        ]
    )


def u32_from_bytes(data):
    return (
        (data[0] << 24)
        | (data[1] << 16)
        | (data[2] << 8)
        | data[3]
    )


def normalize_timer_state(state):
    remaining = max(0, int(state.get("remaining", 0)))
    current = state.get("state", "")
    if current not in ("unset", "running", "paused", "expired"):
        if bool(state.get("expired", False)):
            current = "expired"
        elif bool(state.get("running", False)):
            current = "running"
        elif remaining > 0:
            current = "paused"
        else:
            current = "unset"
    if current == "unset":
        remaining = 0
    return {
        "state": current,
        "remaining": remaining,
    }


def nvm_store():
    if microcontroller is None:
        return None
    try:
        nvm = microcontroller.nvm
        if nvm is not None and len(nvm) >= NVM_RECORD_LEN:
            return nvm
    except (AttributeError, TypeError):
        pass
    return None


def encode_timer_state(state):
    state = normalize_timer_state(state)
    payload = (
        NVM_MAGIC
        + bytes([STATE_CODES.get(state["state"], 0)])
        + int_to_u32(state["remaining"])
    )
    return payload + bytes([checksum(payload)])


def decode_timer_state(data):
    data = bytes(data[:NVM_RECORD_LEN])
    if len(data) != NVM_RECORD_LEN:
        return None
    payload = data[:-1]
    if payload[:4] != NVM_MAGIC:
        return None
    if checksum(payload) != data[-1]:
        return None
    code = payload[4]
    if code >= len(CODE_STATES):
        return None
    return normalize_timer_state(
        {
            "state": CODE_STATES[code],
            "remaining": u32_from_bytes(payload[5:9]),
        }
    )


def load_timer_state_from_nvm():
    nvm = nvm_store()
    if nvm is None:
        return None
    try:
        return decode_timer_state(nvm[:NVM_RECORD_LEN])
    except (OSError, ValueError):
        return None


def save_timer_state_to_nvm():
    nvm = nvm_store()
    if nvm is None:
        return False
    try:
        nvm[:NVM_RECORD_LEN] = encode_timer_state(timer_state)
        return True
    except (OSError, ValueError, TypeError):
        return False


def load_timer_state_from_file():
    try:
        with open(TIMER_STATE_PATH, "r") as f:
            state = json.loads(f.read())
    except (OSError, ValueError):
        return None
    return normalize_timer_state(state)


def save_timer_state_to_file():
    try:
        with open(TIMER_STATE_PATH, "w") as f:
            f.write(json.dumps(normalize_timer_state(timer_state)))
        return True
    except OSError:
        return False


def load_timer_state():
    state = load_timer_state_from_nvm()
    if state is not None:
        return state
    state = load_timer_state_from_file()
    if state is not None:
        return state
    return default_timer_state()


def persist_timer_state():
    if save_timer_state_to_nvm():
        return "nvm"
    if save_timer_state_to_file():
        return "file"
    return "none"


def save_timer_state():
    global last_persist_ok, last_persist_backend
    backend = persist_timer_state()
    last_persist_ok = backend != "none"
    last_persist_backend = backend
    return last_persist_ok


timer_state = load_timer_state()
last_tick = monotonic_seconds()
last_checkpoint = last_tick
last_expired_signal = 0
timer_warning_sent = timer_state["remaining"] <= TIMER_WARNING_SECONDS
timer_warning_pending = False
last_persist_backend = persist_timer_state()
last_persist_ok = last_persist_backend != "none"
serial_buffer = ""


def timer_status():
    return timer_state["state"]


def write_timer_warning():
    write_line("KEYLOCK-WARNING/1 remaining={}".format(timer_state["remaining"]))


def write_pending_timer_warning():
    global timer_warning_pending
    if timer_warning_pending:
        write_timer_warning()
        timer_warning_pending = False


def update_timer():
    global last_tick, last_checkpoint, last_expired_signal, timer_warning_sent, timer_warning_pending

    now = monotonic_seconds()
    elapsed = now - last_tick
    last_tick = now

    if timer_state["state"] == "running" and elapsed > 0:
        previous_remaining = timer_state["remaining"]
        timer_state["remaining"] = max(0, timer_state["remaining"] - elapsed)
        if (
            not timer_warning_sent
            and previous_remaining > TIMER_WARNING_SECONDS
            and 0 < timer_state["remaining"] <= TIMER_WARNING_SECONDS
        ):
            timer_warning_pending = True
            timer_warning_sent = True
        if timer_state["remaining"] == 0:
            timer_state["state"] = "expired"
            save_timer_state()
            last_checkpoint = now

    if timer_state["state"] == "running" and now - last_checkpoint >= TIMER_CHECKPOINT_SECONDS:
        save_timer_state()
        last_checkpoint = now

    if timer_state["state"] == "expired" and now - last_expired_signal >= TIMER_SIGNAL_INTERVAL_SECONDS:
        write_line("KEYLOCK-EXPIRED/1")
        last_expired_signal = now


def set_timer(seconds):
    global last_tick, last_checkpoint, timer_warning_sent, timer_warning_pending
    seconds = max(0, int(seconds))
    timer_state["remaining"] = seconds
    timer_state["state"] = "paused" if seconds > 0 else "unset"
    timer_warning_sent = seconds <= TIMER_WARNING_SECONDS
    timer_warning_pending = False
    last_tick = monotonic_seconds()
    last_checkpoint = last_tick
    save_timer_state()


def add_timer(seconds):
    global last_tick, last_checkpoint, timer_warning_sent, timer_warning_pending
    update_timer()
    seconds = max(0, int(seconds))
    timer_state["remaining"] = timer_state["remaining"] + seconds
    timer_warning_pending = False
    if timer_state["remaining"] > TIMER_WARNING_SECONDS:
        timer_warning_sent = False
    else:
        timer_warning_sent = True
    if timer_state["remaining"] > 0 and timer_state["state"] in ("unset", "expired"):
        timer_state["state"] = "paused"
        last_tick = monotonic_seconds()
        last_checkpoint = last_tick
    save_timer_state()


def pause_timer():
    update_timer()
    if timer_state["state"] == "running":
        timer_state["state"] = "paused" if timer_state["remaining"] > 0 else "expired"
    save_timer_state()


def resume_timer():
    global last_tick
    if timer_state["remaining"] > 0 and timer_state["state"] != "expired":
        timer_state["state"] = "running"
        last_tick = monotonic_seconds()
    save_timer_state()


def clear_timer():
    global timer_warning_sent, timer_warning_pending
    timer_state["remaining"] = 0
    timer_state["state"] = "unset"
    timer_warning_sent = True
    timer_warning_pending = False
    save_timer_state()


def write_timer_status(prefix="TIMER/1"):
    persist = "ok" if last_persist_ok else "failed"
    write_line(
        "{} state={} remaining={} persist={} store={}".format(
            prefix,
            timer_status(),
            timer_state["remaining"],
            persist,
            last_persist_backend,
        )
    )


def verify_timer_mac(command_parts, mac_hex):
    expected = hmac_sha256(SECRET, " ".join(command_parts).encode())
    got = mac_hex.lower()
    want = expected.lower()
    if len(got) != len(want):
        return False
    diff = 0
    for i in range(len(want)):
        diff |= ord(got[i]) ^ ord(want[i])
    return diff == 0


def handle_timer_command(parts):
    if len(parts) == 2 and parts[1] == "STATUS":
        write_timer_status()
        return

    if len(parts) == 4 and parts[1] == "SET":
        try:
            seconds = int(parts[2])
        except ValueError:
            write_line("ERR timer seconds must be an integer")
            return
        if not verify_timer_mac(parts[:3], parts[3]):
            write_line("ERR timer command authentication failed")
            return
        set_timer(seconds)
        write_timer_status("OK TIMER/1")
    elif len(parts) == 4 and parts[1] == "ADD":
        try:
            seconds = int(parts[2])
        except ValueError:
            write_line("ERR timer seconds must be an integer")
            return
        if not verify_timer_mac(parts[:3], parts[3]):
            write_line("ERR timer command authentication failed")
            return
        add_timer(seconds)
        write_timer_status("OK TIMER/1")
    elif len(parts) == 3 and parts[1] in ("PAUSE", "RESUME", "LOCKED", "UNLOCKED", "CLEAR"):
        if not verify_timer_mac(parts[:2], parts[2]):
            write_line("ERR timer command authentication failed")
            return
        command = parts[1]
        if command == "PAUSE":
            pause_timer()
        elif command == "RESUME":
            resume_timer()
        elif command == "LOCKED":
            pause_timer()
        elif command == "UNLOCKED":
            resume_timer()
        elif command == "CLEAR":
            clear_timer()
        write_timer_status("OK TIMER/1")
    else:
        write_line("ERR unsupported timer command")


def handle_line(line):
    parts = line.strip().split()
    if not parts:
        return

    write_pending_timer_warning()

    if len(parts) == 2 and parts[0] == "KEYLOCK/1":
        if timer_state["state"] == "expired":
            write_line("ERR timer expired")
            return
        nonce_hex = parts[1]
        digest = hmac_sha256(SECRET, nonce_hex.encode())
        write_line("HMAC-SHA256 {}".format(digest))
    elif len(parts) == 1 and parts[0] == "KEYLOCK-DIAG/1":
        if ENABLE_DIAGNOSTICS:
            write_line("KEY-SHA256 {}".format(hashlib.sha256(SECRET).hexdigest()))
            write_line("TEST-HMAC-SHA256 {}".format(hmac_sha256(SECRET, TEST_VECTOR_MESSAGE)))
        else:
            write_line("ERR diagnostics disabled")
    elif parts[0] == "KEYLOCK-TIMER/1":
        handle_timer_command(parts)


def read_available_serial():
    global serial_buffer
    if supervisor is None:
        line = sys.stdin.readline()
        if line:
            handle_line(line)
        return

    while supervisor.runtime.serial_bytes_available:
        char = sys.stdin.read(1)
        if char in ("\n", "\r"):
            line = serial_buffer
            serial_buffer = ""
            handle_line(line)
        else:
            serial_buffer += char


while True:
    update_timer()
    read_available_serial()
    time.sleep(0.05)
