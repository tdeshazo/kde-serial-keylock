# kde-serial-keylock

A small Linux/KDE user-session daemon scaffold written in Go. It locks the current session whenever a trusted serial token is absent or fails authentication, and requests unlock when the token proves it knows a shared secret.

This is a scaffold, not a hardened security product. Treat it as a convenience layer on top of the normal KDE/systemd screen lock, not as a replacement for OS authentication, disk encryption, or physical security.

## Protocol

The host sends a fresh random challenge:

```text
KEYLOCK/1 <nonce_hex>
```

The token responds:

```text
HMAC-SHA256 <hex(hmac_sha256(secret, nonce_hex))>
```

The secret is never sent over the serial line.

## Requirements

- Linux with KDE Plasma.
- `go` for building.
- `stty` for serial-port configuration.
- `qdbus6`, `qdbus`, or `dbus-send` for KDE locking.
- `loginctl` for logind lock/unlock requests.
- Permission to read/write the serial device. On many distros this means adding your user to `dialout`, `uucp`, or a distro-specific serial group, then logging out and back in.

## Build

```bash
go build -o keylock ./cmd/keylock
```

## Configure

Copy the example config:

```bash
mkdir -p ~/.config/keylock
cp config.example.json ~/.config/keylock/config.json
```

Start with `dry_run: true`. Once the serial protocol works, change it to `false`.

Put the shared secret in an environment file:

```bash
cat > ~/.config/keylock/secret.env <<'EOF_SECRET'
KEYLOCK_SECRET=replace-this-with-a-long-random-secret
EOF_SECRET
chmod 600 ~/.config/keylock/secret.env
```

Generate a stronger secret with:

```bash
openssl rand -hex 32
```

## Useful commands

List candidate serial devices:

```bash
./keylock -list-ports
```

Check once:

```bash
set -a
. ~/.config/keylock/secret.env
set +a
./keylock -config ~/.config/keylock/config.json -once
```

Check once with authentication diagnostics:

```bash
set -a
. ~/.config/keylock/secret.env
set +a
./keylock -config ~/.config/keylock/config.json -once -auth-debug
```

This logs the candidate serial ports, the challenge nonce, the token response,
the expected HMAC over the ASCII nonce, and the HMAC that would be expected if a
token mistakenly used the raw nonce bytes. Treat these logs as sensitive
diagnostics because they include per-challenge HMAC values.

Ask the token to report its key hash and a fixed HMAC test vector:

```bash
set -a
. ~/.config/keylock/secret.env
set +a
./keylock -config ~/.config/keylock/config.json -token-diag -auth-debug
```

This requires firmware that supports `KEYLOCK-DIAG/1` and has
`ENABLE_DIAGNOSTICS = True`. It compares the token's `sha256(secret)` and
`hmac_sha256(secret, "KEYLOCK-TEST-NONCE")` against the host's values. If the
key hash differs, the token secret is not byte-for-byte the same as
`KEYLOCK_SECRET`. If the key hash matches but the test HMAC differs, the token
HMAC implementation is wrong.

Disable token diagnostics after troubleshooting by setting
`ENABLE_DIAGNOSTICS = False` in the firmware and reloading the board. Diagnostic
outputs are secret verifiers: with a weak secret, they can help an attacker test
guesses offline. Do not run `-auth-debug` or `-token-diag` from the systemd
service, and avoid keeping diagnostic logs longer than needed.

Run as a foreground daemon:

```bash
set -a
. ~/.config/keylock/secret.env
set +a
./keylock -config ~/.config/keylock/config.json
```

## systemd user service

```bash
mkdir -p ~/.local/bin ~/.config/systemd/user
cp keylock ~/.local/bin/keylock
cp systemd/keylock.service ~/.config/systemd/user/keylock.service
systemctl --user daemon-reload
systemctl --user enable --now keylock.service
journalctl --user -u keylock.service -f
```

## Development without hardware

Install `socat`, create two pseudo-terminals, and point the app at one while the simulator listens on the other:

```bash
socat -d -d pty,raw,echo=0 pty,raw,echo=0
```

In `config.json`, set `serial.port` to one reported pty. Then run:

```bash
KEYLOCK_SECRET=replace-this-with-a-long-random-secret ./tools/token_sim.py --debug /dev/pts/N
```

Run keylock against the other pty.

## Important limitations

- KDE exposes a public lock API, but not a reliable “unlock without credentials” API on the same surface. This scaffold requests unlock through `loginctl unlock-session`. Whether that actually unlocks the graphical locker depends on your desktop/session policy.
- If unlock is ignored, the app will still stop re-locking once the token authenticates; you can then type your normal password.
- Anyone with the token and secret can request an unlock. Protect the token firmware and secret.
- The diagnostic modes intentionally disclose secret verifiers for troubleshooting. Keep them disabled during normal operation.
- If the daemon is killed, it stops enforcing the token policy. For stronger behavior, pair it with systemd restart policies and regular OS lock settings.
