# Screen Time MVP

This is an additive, minimal screen-time management scaffold built alongside the
existing serial keylock tools. It is not a hardened security product. It is meant
to coordinate user time allowance across devices and ask each local KDE/Linux
agent to lock when that user's time expires.

## Concept

The coordinator owns user allowance state. Each device runs an agent that:

1. queries the local session lock state,
2. reports that state to the coordinator, and
3. locks the local session when the coordinator says the user's allowance is
   expired.

The timer runs when at least one recently-reporting device for a user is
unlocked. This avoids double-counting if the same user has multiple devices
unlocked at once.

## Build

```bash
make build
```

This builds the existing serial tools plus:

```text
bin/screentime-coordinator
bin/screentime-agent
bin/screentime
```

## Start the coordinator

```bash
./bin/screentime-coordinator \
  -addr 127.0.0.1:8787 \
  -state screen-time-state.json
```

The coordinator stores JSON state in the file supplied with `-state`.

## Set or add time

```bash
./bin/screentime set griffin 2h
./bin/screentime add griffin 30m
./bin/screentime status griffin
./bin/screentime state
```

Durations accept raw seconds or Go-style durations such as `30m`, `1h`, or
`1h30m`.

## Run a local agent

Start dry-run first:

```bash
./bin/screentime-agent \
  -coordinator http://127.0.0.1:8787 \
  -device living-room-pc \
  -user griffin \
  -dry-run=true
```

Once behavior is understood, `-dry-run=false` allows the configured locker
backend to request a real lock.

## Offline behavior

If the coordinator cannot be reached, the agent keeps the previous state for
`-offline-grace` and then requests a local lock. This is intentionally simple and
conservative for the MVP.

## API sketch

```text
GET  /v1/health
GET  /v1/state
GET  /v1/users/{user_id}/status
POST /v1/users/{user_id}/allowance/set
POST /v1/users/{user_id}/allowance/add
POST /v1/users/{user_id}/allowance/clear
POST /v1/devices/{device_id}/state
GET  /v1/devices/{device_id}/policy
```

The serial token code remains untouched and can be treated as a separate backend
or future presence signal.
