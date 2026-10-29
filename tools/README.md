# tools

Development helpers. None of these are needed to build or run the daemon.

## Debian package

`build-deb.sh` wraps `dpkg-buildpackage` and drops the result in `dist/`. Run it on the uConsole
for a native build, or `--docker [arch]` (default `arm64`) to build in a `debian:trixie` container
from any machine with Docker — emulated, so it takes a while. The packaging itself lives in
`debian/`.

## Reference vectors

`tests/vectors.h` and `tests/packet_vectors.h` are frozen fixtures, committed to the repo. They
were produced by an independently written implementation of the same protocol, which is what makes
the crypto and codec tests evidence of wire compatibility rather than self-consistency. Treat them
as ground truth: if the protocol changes, the new bytes have to be sourced from another
implementation again, not adjusted to match ours.

## meshcore-cli compatibility

`cli_compat_test.py` runs [`meshcore-cli`](https://github.com/fdlamotte/meshcore-cli) against the
daemon with no hardware at all. It drives `build/coreletd_sim`: the whole daemon, wired exactly as
`main()` wires it and serving TCP, with the radio replaced by a simulated air that one scripted
MeshCore peer is on. The peer decrypts what the daemon transmits, acks its messages, and sends
adverts, messages and returned paths when told to.

```
    meshcore-cli ──TCP──▶ coreletd_sim ┄┄ simulated air ┄┄ scripted MeshCore peer
```

Every check asserts on both ends: what the client printed and what the peer decoded off the air.
A message typed into the client has to reach the peer with the same text, the peer's ack has to
come back as a delivery receipt, and the peer's messages have to come out of the client's inbox
intact — waiting ones, and one pushed while the client listens. Contacts, routes, channels,
adverts, the contact card, the clock, the settings an app may change — name, position, TX power,
radio parameters, and the repeat frequencies it may not — and the commands the daemon refuses are
covered too.

```sh
cmake --build build                       # builds coreletd_sim with the tests
tools/cli_compat_test.py                  # meshcore-cli from PATH
tools/cli_compat_test.py --meshcli ~/venv/bin/meshcli --verbose
tools/cli_compat_test.py --keep           # keep the daemon log and state
```

It takes under a minute. meshcore-cli runs with `HOME` pointed at a scratch directory, so the init scripts and message log in its
`~/.config/meshcore` are neither run nor written. What this proves is the companion protocol as
that client speaks it; whether real firmware accepts our packets is the next section's question.

## Hardware end-to-end test

`hw_e2e_test.py` is the one that needs no simulation: it deploys the working tree to a uConsole,
runs the daemon on the real SX1262, and asserts against a second, independent MeshCore node — a
T-Echo running the stock firmware — with packets going between them over the air.

```
    this Mac ──ssh──▶ uConsole ──SX1262──▶ ))) 869 MHz ((( ◀──SX1262── T-Echo
        │   (deploy, build, run, tunnel)                                  │
        ├── meshcore-cli ──TCP through the tunnel──▶ coreletd             │
        └── meshcore-cli ──BLE────────────────────────────────────────────┘
```

Both ends are driven with [`meshcore-cli`](https://github.com/fdlamotte/meshcore-cli)
(`pipx install meshcore-cli`), which is a client of the same companion protocol the phone app
uses. Nothing in the script reaches inside coreletd, so what it proves is the part no unit test
can: that the driver keys the radio, that our packets are ones somebody else's firmware accepts,
and that theirs are ones we accept.

The uConsole has to be named — it is somebody's machine, and running the wrong one is not a
mistake to make quietly — but `CORELETD_E2E_HOST` covers a bench you use often. The peer is
whichever MeshCore radio answers over BLE first, which is right when there is one on the desk;
`--peer <name>` picks a particular one when there is not.

```sh
tools/hw_e2e_test.py --host uconsole.local          # the full sweep
export CORELETD_E2E_HOST=uconsole.local             # ... or say it once

tools/hw_e2e_test.py --skip deploy        # reuse the build already on the target
tools/hw_e2e_test.py --only message_tx    # one phase; prerequisites still run
tools/hw_e2e_test.py --list               # what the phases are
tools/hw_e2e_test.py --keep-running       # leave the daemon and tunnel up to poke at
tools/hw_e2e_test.py --with-relay         # also relay through coreletd (see below)
```

The phases build on each other: `preflight` (tools, ssh, LoRa rail, peer on the same air
settings) → `deploy` (rsync + cmake, and `--with-unit-tests` for ctest on the target) → `daemon`
(a generated `.ini`, and the radio preset and name written into the state directory's `settings`
as an app would leave them; start, wait for the SX1262, connect through the tunnel) → `companion` (the
protocol surface) → `advert_tx` / `advert_rx` (a signed advert each way, and no route taken
from the one we receive) → `message_rx` / `message_tx` (an encrypted direct message each way, each
confirmed by the *other* node's ack; the peer's is sent once flooded and once direct, with the
`PATH` exchange between them that gives each node its route to the other) → `path` (a reset route
falls back to flood and is relearned from the reply) → `settings` (the coding rate changed over the
companion socket and put back, the SX1262 retuned for each, then a message each way) → `relay`
(opt-in, below) → `channel` (a group message on a private channel, opt-in) → `restart` (state
survives a stop and start).

Each phase establishes what it needs rather than assuming an earlier one ran, so `--only` works on
any of them. That matters more than it sounds: contacts and channels are wiped at the start of
every run, and until the two nodes have each other's adverts neither can derive a shared secret —
a message to a peer that has never heard of you is undecryptable, which on the air is
indistinguishable from a radio that never transmitted.

The node's *identity* is the one piece of state kept between runs, deliberately. A key minted per
run leaves a dead contact behind on every peer that hears the advert, and MeshCore contact tables
fill up — a busy T-Echo sits at its 350-contact limit already. Keeping the key means the peer's
contact for the test node is refreshed rather than duplicated, so `advert_tx` asserts that the
advert *timestamp moved forward* rather than that a contact appeared.

The remaining defaults — 869.618 MHz, the AIO v2's SPI pins, the command that powers its LoRa
rail — describe the hardware rather than any particular unit, and every one is a flag; see
`--help`. Two things are worth knowing before running it against your own:

- **The air settings must match the peer exactly.** A mismatch is silence, not an error, so
  `preflight` reads them off the peer and compares.
- **The peer's own state is left alone.** Its message queue is never drained: delivery to it is
  asserted from the ack *it* sends, which it only sends after decrypting. Two exceptions: its route
  to the test node is forgotten before the peer sends to us, because a kept identity means the peer
  would otherwise go on using the route from the first run ever and the flood exchange would never
  be tested again — the exchange then teaches it the route back; and `--with-channel` writes one
  spare channel slot and clears it again on the way out.

### Relaying

A relay needs a third node, and the bench has two radios. What makes two enough is that MeshCore
hands its app every frame the radio hears, before it deduplicates, so the peer hears its own packets
come back when coreletd relays them, with the path showing what was done to them. Reading that
needs the raw receive log and a direct packet sent down a path of the script's choosing, neither of
which meshcore-cli has a command for; the `relay` phase gets both from the `meshcore` library that
meshcore-cli is built on, run in meshcore-cli's own interpreter.

The phase has the peer send the same five packets with repeat off and then on: a flood advert, a
raw packet routed through coreletd, one routed past it, and a trace through it with one- and
two-byte hashes. With repeat off nothing may come back; with it on the advert must come back with
our hash appended, the routed packet with our hop popped, the traces with our SNR reading, and the
packet routed past us not at all. A message for us must then be answered with our `PATH` and not
repeated.

It is opt-in (`--with-relay`) because for its minute or so coreletd relays every stranger's flood
in range, and puts itself on the routes their peers build. It turns repeat off again before it
returns, failed or not.

The daemon log is fetched to `dist/e2e-logs/` after each run, and a run that dies half way still
stops the daemon it started — a leftover one holds the SPI bus and the GPIO lines, so the next run
would fail to open the radio at all.
