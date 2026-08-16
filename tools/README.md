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
```

The phases build on each other: `preflight` (tools, ssh, LoRa rail, peer on the same air
settings) → `deploy` (rsync + cmake, and `--with-unit-tests` for ctest on the target) → `daemon`
(generated `.ini`, start, wait for the SX1262, connect through the tunnel) → `companion` (the
protocol surface) → `advert_tx` / `advert_rx` (a signed advert each way, and the return path a
flood advert teaches) → `message_rx` / `message_tx` (an encrypted direct message each way, each
confirmed by the *other* node's ack) → `path` (a reset route falls back to flood and is relearned)
→ `channel` (a group message on a private channel, opt-in) → `restart` (state survives a stop and
start).

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
  asserted from the ack *it* sends, which it only sends after decrypting. The single exception is
  `--with-channel`, which writes one spare channel slot and clears it again on the way out.

The daemon log is fetched to `dist/e2e-logs/` after each run, and a run that dies half way still
stops the daemon it started — a leftover one holds the SPI bus and the GPIO lines, so the next run
would fail to open the radio at all.

## End-to-end test, no radio

`e2e_companion_test.py` drives a *running* daemon over the companion TCP socket the way the app
does, and checks the replies. To exercise the full receive path, start the daemon with a known
identity and a replay file:

```sh
# use node B's key so the canned A->B message is addressed to us
grep -o 'kPrivB = "[0-9a-f]*"' tests/packet_vectors.h | sed 's/.*"\(.*\)"/\1/' > state/identity
chmod 600 state/identity

# replay a signed advert and an encrypted message from node A
grep -o 'kAdvertPacket = "[0-9a-f]*"' tests/packet_vectors.h | sed 's/.*"\(.*\)"/\1/'  > packets.hex
grep -o 'kTextPacket   = "[0-9a-f]*"' tests/packet_vectors.h | sed 's/.*"\(.*\)"/\1/' >> packets.hex

./build/coreletd --config test.ini &   # mock_radio = 1, mock_replay_file = packets.hex
sleep 10                                 # let both packets play in
python3 tools/e2e_companion_test.py 5999
```

It asserts the advert becomes a contact, the message decrypts to its expected plaintext, and the
ack hash matches the reference vector.
