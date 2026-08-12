# umeshcore

A MeshCore daemon for the [ClockworkPi uConsole](https://www.clockworkpi.com/uconsole) with the
[HackerGadgets / OpenSourceSDRLab AIO v2](https://hackergadgets.com/products/uconsole-aio-v2)
expansion board.

It drives the board's SX1262 directly over `spidev` + `libgpiod`, speaks the MeshCore mesh
protocol, and exposes the **companion protocol over TCP** so the MeshCore phone/web app,
[`meshcore-cli`](https://github.com/meshcore-dev/meshcore_py) and `meshtui` can connect — including
from the uConsole itself over loopback.

Clean-room C++20. No Arduino shim, no PlatformIO, no RadioLib: `cmake && make`, one static binary,
one systemd unit.

## Status

| Area | State |
|------|-------|
| Crypto (Ed25519 / X25519 / AES-ECB+HMAC) | Working, validated against a reference implementation |
| Packet + payload codec | Working, validated against a reference implementation |
| Advert send/receive, contact store | Working |
| Direct messages, acks, retries, path learning | Working |
| Channel (group) messages | Working |
| Companion protocol over TCP | Working |
| SX1262 driver | Working on real hardware (uConsole CM4 + AIO v2) |
| Repeater / room server roles | Not implemented (out of scope) |
| BLE and USB-serial companion transports | Not implemented (TCP only) |

Validated on a uConsole (CM4, Debian trixie) with an AIO v2, against a LilyGo T-Echo running
MeshCore v1.17.0 on 869.618 MHz:

- adverts received and signature-verified (RSSI −41, SNR 12.2)
- public channel messages sent and received by the T-Echo
- direct encrypted messages both ways, decrypted correctly at each end
- acks matched, confirming the ack-hash construction agrees with real firmware
- meshcore-cli driving the daemon over TCP from another machine

`--verbose` traces every SPI command and IRQ if you need to debug a different board.

> **Note on `XOSC_START_ERR` (device error `0x0020`):** the SX1262 latches this at power-up because
> it tries to start its oscillator before DIO3 is configured to drive the TCXO. It is cleared after
> calibration and is not a fault. If it is still reported after that, `lora_tcxo` genuinely does not
> match your board.

## Building

On the uConsole (Raspberry Pi OS / Debian):

```sh
sudo apt install build-essential cmake pkg-config libsodium-dev libssl-dev libgpiod-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j4
ctest --test-dir build --output-on-failure
```

`libgpiod` must be **2.0 or newer** (Debian trixie and Raspberry Pi OS 2025+ ship this; on older
bookworm images you will get 1.6 and CMake will stop with an explanatory error).

The SX1262 backend is built automatically on Linux. On macOS or any box without libgpiod it is
skipped and only the mock radio is available, which is enough to develop and run the whole daemon.

### Debian package

Packaging lives in `debian/`, so on the uConsole you can build a `.deb` instead of installing by
hand:

```sh
sudo apt install build-essential debhelper cmake pkgconf libsodium-dev libssl-dev libgpiod-dev
tools/build-deb.sh                  # -> dist/umeshcore_0.1.0_arm64.deb
sudo apt install ./dist/umeshcore_0.1.0_arm64.deb
```

From a non-Debian machine, `tools/build-deb.sh --docker` builds the same package for arm64 in a
`debian:trixie` container (emulated, so expect it to be slow).

The package installs the daemon, the udev rules and the systemd unit, and creates the `umeshcore`
user and `meshcore` group for you. It deliberately **does not enable or start the service** — the
frequency is a legal question and an unfitted antenna is a hardware one, so review
`/etc/umeshcore/umeshcored.ini` and then `systemctl enable --now umeshcored`. Upgrades restart the
daemon if you enabled it. `/usr/share/doc/umeshcore/README.Debian` covers the rest, including why
purging leaves your node identity in `/var/lib/umeshcore` alone.

## Hardware setup

The AIO v2 puts the SX1262 on **SPI1** with chip select on **SPI1-CE0 (GPIO18)**, DIO1 on
**GPIO26**, BUSY on **GPIO24**, RESET on **GPIO25**. DIO2 drives the RF switch and DIO3 powers the
TCXO at 1.8 V.

**1. Enable SPI.** Add to `/boot/firmware/config.txt` and reboot:

```
dtparam=spi=on
dtoverlay=spi1-1cs
```

Confirm `/dev/spidev1.0` exists afterwards.

**2. The LoRa power rail.** The AIO v2 gates power to each subsystem behind a GPIO. **GPIO16 must be
driven high or the SX1262 is unpowered** and every SPI read returns zeroes — the single most likely
cause of a "radio not responding" report. For reference the others are GPS=27, SDR=7, internal
USB=23.

The daemon does not switch the rail: it is shared board-level state, and whatever manages the
uConsole's power owns it. On an AIO v2, use the board utility:

```sh
aiov2_ctl lora on
```

If that utility is unavailable, `gpioset -c gpiochip0 16=1` is the manual fallback. The kernel
reverts a GPIO to its default when the last process holding it exits, so keep `gpioset` running;
libgpiod 2.x does that by default.

Nothing breaks if you do it late. An SX1262 that does not answer is not a startup failure — the
daemon comes up without a radio, retries every `lora_retry_interval` seconds (default 10), and
starts receiving as soon as the chip appears. The same check runs while the radio is up, so cutting
the rail mid-session logs a warning, holds the transmit queue, and reconnects once power is back.

**3. Fit an antenna before transmitting.** Running a 22 dBm PA into an open connector will damage it.

**4. Device access without root:**

```sh
sudo groupadd -f -r meshcore
sudo install -m 644 etc/99-umeshcore.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
ls -l /dev/spidev1.0 /dev/gpiochip0     # -> crw-rw---- root meshcore
```

If `meshtasticd` is installed, stop and disable it — it will hold the same GPIO lines and the
daemon will fail with `EBUSY`.

## Configuring

```sh
sudo install -D -m 644 etc/umeshcored.ini /etc/umeshcore/umeshcored.ini
sudo nano /etc/umeshcore/umeshcored.ini
```

`lora_freq` is **required and has no default** — which band you may transmit on is a legal question,
not a technical one. Set the plan for your region (`869.618` for EU868, `910.525` for US915) and
make sure every node on your mesh shares the same `lora_bw` / `lora_sf` / `lora_cr`.

`etc/umeshcored.ini` documents every option.

## Running

```sh
# foreground, with the config in this repo
./build/umeshcored --config etc/umeshcored.ini --verbose

# as a service
sudo install -m 755 build/umeshcored /usr/sbin/umeshcored
sudo install -m 644 etc/umeshcored.service /etc/systemd/system/
sudo useradd -r -g meshcore -s /usr/sbin/nologin umeshcore
sudo systemctl daemon-reload && sudo systemctl enable --now umeshcored
journalctl -u umeshcored -f
```

Then point a client at `127.0.0.1:5000`, e.g. `meshcore-cli -t 127.0.0.1:5000`.

On first run the daemon generates an Ed25519 identity and writes it to
`/var/lib/umeshcore/identity` (mode 0600). **That file is your node** — back it up; deleting it
gives you a new public key and every contact will see you as a stranger.

### Security

The companion protocol has **no authentication at all**. Anyone who can reach the port can read your
messages and send as you, so `companion_bind` defaults to `127.0.0.1`. Only widen it to `0.0.0.0` on
a network you control, ideally behind an SSH tunnel or WireGuard.

### Running without hardware

Set `mock_radio = 1` to bring the whole daemon up with a fake radio — transmissions are logged and
discarded, and `mock_replay_file` replays a file of hex packets (one per line, `#` comments allowed)
into the receive path. This is how the end-to-end test below works.

## Layout

```
src/
  util/       bytes, hex, INI, logging, clock
  crypto/     Ed25519 (expanded-key), X25519, AES-128-ECB + HMAC, identity
  proto/      packet header/path codec, payload codecs
  radio/      Radio interface, duty cycle, mock radio, SX1262 (spidev + libgpiod)
  mesh/       dispatcher (dedup, priority TX queue), contacts, channels, node
  companion/  frame codec, TCP server, command session
  daemon/     config, poll() event loop, wiring
tests/        unit tests + generated reference vectors
```

Everything runs on a single thread in one `poll()` loop, so there is no locking anywhere in the
codebase. Callbacks must not block.

## Protocol notes

Details that cost time to rediscover:

- **The private key is not a normal Ed25519 key.** MeshCore stores the *expanded* 64-byte
  SHA-512(seed) as `(a, RH)` and throws the seed away. No standard signing API accepts that, so
  `crypto/identity.cpp` assembles signatures from libsodium's scalar primitives. libsodium's
  clamping happens to match MeshCore's hand-rolled version exactly.
- **The shared secret is raw X25519 output with no KDF.** The peer's Ed25519 key is converted
  Edwards-Y → Montgomery-U, and the 32-byte ladder result *is* the key: AES-128 uses its first 16
  bytes, the 2-byte MAC is HMAC-SHA256 over the ciphertext keyed with all 32.
- **`path_length` is not a byte count.** Bits 0–5 are the hop count, bits 6–7 are `hash_size - 1`.
- **Ack hashes cover the unpadded plaintext.** `SHA256(plaintext_without_trailing_zeros || pubkey)[:4]`,
  where the key is the *sender's* — except for signed/room messages, where it is the recipient's.
  Get the padding wrong and acks silently never match.
- **Dedup must ignore the path**, since a packet's path mutates at every hop.
- Adverts are only trusted after the signature verifies, and an advert whose timestamp is not newer
  than the stored one is rejected as a replay.

## Testing

```sh
ctest --test-dir build --output-on-failure
```

The crypto and codec tests run against frozen reference vectors produced by an independently
written implementation of the same protocol — so agreement is real evidence of wire compatibility,
not just self-consistency. The vectors are committed under `tests/`.

An end-to-end script drives a running daemon over the companion socket: it seeds a known identity,
replays a signed advert and an encrypted message from a peer, and asserts that the contact appears,
the message decrypts, and the ack hash matches the reference byte for byte.

## License

GPL-3.0-or-later; see `LICENSE`.

## Credits

Protocol documentation and constants come from
[MeshCore](https://github.com/meshcore-dev/MeshCore) upstream. This is an independent
implementation and is not affiliated with it.
