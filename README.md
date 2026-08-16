# coreletd

A [MeshCore](https://meshcore.co.uk) node for the
[ClockworkPi uConsole](https://www.clockworkpi.com/uconsole) with the
[HackerGadgets / OpenSourceSDRLab AIO v2](https://hackergadgets.com/products/uconsole-aio-v2)
expansion board — the firmware part, running as a Linux daemon.

It drives the board's SX1262 LoRa transceiver directly, speaks the MeshCore mesh protocol, and
offers the **companion protocol over TCP**, so the uConsole behaves like any other MeshCore radio:
point the MeshCore phone or web app, [Corelet](https://github.com/singular0/corelet),
[`meshcore-cli`](https://github.com/fdlamotte/meshcore-cli) or `meshtui` at it — from the uConsole
itself over loopback, or from another machine on your network.

One binary, one systemd unit, no Arduino layer underneath.

> ### Please read this before you put it on the air
>
> coreletd is an **independent, clean-room implementation** of the MeshCore protocol, written from
> the public documentation. It is **not affiliated with, endorsed by, certified by or reviewed by
> the MeshCore project**, and compatibility with real MeshCore firmware is an intention backed by
> testing, not a guarantee anybody has signed off.
>
> A mesh is shared infrastructure. A bug here does not stay local: badly formed packets, traffic
> that should never have been repeated, or a node that ignores the airtime budget affect everyone
> in radio range, including people relying on that network. Try it on a mesh you own before joining
> one you don't, and don't make it the node anything important depends on.
>
> The usual radio rules apply too, and the daemon cannot check them for you: transmit only on a
> band and at a power your local regulations allow, keep within the duty cycle for that band, and
> **fit an antenna before starting it** — a 22 dBm PA into an open connector will damage the radio.

## What it does

Unchecked boxes are not implemented — use different firmware for those.

**Mesh**

- [x] Adverts, sent and received, with signatures verified before anything is trusted.
- [x] A contact store that survives restarts, with routes learned from the traffic it sees.
- [x] Encrypted direct messages, with acknowledgements, retries and automatic fallback to flood
      when a known route stops working.
- [x] Channel (group) messages — the public channel, hashtag channels and private ones.
- [x] Flood repeating for other nodes' traffic, off by default: repeating on a companion radio
      spends your duty-cycle budget and your battery on other people's packets.
- [x] Duty-cycle pacing, and a priority transmit queue so an ack is never stuck behind an advert.
- [ ] Repeater and room-server roles. It is a companion node today; whether it grows into those is
      undecided.
- [ ] Telemetry, path tracing, and the room-server login commands.

**Clients**

- [x] The companion protocol over TCP, on loopback by default.
- [x] One app at a time, as the protocol assumes. A new connection takes over from the old one, so
      a client that died without closing its socket cannot lock you out.
- [ ] A Unix domain socket, for clients on the uConsole itself.
- Bluetooth LE and USB-serial are **not planned**. They are how you reach a microcontroller; this
  runs on a Linux box that already has a network stack.

Radio settings, node name and position come from the configuration file, and the daemon **refuses**
the app's commands that would change them rather than accepting a change that nothing would persist.
Edit the file and restart.

**Operationally**

- [x] Survives the radio disappearing: if the AIO v2's LoRa power rail is off, the daemon starts
      anyway, waits for the chip, and picks it up when it appears. The same check reconnects if the
      rail is cut mid-session.
- [x] Crash-durable state — contacts, channels and your identity are written atomically.
- [x] A Debian package with a systemd unit and udev rules.

### Tested against real hardware

Validated on a uConsole (CM4, Debian trixie) with an AIO v2, against a LilyGo T-Echo running stock
MeshCore firmware on 869.618 MHz: adverts received and signature-verified, public-channel messages
exchanged, encrypted direct messages decrypted correctly at both ends, and acks matched in both
directions — which is the part that shows the two implementations really agree, since an ack is only
sent by a node that decrypted the message.

## What you need

- A ClockworkPi uConsole with the AIO v2 expansion board, running Raspberry Pi OS or Debian
  **trixie or newer** (older images ship libgpiod 1.6, and the build stops with an explanation).
- An antenna for the band you intend to use.
- A MeshCore client to talk to it, on the uConsole or on another machine.

## Install

Download the arm64 `.deb` from [Releases](../../releases) onto the uConsole and install it:

```sh
sudo apt install ./coreletd_0.1.0_arm64.deb
```

Install the *file path*, with the leading `./`, so apt resolves the runtime dependencies. Nothing is
signed, so the `SHA256SUMS` published beside the package is the only way to check what you got.

Or build the package yourself, on the uConsole:

```sh
tools/build-deb.sh deps                             # build dependencies, once
tools/build-deb.sh                                  # -> dist/coreletd_<version>_arm64.deb
sudo apt install ./dist/coreletd_*_arm64.deb
```

A package built from a checkout is named after the commit it came from, so it is a release version
only when you are on a release tag; anything else builds as `0.0.0+g<hash>`, which `coreletd
--version` then reports too. That is deliberate — a build should not claim to be a release nobody
made.

The package installs the daemon, its systemd unit and the udev rules, and creates a `coreletd`
system user and group. It deliberately **does not start the service** — the frequency is a legal
question and an unfitted antenna is a hardware one, so it waits for you. `/usr/share/doc/coreletd/`
has the packaging notes, including why purging leaves your node identity alone.

From a machine that isn't the uConsole, `tools/build-deb.sh --docker` builds the same arm64 package
in a container. It runs emulated, so it is slow, but it works from anywhere with Docker.

<details>
<summary>Or build and install by hand</summary>

```sh
sudo apt install build-essential cmake pkg-config libsodium-dev libssl-dev libgpiod-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j4
ctest --test-dir build --output-on-failure

sudo install -m 755 build/coreletd /usr/sbin/coreletd
sudo install -D -m 644 etc/coreletd.ini /etc/coreletd/coreletd.ini
sudo install -m 644 etc/coreletd.service /etc/systemd/system/
sudo groupadd -f -r coreletd && sudo useradd -r -g coreletd -s /usr/sbin/nologin coreletd
sudo install -m 644 etc/99-coreletd.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo systemctl daemon-reload
```

You get no man page and no upgrade path this way, and removing it is your problem.

</details>

<details>
<summary>Building without a uConsole</summary>

The test suite supplies its own test radios, so building and testing do not require radio hardware.
The SX1262 backend is Linux-only and is skipped automatically on macOS; a daemon built there has no
radio backend and will not start, but all hardware-independent development and tests remain available.

```sh
brew install cmake libsodium openssl@3 pkgconf     # macOS
cmake -S . -B build && cmake --build build -j
ctest --test-dir build --output-on-failure
```

OpenSSL is keg-only on Homebrew, so if CMake can't find `libcrypto`, point it at the right place:
`export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig"`.

</details>

## Set up the board

**1. Enable SPI.** The AIO v2 puts the SX1262 on SPI1. Add to `/boot/firmware/config.txt` and
reboot:

```
dtparam=spi=on
dtoverlay=spi1-1cs
```

Confirm `/dev/spidev1.0` exists afterwards — the service refuses to start without it.

**2. Turn on the LoRa power rail.** The AIO v2 gates power to each subsystem behind a GPIO, and
**GPIO16 must be high or the SX1262 is unpowered**. This is far and away the most common cause of
"the radio isn't responding". The daemon does not touch that switch: it is board-level state, owned
by whatever manages the uConsole's power.

```sh
aiov2_ctl lora on                     # the AIO v2 board utility
gpioset -c gpiochip0 16=1             # fallback; keep it running, the kernel reverts on exit
```

For reference, the other rails are GPS=27, SDR=7, internal USB=23.

You can do this before or after starting the daemon. A radio that isn't answering yet is a normal
state, not a failure.

**3. Fit an antenna.** Before anything transmits.

**4. If `meshtasticd` is installed, stop and disable it.** It holds the same GPIO lines, and
coreletd will fail with `EBUSY`.

## Configure

```sh
sudoedit /etc/coreletd/coreletd.ini
```

**`lora_freq` is required and has no default.** Which band you may transmit on is a legal question,
not a technical one, so the daemon refuses to start until you answer it — `869.618` for EU868,
`910.525` for US915. Every node on a mesh must also agree on `lora_bw`, `lora_sf` and `lora_cr`; the
shipped values are MeshCore's standard settings.

Worth setting while you are in there: `advert_name` (what other nodes see), `lat` / `lon` if you
want to publish a position, and `duty_cycle` for your band. The file documents every option.

## Run

```sh
sudo systemctl enable --now coreletd
journalctl -u coreletd -f
```

Or run it in the foreground while you are still setting things up — one at a time, since two
daemons cannot share the radio:

```sh
sudo systemctl stop coreletd
sudo /usr/sbin/coreletd --config /etc/coreletd/coreletd.ini --verbose
```

Then point a client at the companion port:

```sh
meshcore-cli -t 127.0.0.1:5000
corelet --host 127.0.0.1 --port 5000
```

### Options

| Option | Meaning |
|--------|---------|
| `-c`, `--config <path>` | Configuration file. Default `/etc/coreletd/coreletd.ini`. |
| `-v`, `--verbose` | Log at debug level, overriding the config. Repeat for trace, which reports every SPI command and interrupt. |
| `-s`, `--syslog` | Drop timestamps from log lines, for running under systemd. |
| `-V`, `--version` | Print the version. |
| `-h`, `--help` | Usage summary. |

`man coreletd` has the same reference when installed from the package.

## Your node identity

On first start the daemon generates an Ed25519 key and writes it to `/var/lib/coreletd/identity`.

**That file is your node.** Back it up. Delete it and you get a new public key, which means every
contact you have sees you as a stranger, and your old identity lingers in their contact list as a
node that never speaks again. Purging the package leaves the file in place for exactly this reason.

## Security

The companion protocol has **no authentication of any kind**. Anyone who can reach the port can read
your messages and send messages as you. `companion_bind` therefore defaults to `127.0.0.1`.

Only widen it to `0.0.0.0` on a network you control, and preferably reach it over an SSH tunnel or
WireGuard instead:

```sh
ssh -L 5000:127.0.0.1:5000 uconsole.local
```

## Troubleshooting

**Every SPI read is zeroes / the radio never appears.** The LoRa rail is off — see step 2 above.

**`XOSC_START_ERR`, device error `0x0020`, at startup.** Expected and harmless. The SX1262 latches
it at power-up because it tries to start its oscillator before DIO3 is configured to power the TCXO;
it is cleared after calibration. If it is *still* reported after that, `lora_tcxo` does not match
your board.

**The daemon starts but hears nothing.** Air settings must match the rest of the mesh exactly —
frequency, bandwidth, spreading factor and coding rate. A mismatch is silence, not an error.

**`EBUSY` opening the GPIO chip.** Something else holds the lines; usually `meshtasticd`, sometimes
a `gpioset` you left running, sometimes an earlier coreletd that did not exit.

**Permission denied on `/dev/spidev1.0`.** The udev rules aren't applied, or your user isn't in the
`coreletd` group: `sudo adduser "$USER" coreletd`, then log out and back in.

`--verbose --verbose` traces every SPI command and interrupt, which is where to start if you are
adapting this to a different board.

## License

GPL-3.0-or-later. There is no warranty; see `LICENSE` for the exact terms.

## Credits

Protocol documentation and constants come from the
[MeshCore](https://github.com/meshcore-dev/MeshCore) project. coreletd is an independent
implementation and is not affiliated with it.
