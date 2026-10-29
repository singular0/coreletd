# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this
repository.

`README.md` is written for end users: what the daemon does, how to install and configure it, the
command-line options, the disclaimer about running an uncertified implementation on somebody's
mesh. Keep maintainer detail — architecture, protocol quirks, packaging internals, test
infrastructure — here rather than there, and don't let the two drift into duplicating each other.

Corelet (`../corelet`) is the desktop client on the other side of this protocol, by the same author;
its `CLAUDE.md` covers the client half. This daemon was renamed from `umeshcore` / `umeshcored`, so
references to that name elsewhere — Corelet's notes, older `dist/` artifacts — mean this repository.

## Build

C++20, no framework. Dependencies are libsodium, libcrypto (OpenSSL) and, for the radio backend,
libgpiod **2.0 or newer** — CMake stops with an explanatory error on the 1.6 that bookworm ships.

```sh
# uConsole / Debian trixie
sudo apt install build-essential cmake pkg-config libsodium-dev libssl-dev libgpiod-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j4
ctest --test-dir build --output-on-failure
```

`CORELETD_RADIO_SX1262` defaults on for Linux and off everywhere else. The tests inject test-only
radios, so a macOS checkout still builds and tests all hardware-independent code, but its daemon has
no runnable radio backend. `CORELETD_HAVE_SX1262` guards the code that needs the real backend.

Sources are listed explicitly in `CMakeLists.txt`; a new `.cpp` must be added there or it silently
won't compile. Tests are one CTest binary per `tests/test_<name>.cpp`, registered by the `foreach`
in the same file — a new test file needs its name added to that list. The `version` test is the
exception: a CMake script, registered beside them, that exercises the resolver described below.
`tests/coreletd_sim.cpp` is not a test at all: it builds `coreletd_sim`, the daemon on a simulated
radio with a scripted peer, which `tools/cli_compat_test.py` drives meshcore-cli against.

## Architecture

Everything runs on **a single thread in one `poll()` loop**. There is no locking anywhere in the
codebase, and there must not be: callbacks run on the loop thread and must not block.

```
src/
  util/       bytes, hex, INI, logging, clock, atomic file replacement
  crypto/     Ed25519 (expanded-key), X25519, AES-128-ECB + HMAC, identity
  proto/      packet header/path codec, payload codecs
  radio/      Radio interface, duty cycle, SX1262 (spidev + libgpiod)
  mesh/       dispatcher, contacts, channels, sender, inbox, node, state writer
  companion/  frame codec, Unix/TCP stream server, command session
  daemon/     config, event loop, host metrics, App wiring
tests/        unit tests + frozen reference vectors
```

Ownership runs one way. `App` constructs in a fixed order — identity, the app's settings, radio,
dispatcher, node, state writer, companion server — because each stage needs the one before it.

- **`EventLoop`** owns `poll()`, the timers and the clock. Registrations own their lifetime, so a
  subsystem that goes away takes its watches with it. `main()` hangs its signal check on the loop's
  interrupt predicate; the handler itself only touches a `sig_atomic_t`.
- **`Dispatcher`** owns the radio: everything that transmits or receives goes through it. It
  deduplicates, paces against the duty-cycle budget, and drains a priority transmit queue
  (ack < response < direct < flood < repeat < advert). A queued packet's expiry is derived from its
  priority, so low-priority traffic is dropped rather than delaying something urgent.
- **`Node`** routes between the radio and the app: it builds our adverts, decides what each received
  payload means, and — with `repeat` on — relays as MeshCore's companion does with repeat enabled:
  flood traffic is repeated and direct traffic whose next hop is us is forwarded. The two are a
  pair: a node that appends its hash to flood paths ends up on the routes peers build from them.
  Delivery guarantees are not its job.
- **`ReliableSender`** owns retries: four attempts (the attempt number is two bits on the wire),
  8/16/32 seconds apart, with the last escalating to flood because a stale direct path is the usual
  reason an ack never comes. **`MessageInbox`** owns the receive queue the app pops from.
- **`StateWriter`** owns *when* state is written; the stores own their files and their dirty flags.
  Writes are coalesced over `kCoalesceMs` (1s) with a `kSweepMs` (60s) backstop, because an app
  syncing forty contacts sends forty commands and each durable replacement costs a rewrite plus two
  fsyncs. The cost is that a mutating command is answered before its bytes are on disk, which is
  what `healthy()` reports on.
- **`Session`** translates companion frames into node operations and mesh events back into pushes.
- **`SettingsStore`** owns the settings an app may change: the `settings` file, read over the
  defaults before anything is built from it, and every change after — checked, written, then
  applied to `Node` and, through `Dispatcher::reconfigure()`, the radio. Session sees it only as
  the `companion::Settings` interface and never touches the config.

`App` takes an optional radio and clock (`daemon/app.h`). That seam is what lets `tests/test_app.cpp`
stand the whole stack up against a radio the test drives and a `ManualClock` that runs it on virtual
time — prefer extending that over adding narrower fakes.

## Protocol constraints

Violating any of these produces bugs that only appear against real firmware:

- **The private key is not a normal Ed25519 key.** MeshCore stores the *expanded* 64-byte
  SHA-512(seed) as `(a, RH)` and throws the seed away. No standard signing API accepts that, so
  `crypto/identity.cpp` assembles signatures from libsodium's scalar primitives. libsodium's
  clamping happens to match MeshCore's hand-rolled version exactly.
- **The shared secret is raw X25519 output with no KDF.** The peer's Ed25519 key is converted
  Edwards-Y → Montgomery-U, and the 32-byte ladder result *is* the key: AES-128 uses its first 16
  bytes, and the 2-byte MAC is HMAC-SHA256 over the ciphertext keyed with all 32.
- **`path_length` is not a byte count.** Bits 0–5 are the hop count, bits 6–7 are `hash_size - 1`.
- **Ack hashes cover the text up to its NUL, not the unpadded plaintext.**
  `SHA256(timestamp || flags || text_up_to_NUL || pubkey)[:4]`, where the key is the *sender's* —
  except for signed and room messages, where it is the recipient's and the text starts at byte 9,
  after a 4-byte key prefix that can itself contain a zero. Hash a byte too few or too many and acks
  silently never match, which on the air is indistinguishable from a message that never arrived.
- **Dedup must ignore the path**, since a packet's path mutates at every hop.
- **Adverts are only trusted after the signature verifies**, and one whose timestamp is not newer
  than the stored one is rejected as a replay.
- **A contact's path field is a fixed 64 bytes on the wire**, regardless of the hop count in
  `path_len`; read it as such.
- **Routes come only from returned paths, never from adverts or from reversing a flood path.**
  That is MeshCore's rule and it is ours: a peer's packet reversed is a guess about links nobody has
  used, and a wrong guess installed over a route the peer actually told us costs three direct
  attempts before the ladder floods. A peer that has heard our advert still floods every packet at
  us until it receives a `PATH`, so a flood-routed message from a known contact is answered with
  one: the inbound path *unreversed* — that is the direction their packets will travel — with the
  ack bundled in as `extra`, so the reply is still one transmission. That reply is **flooded**, as
  `BaseChatMesh::onPeerDataRecv` floods it: we hold no route to the sender either, and sent down a
  guessed one it takes the ack with it when the guess is wrong. A flood-routed `PATH` gets a
  reciprocal one back, sent direct along the route it carried, which is what ends the exchange
  rather than trading them for ever; and a flood-routed ack from a contact we hold a route for
  means our `PATH` never arrived, so the route is offered again, direct, three seconds later
  (`handleReturnPathRetry`).
- **A direct-routed packet with hops left on its path is in transit, not for us.** MeshCore reads
  an ack out of one early and otherwise does not decrypt it; with `repeat` on it is forwarded when
  we are the next hop, our hop popped, at ack priority. Two kinds are exempt, and checked first: a
  TRACE's path is not a route but the SNR each hop heard it at, so it goes on when the next hash in
  its *payload* is ours, with our reading appended; and a CONTROL packet with its top bit set is
  zero-hop only and never forwarded. The flood side repeats only what
  `Mesh::routeRecvPacket` would: not a packet that was for us — a text, path or request that
  opens under one of our keys, even one we cannot answer — not an ack that matched, not an
  advert that failed to verify, and never TRACE, MULTIPART, CONTROL, RAW_CUSTOM or a reserved type.
  The hop appended is as wide as the packet's hashes.

### Companion protocol

The enums in `companion/frames.h` are wire numbers shared with every MeshCore client (Corelet
mirrors them in its `protocol/protocol.h`). Never renumber; append only.

- **Replies are untagged** — nothing identifies which command a response answers, so a client sends
  one command at a time. `cmd_get_contacts` is the exception that streams several frames and returns
  nothing to the generic reply path.
- **Pushes (`>= 0x80`) go only to a client that sent `CMD_APP_START`.** Everything unsolicited
  leaves through `Session::push` for that reason. `on_raw_rx` is why it matters: it forwards every
  decoded packet, duplicates included, and a client that connected to probe with `DEVICE_QUERY` and
  is not draining its socket would hit the server's outbound limit in about a thousand packets and
  be disconnected for traffic it never asked for.
- **One client at a time.** A new connection replaces the current one (`Server::accept_client`), so
  a client that died without closing cannot lock the port.
- **A Unix domain socket is the default transport; TCP is the compatibility option.** Selecting
  TCP is the explicit network opt-in, with a loopback bind as its default. BLE and USB-serial are
  deliberately not on the list: they exist because a microcontroller has no network stack, and
  this is a Linux daemon. Don't add them, and don't restructure `Server` in anticipation of them.
- **`SYNC_NEXT_MESSAGE` pops.** The daemon is not message storage; whatever the app collects, the
  app must persist or the message is gone.
- **An app changes what MeshCore's companion lets it change, and nothing else:** the name, the
  position, the radio preset, TX power, the airtime factor and repeat — `Config::app_keys()`.
  Session turns each command into config keys with values in the settings file's syntax, and
  `SettingsStore` puts them through the same table and `Config::validate()` the file gets, so an
  app gets no wider a range than a hand edit. A change is written before it is answered, and a
  write that fails answers `ERR_FILE_IO_ERROR` and applies nothing: these are not coalesced
  through `StateWriter`, since they come a few a session and the reply has to be true. A name the
  advert cannot carry is refused with `ERR_ILLEGAL_ARG`, never truncated as MeshCore truncates it.
  Nothing is advertised on a change, as in MeshCore.
- **The quirks of those commands are upstream's.** `SET_RADIO_PARAMS` without its trailing repeat
  byte turns repeat *off* — although we claim protocol v3 and a v3 client has no reason to send it —
  and an app may turn repeat on only at 433.000, 869.495 and 918.000 MHz (`repeat_freq_ranges`);
  that is a check on the command, so `repeat` written into the settings file by hand is not held
  to it. DEVICE_INFO appends the v9 repeat
  byte and v10 path-hash byte so a client can read the state it must send back. Bandwidth arrives in
  whole hertz (7800 for 7.81 kHz) and is snapped to the chip's within 1%, never further. The
  airtime factor (0–9, in thousandths) is the duty cycle as `100 / (1 + af)`, so `radio.duty_cycle
  = 100` is valid and means no limit. A non-zero RX delay is refused: nothing implements it.
- **Unimplemented commands answer `ERR_UNSUPPORTED_CMD`**: telemetry, path tracing, room-server
  login, key import/export, signing, reboot, and the other parameters — path-hash mode, auto-add,
  flood scope, PIN, custom vars — until the feature behind each exists.
- **Repeater and room-server roles are unimplemented, not ruled out.** `repeat` relays exactly
  what MeshCore's companion relays with repeat enabled; the repeater *role* — its CLI, ACLs,
  transport keys — and the room server are another matter. The daemon is a companion node today and
  whether it takes on those roles is undecided, so don't describe them as out of scope and don't
  foreclose them — but don't start building them either without being asked.

### Radio backend

- **The LoRa rail is not ours to switch.** GPIO16 gates power to the SX1262 on the AIO v2 and is
  shared board-level state; while it is off, every SPI read returns zeroes. An absent radio is
  therefore a normal state, not a startup failure: the daemon comes up without one, retries every
  `[hardware] lora_retry_interval` seconds, and notices the rail going away mid-run.
- **Retuning goes through the same `configure()` as bring-up.** `Radio::reconfigure()` on a running
  SX1262 reprograms it at once, or after the packet on the air, since `configure()` begins with
  `SetStandby`; on one that is down, recovery configures from the new parameters when the rail
  returns. A change to the duty cycle alone is the dispatcher's and leaves the chip alone.
- **No frequency is an idle radio, not a fault.** The SX1262 is neither reset nor configured until
  `reconfigure()` names one, and the dispatcher holds anything queued while `params()` has none,
  whatever the backend — that check is the one the test radios meet too.
- **`XOSC_START_ERR` (`0x0020`) at power-up is not a fault.** The chip latches it because it starts
  its oscillator before DIO3 is configured to drive the TCXO; calibration clears it. Still reported
  afterwards means `[hardware] lora_tcxo` genuinely doesn't match the board.
- **The preamble is derived from the spreading factor, not chosen.** RadioLib's
  `preambleLengthForSF()` gives MeshCore 32 symbols at SF8 and below and 16 above, so
  `[radio] lora_preamble` is an override and unset means the rule. The two datasheet errata are a
  pair: 15.2's TX clamp at `0x08D8`, and 15.1's receiver sensitivity bit at `0x0889`, which is only
  wrong at `lora_bw = 500` but has to be written because the validator accepts that.
- DIO2 drives the RF switch, DIO3 the TCXO at 1.8 V, and chip select is the kernel's SPI1-CE0, which
  is why `[hardware] lora_nss_pin` is unset.

## Configuration

`daemon/config.cpp` holds one table of settings — key, type, destination field, range — and parsing
and validation both walk it, for both files. Add a setting there rather than threading it through
by hand. A config-file setting is documented in `etc/coreletd.ini`: `tests/test_ini.cpp` reads the
shipped file and checks the two agree in both directions, so an undocumented key and a documented
non-key each fail the build's tests.

The table's rows split by owner, and every key has exactly one. `Config::app_keys()` — what
MeshCore's companion keeps in its preferences and lets an app change — are the settings file's,
and `Config::load()` does not read them: a line for one in the config file is warned about and
ignored. Everything else is the operator's, in the config file. There is no precedence between the
two and nothing to migrate, which is the point: an app's change and an operator's edit to the same
key would otherwise need a rule for which is newer. The settings file lives in `state_dir` because
the config file is a dpkg conffile under `/etc`, which `ProtectSystem=strict` makes read-only to
the daemon; and it is not shipped, so the defaults for its keys are the code's, in `config.h`, as
MeshCore's are its build flags. The name is the exception: its default is the first four bytes of
the public key in upper-case hex, as MeshCore's companion names a node without `ADVERT_NAME`, so
`App::start()` loads the identity before the settings and fills it in where nothing else has. It is sparse — only the keys that have been set, in the config
file's syntax — so a default changed in the code reaches every node that never set the key. An
operator without an app writes it by hand with the daemon stopped, and a value there that the
table or `Config::validate()` refuses stops startup rather than being guessed around.

`[radio] lora_freq` deliberately has no default: transmitting on the wrong band is a legal problem.
Without one the daemon starts radio-silent and stays so until an app sets the radio parameters,
which is what MeshCore does — presets live in the phone app, and the firmware has no band plan
either. The package still installs the service disabled.

`[storage] state_dir` has no default either, and is the only storage setting: every state file sits
in it under a fixed name, so the directory is the whole of a backup. It must be absolute and must already
exist — the daemon never creates it, because a path that isn't there is likelier a typo than a first
run, and creating it would quietly mint a new node. The old default guessed from the effective uid,
which made `sudo coreletd` and `coreletd` two different nodes. For the same reason a missing
`identity` beside existing `contacts`, `channels` or `messages` stops startup rather than generating
a key — but not beside `settings`, which holds nothing bound to the key and is what an operator
without an app writes before the first start. The shipped `coreletd.ini` sets it to `/var/lib/coreletd`, which is what the unit's
`StateDirectory=` creates; `ProtectSystem=strict` makes any other path read-only, so a mismatch fails
at startup.

## Testing

```sh
ctest --test-dir build --output-on-failure
```

`tests/vectors.h` and `tests/packet_vectors.h` are **frozen fixtures produced by an independently
written implementation** of the same protocol. That independence is the entire value: agreement is
evidence of wire compatibility rather than self-consistency. Treat them as ground truth — if the
protocol changes, new bytes must be sourced from another implementation, never adjusted to match
ours.

The end-to-end script `tools/hw_e2e_test.py`, documented in `tools/README.md`, deploys to a real
uConsole, runs against the real SX1262, and asserts against a second independent MeshCore node over
the air — the only test that proves the driver keys the radio and that another vendor's firmware
accepts our packets. It needs the host named explicitly (`--host`, or `CORELETD_E2E_HOST`); the node
identity is deliberately kept between runs so peers don't accumulate dead contacts.

`tools/cli_compat_test.py` needs no hardware: it runs meshcore-cli against `coreletd_sim` and
asserts on what the client printed and what the simulated peer decoded off the air. Run it after
touching `Session` or anything a companion command reaches; it is not registered with CTest, since
meshcore-cli is not a build dependency.

The validated-on-hardware run behind the README's claim: uConsole (CM4, Debian trixie) + AIO v2
against a LilyGo T-Echo on MeshCore v1.17.0, 869.618 MHz — adverts signature-verified (RSSI −41,
SNR 12.2), public-channel messages both ways, direct messages decrypted at each end, and acks
matched, which is what confirms the ack-hash construction agrees with real firmware.

## Versioning

There is no version number written down anywhere. `cmake/version.cmake` resolves one from Git —
the same resolver Corelet uses, ported with a `CORELETD_` prefix and without the macOS bundle
fields — and every consumer takes it from there:

- **`CORELETD_VERSION`** (`1.2.3`, `1.2.3-4-gabc1234`, `0.0.0-gabc1234-dirty`) becomes the generated
  `version.h` that `main.cpp` and `app.cpp` include, so it is what `--version` prints and what the
  companion protocol reports as firmware version and build.
- **`CORELETD_VERSION_DEBIAN`** is the same identity in Debian's grammar: a prerelease hyphen
  becomes `~` so `0.2.0~rc.1` sorts *before* `0.2.0`, and everything after a tag becomes `+N.ghash`.
  It names the `.deb` and fills its changelog stanza.
- **`CORELETD_VERSION_DATE`** signs that generated stanza with the commit's own date, so the same
  commit always produces the same package.

Only tags matching SemVer with a `v` prefix count as releases; `nightly` or a tag-shaped typo is
ignored rather than mistaken for the newest release. Anything with no release tag behind it resolves
to `0.0.0+g<hash>`, which is the honest answer for an untagged build and the reason the repository's
first real package needs a `v0.1.0` tag.

A `.git` that exists but cannot be read is **fatal**, never `0.0.0` — that failure is what put
0.0.0 binaries inside Corelet's tagged v0.1.0 debs. `tests/version_test.cmake` (CTest `version`)
covers all of this against throwaway repositories, which is why `git` is a build dependency.

CMake resolves the version at configure time and again before every build, so an already-configured
tree still reports the commit it was built from. Packaging can't do that — it builds from a staged
copy with no `.git` — so `build-deb.sh` freezes the answer into a manifest and passes it in with
`-DCORELETD_VERSION_MANIFEST`; `debian/rules` uses it when it is there. The man page is generated
from `etc/coreletd.8.in` by the same resolver and installed by CMake, so its `.TH` line cannot drift
from the binary next to it.

## Packaging

`debian/` packages the tree for `linux-any`; `tools/build-deb.sh` wraps `dpkg-buildpackage` and
drops the result in `dist/`, with `--docker [arch]` running the same build inside a `debian:trixie`
container for building from a Mac (emulated, so slow — it is for a one-off, not a routine).

Every build goes through a temporary staged copy, because that is where the frozen manifest and the
generated changelog stanza are injected; nothing is written into the working copy. The container
build resolves Git against the read-only mount of the real checkout and hands the manifest to the
same staged path, so a container package identifies itself exactly as a native one does. The last
step asks `dpkg-deb` what version it actually built and fails if it isn't the one the manifest
named.

`debian/control`'s Build-Depends is the only copy of the build dependency list: `build-deb.sh deps`
installs them with `apt-get build-dep` on the tree itself, and the container build and CI both call
that rather than repeating the list. The one deliberate exception is the README's "build by hand"
section, which lists what a plain CMake build needs — a different, shorter list, since debhelper
isn't in it.

CI is two workflows. `debian.yml` builds the package on GitHub's free arm64 runner in a
`debian:trixie` container, on pull requests and on demand — a native build, because debhelper skips
`dh_auto_test` when the host architecture differs from the build one, so a cross-built package would
ship untested. There is no amd64 package: without an AIO v2 under it the binary has no radio.
`release.yml` triggers on `v*` tags, *calls* `debian.yml` rather than repeating it, and publishes the
`.deb` with a `SHA256SUMS` (the `-dbgsym` package is built but deliberately left out of the release).

Its gate job runs the version resolver against the tagged checkout and stops the release unless the
tag resolves to itself — an unreadable `.git` or a missing tag would otherwise be discovered as a
release full of `0.0.0` assets. The Debian spelling of the asset name comes out of the same answer,
and is checked against the file the package job actually produced. A tag that isn't a version at all
is skipped rather than failed. Both jobs check out with `fetch-depth: 0`: a shallow clone has no
tags, so `git describe` would find nothing.

`debian/rules` forces `-DCORELETD_RADIO_SX1262=ON` rather than trusting the platform default: the
package exists for that backend, so a missing libgpiod must fail the build instead of quietly
shipping a binary with no radio backend.

The package installs the unit, the udev rules and a `coreletd` user and group, and **must not
enable the service** (`dh_installsystemd --no-enable`): starting it puts a 22 dBm PA on the air on a
frequency the admin has not chosen yet. Upgrades still restart it if they did enable it. For the
same reason `purge` leaves `/var/lib/coreletd` and the user in place — the identity file there *is*
the node, and removing a package is not consent to destroy it. `debian/README.Debian` is what users
are pointed at for all of this; keep it in step with the README's setup section.

## Conventions

- Files are `snake_case`, members carry a trailing underscore, 4-space indent, ~100 columns.
- Warnings are `-Wall -Wextra -Wpedantic`; keep new code clean.
- Namespace is `clt`, with `clt::mesh`, `clt::proto`, `clt::radio`, `clt::crypto`, `clt::companion`.
- Message content is logged only at trace level. Nothing above it should print what people wrote.
- State is written through `durable_replace()` (`util/persist.h`), which is what makes it atomic,
  durable and `0600`. A new store that writes its file any other way gets none of the three. Its
  file goes in `state_dir` under a fixed name, with an accessor beside the others on `Config`, and
  belongs in `restrict_state_files()` in `daemon/app.cpp` too.
- Comments explain *why* a thing is the way it is — a wire quirk, a hardware constraint, a decision
  that looks wrong without the context. Match that register rather than narrating what the code
  does.
