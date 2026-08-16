#!/usr/bin/env python3
"""End-to-end hardware test: coreletd on a uConsole against a real MeshCore peer.

    this Mac ──ssh──▶ uConsole ──SX1262──▶ ))) 869 MHz ((( ◀──SX1262── T-Echo
        │   (deploy, build, run, tunnel)                                  │
        ├── meshcore-cli ──TCP through the tunnel──▶ coreletd             │
        └── meshcore-cli ──BLE────────────────────────────────────────────┘

Both ends are driven with `meshcore-cli`, the same client the companion protocol
exists to serve, so nothing here reaches inside coreletd: a packet leaves one
radio and is asserted on the other. What that covers, and nothing else can, is
the half of the daemon that only exists on hardware — the SX1262 driver, the
duty-cycle pacing, the retry ladder against a peer that answers on its own
schedule, and wire compatibility with a firmware written by other people.

The uConsole is the one thing with no sensible default, so name it — or export
CORELETD_E2E_HOST once for a bench you use often. The peer is whichever
MeshCore radio answers over BLE first, which is right when there is one on the
desk; --peer picks a particular one when there is not.

    tools/hw_e2e_test.py --host uconsole.local          # the full sweep
    CORELETD_E2E_HOST=192.0.2.10 tools/hw_e2e_test.py   # same, host from the env

Common variations:

    tools/hw_e2e_test.py --skip deploy         # reuse the build already there
    tools/hw_e2e_test.py --only companion      # one phase (deps run anyway)
    tools/hw_e2e_test.py --list                # what the phases are
    tools/hw_e2e_test.py --keep-running        # leave daemon + tunnel up
    tools/hw_e2e_test.py --peer t-echo         # when several radios are in range

Exit status is 0 only if every check passed. Nothing is left running unless
--keep-running is given, and the peer's own state is not modified: the only
write to it is the optional channel slot in --with-channel, which is restored.

Requirements on this machine: python3, ssh (keys configured), rsync, and
meshcore-cli (`pipx install meshcore-cli`). On the uConsole: cmake, g++ and the
build dependencies, plus the LoRa rail powered — see --lora-on-cmd.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# So a bench you use often does not need --host on every invocation.
HOST_ENV = "CORELETD_E2E_HOST"

# ---------------------------------------------------------------------------
# Defaults. Everything here is a flag; nothing here names a particular machine
# or radio. The two that would have — the uConsole and the peer — are the ssh
# target, which has to be given, and the peer, which is discovered.
# ---------------------------------------------------------------------------

DEFAULTS = dict(
    remote_dir="coreletd-e2e",
    local_port=5010,            # this end of the tunnel; 5000 is AirPlay on macOS
    remote_port=5000,
    node_name="uConsoleE2E",
    freq=869.618,               # must match the peer's radio settings exactly
    bw=62.5,
    sf=8,
    cr=8,
    tx_power=22,
    spidev="/dev/spidev1.0",
    gpiochip="gpiochip0",
    irq_pin=26,
    busy_pin=24,
    reset_pin=25,
    channel_slot=3,             # low enough to exist on both, high enough to be spare
    lora_on_cmd="python3 ~/aiov2_ctl/aiov2_ctl.py LORA on",
    lora_status_cmd="python3 ~/aiov2_ctl/aiov2_ctl.py --status",
)

# How long each kind of step is given before it is called a failure. Radio
# round trips are seconds; a build is minutes.
T_SSH = 60
T_BUILD = 900
T_CLI_TCP = 30
T_CLI_BLE = 60          # a BLE connect alone is ~3 s, and a scan can be slower
T_RADIO_READY = 45      # the SX1262 retry interval is 10 s; allow a few
T_ADVERT = 45           # advert out, peer's contact list updated
T_MESSAGE = 30
# A message is not late until the whole retry ladder has run: coreletd tries at
# 0, +8, +24 and +56 s, escalating to flood on the way. On a band with other
# traffic on it, needing the second or third attempt is the system working.
T_ACK_LADDER = 75
# meshcore-cli's wait_ack listens for a fixed 5 s. Two of them chained is the
# fast path — one retry's worth — and the daemon's own log covers the rest.
ACK_WAITS = 2
# One BLE scan, in preflight. Longer than meshcore-cli's 2 s default: this runs
# once and the whole run depends on it finding the radio.
SCAN_SECS = 6

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def paint(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if COLOR else text


@dataclass
class Check:
    phase: str
    name: str
    ok: bool
    detail: str = ""


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def check(self, phase: str, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append(Check(phase, name, bool(ok), detail))
        mark = paint("ok  ", "32") if ok else paint("FAIL", "31;1")
        line = f"  {mark} {name}"
        if detail:
            line += paint(f"  — {detail}", "90")
        print(line, flush=True)
        return bool(ok)

    def note(self, text: str) -> None:
        self.notes.append(text)
        print(f"  {paint('note', '33')} {text}", flush=True)

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if not c.ok]

    def summary(self) -> int:
        print()
        print(paint("summary", "1"))
        passed = len(self.checks) - len(self.failures)
        for c in self.failures:
            # One line each: the detail was printed in full where it happened.
            detail = " ".join(c.detail.split())
            if len(detail) > 120:
                detail = detail[:117] + "..."
            print(f"  {paint('FAIL', '31;1')} {c.phase}: {c.name}"
                  + (f"  — {detail}" if detail else ""))
        for s in self.skipped:
            print(f"  {paint('skip', '90')} {s}")
        verdict = paint("PASSED", "32;1") if not self.failures else paint("FAILED", "31;1")
        print(f"  {passed}/{len(self.checks)} checks passed — {verdict}")
        return 1 if self.failures else 0


class PhaseError(Exception):
    """A phase could not run at all, as opposed to a check that failed."""


# ---------------------------------------------------------------------------
# Process plumbing
# ---------------------------------------------------------------------------


def run(argv: list[str], timeout: int, stdin_null: bool = True) -> subprocess.CompletedProcess:
    """Runs a command, capturing both streams. Never raises on exit status."""
    try:
        return subprocess.run(
            argv,
            stdin=subprocess.DEVNULL if stdin_null else None,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") if isinstance(e.stdout, str) else ""
        err = (e.stderr or "") if isinstance(e.stderr, str) else ""
        return subprocess.CompletedProcess(argv, 124, out, err + f"\n[timed out after {timeout}s]")


def json_docs(text: str) -> list:
    """Pulls every JSON value out of a stream of them.

    meshcore-cli -j prints one pretty-printed document per command, with no
    separators and the occasional plain-English line between them, so the
    output is not a JSON document itself.
    """
    decoder = json.JSONDecoder()
    docs, i, n = [], 0, len(text)
    while i < n:
        while i < n and text[i] not in "[{":
            i += 1
        if i >= n:
            break
        try:
            doc, end = decoder.raw_decode(text, i)
        except ValueError:
            i += 1
            continue
        docs.append(doc)
        i = end
    return docs


class Ssh:
    """One multiplexed ssh connection: commands, the port forward, and rsync.

    A single ControlMaster carries everything, so the dozens of short commands
    this script runs cost one handshake rather than dozens, and the tunnel dies
    with the connection rather than being left behind by a crashed run.
    """

    def __init__(self, host: str, local_port: int, remote_port: int, verbose: bool):
        self.host = host
        self.local_port = local_port
        self.remote_port = remote_port
        self.verbose = verbose
        self.socket = f"/tmp/coreletd-e2e-{os.getpid()}.sock"
        self.open = False

    def connect(self) -> None:
        self.disconnect()  # in case a previous run left one behind
        argv = [
            "ssh", "-M", "-S", self.socket, "-f", "-N",
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "ExitOnForwardFailure=yes",
            "-o", "ServerAliveInterval=15",
            "-L", f"{self.local_port}:127.0.0.1:{self.remote_port}",
            self.host,
        ]
        r = run(argv, timeout=30)
        if r.returncode != 0:
            raise PhaseError(f"ssh to {self.host} failed: {r.stderr.strip() or r.stdout.strip()}")
        self.open = True

    def disconnect(self) -> None:
        run(["ssh", "-S", self.socket, "-O", "exit", self.host], timeout=15)
        try:
            os.unlink(self.socket)
        except OSError:
            pass
        self.open = False

    def run(self, command: str, timeout: int = T_SSH) -> subprocess.CompletedProcess:
        if self.verbose:
            print(paint(f"    ssh: {command}", "90"), flush=True)
        return run(["ssh", "-S", self.socket, "-o", "BatchMode=yes", self.host, command],
                   timeout=timeout)

    def check(self, command: str, timeout: int = T_SSH) -> str:
        r = self.run(command, timeout)
        if r.returncode != 0:
            raise PhaseError(f"remote command failed ({command}): "
                             f"{(r.stderr or r.stdout).strip()[:400]}")
        return r.stdout

    def rsync(self, src: str, dest: str, excludes: list[str], timeout: int) -> None:
        argv = ["rsync", "-az", "--delete", "-e", f"ssh -S {self.socket}"]
        for x in excludes:
            argv += ["--exclude", x]
        argv += [src, f"{self.host}:{dest}"]
        r = run(argv, timeout=timeout)
        if r.returncode != 0:
            raise PhaseError(f"rsync failed: {(r.stderr or r.stdout).strip()[:400]}")


class Node:
    """A MeshCore node reachable through meshcore-cli."""

    def __init__(self, label: str, transport: list[str], timeout: int, verbose: bool):
        self.label = label
        self.transport = transport
        self.timeout = timeout
        self.verbose = verbose

    def cli(self, *cmds: str, attempts: int = 2, timeout: int | None = None,
            expect: bool = True) -> list:
        """Runs chained commands and returns the JSON documents they printed.

        Chaining matters over BLE, where each invocation pays a connect; the
        commands the phases need to run back-to-back are passed together.

        `expect` is False for the commands that print nothing on success
        (set_channel and friends), where an empty result is the good outcome
        rather than a connection that needs retrying.
        """
        argv = ["meshcore-cli", "-j"] + self.transport + [str(c) for c in cmds]
        last = None
        for attempt in range(attempts):
            if self.verbose:
                print(paint(f"    {self.label}: {' '.join(shlex.quote(str(c)) for c in cmds)}",
                            "90"), flush=True)
            r = run(argv, timeout=timeout or self.timeout)
            last = r
            docs = json_docs(r.stdout)
            if r.returncode == 0 and (docs or not expect):
                return docs
            if attempt + 1 < attempts:
                time.sleep(2)
        # The useful part of a meshcore-cli failure is usually a few lines up
        # from the end, so keep the tail rather than the last line alone.
        lines = [l.strip() for l in ((last.stderr or "") + "\n" + (last.stdout or "")).splitlines()
                 if l.strip()]
        raise PhaseError(f"{self.label}: `{' '.join(str(c) for c in cmds)}` produced no result"
                         + (f" ({' / '.join(lines[-3:])[:300]})" if lines else ""))

    def one(self, *cmds: str, **kw) -> dict:
        docs = self.cli(*cmds, **kw)
        return docs[-1] if docs else {}

    def channels(self) -> list[dict]:
        """Every channel slot.

        get_channels rather than get_channel: the singular form prints a Python
        repr rather than JSON, which is not something to parse.
        """
        for doc in self.cli("get_channels"):
            if isinstance(doc, list):
                return [c for c in doc if isinstance(c, dict)]
        return []

    def channel(self, slot: int) -> dict:
        return next((c for c in self.channels() if c.get("channel_idx") == slot), {})

    def contacts(self) -> dict:
        docs = self.cli("contacts")
        for d in docs:
            if isinstance(d, dict):
                return d
        return {}

    def find_contact(self, key_prefix: str) -> dict | None:
        for key, contact in self.contacts().items():
            if key.lower().startswith(key_prefix.lower()):
                return contact
        return None

    def await_contact(self, key_prefix: str, deadline_s: int, poll_s: float = 3.0) -> dict | None:
        end = time.time() + deadline_s
        while True:
            found = self.find_contact(key_prefix)
            if found is not None:
                return found
            if time.time() >= end:
                return None
            time.sleep(poll_s)


# ---------------------------------------------------------------------------
# The harness
# ---------------------------------------------------------------------------


class Harness:
    def __init__(self, args):
        self.a = args
        self.report = Report()
        self.ssh = Ssh(args.host, args.local_port, args.remote_port, args.verbose)
        self.remote = f"~/{args.remote_dir}"
        self.ini = f"{self.remote}/coreletd.ini"
        self.log = f"{self.remote}/run.log"
        self.state = f"{self.remote}/state"
        self.src = f"{self.remote}/src"
        self.nonce = secrets.token_hex(3)
        self.daemon_running = False
        self.started_daemon = False  # whether this run ever launched one
        self.peer_channel_set = False

        self.uconsole = Node("uConsole",
                             ["-t", "127.0.0.1", "-p", str(args.local_port)],
                             T_CLI_TCP, args.verbose)
        # No -a at all means meshcore-cli connects to the first MeshCore radio
        # it finds over BLE, which is what you want with one on the desk.
        self.peer = Node("peer", ["-a", args.peer] if args.peer else [],
                         T_CLI_BLE, args.verbose)

        # Filled in as the phases learn them.
        self.uconsole_key = ""
        self.peer_key = ""

    # -- helpers ----------------------------------------------------------

    @property
    def home(self) -> str:
        """The remote home directory, spelled out.

        Most paths here can keep their tilde and let the remote shell expand
        it, but the config file is read by the daemon rather than a shell, so
        state_dir has to be written out in full.
        """
        if not getattr(self, "_home", ""):
            self._home = self.ssh.check("echo $HOME").strip()
        return self._home

    def banner(self, phase: str, title: str) -> None:
        print()
        print(paint(f"[{phase}] {title}", "1;36"), flush=True)

    def tag(self, what: str) -> str:
        """A message body no other node on the mesh will be sending."""
        return f"coreletd-e2e {what} {self.nonce}"

    def discover_peer(self) -> str:
        """Pins the peer to one BLE address for the rest of the run.

        With no -a, every meshcore-cli invocation rescans, and a scan that
        comes up empty fails a phase rather than merely connecting slowly. One
        scan here and every later invocation addresses the radio directly —
        which is also how the run gets to say which radio it picked.

        A --peer that does not resolve is left as it was given: meshcore-cli
        accepts a platform address that no scan of ours will have listed.
        """
        r = run(["meshcore-cli", "-T", str(SCAN_SECS), "-l"], timeout=T_CLI_BLE)
        devices, in_ble = [], False
        for line in r.stdout.splitlines():
            if line.startswith("BLE devices"):
                in_ble = True
            elif line.startswith("Serial ports"):
                in_ble = False
            elif in_ble and line.strip():
                address, _, name = line.strip().partition(" ")
                devices.append((address, name.strip()))

        if self.a.peer:
            wanted = self.a.peer.lower()
            devices = [d for d in devices if wanted in d[1].lower() or wanted in d[0].lower()]
            if not devices:
                self.peer.transport = ["-a", self.a.peer]
                return ""

        if not devices:
            return ""
        address, name = devices[0]
        self.peer.transport = ["-a", address]
        extra = f" (of {len(devices)} in range)" if len(devices) > 1 else ""
        return f"{name} at {address}{extra}"

    def ensure_peer_knows_us(self) -> dict:
        """The peer cannot decrypt for a key it has never heard of.

        Until we have advertised, the peer has no contact to derive a shared
        secret from, and a message to it is undecryptable — which on the air
        looks exactly like a radio that is not transmitting. advert_tx normally
        does this; --only should not have to include it to work.
        """
        found = self.peer.find_contact(self.uconsole_key[:12])
        if found:
            return found
        self.uconsole.cli("floodadv")
        found = self.peer.await_contact(self.uconsole_key[:12], T_ADVERT)
        if not found:
            raise PhaseError(f"the peer has no contact for {self.uconsole_key[:12]} after our "
                             f"advert — it cannot decrypt anything we send it")
        return found

    def ensure_peer_contact(self) -> dict:
        """There is no encrypting for a contact we do not have.

        Normally advert_rx has already put it there. This is for --only, and
        for a state directory that starts empty every run: the phases that send
        should not fail on a missing prerequisite they can ask for themselves.
        """
        found = self.uconsole.find_contact(self.peer_key[:12])
        if found:
            return found
        self.peer.cli("floodadv")
        found = self.uconsole.await_contact(self.peer_key[:12], T_ADVERT, poll_s=2.0)
        if not found:
            raise PhaseError(f"no contact for {self.peer_key[:12]} after asking the peer to "
                             f"advertise — nothing can be addressed to it")
        return found

    # -- phases -----------------------------------------------------------

    def phase_preflight(self) -> None:
        self.banner("preflight", "tools, host and radios are all there")
        c = self.report.check

        r = run(["meshcore-cli", "-v"], timeout=20)
        version = (r.stdout + r.stderr).strip().splitlines()
        c("preflight", "meshcore-cli present", r.returncode == 0,
          version[-1] if version else "")

        self.ssh.connect()
        uname = self.ssh.check("uname -sm").strip()
        c("preflight", f"ssh to {self.a.host}", bool(uname), uname)

        # The AIO v2 gates power to the LoRa module and the daemon does not
        # touch that switch, so a rail left off looks exactly like broken
        # wiring. Turn it on rather than making someone read the SPI errors.
        if self.a.lora_on_cmd:
            status = self.ssh.run(self.a.lora_status_cmd).stdout
            was_on = bool(re.search(r"LORA.*\bON\b", status))
            if not was_on:
                self.ssh.run(self.a.lora_on_cmd)
                time.sleep(2)
                status = self.ssh.run(self.a.lora_status_cmd).stdout
            now_on = bool(re.search(r"LORA.*\bON\b", status))
            c("preflight", "LoRa rail powered", now_on,
              "already on" if was_on else "switched on for this run")

        found = self.discover_peer()
        c("preflight", "peer radio found over BLE", bool(found),
          found or f"no MeshCore radio advertising in a {SCAN_SECS}s scan"
                   + (f" matching {self.a.peer!r}" if self.a.peer else ""))

        info = self.peer.one("infos", attempts=3)
        self.peer_key = info.get("public_key", "")
        c("preflight", "peer answers the companion protocol", bool(self.peer_key),
          f"{info.get('name', '?')} @ {self.peer_key[:12]}")

        # Every byte on air is interpreted with these; a mismatch is silence,
        # not an error message, so it is worth saying out loud up front.
        same_air = (abs(float(info.get("radio_freq", 0)) - self.a.freq) < 0.0005
                    and abs(float(info.get("radio_bw", 0)) - self.a.bw) < 0.01
                    and int(info.get("radio_sf", 0)) == self.a.sf
                    and int(info.get("radio_cr", 0)) == self.a.cr)
        c("preflight", "peer is on the air settings we will use", same_air,
          f"{info.get('radio_freq')} MHz BW{info.get('radio_bw')} "
          f"SF{info.get('radio_sf')} CR{info.get('radio_cr')}")

    def phase_deploy(self) -> None:
        self.banner("deploy", "sync the working tree and build it on the target")
        c = self.report.check

        self.ssh.check(f"mkdir -p {self.src} {self.state}")
        self.ssh.rsync(REPO + "/", self.src + "/",
                       ["build/", "dist/", ".git/", "__pycache__/"], timeout=300)
        c("deploy", "source tree synced", True, f"{self.a.host}:{self.src}")

        r = self.ssh.run(f"cd {self.src} && cmake -S . -B build "
                         f"-DCMAKE_BUILD_TYPE=RelWithDebInfo", timeout=T_BUILD)
        c("deploy", "cmake configured", r.returncode == 0,
          "SX1262 backend ON" if "SX1262 radio backend : ON" in r.stdout
          else (r.stderr.strip()[-200:] or "check the output"))

        r = self.ssh.run(f"cd {self.src} && cmake --build build -j$(nproc)", timeout=T_BUILD)
        c("deploy", "coreletd built for the target", r.returncode == 0,
          (r.stderr.strip()[-200:] if r.returncode else "arm64, native"))
        if r.returncode != 0:
            raise PhaseError("build failed; nothing to test")

        if self.a.with_unit_tests:
            r = self.ssh.run(f"cd {self.src} && ctest --test-dir build --output-on-failure",
                             timeout=T_BUILD)
            m = re.search(r"(\d+)% tests passed, (\d+) tests failed out of (\d+)", r.stdout)
            c("deploy", "unit tests pass on the target", r.returncode == 0,
              m.group(0) if m else (r.stdout.strip()[-200:] or "no ctest summary"))

    def phase_daemon(self) -> None:
        self.banner("daemon", "configure, start and connect to coreletd")
        c = self.report.check

        self.clear_strays()
        self.ssh.check(f"mkdir -p {self.state}")
        if not self.a.keep_state:
            # Contacts and channels go, so every assertion below is about
            # something this run did. The identity stays: a node that mints a
            # new key every run leaves a dead contact behind on every peer that
            # hears it, and on a peer whose contact table is full that is what
            # eventually stops it hearing us at all.
            self.ssh.check(f"rm -f {self.state}/contacts {self.state}/channels")

        ini = "\n".join([
            "# Written by tools/hw_e2e_test.py. Edits here are overwritten.",
            f"lora_freq = {self.a.freq}",
            f"lora_bw = {self.a.bw}",
            f"lora_sf = {self.a.sf}",
            f"lora_cr = {self.a.cr}",
            f"lora_tx_power = {self.a.tx_power}",
            f"spidev = {self.a.spidev}",
            f"lora_gpiochip = {self.a.gpiochip}",
            f"lora_irq_pin = {self.a.irq_pin}",
            f"lora_busy_pin = {self.a.busy_pin}",
            f"lora_reset_pin = {self.a.reset_pin}",
            f"state_dir = {self.home}/{self.a.remote_dir}/state",
            f"advert_name = {self.a.node_name}",
            # Adverts on demand only: every assertion below is about a packet
            # this script asked for.
            "advert_interval = 0",
            "companion_bind = 127.0.0.1",
            f"companion_port = {self.a.remote_port}",
            "log_level = debug",
            "",
        ])
        # Quoted heredoc: the file is written exactly as composed here.
        self.ssh.check(f"cat > {self.ini} <<'CORELETD_INI'\n{ini}CORELETD_INI")
        c("daemon", "config written", True, self.ini)

        self.start_daemon(fresh_log=True)
        c("daemon", "coreletd running", self.daemon_running,
          f"log at {self.a.host}:{self.log}")

        ready = self.await_radio(T_RADIO_READY)
        c("daemon", "SX1262 up", ready,
          "" if ready else "no 'sx1262: SX1262 on ...' in the log — rail off, or wiring")

        info = self.uconsole.one("infos", attempts=3)
        self.uconsole_key = info.get("public_key", "")
        c("daemon", "companion socket answers over the tunnel", bool(self.uconsole_key),
          f"{info.get('name')} @ {self.uconsole_key[:12]} "
          f"(127.0.0.1:{self.a.local_port} → {self.a.host}:{self.a.remote_port})")

    def phase_companion(self) -> None:
        self.banner("companion", "the protocol surface the phone app uses")
        c = self.report.check

        docs = self.uconsole.cli("infos", "ver", "clock", "get_channels")
        info = next((d for d in docs if isinstance(d, dict) and "public_key" in d), {})
        ver = next((d for d in docs if isinstance(d, dict) and "fw_build" in d), {})
        clock = next((d for d in docs if isinstance(d, dict) and "time" in d), {})
        slots = next((d for d in docs if isinstance(d, list)), [])
        chan = next((c for c in slots if c.get("channel_idx") == 0), {})

        c("companion", "SELF_INFO reports the configured node", info.get("name") == self.a.node_name,
          f"name={info.get('name')!r} key={info.get('public_key', '')[:12]}")
        c("companion", "SELF_INFO reports the configured radio",
          abs(float(info.get("radio_freq", 0)) - self.a.freq) < 0.0005
          and int(info.get("radio_sf", 0)) == self.a.sf,
          f"{info.get('radio_freq')} MHz SF{info.get('radio_sf')} "
          f"BW{info.get('radio_bw')} CR{info.get('radio_cr')}")
        c("companion", "DEVICE_INFO identifies the daemon", bool(ver.get("fw_build")),
          f"{ver.get('model')} {ver.get('ver')} (protocol v{ver.get('fw ver')}, "
          f"{ver.get('max_contacts')} contacts, {ver.get('max_channels')} channels)")

        # The daemon cannot advertise at all with an unset wall clock, so this
        # is a precondition for everything below, not a nicety.
        skew = abs(int(clock.get("time", 0)) - int(time.time()))
        c("companion", "device clock is sane", skew < 120, f"{skew} s from this Mac")

        c("companion", "public channel present in slot 0",
          chan.get("channel_idx") == 0 and chan.get("channel_name") == "Public"
          and chan.get("channel_secret", "0" * 32) != "0" * 32,
          f"{chan.get('channel_name')!r} hash={chan.get('channel_hash')}")

        # The card is a complete signed self-advert, not just a key: another
        # node imports it exactly as if it had heard us on air.
        uri = self.uconsole.one("card").get("uri", "")
        c("companion", "EXPORT_CONTACT builds our contact card",
          uri.startswith("meshcore://") and len(uri) > 80,
          f"{uri[:40]}… ({len(uri)} chars)" if uri else "no uri")

    def phase_advert_tx(self) -> None:
        self.banner("advert_tx", "our advert goes out and the peer believes it")
        c = self.report.check
        if not self.uconsole_key:
            raise PhaseError("no local pubkey yet — run the daemon phase")

        # The peer verifies the Ed25519 signature before storing anything, and
        # ignores an advert no newer than the one it holds. So the timestamp
        # moving forward is the assertion — and unlike "a contact appeared", it
        # still means something when the peer already knew us from a past run.
        before = self.peer.find_contact(self.uconsole_key[:12]) or {}
        stale = before.get("last_advert", 0)
        self.uconsole.cli("floodadv")

        # Each poll is a BLE connect and a contact list, so it paces itself.
        found, end = {}, time.time() + T_ADVERT
        while time.time() < end:
            found = self.peer.find_contact(self.uconsole_key[:12]) or {}
            if found.get("last_advert", 0) > stale:
                break

        c("advert_tx", "the peer accepted our advert", found.get("last_advert", 0) > stale,
          f"{found.get('adv_name')!r} type={found.get('type')}, advert timestamp "
          f"{stale} → {found.get('last_advert')}" if found
          else f"nothing matching {self.uconsole_key[:12]} after {T_ADVERT}s")
        if found:
            c("advert_tx", "peer stored the name we advertise",
              found.get("adv_name") == self.a.node_name, f"{found.get('adv_name')!r}")

    def phase_advert_rx(self) -> None:
        self.banner("advert_rx", "the peer's advert reaches us and teaches a route")
        c = self.report.check

        self.peer.cli("floodadv")
        found = self.uconsole.await_contact(self.peer_key[:12], T_ADVERT, poll_s=2.0)
        c("advert_rx", "we created a contact from the peer's advert", found is not None,
          f"{found.get('adv_name')!r}" if found
          else f"nothing matching {self.peer_key[:12]} after {T_ADVERT}s")
        if not found:
            return

        # A flood advert carries the path it travelled; reversed, that is the
        # route back. Straight off the peer's antenna it is empty, which is a
        # known zero-hop route and not the same as knowing nothing.
        c("advert_rx", "the advert taught us a return path",
          found.get("out_path_len", -1) >= 0,
          f"out_path_len={found.get('out_path_len')} path={found.get('out_path')!r}")

        on_disk = self.ssh.run(f"ls -l {self.state}/contacts 2>&1").stdout.strip()
        c("advert_rx", "the contact reached the state directory",
          "No such file" not in on_disk, on_disk[-70:])

    def phase_message_rx(self) -> None:
        self.banner("message_rx", "peer → coreletd, decrypted, stored and acked")
        c = self.report.check
        self.ensure_peer_knows_us()
        self.ensure_peer_contact()
        body = self.tag("rx")

        # The peer waits for the ack itself. coreletd only acks a message it
        # decrypted and stored, so an ack here already proves the receive path
        # end to end; reading the inbox afterwards proves the contents.
        docs = self.peer.cli("msg", self.uconsole_key[:12], body, *["wait_ack"] * ACK_WAITS,
                             timeout=T_CLI_BLE + T_MESSAGE)
        sent = next((d for d in docs if "expected_ack" in d), {})
        expected = sent.get("expected_ack", "")
        c("message_rx", "peer accepted the message for sending", bool(expected),
          f"expected ack {expected}, suggested timeout {sent.get('suggested_timeout')} ms")

        ack = next((d for d in docs if "code" in d), {})
        # coreletd acks straight out of the receive path, with no ladder of its
        # own, so the only reason to look at the log here is an ack that was
        # lost or late on the way back to the peer.
        acked = ack.get("code") == expected
        detail = f"round trip {ack.get('trip_time')} ms as the peer measured it"
        if not acked and expected:
            line = self.await_log(f"ack: sending {expected}", T_MESSAGE)
            acked = bool(line)
            detail = ("we sent it, the peer did not hear it back in time: " + line[-60:]
                      if line else "no ack, and none in our log either")
        c("message_rx", "coreletd acked it", acked, detail)

        inbox = self.drain_inbox(self.uconsole, body, T_MESSAGE)
        got = next((m for m in inbox if body in (m.get("text") or "")), None)
        c("message_rx", "the message is in our inbox with the right text", got is not None,
          f"{(got or {}).get('text')!r}" if got
          else f"{len(inbox)} message(s) read, none matching")
        if got:
            c("message_rx", "it is attributed to the peer",
              (got.get("pubkey_prefix") or "").lower().startswith(self.peer_key[:12].lower()),
              f"from {got.get('pubkey_prefix')} SNR {got.get('SNR')} dB "
              f"path_len {got.get('path_len')}")

    def phase_message_tx(self) -> None:
        self.banner("message_tx", "coreletd → peer, retried until acknowledged")
        c = self.report.check
        self.ensure_peer_knows_us()
        self.ensure_peer_contact()
        body = self.tag("tx")

        # The peer only acks after decrypting, so its ack — reported back to us
        # as PUSH_SEND_CONFIRMED — is the delivery receipt. Reading the peer's
        # own inbox would prove the same thing while consuming its message
        # queue, which is not ours to consume.
        docs = self.uconsole.cli("msg", self.peer_key[:12], body, *["wait_ack"] * ACK_WAITS,
                                 timeout=T_CLI_TCP + T_MESSAGE)
        sent = next((d for d in docs if "expected_ack" in d), {})
        expected = sent.get("expected_ack", "")
        c("message_tx", "coreletd accepted the message", bool(expected),
          f"expected ack {expected}, "
          f"routed {'direct' if sent.get('type') == 0 else 'flood'}, "
          f"suggested timeout {sent.get('suggested_timeout')} ms")

        acked, detail = self.await_ack(expected, docs, T_ACK_LADDER)
        c("message_tx", "the peer acknowledged it", acked, detail)

        # The round trip is measured by the daemon itself, off the event loop's
        # clock; zero would mean it never started the timer. Only the push
        # carries that figure, so a delivery the ladder rescued has none.
        ack = next((d for d in docs if isinstance(d, dict) and "code" in d), {})
        trip = int(ack.get("trip_time", 0) or 0)
        if ack.get("code") == expected:
            c("message_tx", "the daemon timed the round trip", 0 < trip < 60000, f"{trip} ms")
        elif acked:
            self.report.note("round trip not measured: the ack arrived after the client had "
                             "stopped listening, so no PUSH_SEND_CONFIRMED was delivered")

    def phase_path(self) -> None:
        self.banner("path", "a reset route falls back to flood and is relearned")
        c = self.report.check
        self.ensure_peer_knows_us()
        self.ensure_peer_contact()

        self.uconsole.cli("reset_path", self.peer_key[:12])
        contact = self.uconsole.find_contact(self.peer_key[:12]) or {}
        c("path", "RESET_PATH cleared the route", contact.get("out_path_len", 0) < 0,
          f"out_path_len={contact.get('out_path_len')}")

        body = self.tag("flood")
        docs = self.uconsole.cli("msg", self.peer_key[:12], body, *["wait_ack"] * ACK_WAITS,
                                 timeout=T_CLI_TCP + T_MESSAGE)
        sent = next((d for d in docs if "expected_ack" in d), {})
        c("path", "a routeless message goes out flood-routed", sent.get("type") == 1,
          f"type={sent.get('type')} (0 direct, 1 flood)")
        acked, detail = self.await_ack(sent.get("expected_ack", ""), docs, T_ACK_LADDER)
        c("path", "and is still acknowledged", acked, detail)

        # Acks do not carry a route; only a flood advert does, which is exactly
        # what the daemon sends when the app asks to rediscover a path.
        self.peer.cli("floodadv")
        deadline = time.time() + T_ADVERT
        relearned = {}
        while time.time() < deadline:
            relearned = self.uconsole.find_contact(self.peer_key[:12]) or {}
            if relearned.get("out_path_len", -1) >= 0:
                break
            time.sleep(2)
        c("path", "the next flood advert restores the route",
          relearned.get("out_path_len", -1) >= 0,
          f"out_path_len={relearned.get('out_path_len')}")

    def phase_channel(self) -> None:
        self.banner("channel", "a group message on a private channel")
        c = self.report.check
        slot = self.a.channel_slot

        # A private channel of our own rather than the public one: the same
        # code path, without putting test traffic in front of everybody on the
        # public channel. The key is shared by writing it to both nodes.
        key = secrets.token_hex(16)
        name = f"e2e{self.nonce}"
        self.uconsole.cli("set_channel", str(slot), name, key, expect=False)
        self.peer.cli("set_channel", str(slot), name, key, expect=False)
        self.peer_channel_set = True

        chan = self.uconsole.channel(slot)
        c("channel", f"channel {slot} configured on coreletd",
          chan.get("channel_name") == name and chan.get("channel_secret") == key,
          f"{chan.get('channel_name')!r} hash={chan.get('channel_hash')}")

        body = self.tag("chan")
        self.peer.cli("chan", str(slot), body)
        inbox = self.drain_inbox(self.uconsole, body, T_MESSAGE)
        got = next((m for m in inbox if body in (m.get("text") or "")), None)
        c("channel", "the group message arrives and decrypts", got is not None,
          f"slot {got.get('channel_idx')}: {got.get('text')!r}" if got
          else f"{len(inbox)} message(s) read, none matching")
        if got:
            c("channel", "it is tagged as a channel message on the right slot",
              got.get("type") == "CHAN" and got.get("channel_idx") == slot,
              f"type={got.get('type')} channel_idx={got.get('channel_idx')}")

    def phase_restart(self) -> None:
        self.banner("restart", "state survives a stop and start")
        c = self.report.check

        before = self.ensure_peer_contact()
        self.stop_daemon()
        contacts_file = self.ssh.run(f"wc -c < {self.state}/contacts").stdout.strip()
        c("restart", "contacts were flushed on shutdown",
          contacts_file.isdigit() and int(contacts_file) > 0, f"{contacts_file} bytes on disk")

        self.start_daemon(fresh_log=False)
        self.await_radio(T_RADIO_READY)
        info = self.uconsole.one("infos", attempts=3)
        c("restart", "the node kept its identity", info.get("public_key") == self.uconsole_key,
          info.get("public_key", "")[:12])

        after = self.uconsole.find_contact(self.peer_key[:12]) or {}
        c("restart", "the peer contact survived", bool(after),
          f"{after.get('adv_name')!r} out_path_len={after.get('out_path_len')}")
        c("restart", "so did its route",
          after.get("out_path_len") == before.get("out_path_len"),
          f"{before.get('out_path_len')} → {after.get('out_path_len')}")

        if self.a.with_channel:
            chan = self.uconsole.channel(self.a.channel_slot)
            c("restart", "so did the channel we configured",
              chan.get("channel_name", "").startswith("e2e"),
              f"slot {self.a.channel_slot}: {chan.get('channel_name')!r}")

    # -- daemon lifecycle -------------------------------------------------

    # The daemon is identified by the absolute config path on its command line.
    # The leading character is bracketed so the pattern never matches the shell
    # that carries the pgrep itself, which is otherwise a reliable false
    # positive over ssh.
    @property
    def match(self) -> str:
        return f"[{self.a.remote_dir[0]}]{self.a.remote_dir[1:]}/coreletd.ini"

    def daemon_pids(self) -> list[str]:
        return self.ssh.run(f"pgrep -f '{self.match}' || true").stdout.split()

    def clear_strays(self) -> None:
        """Stops any coreletd already on the host before starting ours.

        One SPI bus and one set of GPIO lines: a daemon left behind by an
        interrupted run holds them, and the only symptom is that the next run
        cannot request line 25. Cheaper to clear than to diagnose.
        """
        listing = self.ssh.run("pgrep -af '[c]oreletd -c' || true").stdout.strip()
        if not listing:
            return
        self.report.note("a coreletd was already running here and would hold the radio — "
                         "stopping it: " + "; ".join(listing.splitlines()))
        self.ssh.run("pkill -TERM -f '[c]oreletd -c' || true")
        time.sleep(2)
        self.ssh.run("pkill -KILL -f '[c]oreletd -c' || true")

    def start_daemon(self, fresh_log: bool) -> None:
        self.started_daemon = True  # set first: a start that fails still needs cleaning up
        redirect = ">" if fresh_log else ">>"
        # The config path goes on the command line with its tilde expanded by
        # the remote shell, which is what makes the process findable by it.
        self.ssh.check(f"cd {self.remote} && setsid ./src/build/coreletd -c {self.ini} "
                       f"</dev/null {redirect} run.log 2>&1 & echo started")
        for _ in range(10):
            time.sleep(0.5)
            if self.daemon_pids():
                self.daemon_running = True
                return
        tail = "\n".join(self.ssh.run(f"tail -5 {self.log}").stdout.strip().splitlines())
        raise PhaseError(f"coreletd did not start; last lines of {self.log}:\n{tail}")

    def stop_daemon(self) -> None:
        """Always tries, even if we think nothing is running.

        A start that this script failed to *notice* still left a daemon holding
        the SPI bus and the companion port, and that is exactly the state a
        failed run leaves behind.
        """
        # SIGTERM, which is what the shutdown path is written for: the state
        # writer flushes and the radio is put back to sleep.
        self.ssh.run(f"pkill -TERM -f '{self.match}' || true")
        for _ in range(20):
            time.sleep(0.5)
            if not self.daemon_pids():
                break
        else:
            self.ssh.run(f"pkill -KILL -f '{self.match}' || true")
        self.daemon_running = False

    def await_log(self, pattern: str, deadline_s: int, poll_s: float = 3.0) -> str:
        """The last log line matching `pattern`, waiting for one to appear.

        The daemon's log is the only place a delivery confirmed on the third
        attempt shows up: the client stopped listening long before, and there
        is no protocol question for "did that message ever land". It couples
        these checks to two log lines, which is worth it to tell "the mesh was
        busy" apart from "the message never arrived".
        """
        end = time.time() + deadline_s
        while True:
            out = self.ssh.run(
                f"grep -F {shlex.quote(pattern)} {self.log} | tail -1 || true").stdout.strip()
            if out:
                return out
            if time.time() >= end:
                return ""
            time.sleep(poll_s)

    def await_ack(self, expected: str, docs: list, deadline_s: int) -> tuple[bool, str]:
        """Did the ack land, and what is there to say about it.

        Prefers the push the app actually receives; falls back to the log when
        the ack outlived the client's listening window.
        """
        ack = next((d for d in docs if isinstance(d, dict) and "code" in d), {})
        if ack.get("code") == expected:
            return True, f"PUSH_SEND_CONFIRMED after {ack.get('trip_time')} ms"

        line = self.await_log(f"ack: {expected} confirmed after", deadline_s)
        m = re.search(r"confirmed after (\d+) attempt", line)
        if m:
            return True, (f"confirmed on attempt {m.group(1)} — past the client's 10 s window, "
                          f"so the retry ladder is what delivered it")
        return False, f"no ack for {expected} in {deadline_s}s, over the whole retry ladder"

    def await_radio(self, deadline_s: int) -> bool:
        """Waits for the SX1262 to report itself up in the daemon's log.

        The companion protocol has no "is the radio there" question, and the
        driver retries a rail that is powered up late, so the log is the only
        place this is visible — and a much better diagnostic than a silent
        advert phase later on.
        """
        end = time.time() + deadline_s
        while time.time() < end:
            out = self.ssh.run(f"grep -c 'sx1262: SX1262 on' {self.log} 2>/dev/null || true")
            if out.stdout.strip().isdigit() and int(out.stdout.strip()) > 0:
                return True
            time.sleep(3)
        return False

    # -- inbox ------------------------------------------------------------

    def drain_inbox(self, node: Node, wanted: str, deadline_s: int) -> list[dict]:
        """Reads messages until `wanted` turns up or time runs out.

        The daemon holds received messages until an app collects them, so this
        is not a race with the radio: it is only waiting for the packet to
        arrive. Anything else queued is returned too, so a phase can say how
        much it saw.
        """
        seen: list[dict] = []
        end = time.time() + deadline_s
        while time.time() < end:
            for doc in node.cli("sync_msgs"):
                for m in (doc if isinstance(doc, list) else [doc]):
                    if isinstance(m, dict) and m.get("text") is not None:
                        seen.append(m)
            if any(wanted in (m.get("text") or "") for m in seen):
                return seen
            time.sleep(2)
        return seen

    # -- teardown ---------------------------------------------------------

    def teardown(self) -> None:
        print()
        print(paint("[teardown]", "1;36"), flush=True)
        try:
            if self.peer_channel_set and not self.a.keep_running:
                self.peer.cli("remove_channel", str(self.a.channel_slot),
                              attempts=1, expect=False)
                print(f"  peer channel slot {self.a.channel_slot} cleared", flush=True)
        except PhaseError as e:
            self.report.note(f"could not clear the peer's channel slot: {e}")

        if self.a.keep_running:
            print("  daemon and tunnel left up. To use them:", flush=True)
            print(f"    meshcore-cli -t 127.0.0.1 -p {self.a.local_port} infos", flush=True)
            print(f"    ssh {self.a.host} tail -f {self.log}", flush=True)
            print("  and to close them:", flush=True)
            print(f"    ssh {self.a.host} \"pkill -TERM -f '{self.match}'\"", flush=True)
            print(f"    ssh -S {self.ssh.socket} -O exit {self.a.host}", flush=True)
            return

        if self.started_daemon:
            try:
                self.stop_daemon()
                print("  coreletd stopped", flush=True)
            except PhaseError as e:
                self.report.note(f"could not stop the daemon: {e}")

        if self.a.fetch_log and self.started_daemon and self.ssh.open:
            dest = os.path.join(self.a.log_dir, f"coreletd-e2e-{time.strftime('%Y%m%d-%H%M%S')}.log")
            os.makedirs(self.a.log_dir, exist_ok=True)
            text = self.ssh.run(f"cat {self.log}", timeout=120).stdout
            if text:
                with open(dest, "w") as fh:
                    fh.write(text)
                print(f"  daemon log saved to {dest}", flush=True)

        self.ssh.disconnect()
        print("  tunnel closed", flush=True)


# ---------------------------------------------------------------------------
# Phase registry
# ---------------------------------------------------------------------------

PHASES = [
    ("preflight", "tools, host and radios are all there", True),
    ("deploy", "sync the working tree and build it on the target", True),
    ("daemon", "configure, start and connect to coreletd", True),
    ("companion", "the protocol surface the phone app uses", True),
    ("advert_tx", "our advert goes out and the peer believes it", True),
    ("advert_rx", "the peer's advert reaches us and teaches a route", True),
    ("message_rx", "peer → coreletd, decrypted, stored and acked", True),
    ("message_tx", "coreletd → peer, retried until acknowledged", True),
    ("path", "a reset route falls back to flood and is relearned", True),
    ("channel", "a group message on a private channel", False),
    ("restart", "state survives a stop and start", True),
]

# preflight opens the ssh connection everything else runs over, so --only
# always drags it in; daemon comes too whenever something after it is wanted.
ALWAYS = "preflight"
NEEDS_DAEMON_AFTER = "daemon"


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Phases: " + ", ".join(name for name, _, _ in PHASES))

    p.add_argument("--host", default=os.environ.get(HOST_ENV),
                   help=f"uConsole ssh target ([user@]host). Required, or set {HOST_ENV}")
    p.add_argument("--remote-dir", default=DEFAULTS["remote_dir"],
                   help="working directory on the uConsole, under $HOME")
    p.add_argument("--peer", default=None,
                   help="BLE name, name fragment or address of the peer radio. "
                        "Omit to use the first MeshCore radio that answers")
    p.add_argument("--local-port", type=int, default=DEFAULTS["local_port"])
    p.add_argument("--remote-port", type=int, default=DEFAULTS["remote_port"])
    p.add_argument("--node-name", default=DEFAULTS["node_name"])

    radio = p.add_argument_group("radio (must match the peer exactly)")
    radio.add_argument("--freq", type=float, default=DEFAULTS["freq"])
    radio.add_argument("--bw", type=float, default=DEFAULTS["bw"])
    radio.add_argument("--sf", type=int, default=DEFAULTS["sf"])
    radio.add_argument("--cr", type=int, default=DEFAULTS["cr"])
    radio.add_argument("--tx-power", type=int, default=DEFAULTS["tx_power"])
    radio.add_argument("--spidev", default=DEFAULTS["spidev"])
    radio.add_argument("--gpiochip", default=DEFAULTS["gpiochip"])
    radio.add_argument("--irq-pin", type=int, default=DEFAULTS["irq_pin"])
    radio.add_argument("--busy-pin", type=int, default=DEFAULTS["busy_pin"])
    radio.add_argument("--reset-pin", type=int, default=DEFAULTS["reset_pin"])
    radio.add_argument("--lora-on-cmd", default=DEFAULTS["lora_on_cmd"],
                       help="remote command that powers the LoRa rail ('' to skip)")
    radio.add_argument("--lora-status-cmd", default=DEFAULTS["lora_status_cmd"])

    sel = p.add_argument_group("what to run")
    sel.add_argument("--only", action="append", default=[], metavar="PHASE",
                     help="run just this phase (repeatable); prerequisites still run")
    sel.add_argument("--skip", action="append", default=[], metavar="PHASE",
                     help="skip this phase (repeatable)")
    sel.add_argument("--list", action="store_true", help="list the phases and exit")
    sel.add_argument("--with-channel", action="store_true",
                     help="also run the channel phase, which writes a channel slot "
                          "on the peer (slot %d by default) and clears it afterwards"
                          % DEFAULTS["channel_slot"])
    sel.add_argument("--channel-slot", type=int, default=DEFAULTS["channel_slot"])
    sel.add_argument("--with-unit-tests", action="store_true",
                     help="also run ctest on the target during deploy")

    misc = p.add_argument_group("behaviour")
    misc.add_argument("--keep-state", action="store_true",
                      help="keep the contacts and channels from the last run. The node's "
                           "identity is kept either way, so the peer sees the same node")
    misc.add_argument("--keep-running", action="store_true",
                      help="leave the daemon and the tunnel up when the run finishes")
    misc.add_argument("--no-fetch-log", dest="fetch_log", action="store_false", default=True)
    misc.add_argument("--log-dir", default=os.path.join(REPO, "dist", "e2e-logs"))
    misc.add_argument("-v", "--verbose", action="store_true",
                      help="echo every ssh and meshcore-cli invocation")
    return p.parse_args(argv)


def selected_phases(args) -> list[str]:
    order = [n for n, _, _ in PHASES]
    wanted = {n for n, _, on in PHASES if on}
    if args.with_channel:
        wanted.add("channel")

    if args.only:
        unknown = set(args.only) - set(order)
        if unknown:
            raise SystemExit(f"unknown phase(s): {', '.join(sorted(unknown))}")
        wanted = set(args.only) | {ALWAYS}
        # deploy is never pulled in implicitly: a build is usually already on
        # the target, and rebuilding is the slowest thing here.
        if any(order.index(n) > order.index(NEEDS_DAEMON_AFTER) for n in args.only):
            wanted.add(NEEDS_DAEMON_AFTER)

    wanted -= set(args.skip)
    return [n for n in order if n in wanted]


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    if args.list:
        print("phases (marked * are off unless asked for):")
        for name, title, on in PHASES:
            print(f"  {' ' if on else '*'} {name:<12} {title}")
        return 0

    # No default: this names somebody's machine, and running the wrong one is
    # not a mistake to make quietly.
    if not args.host:
        raise SystemExit(f"no uConsole given: pass --host [user@]host, "
                         f"or set {HOST_ENV} in the environment")

    names = selected_phases(args)
    h = Harness(args)

    print(paint(f"coreletd hardware end-to-end test — run {h.nonce}", "1"))
    print(f"  uConsole : {args.host} (~/{args.remote_dir})")
    print(f"  peer     : {args.peer or 'first MeshCore radio found'} over BLE")
    print(f"  air      : {args.freq} MHz  BW {args.bw} kHz  SF{args.sf}  CR 4/{args.cr}")
    print(f"  phases   : {', '.join(names)}")

    interrupted = False
    try:
        for name in names:
            phase = getattr(h, f"phase_{name}")
            try:
                phase()
            except PhaseError as e:
                h.report.check(name, "phase ran", False, str(e))
                if name in (ALWAYS, NEEDS_DAEMON_AFTER):
                    h.report.note("stopping: every later phase depends on this one")
                    break
    except KeyboardInterrupt:
        interrupted = True
        print("\n" + paint("interrupted", "33;1"), flush=True)
    finally:
        try:
            h.teardown()
        except Exception as e:  # teardown must never mask the real failure
            print(f"  teardown problem: {e}", flush=True)

    status = h.report.summary()
    return 130 if interrupted else status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
