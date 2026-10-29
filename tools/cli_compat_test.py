#!/usr/bin/env python3
"""meshcore-cli against coreletd, with no radio hardware.

    meshcore-cli ──TCP──▶ coreletd_sim ┄┄ simulated air ┄┄ scripted MeshCore peer

coreletd_sim is the whole daemon, built exactly as main() builds it, with the
radio swapped for one that a single simulated peer is on the air with. Every
check drives the real meshcore-cli and asserts on two things: what the client
printed, and what the peer decoded off the air. So a message typed into the
client has to arrive at the peer with the same text, an ack the peer sends has
to come back to the client as a delivery receipt, and a message the peer sends
has to come out of the client's inbox intact.

This is the companion protocol as one particular client speaks it. Wire
compatibility with real firmware is the frozen vectors' job and the hardware
test's (tools/hw_e2e_test.py); nothing here needs a uConsole or a second radio.

    tools/cli_compat_test.py                      # build/coreletd_sim, meshcore-cli on PATH
    tools/cli_compat_test.py --sim out/coreletd_sim --meshcli ~/venv/bin/meshcli
    tools/cli_compat_test.py --keep               # leave the daemon log and state behind

meshcore-cli runs with HOME pointed at a scratch directory, so neither its init
scripts nor its message log in ~/.config/meshcore are touched. Exit status is 0
only if every check passed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

# Reporting and the JSON-stream parsing are the hardware test's, so the two
# read alike and parse meshcore-cli's output the same way.
from hw_e2e_test import PhaseError, Report, json_docs, paint

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# One meshcore-cli invocation: a Python start, a TCP connect and a handful of
# round trips on loopback. Generous, because a slow machine is not a failure.
T_CLI = 30
# meshcore-cli waits this long for a reply it does not recognise — its own
# DEFAULT_TIMEOUT — so a command answered with something unexpected costs it.
T_CLI_REPLY = 15
# A transmission takes its real LoRa airtime in the simulator: about a second
# for an advert at SF8 / 62.5 kHz, less for a message.
T_AIR = 10

PUBLIC_SECRET = "8b3387e9c5cdea6ac9e5edbaa115cd72"
# The peer's frozen advert (tests/packet_vectors.h).
PEER_LAT, PEER_LON = 51.5074, -0.1278
PEER_ADVERT_TIME = 1765432100
# What the simulated radio stamps on everything it delivers.
SIM_SNR = 8.0


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Sim:
    """coreletd_sim: the daemon on stdin/stdout, its log in a file."""

    def __init__(self, binary: str, workdir: str, verbose: bool):
        self.verbose = verbose
        self.log_path = os.path.join(workdir, "daemon.log")
        state = os.path.join(workdir, "state")
        os.mkdir(state, 0o700)
        self.port = free_port()
        self.events: list[dict] = []
        self.cond = threading.Condition()
        self.log = open(self.log_path, "w")
        self.proc = subprocess.Popen(
            [binary, "--state-dir", state, "--port", str(self.port), "--log-level", "debug"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log,
            text=True, encoding="utf-8", errors="replace", bufsize=1)
        threading.Thread(target=self._read, daemon=True).start()
        self.ready = self.await_event(lambda e: e["event"] == "ready", 10, since=0)
        if self.ready is None:
            self.stop()
            raise PhaseError(f"coreletd_sim did not come up; see {self.log_path}")

    def _read(self) -> None:
        for line in self.proc.stdout:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if self.verbose:
                print(paint(f"    sim: {line.strip()}", "90"), flush=True)
            with self.cond:
                self.events.append(event)
                self.cond.notify_all()

    def send(self, command: str) -> None:
        if self.verbose:
            print(paint(f"    sim< {command}", "90"), flush=True)
        self.proc.stdin.write(command + "\n")
        self.proc.stdin.flush()

    def mark(self) -> int:
        with self.cond:
            return len(self.events)

    def await_event(self, match, timeout: float, since: int) -> dict | None:
        """The first event after `since` that `match` accepts."""
        end = time.time() + timeout
        with self.cond:
            while True:
                for e in self.events[since:]:
                    if match(e):
                        return e
                left = end - time.time()
                if left <= 0 or self.proc.poll() is not None:
                    return None
                self.cond.wait(left)

    def tell(self, command: str, sent_type: str) -> dict:
        """Has the peer put something on the air, and waits until it has.

        The daemon handles the packet in the same loop iteration that delivers
        it, so once the peer reports it sent, the daemon has acted on it.
        """
        mark = self.mark()
        self.send(command)
        event = self.await_event(
            lambda e: e["event"] == "sent" and e["type"] == sent_type, 5, mark)
        if event is None:
            raise PhaseError(f"the simulated peer did not send its {sent_type}")
        return event

    def heard(self, kind: str, since: int, timeout: float = T_AIR, **fields) -> dict:
        """What the peer decoded of the daemon's next `kind` transmission."""
        return self.await_event(
            lambda e: e["event"] == "heard" and e["type"] == kind
            and all(e.get(k) == v for k, v in fields.items()),
            timeout, since) or {}

    def stop(self) -> None:
        if self.proc.poll() is None:
            try:
                self.send("quit")
                self.proc.stdin.close()
                self.proc.wait(5)
            except (OSError, subprocess.TimeoutExpired):
                self.proc.kill()
                self.proc.wait()
        self.log.close()


class Cli:
    """meshcore-cli in JSON mode, pointed at the simulator."""

    def __init__(self, exe: str, port: int, home: str, verbose: bool):
        self.argv = [exe, "-j", "-t", "127.0.0.1", "-p", str(port)]
        self.verbose = verbose
        # Its config directory is under HOME, and it runs the init scripts it
        # finds there and appends every message to a log beside them.
        # Unbuffered, so a background run's output can be read as it comes.
        self.env = dict(os.environ, HOME=home, PYTHONUNBUFFERED="1")

    def _show(self, cmds) -> None:
        if self.verbose:
            print(paint(f"    cli: {' '.join(str(c) for c in cmds)}", "90"), flush=True)

    def run(self, *cmds, timeout: float = T_CLI) -> tuple[list, str, float]:
        """The JSON documents printed, all of the text, and how long it took."""
        self._show(cmds)
        start = time.time()
        try:
            r = subprocess.run(self.argv + [str(c) for c in cmds], env=self.env,
                               stdin=subprocess.DEVNULL, capture_output=True,
                               text=True, timeout=timeout)
            out, err = r.stdout, r.stderr
        except subprocess.TimeoutExpired as e:
            out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
            err = f"[timed out after {timeout:.0f}s]"
        text = out + err
        if self.verbose and text.strip():
            for line in text.strip().splitlines()[-12:]:
                print(paint(f"      {line}", "90"), flush=True)
        return json_docs(out), text, time.time() - start

    def docs(self, *cmds, **kw) -> list:
        return self.run(*cmds, **kw)[0]

    def start(self, *cmds) -> subprocess.Popen:
        self._show(cmds)
        return subprocess.Popen(self.argv + [str(c) for c in cmds], env=self.env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)


def first(docs: list, key: str) -> dict:
    return next((d for d in docs if isinstance(d, dict) and key in d), {})


def first_list(docs: list) -> list:
    return next((d for d in docs if isinstance(d, list)), [])


def card_key(uri: str) -> str | None:
    """The public key in a contact card, which is an advert packet in hex."""
    try:
        raw = bytes.fromhex(uri.removeprefix("meshcore://"))
    except ValueError:
        return None
    if len(raw) < 2 or (raw[0] >> 2) & 0x0F != 0x04:  # not an advert
        return None
    hops, hash_size = raw[1] & 0x3F, (raw[1] >> 6) + 1
    payload = raw[2 + hops * hash_size:]
    return payload[:32].hex() if len(payload) >= 32 else None


class Harness:
    def __init__(self, args, workdir: str):
        self.report = Report()
        self.sim = Sim(args.sim, workdir, args.verbose)
        home = os.path.join(workdir, "home")
        os.mkdir(home, 0o700)
        self.cli = Cli(args.meshcli, self.sim.port, home, args.verbose)
        r = self.sim.ready
        self.key, self.name, self.version = r["key"], r["name"], r["version"]
        self.peer_key, self.peer_name = r["peer_key"], r["peer_name"]
        self.max_channels = 0
        self.serial = 0

    def tag(self, what: str) -> str:
        # Distinct texts, so no check can be satisfied by an earlier one, and
        # non-ASCII, so UTF-8 has to survive the whole way.
        self.serial += 1
        return f"{what} #{self.serial} — ünïcode ✓"

    def banner(self, phase: str, title: str) -> None:
        print()
        print(paint(f"[{phase}]", "1") + f" {title}", flush=True)

    def contact(self) -> dict:
        contacts = first(self.cli.docs("contacts"), self.peer_key)
        return contacts.get(self.peer_key, {})

    # -----------------------------------------------------------------------

    def phase_connect(self) -> None:
        self.banner("connect", "APP_START, DEVICE_QUERY and the clock")
        c = self.report.check
        docs = self.cli.docs("infos", "ver", "clock")
        info, ver, clock = first(docs, "public_key"), first(docs, "fw ver"), first(docs, "time")
        if not docs:
            raise PhaseError("meshcore-cli printed nothing; is it connecting at all?")

        c("connect", "SELF_INFO names the node",
          info.get("name") == self.name and info.get("public_key") == self.key,
          f"{info.get('name')!r} {info.get('public_key', '')[:12]}")
        c("connect", "SELF_INFO carries the radio settings",
          abs(float(info.get("radio_freq", 0)) - 869.618) < 0.0005
          and info.get("radio_bw") == 62.5 and info.get("radio_sf") == 8
          and info.get("radio_cr") == 5 and info.get("tx_power") == 22,
          f"{info.get('radio_freq')} MHz BW{info.get('radio_bw')} SF{info.get('radio_sf')} "
          f"CR{info.get('radio_cr')} {info.get('tx_power')} dBm")
        # The field is 20 bytes, and MeshCore keeps a NUL in it, so a dev build's
        # describe output is cut short; what is there has to be ours.
        shown = ver.get("ver") or ""
        c("connect", "DEVICE_INFO reports the daemon's version",
          len(shown) >= min(len(self.version), 19) and self.version.startswith(shown)
          and int(ver.get("fw ver", 0)) >= 3,
          f"{ver.get('model')!r} {shown!r} of {self.version!r} (protocol v{ver.get('fw ver')})")
        self.max_channels = int(ver.get("max_channels", 0))
        c("connect", "DEVICE_INFO reports table sizes",
          int(ver.get("max_contacts", 0)) > 0 and self.max_channels > 0,
          f"{ver.get('max_contacts')} contacts, {ver.get('max_channels')} channels")
        skew = abs(int(clock.get("time", 0)) - int(time.time()))
        c("connect", "the clock reads wall time", skew <= 5, f"{skew} s off")

    def phase_contacts(self) -> None:
        self.banner("contacts", "a peer's advert, as the client lists it")
        c = self.report.check
        self.sim.tell("advert", "advert")
        peer = self.contact()

        c("contacts", "the peer is listed under its key", peer.get("adv_name") == self.peer_name,
          f"{peer.get('adv_name')!r} {self.peer_key[:12]}")
        c("contacts", "as a chat node", peer.get("type") == 1, f"type {peer.get('type')}")
        c("contacts", "at the advertised position, west longitude included",
          abs(float(peer.get("adv_lat", 0)) - PEER_LAT) < 1e-6
          and abs(float(peer.get("adv_lon", 0)) - PEER_LON) < 1e-6,
          f"{peer.get('adv_lat')}, {peer.get('adv_lon')}")
        c("contacts", "with the advert's own timestamp",
          peer.get("last_advert") == PEER_ADVERT_TIME, f"{peer.get('last_advert')}")
        # An advert is not a route: MeshCore takes one only from a returned path.
        c("contacts", "and no route, so sends to it flood", peer.get("out_path_len") == -1,
          f"out_path_len {peer.get('out_path_len')}")

    def phase_inbox(self) -> None:
        self.banner("inbox", "messages that arrived with no client connected")
        c = self.report.check
        direct, group = self.tag("waiting"), self.tag("waiting on Public")
        self.sim.tell(f"text {direct}", "text")
        self.sim.tell(f"channel {group}", "channel")

        msgs = first_list(self.cli.docs("sync_msgs"))
        priv = next((m for m in msgs if m.get("type") == "PRIV"), {})
        chan = next((m for m in msgs if m.get("type") == "CHAN"), {})
        c("inbox", "the direct message comes out intact", priv.get("text") == direct,
          repr(priv.get("text")))
        c("inbox", "attributed to the peer", priv.get("pubkey_prefix") == self.peer_key[:12],
          f"from {priv.get('pubkey_prefix')}")
        c("inbox", "with its sender's timestamp",
          abs(int(priv.get("sender_timestamp", 0)) - time.time()) < 60,
          f"{priv.get('sender_timestamp')}")
        # The V3 frames are the ones that carry signal quality.
        c("inbox", "and the SNR it was heard at", priv.get("SNR") == SIM_SNR,
          f"SNR {priv.get('SNR')}")
        c("inbox", "the channel message comes out on slot 0, sender named",
          chan.get("channel_idx") == 0 and chan.get("text") == f"{self.peer_name}: {group}",
          f"slot {chan.get('channel_idx')}: {chan.get('text')!r}")

        again = first_list(self.cli.docs("sync_msgs"))
        c("inbox", "collected messages are gone from the daemon", again == [],
          f"{len(again)} left")

    def phase_live(self) -> None:
        self.banner("live", "a message arriving while the client listens")
        c = self.report.check
        body = self.tag("live")
        # sync_msgs prints its closing bracket once the inbox is empty, and
        # trywait_msg is listening for PUSH_MSG_WAITING from then on. Sending any
        # earlier would leave the message to be collected as a waiting one.
        proc = self.cli.start("sync_msgs", "trywait_msg", "15")
        lines: queue.Queue = queue.Queue()
        threading.Thread(target=lambda: [lines.put(l) for l in proc.stdout] + [lines.put(None)],
                         daemon=True).start()
        output, listening, end = [], False, time.time() + T_CLI
        while not listening and time.time() < end:
            try:
                line = lines.get(timeout=max(0.1, end - time.time()))
            except queue.Empty:
                break
            if line is None:
                break
            output.append(line)
            listening = line.strip().endswith("]")
        if listening:
            self.sim.tell(f"text {body}", "text")
        try:
            proc.wait(T_CLI)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        while (line := lines.get()) is not None:
            output.append(line)

        got = first(json_docs("".join(output)), "text")
        c("live", "the client was listening", listening,
          "" if listening else "sync_msgs never finished: " + " / ".join(output[-3:])[:200])
        c("live", "the push woke it and the message came through", got.get("text") == body,
          repr(got.get("text")))

    def phase_direct(self) -> None:
        self.banner("direct", "a direct message out, and its ack back")
        c = self.report.check
        body = self.tag("direct")
        mark = self.sim.mark()
        docs = self.cli.docs("msg", self.peer_name, body, "wait_ack", "wait_ack")
        sent, ack = first(docs, "expected_ack"), first(docs, "code")
        heard = self.sim.heard("text", mark)

        c("direct", "MSG_SENT reports a flood send, with no route yet",
          bool(sent.get("expected_ack")) and sent.get("type") == 1,
          f"type {sent.get('type')}, expected ack {sent.get('expected_ack')}")
        c("direct", "the peer decrypted exactly what was typed", heard.get("text") == body,
          repr(heard.get("text")))
        c("direct", "the ack the client expects is the one the peer computes",
          bool(heard.get("ack")) and heard.get("ack") == sent.get("expected_ack"),
          f"peer {heard.get('ack')}, client {sent.get('expected_ack')}")
        c("direct", "the peer's ack reached the client as PUSH_SEND_CONFIRMED",
          bool(ack.get("code")) and ack.get("code") == sent.get("expected_ack"),
          f"code {ack.get('code')}")

    def phase_channel(self) -> None:
        self.banner("channel", "a message on the Public channel")
        c = self.report.check
        body = self.tag("channel")
        mark = self.sim.mark()
        self.cli.docs("chan", "0", body)
        heard = self.sim.heard("channel", mark)
        c("channel", "the peer read it on Public, under our name",
          heard.get("channel") == "Public" and heard.get("text") == f"{self.name}: {body}",
          repr(heard.get("text")))

    def phase_channels(self) -> None:
        self.banner("channels", "reading and writing channel slots")
        c = self.report.check
        slots = first_list(self.cli.docs("get_channels"))
        public = next((s for s in slots if s.get("channel_idx") == 0), {})
        c("channels", "slot 0 is Public, with the well-known secret",
          public.get("channel_name") == "Public" and public.get("channel_secret") == PUBLIC_SECRET,
          f"{public.get('channel_name')!r} {public.get('channel_secret')}")
        # meshcore-cli asks for slots until one is refused, so the count is
        # where the daemon stops answering.
        c("channels", "every slot DEVICE_INFO promised, and no more",
          len(slots) == self.max_channels, f"{len(slots)} of {self.max_channels}")

        name = "#compat"
        self.cli.run("set_channel", "1", name)
        slots = first_list(self.cli.docs("get_channels"))
        slot = next((s for s in slots if s.get("channel_idx") == 1), {})
        want = hashlib.sha256(name.encode()).digest()[:16].hex()
        c("channels", "a hashtag channel set from the client reads back",
          slot.get("channel_name") == name and slot.get("channel_secret") == want,
          f"{slot.get('channel_name')!r} {slot.get('channel_secret')}")

        self.cli.run("remove_channel", "1")
        slots = first_list(self.cli.docs("get_channels"))
        slot = next((s for s in slots if s.get("channel_idx") == 1), {})
        c("channels", "and removing it empties the slot", slot.get("channel_name") == "",
          f"{slot.get('channel_name')!r}")

    def phase_adverts(self) -> None:
        self.banner("adverts", "our advert, zero-hop and flooded, and our card")
        c = self.report.check
        for cmd, route in (("advert", "direct"), ("floodadv", "flood")):
            mark = self.sim.mark()
            self.cli.docs(cmd)
            heard = self.sim.heard("advert", mark)
            c("adverts", f"`{cmd}` goes out {'zero-hop' if route == 'direct' else 'flooded'}, "
              "signed, as us",
              heard.get("route") == route and heard.get("verified") is True
              and heard.get("key") == self.key and heard.get("name") == self.name,
              f"{heard.get('route')}, verified={heard.get('verified')}, {heard.get('name')!r}")

        uri = first(self.cli.docs("card"), "uri").get("uri", "")
        c("adverts", "`card` is an advert for our key", card_key(uri) == self.key,
          f"{uri[:40]}… ({len(uri)} chars)" if uri else "no uri")

    def phase_time(self) -> None:
        self.banner("time", "setting the clock from the client")
        c = self.report.check
        target = int(time.time()) + 3600
        clock = first(self.cli.docs("time", target, "clock"), "time")
        c("time", "the clock follows SET_DEVICE_TIME", abs(int(clock.get("time", 0)) - target) <= 3,
          f"{int(clock.get('time', 0)) - target:+d} s from what was set")
        self.cli.run("time", int(time.time()))

    def phase_routes(self) -> None:
        self.banner("routes", "a returned path, used, and reset")
        c = self.report.check
        self.sim.tell("path 8f", "path")
        peer = self.contact()
        c("routes", "the route the peer returned is on its contact",
          peer.get("out_path_len") == 1 and peer.get("out_path") == "8f"
          and peer.get("out_path_hash_mode") == 0,
          f"{peer.get('out_path_len')} hop(s) {peer.get('out_path')!r}")

        mark = self.sim.mark()
        sent = first(self.cli.docs("msg", self.peer_name, self.tag("routed"), "wait_ack"),
                     "expected_ack")
        heard = self.sim.heard("text", mark)
        c("routes", "a message now goes direct along it",
          sent.get("type") == 0 and heard.get("route") == "direct" and heard.get("hops") == 1,
          f"MSG_SENT type {sent.get('type')}, heard {heard.get('route')} "
          f"with {heard.get('hops')} hop(s)")

        self.cli.run("reset_path", self.peer_name)
        c("routes", "reset_path puts it back to flood", self.contact().get("out_path_len") == -1)

    def phase_refusals(self) -> None:
        self.banner("refusals", "what the daemon does not do, and how it says so")
        c = self.report.check

        for what, cmds in (("telemetry", ("self_telemetry",)), ("flood scope", ("scope", "#x"))):
            _, text, took = self.cli.run(*cmds)
            c("refusals", f"{what} is refused at once", took < T_CLI_REPLY - 5 and "rror" in text,
              f"{took:.1f} s: {text.strip().splitlines()[-1][:80] if text.strip() else ''}")

    def phase_settings(self) -> None:
        self.banner("settings", "what an app may change, applied at once")
        c = self.report.check

        def infos() -> dict:
            return first(self.cli.docs("infos"), "public_key")

        _, text, took = self.cli.run("set", "name", "renamed")
        info = infos()
        c("settings", "a name change is applied", "Error" not in text
          and info.get("name") == "renamed", f"{info.get('name')!r} in {took:.1f} s")
        # Not advertised by itself, as MeshCore does not; the next one has it.
        mark = self.sim.mark()
        self.cli.docs("floodadv")
        heard = self.sim.heard("advert", mark)
        c("settings", "the next advert carries the new name",
          heard.get("name") == "renamed" and heard.get("verified") is True,
          f"{heard.get('name')!r}, verified={heard.get('verified')}")

        _, text, _ = self.cli.run("set", "tx", "20")
        info = infos()
        c("settings", "TX power is applied", "Error" not in text and info.get("tx_power") == 20,
          f"tx_power {info.get('tx_power')} of {info.get('max_tx_power')}")

        _, text, _ = self.cli.run("set", "coords", "51.5074,-0.1278")
        info = infos()
        lat, lon = float(info.get("adv_lat", 0)), float(info.get("adv_lon", 0))
        c("settings", "a position is applied", "Error" not in text
          and abs(lat - 51.5074) < 1e-6 and abs(lon + 0.1278) < 1e-6, f"{lat}, {lon}")

        # With a position the advert has 23 bytes for the name, and a longer
        # one is refused rather than cut.
        _, text, _ = self.cli.run("set", "name", "x" * 24)
        info = infos()
        c("settings", "a name the advert cannot carry is refused",
          "Error" in text and info.get("name") == "renamed", f"still {info.get('name')!r}")

        _, text, _ = self.cli.run("set", "radio", "869.525,250,11,5")
        info = infos()
        radio = (info.get("radio_freq"), info.get("radio_bw"), info.get("radio_sf"),
                 info.get("radio_cr"))
        c("settings", "radio parameters are applied",
          "Error" not in text and radio == (869.525, 250.0, 11, 5), f"{radio}")

        # Repeat is MeshCore's to the letter: only at 433, 869.495 and 918 MHz.
        _, text, _ = self.cli.run("set", "radio", "869.525,250,11,5,on")
        c("settings", "repeat off MeshCore's frequencies is refused", "Error" in text,
          text.strip().splitlines()[-1][:80] if text.strip() else "")

        # Back to how the sim started, so nothing after this depends on order.
        for cmd in (("set", "radio", "869.618,62.5,8,5"), ("set", "tx", "22"),
                    ("set", "coords", "0,0"), ("set", "name", self.name)):
            self.cli.run(*cmd)
        info = infos()
        c("settings", "and all of it can be put back",
          info.get("name") == self.name and info.get("radio_freq") == 869.618
          and info.get("tx_power") == 22 and float(info.get("adv_lat", 1)) == 0,
          f"{info.get('name')!r} {info.get('radio_freq')} MHz {info.get('tx_power')} dBm")

    def phase_remove(self) -> None:
        self.banner("remove", "forgetting a contact")
        self.cli.run("remove_contact", self.peer_name)
        left = self.contact()
        self.report.check("remove", "the peer is gone from the contact list", left == {},
                          f"still listed as {left.get('adv_name')!r}" if left else "")

    PHASES = ["connect", "contacts", "inbox", "live", "direct", "channel", "channels",
              "adverts", "time", "routes", "refusals", "settings", "remove"]

    def run(self) -> int:
        try:
            for phase in self.PHASES:
                try:
                    getattr(self, f"phase_{phase}")()
                except PhaseError as e:
                    self.report.check(phase, "phase ran", False, str(e))
                    if phase == "connect":
                        break
        finally:
            self.sim.stop()
        return self.report.summary()


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run meshcore-cli against coreletd on a simulated radio.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--sim", default=os.path.join(REPO, "build", "coreletd_sim"),
                   help="the coreletd_sim binary (default: build/coreletd_sim)")
    p.add_argument("--meshcli", default="meshcore-cli",
                   help="the meshcore-cli executable (default: meshcore-cli on PATH)")
    p.add_argument("--keep", action="store_true",
                   help="keep the scratch directory: the daemon log and its state")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="show each command, its output, and what the peer heard")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if not os.access(args.sim, os.X_OK):
        print(f"no simulator at {args.sim}; build it with `cmake --build build`", file=sys.stderr)
        return 2
    if shutil.which(args.meshcli) is None:
        print(f"{args.meshcli} not found; `pipx install meshcore-cli`, or pass --meshcli",
              file=sys.stderr)
        return 2

    workdir = tempfile.mkdtemp(prefix="coreletd-cli-compat-")
    status = 1
    try:
        harness = Harness(args, workdir)
        print(f"coreletd {harness.version} as {harness.name!r} on 127.0.0.1:{harness.sim.port}, "
              f"against {shutil.which(args.meshcli)}")
        status = harness.run()
    except PhaseError as e:
        print(paint(f"cannot run: {e}", "31;1"), file=sys.stderr)
    except KeyboardInterrupt:
        status = 130
    finally:
        if args.keep or status != 0:
            print(f"daemon log and state kept in {workdir}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
