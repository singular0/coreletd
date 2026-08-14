#!/usr/bin/env python3
"""Drive coreletd over the companion TCP protocol, as the MeshCore app would."""
import socket
import struct
import sys
import time

HOST, PORT = "127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 5999

CMD_APP_START = 1
CMD_GET_CONTACTS = 4
CMD_SET_DEVICE_TIME = 6
CMD_SEND_SELF_ADVERT = 7
CMD_SYNC_NEXT_MESSAGE = 10
CMD_DEVICE_QUERY = 22
CMD_GET_CHANNEL = 31
CMD_SEND_TXT_MSG = 2

RESP = {
    0: "OK", 1: "ERR", 2: "CONTACTS_START", 3: "CONTACT", 4: "END_OF_CONTACTS",
    5: "SELF_INFO", 6: "SENT", 9: "CURR_TIME", 10: "NO_MORE_MESSAGES",
    12: "BATTERY", 13: "DEVICE_INFO", 16: "CONTACT_MSG_V3", 17: "CHANNEL_MSG_V3",
    18: "CHANNEL_INFO", 0x80: "PUSH_ADVERT", 0x81: "PUSH_PATH_UPDATED",
    0x82: "PUSH_SEND_CONFIRMED", 0x83: "PUSH_MSG_WAITING", 0x88: "PUSH_LOG_RX_DATA",
    0x8A: "PUSH_NEW_ADVERT",
}

sock = socket.create_connection((HOST, PORT), timeout=5)
buf = b""
failures = []


def send(payload):
    sock.sendall(b"<" + struct.pack("<H", len(payload)) + payload)


def recv_frames(timeout=1.0):
    """Collect every frame that arrives within `timeout`."""
    global buf
    out = []
    deadline = time.time() + timeout
    sock.settimeout(0.2)
    while time.time() < deadline:
        try:
            data = sock.recv(65536)
            if not data:
                break
            buf += data
        except socket.timeout:
            pass
        while len(buf) >= 3:
            n = struct.unpack("<H", buf[1:3])[0]
            if len(buf) < 3 + n:
                break
            out.append(buf[3:3 + n])
            buf = buf[3 + n:]
    return out


def check(cond, label, detail=""):
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{detail}]" if detail else ""))
    if not cond:
        failures.append(label)


def name_of(f):
    return RESP.get(f[0], f"0x{f[0]:02x}")


print("== APP_START ==")
send(bytes([CMD_APP_START]) + b"\0" * 7 + b"testclient")
frames = recv_frames()
self_info = next((f for f in frames if f[0] == 5), None)
check(self_info is not None, "SELF_INFO returned", ",".join(name_of(f) for f in frames))
if self_info:
    adv_type, tx_power, max_tx = self_info[1], self_info[2], self_info[3]
    pubkey = self_info[4:36].hex()
    lat, lon = struct.unpack("<ll", self_info[36:44])
    freq, bw = struct.unpack("<LL", self_info[48:56])
    sf, cr = self_info[56], self_info[57]
    name = self_info[58:].decode("utf-8", "replace")
    check(name == "uConsoleTest", "advert name", name)
    check(freq == 869618, "radio frequency (kHz)", str(freq))
    check(bw == 62500, "radio bandwidth (Hz)", str(bw))
    check((sf, cr) == (8, 8), "SF/CR", f"SF{sf} CR4/{cr}")
    check(lat == 51507400 and lon == -127800, "advertised location", f"{lat},{lon}")
    check(tx_power == 22, "tx power", str(tx_power))
    print(f"       pubkey={pubkey[:16]}...")

print("== DEVICE_QUERY ==")
send(bytes([CMD_DEVICE_QUERY, 3]))
frames = recv_frames()
di = next((f for f in frames if f[0] == 13), None)
check(di is not None, "DEVICE_INFO returned")
if di:
    model = di[20:60].rstrip(b"\0").decode()
    check(di[1] == 3, "firmware protocol version", str(di[1]))
    check("uConsole" in model, "model string", model)

print("== SET_DEVICE_TIME ==")
send(bytes([CMD_SET_DEVICE_TIME]) + struct.pack("<L", int(time.time())))
check(any(f[0] == 0 for f in recv_frames()), "time accepted")

print("== GET_CHANNEL 0 ==")
send(bytes([CMD_GET_CHANNEL, 0]))
frames = recv_frames()
ci = next((f for f in frames if f[0] == 18), None)
check(ci is not None, "CHANNEL_INFO returned")
if ci:
    ch_name = ci[2:34].rstrip(b"\0").decode()
    secret = ci[34:50].hex()
    check(ch_name == "Public", "channel 0 name", ch_name)
    check(secret == "8b3387e9c5cdea6ac9e5edbaa115cd72", "public channel key", secret)

print("== GET_CONTACTS (contact learned from replayed advert) ==")
send(bytes([CMD_GET_CONTACTS]))
frames = recv_frames()
contacts = [f for f in frames if f[0] == 3]
check(len(contacts) >= 1, "at least one contact", f"{len(contacts)} contact(s)")
if contacts:
    c = contacts[0]
    pk = c[1:33].hex()
    ctype, cflags, pathlen = c[33], c[34], c[35]
    cname = c[100:132].rstrip(b"\0").decode("utf-8", "replace")
    clat, clon = struct.unpack("<ll", c[136:144])
    check(cname == "uConsole", "contact name from advert", cname)
    check(pk.startswith("03a107"), "contact public key", pk[:12])
    check(clat == 51507400 and clon == -127800, "contact location", f"{clat},{clon}")
    print(f"       type={ctype} flags=0x{cflags:02x} pathlen={pathlen}")

print("== SYNC_NEXT_MESSAGE (text replayed from A) ==")
send(bytes([CMD_SYNC_NEXT_MESSAGE]))
frames = recv_frames()
msg = next((f for f in frames if f[0] == 16), None)
check(msg is not None, "CONTACT_MSG_V3 returned",
      ",".join(name_of(f) for f in frames))
if msg:
    snr = struct.unpack("b", msg[1:2])[0] / 4.0
    prefix = msg[4:10].hex()
    path_len, txt_type = msg[10], msg[11]
    ts = struct.unpack("<L", msg[12:16])[0]
    text = msg[16:].decode("utf-8", "replace")
    check(text == "hello mesh", "decrypted message text", repr(text))
    check(prefix.startswith("03a107"), "sender key prefix", prefix)
    check(txt_type == 0, "txt_type plain", str(txt_type))
    print(f"       snr={snr} path_len={path_len} ts={ts}")

print("== SYNC again: queue should now be empty ==")
send(bytes([CMD_SYNC_NEXT_MESSAGE]))
check(any(f[0] == 10 for f in recv_frames()), "NO_MORE_MESSAGES")

print("== SEND_SELF_ADVERT ==")
send(bytes([CMD_SEND_SELF_ADVERT, 1]))
check(any(f[0] == 0 for f in recv_frames()), "advert accepted")

print("== SEND_TXT_MSG to the learned contact ==")
if contacts:
    pk_prefix = contacts[0][1:7]
    payload = (bytes([CMD_SEND_TXT_MSG, 0, 0]) + struct.pack("<L", int(time.time()))[:4]
               + pk_prefix + b"reply from uConsole")
    # txt_type(1) attempt(1) timestamp(4) prefix(6) text
    payload = bytes([CMD_SEND_TXT_MSG, 0, 0]) + struct.pack("<L", int(time.time())) + pk_prefix + b"reply from uConsole"
    send(payload)
    frames = recv_frames()
    sent = next((f for f in frames if f[0] == 6), None)
    check(sent is not None, "SENT confirmation", ",".join(name_of(f) for f in frames))
    if sent:
        route = sent[1]
        ack = sent[2:6].hex()
        timeout_ms = struct.unpack("<L", sent[6:10])[0]
        print(f"       route={'flood' if route else 'direct'} expected_ack={ack} timeout={timeout_ms}ms")

sock.close()
print()
if failures:
    print(f"FAILED: {len(failures)} check(s): {failures}")
    sys.exit(1)
print("all companion protocol checks passed")
