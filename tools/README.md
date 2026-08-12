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

## End-to-end test

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

./build/umeshcored --config test.ini &   # mock_radio = 1, mock_replay_file = packets.hex
sleep 10                                 # let both packets play in
python3 tools/e2e_companion_test.py 5999
```

It asserts the advert becomes a contact, the message decrypts to its expected plaintext, and the
ack hash matches the reference vector.
