# Changelog for 0.x

## 0.1.1

### New functionality

* Peers are now told how to reach this node: a flood-routed message is answered with a returned
  path carrying the reciprocal route, with the acknowledgement bundled inside it, so a peer that
  could only flood at us can address us directly
* Receptions the modem could not decode are counted, summarised periodically, and logged with the
  signal they failed at, which is what separates a receiver that has gone deaf from an idle band
* Received messages are held in a state file and survive a restart, since the daemon acknowledges a
  message as soon as it decrypts it and no sender will offer it again

### Changes

* The LoRa preamble follows the spreading factor as MeshCore does — 32 symbols at SF8 and below, 16
  above — and `lora_preamble` becomes an override rather than the source of truth
* The default coding rate is now 4/5, MeshCore's own default; 4/8 costs roughly 35% more airtime per
  packet, on every repeater that forwards one as well as here
* The radio's startup line reports the preamble in use, since a derived setting appears nowhere in
  the config file to be compared against a neighbour's

### Bugfixes

* A received message's path length is reported the way MeshCore reports it — `0xFF` for a direct
  message and the packed path byte for a flood-routed one — rather than the two being inverted, and
  a direct message no longer claims zero hops by flood
* A sender working through its retry ladder no longer has its message handed to the app up to four
  times; every copy is still acknowledged, since the retries mean the acknowledgement was not heard
* Acknowledgements carry MeshCore's full six-byte payload and cover the same hashed region, so a
  second acknowledgement for one message is no longer identical to the first and dropped as a
  duplicate by every repeater in between
* Low-data-rate optimisation is derived from the symbol time instead of being hardcoded off, which
  is the difference between a working link and silence in both directions at SF10-12 on the narrow
  bandwidths the config accepts
* An advert name longer than MeshCore verifies is refused at startup, instead of producing adverts
  whose signature cannot match and a node that never appears on the mesh
* A state file that cannot be parsed is quarantined and recovered from the copy taken before the
  last save, instead of being replaced by an empty one — the keys in it are what let the daemon read
  anything the mesh sends
* Transmissions wait for a clear channel rather than keying up over a reception in progress, which
  destroyed the packet being received and corrupted the sender's for every node in range
* Packets carrying a payload version above v1, and packets with no payload at all, are refused
  rather than mis-parsed, and TRACE packets are deduplicated as MeshCore does them, so a trace whose
  route revisits this node is not suppressed and returned truncated
* The SX1262 applies the errata 15.1 workaround, which `lora_bw = 500` needs, and airtime accounting
  uses the longer sync interval at SF5 and SF6, so the duty-cycle budget matches what is on the air

## 0.1.0

### New functionality

* Initial release: a MeshCore companion node for the ClockworkPi uConsole with a HackerGadgets AIO
  v2, running as a system daemon
* Speaks the MeshCore companion protocol over a Unix domain socket, with TCP as the explicit
  network opt-in
* Drives the SX1262 over spidev and libgpiod, treating an unpowered LoRa rail as a normal state to
  retry rather than a startup failure
* Signed adverts, encrypted direct messages with a retry ladder, group channels, route learning and
  flood repeating, with contacts, channels and node identity persisted across restarts
* Paces every transmission against a configurable duty-cycle budget
* Ships as a Debian package with a systemd unit, udev rules and its own user, deliberately not
  enabled on install
