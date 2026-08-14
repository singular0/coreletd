#pragma once

#include <array>
#include <optional>
#include <string>

#include "crypto/crypto.h"
#include "util/bytes.h"

namespace clt::crypto {

using PubKey = std::array<uint8_t, kPubKeySize>;
using PrivKey = std::array<uint8_t, kPrivKeySize>;

// MeshCore's private key is the *expanded* Ed25519 key: SHA-512(seed) split
// into (a, RH), with `a` clamped. The seed is discarded at generation time and
// is not recoverable, so no standard Ed25519 API accepts this format — signing
// is assembled here from libsodium's scalar primitives instead.
//
// Layout: priv[0..32] = a (clamped scalar), priv[32..64] = RH (nonce prefix).
class LocalIdentity {
public:
    // Regenerates until the public key's first byte is usable: 0x00 and 0xff
    // are reserved node IDs in MeshCore and must not be self-assigned.
    static LocalIdentity generate();

    // Accepts the 64-byte expanded key, or 96 bytes as pub(32)||priv(64) —
    // the latter is what MeshCore's identity blob looks like, so keys can be
    // imported from an existing node. The public key is always recomputed and,
    // for the 96-byte form, checked against the stored one.
    static std::optional<LocalIdentity> from_bytes(ByteView key);

    // Text file holding the private key as 128 hex characters. Also accepts a
    // raw binary 64/96-byte file. Written 0600. A missing file returns nullopt
    // with `error` empty; every other failure describes the problem in `error`.
    static std::optional<LocalIdentity> load(const std::string& path, std::string& error);
    bool save(const std::string& path) const;

    ByteView pub() const { return pub_; }
    ByteView priv() const { return priv_; }
    // The node "hash"/ID other nodes address us by: first byte of the pubkey.
    uint8_t id() const { return pub_[0]; }

    Bytes sign(ByteView msg) const;

    // X25519 on the Ed25519 keys: our clamped scalar against the peer's public
    // key converted from Edwards-Y to Montgomery-U. Returns the raw 32-byte
    // ladder output with no KDF — that value is the encryption key directly.
    // nullopt when the peer key is not a usable curve point.
    std::optional<Bytes> shared_secret(ByteView peer_pub) const;

private:
    PubKey pub_ {};
    PrivKey priv_ {};
};

bool verify(ByteView pub, ByteView msg, ByteView sig);

}  // namespace clt::crypto
