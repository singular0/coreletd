#pragma once

#include <optional>

#include "util/bytes.h"

namespace clt::crypto {

inline constexpr size_t kPubKeySize = 32;
// MeshCore stores the *expanded* Ed25519 key (a, RH) — the 64-byte SHA-512 of
// the seed — not the seed and not seed||pubkey. See identity.h.
inline constexpr size_t kPrivKeySize = 64;
inline constexpr size_t kSignatureSize = 64;
inline constexpr size_t kSharedSecretSize = 32;
inline constexpr size_t kCipherMacSize = 2;
inline constexpr size_t kAckHashSize = 4;
inline constexpr size_t kAesBlockSize = 16;

// Must be called once before any other function here.
bool init();

Bytes sha256(ByteView data);
Bytes hmac_sha256(ByteView key, ByteView data);

// First 4 bytes of SHA-256, used for message acknowledgement hashes.
Bytes ack_hash(ByteView data);

// AES-128-ECB over key[0..16], zero-padded up to a block multiple, with the
// first 2 bytes of HMAC-SHA256(key, ciphertext) prepended.
// Returns mac(2) || ciphertext.
Bytes encrypt_and_mac(ByteView key, ByteView plaintext);

// Verifies the 2-byte MAC before decrypting. Returns nullopt when the MAC does
// not match, which is also how a receiver decides a packet was not for this key.
// The result still carries any zero padding the sender added; the payload
// parsers are responsible for knowing their own length.
std::optional<Bytes> mac_and_decrypt(ByteView key, ByteView mac, ByteView ciphertext);

void random_bytes(ByteSpan out);

// Constant-time compare, for MACs and passwords.
bool equal(ByteView a, ByteView b);

}  // namespace clt::crypto
