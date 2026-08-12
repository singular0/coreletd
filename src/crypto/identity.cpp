#include "crypto/identity.h"

#include <sodium.h>
#include <sys/stat.h>

#include <cstdio>
#include <cerrno>
#include <cstring>
#include <fstream>

#include "util/hex.h"
#include "util/log.h"

namespace umc::crypto {

namespace {

void clamp_scalar(uint8_t a[32]) {
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
}

// Reduce a 32-byte scalar mod L by zero-extending to the 64-byte input that
// libsodium's reduce expects. `a` is clamped and can exceed L; every use of it
// here is inside the order-L group, so reducing first changes nothing.
void reduce32(const uint8_t in[32], uint8_t out[32]) {
    uint8_t wide[64] = {0};
    memcpy(wide, in, 32);
    crypto_core_ed25519_scalar_reduce(out, wide);
}

}  // namespace

LocalIdentity LocalIdentity::generate() {
    LocalIdentity id;
    for (;;) {
        uint8_t seed[32];
        randombytes_buf(seed, sizeof(seed));

        uint8_t expanded[64];
        crypto_hash_sha512(expanded, seed, sizeof(seed));
        sodium_memzero(seed, sizeof(seed));

        clamp_scalar(expanded);
        memcpy(id.priv_.data(), expanded, 64);
        sodium_memzero(expanded, sizeof(expanded));

        if (crypto_scalarmult_ed25519_base_noclamp(id.pub_.data(), id.priv_.data()) != 0) continue;
        if (id.pub_[0] != 0x00 && id.pub_[0] != 0xff) break;
        LOG_DEBUG("identity: drew reserved node id 0x%02x, regenerating", id.pub_[0]);
    }
    return id;
}

std::optional<LocalIdentity> LocalIdentity::from_bytes(ByteView key) {
    ByteView priv;
    ByteView claimed_pub;
    if (key.size() == kPrivKeySize) {
        priv = key;
    } else if (key.size() == kPubKeySize + kPrivKeySize) {
        claimed_pub = key.subspan(0, kPubKeySize);
        priv = key.subspan(kPubKeySize, kPrivKeySize);
    } else {
        LOG_ERROR("identity: expected %zu or %zu bytes, got %zu", kPrivKeySize,
                  kPubKeySize + kPrivKeySize, key.size());
        return std::nullopt;
    }

    LocalIdentity id;
    memcpy(id.priv_.data(), priv.data(), kPrivKeySize);
    // MeshCore stores `a` already clamped, but a hand-edited or foreign key
    // might not be; clamping an already-clamped scalar is a no-op.
    clamp_scalar(id.priv_.data());

    if (crypto_scalarmult_ed25519_base_noclamp(id.pub_.data(), id.priv_.data()) != 0) {
        LOG_ERROR("identity: private key does not yield a valid public key");
        return std::nullopt;
    }
    if (!claimed_pub.empty() && !equal(claimed_pub, id.pub_)) {
        LOG_ERROR("identity: stored public key %s does not match private key (derived %s)",
                  hex_prefix(claimed_pub).c_str(), hex_prefix(id.pub_).c_str());
        return std::nullopt;
    }
    return id;
}

std::optional<LocalIdentity> LocalIdentity::load(const std::string& path, std::string& error) {
    error.clear();
    errno = 0;
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        if (errno != ENOENT)
            error = "cannot open " + path + ": " + std::strerror(errno ? errno : EIO);
        return std::nullopt;
    }

    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (in.bad()) {
        error = "cannot read " + path;
        return std::nullopt;
    }
    // Trim trailing whitespace so a hand-edited hex file with a newline works.
    while (!raw.empty() && (raw.back() == '\n' || raw.back() == '\r' || raw.back() == ' '))
        raw.pop_back();

    std::optional<LocalIdentity> id;
    if (auto bin = unhex(raw)) {
        id = from_bytes(*bin);
    } else {
        id = from_bytes(ByteView(reinterpret_cast<const uint8_t*>(raw.data()), raw.size()));
    }
    if (!id) error = "invalid identity file " + path;
    return id;
}

bool LocalIdentity::save(const std::string& path) const {
    std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            LOG_ERROR("identity: cannot write %s", tmp.c_str());
            return false;
        }
        out << hex(priv_) << "\n";
        if (!out) {
            LOG_ERROR("identity: write to %s failed", tmp.c_str());
            return false;
        }
    }
    // The private key must never be group- or world-readable.
    if (chmod(tmp.c_str(), S_IRUSR | S_IWUSR) != 0) {
        LOG_ERROR("identity: cannot chmod %s", tmp.c_str());
        ::remove(tmp.c_str());
        return false;
    }
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        LOG_ERROR("identity: cannot rename %s -> %s", tmp.c_str(), path.c_str());
        ::remove(tmp.c_str());
        return false;
    }
    return true;
}

Bytes LocalIdentity::sign(ByteView msg) const {
    const uint8_t* a = priv_.data();
    const uint8_t* rh = priv_.data() + 32;

    // r = SHA512(RH || M) mod L
    crypto_hash_sha512_state st;
    uint8_t wide[64];
    uint8_t r[32];
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, rh, 32);
    crypto_hash_sha512_update(&st, msg.data(), msg.size());
    crypto_hash_sha512_final(&st, wide);
    crypto_core_ed25519_scalar_reduce(r, wide);

    // R = r * B
    Bytes sig(kSignatureSize, 0);
    if (crypto_scalarmult_ed25519_base_noclamp(sig.data(), r) != 0) {
        LOG_ERROR("identity: signing failed (degenerate nonce)");
        return {};
    }

    // k = SHA512(R || A || M) mod L
    uint8_t k[32];
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, sig.data(), 32);
    crypto_hash_sha512_update(&st, pub_.data(), 32);
    crypto_hash_sha512_update(&st, msg.data(), msg.size());
    crypto_hash_sha512_final(&st, wide);
    crypto_core_ed25519_scalar_reduce(k, wide);

    // S = r + k*a mod L
    uint8_t a_red[32], ka[32], s[32];
    reduce32(a, a_red);
    crypto_core_ed25519_scalar_mul(ka, k, a_red);
    crypto_core_ed25519_scalar_add(s, r, ka);
    memcpy(sig.data() + 32, s, 32);

    sodium_memzero(wide, sizeof(wide));
    sodium_memzero(r, sizeof(r));
    sodium_memzero(a_red, sizeof(a_red));
    return sig;
}

std::optional<Bytes> LocalIdentity::shared_secret(ByteView peer_pub) const {
    if (peer_pub.size() < kPubKeySize) return std::nullopt;

    // Edwards-Y to Montgomery-U: u = (1 + y) / (1 - y).
    uint8_t curve_pub[crypto_scalarmult_curve25519_BYTES];
    if (crypto_sign_ed25519_pk_to_curve25519(curve_pub, peer_pub.data()) != 0) {
        LOG_DEBUG("identity: peer key %s is not a usable curve point",
                  hex_prefix(peer_pub).c_str());
        return std::nullopt;
    }

    Bytes out(kSharedSecretSize);
    // libsodium clamps the scalar exactly as MeshCore does, and rejects an
    // all-zero (small-order) result.
    if (crypto_scalarmult_curve25519(out.data(), priv_.data(), curve_pub) != 0) {
        LOG_DEBUG("identity: shared secret with %s degenerate", hex_prefix(peer_pub).c_str());
        return std::nullopt;
    }
    return out;
}

bool verify(ByteView pub, ByteView msg, ByteView sig) {
    if (pub.size() < kPubKeySize || sig.size() < kSignatureSize) return false;
    return crypto_sign_verify_detached(sig.data(), msg.data(), msg.size(), pub.data()) == 0;
}

}  // namespace umc::crypto
