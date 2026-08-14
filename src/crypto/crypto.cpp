#include "crypto/crypto.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <sodium.h>

#include "util/log.h"

namespace clt::crypto {

bool init() {
    if (sodium_init() < 0) {
        LOG_ERROR("libsodium failed to initialise");
        return false;
    }
    return true;
}

Bytes sha256(ByteView data) {
    Bytes out(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), out.data());
    return out;
}

Bytes hmac_sha256(ByteView key, ByteView data) {
    Bytes out(SHA256_DIGEST_LENGTH);
    unsigned int len = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(),
         out.data(), &len);
    out.resize(len);
    return out;
}

Bytes ack_hash(ByteView data) {
    Bytes h = sha256(data);
    h.resize(kAckHashSize);
    return h;
}

namespace {

// AES-128-ECB with padding disabled; MeshCore pads with zeroes itself and the
// receiver relies on the payload's own length fields.
bool aes128_ecb(ByteView key16, ByteView in, Bytes& out, bool encrypt) {
    if (key16.size() < kAesBlockSize || in.size() % kAesBlockSize != 0) return false;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    out.assign(in.size(), 0);
    int len = 0, total = 0;
    if (EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key16.data(), nullptr, encrypt ? 1 : 0) ==
            1 &&
        EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
        EVP_CipherUpdate(ctx, out.data(), &len, in.data(), static_cast<int>(in.size())) == 1) {
        total = len;
        if (EVP_CipherFinal_ex(ctx, out.data() + total, &len) == 1) {
            total += len;
            out.resize(static_cast<size_t>(total));
            ok = true;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

}  // namespace

Bytes encrypt_and_mac(ByteView key, ByteView plaintext) {
    Bytes padded(plaintext.begin(), plaintext.end());
    // Pad to a block multiple. A message that is already aligned gets no padding.
    size_t pad = (kAesBlockSize - (padded.size() % kAesBlockSize)) % kAesBlockSize;
    padded.insert(padded.end(), pad, 0);

    Bytes ciphertext;
    if (!aes128_ecb(key, padded, ciphertext, true)) {
        LOG_ERROR("AES encrypt failed");
        return {};
    }

    // The MAC covers the ciphertext and is keyed with the *full* shared secret,
    // while the cipher only uses its first 16 bytes.
    Bytes mac = hmac_sha256(key, ciphertext);

    Bytes out;
    out.reserve(kCipherMacSize + ciphertext.size());
    out.insert(out.end(), mac.begin(), mac.begin() + kCipherMacSize);
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    return out;
}

std::optional<Bytes> mac_and_decrypt(ByteView key, ByteView mac, ByteView ciphertext) {
    if (mac.size() < kCipherMacSize) return std::nullopt;
    if (ciphertext.empty() || ciphertext.size() % kAesBlockSize != 0) return std::nullopt;

    Bytes expect = hmac_sha256(key, ciphertext);
    if (!equal(subview(expect, 0, kCipherMacSize), subview(mac, 0, kCipherMacSize)))
        return std::nullopt;

    Bytes plaintext;
    if (!aes128_ecb(key, ciphertext, plaintext, false)) return std::nullopt;
    return plaintext;
}

void random_bytes(ByteSpan out) { randombytes_buf(out.data(), out.size()); }

bool equal(ByteView a, ByteView b) {
    if (a.size() != b.size()) return false;
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

}  // namespace clt::crypto
