// Validates the crypto layer against the frozen reference vectors in
// tests/vectors.h. If these pass, our packets are byte-compatible with the rest
// of the MeshCore network.

#include "crypto/crypto.h"
#include "crypto/identity.h"
#include "tests/test_util.h"
#include "tests/vectors.h"

#include <cstdio>
#include <fstream>

using namespace umc;
using namespace umc::test;
namespace tv = umc::testvec;

static void test_public_key_derivation() {
    auto a = crypto::LocalIdentity::from_bytes(from_hex(tv::kPrivA));
    CHECK(a.has_value());
    if (a) CHECK_BYTES(a->pub(), from_hex(tv::kPubA));

    auto b = crypto::LocalIdentity::from_bytes(from_hex(tv::kPrivB));
    CHECK(b.has_value());
    if (b) CHECK_BYTES(b->pub(), from_hex(tv::kPubB));
}

static void test_signing() {
    auto a = crypto::LocalIdentity::from_bytes(from_hex(tv::kPrivA));
    if (!a) return;

    Bytes msg = from_str(tv::kSignedMsg);
    Bytes sig = a->sign(msg);

    // Ed25519 is deterministic, so we must reproduce the reference signature exactly.
    CHECK_BYTES(sig, from_hex(tv::kSigA));
    CHECK(crypto::verify(a->pub(), msg, sig));

    // A tampered message must not verify.
    msg[0] ^= 0x01;
    CHECK(!crypto::verify(a->pub(), msg, sig));
}

static void test_shared_secret() {
    auto a = crypto::LocalIdentity::from_bytes(from_hex(tv::kPrivA));
    auto b = crypto::LocalIdentity::from_bytes(from_hex(tv::kPrivB));
    if (!a || !b) return;

    auto ab = a->shared_secret(from_hex(tv::kPubB));
    auto ba = b->shared_secret(from_hex(tv::kPubA));
    CHECK(ab.has_value());
    CHECK(ba.has_value());
    if (!ab || !ba) return;

    CHECK_BYTES(*ab, from_hex(tv::kSharedAB));
    CHECK_BYTES(*ab, *ba);
}

static void test_encrypt_decrypt() {
    Bytes key = from_hex(tv::kSharedAB);

    // Encryption is deterministic (ECB, no IV), so this must match byte for byte.
    Bytes sealed = crypto::encrypt_and_mac(key, from_str(tv::kPlain));
    CHECK_BYTES(sealed, from_hex(tv::kSealed));

    auto opened = crypto::mac_and_decrypt(key, subview(sealed, 0, 2), subview(sealed, 2));
    CHECK(opened.has_value());
    if (opened) {
        // Decryption returns the zero padding too; the payload parsers trim it.
        CHECK_BYTES(subview(*opened, 0, tv::kPlain.size()), from_str(tv::kPlain));
    }

    // A block-aligned plaintext must not gain a spurious padding block.
    Bytes sealed16 = crypto::encrypt_and_mac(key, from_str(tv::kPlain16));
    CHECK_BYTES(sealed16, from_hex(tv::kSealed16));
    CHECK_EQ(sealed16.size(), size_t {2 + 16});
}

static void test_wrong_key_rejected() {
    Bytes key = from_hex(tv::kSharedAB);
    Bytes sealed = crypto::encrypt_and_mac(key, from_str(tv::kPlain));

    Bytes wrong = key;
    wrong[0] ^= 0xff;
    // This is how a node decides a group/direct packet was not meant for it.
    CHECK(!crypto::mac_and_decrypt(wrong, subview(sealed, 0, 2), subview(sealed, 2)).has_value());
}

static void test_ack_hash() {
    Bytes ack = crypto::ack_hash(from_str(tv::kAckInput));
    CHECK_EQ(ack.size(), crypto::kAckHashSize);
    CHECK_BYTES(ack, from_hex(tv::kAckHash));
}

static void test_generate_avoids_reserved_ids() {
    // 0x00 and 0xff are reserved node IDs and must never be self-assigned.
    for (int i = 0; i < 16; i++) {
        auto id = crypto::LocalIdentity::generate();
        CHECK(id.id() != 0x00 && id.id() != 0xff);

        // A freshly generated key must round-trip through the on-wire form.
        auto reloaded = crypto::LocalIdentity::from_bytes(id.priv());
        CHECK(reloaded.has_value());
        if (reloaded) CHECK_BYTES(reloaded->pub(), id.pub());

        // ...and must produce verifiable signatures.
        Bytes msg = from_str("round trip");
        CHECK(crypto::verify(id.pub(), msg, id.sign(msg)));
    }
}

static void test_identity_load_distinguishes_missing_and_invalid() {
    const std::string path = "/tmp/umeshcore_test_identity";
    std::remove(path.c_str());

    std::string error;
    CHECK(!crypto::LocalIdentity::load(path, error).has_value());
    CHECK(error.empty());

    {
        std::ofstream out(path, std::ios::trunc);
        out << "not an identity\n";
    }
    CHECK(!crypto::LocalIdentity::load(path, error).has_value());
    CHECK(!error.empty());

    auto id = crypto::LocalIdentity::from_bytes(from_hex(tv::kPrivA));
    CHECK(id.has_value());
    if (id) {
        CHECK(id->save(path));
        auto loaded = crypto::LocalIdentity::load(path, error);
        CHECK(loaded.has_value());
        CHECK(error.empty());
        if (loaded) CHECK_BYTES(loaded->pub(), id->pub());
    }

    std::remove(path.c_str());
}

int main() {
    if (!crypto::init()) return 2;

    test_public_key_derivation();
    test_signing();
    test_shared_secret();
    test_encrypt_decrypt();
    test_wrong_key_rejected();
    test_ack_hash();
    test_generate_avoids_reserved_ids();
    test_identity_load_distinguishes_missing_and_invalid();

    return finish("crypto");
}
