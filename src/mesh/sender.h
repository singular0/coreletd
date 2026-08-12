#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "mesh/contacts.h"
#include "mesh/dispatcher.h"

namespace umc::mesh {

// Why a send could not be started. These stay distinguishable because the
// companion protocol reports each one differently: telling a user the contact
// table is full when their message was simply too long is a wrong answer.
enum class SendError {
    None,
    // The contact's public key does not yield a shared secret, so nothing can
    // be encrypted for it. A stored contact with a malformed key.
    NoSharedSecret,
    // Too many sends are already waiting for an ack.
    PendingFull,
    // Does not fit in a packet once encrypted and padded.
    TooLong,
};

// Direct text messages, retried until acknowledged.
//
// MeshCore allows four attempts — the attempt number is two bits on the wire —
// spaced 8/16/32 seconds apart, and the last one escalates to flood routing
// because a stale direct path is the usual reason an ack never arrives.
class ReliableSender {
public:
    static constexpr size_t kDefaultPendingLimit = 64;

    // What a matched ack completed, so the caller can report it onwards.
    struct Completion {
        // The hash the caller was originally told to wait for. It differs from
        // the hash that came back whenever a retry was the attempt acked.
        Bytes ack_hash;
        Bytes dest_pubkey;
    };

    ReliableSender(EventLoop& loop, Dispatcher& dispatcher, const crypto::LocalIdentity& self,
                   ContactStore& contacts, size_t pending_limit = kDefaultPendingLimit);

    // Sends a text message, retrying until acked. Returns the expected ack hash
    // so the caller can correlate, or nullopt if it could not be sent. `err`,
    // when given, receives the reason for a nullopt and SendError::None
    // otherwise.
    std::optional<Bytes> send(const Contact& to, const std::string& text, uint8_t txt_type,
                              uint32_t timestamp, SendError* err = nullptr);

    // Completes the send this ack answers and cancels its retry. nullopt when
    // nothing pending matches, which is routine: acks arrive for sends that
    // already completed, and the short wire hashes can collide.
    std::optional<Completion> complete(ByteView ack_hash);

    size_t pending() const { return pending_.size(); }

private:
    struct Pending {
        // Local operation identity. ACK hashes are deliberately short wire
        // identifiers and can collide, so callbacks and timers must never use
        // them to choose which operation to advance. 0 marks a send with no
        // retry state (CLI data), which is never registered in pending_.
        uint64_t id = 0;
        // The first hash is what the companion client was told to wait for.
        // Retries change the attempt bits in the plaintext and therefore have
        // different on-air ack hashes; keep all transmitted hashes so a late
        // or bundled ack for any attempt can complete the original send.
        Bytes ack_hash;
        std::vector<Bytes> accepted_ack_hashes;
        Bytes dest_pubkey;
        std::string text;
        uint8_t txt_type = proto::kTxtPlain;
        uint32_t timestamp = 0;
        uint8_t attempt = 0;
        // Cancelled by dropping the entry, which is the only way a send ends.
        EventLoop::Timer timer;
    };

    // Timers and transmit callbacks are armed for an operation that may have
    // been acked, abandoned or dropped by the time they run, so every lookup
    // has to allow for the entry being gone. nullptr means exactly that, and is
    // never an error.
    Pending* find(uint64_t id);
    void erase(uint64_t id);

    // Builds and transmits one attempt — the initial send is attempt 0, retries
    // are 1..kMaxAttempts-1. `force_flood` ignores a known path, which the last
    // attempt uses. Returns the on-air ack hash of this attempt, or nullopt if
    // the message could not be sealed or queued, in which case `err` receives
    // the reason. Retries pass no `err`: nobody is left waiting on an answer.
    std::optional<Bytes> send_attempt(Pending& pending, const Contact& to, bool force_flood,
                                      SendError* err = nullptr);

    void queue_retry(uint64_t id);
    void on_retry(uint64_t id);
    void on_tx_result(uint64_t id, bool transmitted);

    EventLoop& loop_;
    Dispatcher& dispatcher_;
    const crypto::LocalIdentity& self_;
    ContactStore& contacts_;
    size_t pending_limit_;

    std::vector<Pending> pending_;
    uint64_t next_id_ = 1;
};

}  // namespace umc::mesh
