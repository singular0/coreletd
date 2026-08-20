#pragma once

#include <cstdint>
#include <deque>
#include <optional>
#include <string>

#include "proto/payloads.h"
#include "util/bytes.h"

namespace clt::mesh {

// A message held for the companion app to collect with CMD_SYNC_NEXT_MESSAGE.
struct StoredMessage {
    bool is_channel = false;
    Bytes sender_pubkey;      // direct messages
    uint8_t channel_index = 0;  // channel messages
    uint32_t timestamp = 0;
    uint8_t txt_type = proto::kTxtPlain;
    std::string text;
    int8_t snr_q4 = 0;  // SNR * 4, as the companion protocol carries it
    uint8_t path_len = 0xFF;  // 0xFF == arrived by flood
};

// Store-and-forward queue for received messages. The radio keeps running with
// no companion app attached, so anything received is held here until an app
// connects and drains it.
//
// The queue is persisted, because the alternative is losing mail that was
// already acknowledged. An ack is a promise: the sender stops retrying once it
// arrives, so a message that is only in memory when the daemon restarts is
// gone with nobody left to ask for it again.
class MessageInbox {
public:
    static constexpr size_t kDefaultLimit = 256;

    // The queue owns the file it lives in; nothing else needs to know the path.
    // An empty one makes this an in-memory queue, as it was before: load() and
    // save() do nothing and report failure rather than pretend anything
    // reached disk.
    explicit MessageInbox(size_t limit = kDefaultLimit, std::string path = {})
        : path_(std::move(path)), limit_(limit) {}

    // Bounded: if the app never collects, the oldest message is dropped rather
    // than letting the queue grow without limit.
    //
    // Commits before returning, which is the one place the daemon writes state
    // synchronously instead of leaving the timing to StateWriter. Node calls
    // this before it sends the ack, so returning means the message will still
    // be here after a crash — the ack cannot promise delivery for something
    // only in memory. Returns false if it could not be committed.
    bool store(StoredMessage msg);

    // Popping is persisted lazily, through StateWriter like everything else. A
    // crash between the pop and the write re-delivers a message the app has
    // already seen, and a duplicate is the better failure than a loss.
    std::optional<StoredMessage> pop();

    bool empty() const { return messages_.empty(); }
    size_t size() const { return messages_.size(); }

    // Messages evicted because the app never collected them. Nothing else
    // records that they existed, so this is the only evidence of the loss.
    uint32_t dropped() const { return dropped_; }

    // Distinguishes a queue that was never written from one that is there but
    // unreadable, so the caller can refuse to start rather than write over it.
    enum class Load { Missing, Loaded, Corrupt };
    Load load();

    bool save();
    bool dirty() const { return dirty_; }
    void mark_dirty() { dirty_ = true; }

private:
    std::string path_;
    std::deque<StoredMessage> messages_;
    size_t limit_;
    uint32_t dropped_ = 0;
    bool dirty_ = false;
};

}  // namespace clt::mesh
