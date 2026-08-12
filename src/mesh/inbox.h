#pragma once

#include <cstdint>
#include <deque>
#include <optional>
#include <string>

#include "proto/payloads.h"
#include "util/bytes.h"

namespace umc::mesh {

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
class MessageInbox {
public:
    static constexpr size_t kDefaultLimit = 256;

    explicit MessageInbox(size_t limit = kDefaultLimit) : limit_(limit) {}

    // Bounded: if the app never collects, the oldest message is dropped rather
    // than letting the queue grow without limit.
    void store(StoredMessage msg);

    std::optional<StoredMessage> pop();
    bool empty() const { return messages_.empty(); }
    size_t size() const { return messages_.size(); }

private:
    std::deque<StoredMessage> messages_;
    size_t limit_;
};

}  // namespace umc::mesh
