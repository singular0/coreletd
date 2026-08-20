#include "mesh/inbox.h"

#include <sys/stat.h>

#include <fstream>
#include <limits>
#include <string_view>
#include <vector>

#include "crypto/crypto.h"
#include "mesh/record.h"
#include "util/hex.h"
#include "util/log.h"
#include "util/persist.h"

namespace clt::mesh {

namespace {
constexpr char kHeader[] = "# coreletd messages v1";
constexpr size_t kFields = 8;
}  // namespace

bool MessageInbox::store(StoredMessage msg) {
    messages_.push_back(std::move(msg));
    while (messages_.size() > limit_) {
        dropped_++;
        LOG_WARN("message queue full (%zu), dropping oldest; %u lost so far", limit_, dropped_);
        messages_.pop_front();
    }
    dirty_ = true;

    // Deliberately synchronous: Node sends the ack straight after this, and an
    // ack the sender believes means it stops retrying. Persisting on the usual
    // coalesced schedule would leave a window where we have promised delivery
    // of something a restart would lose, with nobody left to ask again.
    if (path_.empty()) return true;
    return save();
}

std::optional<StoredMessage> MessageInbox::pop() {
    if (messages_.empty()) return std::nullopt;
    StoredMessage m = std::move(messages_.front());
    messages_.pop_front();
    dirty_ = true;
    return m;
}

bool MessageInbox::save() {
    if (path_.empty()) {
        LOG_ERROR("messages: asked to save a queue with no path");
        return false;
    }
    const std::string& path = path_;
    std::string tmp = path + ".tmp";
    std::ofstream out(tmp, std::ios::trunc);
    if (!out) {
        LOG_ERROR("messages: cannot write %s", tmp.c_str());
        return false;
    }

    // Unlike contacts, this file holds what people wrote, so it is not left
    // world-readable for whoever else shares the machine.
    if (::chmod(tmp.c_str(), S_IRUSR | S_IWUSR) != 0) {
        LOG_WARN("messages: cannot restrict permissions on %s", tmp.c_str());
    }

    out << kHeader << '\n';
    out << "# kind\tpeer\tchannel\ttimestamp\ttxt_type\tsnr_q4\tpath_len\ttext_hex\n";
    for (const auto& m : messages_) {
        // The text is hex rather than raw: it arrives off the air as arbitrary
        // bytes, and a newline or a tab in it would otherwise end the record.
        out << (m.is_channel ? "channel" : "direct") << '\t'
            << (m.sender_pubkey.empty() ? "-" : hex(m.sender_pubkey)) << '\t'
            << static_cast<int>(m.channel_index) << '\t' << m.timestamp << '\t'
            << static_cast<int>(m.txt_type) << '\t' << static_cast<int>(m.snr_q4) << '\t'
            << static_cast<int>(m.path_len) << '\t'
            << hex(ByteView(reinterpret_cast<const uint8_t*>(m.text.data()), m.text.size()))
            << '\n';
    }
    out.flush();
    if (!out) {
        LOG_ERROR("messages: write to %s failed", tmp.c_str());
        return false;
    }
    out.close();
    if (!out) {
        LOG_ERROR("messages: close of %s failed", tmp.c_str());
        return false;
    }
    std::string error;
    if (!durable_replace(tmp, path, error)) {
        LOG_ERROR("messages: %s", error.c_str());
        return false;
    }
    dirty_ = false;
    return true;
}

MessageInbox::Load MessageInbox::load() {
    if (path_.empty()) return Load::Missing;
    const std::string& path = path_;
    std::ifstream in(path);
    if (!in) return Load::Missing;

    std::deque<StoredMessage> loaded;
    std::string line;
    int lineno = 0;
    bool saw_header = false;
    while (std::getline(in, line)) {
        lineno++;
        if (line == kHeader) {
            saw_header = true;
            continue;
        }
        if (line.empty() || line[0] == '#') continue;

        auto fail = [&](const char* why) {
            LOG_ERROR("messages: %s:%d %s", path.c_str(), lineno, why);
            return Load::Corrupt;
        };

        std::vector<std::string_view> fields;
        if (!split_fields(line, kFields, fields)) return fail("malformed record");

        StoredMessage m;
        if (fields[0] == "channel") {
            m.is_channel = true;
        } else if (fields[0] == "direct") {
            m.is_channel = false;
        } else {
            return fail("unknown record kind");
        }

        if (fields[1] != "-") {
            auto pubkey = unhex(fields[1]);
            if (!pubkey || pubkey->size() != crypto::kPubKeySize) return fail("invalid sender key");
            m.sender_pubkey = *pubkey;
        } else if (!m.is_channel) {
            return fail("direct message with no sender");
        }

        uint64_t channel = 0, timestamp = 0, txt_type = 0, path_len = 0;
        int64_t snr = 0;
        if (!parse_unsigned(fields[2], std::numeric_limits<uint8_t>::max(), channel) ||
            !parse_unsigned(fields[3], std::numeric_limits<uint32_t>::max(), timestamp) ||
            !parse_unsigned(fields[4], std::numeric_limits<uint8_t>::max(), txt_type) ||
            !parse_signed(fields[5], -128, 127, snr) ||
            !parse_unsigned(fields[6], std::numeric_limits<uint8_t>::max(), path_len))
            return fail("invalid numeric field");

        auto text = unhex(fields[7]);
        if (!text) return fail("invalid message text");

        m.channel_index = static_cast<uint8_t>(channel);
        m.timestamp = static_cast<uint32_t>(timestamp);
        m.txt_type = static_cast<uint8_t>(txt_type);
        m.snr_q4 = static_cast<int8_t>(snr);
        m.path_len = static_cast<uint8_t>(path_len);
        m.text.assign(text->begin(), text->end());
        loaded.push_back(std::move(m));
    }

    if (!saw_header) {
        LOG_ERROR("messages: %s has no version header", path.c_str());
        return Load::Corrupt;
    }
    // A file written by a larger limit than we run with now: keep the newest,
    // which is the same end store() keeps.
    while (loaded.size() > limit_) {
        dropped_++;
        loaded.pop_front();
    }

    messages_ = std::move(loaded);
    dirty_ = false;
    return Load::Loaded;
}

}  // namespace clt::mesh
