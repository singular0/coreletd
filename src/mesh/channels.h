#pragma once

#include <string>
#include <vector>

#include "util/bytes.h"

namespace umc::mesh {

// The well-known MeshCore public channel. Every node ships with this in slot 0
// so a fresh install can talk to anyone.
inline constexpr std::string_view kPublicChannelKeyHex = "8b3387e9c5cdea6ac9e5edbaa115cd72";

struct Channel {
    std::string name;
    Bytes secret;  // 16 bytes

    // Channel identifier on the wire: first byte of SHA-256 over the key.
    uint8_t hash() const;
    bool valid() const { return !secret.empty(); }

    // "Hashtag" channels are public and derive their key from the name, so
    // anyone who knows `#jokes` can join without exchanging a key.
    static Channel from_hashtag(const std::string& name);
    static Channel public_channel();
};

class ChannelStore {
public:
    ChannelStore();

    // The companion protocol addresses channels by slot index.
    static constexpr size_t kMaxChannels = 8;

    Channel* at(size_t index);
    const Channel* at(size_t index) const;
    void set(size_t index, Channel ch);
    size_t size() const { return channels_.size(); }

    // Every channel whose hash matches; the caller disambiguates by MAC.
    std::vector<std::pair<size_t, Channel*>> by_hash(uint8_t hash);

    bool load(const std::string& path);
    // Clears dirty state only after the replacement file is safely installed.
    bool save(const std::string& path);
    bool dirty() const { return dirty_; }

private:
    std::vector<Channel> channels_;
    bool dirty_ = false;
};

}  // namespace umc::mesh
