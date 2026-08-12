#pragma once

#include <optional>
#include <string>
#include <vector>

#include "crypto/identity.h"
#include "proto/payloads.h"
#include "util/bytes.h"

namespace umc::mesh {

struct Contact {
    Bytes pubkey;  // 32
    std::string name;
    uint8_t type = proto::kAdvTypeChat;
    uint8_t flags = 0;

    int32_t lat_e6 = 0;
    int32_t lon_e6 = 0;

    // Timestamp from the peer's most recent advert. Adverts older than this are
    // replays and must be ignored.
    uint32_t adv_timestamp = 0;
    uint32_t last_seen = 0;  // unix, when we last heard anything from them

    // Route to reach them. Empty with `path_known` set means a zero-hop direct
    // neighbour; `path_known` false means we must flood.
    Bytes out_path;
    bool path_known = false;

    int last_rssi = 0;
    float last_snr = 0.0f;

    // Room servers only: how far back the app wants messages synced from.
    uint32_t sync_since = 0;

    uint8_t id() const { return pubkey.empty() ? 0 : pubkey[0]; }

    // Cached ECDH result — deriving it costs a scalar multiplication, and it
    // never changes for a given pair of keys.
    const Bytes& shared_secret(const crypto::LocalIdentity& self) const;

private:
    mutable Bytes shared_;
};

class ContactStore {
public:
    static constexpr size_t kMaxContacts = 100;

    explicit ContactStore(const crypto::LocalIdentity& self,
                          size_t max_contacts = kMaxContacts)
        : self_(self), max_contacts_(max_contacts) {}

    Contact* find(ByteView pubkey);
    const Contact* find(ByteView pubkey) const;

    // Several contacts can share a first key byte, so this returns all matches
    // and the caller disambiguates by trying to decrypt with each.
    std::vector<Contact*> by_id(uint8_t id);

    // Applies a verified advert. Returns nullptr if the advert is a replay
    // (timestamp not newer than the one held). `created` reports whether this
    // was a first sighting, which the companion app is told about.
    Contact* apply_advert(const proto::Advert& adv, const proto::AdvertAppData& app,
                          bool& created);

    // Returns nullptr when a new contact would exceed the store limit. An
    // existing contact is always returned so it can still be updated.
    Contact* upsert(ByteView pubkey);
    bool remove(ByteView pubkey);

    std::vector<Contact>& all() { return contacts_; }
    const std::vector<Contact>& all() const { return contacts_; }
    size_t size() const { return contacts_.size(); }

    bool load(const std::string& path);
    // Clears dirty state only after the replacement file is safely installed.
    bool save(const std::string& path);
    // Set when anything changed, so the daemon can persist lazily instead of
    // rewriting the file on every received packet.
    bool dirty() const { return dirty_; }
    void mark_dirty() { dirty_ = true; }

private:
    const crypto::LocalIdentity& self_;
    size_t max_contacts_;
    std::vector<Contact> contacts_;
    bool dirty_ = false;
};

}  // namespace umc::mesh
