#pragma once

#include <deque>
#include <optional>
#include <string>
#include <vector>

#include "crypto/identity.h"
#include "proto/payloads.h"
#include "util/bytes.h"

namespace clt::mesh {

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

    // The store owns the file it lives in; nothing else needs to know the path.
    // An empty one makes this an in-memory store: load() and save() do nothing
    // and report failure rather than pretend anything reached disk.
    explicit ContactStore(const crypto::LocalIdentity& self, std::string path = {},
                          size_t max_contacts = kMaxContacts)
        : self_(self), path_(std::move(path)), max_contacts_(max_contacts) {}

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

    // --- mutation -------------------------------------------------------
    // Contacts are handed out by reference, so every field written through one
    // has to be paired with a dirty flag the caller must remember to set. These
    // cover the fields the receive path touches and do it themselves.

    // Records that we just heard from a contact.
    void touch(Contact& c);
    // As above, plus the radio quality of the packet we heard it in.
    void touch(Contact& c, int rssi, float snr);

    // Returns false if the contact already had exactly this route, in which
    // case nothing was written and no notification is owed.
    bool set_path(Contact& c, ByteView path);
    bool clear_path(Contact& c);

    // References stay valid across insertion, which the receive path relies on:
    // it holds a Contact& across dispatcher and delegate callbacks that could
    // one day add a contact. A vector would reallocate underneath them.
    std::deque<Contact>& all() { return contacts_; }
    const std::deque<Contact>& all() const { return contacts_; }
    size_t size() const { return contacts_.size(); }

    bool load();
    // Clears dirty state only after the replacement file is safely installed.
    bool save();
    // Set when anything changed, so the daemon can persist lazily instead of
    // rewriting the file on every received packet. StateWriter decides when.
    bool dirty() const { return dirty_; }
    void mark_dirty() { dirty_ = true; }

private:
    const crypto::LocalIdentity& self_;
    std::string path_;
    size_t max_contacts_;
    std::deque<Contact> contacts_;
    bool dirty_ = false;
};

}  // namespace clt::mesh
