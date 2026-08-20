#pragma once

#include <optional>
#include <string>
#include <unordered_map>

#include "mesh/channels.h"
#include "mesh/contacts.h"
#include "mesh/dispatcher.h"
#include "mesh/inbox.h"
#include "mesh/sender.h"
#include "proto/payloads.h"

namespace clt::mesh {

// Routes between the radio and the companion app: builds our adverts, decides
// what each received payload means, and repeats flood traffic. Reliable
// delivery lives in ReliableSender and the receive queue in MessageInbox.
class Node {
public:
    struct Config {
        std::string name = "coreletd";
        uint8_t adv_type = proto::kAdvTypeChat;
        bool has_location = false;
        int32_t lat_e6 = 0;
        int32_t lon_e6 = 0;
        // 0 disables automatic adverts; MeshCore nodes typically re-advertise
        // every few hours so the mesh keeps fresh routes.
        uint32_t advert_interval_s = 0;
        // Repeat other nodes' flood traffic. Off for a plain companion radio.
        bool repeat = false;
        uint8_t max_hops = 32;
        uint32_t message_queue_limit = 256;
        // Where the received-message queue is persisted. Empty keeps it in
        // memory, which is what the tests that do not care about restarts use.
        std::string messages_path;
        uint32_t pending_send_limit = 64;
    };

    // Notifications for whatever is driving the node (the companion session).
    struct Delegate {
        virtual ~Delegate() = default;
        virtual void on_contact_changed(const Contact& c, bool is_new) {}
        virtual void on_message_stored() {}
        virtual void on_ack(ByteView ack_hash) {}
        virtual void on_advert_seen(const Contact& c) {}
        virtual void on_raw_rx(const proto::Packet& p, ByteView raw) {}
        virtual void on_path_updated(const Contact& c) {}
    };

    Node(EventLoop& loop, Dispatcher& dispatcher, const crypto::LocalIdentity& self,
         ContactStore& contacts, ChannelStore& channels, Config cfg);

    void start();
    void set_delegate(Delegate* d) { delegate_ = d; }

    // Read-only: the config is loaded once at startup, and the companion
    // protocol refuses the commands that would edit it at runtime.
    const Config& config() const { return cfg_; }
    const crypto::LocalIdentity& self() const { return self_; }

    // --- outbound -------------------------------------------------------
    void send_advert(bool flood);

    // Builds a signed self-advert packet without transmitting it. This is what
    // the companion protocol hands the app as our "contact card": other nodes
    // import it exactly as if they had heard the advert on air, so it must be
    // a complete, signed packet rather than just our public key.
    // nullopt when the wall clock is not yet trustworthy.
    std::optional<proto::Packet> build_advert_packet(bool flood) const;

    // Sends a direct text message, retrying until acked. Returns the expected
    // ack hash so the caller can correlate, or nullopt if it could not be sent,
    // in which case `err` receives which of the failures it was.
    std::optional<Bytes> send_text(const Contact& to, const std::string& text, uint8_t txt_type,
                                   uint32_t timestamp, SendError* err = nullptr) {
        return sender_.send(to, text, txt_type, timestamp, err);
    }
    bool send_channel_text(size_t channel_index, const std::string& text, uint32_t timestamp);

    // Asks a contact for its route back to us, which populates their path.
    bool send_path_discovery(Contact& to);

    // --- inbound message queue -----------------------------------------
    bool has_messages() const { return !inbox_.empty(); }
    // StateWriter needs it to persist pops; App needs it to load at startup.
    MessageInbox& inbox() { return inbox_; }
    std::optional<StoredMessage> pop_message() { return inbox_.pop(); }

    // --- introspection --------------------------------------------------
    const DispatcherStats& stats() const { return dispatcher_.stats(); }

private:
    void on_packet(proto::Packet&& p);

    void handle_advert(const proto::Packet& p);
    void handle_text(const proto::Packet& p);
    void handle_ack(const proto::Packet& p);
    void handle_path(const proto::Packet& p);
    void handle_group_text(const proto::Packet& p);
    void maybe_repeat(const proto::Packet& p);

    // Tries every contact whose id matches the source hash until one decrypts.
    Contact* decrypt_from(uint8_t src_hash, ByteView mac, ByteView ciphertext, Bytes& plaintext);

    // True the first time this message is seen, false for a retry of one
    // already delivered. Retries are distinct packets — the attempt number
    // occupies two bits of the flags byte — so packet-level dedup cannot tell
    // that they are the same message.
    bool first_delivery(const Contact& from, const proto::TextMessage& msg);
    void expire_delivered();

    void store_message(StoredMessage msg);
    void send_ack(const Contact& to, ByteView ack);
    // Tells `to` how to reach us: the path `inbound` arrived by, unreversed and
    // encrypted to that contact. `extra` rides inside it — an ack, normally,
    // which is how answering a flood-routed message still costs one packet.
    void send_path_return(Contact& to, const proto::Packet& inbound, uint8_t extra_type,
                          ByteView extra);
    void record_return_path(Contact& c, const proto::Packet& p);

    proto::AdvertAppData build_appdata() const;

    EventLoop& loop_;
    Dispatcher& dispatcher_;
    const crypto::LocalIdentity& self_;
    ContactStore& contacts_;
    ChannelStore& channels_;
    Config cfg_;
    Delegate* delegate_ = nullptr;

    EventLoop::Timer advert_timer_;
    EventLoop::Timer delivered_sweep_;
    ReliableSender sender_;
    MessageInbox inbox_;

    // Logical message identity -> expiry in millis. Bounded by the sweep and by
    // a hard cap, so a busy mesh cannot grow it without limit.
    std::unordered_map<uint64_t, uint32_t> delivered_;
};

}  // namespace clt::mesh
