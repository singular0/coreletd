#pragma once

#include <optional>
#include <string>

#include "mesh/channels.h"
#include "mesh/contacts.h"
#include "mesh/dispatcher.h"
#include "mesh/inbox.h"
#include "mesh/sender.h"
#include "proto/payloads.h"

namespace umc::mesh {

// Routes between the radio and the companion app: builds our adverts, decides
// what each received payload means, and repeats flood traffic. Reliable
// delivery lives in ReliableSender and the receive queue in MessageInbox.
class Node {
public:
    struct Config {
        std::string name = "umeshcore";
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

    Config& config() { return cfg_; }
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

    void store_message(StoredMessage msg);
    void send_ack(const Contact& to, ByteView ack_hash);
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
    ReliableSender sender_;
    MessageInbox inbox_;
};

}  // namespace umc::mesh
