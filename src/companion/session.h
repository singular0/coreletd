#pragma once

#include <string>

#include "companion/device_metrics.h"
#include "companion/server.h"
#include "mesh/node.h"
#include "mesh/state_writer.h"
#include "radio/radio.h"

namespace umc::companion {

// Translates companion-protocol frames into operations on the mesh node, and
// pushes mesh events back to the app.
class Session : public mesh::Node::Delegate {
public:
    Session(Server& server, mesh::Node& node, mesh::ContactStore& contacts,
            mesh::ChannelStore& channels, radio::Radio& radio, mesh::StateWriter& state,
            const DeviceMetrics& metrics);

    void attach();

    // mesh::Node::Delegate
    void on_contact_changed(const mesh::Contact& c, bool is_new) override;
    void on_message_stored() override;
    void on_ack(ByteView ack_hash) override;
    void on_advert_seen(const mesh::Contact& c) override;
    void on_raw_rx(const proto::Packet& p, ByteView raw) override;
    void on_path_updated(const mesh::Contact& c) override;

private:
    void handle_frame(ByteView frame);
    void reply(ByteView payload) { server_.send(payload); }
    void reply_err(uint8_t code) { server_.send(resp_err(code)); }

    // Command handlers. Each returns the reply frame to send.
    Bytes cmd_app_start(ByteView args);
    Bytes cmd_device_query(ByteView args);
    Bytes cmd_get_contacts(ByteView args);
    Bytes cmd_get_contact_by_key(ByteView args);
    Bytes cmd_add_update_contact(ByteView args);
    Bytes cmd_remove_contact(ByteView args);
    Bytes cmd_reset_path(ByteView args);
    Bytes cmd_send_txt_msg(ByteView args);
    Bytes cmd_send_channel_txt_msg(ByteView args);
    Bytes cmd_sync_next_message(ByteView args);
    Bytes cmd_get_channel(ByteView args);
    Bytes cmd_set_channel(ByteView args);
    Bytes cmd_set_advert_name(ByteView args);
    Bytes cmd_set_advert_latlon(ByteView args);
    Bytes cmd_get_battery(ByteView args);
    Bytes cmd_set_radio_params(ByteView args);
    Bytes cmd_export_contact(ByteView args);

    Bytes self_info_frame() const;
    Bytes contact_frame(uint8_t code, const mesh::Contact& c) const;

    // Reply for a command that changed persisted state: queues the write and
    // reports whether the last one reached disk.
    Bytes saved_reply();

    Server& server_;
    mesh::Node& node_;
    mesh::ContactStore& contacts_;
    mesh::ChannelStore& channels_;
    radio::Radio& radio_;
    mesh::StateWriter& state_;
    const DeviceMetrics& metrics_;

    // Set once the app has sent CMD_APP_START. Commands before that are still
    // answered — some clients probe with DEVICE_QUERY first.
    bool app_started_ = false;
    std::string app_name_;
    // Round-trip timing for PUSH_CODE_SEND_CONFIRMED.
    uint32_t last_send_ms_ = 0;
};

}  // namespace umc::companion
