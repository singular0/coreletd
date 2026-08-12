#pragma once

#include <string>

#include "companion/server.h"
#include "mesh/node.h"
#include "radio/radio.h"

namespace umc::companion {

// Translates companion-protocol frames into operations on the mesh node, and
// pushes mesh events back to the app.
class Session : public mesh::Node::Delegate {
public:
    struct DeviceInfo {
        std::string model = "uConsole AIO v2";
        std::string firmware_build = UMESHCORE_VERSION;
        std::string version = UMESHCORE_VERSION;
        uint8_t max_contacts_div2 = 50;  // reported as value * 2
        uint8_t max_channels = mesh::ChannelStore::kMaxChannels;
    };

    Session(Server& server, mesh::Node& node, mesh::ContactStore& contacts,
            mesh::ChannelStore& channels, radio::Radio& radio, DeviceInfo info);

    void attach();

    // Paths the daemon persists to; the session saves after mutating commands.
    void set_store_paths(std::string contacts_path, std::string channels_path);

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

    bool save_contacts();
    bool save_channels();

    Server& server_;
    mesh::Node& node_;
    mesh::ContactStore& contacts_;
    mesh::ChannelStore& channels_;
    radio::Radio& radio_;
    DeviceInfo info_;

    std::string contacts_path_;
    std::string channels_path_;

    // Set once the app has sent CMD_APP_START. Commands before that are still
    // answered — some clients probe with DEVICE_QUERY first.
    bool app_started_ = false;
    std::string app_name_;
    // Round-trip timing for PUSH_CODE_SEND_CONFIRMED.
    uint32_t last_send_ms_ = 0;
};

}  // namespace umc::companion
