#include "companion/session.h"

#include <algorithm>
#include <cstdint>

#include "util/clock.h"
#include "util/hex.h"
#include "util/log.h"

namespace umc::companion {

namespace {

// The wire figures are kilobytes, so anything under 1 kB reports as 0 rather
// than rounding a nearly-full disk up to something reassuring.
uint32_t to_kb(uint64_t bytes) {
    return static_cast<uint32_t>(std::min<uint64_t>(bytes / 1024, UINT32_MAX));
}

// The three ways a send can fail are three different things for the user to do
// about it, so each gets its own protocol error rather than collapsing into one.
uint8_t send_error_code(mesh::SendError err) {
    switch (err) {
        case mesh::SendError::NoSharedSecret:
            return kErrBadState;  // the stored contact key is unusable
        case mesh::SendError::PendingFull:
            return kErrTableFull;  // too many messages awaiting an ack
        case mesh::SendError::TooLong:
            return kErrIllegalArg;  // shorten the message and retry
        case mesh::SendError::None:
            break;
    }
    return kErrBadState;
}

void put_padded(Bytes& out, ByteView data, size_t width) {
    size_t n = std::min(data.size(), width);
    out.insert(out.end(), data.begin(), data.begin() + n);
    out.insert(out.end(), width - n, 0);
}

}  // namespace

Session::Session(Server& server, mesh::Node& node, mesh::ContactStore& contacts,
                 mesh::ChannelStore& channels, radio::Radio& radio, mesh::StateWriter& state,
                 const DeviceMetrics& metrics)
    : server_(server),
      node_(node),
      contacts_(contacts),
      channels_(channels),
      radio_(radio),
      state_(state),
      metrics_(metrics) {}

void Session::attach() {
    server_.set_frame_handler([this](ByteView f) { handle_frame(f); });
    server_.set_connect_handler([this] { app_started_ = false; });
    node_.set_delegate(this);
}

Bytes Session::saved_reply() {
    state_.request_save();
    // The write has not happened yet, so this reports the state directory as
    // the previous write found it. Answering OK per command and writing once
    // is the trade the app wants: it syncs contacts one at a time, and each
    // synchronous save was a full rewrite plus two fsyncs.
    return state_.healthy() ? resp_ok() : resp_err(kErrFileIoError);
}

// ---------------------------------------------------------------------------
// Frame dispatch
// ---------------------------------------------------------------------------

void Session::handle_frame(ByteView frame) {
    if (frame.empty()) return;

    const uint8_t cmd = frame[0];
    ByteView args = subview(frame, 1);
    LOG_DEBUG("companion: cmd %u (%zu byte args)", cmd, args.size());

    Bytes out;
    switch (cmd) {
        case kCmdAppStart: out = cmd_app_start(args); break;
        case kCmdDeviceQuery: out = cmd_device_query(args); break;
        case kCmdGetDeviceTime: {
            out = Bytes {kRespCurrTime};
            put_u32(out, unix_now());
            break;
        }
        case kCmdSetDeviceTime: {
            if (args.size() < 4) {
                out = resp_err(kErrIllegalArg);
                break;
            }
            uint32_t app_time = rd_u32(args, 0);
            // We do not have permission to step the system clock, so track the
            // difference instead. Adverts need a sane wall clock to be accepted.
            int64_t now = static_cast<int64_t>(unix_now()) - clock_offset();
            set_clock_offset(static_cast<int64_t>(app_time) - now);
            LOG_INFO("companion: app set device time to %u (offset %lld s)", app_time,
                     static_cast<long long>(clock_offset()));
            out = resp_ok();
            break;
        }
        case kCmdSendSelfAdvert: {
            // Byte 0 of args, when present, selects flood (1) vs zero-hop (0).
            bool flood = args.empty() || args[0] != 0;
            node_.send_advert(flood);
            out = resp_ok();
            break;
        }
        case kCmdSetAdvertName: out = cmd_set_advert_name(args); break;
        case kCmdSetAdvertLatLon: out = cmd_set_advert_latlon(args); break;
        case kCmdGetContacts: out = cmd_get_contacts(args); return;  // streams its own frames
        case kCmdGetContactByKey: out = cmd_get_contact_by_key(args); break;
        case kCmdAddUpdateContact: out = cmd_add_update_contact(args); break;
        case kCmdRemoveContact: out = cmd_remove_contact(args); break;
        case kCmdResetPath: out = cmd_reset_path(args); break;
        case kCmdShareContact:
        case kCmdExportContact: out = cmd_export_contact(args); break;
        case kCmdSendTxtMsg: out = cmd_send_txt_msg(args); break;
        case kCmdSendChannelTxtMsg: out = cmd_send_channel_txt_msg(args); break;
        case kCmdSyncNextMessage: out = cmd_sync_next_message(args); break;
        case kCmdGetChannel: out = cmd_get_channel(args); break;
        case kCmdSetChannel: out = cmd_set_channel(args); break;
        case kCmdGetBatteryVoltage: out = cmd_get_battery(args); break;
        case kCmdSetRadioParams: out = cmd_set_radio_params(args); break;
        case kCmdSetRadioTxPower:
            // Changing TX power needs a radio re-init; accept and ignore rather
            // than fail, so the app's settings screen still works.
            LOG_INFO("companion: ignoring TX power change (set it in the config file)");
            out = resp_ok();
            break;
        case kCmdHasConnection: out = resp_ok(server_.connected() ? 1 : 0); break;
        case kCmdLogout: out = resp_ok(); break;
        case kCmdReboot:
            LOG_WARN("companion: app requested reboot; not supported, ignoring");
            out = resp_err(kErrUnsupportedCmd);
            break;
        default:
            LOG_INFO("companion: unsupported command %u", cmd);
            out = resp_err(kErrUnsupportedCmd);
            break;
    }

    if (!out.empty()) reply(out);
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

Bytes Session::cmd_app_start(ByteView args) {
    // Bytes 0-6 are reserved; anything after is the app's name.
    if (args.size() > 7) app_name_ = to_string(subview(args, 7));
    app_started_ = true;
    LOG_INFO("companion: app \"%s\" started", app_name_.c_str());
    return self_info_frame();
}

Bytes Session::self_info_frame() const {
    const auto& cfg = node_.config();
    const auto& rp = radio_.params();

    Bytes out {kRespSelfInfo};
    out.push_back(cfg.adv_type);
    out.push_back(static_cast<uint8_t>(rp.tx_power_dbm));
    out.push_back(static_cast<uint8_t>(30));  // max tx power the SX1262 PA allows
    put_bytes(out, node_.self().pub());
    put_i32(out, cfg.has_location ? cfg.lat_e6 : 0);
    put_i32(out, cfg.has_location ? cfg.lon_e6 : 0);
    out.push_back(0);  // multi-acks
    out.push_back(0);  // advert location policy
    out.push_back(0);  // telemetry mode
    out.push_back(0);  // manual add contacts
    put_u32(out, static_cast<uint32_t>(rp.freq_mhz * 1000.0));
    put_u32(out, static_cast<uint32_t>(rp.bw_khz * 1000.0));
    out.push_back(rp.sf);
    out.push_back(rp.cr);
    put_str(out, cfg.name);
    return out;
}

Bytes Session::cmd_device_query(ByteView args) {
    const auto& info = metrics_.info();
    Bytes out {kRespDeviceInfo, kFirmwareVersion};
    out.push_back(info.max_contacts_div2);
    out.push_back(info.max_channels);
    put_u32(out, 0);  // BLE pin, not applicable over TCP
    put_padded(out, to_bytes(info.firmware_build), 12);
    put_padded(out, to_bytes(info.model), 40);
    put_padded(out, to_bytes(info.version), 20);
    return out;
}

Bytes Session::contact_frame(uint8_t code, const mesh::Contact& c) const {
    Bytes out {code};
    put_bytes(out, c.pubkey);
    out.push_back(c.type);
    out.push_back(c.flags);
    // Signed byte: -1 (0xFF) means no known route, so the app shows "flood".
    out.push_back(c.path_known ? static_cast<uint8_t>(c.out_path.size()) : kNoPath);
    put_padded(out, c.out_path, kContactPathField);
    put_padded(out, to_bytes(c.name), kContactNameField);
    put_u32(out, c.adv_timestamp);
    put_i32(out, c.lat_e6);
    put_i32(out, c.lon_e6);
    put_u32(out, c.last_seen ? c.last_seen : c.adv_timestamp);
    return out;
}

Bytes Session::cmd_get_contacts(ByteView args) {
    // Optional 4-byte "since" filter lets the app sync incrementally.
    uint32_t since = args.size() >= 4 ? rd_u32(args, 0) : 0;

    std::vector<const mesh::Contact*> matching;
    uint32_t most_recent = 0;
    for (const auto& c : contacts_.all()) {
        if (c.adv_timestamp < since) continue;
        matching.push_back(&c);
        most_recent = std::max(most_recent, c.adv_timestamp);
    }

    Bytes start {kRespContactsStart};
    put_u32(start, static_cast<uint32_t>(matching.size()));
    reply(start);

    for (const auto* c : matching) reply(contact_frame(kRespContact, *c));

    Bytes end {kRespEndOfContacts};
    put_u32(end, most_recent);
    reply(end);

    LOG_DEBUG("companion: sent %zu contacts (since %u)", matching.size(), since);
    return {};
}

Bytes Session::cmd_get_contact_by_key(ByteView args) {
    if (args.size() < crypto::kPubKeySize) return resp_err(kErrIllegalArg);
    const mesh::Contact* c = contacts_.find(subview(args, 0, crypto::kPubKeySize));
    if (!c) return resp_err(kErrNotFound);
    return contact_frame(kRespContact, *c);
}

Bytes Session::cmd_add_update_contact(ByteView args) {
    // pubkey(32) type(1) flags(1) path_len(1) path(path_len) name(32)
    // last_advert(4) [lat(4) lon(4)]
    if (args.size() < 35) return resp_err(kErrIllegalArg);

    ByteView pubkey = subview(args, 0, crypto::kPubKeySize);
    uint8_t type = args[32];
    uint8_t flags = args[33];
    uint8_t path_len = args[34];

    if (path_len != kNoPath && args.size() < 35u + path_len) return resp_err(kErrIllegalArg);

    mesh::Contact* c = contacts_.upsert(pubkey);
    if (!c) return resp_err(kErrTableFull);
    c->type = type;
    c->flags = flags;

    size_t off = 35;
    if (path_len == kNoPath) {
        contacts_.clear_path(*c);
    } else {
        contacts_.set_path(*c, subview(args, off, path_len));
        off += path_len;
    }

    if (args.size() >= off + kContactNameField) {
        c->name = rd_fixed_str(args, off, kContactNameField);
        off += kContactNameField;
    }
    if (args.size() >= off + 4) {
        c->adv_timestamp = rd_u32(args, off);
        off += 4;
    }
    if (args.size() >= off + 8) {
        c->lat_e6 = rd_i32(args, off);
        c->lon_e6 = rd_i32(args, off + 4);
    }

    contacts_.mark_dirty();
    LOG_INFO("companion: contact %s (%s) added/updated", hex_prefix(c->pubkey).c_str(),
             c->name.c_str());
    return saved_reply();
}

Bytes Session::cmd_remove_contact(ByteView args) {
    if (args.size() < crypto::kPubKeySize) return resp_err(kErrIllegalArg);
    if (!contacts_.remove(subview(args, 0, crypto::kPubKeySize))) return resp_err(kErrNotFound);
    return saved_reply();
}

Bytes Session::cmd_reset_path(ByteView args) {
    if (args.size() < crypto::kPubKeySize) return resp_err(kErrIllegalArg);
    mesh::Contact* c = contacts_.find(subview(args, 0, crypto::kPubKeySize));
    if (!c) return resp_err(kErrNotFound);

    // Forget the route so the next message floods and rediscovers it.
    contacts_.clear_path(*c);
    LOG_INFO("companion: reset path to %s", hex_prefix(c->pubkey).c_str());
    return saved_reply();
}

Bytes Session::cmd_export_contact(ByteView args) {
    // The payload is a complete signed advert packet, which is what the app
    // encodes into a meshcore:// URI. A bare public key is not importable:
    // the receiving node verifies the signature before trusting the name.
    if (args.size() >= crypto::kPubKeySize) {
        // Re-exporting someone else's card needs their original signed advert,
        // which we cannot forge and do not retain.
        const mesh::Contact* c = contacts_.find(subview(args, 0, crypto::kPubKeySize));
        if (!c) return resp_err(kErrNotFound);
        LOG_INFO("companion: cannot export %s — peer adverts are not retained",
                 hex_prefix(c->pubkey).c_str());
        return resp_err(kErrNotFound);
    }

    auto advert = node_.build_advert_packet(true);
    if (!advert) return resp_err(kErrBadState);

    Bytes out {kRespExportContact};
    put_bytes(out, advert->encode());
    return out;
}

Bytes Session::cmd_send_txt_msg(ByteView args) {
    // txt_type(1) attempt(1) timestamp(4) pubkey_prefix(6) message
    if (args.size() < 12) return resp_err(kErrIllegalArg);

    uint8_t txt_type = args[0];
    uint32_t timestamp = rd_u32(args, 2);
    ByteView prefix = subview(args, 6, 6);
    std::string text = to_string(subview(args, 12));

    // The app addresses contacts by a 6-byte key prefix, not the full key.
    mesh::Contact* target = nullptr;
    for (auto& c : contacts_.all()) {
        if (c.pubkey.size() >= 6 && std::equal(prefix.begin(), prefix.end(), c.pubkey.begin())) {
            target = &c;
            break;
        }
    }
    if (!target) {
        LOG_WARN("companion: no contact matching prefix %s", hex(prefix).c_str());
        return resp_err(kErrNotFound);
    }

    mesh::SendError err = mesh::SendError::None;
    auto ack = node_.send_text(*target, text, txt_type, timestamp, &err);
    if (!ack) return resp_err(send_error_code(err));

    last_send_ms_ = millis();

    Bytes out {kRespSent};
    out.push_back(target->path_known ? 0 : 1);  // 0 = direct, 1 = flood
    put_bytes(out, *ack);
    // Suggested timeout the app shows as "sending"; flood round trips are slow.
    put_u32(out, target->path_known ? 8000u : 30000u);
    return out;
}

Bytes Session::cmd_send_channel_txt_msg(ByteView args) {
    // txt_type(1) channel_index(1) timestamp(4) message
    if (args.size() < 6) return resp_err(kErrIllegalArg);

    uint8_t channel_index = args[1];
    uint32_t timestamp = rd_u32(args, 2);
    std::string text = to_string(subview(args, 6));

    if (!node_.send_channel_text(channel_index, text, timestamp)) return resp_err(kErrNotFound);

    // Plain OK, not RESP_CODE_SENT: a channel message has no addressee and so
    // no ack to correlate. Clients wait for the specific reply their command
    // expects, and answering with SENT here leaves them hanging until timeout.
    return resp_ok();
}

Bytes Session::cmd_sync_next_message(ByteView args) {
    auto msg = node_.pop_message();
    if (!msg) return Bytes {kRespNoMoreMessages};

    if (msg->is_channel) {
        Bytes out {kRespChannelMsgRecvV3};
        out.push_back(static_cast<uint8_t>(msg->snr_q4));
        out.push_back(0);  // reserved
        out.push_back(0);
        out.push_back(msg->channel_index);
        out.push_back(msg->path_len);
        out.push_back(msg->txt_type);
        put_u32(out, msg->timestamp);
        put_str(out, msg->text);
        return out;
    }

    Bytes out {kRespContactMsgRecvV3};
    out.push_back(static_cast<uint8_t>(msg->snr_q4));
    out.push_back(0);  // reserved
    out.push_back(0);
    put_padded(out, subview(msg->sender_pubkey, 0, 6), 6);
    out.push_back(msg->path_len);
    out.push_back(msg->txt_type);
    put_u32(out, msg->timestamp);
    put_str(out, msg->text);
    return out;
}

Bytes Session::cmd_get_channel(ByteView args) {
    if (args.empty()) return resp_err(kErrIllegalArg);
    uint8_t index = args[0];
    const mesh::Channel* ch = channels_.at(index);
    if (!ch) return resp_err(kErrNotFound);

    Bytes out {kRespChannelInfo};
    out.push_back(index);
    put_padded(out, to_bytes(ch->name), kChannelNameField);
    put_padded(out, ch->secret, kChannelSecretSize);
    return out;
}

Bytes Session::cmd_set_channel(ByteView args) {
    // index(1) name(32) secret(16)
    if (args.size() < 1 + kChannelNameField + kChannelSecretSize) return resp_err(kErrIllegalArg);

    uint8_t index = args[0];
    if (index >= mesh::ChannelStore::kMaxChannels) return resp_err(kErrIllegalArg);

    mesh::Channel ch;
    ch.name = rd_fixed_str(args, 1, kChannelNameField);
    ByteView secret = subview(args, 1 + kChannelNameField, kChannelSecretSize);
    ch.secret.assign(secret.begin(), secret.end());

    // An all-zero secret is how the app clears a slot.
    if (std::all_of(ch.secret.begin(), ch.secret.end(), [](uint8_t b) { return b == 0; }))
        ch.secret.clear();

    channels_.set(index, std::move(ch));
    LOG_INFO("companion: channel %u set", index);
    return saved_reply();
}

Bytes Session::cmd_set_advert_name(ByteView args) {
    if (args.empty()) return resp_err(kErrIllegalArg);
    node_.config().name = to_string(args);
    LOG_INFO("companion: advert name set to \"%s\"", node_.config().name.c_str());
    return resp_ok();
}

Bytes Session::cmd_set_advert_latlon(ByteView args) {
    if (args.size() < 8) return resp_err(kErrIllegalArg);
    auto& cfg = node_.config();
    cfg.lat_e6 = rd_i32(args, 0);
    cfg.lon_e6 = rd_i32(args, 4);
    cfg.has_location = cfg.lat_e6 != 0 || cfg.lon_e6 != 0;
    LOG_INFO("companion: advert location set to %.6f, %.6f", cfg.lat_e6 / 1e6, cfg.lon_e6 / 1e6);
    return resp_ok();
}

Bytes Session::cmd_get_battery(ByteView args) {
    auto storage = metrics_.storage();

    Bytes out {kRespBatteryVoltage};
    put_u16(out, metrics_.battery_mv());
    put_u32(out, to_kb(storage.used_bytes));
    put_u32(out, to_kb(storage.total_bytes));
    return out;
}

Bytes Session::cmd_set_radio_params(ByteView args) {
    // Radio parameters come from the config file and require re-initialising
    // the SX1262; accepting them here would silently do nothing.
    LOG_INFO("companion: radio parameter change refused (set them in the config file)");
    return Bytes {kRespDisabled};
}

// ---------------------------------------------------------------------------
// Pushes
// ---------------------------------------------------------------------------

void Session::on_advert_seen(const mesh::Contact& c) {
    Bytes out {kPushAdvert};
    put_bytes(out, c.pubkey);
    reply(out);
}

void Session::on_contact_changed(const mesh::Contact& c, bool is_new) {
    if (is_new) {
        Bytes out {kPushNewAdvert};
        put_bytes(out, c.pubkey);
        reply(out);
    }
    state_.request_save();
}

void Session::on_path_updated(const mesh::Contact& c) {
    Bytes out {kPushPathUpdated};
    put_bytes(out, c.pubkey);
    reply(out);
}

void Session::on_message_stored() { reply(Bytes {kPushMsgWaiting}); }

void Session::on_ack(ByteView ack_hash) {
    Bytes out {kPushSendConfirmed};
    put_bytes(out, ack_hash);
    put_u32(out, last_send_ms_ ? millis() - last_send_ms_ : 0);
    reply(out);
}

void Session::on_raw_rx(const proto::Packet& p, ByteView raw) {
    // The app derives repeat counts and its Discover list from seeing every
    // packet, including duplicates.
    Bytes out {kPushLogRxData};
    out.push_back(static_cast<uint8_t>(static_cast<int8_t>(std::clamp(p.snr * 4.0f, -128.0f, 127.0f))));
    out.push_back(static_cast<uint8_t>(static_cast<int8_t>(std::clamp(p.rssi, -128, 127))));
    put_bytes(out, raw);
    reply(out);
}

}  // namespace umc::companion
