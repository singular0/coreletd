#include "companion/session.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <iterator>

#include "util/clock.h"
#include "util/hex.h"
#include "util/log.h"

namespace clt::companion {

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

// The only frequencies at which MeshCore lets an app turn repeat on
// (repeat_freq_ranges in its companion), in kHz as the command carries them.
// It is a check on the app, as it is in MeshCore: a repeat written into the
// settings file by hand is not held to these.
constexpr uint32_t kRepeatFreqsKhz[] = {433000, 869495, 918000};

// MeshCore's companion clamps the airtime factor to 0-9 when it loads its
// preferences. The wire carries it in thousandths.
constexpr uint32_t kMaxAirtimeFactorMilli = 9000;

// The values below go to the config as the text a line of the settings file
// would hold, so each is spelled out exactly rather than through a double.
std::string mhz_from_khz(uint32_t khz) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%u.%03u", khz / 1000, khz % 1000);
    return buf;
}

std::string degrees_from_e6(int32_t e6) {
    const long long v = e6;
    const long long magnitude = v < 0 ? -v : v;
    char buf[24];
    snprintf(buf, sizeof(buf), "%s%lld.%06lld", v < 0 ? "-" : "", magnitude / 1000000,
             magnitude % 1000000);
    return buf;
}

std::string exact(double v) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%.17g", v);
    return buf;
}

}  // namespace

Session::Session(const Clock& clock, Server& server, mesh::Node& node,
                 mesh::ContactStore& contacts, mesh::ChannelStore& channels, radio::Radio& radio,
                 mesh::StateWriter& state, const DeviceMetrics& metrics, Settings& settings)
    : clock_(clock),
      server_(server),
      node_(node),
      contacts_(contacts),
      channels_(channels),
      radio_(radio),
      state_(state),
      metrics_(metrics),
      settings_(settings) {}

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

Bytes Session::settings_reply(std::vector<Settings::Change> changes) {
    switch (settings_.set(changes)) {
        case Settings::Result::Ok: return resp_ok();
        case Settings::Result::Invalid: return resp_err(kErrIllegalArg);
        case Settings::Result::IoError: return resp_err(kErrFileIoError);
    }
    return resp_err(kErrBadState);
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
        case kCmdAppStart:
            // SELF_INFO first, then the inbox. Anything that arrived before the
            // app identified itself had its PUSH_MSG_WAITING dropped by the
            // gate, so without this the app would not learn of waiting messages
            // until the next one came in.
            reply(cmd_app_start(args));
            if (node_.has_messages()) push(Bytes {kPushMsgWaiting});
            return;
        case kCmdDeviceQuery: out = cmd_device_query(args); break;
        case kCmdGetDeviceTime: {
            out = Bytes {kRespCurrTime};
            put_u32(out, unix_now());
            break;
        }
        case kCmdSetDeviceTime: {
            Reader r(args);
            uint32_t app_time = r.u32();
            if (!r.ok()) {
                out = resp_err(kErrIllegalArg);
                break;
            }
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
        case kCmdSetRadioTxPower: out = cmd_set_tx_power(args); break;
        case kCmdSetTuningParams: out = cmd_set_tuning_params(args); break;
        case kCmdGetTuningParams: out = cmd_get_tuning_params(args); break;
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
    out.push_back(static_cast<uint8_t>(radio::kMaxTxPowerDbm));
    put_bytes(out, node_.self().pub());
    put_i32(out, cfg.lat_e6);
    put_i32(out, cfg.lon_e6);
    out.push_back(0);  // multi-acks
    out.push_back(0);  // advert location policy
    out.push_back(0);  // telemetry mode
    out.push_back(0);  // manual add contacts
    // Rounded, not truncated: 869.525 is a hair under itself in binary, and
    // would otherwise come back to the app as 869.524.
    put_u32(out, static_cast<uint32_t>(std::lround(rp.freq_mhz * 1000.0)));
    put_u32(out, static_cast<uint32_t>(std::lround(rp.bw_khz * 1000.0)));
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
    put_u32(out, 0);  // BLE pin, not applicable to either stream transport
    put_padded(out, to_bytes(info.firmware_build), 12);
    put_padded(out, to_bytes(info.model), 40);
    put_padded(out, to_bytes(info.version), 20);
    // MeshCore's v9 and v10 bytes, past the version we claim. A client that
    // parses by version stops before them, but SET_RADIO_PARAMS without its
    // repeat byte turns repeat off, so a client keeping it on has to be able
    // to read it from somewhere.
    out.push_back(node_.config().repeat ? 1 : 0);
    out.push_back(0);  // path hash mode: one-byte hashes
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
    Reader r(args);
    uint32_t since = r.has(4) ? r.u32() : 0;

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
    Reader r(args);
    ByteView pubkey = r.take(crypto::kPubKeySize);
    if (!r.ok()) return resp_err(kErrIllegalArg);

    const mesh::Contact* c = contacts_.find(pubkey);
    if (!c) return resp_err(kErrNotFound);
    return contact_frame(kRespContact, *c);
}

Bytes Session::cmd_add_update_contact(ByteView args) {
    // pubkey(32) type(1) flags(1) path_len(1) path(64) name(32)
    // last_advert(4) [lat(4) lon(4)]
    //
    // The path field is a fixed 64 bytes with only the first path_len
    // meaningful, exactly as contact_frame() writes it. Consuming path_len
    // bytes instead would leave every later field short by the padding.
    Reader r(args);
    ByteView pubkey = r.take(crypto::kPubKeySize);
    uint8_t type = r.u8();
    uint8_t flags = r.u8();
    uint8_t path_len = r.u8();
    ByteView path_field = r.take(kContactPathField);
    if (!r.ok()) return resp_err(kErrIllegalArg);
    if (path_len != kNoPath && path_len > kContactPathField) return resp_err(kErrIllegalArg);
    ByteView path = path_len == kNoPath ? ByteView {} : path_field.first(path_len);

    mesh::Contact* c = contacts_.upsert(pubkey);
    if (!c) return resp_err(kErrTableFull);
    c->type = type;
    c->flags = flags;

    if (path_len == kNoPath)
        contacts_.clear_path(*c);
    else
        contacts_.set_path(*c, path);

    // The tail is optional, one field at a time: an app may stop after the
    // path, after the name, or after the timestamp.
    if (r.has(kContactNameField)) c->name = r.fixed_str(kContactNameField);
    if (r.has(4)) c->adv_timestamp = r.u32();
    if (r.has(8)) {
        c->lat_e6 = r.i32();
        c->lon_e6 = r.i32();
    }

    contacts_.mark_dirty();
    LOG_INFO("companion: contact %s (%s) added/updated", hex_prefix(c->pubkey).c_str(),
             c->name.c_str());
    return saved_reply();
}

Bytes Session::cmd_remove_contact(ByteView args) {
    Reader r(args);
    ByteView pubkey = r.take(crypto::kPubKeySize);
    if (!r.ok()) return resp_err(kErrIllegalArg);

    if (!contacts_.remove(pubkey)) return resp_err(kErrNotFound);
    return saved_reply();
}

Bytes Session::cmd_reset_path(ByteView args) {
    Reader r(args);
    ByteView pubkey = r.take(crypto::kPubKeySize);
    if (!r.ok()) return resp_err(kErrIllegalArg);

    mesh::Contact* c = contacts_.find(pubkey);
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
    Reader r(args);
    if (r.has(crypto::kPubKeySize)) {
        // Re-exporting someone else's card needs their original signed advert,
        // which we cannot forge and do not retain.
        const mesh::Contact* c = contacts_.find(r.take(crypto::kPubKeySize));
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
    Reader r(args);
    uint8_t txt_type = r.u8();
    r.skip(1);  // attempt: the node runs its own retry ladder
    uint32_t timestamp = r.u32();
    ByteView prefix = r.take(6);
    if (!r.ok()) return resp_err(kErrIllegalArg);

    std::string text = to_string(r.rest());

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

    last_send_ms_ = clock_.now_ms();

    Bytes out {kRespSent};
    out.push_back(target->path_known ? 0 : 1);  // 0 = direct, 1 = flood
    put_bytes(out, *ack);
    // Suggested timeout the app shows as "sending"; flood round trips are slow.
    put_u32(out, target->path_known ? 8000u : 30000u);
    return out;
}

Bytes Session::cmd_send_channel_txt_msg(ByteView args) {
    // txt_type(1) channel_index(1) timestamp(4) message
    Reader r(args);
    r.skip(1);  // txt_type: channel messages are always plain
    uint8_t channel_index = r.u8();
    uint32_t timestamp = r.u32();
    if (!r.ok()) return resp_err(kErrIllegalArg);

    std::string text = to_string(r.rest());

    if (!node_.send_channel_text(channel_index, text, timestamp)) return resp_err(kErrNotFound);

    // Plain OK, not RESP_CODE_SENT: a channel message has no addressee and so
    // no ack to correlate. Clients wait for the specific reply their command
    // expects, and answering with SENT here leaves them hanging until timeout.
    return resp_ok();
}

Bytes Session::cmd_sync_next_message(ByteView args) {
    auto msg = node_.pop_message();
    if (!msg) return Bytes {kRespNoMoreMessages};

    // The queue is persisted, so a collected message has to stop being queued
    // on disk too. Coalesced like any other mutation rather than written here:
    // an app draining forty messages would otherwise cost forty rewrites, and
    // a crash in that window re-delivers rather than loses.
    state_.request_save();

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
    Reader r(args);
    uint8_t index = r.u8();
    if (!r.ok()) return resp_err(kErrIllegalArg);

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
    Reader r(args);
    uint8_t index = r.u8();
    std::string name = r.fixed_str(kChannelNameField);
    ByteView secret = r.take(kChannelSecretSize);
    if (!r.ok()) return resp_err(kErrIllegalArg);
    if (index >= mesh::ChannelStore::kMaxChannels) return resp_err(kErrIllegalArg);

    mesh::Channel ch;
    ch.name = std::move(name);
    ch.secret.assign(secret.begin(), secret.end());

    // An all-zero secret is how the app clears a slot.
    if (std::all_of(ch.secret.begin(), ch.secret.end(), [](uint8_t b) { return b == 0; }))
        ch.secret.clear();

    channels_.set(index, std::move(ch));
    LOG_INFO("companion: channel %u set", index);
    return saved_reply();
}

Bytes Session::cmd_set_advert_name(ByteView args) {
    // The rest of the frame, as MeshCore reads it; one that stops at a NUL is
    // that long. MeshCore cuts a long name to fit its buffer, but a cut name is
    // one nobody chose, so here one that does not fit the advert is refused.
    std::string name = to_string(args);
    name.resize(std::min(name.find('\0'), name.size()));
    if (name.empty()) return resp_err(kErrIllegalArg);
    return settings_reply({{"node.advert_name", name}});
}

Bytes Session::cmd_set_advert_latlon(ByteView args) {
    // lat(4) lon(4) [alt(4)], in millionths of a degree. MeshCore reads the
    // altitude for later and does nothing with it, and neither does this.
    Reader r(args);
    const int32_t lat = r.i32();
    const int32_t lon = r.i32();
    if (!r.ok()) return resp_err(kErrIllegalArg);
    return settings_reply({
        {"node.lat", degrees_from_e6(lat)},
        {"node.lon", degrees_from_e6(lon)},
    });
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
    // freq(4) in kHz, bw(4) in Hz, sf(1), cr(1), and from protocol v9 repeat(1).
    Reader r(args);
    const uint32_t freq_khz = r.u32();
    const uint32_t bw_hz = r.u32();
    const uint8_t sf = r.u8();
    const uint8_t cr = r.u8();
    if (!r.ok()) return resp_err(kErrIllegalArg);
    // Absent means off, as it does to MeshCore — even though we claim v3, and
    // a v3 client has no reason to send it. DEVICE_INFO reports the current
    // state for a client that means to keep it.
    const bool repeat = r.has(1) && r.u8() != 0;

    if (repeat && std::find(std::begin(kRepeatFreqsKhz), std::end(kRepeatFreqsKhz), freq_khz) ==
                      std::end(kRepeatFreqsKhz)) {
        LOG_INFO("companion: repeat refused at %s MHz — an app may turn it on only at 433.000, "
                 "869.495 or 918.000, as MeshCore allows",
                 mhz_from_khz(freq_khz).c_str());
        return resp_err(kErrIllegalArg);
    }
    // The config takes 0 as no frequency at all, which is not what an app
    // setting one means.
    if (freq_khz == 0) return resp_err(kErrIllegalArg);
    const auto bw = radio::nearest_bandwidth(bw_hz / 1000.0);
    if (!bw) {
        LOG_INFO("companion: no SX1262 bandwidth near %u Hz", bw_hz);
        return resp_err(kErrIllegalArg);
    }

    return settings_reply({
        {"radio.lora_freq", mhz_from_khz(freq_khz)},
        {"radio.lora_bw", exact(*bw)},
        {"radio.lora_sf", std::to_string(sf)},
        {"radio.lora_cr", std::to_string(cr)},
        {"node.repeat", repeat ? "1" : "0"},
    });
}

Bytes Session::cmd_set_tx_power(ByteView args) {
    // A signed byte, as MeshCore reads it. meshcore-cli sends a 32-bit
    // integer, and this is its low byte.
    Reader r(args);
    const int8_t dbm = static_cast<int8_t>(r.u8());
    if (!r.ok()) return resp_err(kErrIllegalArg);
    return settings_reply({{"radio.lora_tx_power", std::to_string(dbm)}});
}

Bytes Session::cmd_set_tuning_params(ByteView args) {
    // rx_delay(4) airtime_factor(4), each in thousandths.
    Reader r(args);
    const uint32_t rx_delay = r.u32();
    const uint32_t af = r.u32();
    if (!r.ok()) return resp_err(kErrIllegalArg);
    // MeshCore holds a received flood packet back before acting on it, the
    // longer the weaker it was heard, so that a better copy can overtake it.
    // Nothing here does, and accepting a delay would claim otherwise.
    if (rx_delay != 0) {
        LOG_INFO("companion: RX delay refused — not implemented, so only 0 is accepted");
        return resp_err(kErrIllegalArg);
    }
    if (af > kMaxAirtimeFactorMilli) return resp_err(kErrIllegalArg);
    // The factor is how long MeshCore keeps quiet after a transmission, as a
    // multiple of its airtime, which comes to a duty cycle of 1 / (1 + af).
    return settings_reply({{"radio.duty_cycle", exact(100.0 / (1.0 + af / 1000.0))}});
}

Bytes Session::cmd_get_tuning_params(ByteView args) {
    Bytes out {kRespTuningParams};
    put_u32(out, 0);  // RX delay: not implemented
    // A duty cycle written into the settings file by hand need not be one an
    // airtime factor makes, and is reported as the factor nearest to it.
    const double af = 100.0 / radio_.params().duty_cycle_pct - 1.0;
    put_u32(out, static_cast<uint32_t>(std::lround(af * 1000.0)));
    return out;
}

// ---------------------------------------------------------------------------
// Pushes
// ---------------------------------------------------------------------------

// Commands are answered to whoever is connected; pushes are not. Nothing here
// was requested by the client — these are mesh events that happen whether or not
// anyone is listening — so they go only to a client that said CMD_APP_START and
// thereby asked for a session.
//
// on_raw_rx is why this matters rather than merely being tidy: it forwards every
// packet the radio decodes, duplicates included, at up to kMaxPacketSize plus
// framing apiece. A client that connected to probe with DEVICE_QUERY and is not
// draining its socket reaches Server's outbound limit in about a thousand
// packets and gets disconnected for traffic it never asked for.
void Session::push(ByteView payload) {
    if (!app_started_) return;
    server_.send(payload);
}

void Session::on_advert_seen(const mesh::Contact& c) {
    Bytes out {kPushAdvert};
    put_bytes(out, c.pubkey);
    push(out);
}

void Session::on_contact_changed(const mesh::Contact& c, bool is_new) {
    if (is_new) {
        Bytes out {kPushNewAdvert};
        put_bytes(out, c.pubkey);
        push(out);
    }
    // Outside the gate: the contact changed regardless of who is listening, and
    // losing it because no app had started would be the bug from item 4 again.
    state_.request_save();
}

void Session::on_path_updated(const mesh::Contact& c) {
    Bytes out {kPushPathUpdated};
    put_bytes(out, c.pubkey);
    push(out);
}

void Session::on_message_stored() { push(Bytes {kPushMsgWaiting}); }

void Session::on_ack(ByteView ack_hash) {
    Bytes out {kPushSendConfirmed};
    put_bytes(out, ack_hash);
    put_u32(out, last_send_ms_ ? clock_.now_ms() - *last_send_ms_ : 0);
    push(out);
}

void Session::on_raw_rx(const proto::Packet& p, ByteView raw) {
    // The app derives repeat counts and its Discover list from seeing every
    // packet, including duplicates.
    Bytes out {kPushLogRxData};
    out.push_back(static_cast<uint8_t>(static_cast<int8_t>(std::clamp(p.snr * 4.0f, -128.0f, 127.0f))));
    out.push_back(static_cast<uint8_t>(static_cast<int8_t>(std::clamp(p.rssi, -128, 127))));
    put_bytes(out, raw);
    push(out);
}

}  // namespace clt::companion
