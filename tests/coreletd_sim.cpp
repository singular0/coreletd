// coreletd on a simulated radio, for driving with real companion clients.
//
// The whole daemon is App exactly as main() builds it, serving the companion
// protocol over TCP. Only the radio is replaced: the one other node on the air
// is a MeshCore peer played by this program, holding identity A of the frozen
// vectors while the daemon is B. The peer decrypts what the daemon transmits
// and reports it, acks the daemon's direct messages, and sends whatever it is
// told to. tools/cli_compat_test.py uses it to run meshcore-cli against the
// daemon without hardware; the client sees a node, and the script sees both
// what the client was told and what went out on the air.
//
//   stdin   one command per line:
//             advert          the peer's signed advert (the frozen vector)
//             text <body>     a direct message to the daemon, flood-routed
//             channel <body>  a message on the Public channel
//             path <hex>      a returned path: the route, one byte per hop
//             ack on|off      whether the peer acks the daemon's messages
//             quit
//   stdout  one JSON object per line: "ready" once the daemon is serving,
//           "heard" for each transmission the peer decoded, "sent" for each
//           thing it put on the air itself, "error" for a bad command.
//   stderr  the daemon's own log.
//
// End of input stops it, so a test that dies takes the daemon with it.

#include <poll.h>
#include <signal.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <functional>
#include <memory>
#include <optional>
#include <string>

#include "crypto/crypto.h"
#include "crypto/identity.h"
#include "daemon/app.h"
#include "mesh/channels.h"
#include "proto/packet.h"
#include "proto/payloads.h"
#include "tests/packet_vectors.h"
#include "util/hex.h"
#include "util/log.h"
#include "version.h"

using namespace clt;
namespace pv = clt::pktvec;

namespace {

volatile sig_atomic_t g_stop = 0;

void on_signal(int) { g_stop = 1; }

std::string json_str(std::string_view s) {
    std::string out = "\"";
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out + "\"";
}

// Each event is one line, flushed: the script reads them as they happen.
void emit(const std::string& fields) {
    printf("{%s}\n", fields.c_str());
    fflush(stdout);
}

// A radio with exactly one other node in range. A transmission takes its real
// airtime, so the duty-cycle accounting sees what the SX1262 would report, and
// the peer hears it when it ends.
class SimRadio final : public radio::Radio {
public:
    using Heard = std::function<void(const Bytes&)>;

    explicit SimRadio(radio::RadioParams params) : params_(params) {}

    bool begin(EventLoop& loop, std::string&) override {
        loop_ = &loop;
        return true;
    }
    bool send(ByteView data) override {
        if (busy_) return false;
        busy_ = true;
        Bytes sent(data.begin(), data.end());
        const uint32_t airtime = airtime_ms(sent.size());
        tx_done_ = loop_->add_timer(airtime, [this, sent, airtime] {
            busy_ = false;
            deliver_tx_done(airtime);
            if (heard_) heard_(sent);
        });
        return true;
    }
    bool tx_busy() const override { return busy_; }
    const radio::RadioParams& params() const override { return params_; }
    std::string describe() const override { return "simulated radio"; }
    // The peer hears whatever is sent, whatever it is sent on: the script
    // asserts on what the client is told and leaves the air settings alone.
    void reconfigure(const radio::RadioParams& params) override { params_ = params; }

    void set_heard_handler(Heard h) { heard_ = std::move(h); }
    void inject(Bytes data) {
        deliver_rx(radio::RxPacket {std::move(data), -60, 8.0f, loop_->now_ms()});
    }

private:
    radio::RadioParams params_;
    EventLoop* loop_ = nullptr;
    bool busy_ = false;
    EventLoop::Timer tx_done_;
    Heard heard_;
};

// Node A of the frozen vectors, as a MeshCore companion would behave towards
// the daemon in the few ways the tests need.
class Peer {
public:
    Peer(EventLoop& loop, SimRadio& radio, ByteView daemon_pub)
        : loop_(loop),
          radio_(radio),
          self_(*crypto::LocalIdentity::from_bytes(*unhex(pv::kPrivA))),
          daemon_pub_(daemon_pub.begin(), daemon_pub.end()),
          shared_(*self_.shared_secret(daemon_pub)),
          public_(mesh::Channel::public_channel()) {
        radio_.set_heard_handler([this](const Bytes& raw) { heard(raw); });
    }

    ByteView pub() const { return self_.pub(); }

    void command(const std::string& line) {
        const size_t space = line.find(' ');
        const std::string verb = line.substr(0, space);
        const std::string arg = space == std::string::npos ? "" : line.substr(space + 1);

        if (verb == "advert") {
            // Signed once, at a fixed time: the daemon takes it the first time
            // and rejects it as a replay after that, as it would on the air.
            radio_.inject(*unhex(pv::kAdvertPacket));
            emit("\"event\":\"sent\",\"type\":\"advert\"");
        } else if (verb == "text") {
            send_text(arg);
        } else if (verb == "channel") {
            send_channel(arg);
        } else if (verb == "path") {
            send_path(arg);
        } else if (verb == "ack" && (arg == "on" || arg == "off")) {
            acking_ = arg == "on";
        } else if (verb == "quit") {
            loop_.stop();
        } else if (!line.empty()) {
            emit("\"event\":\"error\",\"detail\":" + json_str("unknown command: " + line));
        }
    }

private:
    void send_text(const std::string& body) {
        proto::TextMessage msg;
        msg.timestamp = static_cast<uint32_t>(time(nullptr));
        msg.text = to_bytes(body);
        const Bytes plain = msg.encode();

        proto::Packet p;
        p.type = proto::PayloadType::TxtMsg;
        p.route = proto::RouteType::Flood;
        p.payload = proto::DirectEnvelope::seal(daemon_pub_[0], self_.id(), shared_, plain).encode();
        radio_.inject(p.encode());
        // What the daemon's ack has to carry if it decrypted the same text.
        emit("\"event\":\"sent\",\"type\":\"text\",\"ack\":" +
             json_str(hex(proto::message_ack_hash(plain, self_.pub()))));
    }

    void send_channel(const std::string& body) {
        proto::TextMessage msg;
        msg.timestamp = static_cast<uint32_t>(time(nullptr));
        // Group messages name their sender inline, as MeshCore writes them.
        msg.text = to_bytes(std::string(pv::kNameA) + ": " + body);

        proto::Packet p;
        p.type = proto::PayloadType::GrpTxt;
        p.route = proto::RouteType::Flood;
        p.payload = proto::GroupEnvelope::seal(public_.hash(), public_.secret, msg.encode()).encode();
        radio_.inject(p.encode());
        emit("\"event\":\"sent\",\"type\":\"channel\"");
    }

    // A route the daemon should use to reach the peer, returned the way a
    // MeshCore node returns one: sealed, and flooded, since the peer has no
    // route back yet either.
    void send_path(const std::string& hops_hex) {
        auto hops = unhex(hops_hex);
        if (!hops) {
            emit("\"event\":\"error\",\"detail\":" + json_str("bad path: " + hops_hex));
            return;
        }
        proto::PathReturn ret;
        ret.path = *hops;

        proto::Packet p;
        p.type = proto::PayloadType::Path;
        p.route = proto::RouteType::Flood;
        p.payload =
            proto::DirectEnvelope::seal(daemon_pub_[0], self_.id(), shared_, ret.encode()).encode();
        radio_.inject(p.encode());
        emit("\"event\":\"sent\",\"type\":\"path\",\"path\":" + json_str(hops_hex));
    }

    void heard(const Bytes& raw) {
        auto p = proto::Packet::decode(raw);
        if (!p) {
            emit("\"event\":\"heard\",\"type\":\"undecodable\",\"raw\":" + json_str(hex(raw)));
            return;
        }
        const std::string head = "\"event\":\"heard\",\"route\":" +
                                 json_str(proto::route_type_name(p->route)) +
                                 ",\"hops\":" + std::to_string(p->hop_count());
        switch (p->type) {
            case proto::PayloadType::Advert: heard_advert(head, *p); break;
            case proto::PayloadType::TxtMsg: heard_text(head, *p); break;
            case proto::PayloadType::GrpTxt: heard_channel(head, *p); break;
            case proto::PayloadType::Path: heard_path(head, *p); break;
            case proto::PayloadType::Ack:
                emit(head + ",\"type\":\"ack\",\"ack\":" +
                     json_str(hex(subview(p->payload, 0, crypto::kAckHashSize))));
                break;
            default:
                emit(head + ",\"type\":" + json_str(proto::payload_type_name(p->type)));
                break;
        }
    }

    void heard_advert(const std::string& head, const proto::Packet& p) {
        auto adv = proto::Advert::decode(p.payload);
        if (!adv) {
            emit(head + ",\"type\":\"advert\",\"verified\":false");
            return;
        }
        auto app = proto::AdvertAppData::decode(adv->appdata);
        emit(head + ",\"type\":\"advert\",\"verified\":" + (adv->verify() ? "true" : "false") +
             ",\"key\":" + json_str(hex(adv->pubkey)) +
             ",\"name\":" + json_str(app ? app->name : "") +
             ",\"timestamp\":" + std::to_string(adv->timestamp));
    }

    // Only ever from the daemon, and only to us: the air has nobody else on it.
    std::optional<Bytes> open(const proto::Packet& p) {
        auto env = proto::DirectEnvelope::decode(p.payload);
        if (!env || env->dest_hash != self_.id()) return std::nullopt;
        return crypto::mac_and_decrypt(shared_, env->mac, env->ciphertext);
    }

    void heard_text(const std::string& head, const proto::Packet& p) {
        auto plain = open(p);
        auto msg = plain ? proto::TextMessage::decode(*plain) : std::nullopt;
        if (!msg) {
            emit(head + ",\"type\":\"text\",\"opened\":false");
            return;
        }
        // The author's key, since this is plain text rather than signed.
        const Bytes ack = proto::message_ack_hash(*plain, daemon_pub_);
        emit(head + ",\"type\":\"text\",\"opened\":true,\"text\":" + json_str(msg->body()) +
             ",\"attempt\":" + std::to_string(msg->attempt) + ",\"ack\":" + json_str(hex(ack)));
        if (!acking_) return;

        // A plain ack rather than MeshCore's path return with the ack inside:
        // the tests are about what the client is told, and this leaves the
        // daemon without a route unless a test hands it one.
        proto::Packet reply;
        reply.type = proto::PayloadType::Ack;
        reply.route = proto::RouteType::Flood;
        reply.payload = proto::ack_payload(ack, proto::ack_extended_attempt(*plain));
        pending_ack_ = loop_.add_timer(100, [this, raw = reply.encode()] { radio_.inject(raw); });
    }

    void heard_channel(const std::string& head, const proto::Packet& p) {
        auto env = proto::GroupEnvelope::decode(p.payload);
        auto plain = env && env->channel_hash == public_.hash()
                         ? crypto::mac_and_decrypt(public_.secret, env->mac, env->ciphertext)
                         : std::nullopt;
        auto msg = plain ? proto::TextMessage::decode(*plain) : std::nullopt;
        if (!msg) {
            emit(head + ",\"type\":\"channel\",\"opened\":false");
            return;
        }
        emit(head + ",\"type\":\"channel\",\"opened\":true,\"channel\":\"Public\",\"text\":" +
             json_str(msg->body()));
    }

    void heard_path(const std::string& head, const proto::Packet& p) {
        auto plain = open(p);
        auto ret = plain ? proto::PathReturn::decode(*plain) : std::nullopt;
        if (!ret) {
            emit(head + ",\"type\":\"path\",\"opened\":false");
            return;
        }
        std::string fields = head + ",\"type\":\"path\",\"opened\":true,\"path\":" +
                             json_str(hex(ret->path));
        if (ret->has_extra && ret->extra_type == static_cast<uint8_t>(proto::PayloadType::Ack))
            fields += ",\"ack\":" + json_str(hex(subview(ret->extra, 0, crypto::kAckHashSize)));
        emit(fields);
    }

    EventLoop& loop_;
    SimRadio& radio_;
    crypto::LocalIdentity self_;
    Bytes daemon_pub_;
    Bytes shared_;
    mesh::Channel public_;
    bool acking_ = true;
    EventLoop::Timer pending_ack_;
};

int usage() {
    fprintf(stderr,
            "usage: coreletd_sim --state-dir DIR --port N [--name NAME] [--log-level LEVEL]\n"
            "  DIR must exist; the daemon's identity is written into it.\n");
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    std::string state_dir, name = "coreletd-sim";
    int port = 0;
    LogLevel level = LogLevel::Info;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (i + 1 >= argc) return usage();
        if (a == "--state-dir") state_dir = argv[++i];
        else if (a == "--port") port = atoi(argv[++i]);
        else if (a == "--name") name = argv[++i];
        else if (a == "--log-level") {
            if (!log_parse_level(argv[++i], level)) return usage();
        } else {
            return usage();
        }
    }
    if (state_dir.empty() || port <= 0 || port > 65535) return usage();
    if (!crypto::init()) return 1;

    Config cfg;
    cfg.log_level = level;
    cfg.state_dir = state_dir;
    cfg.node.name = name;
    cfg.radio.freq_mhz = 869.618;  // MeshCore's EU narrow preset, so SELF_INFO looks like a node
    cfg.companion.transport = companion::Server::Transport::Tcp;
    cfg.companion.bind_addr = "127.0.0.1";
    cfg.companion.port = static_cast<uint16_t>(port);
    cfg.finalise();
    log_set_level(level);

    // The daemon is B, so that A's frozen advert is from a stranger to it.
    auto self = crypto::LocalIdentity::from_bytes(*unhex(pv::kPrivB));
    if (!self || !self->save(cfg.identity_path())) {
        fprintf(stderr, "coreletd_sim: cannot write %s\n", cfg.identity_path().c_str());
        return 1;
    }

    auto radio_owned = std::make_unique<SimRadio>(cfg.radio);
    SimRadio& radio = *radio_owned;
    App app(std::move(cfg), std::move(radio_owned));

    struct sigaction sa {};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    signal(SIGPIPE, SIG_IGN);

    if (!app.start()) return 1;
    app.loop().set_interrupt_check([] { return g_stop != 0; });

    Peer peer(app.loop(), radio, self->pub());

    std::string pending;
    EventLoop::FdWatch input = app.loop().add_fd(STDIN_FILENO, POLLIN, [&](short) {
        char buf[1024];
        ssize_t n = ::read(STDIN_FILENO, buf, sizeof(buf));
        if (n <= 0) {
            app.loop().stop();
            return;
        }
        pending.append(buf, static_cast<size_t>(n));
        for (size_t nl; (nl = pending.find('\n')) != std::string::npos;) {
            std::string line = pending.substr(0, nl);
            pending.erase(0, nl + 1);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            peer.command(line);
        }
    });

    emit("\"event\":\"ready\",\"port\":" + std::to_string(port) +
         ",\"key\":" + json_str(hex(self->pub())) + ",\"name\":" + json_str(name) +
         ",\"version\":" + json_str(CORELETD_VERSION) +
         ",\"peer_key\":" + json_str(hex(peer.pub())) +
         ",\"peer_name\":" + json_str(pv::kNameA));

    app.run();
    app.request_stop();
    return 0;
}
