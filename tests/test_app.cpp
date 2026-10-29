// The daemon as a whole, stood up in-process. App takes the radio and the clock
// from the caller, so these tests own both ends of it: packets arrive when the
// test injects them, replies are the bytes the radio was handed, and time only
// moves when the test moves it. Everything in between — dispatcher, node,
// sender, stores, companion session — is wired by App exactly as `main()` gets
// it, which is the point: nothing here constructs a subsystem.

#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <string>

#include "companion/frames.h"
#include "crypto/crypto.h"
#include "crypto/identity.h"
#include "daemon/app.h"
#include "mesh/channels.h"
#include "mesh/contacts.h"
#include "proto/packet.h"
#include "proto/payloads.h"
#include "tests/gated_radio.h"
#include "tests/packet_vectors.h"
#include "tests/test_util.h"

using namespace clt;
using namespace clt::test;
using namespace clt::companion;
namespace pv = clt::pktvec;

namespace {

// One state directory per test, emptied first so that what a previous run left
// behind cannot make a test pass.
std::string fresh_state_dir(const char* name) {
    std::string dir = std::string("/tmp/coreletd_test_app_") + name;
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    std::filesystem::create_directories(dir, ec);
    return dir;
}

// A node an app has tuned already, since nothing transmits without a
// frequency. The app keys set here stand where the code's defaults would.
Config harness_config(const std::string& state_dir) {
    Config cfg;
    cfg.state_dir = state_dir;
    cfg.radio.freq_mhz = 869.618;
    cfg.companion.socket_path = state_dir + "/companion.sock";
    cfg.finalise();
    return cfg;
}

// The frozen vectors are a conversation between identities A and B, so the
// daemon has to be B for the reference packets to be addressed to it. Writing
// the key beforehand also puts startup on the load-an-existing-key path.
bool install_identity(const Config& cfg, std::string_view priv) {
    auto id = crypto::LocalIdentity::from_bytes(from_hex(priv));
    return id && id->save(cfg.identity_path());
}

// Lets the daemon run over `ms` of virtual time. run() rather than
// EventLoop::advance(): advance() never enters poll(), so it would not notice
// the companion socket.
void run_for(App& app, uint32_t ms) {
    EventLoop::Timer stop = app.loop().add_timer(ms, [&app] { app.loop().stop(); });
    app.loop().run();
}

// A companion app on the other end of the default Unix socket: sends command
// frames and picks replies out of the stream by response code, which is what a
// real client does too — advisory pushes for the traffic under test share it.
class Client {
public:
    Client(App& app, const std::string& socket_path) : app_(app) {
        fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd_ < 0) return;
        sockaddr_un addr {};
        addr.sun_family = AF_UNIX;
        if (socket_path.size() >= sizeof(addr.sun_path)) {
            ::close(fd_);
            fd_ = -1;
            return;
        }
        memcpy(addr.sun_path, socket_path.c_str(), socket_path.size() + 1);
        if (::connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }
    ~Client() {
        if (fd_ >= 0) ::close(fd_);
    }
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    bool connected() const { return fd_ >= 0; }

    void send(const Bytes& payload) {
        Bytes framed {kFrameToDevice};
        put_u16(framed, static_cast<uint16_t>(payload.size()));
        put_bytes(framed, payload);
        // A few dozen bytes onto a fresh loopback socket: a short write would be
        // a broken test rather than something to handle.
        ssize_t n = ::write(fd_, framed.data(), framed.size());
        CHECK_EQ(n, static_cast<ssize_t>(framed.size()));
    }

    // Runs the daemon until a frame carrying `code` turns up, or gives up and
    // returns empty rather than hanging.
    Bytes await(uint8_t code) {
        for (int round = 0; round < 20; round++) {
            drain(round == 0 ? 0 : 5);
            for (;;) {
                auto frame = reader_.next();
                if (!frame) break;
                if (!frame->empty() && (*frame)[0] == code) return *frame;
            }
            run_for(app_, 1);
        }
        return {};
    }

    // The answer to the last command. Replies are untagged, so it is the next
    // frame that is not a push, whatever its code.
    Bytes reply() {
        for (int round = 0; round < 20; round++) {
            drain(round == 0 ? 0 : 5);
            for (;;) {
                auto frame = reader_.next();
                if (!frame) break;
                if (!frame->empty() && (*frame)[0] < kPushAdvert) return *frame;
            }
            run_for(app_, 1);
        }
        return {};
    }

    Bytes command(const Bytes& payload) {
        send(payload);
        return reply();
    }

    // The codes of whatever the daemon has written so far, in order. await()
    // waits for a frame to turn up and so cannot show that none did; this can.
    std::vector<uint8_t> drained() {
        run_for(app_, 1);
        drain(5);
        std::vector<uint8_t> codes;
        for (;;) {
            auto frame = reader_.next();
            if (!frame) break;
            if (!frame->empty()) codes.push_back((*frame)[0]);
        }
        return codes;
    }

private:
    // Reads whatever the daemon has already written. The wait is real
    // milliseconds and only a backstop: replies are produced synchronously
    // inside run_for(), so they are normally in the socket buffer already.
    void drain(int wait_ms) {
        for (int timeout = wait_ms;; timeout = 0) {
            pollfd p {fd_, POLLIN, 0};
            if (::poll(&p, 1, timeout) <= 0) return;
            uint8_t buf[4096];
            ssize_t n = ::read(fd_, buf, sizeof(buf));
            if (n <= 0) return;
            reader_.feed(ByteView(buf, static_cast<size_t>(n)));
        }
    }

    App& app_;
    FrameReader reader_;
    int fd_ = -1;
};

// The reply to a flood-routed message is a PATH return with the ack inside it,
// so reading the ack means decrypting one. Returns what A would decode.
std::optional<proto::PathReturn> path_return_to_a(const proto::Packet& p) {
    auto peer = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivB));
    if (!peer || !self) return std::nullopt;
    auto shared = peer->shared_secret(self->pub());
    if (!shared) return std::nullopt;
    auto env = proto::DirectEnvelope::decode(p.payload);
    if (!env) return std::nullopt;
    auto plain = crypto::mac_and_decrypt(*shared, env->mac, env->ciphertext);
    if (!plain) return std::nullopt;
    return proto::PathReturn::decode(*plain);
}

// The bundled ack, checked the way A would: the first four bytes are the hash,
// and everything past the six MeshCore writes is block padding.
void check_bundled_ack(const proto::Packet& sent, std::string_view want_hash) {
    CHECK(sent.type == proto::PayloadType::Path);
    auto ret = path_return_to_a(sent);
    CHECK(ret.has_value());
    if (!ret) return;
    CHECK_EQ(ret->extra_type, static_cast<uint8_t>(proto::PayloadType::Ack));
    CHECK(ret->extra.size() >= 6);
    if (ret->extra.size() >= 4) CHECK_BYTES(subview(ret->extra, 0, 4), from_hex(want_hash));
}

// SELF_INFO, as an app reads it on connecting.
struct SelfInfo {
    uint8_t tx_power = 0;
    uint8_t max_tx_power = 0;
    int32_t lat_e6 = 0;
    int32_t lon_e6 = 0;
    uint32_t freq_khz = 0;
    uint32_t bw_hz = 0;
    uint8_t sf = 0;
    uint8_t cr = 0;
    std::string name;
};

std::optional<SelfInfo> self_info(Client& client) {
    Bytes start {kCmdAppStart, 0, 0, 0, 0, 0, 0, 0};
    put_str(start, "test");
    client.send(start);
    Bytes frame = client.await(kRespSelfInfo);
    // code, adv_type, tx power, max tx power, key, lat, lon, four policy
    // bytes, freq, bw, sf, cr, then the name.
    Reader r(subview(frame, 1));
    SelfInfo info;
    r.skip(1);
    info.tx_power = r.u8();
    info.max_tx_power = r.u8();
    r.skip(crypto::kPubKeySize);
    info.lat_e6 = r.i32();
    info.lon_e6 = r.i32();
    r.skip(4);
    info.freq_khz = r.u32();
    info.bw_hz = r.u32();
    info.sf = r.u8();
    info.cr = r.u8();
    if (!r.ok()) return std::nullopt;
    info.name = to_string(r.rest());
    return info;
}

// DEVICE_INFO's trailing bytes: MeshCore's v9 repeat flag and v10 path-hash
// mode, past the 79 bytes of the version we claim.
constexpr size_t kDeviceInfoRepeatAt = 80;

int repeat_reported(Client& client) {
    Bytes info = client.command(Bytes {kCmdDeviceQuery, 3});
    CHECK_EQ(info.size(), kDeviceInfoRepeatAt + 2);
    return info.size() > kDeviceInfoRepeatAt ? info[kDeviceInfoRepeatAt] : -1;
}

Bytes set_name(std::string_view name) {
    Bytes out {kCmdSetAdvertName};
    put_str(out, name);
    return out;
}

Bytes set_latlon(int32_t lat_e6, int32_t lon_e6) {
    Bytes out {kCmdSetAdvertLatLon};
    put_i32(out, lat_e6);
    put_i32(out, lon_e6);
    put_i32(out, 0);  // altitude, which meshcore-cli sends and nothing reads
    return out;
}

Bytes set_radio(uint32_t freq_khz, uint32_t bw_hz, uint8_t sf, uint8_t cr,
                std::optional<uint8_t> repeat = std::nullopt) {
    Bytes out {kCmdSetRadioParams};
    put_u32(out, freq_khz);
    put_u32(out, bw_hz);
    out.push_back(sf);
    out.push_back(cr);
    if (repeat) out.push_back(*repeat);
    return out;
}

Bytes set_tx_power(int8_t dbm) { return Bytes {kCmdSetRadioTxPower, static_cast<uint8_t>(dbm)}; }

Bytes set_tuning(uint32_t rx_delay, uint32_t af_milli) {
    Bytes out {kCmdSetTuningParams};
    put_u32(out, rx_delay);
    put_u32(out, af_milli);
    return out;
}

const Bytes kOk {kRespOk};
const Bytes kIllegalArg {kRespErr, kErrIllegalArg};

// The name and position the advert on the air carries, which is what says the
// node itself took a change rather than only the reply to it.
std::optional<proto::AdvertAppData> advertised(const GatedRadio& air) {
    auto p = proto::Packet::decode(air.last_sent());
    if (!p || p->type != proto::PayloadType::Advert) return std::nullopt;
    auto adv = proto::Advert::decode(p->payload);
    if (!adv) return std::nullopt;
    return proto::AdvertAppData::decode(adv->appdata);
}

}  // namespace

// A packet goes in at the antenna and the reply comes back out of it. The only
// things the test touches are the radio and the state directory.
static void test_received_text_is_acked_on_air() {
    const std::string dir = fresh_state_dir("ack");
    Config cfg = harness_config(dir);
    CHECK(install_identity(cfg, pv::kPrivB));
    const std::string contacts_path = cfg.contacts_path();

    ManualClock clock;
    auto radio = std::make_unique<GatedRadio>();
    GatedRadio* air = radio.get();
    App app(std::move(cfg), std::move(radio), clock);
    CHECK(app.start());
    air->set_ready(true);

    // A's advert is how the daemon comes to hold the contact it will later
    // decrypt from, in the order a real mesh delivers them.
    air->inject(from_hex(pv::kAdvertPacket));
    CHECK_EQ(air->send_count(), size_t {0});  // a companion node repeats nothing

    air->inject(from_hex(pv::kTextPacket));

    // The reply needs no timer to get out: the radio is ready and nothing is
    // queued ahead of it. The reference packet is flood-routed, so the reply is
    // a PATH return teaching A the way back, with the ack riding inside it
    // rather than costing a second transmission — and flooded, as MeshCore
    // floods it, since A's advert taught us no route to A either.
    CHECK_EQ(air->send_count(), size_t {1});
    auto sent = proto::Packet::decode(air->last_sent());
    CHECK(sent.has_value());
    if (!sent) return;
    check_bundled_ack(*sent, pv::kTextAckHash);
    CHECK(sent->is_flood());

    // Shutting down flushes what the exchange changed, so the contact A
    // advertised is on disk under the name it advertised.
    app.request_stop();

    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivB));
    CHECK(self.has_value());
    if (!self) return;
    mesh::ContactStore reloaded(*self, contacts_path);
    CHECK(reloaded.load() == mesh::LoadResult::Loaded);
    const Bytes a_pub = from_hex(pv::kPubA);
    mesh::Contact* a = reloaded.find(a_pub);
    CHECK(a != nullptr);
    if (a) CHECK(a->name == pv::kNameA);
}

// The radio keeps running with no app attached, and the ack the daemon sent
// told the sender to stop retrying. So a message received while nobody was
// collecting has to still be there after a restart: there is nobody left to
// ask for it again.
static void test_message_received_offline_survives_a_restart() {
    const std::string dir = fresh_state_dir("inboxrestart");
    Config cfg = harness_config(dir);
    CHECK(install_identity(cfg, pv::kPrivB));
    const std::string socket_path = cfg.companion.socket_path;
    Config second = harness_config(dir);

    {
        ManualClock clock;
        auto radio = std::make_unique<GatedRadio>();
        GatedRadio* air = radio.get();
        App app(std::move(cfg), std::move(radio), clock);
        CHECK(app.start());
        air->set_ready(true);

        // No companion app ever connects during this run.
        air->inject(from_hex(pv::kAdvertPacket));
        air->inject(from_hex(pv::kTextPacket));

        // The ack went out, which is the promise that makes losing it a fault.
        CHECK_EQ(air->send_count(), size_t {1});
        auto sent = proto::Packet::decode(air->last_sent());
        CHECK(sent.has_value());
        if (sent) check_bundled_ack(*sent, pv::kTextAckHash);

        app.request_stop();
    }

    // A second daemon over the same state directory, as a restart would be.
    ManualClock clock;
    auto radio = std::make_unique<GatedRadio>();
    App app(std::move(second), std::move(radio), clock);
    CHECK(app.start());

    Client client(app, socket_path);
    CHECK(client.connected());
    if (!client.connected()) return;

    client.send(Bytes {kCmdAppStart, 1, 0, 0, 0, 0, 0, 't', 'e', 's', 't'});
    CHECK(!client.await(kRespSelfInfo).empty());

    client.send(Bytes {kCmdSyncNextMessage});
    Bytes msg = client.await(kRespContactMsgRecvV3);
    CHECK(!msg.empty());
    if (msg.empty()) return;

    // snr(1) reserved(2) pubkey(6) path_len(1) txt_type(1) timestamp(4), then
    // the text the sender wrote.
    const size_t kTextAt = 1 + 1 + 2 + 6 + 1 + 1 + 4;
    CHECK(msg.size() > kTextAt);
    if (msg.size() > kTextAt) {
        std::string text(msg.begin() + kTextAt, msg.end());
        CHECK(text == pv::kTextBody);
    }

    // And it is a pop, not a peek: the queue is empty behind it.
    client.send(Bytes {kCmdSyncNextMessage});
    CHECK(!client.await(kRespNoMoreMessages).empty());

    app.request_stop();
}

// MeshCore reports a received message's path the opposite way round from the
// intuitive reading: 0xFF says it came direct, and anything else is the flood
// path_length byte the packet arrived with. Clients depend on exactly that — the
// Python client tests `plen == 255` for direct and meshcore-cli renders it as
// "D" — so getting it backwards mislabels every message in the app.
static void test_message_path_len_is_meshcores_way_round() {
    const std::string dir = fresh_state_dir("pathlen");
    Config cfg = harness_config(dir);
    CHECK(install_identity(cfg, pv::kPrivB));
    const std::string socket_path = cfg.companion.socket_path;

    ManualClock clock;
    auto radio = std::make_unique<GatedRadio>();
    GatedRadio* air = radio.get();
    App app(std::move(cfg), std::move(radio), clock);
    CHECK(app.start());
    air->set_ready(true);

    // A's advert first: without the contact there is no shared secret and the
    // text below is undecryptable.
    air->inject(from_hex(pv::kAdvertPacket));

    Client client(app, socket_path);
    CHECK(client.connected());
    if (!client.connected()) return;
    client.send(Bytes {kCmdAppStart, 1, 0, 0, 0, 0, 0, 't', 'e', 's', 't'});
    CHECK(!client.await(kRespSelfInfo).empty());

    auto peer = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivA));
    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivB));
    CHECK(peer.has_value());
    CHECK(self.has_value());
    if (!peer || !self) return;
    auto shared = peer->shared_secret(self->pub());
    CHECK(shared.has_value());
    if (!shared) return;

    // Each message needs its own timestamp: the node delivers a repeat of one
    // it has already handed over exactly once, however it was routed.
    uint32_t stamp = 1700000000;
    auto text_payload = [&](ByteView key, bool group) {
        proto::TextMessage msg;
        msg.timestamp = ++stamp;
        msg.txt_type = proto::kTxtPlain;
        msg.text = from_str(group ? "uConsole: hello" : "hello");
        return group ? proto::GroupEnvelope::seal(mesh::Channel::public_channel().hash(), key,
                                                  msg.encode())
                           .encode()
                     : proto::DirectEnvelope::seal(self->pub()[0], peer->pub()[0], key,
                                                   msg.encode())
                           .encode();
    };

    // Injects one message and returns the path_len byte the companion frame
    // reports for it, or -1 if no frame arrived.
    auto reported_path_len = [&](proto::PayloadType type, proto::RouteType route, size_t hops,
                                 bool group) -> int {
        proto::Packet p;
        p.type = type;
        p.route = route;
        p.path_hash_size = 1;
        p.path.assign(hops, 0xa1);
        p.payload = group ? text_payload(mesh::Channel::public_channel().secret, true)
                          : text_payload(*shared, false);
        air->inject(p.encode());

        client.send(Bytes {kCmdSyncNextMessage});
        const uint8_t code = group ? kRespChannelMsgRecvV3 : kRespContactMsgRecvV3;
        Bytes frame = client.await(code);
        CHECK(!frame.empty());
        // code(1) snr(1) reserved(2), then either a 6-byte sender prefix or a
        // one-byte channel index, and the path_len byte after it.
        const size_t at = group ? 5 : 10;
        if (frame.size() <= at) return -1;
        return frame[at];
    };

    // Direct: 0xFF, and never the hop count. A direct packet reaches its
    // destination with an empty path — every hop pops itself off on the way —
    // so reporting hops here would say "zero hops, flooded" for all of them.
    CHECK_EQ(reported_path_len(proto::PayloadType::TxtMsg, proto::RouteType::Direct, 0, false),
             0xFF);
    CHECK_EQ(reported_path_len(proto::PayloadType::GrpTxt, proto::RouteType::Direct, 0, true),
             0xFF);

    // Flood: the packed path_length byte, so the hop count and the hash-size
    // bits both survive to the app.
    CHECK_EQ(reported_path_len(proto::PayloadType::TxtMsg, proto::RouteType::Flood, 0, false), 0);
    CHECK_EQ(reported_path_len(proto::PayloadType::TxtMsg, proto::RouteType::Flood, 3, false), 3);
    CHECK_EQ(reported_path_len(proto::PayloadType::GrpTxt, proto::RouteType::Flood, 0, true), 0);
    CHECK_EQ(reported_path_len(proto::PayloadType::GrpTxt, proto::RouteType::Flood, 2, true), 2);

    app.request_stop();
}

// Counts the files a quarantine left behind, which is how the daemon says it
// found a state file it could not read.
static int quarantined(const std::string& dir, const std::string& stem) {
    int n = 0;
    std::error_code ec;
    for (const auto& e : std::filesystem::directory_iterator(dir, ec)) {
        const std::string name = e.path().filename().string();
        if (name.rfind(stem + ".corrupt-", 0) == 0) n++;
    }
    return n;
}

// A contacts file that cannot be parsed used to be indistinguishable from one
// that was not there: both started an empty store, and the first save after
// that replaced the damaged file with an empty one. The keys in it are what let
// us decrypt anything the mesh sends us, so it has to be kept.
static void test_corrupt_contacts_are_kept_not_overwritten() {
    const std::string dir = fresh_state_dir("corruptcontacts");
    Config cfg = harness_config(dir);
    CHECK(install_identity(cfg, pv::kPrivB));
    const std::string contacts_path = cfg.contacts_path();

    const std::string garbage = "# coreletd contacts v1\nnot a contact record at all\n";
    {
        std::ofstream out(contacts_path, std::ios::trunc);
        out << garbage;
    }

    ManualClock clock;
    auto radio = std::make_unique<GatedRadio>();
    GatedRadio* air = radio.get();
    App app(std::move(cfg), std::move(radio), clock);
    // The radio is the point of the daemon, so it still comes up.
    CHECK(app.start());
    air->set_ready(true);

    // Exactly one copy of the damaged file was set aside, and it still holds
    // what it held.
    CHECK_EQ(quarantined(dir, "contacts"), 1);
    for (const auto& e : std::filesystem::directory_iterator(dir)) {
        if (e.path().filename().string().rfind("contacts.corrupt-", 0) != 0) continue;
        std::ifstream in(e.path());
        std::string kept((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        CHECK(kept == garbage);
    }

    // And a save afterwards writes a fresh file rather than failing.
    air->inject(from_hex(pv::kAdvertPacket));
    app.request_stop();

    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivB));
    CHECK(self.has_value());
    if (!self) return;
    mesh::ContactStore reloaded(*self, contacts_path);
    CHECK(reloaded.load() == mesh::LoadResult::Loaded);
    CHECK(reloaded.find(from_hex(pv::kPubA)) != nullptr);
}

// When the save before the damaged one is still there, the contact and its
// shared secret come back — which the daemon demonstrates by decrypting a
// message from that contact and acking it.
static void test_corrupt_contacts_recover_from_the_backup() {
    const std::string dir = fresh_state_dir("contactsbackup");
    Config cfg = harness_config(dir);
    CHECK(install_identity(cfg, pv::kPrivB));
    const std::string contacts_path = cfg.contacts_path();
    Config second = harness_config(dir);

    // A first run learns A from its advert and writes it out on the way down.
    {
        ManualClock clock;
        auto radio = std::make_unique<GatedRadio>();
        GatedRadio* air = radio.get();
        App app(std::move(cfg), std::move(radio), clock);
        CHECK(app.start());
        air->set_ready(true);
        air->inject(from_hex(pv::kAdvertPacket));
        app.request_stop();
    }

    // That good file becomes the backup, and the live one is destroyed.
    std::error_code ec;
    std::filesystem::copy_file(contacts_path, contacts_path + ".bak",
                               std::filesystem::copy_options::overwrite_existing, ec);
    CHECK(!ec);
    {
        std::ofstream out(contacts_path, std::ios::trunc);
        out << "wreckage\n";
    }

    ManualClock clock;
    auto radio = std::make_unique<GatedRadio>();
    GatedRadio* air = radio.get();
    App app(std::move(second), std::move(radio), clock);
    CHECK(app.start());
    air->set_ready(true);
    CHECK_EQ(quarantined(dir, "contacts"), 1);

    // The proof that the contact really came back: a message from A decrypts,
    // which needs its public key, and is acked.
    air->inject(from_hex(pv::kTextPacket));
    CHECK_EQ(air->send_count(), size_t {1});
    auto sent = proto::Packet::decode(air->last_sent());
    CHECK(sent.has_value());
    // Six bytes of ack inside the path return: the hash, the extended attempt
    // byte, and a random one so two acks for the same message are not the same
    // packet.
    if (sent) check_bundled_ack(*sent, pv::kTextAckHash);
    app.request_stop();
}

static unsigned mode_of(const std::string& path) {
    struct stat st {};
    if (::stat(path.c_str(), &st) != 0) return 0;
    return st.st_mode & 07777;
}

// main() narrows the umask, but App is not main(), and a file's mode should not
// depend on how the process was started. Under a umask that leaves everything
// open, what the daemon writes still ends up its own: the key, the contacts it
// learns and the messages it holds.
static void test_state_is_private_whatever_the_umask() {
    const mode_t old_umask = ::umask(0);
    const std::string dir = fresh_state_dir("private");
    Config cfg = harness_config(dir);
    CHECK(install_identity(cfg, pv::kPrivB));
    const Config paths = cfg;

    {
        ManualClock clock;
        auto radio = std::make_unique<GatedRadio>();
        GatedRadio* air = radio.get();
        App app(std::move(cfg), std::move(radio), clock);
        CHECK(app.start());
        air->set_ready(true);
        air->inject(from_hex(pv::kAdvertPacket));
        air->inject(from_hex(pv::kTextPacket));
        app.request_stop();
    }
    ::umask(old_umask);

    CHECK_EQ(mode_of(paths.identity_path()), 0600u);
    CHECK_EQ(mode_of(paths.contacts_path()), 0600u);
    CHECK_EQ(mode_of(paths.messages_path()), 0600u);
}

// A state directory that is not there is a typo far more often than a first
// run, and creating it would be a new node with nobody told.
static void test_missing_state_dir_is_not_created() {
    const std::string dir = fresh_state_dir("missing") + "/not-yet";
    ManualClock clock;
    App app(harness_config(dir), std::make_unique<GatedRadio>(), clock);
    CHECK(!app.start());
    CHECK(!std::filesystem::exists(dir));
}

// Contacts without a key are a node whose key went missing, not a first run.
// Minting a new one would make this a stranger to everyone the contacts name,
// so startup stops and leaves the directory as it found it.
static void test_lost_identity_is_not_replaced() {
    const std::string dir = fresh_state_dir("lostkey");
    Config cfg = harness_config(dir);
    {
        mesh::ChannelStore channels(cfg.channels_path());
        channels.set(1, mesh::Channel::from_hashtag("#private"));
        CHECK(channels.save());
    }
    const std::string identity_path = cfg.identity_path();

    {
        ManualClock clock;
        App app(std::move(cfg), std::make_unique<GatedRadio>(), clock);
        CHECK(!app.start());
    }
    CHECK(!std::filesystem::exists(identity_path));

    // With nothing else there, the same directory is a first run. Settings
    // written by hand ahead of it are not a node that lived here.
    std::filesystem::remove(harness_config(dir).channels_path());
    std::ofstream(harness_config(dir).settings_path()) << "[node]\nadvert_name = First\n";
    ManualClock clock;
    App app(harness_config(dir), std::make_unique<GatedRadio>(), clock);
    CHECK(app.start());
    CHECK(std::filesystem::exists(identity_path));
    app.request_stop();
}

// Before every save was restricted, contacts and channels were written under
// the umask, and a restored backup is whatever the copy made it. Startup closes
// those rather than waiting for a save, which a channel list nobody edits may
// never get — and the backup beside it is the same secrets.
static void test_open_state_is_restricted_at_startup() {
    const std::string dir = fresh_state_dir("openstate");
    Config cfg = harness_config(dir);
    CHECK(install_identity(cfg, pv::kPrivB));
    {
        mesh::ChannelStore channels(cfg.channels_path());
        channels.set(1, mesh::Channel::from_hashtag("#private"));
        CHECK(channels.save());
        CHECK(channels.save());  // the second leaves the first as the backup
    }
    std::ofstream(cfg.contacts_path() + ".tmp") << "# coreletd contacts v1\n";
    for (const std::string& path :
         {cfg.identity_path(), cfg.channels_path(), cfg.channels_path() + ".bak",
          cfg.contacts_path() + ".tmp"}) {
        CHECK(::chmod(path.c_str(), 0644) == 0);
    }
    CHECK(::chmod(dir.c_str(), 0755) == 0);
    const Config paths = cfg;

    ManualClock clock;
    App app(std::move(cfg), std::make_unique<GatedRadio>(), clock);
    CHECK(app.start());

    CHECK_EQ(mode_of(paths.identity_path()), 0600u);
    CHECK_EQ(mode_of(paths.channels_path()), 0600u);
    CHECK_EQ(mode_of(paths.channels_path() + ".bak"), 0600u);
    CHECK_EQ(mode_of(paths.contacts_path() + ".tmp"), 0600u);
    // The directory is the operator's to name, and possibly shared, so it is
    // warned about rather than changed.
    CHECK_EQ(mode_of(dir), 0755u);
    app.request_stop();
}

// The external-client round trip, in-process: a client connects over the
// default Unix transport, starts a session, sends a message and sees it
// confirmed.
static void test_companion_app_round_trip() {
    const std::string dir = fresh_state_dir("companion");
    Config cfg = harness_config(dir);
    CHECK(install_identity(cfg, pv::kPrivB));
    const std::string socket_path = cfg.companion.socket_path;

    ManualClock clock;
    auto radio = std::make_unique<GatedRadio>();
    GatedRadio* air = radio.get();
    App app(std::move(cfg), std::move(radio), clock);
    CHECK(app.start());
    air->set_ready(true);

    Client client(app, socket_path);
    CHECK(client.connected());
    if (!client.connected()) return;

    Bytes start {kCmdAppStart, 0, 0, 0, 0, 0, 0, 0};
    put_str(start, "test");
    client.send(start);

    // SELF_INFO carries the key we installed, which is what says this reply came
    // from the daemon we built rather than something else on the port.
    Bytes info = client.await(kRespSelfInfo);
    CHECK(!info.empty());
    if (info.empty()) return;
    // Response code, then adv_type, tx power and max tx power, then the key.
    CHECK_BYTES(subview(info, 4, crypto::kPubKeySize), from_hex(pv::kPubB));

    // Give the daemon someone to talk to.
    air->inject(from_hex(pv::kAdvertPacket));

    const Bytes a_pub = from_hex(pv::kPubA);
    Bytes msg {kCmdSendTxtMsg, proto::kTxtPlain, 0};
    put_u32(msg, pv::kFixedTime);
    put_bytes(msg, subview(a_pub, 0, 6));  // the app addresses by key prefix
    put_str(msg, "hello back");
    client.send(msg);

    Bytes sent = client.await(kRespSent);
    CHECK(!sent.empty());
    if (sent.size() < 6) return;
    CHECK_EQ(air->send_count(), size_t {1});

    // The peer answers five seconds later, on the clock the test owns.
    const Bytes ack_hash(sent.begin() + 2, sent.begin() + 6);
    app.loop().advance(5000);
    proto::Packet ack;
    ack.type = proto::PayloadType::Ack;
    ack.route = proto::RouteType::Direct;
    ack.payload = ack_hash;
    air->inject(ack.encode());

    Bytes confirmed = client.await(kPushSendConfirmed);
    CHECK(!confirmed.empty());
    if (confirmed.size() < 9) return;
    CHECK_BYTES(subview(confirmed, 1, crypto::kAckHashSize), ack_hash);

    // The round trip is measured on the loop's clock, so it reports the five
    // seconds the test moved rather than the microseconds the test took. The
    // slack is the loop slices that carried the frames across the socket.
    Reader r(subview(confirmed, 5));
    const uint32_t elapsed = r.u32();
    CHECK(elapsed >= 5000);
    CHECK(elapsed < 5100);
}

// A client that connects and probes is answered, but is not sent the mesh
// traffic it never asked for. Pushes start at CMD_APP_START and not before.
static void test_pushes_wait_for_app_start() {
    const std::string dir = fresh_state_dir("pushgate");
    Config cfg = harness_config(dir);
    CHECK(install_identity(cfg, pv::kPrivB));
    const std::string socket_path = cfg.companion.socket_path;

    ManualClock clock;
    auto radio = std::make_unique<GatedRadio>();
    GatedRadio* air = radio.get();
    App app(std::move(cfg), std::move(radio), clock);
    CHECK(app.start());
    air->set_ready(true);

    Client client(app, socket_path);
    CHECK(client.connected());
    if (!client.connected()) return;

    // The probe a client makes before deciding to speak the protocol.
    client.send(Bytes {kCmdDeviceQuery});
    CHECK(!client.await(kRespDeviceInfo).empty());

    // Everything a busy mesh would produce: a new contact, a message stored for
    // collection, and two raw frames — the second a duplicate, which on_raw_rx
    // forwards as well.
    air->inject(from_hex(pv::kAdvertPacket));
    air->inject(from_hex(pv::kTextPacket));
    air->inject(from_hex(pv::kTextPacket));

    // Not "no LOG_RX_DATA" but nothing at all: no ADVERT, no NEW_ADVERT, no
    // MSG_WAITING. The client asked one question and got one answer.
    CHECK(client.drained().empty());

    Bytes start {kCmdAppStart, 0, 0, 0, 0, 0, 0, 0};
    put_str(start, "test");
    client.send(start);
    CHECK(!client.await(kRespSelfInfo).empty());

    // The message that arrived before the app identified itself is still in the
    // inbox, and starting the app is what tells it so — the push at the time was
    // dropped, and nothing else would have mentioned it.
    CHECK(!client.await(kPushMsgWaiting).empty());

    // From here the feed is live, duplicates included: this is the third copy of
    // a packet the dispatcher has already deduplicated twice.
    air->inject(from_hex(pv::kTextPacket));
    Bytes logged = client.await(kPushLogRxData);
    CHECK(!logged.empty());
    if (logged.size() < 3) return;
    // Code, then SNR in quarter-dB and RSSI, then the frame exactly as received.
    CHECK_BYTES(subview(logged, 3), from_hex(pv::kTextPacket));
}

// Each setter an app has, applied to the running node: the reply says OK, the
// handshake reports the new value, and the node acts on it.
static void test_app_changes_settings_live() {
    const std::string dir = fresh_state_dir("settings");
    Config cfg = harness_config(dir);
    CHECK(install_identity(cfg, pv::kPrivB));
    const std::string socket_path = cfg.companion.socket_path;

    ManualClock clock;
    auto radio = std::make_unique<GatedRadio>();
    GatedRadio* air = radio.get();
    App app(std::move(cfg), std::move(radio), clock);
    CHECK(app.start());
    air->set_ready(true);

    Client client(app, socket_path);
    CHECK(client.connected());
    if (!client.connected()) return;

    auto before = self_info(client);
    CHECK(before.has_value());
    if (!before) return;
    // The SX1262's PA stops at 22 dBm, and an app builds its slider from this.
    CHECK_EQ(before->max_tx_power, uint8_t {22});
    CHECK_EQ(before->freq_khz, uint32_t {869618});
    // Nobody has named the node, so it goes by its key, as a MeshCore one
    // does: the first four bytes of kPubB.
    CHECK(before->name == "4FD099CC");

    CHECK_BYTES(client.command(set_name("Field unit")), kOk);
    CHECK_BYTES(client.command(set_latlon(51507400, -127800)), kOk);
    CHECK_BYTES(client.command(set_tx_power(10)), kOk);
    CHECK_BYTES(client.command(set_radio(869525, 250000, 11, 5)), kOk);

    auto after = self_info(client);
    CHECK(after.has_value());
    if (!after) return;
    CHECK(after->name == "Field unit");
    CHECK_EQ(after->lat_e6, int32_t {51507400});
    CHECK_EQ(after->lon_e6, int32_t {-127800});
    CHECK_EQ(after->tx_power, uint8_t {10});
    CHECK_EQ(after->freq_khz, uint32_t {869525});
    CHECK_EQ(after->bw_hz, uint32_t {250000});
    CHECK_EQ(after->sf, uint8_t {11});
    CHECK_EQ(after->cr, uint8_t {5});
    // And the radio was handed them.
    CHECK_EQ(air->params().tx_power_dbm, 10);
    CHECK(air->params().freq_mhz == 869.525);
    CHECK_EQ(air->params().sf, uint8_t {11});

    // Nothing is advertised on a change, as MeshCore advertises nothing; the
    // next advert carries it.
    CHECK_EQ(air->send_count(), size_t {0});
    CHECK_BYTES(client.command(Bytes {kCmdSendSelfAdvert, 1}), kOk);
    CHECK_EQ(air->send_count(), size_t {1});
    auto adv = advertised(*air);
    CHECK(adv.has_value());
    if (adv) {
        CHECK(adv->name == "Field unit");
        CHECK(adv->has_location());
        CHECK_EQ(adv->lat_e6, int32_t {51507400});
    }
    air->complete_tx();

    // Apps send whole hertz, so 7800 is the datasheet's 7.81 kHz; a bandwidth
    // the chip does not have is refused rather than rounded to one it does.
    CHECK_BYTES(client.command(set_radio(869525, 7800, 11, 5)), kOk);
    CHECK(air->params().bw_khz == 7.81);
    CHECK_BYTES(client.command(set_radio(869525, 100000, 11, 5)), kIllegalArg);
    CHECK(air->params().bw_khz == 7.81);
    // Out of the settings file's ranges is out of the app's.
    CHECK_BYTES(client.command(set_radio(1200000, 250000, 11, 5)), kIllegalArg);
    CHECK_BYTES(client.command(set_radio(0, 250000, 11, 5)), kIllegalArg);
    CHECK_BYTES(client.command(set_radio(869525, 250000, 13, 5)), kIllegalArg);
    CHECK_BYTES(client.command(set_tx_power(23)), kIllegalArg);
    CHECK_BYTES(client.command(set_latlon(90000001, 0)), kIllegalArg);
    CHECK_EQ(air->params().sf, uint8_t {11});

    // The advert budget is enforced, never by cutting the name short: with a
    // position set, 23 bytes fit and 24 do not.
    CHECK_BYTES(client.command(set_name(std::string(24, 'x'))), kIllegalArg);
    CHECK_BYTES(client.command(set_name(std::string(23, 'x'))), kOk);
    // A position the shorter name fits beside, and not the longer one.
    CHECK_BYTES(client.command(set_name(std::string(31, 'x'))), kIllegalArg);
    CHECK_BYTES(client.command(set_latlon(0, 0)), kOk);
    CHECK_BYTES(client.command(set_name(std::string(31, 'x'))), kOk);
    CHECK_BYTES(client.command(set_latlon(51507400, -127800)), kIllegalArg);
    CHECK_BYTES(client.command(set_name("")), kIllegalArg);

    // The airtime factor is MeshCore's duty cycle: 100 / (1 + af).
    CHECK_BYTES(client.command(set_tuning(0, 1000)), kOk);
    CHECK(air->params().duty_cycle_pct == 50.0);
    Bytes tuning = client.command(Bytes {kCmdGetTuningParams});
    CHECK_EQ(tuning.size(), size_t {9});
    if (tuning.size() == 9) {
        Reader r(subview(tuning, 1));
        CHECK_EQ(r.u32(), uint32_t {0});
        CHECK_EQ(r.u32(), uint32_t {1000});
    }
    CHECK_BYTES(client.command(set_tuning(0, 0)), kOk);
    CHECK(air->params().duty_cycle_pct == 100.0);
    // 0-9, as MeshCore holds it; and no RX delay, which nothing here does.
    CHECK_BYTES(client.command(set_tuning(0, 9001)), kIllegalArg);
    CHECK_BYTES(client.command(set_tuning(500, 1000)), kIllegalArg);
    CHECK(air->params().duty_cycle_pct == 100.0);

    app.request_stop();
}

// What the app set is kept, and is what the next start runs on. An operator
// with no app may write the file by hand, and that counts the same; but one
// the daemon would not have written stops startup rather than be guessed
// around, since the frequency is in it.
static void test_settings_survive_a_restart() {
    const std::string dir = fresh_state_dir("settingsrestart");
    Config cfg = harness_config(dir);
    CHECK(install_identity(cfg, pv::kPrivB));
    const std::string socket_path = cfg.companion.socket_path;
    const std::string settings_path = cfg.settings_path();

    // False when the daemon would not start.
    auto run = [&](auto&& body) {
        ManualClock clock;
        auto radio = std::make_unique<GatedRadio>();
        GatedRadio* air = radio.get();
        App app(harness_config(dir), std::move(radio), clock);
        if (!app.start()) return false;
        Client client(app, socket_path);
        CHECK(client.connected());
        if (client.connected()) body(client, *air);
        app.request_stop();
        return true;
    };
    auto write_settings = [&](const std::string& body) {
        std::ofstream(settings_path, std::ios::trunc) << body;
    };

    CHECK(run([](Client& client, GatedRadio&) {
        CHECK_BYTES(client.command(set_name("Renamed")), kOk);
        CHECK_BYTES(client.command(set_tx_power(10)), kOk);
    }));
    // Written before the reply, and as private as the rest of the node.
    CHECK(std::filesystem::exists(settings_path));
    CHECK_EQ(mode_of(settings_path), 0600u);

    // Both still stand, and the radio is given the TX power before anything
    // is sent.
    CHECK(run([](Client& client, GatedRadio& air) {
        auto info = self_info(client);
        CHECK(info && info->name == "Renamed");
        CHECK(info && info->tx_power == 10);
        CHECK_EQ(air.params().tx_power_dbm, 10);
    }));

    // By hand, with the daemon stopped. What the file leaves out is the
    // default again.
    write_settings("[node]\nadvert_name = \"By hand #1\"\n[radio]\nlora_sf = 9\n");
    CHECK(run([](Client& client, GatedRadio& air) {
        auto info = self_info(client);
        CHECK(info && info->name == "By hand #1");
        CHECK(info && info->tx_power == 22);
        CHECK_EQ(air.params().sf, uint8_t {9});
        // And the app's next change keeps the hand-written ones beside it.
        CHECK_BYTES(client.command(set_tx_power(5)), kOk);
    }));
    CHECK(run([](Client& client, GatedRadio&) {
        auto info = self_info(client);
        CHECK(info && info->name == "By hand #1" && info->tx_power == 5 && info->sf == 9);
    }));

    // Out of range, a name the advert cannot carry beside the position, a
    // line that is not a setting: each is refused, and the file left for the
    // operator to put right.
    for (const char* bad : {"[radio]\nlora_sf = 13\n",
                            "[node]\nlat = 51.5\nlon = -0.1\nadvert_name = "
                            "xxxxxxxxxxxxxxxxxxxxxxxx\n",
                            "[radio]\nlora_sf\n"}) {
        write_settings(bad);
        CHECK(!run([](Client&, GatedRadio&) {}));
        CHECK(std::filesystem::exists(settings_path));
    }
}

// With the rail off, a radio setting is still a setting: kept, answered OK,
// and handed to the radio for when it returns.
static void test_settings_while_the_radio_is_absent() {
    const std::string dir = fresh_state_dir("settingsabsent");
    Config cfg = harness_config(dir);
    CHECK(install_identity(cfg, pv::kPrivB));
    const std::string socket_path = cfg.companion.socket_path;
    const std::string settings_path = cfg.settings_path();

    ManualClock clock;
    auto radio = std::make_unique<GatedRadio>();
    GatedRadio* air = radio.get();
    App app(std::move(cfg), std::move(radio), clock);
    CHECK(app.start());
    // Never made ready: the rail is off.

    Client client(app, socket_path);
    CHECK(client.connected());
    if (!client.connected()) return;

    CHECK_BYTES(client.command(set_radio(869525, 62500, 9, 5)), kOk);
    CHECK_EQ(air->params().sf, uint8_t {9});
    CHECK(std::filesystem::exists(settings_path));

    // It comes back, and the queue it held goes out on what it was given.
    CHECK_BYTES(client.command(Bytes {kCmdSendSelfAdvert, 1}), kOk);
    CHECK_EQ(air->send_count(), size_t {0});
    air->set_ready(true);
    app.loop().advance(1500);
    CHECK_EQ(air->send_count(), size_t {1});
    app.request_stop();
}

// No frequency is a first start, not a fault: the daemon comes up and
// transmits nothing until an app names one.
static void test_first_start_is_radio_silent() {
    const std::string dir = fresh_state_dir("silent");
    Config cfg = harness_config(dir);
    cfg.radio.freq_mhz = 0;
    CHECK(install_identity(cfg, pv::kPrivB));
    const std::string socket_path = cfg.companion.socket_path;

    ManualClock clock;
    auto radio = std::make_unique<GatedRadio>();
    GatedRadio* air = radio.get();
    App app(std::move(cfg), std::move(radio), clock);
    CHECK(app.start());
    air->set_ready(true);
    // The radio was handed the want of a frequency.
    CHECK(!air->params().has_frequency());

    Client client(app, socket_path);
    CHECK(client.connected());
    if (!client.connected()) return;

    auto info = self_info(client);
    CHECK(info && info->freq_khz == 0);

    // Asked for, queued, and held: a ready radio is not a tuned one.
    CHECK_BYTES(client.command(Bytes {kCmdSendSelfAdvert, 1}), kOk);
    app.loop().advance(3000);
    CHECK_EQ(air->send_count(), size_t {0});

    // The app picks the preset, and what was waiting goes out on it.
    CHECK_BYTES(client.command(set_radio(869618, 62500, 8, 5)), kOk);
    CHECK_EQ(air->send_count(), size_t {1});
    CHECK(air->params().freq_mhz == 869.618);
    app.request_stop();
}

// The repeat byte is MeshCore's to the letter: absent means off, and an app
// may turn it on only at the three frequencies MeshCore allows. DEVICE_INFO
// reports it, since a client that means to keep it has to send it back.
static void test_repeat_byte_and_frequency_list() {
    const std::string dir = fresh_state_dir("repeat");
    Config cfg = harness_config(dir);
    CHECK(install_identity(cfg, pv::kPrivB));
    const std::string socket_path = cfg.companion.socket_path;

    {
        ManualClock clock;
        auto radio = std::make_unique<GatedRadio>();
        GatedRadio* air = radio.get();
        App app(std::move(cfg), std::move(radio), clock);
        CHECK(app.start());
        Client client(app, socket_path);
        CHECK(client.connected());
        if (!client.connected()) return;

        CHECK_EQ(repeat_reported(client), 0);
        CHECK_BYTES(client.command(set_radio(869618, 62500, 8, 5, 1)), kIllegalArg);
        CHECK_EQ(repeat_reported(client), 0);
        CHECK(air->params().freq_mhz == 869.618);

        CHECK_BYTES(client.command(set_radio(869495, 250000, 11, 5, 1)), kOk);
        CHECK_EQ(repeat_reported(client), 1);
        // Repeat off is allowed anywhere, and is what a v3 client gets.
        CHECK_BYTES(client.command(set_radio(869495, 250000, 11, 5)), kOk);
        CHECK_EQ(repeat_reported(client), 0);
        CHECK_BYTES(client.command(set_radio(918000, 250000, 11, 5, 1)), kOk);
        CHECK_EQ(repeat_reported(client), 1);
        app.request_stop();
    }

    // The list is a check on the app: repeat written into the settings file
    // by hand is not held to it.
    const std::string other = fresh_state_dir("repeathand");
    Config operator_cfg = harness_config(other);
    CHECK(install_identity(operator_cfg, pv::kPrivB));
    std::ofstream(operator_cfg.settings_path()) << "[node]\nrepeat = 1\n";
    ManualClock clock;
    App app(std::move(operator_cfg), std::make_unique<GatedRadio>(), clock);
    CHECK(app.start());
    Client client(app, other + "/companion.sock");
    CHECK(client.connected());
    if (client.connected()) CHECK_EQ(repeat_reported(client), 1);
    app.request_stop();
}

// The reply has to be true: a change that could not be written is refused,
// and the node is left as it was rather than running on something a restart
// would undo.
static void test_unwritable_settings_are_refused() {
    const std::string dir = fresh_state_dir("settingsio");
    Config cfg = harness_config(dir);
    CHECK(install_identity(cfg, pv::kPrivB));
    const std::string socket_path = cfg.companion.socket_path;
    // Nothing can be written over a directory, whoever the test runs as.
    std::filesystem::create_directory(cfg.settings_path() + ".tmp");

    ManualClock clock;
    auto radio = std::make_unique<GatedRadio>();
    GatedRadio* air = radio.get();
    App app(std::move(cfg), std::move(radio), clock);
    CHECK(app.start());
    Client client(app, socket_path);
    CHECK(client.connected());
    if (!client.connected()) return;

    CHECK_BYTES(client.command(set_name("Unsaved")), (Bytes {kRespErr, kErrFileIoError}));
    CHECK_BYTES(client.command(set_tx_power(5)), (Bytes {kRespErr, kErrFileIoError}));
    auto info = self_info(client);
    CHECK(info && info->name == "4FD099CC");
    CHECK_EQ(air->params().tx_power_dbm, 22);
    app.request_stop();
}

int main() {
    if (!crypto::init()) return 2;

    test_received_text_is_acked_on_air();
    test_message_received_offline_survives_a_restart();
    test_message_path_len_is_meshcores_way_round();
    test_corrupt_contacts_are_kept_not_overwritten();
    test_corrupt_contacts_recover_from_the_backup();
    test_state_is_private_whatever_the_umask();
    test_open_state_is_restricted_at_startup();
    test_missing_state_dir_is_not_created();
    test_lost_identity_is_not_replaced();
    test_companion_app_round_trip();
    test_pushes_wait_for_app_start();
    test_app_changes_settings_live();
    test_settings_survive_a_restart();
    test_settings_while_the_radio_is_absent();
    test_first_start_is_radio_silent();
    test_repeat_byte_and_frequency_list();
    test_unwritable_settings_are_refused();

    return finish("app");
}
