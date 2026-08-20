// The daemon as a whole, stood up in-process. App takes the radio and the clock
// from the caller, so these tests own both ends of it: packets arrive when the
// test injects them, replies are the bytes the radio was handed, and time only
// moves when the test moves it. Everything in between — dispatcher, node,
// sender, stores, companion session — is wired by App exactly as `main()` gets
// it, which is the point: nothing here constructs a subsystem.

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
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

Config harness_config(const std::string& state_dir) {
    Config cfg;
    cfg.state_dir = state_dir;
    cfg.companion.socket_path = state_dir + "/companion.sock";
    cfg.finalise();
    return cfg;
}

// The frozen vectors are a conversation between identities A and B, so the
// daemon has to be B for the reference packets to be addressed to it. Writing
// the key beforehand also puts startup on the load-an-existing-key path.
bool install_identity(const Config& cfg, std::string_view priv) {
    auto id = crypto::LocalIdentity::from_bytes(from_hex(priv));
    return id && id->save(cfg.identity_path);
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

}  // namespace

// A packet goes in at the antenna and the reply comes back out of it. The only
// things the test touches are the radio and the state directory.
static void test_received_text_is_acked_on_air() {
    const std::string dir = fresh_state_dir("ack");
    Config cfg = harness_config(dir);
    CHECK(install_identity(cfg, pv::kPrivB));
    const std::string contacts_path = cfg.contacts_path;

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

    // The ack needs no timer to get out: the radio is ready and nothing is
    // queued ahead of it.
    CHECK_EQ(air->send_count(), size_t {1});
    auto sent = proto::Packet::decode(air->last_sent());
    CHECK(sent.has_value());
    if (!sent) return;
    CHECK(sent->type == proto::PayloadType::Ack);
    CHECK_EQ(sent->payload.size(), size_t {6});
    CHECK_BYTES(subview(sent->payload, 0, 4), from_hex(pv::kTextAckHash));

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
        if (sent) CHECK(sent->type == proto::PayloadType::Ack);

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
    const std::string contacts_path = cfg.contacts_path;

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
    const std::string contacts_path = cfg.contacts_path;
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
    if (sent) {
        CHECK(sent->type == proto::PayloadType::Ack);
        // Six bytes now: the hash, the extended attempt byte, and a random one
        // so two acks for the same message are not the same packet.
        CHECK_EQ(sent->payload.size(), size_t {6});
        CHECK_BYTES(subview(sent->payload, 0, 4), from_hex(pv::kTextAckHash));
    }
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

int main() {
    if (!crypto::init()) return 2;

    test_received_text_is_acked_on_air();
    test_message_received_offline_survives_a_restart();
    test_message_path_len_is_meshcores_way_round();
    test_corrupt_contacts_are_kept_not_overwritten();
    test_corrupt_contacts_recover_from_the_backup();
    test_companion_app_round_trip();
    test_pushes_wait_for_app_start();

    return finish("app");
}
