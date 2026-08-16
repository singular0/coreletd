// The daemon as a whole, stood up in-process. App takes the radio and the clock
// from the caller, so these tests own both ends of it: packets arrive when the
// test injects them, replies are the bytes the radio was handed, and time only
// moves when the test moves it. Everything in between — dispatcher, node,
// sender, stores, companion session — is wired by App exactly as `main()` gets
// it, which is the point: nothing here constructs a subsystem.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <filesystem>
#include <memory>
#include <string>

#include "companion/frames.h"
#include "crypto/crypto.h"
#include "crypto/identity.h"
#include "daemon/app.h"
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

// The companion port the harness binds. Fixed rather than ephemeral because the
// client has to connect to it, and App deliberately does not hand out its
// Server.
constexpr uint16_t kPort = 45879;

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
    cfg.companion.port = kPort;
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

// A companion app on the other end of the TCP socket: sends command frames and
// picks replies out of the stream by response code, which is what a real client
// does too — advisory pushes for the traffic under test share that stream.
class Client {
public:
    explicit Client(App& app) : app_(app) {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) return;
        sockaddr_in addr {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(kPort);
        ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
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
    CHECK_BYTES(sent->payload, from_hex(pv::kTextAckHash));

    // Shutting down flushes what the exchange changed, so the contact A
    // advertised is on disk under the name it advertised.
    app.request_stop();

    auto self = crypto::LocalIdentity::from_bytes(from_hex(pv::kPrivB));
    CHECK(self.has_value());
    if (!self) return;
    mesh::ContactStore reloaded(*self, contacts_path);
    CHECK(reloaded.load());
    const Bytes a_pub = from_hex(pv::kPubA);
    mesh::Contact* a = reloaded.find(a_pub);
    CHECK(a != nullptr);
    if (a) CHECK(a->name == pv::kNameA);
}

// What the external e2e script does, in-process: a client connects over TCP,
// starts a session, sends a message and sees it confirmed.
static void test_companion_app_round_trip() {
    const std::string dir = fresh_state_dir("companion");
    Config cfg = harness_config(dir);
    CHECK(install_identity(cfg, pv::kPrivB));

    ManualClock clock;
    auto radio = std::make_unique<GatedRadio>();
    GatedRadio* air = radio.get();
    App app(std::move(cfg), std::move(radio), clock);
    CHECK(app.start());
    air->set_ready(true);

    Client client(app);
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

// The seam must not change what the daemon does on its own: handed no radio, it
// still builds the one the config asks for, and still generates an identity on
// a first run.
static void test_app_builds_its_own_radio() {
    const std::string dir = fresh_state_dir("mock");
    Config cfg = harness_config(dir);
    cfg.use_mock_radio = true;

    ManualClock clock;
    App app(std::move(cfg), nullptr, clock);
    CHECK(app.start());
    CHECK(std::filesystem::exists(dir + "/identity"));
    app.request_stop();
}

int main() {
    if (!crypto::init()) return 2;

    test_received_text_is_acked_on_air();
    test_companion_app_round_trip();
    test_app_builds_its_own_radio();

    return finish("app");
}
