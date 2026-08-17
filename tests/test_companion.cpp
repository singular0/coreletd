#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <fstream>

#include "companion/frames.h"
#include "companion/server.h"
#include "daemon/host_metrics.h"
#include "tests/test_util.h"

using namespace clt;
using namespace clt::test;
using namespace clt::companion;

static Bytes make_frame(uint8_t marker, const Bytes& payload) {
    Bytes out {marker};
    put_u16(out, static_cast<uint16_t>(payload.size()));
    put_bytes(out, payload);
    return out;
}

static void test_single_frame() {
    FrameReader r;
    Bytes payload = {kCmdAppStart, 0, 0, 0, 0, 0, 0, 0, 'm', 'c'};
    r.feed(make_frame(kFrameToDevice, payload));

    auto f = r.next();
    CHECK(f.has_value());
    if (f) CHECK_BYTES(*f, payload);
    CHECK(!r.next().has_value());
}

static void test_split_across_reads() {
    FrameReader r;
    Bytes payload = {kCmdDeviceQuery, 3};
    Bytes framed = make_frame(kFrameToDevice, payload);

    // Deliver one byte at a time: a TCP stream gives no framing guarantees.
    for (size_t i = 0; i + 1 < framed.size(); i++) {
        r.feed(ByteView(framed).subspan(i, 1));
        CHECK(!r.next().has_value());
    }
    r.feed(ByteView(framed).subspan(framed.size() - 1, 1));

    auto f = r.next();
    CHECK(f.has_value());
    if (f) CHECK_BYTES(*f, payload);
}

static void test_multiple_frames_in_one_read() {
    FrameReader r;
    Bytes a = {kCmdGetDeviceTime};
    Bytes b = {kCmdSyncNextMessage};

    Bytes stream = make_frame(kFrameToDevice, a);
    Bytes second = make_frame(kFrameToDevice, b);
    stream.insert(stream.end(), second.begin(), second.end());
    r.feed(stream);

    auto f1 = r.next();
    auto f2 = r.next();
    CHECK(f1.has_value());
    CHECK(f2.has_value());
    if (f1) CHECK_BYTES(*f1, a);
    if (f2) CHECK_BYTES(*f2, b);
    CHECK(!r.next().has_value());
}

static void test_resync_after_junk() {
    FrameReader r;
    Bytes payload = {kCmdAppStart};

    // Junk before a valid frame must be discarded, not stall the reader.
    Bytes stream = {0xAA, 0xBB, 0xCC};
    Bytes good = make_frame(kFrameToDevice, payload);
    stream.insert(stream.end(), good.begin(), good.end());
    r.feed(stream);

    auto f = r.next();
    CHECK(f.has_value());
    if (f) CHECK_BYTES(*f, payload);
}

static void test_empty_frame_is_returned_not_hung() {
    FrameReader r;
    r.feed(make_frame(kFrameToDevice, {}));
    auto f = r.next();
    CHECK(f.has_value());
    if (f) CHECK_EQ(f->size(), size_t {0});
}

static void test_oversized_length_resyncs() {
    FrameReader r;
    // A bogus length must not wedge the reader waiting for bytes forever.
    Bytes bad {kFrameToDevice, 0xFF, 0xFF};
    Bytes payload = {kCmdAppStart};
    Bytes good = make_frame(kFrameToDevice, payload);
    bad.insert(bad.end(), good.begin(), good.end());
    r.feed(bad);

    auto f = r.next();
    CHECK(f.has_value());
    if (f) CHECK_BYTES(*f, payload);
}

static void test_response_framing() {
    Bytes payload = {kRespOk, 1, 2, 3};
    Bytes framed = frame_response(payload);

    Reader hdr(framed);
    CHECK_EQ(hdr.u8(), uint8_t {kFrameToApp});
    CHECK_EQ(hdr.u16(), uint16_t {4});
    CHECK_BYTES(hdr.rest(), payload);

    // A framed response must be readable by the same de-framer.
    FrameReader r;
    r.feed(framed);
    auto f = r.next();
    CHECK(f.has_value());
    if (f) CHECK_BYTES(*f, payload);
}

static void test_response_helpers() {
    CHECK_BYTES(resp_ok(), (Bytes {0}));
    CHECK_BYTES(resp_err(kErrNotFound), (Bytes {1, 2}));

    Bytes ok_val = resp_ok(0x12345678);
    CHECK_EQ(ok_val.size(), size_t {5});
    Reader r(ok_val);
    CHECK_EQ(r.u8(), uint8_t {kRespOk});
    CHECK_EQ(r.u32(), uint32_t {0x12345678});
}

static void test_outbound_buffer_limit_is_overflow_safe() {
    CHECK(outbound_buffer_has_capacity(0, 8, 8));
    CHECK(outbound_buffer_has_capacity(3, 5, 8));
    CHECK(!outbound_buffer_has_capacity(3, 6, 8));
    CHECK(!outbound_buffer_has_capacity(9, 0, 8));
    CHECK(!outbound_buffer_has_capacity(size_t(-2), 4, size_t(-1)));
}

static std::string fresh_socket_path(const char* name) {
    std::string dir = std::string("/tmp/coreletd_test_companion_") +
                      std::to_string(static_cast<unsigned long>(::getpid())) + "_" + name;
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    std::filesystem::create_directories(dir, ec);
    CHECK(!ec);
    return dir + "/companion.sock";
}

static int connect_unix(const std::string& path) {
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof(addr.sun_path)) {
        ::close(fd);
        return -1;
    }
    memcpy(addr.sun_path, path.c_str(), path.size() + 1);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

static int connect_tcp(uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

static void run_for(EventLoop& loop, uint32_t ms = 10) {
    auto deadline = loop.add_timer(ms, [&loop] { loop.stop(); });
    loop.run();
}

static void remove_socket_test_dir(const std::string& path) {
    std::error_code ec;
    std::filesystem::remove_all(std::filesystem::path(path).parent_path(), ec);
}

static void test_unix_socket_stale_cleanup_permissions_and_shutdown() {
    const std::string path = fresh_socket_path("lifecycle");

    // Simulate the filesystem entry left by a process that died without
    // running Server::shutdown().
    int stale = ::socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(stale >= 0);
    if (stale < 0) return;
    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, path.c_str(), path.size() + 1);
    CHECK(::bind(stale, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    ::close(stale);

    EventLoop loop;
    Server::Options opts;
    opts.socket_path = path;
    Server server(loop, opts);
    std::string error;
    CHECK(server.start(error));

    struct stat st {};
    CHECK(::lstat(path.c_str(), &st) == 0);
    CHECK(S_ISSOCK(st.st_mode));
    CHECK_EQ(st.st_mode & 0777, mode_t {0660});
    CHECK_EQ(st.st_gid, ::getegid());

    server.shutdown();
    CHECK(::lstat(path.c_str(), &st) != 0 && errno == ENOENT);
    remove_socket_test_dir(path);
}

static void test_unix_socket_refuses_non_socket_path() {
    const std::string path = fresh_socket_path("nonsocket");
    {
        std::ofstream out(path);
        out << "do not replace me";
    }

    EventLoop loop;
    Server::Options opts;
    opts.socket_path = path;
    Server server(loop, opts);
    std::string error;
    CHECK(!server.start(error));
    CHECK(error.find("non-socket") != std::string::npos);
    CHECK(std::filesystem::is_regular_file(path));

    remove_socket_test_dir(path);
}

static void test_unix_socket_takeover_frames_and_reconnect() {
    const std::string path = fresh_socket_path("sessions");
    EventLoop loop;
    Server::Options opts;
    opts.socket_path = path;
    Server server(loop, opts);

    int connects = 0;
    int disconnects = 0;
    Bytes received;
    server.set_connect_handler([&] { connects++; });
    server.set_disconnect_handler([&] { disconnects++; });
    server.set_frame_handler([&](ByteView frame) { received.assign(frame.begin(), frame.end()); });

    std::string error;
    CHECK(server.start(error));
    int first = connect_unix(path);
    CHECK(first >= 0);
    if (first < 0) return;
    run_for(loop);
    CHECK_EQ(connects, 1);

    // A second daemon cannot unlink a live endpoint, while a second client is
    // deliberately allowed to take the one protocol session over.
    EventLoop contender_loop;
    Server contender(contender_loop, opts);
    std::string contender_error;
    CHECK(!contender.start(contender_error));
    CHECK(contender_error.find("already in use") != std::string::npos);

    int second = connect_unix(path);
    CHECK(second >= 0);
    if (second < 0) {
        ::close(first);
        return;
    }
    run_for(loop);
    CHECK_EQ(connects, 2);
    CHECK_EQ(disconnects, 1);

    pollfd old_peer {first, POLLIN | POLLHUP, 0};
    CHECK(::poll(&old_peer, 1, 50) > 0);
    char byte = 0;
    CHECK_EQ(::read(first, &byte, 1), ssize_t {0});
    ::close(first);

    // Framing is transport-independent in both directions.
    const Bytes command {kCmdDeviceQuery, 7};
    Bytes framed = make_frame(kFrameToDevice, command);
    CHECK_EQ(::write(second, framed.data(), framed.size()),
             static_cast<ssize_t>(framed.size()));
    run_for(loop);
    CHECK_BYTES(received, command);

    const Bytes response {kRespOk, 9};
    server.send(response);
    pollfd response_ready {second, POLLIN, 0};
    CHECK(::poll(&response_ready, 1, 50) > 0);
    uint8_t buf[32];
    ssize_t n = ::read(second, buf, sizeof(buf));
    CHECK(n > 0);
    FrameReader response_reader;
    if (n > 0) response_reader.feed(ByteView(buf, static_cast<size_t>(n)));
    auto response_frame = response_reader.next();
    CHECK(response_frame.has_value());
    if (response_frame) CHECK_BYTES(*response_frame, response);

    ::close(second);
    run_for(loop);
    CHECK_EQ(disconnects, 2);

    int third = connect_unix(path);
    CHECK(third >= 0);
    if (third >= 0) {
        run_for(loop);
        CHECK_EQ(connects, 3);
        ::close(third);
        run_for(loop);
    }

    server.shutdown();
    remove_socket_test_dir(path);
}

static void test_tcp_allows_configured_bind_address() {
    EventLoop loop;
    Server::Options opts;
    opts.transport = Server::Transport::Tcp;
    opts.bind_addr = "0.0.0.0";
    opts.port = 0;

    Server remote(loop, opts);
    std::string error;
    CHECK(remote.start(error));
    remote.shutdown();

    opts.bind_addr = "127.0.0.1";
    Server local(loop, opts);
    error.clear();
    CHECK(local.start(error));
    local.shutdown();
}

static void test_tcp_uses_the_same_frame_layer() {
    EventLoop loop;
    Server::Options opts;
    opts.transport = Server::Transport::Tcp;
    opts.port = 0;  // let the kernel choose a collision-free test port
    Server server(loop, opts);

    Bytes received;
    server.set_frame_handler([&](ByteView frame) { received.assign(frame.begin(), frame.end()); });
    std::string error;
    CHECK(server.start(error));

    int client = connect_tcp(server.options().port);
    CHECK(client >= 0);
    if (client < 0) return;
    run_for(loop);

    const Bytes command {kCmdGetDeviceTime, 4};
    Bytes framed = make_frame(kFrameToDevice, command);
    CHECK_EQ(::write(client, framed.data(), framed.size()),
             static_cast<ssize_t>(framed.size()));
    run_for(loop);
    CHECK_BYTES(received, command);

    const Bytes response {kRespOk, 5};
    server.send(response);
    pollfd ready {client, POLLIN, 0};
    CHECK(::poll(&ready, 1, 50) > 0);
    uint8_t buf[32];
    ssize_t n = ::read(client, buf, sizeof(buf));
    CHECK(n > 0);
    FrameReader reader;
    if (n > 0) reader.feed(ByteView(buf, static_cast<size_t>(n)));
    auto response_frame = reader.next();
    CHECK(response_frame.has_value());
    if (response_frame) CHECK_BYTES(*response_frame, response);

    ::close(client);
    run_for(loop);
    server.shutdown();
}

// Both figures the app shows come from one statvfs, and the reply carries them
// as a pair: a total smaller than the used part, or a used part that swallowed
// the reserved blocks into a negative, would render as nonsense.
static void test_host_metrics_storage_is_coherent() {
    clt::HostMetrics::Info info;
    info.model = "test";
    clt::HostMetrics metrics(info, "/tmp");

    auto s = metrics.storage();
    CHECK(s.total_bytes > 0);
    CHECK(s.used_bytes <= s.total_bytes);

    // No battery on a dev machine, and none on any host where the sysfs walk
    // found nothing: 0 is the protocol's "unknown", not a flat pack.
    CHECK(metrics.battery_mv() == 0 || metrics.battery_mv() > 1000);

    // The identity half is passed through untouched.
    CHECK(metrics.info().model == "test");
}

// An unreadable state directory must report zeros rather than whatever an
// uninitialised statvfs left on the stack.
static void test_host_metrics_storage_survives_a_bad_path() {
    clt::HostMetrics metrics(clt::HostMetrics::Info {}, "/nonexistent/coreletd/state");
    auto s = metrics.storage();
    CHECK_EQ(s.used_bytes, uint64_t {0});
    CHECK_EQ(s.total_bytes, uint64_t {0});
}

int main() {
    test_single_frame();
    test_split_across_reads();
    test_multiple_frames_in_one_read();
    test_resync_after_junk();
    test_empty_frame_is_returned_not_hung();
    test_oversized_length_resyncs();
    test_response_framing();
    test_response_helpers();
    test_outbound_buffer_limit_is_overflow_safe();
    test_unix_socket_stale_cleanup_permissions_and_shutdown();
    test_unix_socket_refuses_non_socket_path();
    test_unix_socket_takeover_frames_and_reconnect();
    test_tcp_allows_configured_bind_address();
    test_tcp_uses_the_same_frame_layer();
    test_host_metrics_storage_is_coherent();
    test_host_metrics_storage_survives_a_bad_path();
    return finish("companion");
}
