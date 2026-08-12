#pragma once

#include <functional>
#include <string>

#include "companion/frames.h"
#include "daemon/eventloop.h"
#include "util/bytes.h"

namespace umc::companion {

// Overflow-safe capacity check shared with the transport regression tests.
bool outbound_buffer_has_capacity(size_t buffered, size_t next, size_t limit);

// TCP transport for the companion protocol. The firmware model is a single
// connected app, so a new connection replaces the old one rather than being
// refused — otherwise a crashed client would lock everyone out until the TCP
// timeout expired.
class Server {
public:
    struct Options {
        std::string bind_addr = "127.0.0.1";
        uint16_t port = 5000;
        // A client that cannot drain this much queued output is disconnected.
        size_t max_outbound_bytes = 256 * 1024;
    };

    using FrameHandler = std::function<void(ByteView frame)>;
    using ConnectHandler = std::function<void()>;
    using DisconnectHandler = std::function<void()>;

    Server(EventLoop& loop, Options opts);
    ~Server();

    bool start(std::string& error);
    void shutdown();

    void set_frame_handler(FrameHandler h) { on_frame_ = std::move(h); }
    void set_connect_handler(ConnectHandler h) { on_connect_ = std::move(h); }
    void set_disconnect_handler(DisconnectHandler h) { on_disconnect_ = std::move(h); }

    bool connected() const { return client_fd_ >= 0; }
    // Wraps `payload` in a frame and queues it. Silently dropped when no app is
    // connected, which is correct: pushes are advisory.
    void send(ByteView payload);

    const Options& options() const { return opts_; }

private:
    void on_listen_ready(short revents);
    void on_client_ready(short revents);
    void accept_client();
    void drop_client(const char* why);
    void flush();

    EventLoop& loop_;
    Options opts_;

    int listen_fd_ = -1;
    int client_fd_ = -1;
    EventLoop::WatchId listen_watch_ = 0;
    EventLoop::WatchId client_watch_ = 0;

    FrameReader reader_;
    Bytes out_buf_;

    FrameHandler on_frame_;
    ConnectHandler on_connect_;
    DisconnectHandler on_disconnect_;
};

}  // namespace umc::companion
