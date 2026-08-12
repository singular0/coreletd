#include "companion/server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "util/hex.h"
#include "util/log.h"

namespace umc::companion {

bool outbound_buffer_has_capacity(size_t buffered, size_t next, size_t limit) {
    return buffered <= limit && next <= limit - buffered;
}

namespace {
bool set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}
}  // namespace

Server::Server(EventLoop& loop, Options opts) : loop_(loop), opts_(std::move(opts)) {}

Server::~Server() { shutdown(); }

bool Server::start(std::string& error) {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        error = std::string("socket: ") + strerror(errno);
        return false;
    }

    int one = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(opts_.port);
    if (opts_.bind_addr.empty() || opts_.bind_addr == "0.0.0.0") {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else if (::inet_pton(AF_INET, opts_.bind_addr.c_str(), &addr.sin_addr) != 1) {
        error = "invalid bind address " + opts_.bind_addr;
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }

    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        error = "bind " + opts_.bind_addr + ":" + std::to_string(opts_.port) + ": " +
                strerror(errno);
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    if (::listen(listen_fd_, 1) != 0) {
        error = std::string("listen: ") + strerror(errno);
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }
    if (!set_nonblocking(listen_fd_)) {
        error = std::string("fcntl: ") + strerror(errno);
        ::close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }

    listen_watch_ = loop_.add_fd(listen_fd_, POLLIN, [this](short r) { on_listen_ready(r); });
    LOG_INFO("companion: listening on %s:%u", opts_.bind_addr.c_str(), opts_.port);
    return true;
}

void Server::shutdown() {
    if (client_fd_ >= 0) drop_client("shutting down");
    if (listen_fd_ >= 0) {
        listen_watch_.reset();
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
}

void Server::on_listen_ready(short revents) {
    if (revents & POLLIN) accept_client();
}

void Server::accept_client() {
    sockaddr_in peer {};
    socklen_t len = sizeof(peer);
    int fd = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&peer), &len);
    if (fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) LOG_WARN("companion: accept: %s", strerror(errno));
        return;
    }

    char ip[INET_ADDRSTRLEN] = "?";
    ::inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));

    if (client_fd_ >= 0) {
        // Replace the existing session: a dead client must not lock out a live one.
        LOG_INFO("companion: new connection from %s replacing existing client", ip);
        drop_client("replaced by a new connection");
    }

    if (!set_nonblocking(fd)) {
        LOG_WARN("companion: cannot set client non-blocking: %s", strerror(errno));
        ::close(fd);
        return;
    }
    // Responses are small and latency matters more than packing.
    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    client_fd_ = fd;
    reader_.reset();
    out_buf_.clear();
    client_watch_ = loop_.add_fd(client_fd_, POLLIN, [this](short r) { on_client_ready(r); });

    LOG_INFO("companion: app connected from %s:%u", ip, ntohs(peer.sin_port));
    if (on_connect_) on_connect_();
}

void Server::drop_client(const char* why) {
    if (client_fd_ < 0) return;
    LOG_INFO("companion: app disconnected (%s)", why);

    client_watch_.reset();
    ::close(client_fd_);
    client_fd_ = -1;
    reader_.reset();
    out_buf_.clear();

    if (on_disconnect_) on_disconnect_();
}

void Server::on_client_ready(short revents) {
    if (revents & (POLLERR | POLLNVAL)) {
        drop_client("socket error");
        return;
    }

    if (revents & POLLOUT) flush();
    if (client_fd_ < 0) return;

    if (revents & POLLIN) {
        uint8_t buf[4096];
        for (;;) {
            ssize_t n = ::read(client_fd_, buf, sizeof(buf));
            if (n > 0) {
                reader_.feed(ByteView(buf, static_cast<size_t>(n)));
                // Dispatch every complete frame; a handler may drop the client,
                // so re-check the fd each time round.
                while (client_fd_ >= 0) {
                    auto frame = reader_.next();
                    if (!frame) break;
                    if (frame->empty()) continue;
                    if (on_frame_) on_frame_(*frame);
                }
                if (client_fd_ < 0) return;
                if (static_cast<size_t>(n) < sizeof(buf)) break;  // drained
                continue;
            }
            if (n == 0) {
                drop_client("peer closed");
                return;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            drop_client(strerror(errno));
            return;
        }
    }

    // POLLHUP can arrive alongside readable data, so only act on it once the
    // read side is drained.
    if ((revents & POLLHUP) && client_fd_ >= 0) drop_client("peer hung up");
}

void Server::send(ByteView payload) {
    if (client_fd_ < 0) {
        LOG_TRACE("companion: no client, dropping %zu byte response", payload.size());
        return;
    }

    Bytes framed = frame_response(payload);
    LOG_TRACE("companion: tx %zu bytes: %s", framed.size(), hex_prefix(framed, 16).c_str());
    if (!outbound_buffer_has_capacity(out_buf_.size(), framed.size(),
                                      opts_.max_outbound_bytes)) {
        drop_client("outbound buffer limit exceeded");
        return;
    }
    out_buf_.insert(out_buf_.end(), framed.begin(), framed.end());
    flush();
}

void Server::flush() {
    while (client_fd_ >= 0 && !out_buf_.empty()) {
        ssize_t n = ::write(client_fd_, out_buf_.data(), out_buf_.size());
        if (n > 0) {
            out_buf_.erase(out_buf_.begin(), out_buf_.begin() + n);
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            // Kernel buffer full: wait for writability and finish then.
            loop_.update_fd(client_watch_, POLLIN | POLLOUT);
            return;
        }
        if (n < 0 && errno == EINTR) continue;
        drop_client(strerror(errno));
        return;
    }
    if (client_fd_ >= 0) loop_.update_fd(client_watch_, POLLIN);
}

}  // namespace umc::companion
