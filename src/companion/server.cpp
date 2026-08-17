#include "companion/server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "util/hex.h"
#include "util/log.h"

namespace clt::companion {

bool outbound_buffer_has_capacity(size_t buffered, size_t next, size_t limit) {
    return buffered <= limit && next <= limit - buffered;
}

namespace {
constexpr mode_t kUnixSocketMode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;  // 0660

bool set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

void close_fd(int& fd) {
    if (fd < 0) return;
    ::close(fd);
    fd = -1;
}
}  // namespace

Server::Server(EventLoop& loop, Options opts) : loop_(loop), opts_(std::move(opts)) {}

Server::~Server() { shutdown(); }

bool Server::start(std::string& error) {
    if (listen_fd_ >= 0) {
        error = "already started";
        return false;
    }
    return opts_.transport == Transport::Unix ? start_unix(error) : start_tcp(error);
}

bool Server::start_tcp(std::string& error) {
    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(opts_.port);
    if (opts_.bind_addr.empty() || opts_.bind_addr == "0.0.0.0") {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (::inet_pton(AF_INET, opts_.bind_addr.c_str(), &addr.sin_addr) != 1) {
        error = "invalid bind address " + opts_.bind_addr;
        return false;
    }

    const bool loopback = (ntohl(addr.sin_addr.s_addr) & 0xFF000000u) == 0x7F000000u;
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        error = std::string("socket: ") + strerror(errno);
        return false;
    }

    int one = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        error = "bind " + opts_.bind_addr + ":" + std::to_string(opts_.port) + ": " +
                strerror(errno);
        close_fd(listen_fd_);
        return false;
    }
    if (opts_.port == 0) {
        sockaddr_in bound {};
        socklen_t bound_len = sizeof(bound);
        if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&bound), &bound_len) != 0) {
            error = std::string("getsockname: ") + strerror(errno);
            close_fd(listen_fd_);
            return false;
        }
        opts_.port = ntohs(bound.sin_port);
    }
    if (::listen(listen_fd_, 1) != 0) {
        error = std::string("listen: ") + strerror(errno);
        close_fd(listen_fd_);
        return false;
    }
    if (!set_nonblocking(listen_fd_)) {
        error = std::string("fcntl: ") + strerror(errno);
        close_fd(listen_fd_);
        return false;
    }

    listen_watch_ = loop_.add_fd(listen_fd_, POLLIN, [this](short r) { on_listen_ready(r); });
    if (!loopback)
        LOG_WARN("companion: exposing unauthenticated TCP on %s:%u",
                 opts_.bind_addr.c_str(), opts_.port);
    LOG_INFO("companion: listening on %s:%u", opts_.bind_addr.c_str(), opts_.port);
    return true;
}

bool Server::start_unix(std::string& error) {
    if (opts_.socket_path.empty()) {
        error = "companion socket path is empty";
        return false;
    }

    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    if (opts_.socket_path.size() >= sizeof(addr.sun_path)) {
        error = "companion socket path is too long: " + opts_.socket_path;
        return false;
    }
    memcpy(addr.sun_path, opts_.socket_path.c_str(), opts_.socket_path.size() + 1);

    // A stable sidecar lock distinguishes a socket left behind by a crash from
    // one owned by another live daemon. Blindly unlinking the latter would let
    // two servers run while only the newer one remained reachable by path.
    const std::string lock_path = opts_.socket_path + ".lock";
    unix_lock_fd_ =
        ::open(lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, kUnixSocketMode);
    if (unix_lock_fd_ < 0) {
        error = "open " + lock_path + ": " + strerror(errno);
        return false;
    }
    struct stat lock_stat {};
    if (::fstat(unix_lock_fd_, &lock_stat) != 0 || !S_ISREG(lock_stat.st_mode)) {
        error = "companion socket lock is not a regular file: " + lock_path;
        close_fd(unix_lock_fd_);
        return false;
    }
    if (::fchown(unix_lock_fd_, static_cast<uid_t>(-1), ::getegid()) != 0) {
        error = "chown " + lock_path + ": " + strerror(errno);
        close_fd(unix_lock_fd_);
        return false;
    }
    if (::fchmod(unix_lock_fd_, kUnixSocketMode) != 0) {
        error = "chmod " + lock_path + ": " + strerror(errno);
        close_fd(unix_lock_fd_);
        return false;
    }
    if (::flock(unix_lock_fd_, LOCK_EX | LOCK_NB) != 0) {
        error = "companion socket is already in use: " + opts_.socket_path;
        close_fd(unix_lock_fd_);
        return false;
    }

    struct stat existing {};
    if (::lstat(opts_.socket_path.c_str(), &existing) == 0) {
        if (!S_ISSOCK(existing.st_mode)) {
            error = "refusing to replace non-socket path " + opts_.socket_path;
            close_fd(unix_lock_fd_);
            return false;
        }
        if (::unlink(opts_.socket_path.c_str()) != 0) {
            error = "remove stale socket " + opts_.socket_path + ": " + strerror(errno);
            close_fd(unix_lock_fd_);
            return false;
        }
        LOG_INFO("companion: removed stale socket %s", opts_.socket_path.c_str());
    } else if (errno != ENOENT) {
        error = "inspect " + opts_.socket_path + ": " + strerror(errno);
        close_fd(unix_lock_fd_);
        return false;
    }

    listen_fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        error = std::string("socket: ") + strerror(errno);
        close_fd(unix_lock_fd_);
        return false;
    }

    // Apply the secure mode at creation as well as explicitly below, so there
    // is no instant in which a permissive process umask exposes the endpoint.
    const mode_t old_umask = ::umask(0117);
    const socklen_t addr_len = static_cast<socklen_t>(
        offsetof(sockaddr_un, sun_path) + opts_.socket_path.size() + 1);
    const int bind_result = ::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), addr_len);
    const int bind_errno = errno;
    ::umask(old_umask);
    if (bind_result != 0) {
        error = "bind " + opts_.socket_path + ": " + strerror(bind_errno);
        close_fd(listen_fd_);
        close_fd(unix_lock_fd_);
        return false;
    }
    owns_unix_path_ = true;

    struct stat bound {};
    if (::lstat(opts_.socket_path.c_str(), &bound) != 0) {
        error = "inspect bound socket " + opts_.socket_path + ": " + strerror(errno);
        close_fd(listen_fd_);
        cleanup_unix_path();
        close_fd(unix_lock_fd_);
        return false;
    }
    unix_path_dev_ = static_cast<uint64_t>(bound.st_dev);
    unix_path_ino_ = static_cast<uint64_t>(bound.st_ino);

    // BSD filesystems may inherit the parent directory's group rather than the
    // process's effective group, so set it explicitly instead of relying on
    // bind()'s ownership rules.
    if (::chown(opts_.socket_path.c_str(), static_cast<uid_t>(-1), ::getegid()) != 0) {
        error = "chown " + opts_.socket_path + ": " + strerror(errno);
        close_fd(listen_fd_);
        cleanup_unix_path();
        close_fd(unix_lock_fd_);
        return false;
    }
    if (::chmod(opts_.socket_path.c_str(), kUnixSocketMode) != 0) {
        error = "chmod " + opts_.socket_path + ": " + strerror(errno);
        close_fd(listen_fd_);
        cleanup_unix_path();
        close_fd(unix_lock_fd_);
        return false;
    }

    if (::listen(listen_fd_, 1) != 0) {
        error = std::string("listen: ") + strerror(errno);
        close_fd(listen_fd_);
        cleanup_unix_path();
        close_fd(unix_lock_fd_);
        return false;
    }
    if (!set_nonblocking(listen_fd_)) {
        error = std::string("fcntl: ") + strerror(errno);
        close_fd(listen_fd_);
        cleanup_unix_path();
        close_fd(unix_lock_fd_);
        return false;
    }

    listen_watch_ = loop_.add_fd(listen_fd_, POLLIN, [this](short r) { on_listen_ready(r); });
    LOG_INFO("companion: listening on unix://%s (mode 0660, gid %lu)",
             opts_.socket_path.c_str(), static_cast<unsigned long>(::getegid()));
    return true;
}

void Server::cleanup_unix_path() {
    if (!owns_unix_path_) return;

    struct stat current {};
    if (::lstat(opts_.socket_path.c_str(), &current) == 0 && S_ISSOCK(current.st_mode) &&
        static_cast<uint64_t>(current.st_dev) == unix_path_dev_ &&
        static_cast<uint64_t>(current.st_ino) == unix_path_ino_) {
        if (::unlink(opts_.socket_path.c_str()) != 0)
            LOG_WARN("companion: cannot remove socket %s: %s", opts_.socket_path.c_str(),
                     strerror(errno));
    }
    owns_unix_path_ = false;
    unix_path_dev_ = 0;
    unix_path_ino_ = 0;
}

void Server::shutdown() {
    if (client_fd_ >= 0) drop_client("shutting down");
    if (listen_fd_ >= 0) {
        listen_watch_.reset();
        close_fd(listen_fd_);
    }
    cleanup_unix_path();
    close_fd(unix_lock_fd_);
}

void Server::on_listen_ready(short revents) {
    if (revents & POLLIN) accept_client();
}

void Server::accept_client() {
    sockaddr_storage peer {};
    socklen_t len = sizeof(peer);
    int fd = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&peer), &len);
    if (fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) LOG_WARN("companion: accept: %s", strerror(errno));
        return;
    }

    std::string peer_name = "local process";
    uint16_t peer_port = 0;
    if (opts_.transport == Transport::Tcp) {
        const auto* tcp_peer = reinterpret_cast<const sockaddr_in*>(&peer);
        char ip[INET_ADDRSTRLEN] = "?";
        ::inet_ntop(AF_INET, &tcp_peer->sin_addr, ip, sizeof(ip));
        peer_name = ip;
        peer_port = ntohs(tcp_peer->sin_port);
    }

    if (client_fd_ >= 0) {
        // Replace the existing session: a dead client must not lock out a live one.
        LOG_INFO("companion: new connection from %s replacing existing client",
                 peer_name.c_str());
        drop_client("replaced by a new connection");
    }

    if (!set_nonblocking(fd)) {
        LOG_WARN("companion: cannot set client non-blocking: %s", strerror(errno));
        ::close(fd);
        return;
    }
    // Responses are small and latency matters more than packing.
    if (opts_.transport == Transport::Tcp) {
        int one = 1;
        ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }

    client_fd_ = fd;
    reader_.reset();
    out_buf_.clear();
    client_watch_ = loop_.add_fd(client_fd_, POLLIN, [this](short r) { on_client_ready(r); });

    if (opts_.transport == Transport::Tcp)
        LOG_INFO("companion: app connected from %s:%u", peer_name.c_str(), peer_port);
    else
        LOG_INFO("companion: app connected from %s", peer_name.c_str());
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

}  // namespace clt::companion
