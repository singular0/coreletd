#include "util/persist.h"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

namespace clt {

namespace {

int open_nointr(const char* path, int flags) {
    int fd;
    do {
        fd = ::open(path, flags);
    } while (fd < 0 && errno == EINTR);
    return fd;
}

bool sync_and_close(int fd, const std::string& what, std::string& error) {
    int rc;
    do {
        rc = ::fsync(fd);
    } while (rc != 0 && errno == EINTR);
    if (rc != 0) {
        int saved_errno = errno;
        ::close(fd);
        error = "cannot fsync " + what + ": " + std::strerror(saved_errno);
        return false;
    }
    if (::close(fd) != 0) {
        error = "cannot close " + what + ": " + std::strerror(errno);
        return false;
    }
    return true;
}

std::string parent_directory(const std::string& path) {
    size_t slash = path.find_last_of('/');
    if (slash == std::string::npos) return ".";
    if (slash == 0) return "/";
    return path.substr(0, slash);
}

}  // namespace

bool durable_replace(const std::string& tmp_path, const std::string& path,
                     std::string& error) {
    error.clear();

    int file_flags = O_WRONLY;
#ifdef O_CLOEXEC
    file_flags |= O_CLOEXEC;
#endif
    int tmp_fd = open_nointr(tmp_path.c_str(), file_flags);
    if (tmp_fd < 0) {
        error = "cannot open " + tmp_path + " for syncing: " + std::strerror(errno);
        return false;
    }
    if (!sync_and_close(tmp_fd, tmp_path, error)) return false;

    int rc;
    do {
        rc = ::rename(tmp_path.c_str(), path.c_str());
    } while (rc != 0 && errno == EINTR);
    if (rc != 0) {
        error = "cannot rename " + tmp_path + " to " + path + ": " + std::strerror(errno);
        return false;
    }

    std::string parent = parent_directory(path);
    int directory_flags = O_RDONLY;
#ifdef O_CLOEXEC
    directory_flags |= O_CLOEXEC;
#endif
#ifdef O_DIRECTORY
    directory_flags |= O_DIRECTORY;
#endif
    int parent_fd = open_nointr(parent.c_str(), directory_flags);
    if (parent_fd < 0) {
        error = "cannot open directory " + parent + " for syncing: " + std::strerror(errno);
        return false;
    }
    return sync_and_close(parent_fd, "directory " + parent, error);
}

}  // namespace clt
