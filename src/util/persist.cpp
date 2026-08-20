#include "util/persist.h"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>

#include "util/log.h"

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

bool durable_replace(const std::string& tmp_path, const std::string& path, std::string& error,
                     bool keep_backup) {
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

    if (keep_backup) {
        std::string backup = path + ".bak";
        ::unlink(backup.c_str());
        // ENOENT just means there is nothing to back up yet. Any other failure
        // is worth saying, but not worth refusing the write over: a save we
        // skipped is a guaranteed loss, a missing backup only a possible one.
        if (::link(path.c_str(), backup.c_str()) != 0 && errno != ENOENT) {
            LOG_WARN("cannot keep a backup of %s: %s", path.c_str(), std::strerror(errno));
        }
    }

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

std::string quarantine(const std::string& path) {
    // Second-resolution suffix: two corrupt files in the same second would be
    // the same file rewritten, and keeping the first is the useful choice.
    char suffix[32];
    std::time_t now = std::time(nullptr);
    std::tm tm {};
    ::gmtime_r(&now, &tm);
    std::strftime(suffix, sizeof suffix, ".corrupt-%Y%m%d-%H%M%S", &tm);

    std::string dest = path + suffix;
    if (::rename(path.c_str(), dest.c_str()) != 0) {
        LOG_ERROR("cannot move %s aside: %s", path.c_str(), std::strerror(errno));
        return {};
    }
    LOG_WARN("%s could not be read; kept as %s", path.c_str(), dest.c_str());
    return dest;
}

}  // namespace clt
