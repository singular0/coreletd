#include "util/log.h"

#include <cstdarg>
#include <ctime>
#include <mutex>
#include <vector>

namespace clt {

namespace {
LogLevel g_level = LogLevel::Info;
bool g_syslog_style = false;
std::mutex g_mutex;

const char* level_name(LogLevel l) {
    switch (l) {
        case LogLevel::Error: return "ERROR";
        case LogLevel::Warn: return "WARN ";
        case LogLevel::Info: return "INFO ";
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Trace: return "TRACE";
    }
    return "?????";
}
}  // namespace

void log_set_level(LogLevel level) { g_level = level; }
LogLevel log_level() { return g_level; }
void log_set_syslog_style(bool on) { g_syslog_style = on; }

bool log_parse_level(std::string_view name, LogLevel& out) {
    if (name == "error") { out = LogLevel::Error; return true; }
    if (name == "warn" || name == "warning") { out = LogLevel::Warn; return true; }
    if (name == "info") { out = LogLevel::Info; return true; }
    if (name == "debug") { out = LogLevel::Debug; return true; }
    if (name == "trace") { out = LogLevel::Trace; return true; }
    return false;
}

void log_write(LogLevel level, std::string_view msg) {
    std::lock_guard<std::mutex> lock(g_mutex);
    FILE* out = level == LogLevel::Error || level == LogLevel::Warn ? stderr : stdout;
    if (g_syslog_style) {
        // journald captures stdout/stderr and stamps its own time.
        fprintf(out, "[%s] %.*s\n", level_name(level), static_cast<int>(msg.size()), msg.data());
    } else {
        char ts[32];
        std::time_t now = std::time(nullptr);
        std::tm tm {};
        localtime_r(&now, &tm);
        std::strftime(ts, sizeof(ts), "%H:%M:%S", &tm);
        fprintf(out, "%s [%s] %.*s\n", ts, level_name(level), static_cast<int>(msg.size()),
                msg.data());
    }
    fflush(out);
}

std::string vformat(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    va_list copy;
    va_copy(copy, args);
    int n = vsnprintf(nullptr, 0, fmt, copy);
    va_end(copy);
    if (n < 0) {
        va_end(args);
        return {};
    }
    std::string out(static_cast<size_t>(n), '\0');
    vsnprintf(out.data(), static_cast<size_t>(n) + 1, fmt, args);
    va_end(args);
    return out;
}

}  // namespace clt
