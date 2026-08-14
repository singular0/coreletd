#pragma once

#include <cstdio>
#include <string>
#include <string_view>
#include <utility>

namespace clt {

enum class LogLevel { Error = 0, Warn, Info, Debug, Trace };

void log_set_level(LogLevel level);
LogLevel log_level();
bool log_parse_level(std::string_view name, LogLevel& out);

// When true, lines are written without a timestamp because journald adds one.
void log_set_syslog_style(bool on);

void log_write(LogLevel level, std::string_view msg);

std::string vformat(const char* fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 1, 2)))
#endif
    ;

#define UMC_LOG(level, ...)                                    \
    do {                                                       \
        if (static_cast<int>(level) <= static_cast<int>(::clt::log_level())) \
            ::clt::log_write(level, ::clt::vformat(__VA_ARGS__)); \
    } while (0)

#define LOG_ERROR(...) UMC_LOG(::clt::LogLevel::Error, __VA_ARGS__)
#define LOG_WARN(...) UMC_LOG(::clt::LogLevel::Warn, __VA_ARGS__)
#define LOG_INFO(...) UMC_LOG(::clt::LogLevel::Info, __VA_ARGS__)
#define LOG_DEBUG(...) UMC_LOG(::clt::LogLevel::Debug, __VA_ARGS__)
#define LOG_TRACE(...) UMC_LOG(::clt::LogLevel::Trace, __VA_ARGS__)

}  // namespace clt
