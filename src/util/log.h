#pragma once

#include <cstdio>
#include <string>
#include <string_view>
#include <utility>

namespace umc {

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
        if (static_cast<int>(level) <= static_cast<int>(::umc::log_level())) \
            ::umc::log_write(level, ::umc::vformat(__VA_ARGS__)); \
    } while (0)

#define LOG_ERROR(...) UMC_LOG(::umc::LogLevel::Error, __VA_ARGS__)
#define LOG_WARN(...) UMC_LOG(::umc::LogLevel::Warn, __VA_ARGS__)
#define LOG_INFO(...) UMC_LOG(::umc::LogLevel::Info, __VA_ARGS__)
#define LOG_DEBUG(...) UMC_LOG(::umc::LogLevel::Debug, __VA_ARGS__)
#define LOG_TRACE(...) UMC_LOG(::umc::LogLevel::Trace, __VA_ARGS__)

}  // namespace umc
