#pragma once

// Dependency-free test scaffolding. Each test binary has its own main() and
// returns non-zero on first failure count, which is all CTest needs.

#include <cstdio>
#include <string>
#include <string_view>

#include "util/bytes.h"
#include "util/hex.h"

namespace umc::test {

inline int g_failures = 0;
inline int g_checks = 0;

inline void report(bool ok, const char* expr, const char* file, int line,
                   const std::string& detail = {}) {
    g_checks++;
    if (ok) return;
    g_failures++;
    fprintf(stderr, "FAIL %s:%d: %s\n", file, line, expr);
    if (!detail.empty()) fprintf(stderr, "     %s\n", detail.c_str());
}

inline Bytes from_hex(std::string_view s) {
    auto b = unhex(s);
    if (!b) {
        fprintf(stderr, "FATAL: bad hex literal in test: %.*s\n", (int)s.size(), s.data());
        abort();
    }
    return *b;
}

inline Bytes from_str(std::string_view s) {
    return Bytes(s.begin(), s.end());
}

inline int finish(const char* name) {
    if (g_failures == 0) {
        printf("ok  %s (%d checks)\n", name, g_checks);
        return 0;
    }
    printf("FAILED %s (%d/%d checks failed)\n", name, g_failures, g_checks);
    return 1;
}

}  // namespace umc::test

#define CHECK(expr) ::umc::test::report((expr), #expr, __FILE__, __LINE__)

#define CHECK_EQ(a, b)                                                          \
    do {                                                                        \
        auto _a = (a);                                                          \
        auto _b = (b);                                                          \
        ::umc::test::report(_a == _b, #a " == " #b, __FILE__, __LINE__,          \
                            "got " + std::to_string(_a) + ", want " + std::to_string(_b)); \
    } while (0)

// Both arguments must be bound before use: evaluating them twice would take
// begin() and end() from two different temporaries.
#define CHECK_BYTES(a, b)                                                       \
    do {                                                                        \
        auto&& _av = (a);                                                       \
        auto&& _bv = (b);                                                       \
        ::umc::Bytes _a(_av.begin(), _av.end());                                \
        ::umc::Bytes _b(_bv.begin(), _bv.end());                                \
        ::umc::test::report(_a == _b, #a " == " #b, __FILE__, __LINE__,          \
                            "got " + ::umc::hex(_a) + "\n     want " + ::umc::hex(_b)); \
    } while (0)
