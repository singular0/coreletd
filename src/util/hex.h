#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "util/bytes.h"

namespace clt {

std::string hex(ByteView b);

// Short form used in logs: first `n` bytes of a key/hash.
std::string hex_prefix(ByteView b, size_t n = 6);

std::optional<Bytes> unhex(std::string_view s);

}  // namespace clt
