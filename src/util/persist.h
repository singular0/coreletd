#pragma once

#include <string>

namespace clt {

// Atomically replaces `path` with an already flushed and closed temporary file.
// The file is synced before the rename and the parent directory afterwards so
// a successful return means the replacement survives a power loss.
bool durable_replace(const std::string& tmp_path, const std::string& path,
                     std::string& error);

}  // namespace clt
