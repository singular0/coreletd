#pragma once

#include <string>

namespace clt {

// Atomically replaces `path` with an already flushed and closed temporary file.
// The file is synced before the rename and the parent directory afterwards so
// a successful return means the replacement survives a power loss.
// The replacement is made 0600 before it is installed, whatever the umask made
// it: everything written through here is node state — the private key, channel
// secrets, who we talk to and what they said — and nothing else on the machine
// has a reason to read it. One that cannot be restricted is not installed.
// With `keep_backup`, the file being replaced is hard-linked to `path + ".bak"`
// first, so the last version that was readable survives a save that writes
// something that is not. Atomic replacement makes a torn file impossible, but a
// bug in our own serialisation would otherwise destroy the only copy on the
// next write. It is a link rather than a copy: no data is moved, and `path`
// never stops existing.
bool durable_replace(const std::string& tmp_path, const std::string& path, std::string& error,
                     bool keep_backup = false);

// Moves a state file that could not be parsed out of the way, so that the next
// successful save cannot quietly overwrite the evidence. Returns the path it
// was moved to, or an empty string if it could not be moved — in which case the
// caller is looking at a directory it cannot write, which is worth saying.
std::string quarantine(const std::string& path);

// Removes group and other access from a state file that already exists, for
// files written before durable_replace() restricted them, or put in place by
// hand. A missing file is not an error. A file that cannot be restricted —
// typically one root copied in and still owns — is reported and left alone;
// the next save replaces it with one of ours.
void restrict_to_owner(const std::string& path);

}  // namespace clt
