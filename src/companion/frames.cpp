#include "companion/frames.h"

#include "util/hex.h"
#include "util/log.h"

namespace umc::companion {

void FrameReader::feed(ByteView data) {
    buf_.insert(buf_.end(), data.begin(), data.end());
}

std::optional<Bytes> FrameReader::next() {
    for (;;) {
        // Resync: drop anything before a start marker.
        size_t start = 0;
        while (start < buf_.size() && buf_[start] != kFrameToDevice &&
               buf_[start] != kFrameToApp)
            start++;
        if (start > 0) {
            LOG_WARN("companion: discarded %zu junk bytes before frame start", start);
            buf_.erase(buf_.begin(), buf_.begin() + start);
        }

        Reader r(buf_);
        r.skip(1);  // start marker, matched above
        uint16_t len = r.u16();
        if (!r.ok()) return std::nullopt;  // need marker + length

        if (len > kMaxFrameSize) {
            // Length is nonsense; drop the marker and resynchronise rather than
            // stalling forever waiting for bytes that will never come.
            LOG_WARN("companion: frame length %u exceeds max, resyncing", len);
            buf_.erase(buf_.begin());
            continue;
        }

        ByteView body = r.take(len);
        if (!r.ok()) return std::nullopt;  // frame still arriving

        Bytes frame(body.begin(), body.end());
        buf_.erase(buf_.begin(), buf_.begin() + 3 + len);
        return frame;
    }
}

Bytes frame_response(ByteView payload) {
    Bytes out;
    out.reserve(3 + payload.size());
    out.push_back(kFrameToApp);
    put_u16(out, static_cast<uint16_t>(payload.size()));
    put_bytes(out, payload);
    return out;
}

Bytes resp_ok() { return Bytes {kRespOk}; }

Bytes resp_ok(uint32_t value) {
    Bytes out {kRespOk};
    put_u32(out, value);
    return out;
}

Bytes resp_err(uint8_t code) { return Bytes {kRespErr, code}; }

}  // namespace umc::companion
