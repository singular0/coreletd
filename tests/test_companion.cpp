#include "companion/frames.h"
#include "companion/server.h"
#include "daemon/host_metrics.h"
#include "tests/test_util.h"

using namespace umc;
using namespace umc::test;
using namespace umc::companion;

static Bytes make_frame(uint8_t marker, const Bytes& payload) {
    Bytes out {marker};
    put_u16(out, static_cast<uint16_t>(payload.size()));
    put_bytes(out, payload);
    return out;
}

static void test_single_frame() {
    FrameReader r;
    Bytes payload = {kCmdAppStart, 0, 0, 0, 0, 0, 0, 0, 'm', 'c'};
    r.feed(make_frame(kFrameToDevice, payload));

    auto f = r.next();
    CHECK(f.has_value());
    if (f) CHECK_BYTES(*f, payload);
    CHECK(!r.next().has_value());
}

static void test_split_across_reads() {
    FrameReader r;
    Bytes payload = {kCmdDeviceQuery, 3};
    Bytes framed = make_frame(kFrameToDevice, payload);

    // Deliver one byte at a time: a TCP stream gives no framing guarantees.
    for (size_t i = 0; i + 1 < framed.size(); i++) {
        r.feed(ByteView(framed).subspan(i, 1));
        CHECK(!r.next().has_value());
    }
    r.feed(ByteView(framed).subspan(framed.size() - 1, 1));

    auto f = r.next();
    CHECK(f.has_value());
    if (f) CHECK_BYTES(*f, payload);
}

static void test_multiple_frames_in_one_read() {
    FrameReader r;
    Bytes a = {kCmdGetDeviceTime};
    Bytes b = {kCmdSyncNextMessage};

    Bytes stream = make_frame(kFrameToDevice, a);
    Bytes second = make_frame(kFrameToDevice, b);
    stream.insert(stream.end(), second.begin(), second.end());
    r.feed(stream);

    auto f1 = r.next();
    auto f2 = r.next();
    CHECK(f1.has_value());
    CHECK(f2.has_value());
    if (f1) CHECK_BYTES(*f1, a);
    if (f2) CHECK_BYTES(*f2, b);
    CHECK(!r.next().has_value());
}

static void test_resync_after_junk() {
    FrameReader r;
    Bytes payload = {kCmdAppStart};

    // Junk before a valid frame must be discarded, not stall the reader.
    Bytes stream = {0xAA, 0xBB, 0xCC};
    Bytes good = make_frame(kFrameToDevice, payload);
    stream.insert(stream.end(), good.begin(), good.end());
    r.feed(stream);

    auto f = r.next();
    CHECK(f.has_value());
    if (f) CHECK_BYTES(*f, payload);
}

static void test_empty_frame_is_returned_not_hung() {
    FrameReader r;
    r.feed(make_frame(kFrameToDevice, {}));
    auto f = r.next();
    CHECK(f.has_value());
    if (f) CHECK_EQ(f->size(), size_t {0});
}

static void test_oversized_length_resyncs() {
    FrameReader r;
    // A bogus length must not wedge the reader waiting for bytes forever.
    Bytes bad {kFrameToDevice, 0xFF, 0xFF};
    Bytes payload = {kCmdAppStart};
    Bytes good = make_frame(kFrameToDevice, payload);
    bad.insert(bad.end(), good.begin(), good.end());
    r.feed(bad);

    auto f = r.next();
    CHECK(f.has_value());
    if (f) CHECK_BYTES(*f, payload);
}

static void test_response_framing() {
    Bytes payload = {kRespOk, 1, 2, 3};
    Bytes framed = frame_response(payload);

    Reader hdr(framed);
    CHECK_EQ(hdr.u8(), uint8_t {kFrameToApp});
    CHECK_EQ(hdr.u16(), uint16_t {4});
    CHECK_BYTES(hdr.rest(), payload);

    // A framed response must be readable by the same de-framer.
    FrameReader r;
    r.feed(framed);
    auto f = r.next();
    CHECK(f.has_value());
    if (f) CHECK_BYTES(*f, payload);
}

static void test_response_helpers() {
    CHECK_BYTES(resp_ok(), (Bytes {0}));
    CHECK_BYTES(resp_err(kErrNotFound), (Bytes {1, 2}));

    Bytes ok_val = resp_ok(0x12345678);
    CHECK_EQ(ok_val.size(), size_t {5});
    Reader r(ok_val);
    CHECK_EQ(r.u8(), uint8_t {kRespOk});
    CHECK_EQ(r.u32(), uint32_t {0x12345678});
}

static void test_outbound_buffer_limit_is_overflow_safe() {
    CHECK(outbound_buffer_has_capacity(0, 8, 8));
    CHECK(outbound_buffer_has_capacity(3, 5, 8));
    CHECK(!outbound_buffer_has_capacity(3, 6, 8));
    CHECK(!outbound_buffer_has_capacity(9, 0, 8));
    CHECK(!outbound_buffer_has_capacity(size_t(-2), 4, size_t(-1)));
}

// Both figures the app shows come from one statvfs, and the reply carries them
// as a pair: a total smaller than the used part, or a used part that swallowed
// the reserved blocks into a negative, would render as nonsense.
static void test_host_metrics_storage_is_coherent() {
    umc::HostMetrics::Info info;
    info.model = "test";
    umc::HostMetrics metrics(info, "/tmp");

    auto s = metrics.storage();
    CHECK(s.total_bytes > 0);
    CHECK(s.used_bytes <= s.total_bytes);

    // No battery on a dev machine, and none on any host where the sysfs walk
    // found nothing: 0 is the protocol's "unknown", not a flat pack.
    CHECK(metrics.battery_mv() == 0 || metrics.battery_mv() > 1000);

    // The identity half is passed through untouched.
    CHECK(metrics.info().model == "test");
}

// An unreadable state directory must report zeros rather than whatever an
// uninitialised statvfs left on the stack.
static void test_host_metrics_storage_survives_a_bad_path() {
    umc::HostMetrics metrics(umc::HostMetrics::Info {}, "/nonexistent/umeshcore/state");
    auto s = metrics.storage();
    CHECK_EQ(s.used_bytes, uint64_t {0});
    CHECK_EQ(s.total_bytes, uint64_t {0});
}

int main() {
    test_single_frame();
    test_split_across_reads();
    test_multiple_frames_in_one_read();
    test_resync_after_junk();
    test_empty_frame_is_returned_not_hung();
    test_oversized_length_resyncs();
    test_response_framing();
    test_response_helpers();
    test_outbound_buffer_limit_is_overflow_safe();
    test_host_metrics_storage_is_coherent();
    test_host_metrics_storage_survives_a_bad_path();
    return finish("companion");
}
