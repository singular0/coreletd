#include "companion/frames.h"
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

    CHECK_EQ(framed[0], uint8_t {kFrameToApp});
    CHECK_EQ(rd_u16(framed, 1), uint16_t {4});
    CHECK_BYTES(subview(framed, 3), payload);

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
    CHECK_EQ(rd_u32(ok_val, 1), uint32_t {0x12345678});
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
    return finish("companion");
}
