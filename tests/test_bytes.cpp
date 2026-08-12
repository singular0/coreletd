#include "tests/test_util.h"
#include "util/bytes.h"

using namespace umc;
using namespace umc::test;

static void test_reads_fields_in_order() {
    Bytes b;
    b.push_back(0x11);
    put_u16(b, 0x2233);
    put_u32(b, 0x44556677);
    put_i32(b, -2);
    put_bytes(b, to_bytes("tail"));

    Reader r(b);
    CHECK_EQ(r.u8(), uint8_t {0x11});
    CHECK_EQ(r.u16(), uint16_t {0x2233});
    CHECK_EQ(r.u32(), uint32_t {0x44556677});
    CHECK_EQ(r.i32(), int32_t {-2});
    CHECK_BYTES(r.rest(), to_bytes("tail"));
    CHECK(r.ok());
    CHECK_EQ(r.remaining(), size_t {0});
}

// The whole point of the cursor: a short frame yields a failed reader rather
// than a read past the end.
static void test_short_read_fails_rather_than_overruns() {
    Bytes b = {1, 2, 3};

    Reader r(b);
    CHECK_EQ(r.u32(), uint32_t {0});
    CHECK(!r.ok());
    // The failed read consumed nothing, so the caller can still report how
    // much it did have.
    CHECK_EQ(r.remaining(), size_t {3});
}

// Failure is sticky so a decoder can read every field and check once at the
// end; a later short field must not be masked by an earlier long one.
static void test_failure_is_sticky() {
    Bytes b = {1, 2, 3, 4, 5};

    Reader r(b);
    CHECK_EQ(r.u32(), uint32_t {0x04030201});
    CHECK(r.ok());
    CHECK_EQ(r.u32(), uint32_t {0});  // only one byte left
    CHECK(!r.ok());

    // Reads that would otherwise succeed still fail.
    CHECK_EQ(r.u8(), uint8_t {0});
    CHECK(r.take(1).empty());
    CHECK(r.rest().empty());
    CHECK(!r.has(1));
}

static void test_take_is_all_or_nothing() {
    Bytes b = {1, 2, 3, 4};

    Reader r(b);
    CHECK_BYTES(r.take(3), (Bytes {1, 2, 3}));
    CHECK(r.ok());
    CHECK(r.take(2).empty());
    CHECK(!r.ok());
}

// Optional trailing fields: has() is how a handler distinguishes "absent",
// which is fine, from "truncated", which is not.
static void test_has_reports_optional_tails() {
    Bytes b = {1, 2, 3};

    Reader r(b);
    CHECK(r.has(3));
    CHECK(!r.has(4));
    r.skip(3);
    CHECK(r.ok());
    CHECK(!r.has(1));
    CHECK(r.rest().empty());
    CHECK(r.ok());  // consuming an empty tail is not a failure
}

static void test_fixed_str_stops_at_nul() {
    Bytes b = to_bytes("name");
    b.resize(8, 0);
    put_bytes(b, to_bytes("after"));

    Reader r(b);
    CHECK(r.fixed_str(8) == "name");
    CHECK_BYTES(r.rest(), to_bytes("after"));

    // A field with no NUL uses the full width.
    Bytes full = to_bytes("abcd");
    Reader r2(full);
    CHECK(r2.fixed_str(4) == "abcd");
    CHECK(r2.ok());

    // A truncated field is a failure, not a short string.
    Reader r3(full);
    CHECK(r3.fixed_str(5).empty());
    CHECK(!r3.ok());
}

static void test_empty_input() {
    Reader r(ByteView {});
    CHECK(r.ok());
    CHECK_EQ(r.remaining(), size_t {0});
    CHECK(r.rest().empty());
    CHECK_EQ(r.u8(), uint8_t {0});
    CHECK(!r.ok());
}

int main() {
    test_reads_fields_in_order();
    test_short_read_fails_rather_than_overruns();
    test_failure_is_sticky();
    test_take_is_all_or_nothing();
    test_has_reports_optional_tails();
    test_fixed_str_stops_at_nul();
    test_empty_input();
    return finish("bytes");
}
