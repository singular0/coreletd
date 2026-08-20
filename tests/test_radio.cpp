// Radio parameters that are physical-layer facts rather than preferences.
// Low-data-rate optimisation is the one that bites: both ends have to agree or
// there is no link, and nothing on the air says which side is wrong.

#include <cmath>

#include "radio/radio.h"
#include "tests/test_util.h"

using namespace clt;
using namespace clt::test;

// The ten bandwidths daemon/config.cpp accepts, against the spreading factors
// it accepts, is the whole space an operator can reach from the ini file.
static constexpr double kBandwidths[] = {7.81,  10.42, 15.63, 20.83, 31.25,
                                         41.67, 62.5,  125.0, 250.0, 500.0};

// RadioLib's threshold: LDRO is on once a symbol reaches 16 ms. Written out
// here rather than reusing the implementation, so the test would notice the
// implementation changing its mind.
static bool want_ldro(uint8_t sf, double bw_khz) {
    return std::pow(2.0, sf) / bw_khz >= 16.0;
}

static void test_ldro_matches_the_symbol_time_threshold() {
    for (uint8_t sf = 5; sf <= 12; sf++) {
        for (double bw : kBandwidths) {
            radio::RadioParams p;
            p.sf = sf;
            p.bw_khz = bw;
            const bool got = p.low_data_rate_optimize();
            report(got == want_ldro(sf, bw), "ldro matches threshold", __FILE__, __LINE__,
                   "SF" + std::to_string(sf) + " BW" + std::to_string(bw) + ": got " +
                       std::to_string(got) + ", want " + std::to_string(want_ldro(sf, bw)));
        }
    }
}

// The combinations issue #15 names: MeshCore turns LDRO on for every one of
// these and the daemon used to leave it off, which is silence on the air.
static void test_the_settings_that_used_to_mismatch() {
    struct Case {
        uint8_t sf;
        double bw;
    };
    static constexpr Case kOn[] = {
        {10, 62.5}, {11, 62.5}, {12, 62.5},   // SF10-12 at 62.5 kHz
        {9, 31.25}, {10, 31.25}, {11, 31.25}, {12, 31.25},
        {11, 125.0}, {12, 125.0},             // SF11/12 at 125 kHz
        {12, 250.0},                          // SF12 at 250 kHz
    };
    for (const auto& c : kOn) {
        radio::RadioParams p;
        p.sf = c.sf;
        p.bw_khz = c.bw;
        report(p.low_data_rate_optimize(), "ldro on", __FILE__, __LINE__,
               "SF" + std::to_string(c.sf) + " BW" + std::to_string(c.bw));
    }

    // The shipped default is the case the old hardcoded 0x00 got right.
    radio::RadioParams def;
    CHECK(!def.low_data_rate_optimize());
    CHECK_EQ(def.sf, uint8_t {8});
}

// A test-only radio, because airtime_ms() is on the base class and needs no
// hardware to answer.
class ParamsOnlyRadio : public radio::Radio {
public:
    explicit ParamsOnlyRadio(radio::RadioParams p) : params_(p) {}
    bool begin(EventLoop&, std::string&) override { return true; }
    bool send(ByteView) override { return false; }
    bool tx_busy() const override { return false; }
    const radio::RadioParams& params() const override { return params_; }
    std::string describe() const override { return "params-only"; }

private:
    radio::RadioParams params_;
};

// Duty-cycle accounting divides by 4*(sf-2) when LDRO is on, so ignoring it
// undercounts airtime for exactly the slow settings that spend the most of it.
static void test_airtime_follows_the_ldro_bit() {
    radio::RadioParams slow;
    slow.sf = 12;
    slow.bw_khz = 62.5;
    CHECK(slow.low_data_rate_optimize());

    ParamsOnlyRadio r(slow);
    const uint32_t with_de = r.airtime_ms(32);

    // The same settings costed the old way, with the DE term forced off.
    const double t_sym = std::pow(2.0, slow.sf) / (slow.bw_khz * 1000.0);
    const double t_preamble = (slow.preamble + 4.25) * t_sym;
    const double numerator = 8.0 * 32 - 4.0 * slow.sf + 28 + 16;
    const double n_no_de = 8 + std::ceil(numerator / (4.0 * slow.sf)) * (4 + (slow.cr - 4));
    const auto without_de = static_cast<uint32_t>(std::ceil((t_preamble + n_no_de * t_sym) * 1000.0));

    CHECK(with_de > without_de);

    // A setting below the threshold is unchanged, so the default's budget is
    // exactly what it was before.
    radio::RadioParams fast;
    CHECK(!fast.low_data_rate_optimize());
    ParamsOnlyRadio f(fast);
    CHECK(f.airtime_ms(32) > 0);
}

int main() {
    test_ldro_matches_the_symbol_time_threshold();
    test_the_settings_that_used_to_mismatch();
    test_airtime_follows_the_ldro_bit();

    return finish("radio");
}
