#include <algorithm>
#include <cstdio>
#include <fstream>
#include <vector>

#include "daemon/config.h"
#include "tests/test_util.h"
#include "util/ini.h"

using namespace clt;
using namespace clt::test;

static std::string write_temp(const std::string& body) {
    std::string path = "/tmp/coreletd_test_ini.ini";
    std::ofstream out(path, std::ios::trunc);
    out << body;
    return path;
}

static void test_basic_parsing() {
    std::string path = write_temp(
        "# a comment\n"
        "; another comment\n"
        "advert_name = uConsole\n"
        "lora_freq=869.618\n"
        "  lora_sf  =  8  \n"
        "repeat = true\n"
        "empty =\n"
        "\n");

    Ini ini;
    std::string error;
    CHECK(ini.load(path, error));

    CHECK(ini.get_str("advert_name") == "uConsole");
    CHECK(ini.get_double("lora_freq", 0.0) == 869.618);
    CHECK_EQ(ini.get_int("lora_sf", 0), 8L);
    CHECK(ini.get_bool("repeat", false));
    // An empty value falls back to the default rather than an empty string.
    CHECK(ini.get_str("empty", "fallback") == "fallback");
    CHECK(ini.get_str("missing", "default") == "default");

    std::remove(path.c_str());
}

static void test_quotes_and_inline_comments() {
    std::string path = write_temp(
        "plain = value # trailing comment\n"
        "quoted = \"has # hash inside\"\n"
        "single = 'also quoted'\n");

    Ini ini;
    std::string error;
    CHECK(ini.load(path, error));

    CHECK(ini.get_str("plain") == "value");
    // A password containing '#' must survive.
    CHECK(ini.get_str("quoted") == "has # hash inside");
    CHECK(ini.get_str("single") == "also quoted");

    std::remove(path.c_str());
}

static void test_sections_prefix_keys() {
    std::string path = write_temp(
        "[radio]\n"
        "freq = 915.0\n"
        "[node]\n"
        "name = test\n");

    Ini ini;
    std::string error;
    CHECK(ini.load(path, error));
    CHECK(ini.get_double("radio.freq", 0.0) == 915.0);
    CHECK(ini.get_str("node.name") == "test");

    std::remove(path.c_str());
}

static void test_case_insensitive_keys() {
    std::string path = write_temp("Advert_Name = Mixed\n");
    Ini ini;
    std::string error;
    CHECK(ini.load(path, error));
    CHECK(ini.get_str("advert_name") == "Mixed");
    std::remove(path.c_str());
}

static void test_malformed_reports_error() {
    std::string path = write_temp("this line has no equals sign\n");
    Ini ini;
    std::string error;
    CHECK(!ini.load(path, error));
    CHECK(!error.empty());
    std::remove(path.c_str());

    Ini missing;
    std::string e2;
    CHECK(!missing.load("/nonexistent/path/coreletd.ini", e2));
    CHECK(!e2.empty());
}

static void test_bad_values_are_reported() {
    std::string path = write_temp("lora_sf = eight\nflag = maybe\n");
    Ini ini;
    std::string error;
    CHECK(ini.load(path, error));

    // A typo'd pin number must be surfaced, not silently defaulted.
    bool ok = true;
    ini.get_int("lora_sf", 8, ok);
    CHECK(!ok);

    ok = true;
    ini.get_bool("flag", false, ok);
    CHECK(!ok);

    std::remove(path.c_str());
}

static void test_unread_keys_are_tracked() {
    std::string path = write_temp("known = 1\nmispelled_key = 2\n");
    Ini ini;
    std::string error;
    CHECK(ini.load(path, error));

    ini.get_int("known", 0);
    auto unread = ini.unread_keys();
    CHECK_EQ(unread.size(), size_t {1});
    if (unread.size() == 1) CHECK(unread[0] == "mispelled_key");

    std::remove(path.c_str());
}

static void test_retry_interval() {
    // Absent: the radio is retried every 10 s by default.
    std::string path = write_temp("[radio]\nlora_freq = 869.618\n");
    Config def;
    std::string error;
    CHECK(def.load(path, error));
    CHECK_EQ(def.spi.retry_interval_s, uint32_t {10});

    path = write_temp(
        "[radio]\n"
        "lora_freq = 869.618\n"
        "[hardware]\n"
        "lora_retry_interval = 45\n");
    Config cfg;
    CHECK(cfg.load(path, error));
    CHECK_EQ(cfg.spi.retry_interval_s, uint32_t {45});

    // 0 is meaningful: it turns retrying off entirely.
    path = write_temp(
        "[radio]\n"
        "lora_freq = 869.618\n"
        "[hardware]\n"
        "lora_retry_interval = 0\n");
    Config off;
    CHECK(off.load(path, error));
    CHECK_EQ(off.spi.retry_interval_s, uint32_t {0});

    path = write_temp(
        "[radio]\n"
        "lora_freq = 869.618\n"
        "[hardware]\n"
        "lora_retry_interval = -5\n");
    Config bad;
    std::string bad_error;
    CHECK(!bad.load(path, bad_error));
    CHECK(!bad_error.empty());

    std::remove(path.c_str());
}

static void test_companion_interfaces() {
    std::string path = write_temp("[radio]\nlora_freq = 869.618\n");
    Config def;
    std::string error;
    CHECK(def.load(path, error));
    CHECK(def.companion.transport == companion::Server::Transport::Unix);
    CHECK(def.companion.socket_path == "/run/coreletd/companion.sock");

    path = write_temp(
        "[radio]\n"
        "lora_freq = 869.618\n"
        "[companion]\n"
        "companion_interface = tcp\n"
        "companion_bind = 127.0.0.2\n"
        "companion_port = 6000\n");
    Config tcp;
    CHECK(tcp.load(path, error));
    CHECK(tcp.companion.transport == companion::Server::Transport::Tcp);
    CHECK(tcp.companion.bind_addr == "127.0.0.2");
    CHECK_EQ(tcp.companion.port, uint16_t {6000});

    path = write_temp(
        "[radio]\n"
        "lora_freq = 869.618\n"
        "[companion]\n"
        "companion_interface = serial\n");
    Config bad;
    std::string bad_error;
    CHECK(!bad.load(path, bad_error));
    CHECK(bad_error.find("unix") != std::string::npos);

    std::remove(path.c_str());
}

static std::string as_sectioned_setting(const std::string& setting) {
    size_t dot = setting.find('.');
    CHECK(dot != std::string::npos);
    if (dot == std::string::npos) return setting;
    return "[" + setting.substr(0, dot) + "]\n" + setting.substr(dot + 1) + "\n";
}

static void check_config_rejected(const std::string& setting) {
    std::string path =
        write_temp("[radio]\nlora_freq = 869.618\n" + as_sectioned_setting(setting));
    Config cfg;
    std::string error;
    CHECK(!cfg.load(path, error));
    CHECK(!error.empty());
}

static void test_config_rejects_malformed_and_unsafe_values() {
    // Malformed values must fail startup instead of silently selecting the
    // defaults. Cover each parser kind used by Config.
    check_config_rejected("radio.lora_sf = eight");
    check_config_rejected("radio.duty_cycle = often");
    check_config_rejected("node.repeat = perhaps");

    // Narrow integer fields and timer multiplication cannot wrap.
    check_config_rejected("radio.lora_preamble = 65536");
    check_config_rejected("radio.lora_sync_word = 256");
    check_config_rejected("node.advert_interval = -1");
    check_config_rejected("node.advert_interval = 4294968");
    check_config_rejected("node.max_hops = -1");
    check_config_rejected("node.max_hops = 65");
    check_config_rejected("companion.companion_port = 0");
    check_config_rejected("companion.companion_port = 65536");

    // Values sent to the radio must remain within SX1262 limits.
    check_config_rejected("radio.lora_freq = 149.9");
    check_config_rejected("radio.lora_freq = 960.1");
    check_config_rejected("radio.lora_bw = 100");
    check_config_rejected("hardware.lora_tcxo = 1.5");
    check_config_rejected("hardware.lora_tcxo = 3.4");
    check_config_rejected("hardware.current_limit = 0");
    check_config_rejected("hardware.current_limit = 158");
    check_config_rejected("hardware.spi_speed = 0");
    check_config_rejected("hardware.spi_speed = 16000001");

    // Duty-cycle enforcement must never be disabled by an invalid percentage.
    check_config_rejected("radio.duty_cycle = 0");
    check_config_rejected("radio.duty_cycle = 100");
    check_config_rejected("radio.duty_cycle = nan");

    check_config_rejected("node.lat = -90.1");
    check_config_rejected("node.lat = nan");
    check_config_rejected("node.lon = 180.1");
}

static void test_config_accepts_valid_boundaries() {
    std::string path = write_temp(
        "[radio]\n"
        "lora_freq = 150\n"
        "lora_bw = 7.81\n"
        "lora_sf = 5\n"
        "lora_cr = 5\n"
        "lora_tx_power = -9\n"
        "lora_preamble = 1\n"
        "lora_sync_word = 255\n"
        "duty_cycle = 0.01\n"
        "[hardware]\n"
        "lora_tcxo = 0\n"
        "current_limit = 157\n"
        "spi_speed = 16000000\n"
        "lora_retry_interval = 0\n"
        "[node]\n"
        "advert_interval = 4294967\n"
        "max_hops = 64\n"
        "lat = -90\n"
        "lon = 180\n"
        "[companion]\n"
        "companion_port = 65535\n");
    Config cfg;
    std::string error;
    CHECK(cfg.load(path, error));
    CHECK_EQ(cfg.radio.preamble, uint16_t {1});
    CHECK_EQ(cfg.node.advert_interval_s, uint32_t {4294967});
    CHECK_EQ(cfg.node.max_hops, uint8_t {64});
    CHECK_EQ(cfg.companion.port, uint16_t {65535});
    CHECK_EQ(cfg.node.lat_e6, int32_t {-90000000});
    CHECK_EQ(cfg.node.lon_e6, int32_t {180000000});
}

static void test_config_requires_sections() {
    std::string path = write_temp("lora_freq = 869.618\n");
    Config cfg;
    std::string error;
    CHECK(!cfg.load(path, error));
    CHECK(error.find("radio.lora_freq") != std::string::npos);
    std::remove(path.c_str());
}

// Every `key = value` in the shipped file, commented-out samples included. A
// commented line only counts when the '=' is spaced, which is how the file
// writes every setting — that is what keeps unrelated snippets in the prose
// (dtparam=spi=on) from being read as settings.
static std::vector<std::string> shipped_ini_keys() {
    std::ifstream in(std::string(CORELETD_SOURCE_DIR) + "/etc/coreletd.ini");
    std::vector<std::string> keys;
    std::string line, section;
    while (std::getline(in, line)) {
        size_t i = line.find_first_not_of(" \t");
        if (i == std::string::npos) continue;
        bool commented = line[i] == '#' || line[i] == ';';
        if (!commented && line[i] == '[') {
            size_t end = line.find(']', i + 1);
            if (end != std::string::npos) section = line.substr(i + 1, end - i - 1);
            continue;
        }
        if (commented) i = line.find_first_not_of("#; \t", i);
        if (i == std::string::npos) continue;

        size_t start = i;
        while (i < line.size() &&
               (islower(static_cast<unsigned char>(line[i])) ||
                isdigit(static_cast<unsigned char>(line[i])) || line[i] == '_'))
            i++;
        if (i == start) continue;

        size_t sep = line.find_first_not_of(' ', i);
        if (sep == std::string::npos || line[sep] != '=') continue;
        if (commented && sep == i) continue;
        std::string key = line.substr(start, i - start);
        keys.push_back(section.empty() ? key : section + "." + key);
    }
    return keys;
}

static void test_shipped_ini_matches_the_settings_table() {
    // etc/coreletd.ini is the only documentation of what the daemon reads, so
    // it and Config's settings table have to name the same keys: one that is
    // only in the table is undocumented, one that is only in the file is a
    // setting the daemon would warn about as unknown and then ignore.
    std::vector<std::string> documented = shipped_ini_keys();
    CHECK(!documented.empty());
    std::vector<std::string_view> known = Config::keys();

    for (std::string_view k : known) {
        std::string key(k);
        bool found = std::find(documented.begin(), documented.end(), key) != documented.end();
        if (!found) fprintf(stderr, "     undocumented in coreletd.ini: %s\n", key.c_str());
        CHECK(found);
    }
    for (const std::string& key : documented) {
        bool found = std::find(known.begin(), known.end(), std::string_view(key)) != known.end();
        if (!found) fprintf(stderr, "     coreletd.ini documents unknown key: %s\n", key.c_str());
        CHECK(found);
    }
}

int main() {
    test_basic_parsing();
    test_quotes_and_inline_comments();
    test_sections_prefix_keys();
    test_case_insensitive_keys();
    test_malformed_reports_error();
    test_bad_values_are_reported();
    test_unread_keys_are_tracked();
    test_retry_interval();
    test_companion_interfaces();
    test_config_rejects_malformed_and_unsafe_values();
    test_config_accepts_valid_boundaries();
    test_config_requires_sections();
    test_shipped_ini_matches_the_settings_table();
    return finish("ini");
}
