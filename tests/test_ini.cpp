#include <cstdio>
#include <fstream>

#include "tests/test_util.h"
#include "util/ini.h"

using namespace umc;
using namespace umc::test;

static std::string write_temp(const std::string& body) {
    std::string path = "/tmp/umeshcore_test_ini.ini";
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
    CHECK(!missing.load("/nonexistent/path/umeshcore.ini", e2));
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

int main() {
    test_basic_parsing();
    test_quotes_and_inline_comments();
    test_sections_prefix_keys();
    test_case_insensitive_keys();
    test_malformed_reports_error();
    test_bad_values_are_reported();
    test_unread_keys_are_tracked();
    return finish("ini");
}
