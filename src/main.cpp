#include <getopt.h>
#include <signal.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>

#include "daemon/app.h"
#include "daemon/config.h"
#include "util/log.h"

namespace {

volatile sig_atomic_t g_stop = 0;

void on_signal(int) { g_stop = 1; }

void usage(const char* argv0) {
    printf(
        "coreletd %s — MeshCore daemon for uConsole + AIO v2\n"
        "\n"
        "Usage: %s [options]\n"
        "\n"
        "  -c, --config PATH   configuration file (default: %s)\n"
        "  -v, --verbose       raise log level to debug (repeat for trace)\n"
        "  -s, --syslog        omit timestamps, for running under systemd\n"
        "  -V, --version       print version and exit\n"
        "  -h, --help          this message\n",
        CORELETD_VERSION, argv0, clt::kDefaultConfigPath);
}

}  // namespace

int main(int argc, char** argv) {
    std::string config_path = clt::kDefaultConfigPath;
    int verbosity = 0;
    bool syslog_style = false;

    static const option longopts[] = {
        {"config", required_argument, nullptr, 'c'},
        {"verbose", no_argument, nullptr, 'v'},
        {"syslog", no_argument, nullptr, 's'},
        {"version", no_argument, nullptr, 'V'},
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "c:vsVh", longopts, nullptr)) != -1) {
        switch (opt) {
            case 'c': config_path = optarg; break;
            case 'v': verbosity++; break;
            case 's': syslog_style = true; break;
            case 'V': printf("%s\n", CORELETD_VERSION); return 0;
            case 'h': usage(argv[0]); return 0;
            default: usage(argv[0]); return 2;
        }
    }

    clt::log_set_syslog_style(syslog_style);

    clt::Config cfg;
    std::string error;
    if (!cfg.load(config_path, error)) {
        // Log level is still at its default here, which is fine: this must be
        // visible regardless of what the (unreadable) config would have said.
        LOG_ERROR("config: %s", error.c_str());
        return 1;
    }
    cfg.finalise();

    // An explicit -v beats the file, so a service can be debugged without
    // editing its config.
    if (verbosity == 1) cfg.log_level = clt::LogLevel::Debug;
    if (verbosity >= 2) cfg.log_level = clt::LogLevel::Trace;
    clt::log_set_level(cfg.log_level);

    clt::App app(std::move(cfg));

    struct sigaction sa {};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    // A dead companion socket must not kill the daemon.
    signal(SIGPIPE, SIG_IGN);

    if (!app.start()) return 1;

    // Delivering a signal interrupts poll(); the loop then asks this predicate
    // whether it should exit. The handler itself only touches a sig_atomic_t.
    app.loop().set_interrupt_check([] { return g_stop != 0; });

    app.run();
    app.request_stop();
    return 0;
}
