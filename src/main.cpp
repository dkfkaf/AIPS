#include <signal.h>

#include <csignal>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <vector>

#include "miniips/cli.hpp"

namespace {
volatile std::sig_atomic_t stop_signal = 0;
extern "C" void request_stop(int number) {
    if (stop_signal == 0) stop_signal = number;
}
class LiveSignals {
   public:
    LiveSignals() {
        stop_signal = 0;
        struct sigaction action {};
        action.sa_handler = request_stop;
        sigemptyset(&action.sa_mask);
        sigaddset(&action.sa_mask, SIGINT);
        sigaddset(&action.sa_mask, SIGTERM);
        if (sigaction(SIGINT, &action, &old_int_) != 0) {
            throw std::runtime_error("Cannot install live interrupt handler.");
        }
        if (sigaction(SIGTERM, &action, &old_term_) != 0) {
            sigaction(SIGINT, &old_int_, nullptr);
            throw std::runtime_error("Cannot install live termination handler.");
        }
    }
    ~LiveSignals() {
        sigaction(SIGTERM, &old_term_, nullptr);
        sigaction(SIGINT, &old_int_, nullptr);
    }
    LiveSignals(const LiveSignals&) = delete;
    LiveSignals& operator=(const LiveSignals&) = delete;

   private:
    struct sigaction old_int_ {
    }, old_term_{};
};
}  // namespace

int main(int argc, char* argv[]) {
    std::vector<std::string_view> arguments;
    for (int index = 1; index < argc; ++index) {
        arguments.emplace_back(argv[index]);
    }

    for (std::size_t index = 0; index + 1 < arguments.size(); index += 2) {
        if (arguments[index] == "--log") {
            // Log file limits and a closed JSONL consumer are write failures;
            // retain inspection instead of terminating on the default signal.
            if (std::signal(SIGXFSZ, SIG_IGN) == SIG_ERR ||
                (arguments[index + 1] == "-" && std::signal(SIGPIPE, SIG_IGN) == SIG_ERR)) {
                std::cerr << "log_error: Cannot handle log output signals.\n";
                return 1;
            }
            break;
        }
    }

    try {
        std::optional<LiveSignals> signals;
        miniips::StopRequest stop;
        for (std::size_t index = 0; index + 1 < arguments.size(); index += 2) {
            if (arguments[index] == "--mode" && arguments[index + 1] == "live") {
                signals.emplace();
                stop = []() -> std::optional<miniips::LiveStopReason> {
                    const auto requested = stop_signal;
                    if (requested == SIGINT) return miniips::LiveStopReason::Sigint;
                    if (requested == SIGTERM) return miniips::LiveStopReason::Sigterm;
                    return std::nullopt;
                };
                break;
            }
        }
        return miniips::run_cli(arguments, std::cout, std::cerr, stop);
    } catch (const std::exception& error) {
        std::cerr << "capture_error: " << error.what() << '\n';
        return 1;
    }
}
