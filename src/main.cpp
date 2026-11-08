#include <csignal>
#include <iostream>
#include <string_view>
#include <vector>

#include "miniips/cli.hpp"

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

    return miniips::run_cli(arguments, std::cout, std::cerr);
}
