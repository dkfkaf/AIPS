#pragma once

#include <iosfwd>
#include <span>
#include <string_view>

#include "miniips/capture_source.hpp"

namespace miniips {

// arguments excludes argv[0]; views must remain valid until this call returns.
// Returns 0 for help/version/completed analysis, 1 for capture/output failure,
// and 2 for invalid arguments. Packet skips are reported separately on stderr.
int run_cli(std::span<const std::string_view> arguments, std::ostream& output, std::ostream& errors,
            const StopRequest& stop = {});

}  // namespace miniips
