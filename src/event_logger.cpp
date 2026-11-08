#include "miniips/event_logger.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <locale>
#include <sstream>
#include <string>
#include <string_view>

namespace miniips {
namespace {
using Json = nlohmann::json;

std::string ipv4(std::uint32_t ip) {
    return std::to_string((ip >> 24U) & 255U) + "." + std::to_string((ip >> 16U) & 255U) + "." +
           std::to_string((ip >> 8U) & 255U) + "." + std::to_string(ip & 255U);
}

Json timestamp(std::chrono::microseconds time) {
    using namespace std::chrono;
    constexpr auto LIMIT =
        duration_cast<microseconds>(sys_days{year{10000} / January / 1}.time_since_epoch());
    if (time.count() < 0 || time >= LIMIT) {
        return nullptr;
    }
    const sys_time<microseconds> point{time};
    const auto day = floor<days>(point);
    const year_month_day date{day};
    const hh_mm_ss clock{point - day};
    std::ostringstream result;
    result.imbue(std::locale::classic());
    result << std::setfill('0') << std::setw(4) << static_cast<int>(date.year()) << '-'
           << std::setw(2) << static_cast<unsigned int>(date.month()) << '-' << std::setw(2)
           << static_cast<unsigned int>(date.day()) << 'T' << std::setw(2) << clock.hours().count()
           << ':' << std::setw(2) << clock.minutes().count() << ':' << std::setw(2)
           << clock.seconds().count() << '.' << std::setw(6) << clock.subseconds().count() << 'Z';
    return result.str();
}

Json document(const Event& event, std::uint64_t id) {
    const auto type = event_type_name(event.type);
    const auto action = event_action_name(event.action);
    const auto& context = event.context;
    if (type == "unknown" || action == "unknown" || capture_mode_name(context.mode) == "unknown" ||
        !event.fields.is_object() || (context.packet_number && *context.packet_number == 0) ||
        (context.flow_id && *context.flow_id == 0) || (event.sid && *event.sid == 0)) {
        throw std::invalid_argument("Invalid event metadata.");
    }
    Json row{
        {"schema_version", 1},
        {"event_type", type},
        {"event_id", id},
        {"packet_number", context.packet_number ? Json(*context.packet_number) : Json(nullptr)},
        {"timestamp", nullptr},
        {"timestamp_us", nullptr},
        {"timestamp_status", "unknown"},
        {"flow_id", context.flow_id ? Json(*context.flow_id) : Json(nullptr)},
        {"src_ip", nullptr},
        {"src_port", nullptr},
        {"dst_ip", nullptr},
        {"dst_port", nullptr},
        {"protocol", nullptr},
        {"direction", nullptr},
        {"mode", capture_mode_name(context.mode)},
        {"enforced", false},
        {"action", action},
        {"sid", event.sid ? Json(*event.sid) : Json(nullptr)},
        {"message", event.message.substr(0, 4096)},
        {"message_truncated", event.message_truncated || event.message.size() > 4096}};
    if (context.captured_at) {
        row["timestamp_us"] = context.captured_at->count();
        row["timestamp"] = timestamp(*context.captured_at);
        row["timestamp_status"] = row["timestamp"].is_null() ? "out_of_range" : "capture";
    }
    if (context.source) {
        row["src_ip"] = ipv4(context.source->ip);
        row["src_port"] = context.source->port;
    }
    if (context.destination) {
        row["dst_ip"] = ipv4(context.destination->ip);
        row["dst_port"] = context.destination->port;
    }
    if (context.protocol) {
        if (*context.protocol != TransportProtocol::Tcp &&
            *context.protocol != TransportProtocol::Udp) {
            throw std::invalid_argument("Unknown event protocol.");
        }
        row["protocol"] = *context.protocol == TransportProtocol::Tcp ? "tcp" : "udp";
    }
    if (context.direction) {
        if (*context.direction != FlowDirection::Forward &&
            *context.direction != FlowDirection::Backward) {
            throw std::invalid_argument("Unknown event direction.");
        }
        row["direction"] = *context.direction == FlowDirection::Forward ? "fwd" : "bwd";
    }
    for (const auto& [key, value] : event.fields.items()) {
        if (row.contains(key)) {
            throw std::invalid_argument("Reserved event key override.");
        }
        row[key] = value;
    }
    return row;
}

std::string line_for(const Event& event, std::uint64_t id) {
    const auto encoded = document(event, id).dump(-1, ' ', true, Json::error_handler_t::replace);
    std::string line;
    line.reserve(encoded.size() + 1);
    for (const char byte : encoded) {
        if (byte == '\x7f') {
            line += "\\u007f";
        } else {
            line += byte;
        }
    }
    line += '\n';
    return line;
}

}  // namespace

std::string_view event_type_name(EventType type) noexcept {
    constexpr std::array<std::string_view, 7> NAMES{
        "alert", "verdict", "flow", "parse_error", "reassembly_warning", "stats", "engine_error"};
    const auto index = static_cast<std::size_t>(type);
    return index < NAMES.size() ? NAMES[index] : "unknown";
}

std::string_view event_action_name(EventAction action) noexcept {
    constexpr std::array<std::string_view, 8> NAMES{"alert", "drop",    "pass",  "allow",
                                                    "skip",  "observe", "error", "none"};
    const auto index = static_cast<std::size_t>(action);
    return index < NAMES.size() ? NAMES[index] : "unknown";
}

EventLogger::EventLogger(std::ostream& output, LoggerConfig config)
    : output_(&output), config_(config) {
    if (config_.max_line_bytes == 0) {
        throw std::invalid_argument("Log line limit must be positive.");
    }
}

EventLogger::EventLogger(const std::filesystem::path& path, LoggerConfig config) : config_(config) {
    if (config_.max_line_bytes == 0) {
        throw std::invalid_argument("Log line limit must be positive.");
    }
    fd_ = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd_ < 0) {
        throw LogOpenError(
            "Cannot create new JSONL file; it may exist or its parent is unavailable.");
    }
}

EventLogger::~EventLogger() { finish(); }

bool EventLogger::begin_event() noexcept {
    if (stats_.attempted == std::numeric_limits<std::uint64_t>::max()) {
        stats_.failed = true;
        return false;
    }
    ++stats_.attempted;
    if (stats_.failed) {
        ++stats_.dropped;
        return false;
    }
    if (stats_.finished) {
        fail_event(false);
        return false;
    }
    return true;
}

void EventLogger::fail_event(bool io) noexcept {
    ++stats_.failed_events;
    stats_.io_errors += io ? 1U : 0U;
    stats_.failed = true;
}

void EventLogger::reject_event() noexcept {
    if (begin_event()) {
        fail_event(false);
    }
}

bool EventLogger::write(const Event& event) noexcept {
    if (!begin_event()) {
        return false;
    }
    std::string line;
    try {
        line = line_for(event, stats_.attempted);
        if (line.size() > config_.max_line_bytes) {
            fail_event(false);
            return false;
        }
    } catch (...) {
        fail_event(false);
        return false;
    }
    try {
        if (output_) {
            output_->write(line.data(), static_cast<std::streamsize>(line.size()));
            if (!*output_) {
                fail_event(true);
                return false;
            }
        } else {
            std::size_t offset = 0;
            unsigned int interruptions = 0;
            while (offset < line.size()) {
                const auto count = ::write(fd_, line.data() + offset, line.size() - offset);
                if (count < 0 && errno == EINTR && ++interruptions <= 16) {
                    continue;
                }
                if (count <= 0) {
                    fail_event(true);
                    return false;
                }
                interruptions = 0;
                offset += static_cast<std::size_t>(count);
            }
        }
    } catch (...) {
        fail_event(true);
        return false;
    }
    ++stats_.written;
    stats_.alert_written += event.type == EventType::Alert ? 1U : 0U;
    return true;
}

bool EventLogger::finish() noexcept {
    if (stats_.finished) {
        return !stats_.failed;
    }
    stats_.finished = true;
    try {
        if (output_ && !stats_.failed) {
            output_->flush();
            if (!*output_) {
                ++stats_.io_errors;
                stats_.failed = true;
            }
        }
    } catch (...) {
        ++stats_.io_errors;
        stats_.failed = true;
    }
    if (fd_ >= 0) {
        const int owned = fd_;
        fd_ = -1;
        if (::close(owned) != 0) {
            ++stats_.io_errors;
            stats_.failed = true;
        }
    }
    return !stats_.failed;
}

LoggerStats EventLogger::stats() const noexcept { return stats_; }
bool EventLogger::failed() const noexcept { return stats_.failed; }

}  // namespace miniips
