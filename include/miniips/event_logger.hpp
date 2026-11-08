#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <ostream>
#include <stdexcept>

#include "miniips/event.hpp"

namespace miniips {

class LogOpenError : public std::runtime_error {
   public:
    using std::runtime_error::runtime_error;
};
struct LoggerConfig {
    std::size_t max_line_bytes{65536};
};
struct LoggerStats {
    std::uint64_t attempted{};
    std::uint64_t written{};
    std::uint64_t failed_events{};
    std::uint64_t dropped{};
    std::uint64_t io_errors{};
    std::uint64_t alert_written{};
    bool failed{};
    bool finished{};
};

// Single-threaded, no event queue. Borrows streams; exclusively creates files.
// No exception escapes write/finish/reject_event. After failure, no later writes.
class EventLogger {
   public:
    explicit EventLogger(std::ostream& output, LoggerConfig config = {});
    explicit EventLogger(const std::filesystem::path& path, LoggerConfig config = {});
    ~EventLogger();
    EventLogger(const EventLogger&) = delete;
    EventLogger& operator=(const EventLogger&) = delete;
    bool write(const Event& event) noexcept;
    bool finish() noexcept;
    // Count a publisher construction failure, or a skipped event after failure.
    void reject_event() noexcept;
    LoggerStats stats() const noexcept;
    bool failed() const noexcept;

   private:
    bool begin_event() noexcept;
    void fail_event(bool io) noexcept;
    std::ostream* output_{};
    int fd_{-1};
    LoggerConfig config_;
    LoggerStats stats_;
};

}  // namespace miniips
