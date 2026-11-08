#pragma once

#include <cstddef>
#include <filesystem>

#include "reassembly_fixtures.hpp"

namespace miniips::test {
// With max-flows=1 and tcp-stream-bytes=16 this covers all seven A5 kinds.
inline void write_jsonl_fixture(const std::filesystem::path& path) {
    write_pcap(
        path,
        {record_at(tcp_segment({.sequence = 99, .flags = 0x02}), 1),
         record_at(tcp_segment({.sequence = 103, .payload = "LO"}), 2),
         record_at(tcp_segment({.sequence = 100, .payload = "HEL"}), 3),
         record_at(tcp_segment({.sequence = 100, .payload = "HEL"}), 4),
         record_at(tcp_segment({.sequence = 500, .payload = "SAFE", .backward = true}), 5),
         record_at(tcp_segment({.sequence = 100, .payload = "XXX"}), 6),
         record_at(tcp_segment({.sequence = 200, .payload = "Z"}), 7), record_at(udp_packet(), 8),
         record_at({std::byte{0}}, 200), record_at(udp_packet(), 201)});
}
}  // namespace miniips::test
