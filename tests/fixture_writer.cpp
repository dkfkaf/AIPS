#include <cstddef>
#include <exception>
#include <filesystem>
#include <iostream>

#include "fixtures/flow_fixtures.hpp"
#include "fixtures/reassembly_fixtures.hpp"
#include "pcap_fixture.hpp"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        return 2;
    }
    try {
        const std::filesystem::path directory{argv[1]};
        std::filesystem::create_directories(directory);
        using miniips::test::record;
        using miniips::test::tcp_packet;
        using miniips::test::udp_packet;
        using miniips::test::write_pcap;
        write_pcap(directory / "normal.pcap", {record(tcp_packet()), record(udp_packet())});
        write_pcap(directory / "mixed.pcap",
                   {record({std::byte{1}, std::byte{2}}), record(udp_packet())});
        write_pcap(directory / "empty.pcap", {});
        write_pcap(directory / "unsupported.pcap", {record(tcp_packet())}, 101);
        const auto truncated = directory / "truncated.pcap";
        write_pcap(truncated, {record(tcp_packet())});
        std::filesystem::resize_file(truncated, std::filesystem::file_size(truncated) - 1);
        using miniips::test::record_at;
        using miniips::test::reverse_tcp_packet;
        write_pcap(directory / "flow_bidirectional.pcap",
                   {record_at(tcp_packet(), 1), record_at(reverse_tcp_packet(), 2),
                    record_at(tcp_packet(), 3)});
        write_pcap(directory / "flow_expired.pcap",
                   {record_at(tcp_packet(), 1), record_at(reverse_tcp_packet(), 2),
                    record_at(tcp_packet(), 122)});
        write_pcap(directory / "flow_capacity.pcap",
                   {record_at(tcp_packet(), 1), record_at(udp_packet(), 2),
                    record_at(reverse_tcp_packet(), 3)});
        using miniips::test::tcp_segment;
        write_pcap(directory / "reassembly_hello.pcap",
                   {record_at(tcp_segment({.sequence = 99, .flags = 0x02}), 1),
                    record_at(tcp_segment({.sequence = 103, .payload = "LO"}), 2),
                    record_at(tcp_segment({.sequence = 100, .payload = "HEL"}), 3),
                    record_at(tcp_segment({.sequence = 105, .flags = 0x11}), 4)});
        write_pcap(directory / "reassembly_gap.pcap",
                   {record_at(tcp_segment({.sequence = 99, .flags = 0x02}), 1),
                    record_at(tcp_segment({.sequence = 103, .payload = "LO"}), 2)});
        write_pcap(directory / "reassembly_reset.pcap",
                   {record_at(tcp_segment({.sequence = 99, .flags = 0x02}), 1),
                    record_at(tcp_segment({.sequence = 100, .payload = "A", .flags = 0x11}), 2),
                    record_at(tcp_segment({.sequence = 102, .flags = 0x04}), 3)});
        write_pcap(
            directory / "reassembly_ambiguous_fin.pcap",
            {record_at(tcp_segment({.sequence = 0xffffffffU, .flags = 0x02}), 1),
             record_at(tcp_segment({.sequence = 0x7fffffffU, .payload = "X", .flags = 0x11}), 2),
             record_at(tcp_segment({.sequence = 0, .flags = 0x11}), 3)});
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
