#include <cstddef>
#include <exception>
#include <filesystem>
#include <iostream>

#include "fixtures/packet_fixtures.hpp"
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
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
