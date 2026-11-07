#include <gtest/gtest.h>

#include <cstddef>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

#include "fixtures/packet_fixtures.hpp"
#include "miniips/capture_source.hpp"
#include "pcap_fixture.hpp"

namespace miniips {
namespace {

TEST(PcapSource, ReadsBothRecordsAndCaptureMetadata) {
    test::TempPcap file;
    test::write_pcap(file.path(),
                     {test::record(test::tcp_packet()), test::record(test::udp_packet())});
    std::vector<std::vector<std::byte>> retained;
    read_pcap(file.path().string(), [&](const PacketEnvelope& packet) {
        EXPECT_EQ(packet.layer, PacketLayer::Ethernet);
        EXPECT_EQ(packet.captured_at.count(), 1250000);
        if (retained.empty()) {
            EXPECT_EQ(packet.original_length, 59);
            EXPECT_EQ(packet.bytes.size(), 59);
        } else {
            EXPECT_EQ(packet.original_length, 45);
            EXPECT_EQ(packet.bytes.size(), 45);
        }
        retained.emplace_back(packet.bytes.begin(), packet.bytes.end());
    });
    ASSERT_EQ(retained.size(), 2);
    EXPECT_EQ(retained[0], test::tcp_packet());
    EXPECT_EQ(retained[1], test::udp_packet());
}

TEST(PcapSource, AcceptsEmptyCapture) {
    test::TempPcap file;
    test::write_pcap(file.path(), {});
    std::size_t count = 0;
    read_pcap(file.path().string(), [&](const PacketEnvelope&) { ++count; });
    EXPECT_EQ(count, 0);
}

TEST(PcapSource, ReportsMissingFile) {
    test::TempPcap file;
    EXPECT_THROW(read_pcap(file.path().string(), [](const PacketEnvelope&) {}), std::runtime_error);
}

TEST(PcapSource, RejectsUnsupportedLinkType) {
    test::TempPcap file;
    test::write_pcap(file.path(), {test::record(test::tcp_packet())}, 101);
    EXPECT_THROW(read_pcap(file.path().string(), [](const PacketEnvelope&) {}), std::runtime_error);
}

TEST(PcapSource, ReportsTruncatedGlobalHeader) {
    test::TempPcap file;
    test::write_pcap(file.path(), {});
    std::filesystem::resize_file(file.path(), 10);
    EXPECT_THROW(read_pcap(file.path().string(), [](const PacketEnvelope&) {}), std::runtime_error);
}

TEST(PcapSource, ReportsTruncatedRecordBody) {
    test::TempPcap file;
    test::write_pcap(file.path(), {test::record(test::tcp_packet())});
    std::filesystem::resize_file(file.path(), std::filesystem::file_size(file.path()) - 1);
    EXPECT_THROW(read_pcap(file.path().string(), [](const PacketEnvelope&) {}), std::runtime_error);
}

TEST(PcapSource, ConvertsNanosecondTimestampsToMicroseconds) {
    test::TempPcap file;
    auto item = test::record(test::tcp_packet());
    item.fractional = 250000000;
    test::write_pcap(file.path(), {item}, 1, 0xA1B23C4DU);
    std::size_t count = 0;
    read_pcap(file.path().string(), [&](const PacketEnvelope& packet) {
        ++count;
        EXPECT_EQ(packet.captured_at.count(), 1250000);
    });
    EXPECT_EQ(count, 1);
}

TEST(PcapSource, RejectsInvalidMicrosecondTimestamp) {
    test::TempPcap file;
    auto item = test::record(test::tcp_packet());
    item.fractional = 1000000;
    test::write_pcap(file.path(), {item});
    EXPECT_THROW(read_pcap(file.path().string(), [](const PacketEnvelope&) {}), std::runtime_error);
}

TEST(PcapSource, PropagatesCallbackExceptionAndCanReopenFile) {
    test::TempPcap file;
    test::write_pcap(file.path(), {test::record(test::tcp_packet())});
    EXPECT_THROW(
        read_pcap(file.path().string(),
                  [](const PacketEnvelope&) { throw std::runtime_error("handler failed"); }),
        std::runtime_error);
    std::size_t count = 0;
    read_pcap(file.path().string(), [&](const PacketEnvelope&) { ++count; });
    EXPECT_EQ(count, 1);
}

TEST(PcapSource, RejectsStdinAndEmptyHandler) {
    EXPECT_THROW(read_pcap("-", [](const PacketEnvelope&) {}), std::invalid_argument);
    EXPECT_THROW(read_pcap("unused.pcap", {}), std::invalid_argument);
    EXPECT_THROW(read_pcap("", [](const PacketEnvelope&) {}), std::invalid_argument);
}

TEST(PcapSource, AcceptsSnapshotAtLimit) {
    test::TempPcap file;
    test::write_pcap(file.path(), {test::record(test::tcp_packet())}, 1, 0xA1B2C3D4U, 262144);
    std::size_t count = 0;
    read_pcap(file.path().string(), [&](const PacketEnvelope&) { ++count; });
    EXPECT_EQ(count, 1);
}

TEST(PcapSource, RejectsSnapshotAboveLimit) {
    test::TempPcap file;
    test::write_pcap(file.path(), {}, 1, 0xA1B2C3D4U, 262145);
    EXPECT_THROW(read_pcap(file.path().string(), [](const PacketEnvelope&) {}), std::runtime_error);
}

TEST(PcapSource, PreservesCapturedAndOriginalLengthsSeparately) {
    test::TempPcap file;
    auto item = test::record(test::tcp_packet());
    item.original_length = 60;
    test::write_pcap(file.path(), {item});
    std::size_t count = 0;
    read_pcap(file.path().string(), [&](const PacketEnvelope& packet) {
        ++count;
        EXPECT_EQ(packet.bytes.size(), 59);
        EXPECT_EQ(packet.original_length, 60);
    });
    EXPECT_EQ(count, 1);
}

}  // namespace
}  // namespace miniips
