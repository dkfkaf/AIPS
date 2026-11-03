#include "miniips/packet_parser.hpp"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>
#include <vector>

#include "fixtures/packet_fixtures.hpp"

namespace miniips {
namespace {

ParseResult parse(const std::vector<std::byte>& bytes) {
    return parse_packet(PacketEnvelope{bytes, static_cast<std::uint32_t>(bytes.size()),
                                       std::chrono::microseconds{1250000}, PacketLayer::Ethernet});
}

void expect_error(const ParseResult& result, ParseError expected) {
    const auto* error = std::get_if<ParseError>(&result);
    ASSERT_NE(error, nullptr);
    EXPECT_EQ(*error, expected);
}

void set_u16(std::vector<std::byte>& bytes, std::size_t offset, std::uint16_t value) {
    bytes.at(offset) = static_cast<std::byte>(value >> 8U);
    bytes.at(offset + 1) = static_cast<std::byte>(value & 0xFFU);
}

TEST(PacketParser, ParsesTcpFieldsAndPayload) {
    const auto bytes = test::tcp_packet();
    const auto result = parse(bytes);
    const auto* packet = std::get_if<ParsedPacket>(&result);
    ASSERT_NE(packet, nullptr);
    EXPECT_EQ(packet->src_ip, 0xC0000201U);
    EXPECT_EQ(packet->dst_ip, 0xC6336402U);
    EXPECT_EQ(packet->src_port, 12345);
    EXPECT_EQ(packet->dst_port, 8080);
    EXPECT_EQ(packet->protocol, TransportProtocol::Tcp);
    EXPECT_EQ(packet->ip_total_length, 45);
    EXPECT_EQ(packet->ip_header_bytes, 20);
    EXPECT_EQ(packet->transport_header_bytes, 20);
    EXPECT_EQ(packet->captured_at.count(), 1250000);
    ASSERT_TRUE(packet->tcp.has_value());
    EXPECT_EQ(packet->tcp->sequence_number, 0x01020304U);
    EXPECT_EQ(packet->tcp->acknowledgement_number, 0x05060708U);
    EXPECT_EQ(packet->tcp->flags, 0x18);
    ASSERT_EQ(packet->payload.size(), 5);
    EXPECT_EQ(packet->payload.data(), bytes.data() + 54);
    EXPECT_EQ(packet->payload[0], std::byte{0x48});
    EXPECT_EQ(packet->payload[4], std::byte{0x4F});
}

TEST(PacketParser, ParsesUdpFieldsAndPayload) {
    const auto bytes = test::udp_packet();
    const auto result = parse(bytes);
    const auto* packet = std::get_if<ParsedPacket>(&result);
    ASSERT_NE(packet, nullptr);
    EXPECT_EQ(packet->src_ip, 0xC0000201U);
    EXPECT_EQ(packet->dst_ip, 0xC6336402U);
    EXPECT_EQ(packet->src_port, 53);
    EXPECT_EQ(packet->dst_port, 54321);
    EXPECT_EQ(packet->protocol, TransportProtocol::Udp);
    EXPECT_EQ(packet->ip_total_length, 31);
    EXPECT_EQ(packet->transport_header_bytes, 8);
    EXPECT_FALSE(packet->tcp.has_value());
    ASSERT_EQ(packet->payload.size(), 3);
    EXPECT_EQ(packet->payload.data(), bytes.data() + 42);
    EXPECT_EQ(packet->payload[0], std::byte{0x44});
}

TEST(PacketParser, RejectsEveryTruncatedTcpPrefix) {
    const auto complete = test::tcp_packet();
    for (std::size_t length = 0; length < complete.size(); ++length) {
        SCOPED_TRACE(length);
        const auto view = std::span<const std::byte>{complete}.first(length);
        const std::vector<std::byte> prefix(view.begin(), view.end());
        EXPECT_TRUE(std::holds_alternative<ParseError>(parse(prefix)));
    }
}

TEST(PacketParser, RejectsEveryTruncatedUdpPrefix) {
    const auto complete = test::udp_packet();
    for (std::size_t length = 0; length < complete.size(); ++length) {
        SCOPED_TRACE(length);
        const auto view = std::span<const std::byte>{complete}.first(length);
        const std::vector<std::byte> prefix(view.begin(), view.end());
        EXPECT_TRUE(std::holds_alternative<ParseError>(parse(prefix)));
    }
}

TEST(PacketParser, RejectsUnsupportedInputLayer) {
    const auto bytes = test::tcp_packet();
    const PacketEnvelope envelope{bytes, 59, {}, static_cast<PacketLayer>(99)};
    expect_error(parse_packet(envelope), ParseError::UnsupportedLinkLayer);
}

TEST(PacketParser, RejectsCaptureLongerThanWireLength) {
    const auto bytes = test::tcp_packet();
    expect_error(parse_packet(PacketEnvelope{bytes, 58}), ParseError::InvalidCaptureLength);
}

TEST(PacketParser, RejectsSnaplenTruncationEvenWhenIpFits) {
    const auto bytes = test::tcp_packet();
    expect_error(parse_packet(PacketEnvelope{bytes, 60}), ParseError::TruncatedCapture);
}

TEST(PacketParser, RejectsShortEthernetAndIpv4Headers) {
    expect_error(parse(std::vector<std::byte>(13)), ParseError::TruncatedEthernet);
    auto bytes = test::tcp_packet();
    bytes.resize(33);
    expect_error(parse(bytes), ParseError::TruncatedIpv4Header);
}

TEST(PacketParser, RejectsIpv6ArpAndVlanEtherTypes) {
    for (const auto type : std::array<std::uint16_t, 3>{0x86DD, 0x0806, 0x8100}) {
        auto bytes = test::tcp_packet();
        set_u16(bytes, 12, type);
        expect_error(parse(bytes), ParseError::UnsupportedEtherType);
    }
}

TEST(PacketParser, RejectsInvalidIpv4Version) {
    auto bytes = test::tcp_packet();
    bytes[14] = std::byte{0x65};
    expect_error(parse(bytes), ParseError::InvalidIpv4Version);
}

TEST(PacketParser, RejectsTooSmallIpv4Ihl) {
    auto bytes = test::tcp_packet();
    bytes[14] = std::byte{0x44};
    expect_error(parse(bytes), ParseError::InvalidIpv4HeaderLength);
}

TEST(PacketParser, RejectsTruncatedIpv4Options) {
    auto bytes = test::tcp_packet();
    bytes[14] = std::byte{0x4F};
    expect_error(parse(bytes), ParseError::TruncatedIpv4Header);
}

TEST(PacketParser, RejectsIpv4TotalLengthSmallerThanHeader) {
    auto bytes = test::tcp_packet();
    for (const auto length : std::array<std::uint16_t, 2>{0, 19}) {
        set_u16(bytes, 16, length);
        expect_error(parse(bytes), ParseError::InvalidIpv4TotalLength);
    }
}

TEST(PacketParser, RejectsIpv4TotalLengthBeyondCapture) {
    auto bytes = test::tcp_packet();
    set_u16(bytes, 16, 65535);
    expect_error(parse(bytes), ParseError::TruncatedIpv4Packet);
}

TEST(PacketParser, RejectsFirstAndLaterFragments) {
    for (const auto fragment : std::array<std::uint16_t, 3>{0x2000, 0x0001, 0x6000}) {
        auto bytes = test::tcp_packet();
        set_u16(bytes, 20, fragment);
        expect_error(parse(bytes), ParseError::Ipv4Fragment);
    }
}

TEST(PacketParser, RejectsReservedIpv4Flag) {
    auto bytes = test::tcp_packet();
    set_u16(bytes, 20, 0x8000);
    expect_error(parse(bytes), ParseError::InvalidIpv4Flags);
}

TEST(PacketParser, RejectsUnsupportedIpProtocol) {
    auto bytes = test::tcp_packet();
    bytes[23] = std::byte{1};
    expect_error(parse(bytes), ParseError::UnsupportedProtocol);
}

TEST(PacketParser, RejectsShortTcpHeader) {
    auto bytes = test::tcp_packet();
    bytes.resize(53);
    set_u16(bytes, 16, 39);
    expect_error(parse(bytes), ParseError::TruncatedTcpHeader);
}

TEST(PacketParser, RejectsInvalidTcpDataOffset) {
    for (const auto offset : {std::byte{0x40}, std::byte{0xF0}}) {
        auto bytes = test::tcp_packet();
        bytes[46] = offset;
        expect_error(parse(bytes), ParseError::InvalidTcpHeaderLength);
    }
}

TEST(PacketParser, RejectsShortUdpHeader) {
    auto bytes = test::udp_packet();
    bytes.resize(41);
    set_u16(bytes, 16, 27);
    expect_error(parse(bytes), ParseError::TruncatedUdpHeader);
}

TEST(PacketParser, RejectsUdpLengthMismatch) {
    for (const auto length : std::array<std::uint16_t, 5>{0, 7, 10, 12, 65535}) {
        auto bytes = test::udp_packet();
        set_u16(bytes, 38, length);
        expect_error(parse(bytes), ParseError::InvalidUdpLength);
    }
}

TEST(PacketParser, SkipsIpv4OptionsBeforeTcp) {
    auto bytes = test::tcp_packet();
    bytes.insert(bytes.begin() + 34, 4, std::byte{1});
    bytes[14] = std::byte{0x46};
    set_u16(bytes, 16, 49);
    const auto result = parse(bytes);
    const auto* packet = std::get_if<ParsedPacket>(&result);
    ASSERT_NE(packet, nullptr);
    EXPECT_EQ(packet->src_port, 12345);
    EXPECT_EQ(packet->ip_header_bytes, 24);
    EXPECT_EQ(packet->payload.size(), 5);
    EXPECT_EQ(packet->payload.data(), bytes.data() + 58);
}

TEST(PacketParser, SkipsTcpOptionsBeforePayload) {
    auto bytes = test::tcp_packet();
    bytes.insert(bytes.begin() + 54, 4, std::byte{1});
    bytes[46] = std::byte{0x60};
    set_u16(bytes, 16, 49);
    const auto result = parse(bytes);
    const auto* packet = std::get_if<ParsedPacket>(&result);
    ASSERT_NE(packet, nullptr);
    EXPECT_EQ(packet->transport_header_bytes, 24);
    EXPECT_EQ(packet->payload.size(), 5);
    EXPECT_EQ(packet->payload.data(), bytes.data() + 58);
}

TEST(PacketParser, ExcludesEthernetPaddingFromPayload) {
    auto bytes = test::tcp_packet();
    bytes.insert(bytes.end(), 20, std::byte{0xFF});
    const auto result = parse(bytes);
    const auto* packet = std::get_if<ParsedPacket>(&result);
    ASSERT_NE(packet, nullptr);
    EXPECT_EQ(packet->ip_total_length, 45);
    EXPECT_EQ(packet->payload.size(), 5);
}

TEST(PacketParser, PreservesBinaryPayloadBytes) {
    auto bytes = test::tcp_packet();
    bytes[54] = std::byte{0};
    bytes[55] = std::byte{0xFF};
    const auto result = parse(bytes);
    const auto* packet = std::get_if<ParsedPacket>(&result);
    ASSERT_NE(packet, nullptr);
    ASSERT_EQ(packet->payload.size(), 5);
    EXPECT_EQ(packet->payload[0], std::byte{0});
    EXPECT_EQ(packet->payload[1], std::byte{0xFF});
}

TEST(PacketParser, AcceptsEmptyTcpPayload) {
    auto bytes = test::tcp_packet();
    bytes.resize(54);
    set_u16(bytes, 16, 40);
    const auto result = parse(bytes);
    const auto* packet = std::get_if<ParsedPacket>(&result);
    ASSERT_NE(packet, nullptr);
    EXPECT_TRUE(packet->payload.empty());
}

TEST(PacketParser, ReportsFragmentReason) {
    EXPECT_EQ(parse_error_name(ParseError::Ipv4Fragment), "ipv4_fragment");
}

}  // namespace
}  // namespace miniips
