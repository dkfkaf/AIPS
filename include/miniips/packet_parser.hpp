#pragma once

#include <string_view>
#include <variant>

#include "miniips/packet.hpp"

namespace miniips {

enum class ParseError {
    UnsupportedLinkLayer,
    InvalidCaptureLength,
    TruncatedCapture,
    TruncatedEthernet,
    UnsupportedEtherType,
    TruncatedIpv4Header,
    InvalidIpv4Version,
    InvalidIpv4HeaderLength,
    InvalidIpv4TotalLength,
    TruncatedIpv4Packet,
    InvalidIpv4Flags,
    Ipv4Fragment,
    UnsupportedProtocol,
    TruncatedTcpHeader,
    InvalidTcpHeaderLength,
    TruncatedUdpHeader,
    InvalidUdpLength
};

using ParseResult = std::variant<ParsedPacket, ParseError>;

// Parses Ethernet/IPv4/TCP or UDP without retaining or copying the input.
// Malformed/unsupported packets produce a reason, never a partial successful packet.
ParseResult parse_packet(const PacketEnvelope& envelope) noexcept;
std::string_view parse_error_name(ParseError error) noexcept;

}  // namespace miniips
