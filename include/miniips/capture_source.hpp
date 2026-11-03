#pragma once

#include <functional>
#include <string>

#include "miniips/packet.hpp"

namespace miniips {

using PacketHandler = std::function<void(const PacketEnvelope&)>;

// Reads an offline Ethernet capture to EOF, closing it on every return/exception.
// The handler must consume/copy borrowed bytes before returning.
// Throws on open/read/link-type/timestamp errors; propagates handler exceptions.
// A path of "-" (stdin) is intentionally unsupported.
void read_pcap(const std::string& path, const PacketHandler& on_packet);

}  // namespace miniips
