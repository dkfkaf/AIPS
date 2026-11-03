#include "miniips/capture_source.hpp"

#include <pcap/pcap.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>

namespace miniips {
namespace {

constexpr int MAX_CAPTURE_BYTES = 262144;
constexpr std::int64_t MICROSECONDS_PER_SECOND = 1000000;

std::chrono::microseconds capture_time(const pcap_pkthdr& header) {
    const auto seconds = static_cast<std::int64_t>(header.ts.tv_sec);
    const auto microseconds = static_cast<std::int64_t>(header.ts.tv_usec);
    if (seconds < 0 || microseconds < 0 || microseconds >= MICROSECONDS_PER_SECOND) {
        throw std::runtime_error("Invalid PCAP timestamp.");
    }
    if (seconds > (std::numeric_limits<std::int64_t>::max() - microseconds) /
                      MICROSECONDS_PER_SECOND) {
        throw std::runtime_error("PCAP timestamp overflows microseconds.");
    }
    return std::chrono::microseconds{seconds * MICROSECONDS_PER_SECOND + microseconds};
}

}  // namespace

void read_pcap(const std::string& path, const PacketHandler& on_packet) {
    if (path.empty() || path == "-" || path.find('\0') != std::string::npos || !on_packet) {
        throw std::invalid_argument(
            "A file path and packet handler are required; stdin is unsupported.");
    }

    char error_buffer[PCAP_ERRBUF_SIZE]{};
    using PcapHandle = std::unique_ptr<pcap_t, decltype(&pcap_close)>;
    PcapHandle capture(
        pcap_open_offline_with_tstamp_precision(path.c_str(), PCAP_TSTAMP_PRECISION_MICRO,
                                               error_buffer),
        &pcap_close);
    if (!capture) {
        throw std::runtime_error(std::string{"Cannot open PCAP: "} + error_buffer);
    }
    if (pcap_datalink(capture.get()) != DLT_EN10MB) {
        throw std::runtime_error("Unsupported PCAP link type; Ethernet (DLT_EN10MB) is required.");
    }
    const int snapshot_bytes = pcap_snapshot(capture.get());
    if (snapshot_bytes <= 0 || snapshot_bytes > MAX_CAPTURE_BYTES) {
        throw std::runtime_error("PCAP snapshot length exceeds the supported 262144-byte limit.");
    }

    while (true) {
        pcap_pkthdr* header = nullptr;
        const unsigned char* data = nullptr;
        const int status = pcap_next_ex(capture.get(), &header, &data);
        if (status == PCAP_ERROR_BREAK) {
            return;
        }
        if (status == PCAP_ERROR) {
            throw std::runtime_error(
                std::string{"Cannot read PCAP: "} + pcap_geterr(capture.get()));
        }
        if (status != 1 || header == nullptr || (data == nullptr && header->caplen != 0)) {
            throw std::runtime_error("Unexpected offline PCAP read result.");
        }
        if (header->caplen > static_cast<std::uint32_t>(snapshot_bytes)) {
            throw std::runtime_error("PCAP record exceeds the snapshot length.");
        }
        const auto bytes = std::as_bytes(
            std::span<const unsigned char>{data, static_cast<std::size_t>(header->caplen)});
        on_packet(PacketEnvelope{bytes, header->len, capture_time(*header), PacketLayer::Ethernet});
    }
}

}  // namespace miniips
