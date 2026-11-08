#include "miniips/live_pcap_source.hpp"

#include <net/if.h>
#include <pcap/pcap.h>
#include <poll.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <limits>
#include <span>
#include <stdexcept>
#include <utility>

#include "pcap_timestamp.hpp"

namespace miniips {
struct LivePcapSource::Impl {
    explicit Impl(LiveCaptureConfig value) : config(std::move(value)) {
        if (config.interface.empty() || config.interface.size() >= IFNAMSIZ ||
            config.interface.find('\0') != std::string::npos ||
            (config.packet_limit && *config.packet_limit == 0)) {
            throw std::invalid_argument(
                "Live capture requires a valid interface and positive count.");
        }
        char error[PCAP_ERRBUF_SIZE]{};
        capture.reset(pcap_create(config.interface.c_str(), error));
        if (!capture) throw std::runtime_error(std::string{"Cannot create live capture: "} + error);
        const auto check = [&](int status) {
            if (status != 0)
                throw std::runtime_error(std::string{"Cannot configure live capture: "} +
                                         pcap_geterr(capture.get()));
        };
        check(pcap_set_snaplen(capture.get(), detail::MAX_CAPTURE_BYTES));
        check(pcap_set_promisc(capture.get(), 0));
        check(pcap_set_timeout(capture.get(), 100));
        check(pcap_set_immediate_mode(capture.get(), 1));
        const int active = pcap_activate(capture.get());
        if (active < 0)
            throw std::runtime_error(std::string{"Cannot activate live capture: "} +
                                     pcap_geterr(capture.get()));
        if (active > 0) warning = pcap_statustostr(active);
        if (pcap_datalink(capture.get()) != DLT_EN10MB) {
            throw std::runtime_error(
                "Unsupported live link type; Ethernet (DLT_EN10MB) is required.");
        }
        if (pcap_setnonblock(capture.get(), 1, error) != 0) {
            throw std::runtime_error(std::string{"Cannot enable nonblocking capture: "} + error);
        }
        fd = pcap_get_selectable_fd(capture.get());
        if (fd < 0) throw std::runtime_error("Live device has no supported selectable descriptor.");
    }
    LiveCaptureConfig config;
    std::unique_ptr<pcap_t, decltype(&pcap_close)> capture{nullptr, &pcap_close};
    std::string warning;
    int fd{-1};
    bool ran{};
};

LivePcapSource::LivePcapSource(LiveCaptureConfig config)
    : impl_(std::make_unique<Impl>(std::move(config))) {}
LivePcapSource::~LivePcapSource() = default;
const std::string& LivePcapSource::activation_warning() const noexcept { return impl_->warning; }

LiveCaptureResult LivePcapSource::run(const PacketHandler& handler, const StopRequest& stop) {
    if (!handler || impl_->ran)
        throw std::invalid_argument("Live source requires a handler and runs once.");
    impl_->ran = true;
    const auto packet_limit = impl_->config.packet_limit;
    std::uint64_t packets = 0;
    while (true) {
        if (stop) {
            if (const auto reason = stop()) {
                if (live_stop_name(*reason) == "unknown" ||
                    *reason == LiveStopReason::PacketLimit) {
                    throw std::invalid_argument("Invalid external stop request.");
                }
                return {*reason, packets};
            }
        }
        if (packet_limit && packets >= *packet_limit) {
            return {LiveStopReason::PacketLimit, packets};
        }
        pcap_pkthdr* header = nullptr;
        const unsigned char* data = nullptr;
        const int status = pcap_next_ex(impl_->capture.get(), &header, &data);
        if (status == 1) {
            if (!header || (data == nullptr && header->caplen != 0) ||
                header->caplen > static_cast<std::uint32_t>(detail::MAX_CAPTURE_BYTES)) {
                throw std::runtime_error("Invalid live capture record.");
            }
            const auto bytes = std::as_bytes(std::span<const unsigned char>{data, header->caplen});
            handler({bytes, header->len, detail::capture_time(*header), PacketLayer::Ethernet});
            ++packets;
            continue;
        }
        if (status != 0) {
            throw std::runtime_error(std::string{"Live capture stopped unexpectedly: "} +
                                     pcap_geterr(impl_->capture.get()));
        }
        auto wait = std::chrono::microseconds{100000};
        if (const auto* required = pcap_get_required_select_timeout(impl_->capture.get())) {
            if (required->tv_sec < 0 || required->tv_usec < 0 || required->tv_usec >= 1000000) {
                throw std::runtime_error("Invalid libpcap required timeout.");
            }
            if (required->tv_sec == 0)
                wait = std::min(wait, std::chrono::microseconds{required->tv_usec});
        }
        timespec timeout{};
        timeout.tv_nsec = static_cast<long>(wait.count() * 1000);
        pollfd descriptor{impl_->fd, POLLIN, 0};
        const int ready = ::ppoll(&descriptor, 1, &timeout, nullptr);
        if (ready < 0 && errno != EINTR) throw std::runtime_error("Cannot wait for live capture.");
        if (ready > 0 && (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            throw std::runtime_error("Live capture descriptor failed.");
        }
    }
}

CaptureStats LivePcapSource::snapshot_stats() const {
    pcap_stat raw{};
    CaptureStats result;
    result.counter_bits = std::numeric_limits<decltype(raw.ps_recv)>::digits;
    if (pcap_stats(impl_->capture.get(), &raw) != 0) {
        result.error = pcap_geterr(impl_->capture.get());
        if (result.error.size() > 4096) result.error.resize(4096);
        return result;
    }
    result.available = true;
    result.received = raw.ps_recv;
    result.dropped = raw.ps_drop;
    result.interface_dropped = raw.ps_ifdrop;
    return result;
}
}  // namespace miniips
