#include "miniips/nfqueue_source.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <poll.h>
#include <sys/socket.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <exception>
#include <span>
#include <stdexcept>

namespace miniips {
namespace {
struct CloseHandle {
    void operator()(nfq_handle* h) const noexcept { nfq_close(h); }
};
struct CloseQueue {
    void operator()(nfq_q_handle* q) const noexcept { nfq_destroy_queue(q); }
};
bool send_verdict(void* queue, std::uint32_t id, QueueAction action) noexcept {
    return nfq_set_verdict(
               static_cast<nfq_q_handle*>(queue), id,
               static_cast<std::uint32_t>(action == QueueAction::Drop ? NF_DROP : NF_ACCEPT), 0,
               nullptr) >= 0;
}
}  // namespace

struct NfqueueSource::Impl {
    explicit Impl(QueueConfig config) {
        if (!config.enabled || config.queue_num > 65535 || config.max_pending == 0) {
            throw std::invalid_argument(
                "Inline requires explicit enable, queue0..65535 and positive capacity.");
        }
        handle.reset(nfq_open());
        if (!handle) throw std::runtime_error("Cannot open NFQUEUE handle.");
        if (nfq_bind_pf(handle.get(), AF_INET) < 0)
            throw std::runtime_error("Cannot bind NFQUEUE IPv4 protocol; check permissions.");
        queue.reset(nfq_create_queue(handle.get(), static_cast<std::uint16_t>(config.queue_num),
                                     callback, this));
        if (!queue)
            throw std::runtime_error("Cannot bind NFQUEUE; check permissions or another listener.");
        if (nfq_set_mode(queue.get(), NFQNL_COPY_PACKET, 65535) < 0 ||
            nfq_set_queue_maxlen(queue.get(), config.max_pending) < 0 ||
            nfq_set_queue_flags(queue.get(), NFQA_CFG_F_FAIL_OPEN, 0) < 0) {
            throw std::runtime_error("Cannot configure NFQUEUE copy/capacity/fail-open policy.");
        }
        fd = nfq_fd(handle.get());
        const int flags = fcntl(fd, F_GETFL, 0);
        if (fd < 0 || flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            throw std::runtime_error("Cannot configure nonblocking NFQUEUE socket.");
        }
    }
    static int callback(nfq_q_handle* q, nfgenmsg*, nfq_data* packet, void* context) noexcept {
        return static_cast<Impl*>(context)->consume(q, packet);
    }
    int consume(nfq_q_handle* q, nfq_data* packet) noexcept {
        ++counters.callbacks;
        const auto* header = nfq_get_msg_packet_hdr(packet);
        if (!header) {
            ++counters.missing_ids;
            fatal = true;
            return 0;
        }
        std::uint32_t network_id{};
        std::memcpy(&network_id, &header->packet_id, sizeof(network_id));
        const auto at = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch());
        VerdictGuard verdict(ntohl(network_id), counters.callbacks, at, {q, send_verdict},
                             counters);
        std::optional<PacketResult> result;
        if (!running || fatal) {
            verdict.submit(QueueAction::Drop, VerdictReason::Shutdown);
        } else {
            try {
                unsigned char* bytes = nullptr;
                const int length = nfq_get_payload(packet, &bytes);
                if (length < 0 || (length != 0 && !bytes)) {
                    ++counters.processing_errors;
                    fatal = true;
                    verdict.submit(QueueAction::Drop, VerdictReason::MissingPayload);
                } else {
                    const auto span = std::as_bytes(
                        std::span<const unsigned char>{bytes, static_cast<std::size_t>(length)});
                    auto inspected =
                        inspect({span, static_cast<std::uint32_t>(length), at, PacketLayer::Ipv4});
                    if (inspected.processing_error) {
                        ++counters.processing_errors;
                        fatal = true;
                    }
                    const auto reason = inspected.processing_error ? VerdictReason::ProcessingError
                                        : inspected.parse_error    ? VerdictReason::ParseAccept
                                                                   : VerdictReason::Decision;
                    verdict.submit(choose_inline_action(inspected), reason);
                    result = std::move(inspected);
                }
            } catch (...) {
                ++counters.processing_errors;
                fatal = true;
                if (!failure) failure = std::current_exception();
                verdict.submit(QueueAction::Drop, VerdictReason::ProcessingError);
            }
        }
        if (!verdict.receipt().sent) fatal = true;
        try {
            if (after) after(result ? &*result : nullptr, verdict.receipt());
        } catch (...) {
            fatal = true;
            if (!failure) failure = std::current_exception();
        }
        // Do not abort the C dispatcher: guard every remaining valid ID in the
        // already-read datagram even after an inspect/send/publication failure.
        return 0;
    }
    QueueInspector inspect;
    QueueAfter after;
    QueueStats counters;
    std::exception_ptr failure;
    std::array<char, 131072> buffer{};
    int fd{-1};
    bool running{}, ran{}, fatal{}, closed{};
    // Constructor unwinding may destroy a queue with pending callbacks too:
    // keep their state alive until both library resources are released.
    std::unique_ptr<nfq_handle, CloseHandle> handle;
    std::unique_ptr<nfq_q_handle, CloseQueue> queue;
};

NfqueueSource::NfqueueSource(QueueConfig config) : impl_(std::make_unique<Impl>(config)) {}
NfqueueSource::~NfqueueSource() { close(); }
QueueStats NfqueueSource::stats() const noexcept { return impl_->counters; }
bool NfqueueSource::close() noexcept {
    if (impl_->closed) return !impl_->fatal && impl_->counters.close_errors == 0;
    impl_->running = false;
    impl_->inspect = {};
    impl_->after = {};
    if (auto* queue = impl_->queue.release()) {
        if (nfq_destroy_queue(queue) < 0) ++impl_->counters.close_errors;
    }
    if (auto* handle = impl_->handle.release()) {
        if (nfq_close(handle) < 0) ++impl_->counters.close_errors;
    }
    impl_->closed = true;
    return !impl_->fatal && impl_->counters.close_errors == 0;
}

LiveStopReason NfqueueSource::run(const QueueInspector& inspect, const QueueAfter& after,
                                  const StopRequest& stop, std::optional<std::uint64_t> limit) {
    if (!inspect || impl_->ran || impl_->closed || (limit && *limit == 0)) {
        throw std::invalid_argument(
            "NFQUEUE requires an inspector and one run with positive limit.");
    }
    impl_->inspect = inspect;
    impl_->after = after;
    impl_->ran = impl_->running = true;
    while (true) {
        if (impl_->failure) std::rethrow_exception(impl_->failure);
        if (impl_->fatal)
            throw std::runtime_error("NFQUEUE processing/verdict failed; no retry was performed.");
        if (stop) {
            if (const auto reason = stop()) {
                impl_->running = false;
                return *reason;
            }
        }
        if (limit && impl_->counters.valid_ids >= *limit) {
            impl_->running = false;
            return LiveStopReason::PacketLimit;
        }
        const auto needed = ::recv(impl_->fd, nullptr, 0, MSG_PEEK | MSG_TRUNC | MSG_DONTWAIT);
        if (needed < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            pollfd descriptor{impl_->fd, POLLIN, 0};
            const timespec timeout{0, 100000000};
            const int ready = ::ppoll(&descriptor, 1, &timeout, nullptr);
            if (ready < 0 && errno != EINTR) {
                ++impl_->counters.receive_errors;
                throw std::runtime_error("Cannot wait for NFQUEUE socket.");
            }
            if (ready > 0 && (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                ++impl_->counters.receive_errors;
                if ((descriptor.revents & POLLERR) != 0) {
                    int socket_error = 0;
                    socklen_t length = sizeof(socket_error);
                    if (::getsockopt(impl_->fd, SOL_SOCKET, SO_ERROR, &socket_error, &length) ==
                            0 &&
                        socket_error == ENOBUFS) {
                        ++impl_->counters.overflow_errors;
                    }
                }
                throw std::runtime_error("NFQUEUE socket failed.");
            }
            continue;
        }
        if (needed <= 0 || static_cast<std::size_t>(needed) > impl_->buffer.size()) {
            ++impl_->counters.receive_errors;
            impl_->counters.overflow_errors += needed < 0 && errno == ENOBUFS ? 1U : 0U;
            throw std::runtime_error("NFQUEUE receive failed or datagram exceeds bounded buffer.");
        }
        sockaddr_nl sender{};
        iovec payload{impl_->buffer.data(), impl_->buffer.size()};
        msghdr message{};
        message.msg_name = &sender;
        message.msg_namelen = sizeof(sender);
        message.msg_iov = &payload;
        message.msg_iovlen = 1;
        const auto count = ::recvmsg(impl_->fd, &message, MSG_DONTWAIT);
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
        if (count <= 0 || (message.msg_flags & MSG_TRUNC) != 0 || sender.nl_family != AF_NETLINK ||
            sender.nl_pid != 0) {
            ++impl_->counters.receive_errors;
            impl_->counters.overflow_errors += count < 0 && errno == ENOBUFS ? 1U : 0U;
            throw std::runtime_error("Invalid NFQUEUE netlink datagram.");
        }
        if (nfq_handle_packet(impl_->handle.get(), impl_->buffer.data(), static_cast<int>(count)) <
            0) {
            ++impl_->counters.receive_errors;
            throw std::runtime_error("Cannot dispatch NFQUEUE datagram.");
        }
    }
}
}  // namespace miniips
