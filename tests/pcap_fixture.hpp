#pragma once

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace miniips::test {

struct PcapRecord {
    std::vector<std::byte> bytes;
    std::uint32_t original_length{};
    std::uint32_t seconds{1};
    std::uint32_t fractional{250000};
};

inline PcapRecord record(std::vector<std::byte> bytes) {
    const auto length = static_cast<std::uint32_t>(bytes.size());
    return {std::move(bytes), length, 1, 250000};
}

inline void write_le(std::ostream& output, std::uint32_t value, unsigned int count) {
    for (unsigned int index = 0; index < count; ++index) {
        output.put(std::bit_cast<char>(static_cast<unsigned char>(value & 0xFFU)));
        value >>= 8U;
    }
}

// The capture encoder is independent of the production libpcap reader.
inline void write_pcap(const std::filesystem::path& path, std::initializer_list<PcapRecord> records,
                       std::uint32_t link_type = 1, std::uint32_t magic = 0xA1B2C3D4U,
                       std::uint32_t snapshot_bytes = 65535) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.exceptions(std::ios::failbit | std::ios::badbit);
    write_le(output, magic, 4);
    write_le(output, 2, 2);
    write_le(output, 4, 2);
    write_le(output, 0, 4);
    write_le(output, 0, 4);
    write_le(output, snapshot_bytes, 4);
    write_le(output, link_type, 4);
    for (const auto& item : records) {
        write_le(output, item.seconds, 4);
        write_le(output, item.fractional, 4);
        write_le(output, static_cast<std::uint32_t>(item.bytes.size()), 4);
        write_le(output, item.original_length, 4);
        for (const auto value : item.bytes) {
            output.put(std::bit_cast<char>(value));
        }
    }
    output.close();
}

class TempPcap {
   public:
    TempPcap() {
        const auto pattern =
            (std::filesystem::temp_directory_path() / "miniips-a1-XXXXXX").string();
        std::vector<char> buffer(pattern.begin(), pattern.end());
        buffer.push_back('\0');
        const char* created = ::mkdtemp(buffer.data());
        if (created == nullptr) {
            throw std::runtime_error("Cannot create an isolated PCAP test directory.");
        }
        directory_ = created;
        path_ = directory_ / "fixture.pcap";
    }

    ~TempPcap() {
        std::error_code ignored;
        std::filesystem::remove_all(directory_, ignored);
    }

    TempPcap(const TempPcap&) = delete;
    TempPcap& operator=(const TempPcap&) = delete;

    const std::filesystem::path& path() const { return path_; }

   private:
    std::filesystem::path directory_;
    std::filesystem::path path_;
};

}  // namespace miniips::test
