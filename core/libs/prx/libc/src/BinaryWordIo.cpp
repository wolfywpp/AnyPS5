#include "prx/libc/include/Api.hpp"
#include "prx/libc/include/FileStream.hpp"
#include "prx/libc/include/General.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"
#include <array>
#include <bit>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>

static_assert(sizeof(int) == 4 && std::endian::native == std::endian::little);

namespace {

class LockedStream {
    FileStream* stream;

public:
    explicit LockedStream(FileStream* value) : stream(value) { flockfile_nid_postfix(stream); }
    ~LockedStream() { funlockfile_nid_postfix(stream); }
};

bool StreamIsOpen(const FileStream* stream) {
    const int savedErrno = errno;
    std::array<std::byte, sizeof(FileStream)> snapshot{};
    const bool copied = GuestCopyIn_nid_no_patch(snapshot.data(), stream, snapshot.size());
    errno = savedErrno;
    if (!copied) throw std::invalid_argument("putw: unreadable stream");
    std::FILE* handle = nullptr;
    std::memcpy(&handle, snapshot.data() + 256, sizeof(handle));
    return handle != nullptr;
}

}

extern "C" int APS5_VABI getw_nid_postfix(FileStream* stream) {
    int value = 0;
    if (fread_nid_postfix(&value, sizeof(value), 1, stream) != 1) return -1;
    return value;
}

extern "C" int APS5_VABI putw_nid_postfix(int value, FileStream* stream) {
    if (stream && !StreamIsOpen(stream)) { errno = 9; return -1; }
    const LockedStream lock(stream);
    const auto bits = static_cast<std::uint32_t>(value);
    for (unsigned shift = 0; shift < 32; shift += 8)
        if (putc_unlocked_nid_postfix((bits >> shift) & 0xff, stream) == -1) return -1;
    return 0;
}
