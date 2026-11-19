#include "prx/libSceAjm.native/include/Api.hpp"
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace {

void Require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

bool AllZero(const void* data, std::size_t size) {
    const std::uint8_t* bytes = static_cast<const std::uint8_t*>(data);
    for (std::size_t i = 0; i < size; ++i) {
        if (bytes[i] != 0) {
            return false;
        }
    }
    return true;
}

}

int main() {
    AjmBatchInfo info{};
    std::memset(&info, 0xAA, sizeof(info));
    AjmBatchError error{};
    std::memset(&error, 0xAA, sizeof(error));
    Require(sceAjmBatchErrorDump(&info, &error) == 0);
    Require(AllZero(&error, sizeof(error)));

    Require(sceAjmBatchErrorDump(reinterpret_cast<const AjmBatchInfo*>(0x10), nullptr) == 0);
    constexpr int kInvalidParameter = static_cast<int>(0x80930005);
    Require(sceAjmBatchErrorDump(&info, reinterpret_cast<AjmBatchError*>(0x10)) == kInvalidParameter);

    std::array<std::uint8_t, 512> buffer{};
    std::array<std::uint8_t, 16> codecParameters{};
    std::array<std::uint8_t, 8> gaplessDecode{};
    std::array<std::uint8_t, 16> inputData{};
    std::array<std::uint8_t, 16> outputData{};
    std::array<std::uint8_t, 16> sideband{};
    const AjmBuffer inBuf{inputData.data(), inputData.size()};
    const AjmBuffer outBuf{outputData.data(), outputData.size()};
    auto* const unmappedInfo = reinterpret_cast<AjmBatchInfo*>(0x10);
    const auto* const unmappedBuffers = reinterpret_cast<const AjmBuffer*>(0x10);

    Require(sceAjmBatchInitialize(buffer.data(), buffer.size(), &info) == 0);
    errno = 71;
    Require(sceAjmBatchJobInitialize(unmappedInfo, 1, codecParameters.data(), codecParameters.size(), sideband.data()) == kInvalidParameter && errno == 71);
    Require(sceAjmBatchJobInitialize(&info, 1, reinterpret_cast<const void*>(0x10), codecParameters.size(), sideband.data()) == kInvalidParameter && errno == 71);
    Require(sceAjmBatchJobSetGaplessDecode(unmappedInfo, 1, gaplessDecode.data(), 0, sideband.data()) == kInvalidParameter && errno == 71);
    Require(sceAjmBatchJobSetGaplessDecode(&info, 1, reinterpret_cast<const void*>(0x10), 0, sideband.data()) == kInvalidParameter && errno == 71);
    Require(sceAjmBatchJobRunSplit(unmappedInfo, 1, 0, &inBuf, 1, &outBuf, 1, sideband.data(), sideband.size()) == kInvalidParameter && errno == 71);
    Require(sceAjmBatchJobRunSplit(&info, 1, 0, unmappedBuffers, 1, &outBuf, 1, sideband.data(), sideband.size()) == kInvalidParameter && errno == 71);
    Require(sceAjmBatchJobRunSplit(&info, 1, 0, &inBuf, 1, unmappedBuffers, 1, sideband.data(), sideband.size()) == kInvalidParameter && errno == 71);
    Require(info.offset == 0);

    AjmBatchInfo unwritableBufferInfo{reinterpret_cast<void*>(0x10), 0, buffer.size()};
    Require(sceAjmBatchJobInitialize(&unwritableBufferInfo, 1, codecParameters.data(), codecParameters.size(), sideband.data()) == kInvalidParameter && errno == 71);
    Require(unwritableBufferInfo.offset == 0);

    Require(sceAjmBatchJobInitialize(&info, 1, codecParameters.data(), codecParameters.size(), sideband.data()) == 0 && errno == 71);
    const std::size_t afterInit = info.offset;
    Require(afterInit > 0);
    Require(sceAjmBatchJobSetGaplessDecode(&info, 1, gaplessDecode.data(), 1, sideband.data()) == 0 && errno == 71);
    const std::size_t afterGapless = info.offset;
    Require(afterGapless > afterInit);
    Require(sceAjmBatchJobRunSplit(&info, 1, 0, &inBuf, 1, &outBuf, 1, sideband.data(), sideband.size()) == 0 && errno == 71);
    Require(info.offset > afterGapless);
    return 0;
}
