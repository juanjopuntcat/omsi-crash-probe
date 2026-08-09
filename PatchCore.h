#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace omsi_patch {

struct PeIdentity {
    uint16_t machine = 0;
    uint16_t characteristics = 0;
    uint32_t timeDateStamp = 0;
    uint32_t sizeOfImage = 0;
    uint64_t fileSize = 0;
    std::string sha256;

    bool IsLargeAddressAware() const;
};

struct PeSection {
    std::string name;
    uint32_t virtualAddress = 0;
    uint32_t virtualSize = 0;
    uint32_t rawOffset = 0;
    uint32_t rawSize = 0;
};

struct PeImage {
    PeIdentity identity;
    std::vector<PeSection> sections;
    std::vector<uint8_t> bytes;
};

bool LoadPeImage(const std::wstring& path, PeImage* image, std::string* error);
bool ParsePeImage(const std::vector<uint8_t>& bytes, PeImage* image, std::string* error);
bool RvaToFileOffset(const PeImage& image, uint32_t rva, uint32_t* offset);
bool BytesMatch(const PeImage& image, uint32_t fileOffset, const std::vector<uint8_t>& expected);

}  // namespace omsi_patch
