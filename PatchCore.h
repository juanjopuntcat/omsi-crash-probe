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

struct PatchRequest {
    std::string id;
    std::string allowedOriginalSha256;
    uint32_t fileOffset = 0;
    std::vector<uint8_t> expectedBytes;
    std::vector<uint8_t> replacementBytes;
};

bool LoadPeImage(const std::wstring& path, PeImage* image, std::string* error);
bool ParsePeImage(const std::vector<uint8_t>& bytes, PeImage* image, std::string* error);
bool RvaToFileOffset(const PeImage& image, uint32_t rva, uint32_t* offset);
bool BytesMatch(const PeImage& image, uint32_t fileOffset, const std::vector<uint8_t>& expected);
std::wstring BackupPath(const std::wstring& targetPath, const std::string& patchId);
bool AuditPatch(const std::wstring& targetPath, const PatchRequest& request, std::string* error);
bool ApplyPatch(const std::wstring& targetPath, const PatchRequest& request, std::string* error);
bool RollbackPatch(const std::wstring& targetPath, const PatchRequest& request, std::string* error);

}  // namespace omsi_patch
