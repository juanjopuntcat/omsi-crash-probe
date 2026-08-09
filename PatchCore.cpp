#include "PatchCore.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cstring>
#include <cstdio>
#include <limits>
#include <utility>

#pragma comment(lib, "bcrypt.lib")

namespace omsi_patch {
namespace {

template <typename T>
bool ReadValue(const std::vector<uint8_t>& bytes, size_t offset, T* value) {
    if (value == nullptr || offset > bytes.size() || sizeof(T) > bytes.size() - offset) {
        return false;
    }
    memcpy(value, bytes.data() + offset, sizeof(T));
    return true;
}

void SetError(std::string* error, const char* message) {
    if (error != nullptr) {
        *error = message;
    }
}

std::string Hex(const uint8_t* bytes, size_t count) {
    static const char digits[] = "0123456789ABCDEF";
    std::string result(count * 2, '0');
    for (size_t i = 0; i < count; ++i) {
        result[i * 2] = digits[bytes[i] >> 4];
        result[i * 2 + 1] = digits[bytes[i] & 0x0F];
    }
    return result;
}

bool Sha256(const std::vector<uint8_t>& bytes, std::string* digest, std::string* error) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objectSize = 0;
    DWORD hashSize = 0;
    DWORD returned = 0;
    std::vector<uint8_t> object;
    std::vector<uint8_t> output;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status >= 0) {
        status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &returned, 0);
    }
    if (status >= 0) {
        status = BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hashSize), sizeof(hashSize), &returned, 0);
    }
    if (status >= 0) {
        object.resize(objectSize);
        output.resize(hashSize);
        status = BCryptCreateHash(algorithm, &hash, object.data(), objectSize, nullptr, 0, 0);
    }
    if (status >= 0 && bytes.size() > static_cast<size_t>(std::numeric_limits<ULONG>::max())) {
        status = static_cast<NTSTATUS>(0xC000000DL);
    }
    if (status >= 0) {
        status = BCryptHashData(hash, const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0);
    }
    if (status >= 0) {
        status = BCryptFinishHash(hash, output.data(), hashSize, 0);
    }
    if (hash != nullptr) BCryptDestroyHash(hash);
    if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) {
        SetError(error, "Windows BCrypt could not calculate SHA-256");
        return false;
    }
    *digest = Hex(output.data(), output.size());
    return true;
}

bool IsPatchIdValid(const std::string& id) {
    if (id.empty() || id.size() > 80) return false;
    return std::all_of(id.begin(), id.end(), [](unsigned char character) {
        return (character >= 'a' && character <= 'z') ||
            (character >= 'A' && character <= 'Z') ||
            (character >= '0' && character <= '9') || character == '-' || character == '_';
    });
}

bool EqualAsciiInsensitive(const std::string& left, const std::string& right) {
    if (left.size() != right.size()) return false;
    for (size_t i = 0; i < left.size(); ++i) {
        char a = left[i];
        char b = right[i];
        if (a >= 'a' && a <= 'z') a = static_cast<char>(a - 'a' + 'A');
        if (b >= 'a' && b <= 'z') b = static_cast<char>(b - 'a' + 'A');
        if (a != b) return false;
    }
    return true;
}

bool ValidateRequest(const PatchRequest& request, std::string* error) {
    if (!IsPatchIdValid(request.id)) {
        SetError(error, "Patch ID must contain only letters, digits, hyphens, or underscores");
        return false;
    }
    if (request.allowedOriginalSha256.size() != 64) {
        SetError(error, "Patch requires one complete original SHA-256");
        return false;
    }
    if (request.expectedBytes.empty() || request.expectedBytes.size() != request.replacementBytes.size()) {
        SetError(error, "Patch byte sequences must be non-empty and preserve length");
        return false;
    }
    return true;
}

bool ValidateOriginal(const PeImage& image, const PatchRequest& request, std::string* error) {
    if (!EqualAsciiInsensitive(image.identity.sha256, request.allowedOriginalSha256)) {
        SetError(error, "Target SHA-256 is not the approved original");
        return false;
    }
    if (!BytesMatch(image, request.fileOffset, request.expectedBytes)) {
        SetError(error, "Target bytes do not match the approved original sequence");
        return false;
    }
    return true;
}

bool WriteTemporaryAndReplace(
        const std::wstring& targetPath,
        const std::vector<uint8_t>& bytes,
        std::string* error) {
    const std::wstring temporary = targetPath + L".omsicrashprobe.tmp";
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        SetError(error, "Could not create a new temporary patch file");
        return false;
    }
    DWORD written = 0;
    const bool wrote = bytes.size() <= MAXDWORD &&
        WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) != FALSE &&
        written == bytes.size() && FlushFileBuffers(file) != FALSE;
    CloseHandle(file);
    if (!wrote) {
        DeleteFileW(temporary.c_str());
        SetError(error, "Could not write the complete temporary patch file");
        return false;
    }
    if (!MoveFileExW(temporary.c_str(), targetPath.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temporary.c_str());
        SetError(error, "Could not atomically replace the target file");
        return false;
    }
    return true;
}

}  // namespace

bool PeIdentity::IsLargeAddressAware() const {
    return (characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0;
}

bool LoadPeImage(const std::wstring& path, PeImage* image, std::string* error) {
    if (image == nullptr) {
        SetError(error, "Output image is null");
        return false;
    }
    FILE* file = nullptr;
    if (_wfopen_s(&file, path.c_str(), L"rb") != 0 || file == nullptr) {
        SetError(error, "Could not open PE file");
        return false;
    }
    _fseeki64(file, 0, SEEK_END);
    const __int64 length = _ftelli64(file);
    _fseeki64(file, 0, SEEK_SET);
    if (length < 0 || static_cast<uint64_t>(length) > std::numeric_limits<size_t>::max()) {
        fclose(file);
        SetError(error, "PE file size is unsupported");
        return false;
    }
    std::vector<uint8_t> bytes(static_cast<size_t>(length));
    const size_t read = bytes.empty() ? 0 : fread(bytes.data(), 1, bytes.size(), file);
    fclose(file);
    if (read != bytes.size()) {
        SetError(error, "Could not read complete PE file");
        return false;
    }
    if (!ParsePeImage(bytes, image, error)) {
        return false;
    }
    return Sha256(image->bytes, &image->identity.sha256, error);
}

bool ParsePeImage(const std::vector<uint8_t>& bytes, PeImage* image, std::string* error) {
    if (image == nullptr) {
        SetError(error, "Output image is null");
        return false;
    }
    uint16_t mz = 0;
    uint32_t peOffset = 0;
    if (!ReadValue(bytes, 0, &mz) || mz != IMAGE_DOS_SIGNATURE ||
        !ReadValue(bytes, 0x3C, &peOffset)) {
        SetError(error, "Missing DOS header");
        return false;
    }
    uint32_t signature = 0;
    if (!ReadValue(bytes, peOffset, &signature) || signature != IMAGE_NT_SIGNATURE) {
        SetError(error, "Missing PE signature");
        return false;
    }
    const size_t fileHeader = static_cast<size_t>(peOffset) + sizeof(uint32_t);
    uint16_t sectionCount = 0;
    uint16_t optionalSize = 0;
    PeImage parsed;
    if (!ReadValue(bytes, fileHeader, &parsed.identity.machine) ||
        !ReadValue(bytes, fileHeader + 2, &sectionCount) ||
        !ReadValue(bytes, fileHeader + 4, &parsed.identity.timeDateStamp) ||
        !ReadValue(bytes, fileHeader + 16, &optionalSize) ||
        !ReadValue(bytes, fileHeader + 18, &parsed.identity.characteristics)) {
        SetError(error, "Truncated PE file header");
        return false;
    }
    const size_t optionalHeader = fileHeader + 20;
    uint16_t magic = 0;
    if (optionalSize < 60 || !ReadValue(bytes, optionalHeader, &magic) ||
        magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
        !ReadValue(bytes, optionalHeader + 56, &parsed.identity.sizeOfImage)) {
        SetError(error, "Expected a complete 32-bit PE optional header");
        return false;
    }
    const size_t sectionTable = optionalHeader + optionalSize;
    if (sectionCount > 96 || sectionTable > bytes.size() ||
        static_cast<size_t>(sectionCount) * 40 > bytes.size() - sectionTable) {
        SetError(error, "Invalid PE section table");
        return false;
    }
    parsed.sections.reserve(sectionCount);
    for (uint16_t i = 0; i < sectionCount; ++i) {
        const size_t offset = sectionTable + static_cast<size_t>(i) * 40;
        PeSection section;
        const char* name = reinterpret_cast<const char*>(bytes.data() + offset);
        section.name.assign(name, std::find(name, name + 8, '\0'));
        ReadValue(bytes, offset + 8, &section.virtualSize);
        ReadValue(bytes, offset + 12, &section.virtualAddress);
        ReadValue(bytes, offset + 16, &section.rawSize);
        ReadValue(bytes, offset + 20, &section.rawOffset);
        if (section.rawOffset > bytes.size() || section.rawSize > bytes.size() - section.rawOffset) {
            SetError(error, "PE section raw data is outside the file");
            return false;
        }
        parsed.sections.push_back(section);
    }
    parsed.identity.fileSize = bytes.size();
    parsed.bytes = bytes;
    *image = std::move(parsed);
    return true;
}

bool RvaToFileOffset(const PeImage& image, uint32_t rva, uint32_t* offset) {
    if (offset == nullptr) return false;
    for (const PeSection& section : image.sections) {
        const uint64_t span = (std::max)(section.virtualSize, section.rawSize);
        if (rva >= section.virtualAddress && static_cast<uint64_t>(rva) < section.virtualAddress + span) {
            const uint64_t delta = rva - section.virtualAddress;
            const uint64_t raw = section.rawOffset + delta;
            if (delta >= section.rawSize || raw >= image.bytes.size()) return false;
            *offset = static_cast<uint32_t>(raw);
            return true;
        }
    }
    return false;
}

bool BytesMatch(const PeImage& image, uint32_t fileOffset, const std::vector<uint8_t>& expected) {
    if (fileOffset > image.bytes.size() || expected.size() > image.bytes.size() - fileOffset) return false;
    return std::equal(expected.begin(), expected.end(), image.bytes.begin() + fileOffset);
}

std::wstring BackupPath(const std::wstring& targetPath, const std::string& patchId) {
    std::wstring wideId(patchId.begin(), patchId.end());
    return targetPath + L".omsicrashprobe-" + wideId + L".bak";
}

bool AuditPatch(const std::wstring& targetPath, const PatchRequest& request, std::string* error) {
    if (!ValidateRequest(request, error)) return false;
    PeImage image;
    return LoadPeImage(targetPath, &image, error) && ValidateOriginal(image, request, error);
}

bool ApplyPatch(const std::wstring& targetPath, const PatchRequest& request, std::string* error) {
    if (!ValidateRequest(request, error)) return false;
    PeImage image;
    if (!LoadPeImage(targetPath, &image, error) || !ValidateOriginal(image, request, error)) return false;
    const std::wstring backup = BackupPath(targetPath, request.id);
    if (!CopyFileW(targetPath.c_str(), backup.c_str(), TRUE)) {
        SetError(error, "Could not create a new patch-specific backup");
        return false;
    }
    PeImage backupImage;
    if (!LoadPeImage(backup, &backupImage, error) || !ValidateOriginal(backupImage, request, error)) {
        DeleteFileW(backup.c_str());
        SetError(error, "New backup does not match the approved original");
        return false;
    }
    std::copy(request.replacementBytes.begin(), request.replacementBytes.end(),
        image.bytes.begin() + request.fileOffset);
    if (!WriteTemporaryAndReplace(targetPath, image.bytes, error)) {
        CopyFileW(backup.c_str(), targetPath.c_str(), FALSE);
        return false;
    }
    return true;
}

bool RollbackPatch(const std::wstring& targetPath, const PatchRequest& request, std::string* error) {
    if (!ValidateRequest(request, error)) return false;
    const std::wstring backup = BackupPath(targetPath, request.id);
    PeImage backupImage;
    if (!LoadPeImage(backup, &backupImage, error)) {
        SetError(error, "Patch backup is missing or invalid");
        return false;
    }
    if (!ValidateOriginal(backupImage, request, error)) {
        SetError(error, "Patch backup is not the approved original");
        return false;
    }
    return WriteTemporaryAndReplace(targetPath, backupImage.bytes, error);
}

}  // namespace omsi_patch
