#include "PatchCore.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <vector>

namespace {

template <typename T>
void Put(std::vector<uint8_t>* bytes, size_t offset, T value) {
    memcpy(bytes->data() + offset, &value, sizeof(value));
}

std::vector<uint8_t> SyntheticPe() {
    std::vector<uint8_t> bytes(0x600, 0);
    Put<uint16_t>(&bytes, 0, 0x5A4D);
    Put<uint32_t>(&bytes, 0x3C, 0x80);
    Put<uint32_t>(&bytes, 0x80, 0x00004550);
    Put<uint16_t>(&bytes, 0x84, 0x014C);
    Put<uint16_t>(&bytes, 0x86, 1);
    Put<uint32_t>(&bytes, 0x88, 0x12345678);
    Put<uint16_t>(&bytes, 0x94, 0x00E0);
    Put<uint16_t>(&bytes, 0x96, 0x0122);
    Put<uint16_t>(&bytes, 0x98, 0x010B);
    Put<uint32_t>(&bytes, 0xD0, 0x00300000);
    const size_t section = 0x178;
    memcpy(bytes.data() + section, ".text", 5);
    Put<uint32_t>(&bytes, section + 8, 0x300);
    Put<uint32_t>(&bytes, section + 12, 0x1000);
    Put<uint32_t>(&bytes, section + 16, 0x200);
    Put<uint32_t>(&bytes, section + 20, 0x400);
    bytes[0x420] = 0xAA;
    bytes[0x421] = 0xBB;
    return bytes;
}

bool Check(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "FAILED: %s\n", message);
    return condition;
}

}  // namespace

int main() {
    bool ok = true;
    std::string error;
    omsi_patch::PeImage image;
    std::vector<uint8_t> bytes = SyntheticPe();
    ok &= Check(omsi_patch::ParsePeImage(bytes, &image, &error), "valid synthetic PE must parse");
    ok &= Check(image.identity.machine == 0x014C, "machine must be x86");
    ok &= Check(image.identity.timeDateStamp == 0x12345678, "timestamp must parse");
    ok &= Check(image.identity.sizeOfImage == 0x00300000, "image size must parse");
    ok &= Check(image.identity.IsLargeAddressAware(), "LAA characteristic must parse");

    uint32_t offset = 0;
    ok &= Check(omsi_patch::RvaToFileOffset(image, 0x1020, &offset) && offset == 0x420,
        "RVA must map through section raw data");
    ok &= Check(!omsi_patch::RvaToFileOffset(image, 0x1250, &offset),
        "virtual tail without raw bytes must not map");
    ok &= Check(omsi_patch::BytesMatch(image, 0x420, {0xAA, 0xBB}), "expected bytes must match");
    ok &= Check(!omsi_patch::BytesMatch(image, 0x420, {0xAA, 0xBC}), "different bytes must fail");
    ok &= Check(!omsi_patch::BytesMatch(image, 0x5FF, {0, 0}), "out-of-range comparison must fail");

    wchar_t tempDirectory[MAX_PATH] = {};
    wchar_t tempFile[MAX_PATH] = {};
    ok &= Check(GetTempPathW(MAX_PATH, tempDirectory) != 0 &&
        GetTempFileNameW(tempDirectory, L"ocp", 0, tempFile) != 0,
        "temporary PE path must be created");
    FILE* file = nullptr;
    ok &= Check(_wfopen_s(&file, tempFile, L"wb") == 0 && file != nullptr,
        "temporary PE must open for writing");
    if (file != nullptr) {
        ok &= Check(fwrite(image.bytes.data(), 1, image.bytes.size(), file) == image.bytes.size(),
            "complete temporary PE must be written");
        fclose(file);
        omsi_patch::PeImage loaded;
        ok &= Check(omsi_patch::LoadPeImage(tempFile, &loaded, &error),
            "file-backed PE inspection must succeed");
        ok &= Check(loaded.identity.sha256.size() == 64, "SHA-256 must contain 64 hex digits");
        omsi_patch::PatchRequest request;
        request.id = "synthetic-byte-change";
        request.allowedOriginalSha256 = loaded.identity.sha256;
        request.fileOffset = 0x420;
        request.expectedBytes = {0xAA, 0xBB};
        request.replacementBytes = {0x11, 0x22};
        ok &= Check(omsi_patch::AuditPatch(tempFile, request, &error),
            "approved synthetic patch must audit successfully");
        ok &= Check(omsi_patch::ApplyPatch(tempFile, request, &error),
            "approved synthetic patch must apply successfully");
        omsi_patch::PeImage patched;
        ok &= Check(omsi_patch::LoadPeImage(tempFile, &patched, &error) &&
            omsi_patch::BytesMatch(patched, 0x420, {0x11, 0x22}),
            "apply must write replacement bytes");
        ok &= Check(!omsi_patch::ApplyPatch(tempFile, request, &error),
            "already patched target must not apply twice");
        ok &= Check(omsi_patch::RollbackPatch(tempFile, request, &error),
            "approved backup must roll back successfully");
        omsi_patch::PeImage restored;
        ok &= Check(omsi_patch::LoadPeImage(tempFile, &restored, &error) &&
            restored.identity.sha256 == request.allowedOriginalSha256,
            "rollback must restore the exact original hash");
        ok &= Check(!omsi_patch::ApplyPatch(tempFile, request, &error),
            "apply must refuse to overwrite an existing backup");
        DeleteFileW(omsi_patch::BackupPath(tempFile, request.id).c_str());

        omsi_patch::PatchRequest unsafeId = request;
        unsafeId.id = "..\\escape";
        ok &= Check(!omsi_patch::AuditPatch(tempFile, unsafeId, &error),
            "unsafe patch ID must fail validation");
        omsi_patch::PatchRequest wrongBytes = request;
        wrongBytes.expectedBytes = {0x00, 0x00};
        ok &= Check(!omsi_patch::AuditPatch(tempFile, wrongBytes, &error),
            "unexpected original bytes must fail audit");
    }
    DeleteFileW(tempFile);

    std::vector<uint8_t> truncated(32, 0);
    ok &= Check(!omsi_patch::ParsePeImage(truncated, &image, &error), "truncated DOS header must fail");
    bytes = SyntheticPe();
    Put<uint16_t>(&bytes, 0x98, 0x020B);
    ok &= Check(!omsi_patch::ParsePeImage(bytes, &image, &error), "PE32+ image must fail");
    bytes = SyntheticPe();
    Put<uint32_t>(&bytes, 0x178 + 20, 0x580);
    ok &= Check(!omsi_patch::ParsePeImage(bytes, &image, &error), "section beyond file must fail");

    if (!ok) return 1;
    std::puts("All native patch core tests passed.");
    return 0;
}
