#pragma once

#include "PatchCore.h"

#include <cstdint>
#include <string>
#include <vector>

namespace omsi_patch {

struct ManifestPatch {
    std::string id;
    std::string title;
    std::wstring target;
    std::vector<std::string> allowedSha256;
    uint32_t peTimeDateStamp = 0;
    uint32_t peSizeOfImage = 0;
    uint32_t rva = 0;
    PatchRequest request;
    std::string rationale;
    bool reversible = true;
};

struct PatchManifest {
    uint32_t schemaVersion = 0;
    std::vector<ManifestPatch> patches;
};

bool LoadPatchManifest(const std::wstring& path, PatchManifest* manifest, std::string* error);
bool ParsePatchManifest(const std::string& jsonText, PatchManifest* manifest, std::string* error);
bool PreparePatchRequest(
    const ManifestPatch& patch, const PeIdentity& identity, PatchRequest* request, std::string* error);

}  // namespace omsi_patch
