#include "PatchManifest.h"

#pragma warning(push, 0)
#include "third_party/nlohmann/json.hpp"
#pragma warning(pop)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <limits>
#include <set>

namespace omsi_patch {
namespace {

using Json = nlohmann::json;

void SetError(std::string* error, const std::string& message) {
    if (error != nullptr) *error = message;
}

bool HasOnlyKeys(const Json& object, const std::set<std::string>& allowed, std::string* error) {
    if (!object.is_object()) {
        SetError(error, "Manifest value must be an object");
        return false;
    }
    for (auto iterator = object.begin(); iterator != object.end(); ++iterator) {
        if (allowed.find(iterator.key()) == allowed.end()) {
            SetError(error, "Unknown manifest key: " + iterator.key());
            return false;
        }
    }
    return true;
}

bool IsSha256(const std::string& text) {
    return text.size() == 64 && std::all_of(text.begin(), text.end(), [](unsigned char character) {
        return (character >= '0' && character <= '9') ||
            (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F');
    });
}

bool ParseHexUint32(const std::string& text, uint32_t* value) {
    if (value == nullptr || text.size() < 3 || text[0] != '0' || (text[1] != 'x' && text[1] != 'X')) return false;
    errno = 0;
    char* end = nullptr;
    const unsigned long parsed = strtoul(text.c_str() + 2, &end, 16);
    if (errno != 0 || end == text.c_str() + 2 || *end != '\0' || parsed > UINT32_MAX) return false;
    *value = static_cast<uint32_t>(parsed);
    return true;
}

bool ParseHexBytes(const std::string& text, std::vector<uint8_t>* bytes) {
    if (bytes == nullptr) return false;
    bytes->clear();
    int high = -1;
    for (unsigned char character : text) {
        if (character == ' ' || character == '\t' || character == '\r' || character == '\n') continue;
        int nibble = -1;
        if (character >= '0' && character <= '9') nibble = character - '0';
        if (character >= 'a' && character <= 'f') nibble = character - 'a' + 10;
        if (character >= 'A' && character <= 'F') nibble = character - 'A' + 10;
        if (nibble < 0) return false;
        if (high < 0) {
            high = nibble;
        } else {
            bytes->push_back(static_cast<uint8_t>((high << 4) | nibble));
            high = -1;
        }
    }
    return high < 0 && !bytes->empty();
}

std::wstring Utf8ToWide(const std::string& text) {
    if (text.empty()) return {};
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (count <= 0) return {};
    std::wstring result(static_cast<size_t>(count), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            text.data(), static_cast<int>(text.size()), result.data(), count) != count) return {};
    return result;
}

bool RequiredString(const Json& object, const char* key, std::string* value, std::string* error) {
    const auto iterator = object.find(key);
    if (iterator == object.end() || !iterator->is_string() || iterator->get_ref<const std::string&>().empty()) {
        SetError(error, std::string("Missing or invalid string: ") + key);
        return false;
    }
    *value = iterator->get<std::string>();
    return true;
}

bool ParseEntry(const Json& object, ManifestPatch* patch, std::string* error) {
    static const std::set<std::string> keys = {
        "id", "title", "target", "allowedSha256", "peTimeDateStamp", "peSizeOfImage",
        "rva", "fileOffset", "expectedBytes", "replacementBytes", "rationale", "reversible"
    };
    if (!HasOnlyKeys(object, keys, error)) return false;
    ManifestPatch parsed;
    std::string target;
    std::string timestamp;
    std::string imageSize;
    std::string rva;
    std::string offset;
    std::string expected;
    std::string replacement;
    if (!RequiredString(object, "id", &parsed.id, error) ||
        !RequiredString(object, "title", &parsed.title, error) ||
        !RequiredString(object, "target", &target, error) ||
        !RequiredString(object, "peTimeDateStamp", &timestamp, error) ||
        !RequiredString(object, "peSizeOfImage", &imageSize, error) ||
        !RequiredString(object, "rva", &rva, error) ||
        !RequiredString(object, "fileOffset", &offset, error) ||
        !RequiredString(object, "expectedBytes", &expected, error) ||
        !RequiredString(object, "replacementBytes", &replacement, error) ||
        !RequiredString(object, "rationale", &parsed.rationale, error)) return false;
    parsed.target = Utf8ToWide(target);
    const std::filesystem::path targetPath(parsed.target);
    const bool traversal = std::any_of(targetPath.begin(), targetPath.end(), [](const auto& part) {
        return part == L"..";
    });
    if (parsed.target.empty() || targetPath.is_absolute() || targetPath.has_root_name() || traversal ||
        !ParseHexUint32(timestamp, &parsed.peTimeDateStamp) ||
        !ParseHexUint32(imageSize, &parsed.peSizeOfImage) || !ParseHexUint32(rva, &parsed.rva) ||
        !ParseHexUint32(offset, &parsed.request.fileOffset) ||
        !ParseHexBytes(expected, &parsed.request.expectedBytes) ||
        !ParseHexBytes(replacement, &parsed.request.replacementBytes)) {
        SetError(error, "Manifest patch contains an invalid target, hex integer, or byte sequence");
        return false;
    }
    const auto hashes = object.find("allowedSha256");
    if (hashes == object.end() || !hashes->is_array() || hashes->empty()) {
        SetError(error, "allowedSha256 must be a non-empty array");
        return false;
    }
    for (const Json& hash : *hashes) {
        if (!hash.is_string() || !IsSha256(hash.get_ref<const std::string&>())) {
            SetError(error, "allowedSha256 contains an invalid hash");
            return false;
        }
        parsed.allowedSha256.push_back(hash.get<std::string>());
    }
    const auto reversible = object.find("reversible");
    if (reversible == object.end() || !reversible->is_boolean()) {
        SetError(error, "reversible must be a boolean");
        return false;
    }
    parsed.reversible = reversible->get<bool>();
    if (!parsed.reversible || parsed.request.expectedBytes.size() != parsed.request.replacementBytes.size()) {
        SetError(error, "Only reversible, same-length patches are supported");
        return false;
    }
    parsed.request.id = parsed.id;
    parsed.request.allowedOriginalSha256 = parsed.allowedSha256.front();
    *patch = std::move(parsed);
    return true;
}

}  // namespace

bool LoadPatchManifest(const std::wstring& path, PatchManifest* manifest, std::string* error) {
    FILE* file = nullptr;
    if (_wfopen_s(&file, path.c_str(), L"rb") != 0 || file == nullptr) {
        SetError(error, "Could not open patch manifest");
        return false;
    }
    _fseeki64(file, 0, SEEK_END);
    const __int64 length = _ftelli64(file);
    _fseeki64(file, 0, SEEK_SET);
    if (length < 0 || length > 4 * 1024 * 1024) {
        fclose(file);
        SetError(error, "Patch manifest exceeds the 4 MiB limit");
        return false;
    }
    std::string text(static_cast<size_t>(length), '\0');
    const size_t read = text.empty() ? 0 : fread(text.data(), 1, text.size(), file);
    fclose(file);
    if (read != text.size()) {
        SetError(error, "Could not read complete patch manifest");
        return false;
    }
    return ParsePatchManifest(text, manifest, error);
}

bool ParsePatchManifest(const std::string& jsonText, PatchManifest* manifest, std::string* error) {
    if (manifest == nullptr) {
        SetError(error, "Output manifest is null");
        return false;
    }
    try {
        const Json root = Json::parse(jsonText);
        static const std::set<std::string> rootKeys = {"schemaVersion", "patches"};
        if (!HasOnlyKeys(root, rootKeys, error)) return false;
        const auto version = root.find("schemaVersion");
        const auto patches = root.find("patches");
        if (version == root.end() || !version->is_number_unsigned() || version->get<uint64_t>() != 1 ||
            patches == root.end() || !patches->is_array()) {
            SetError(error, "Manifest requires schemaVersion 1 and a patches array");
            return false;
        }
        PatchManifest parsed;
        parsed.schemaVersion = 1;
        std::set<std::string> ids;
        for (const Json& value : *patches) {
            ManifestPatch patch;
            if (!ParseEntry(value, &patch, error)) return false;
            if (!ids.insert(patch.id).second) {
                SetError(error, "Duplicate patch ID: " + patch.id);
                return false;
            }
            parsed.patches.push_back(std::move(patch));
        }
        *manifest = std::move(parsed);
        return true;
    } catch (const std::exception& exception) {
        SetError(error, std::string("Invalid JSON manifest: ") + exception.what());
        return false;
    }
}

bool PreparePatchRequest(
        const ManifestPatch& patch,
        const PeIdentity& identity,
        PatchRequest* request,
        std::string* error) {
    if (request == nullptr) {
        SetError(error, "Output patch request is null");
        return false;
    }
    if (identity.timeDateStamp != patch.peTimeDateStamp || identity.sizeOfImage != patch.peSizeOfImage) {
        SetError(error, "PE timestamp or image size is incompatible with this patch");
        return false;
    }
    auto equalHash = [&identity](const std::string& candidate) {
        if (candidate.size() != identity.sha256.size()) return false;
        for (size_t i = 0; i < candidate.size(); ++i) {
            const unsigned char left = static_cast<unsigned char>(candidate[i]);
            const unsigned char right = static_cast<unsigned char>(identity.sha256[i]);
            if (std::toupper(left) != std::toupper(right)) return false;
        }
        return true;
    };
    const auto hash = std::find_if(patch.allowedSha256.begin(), patch.allowedSha256.end(), equalHash);
    if (hash == patch.allowedSha256.end()) {
        SetError(error, "Target SHA-256 is not compatible with this patch");
        return false;
    }
    *request = patch.request;
    request->allowedOriginalSha256 = *hash;
    return true;
}

}  // namespace omsi_patch
