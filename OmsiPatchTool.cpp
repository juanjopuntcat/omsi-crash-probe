#include "PatchCore.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace {

std::string JsonEscape(const std::string& text) {
    std::string result;
    for (unsigned char character : text) {
        switch (character) {
            case '\\': result += "\\\\"; break;
            case '"': result += "\\\""; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (character < 0x20) {
                    char escaped[7] = {};
                    std::snprintf(escaped, sizeof(escaped), "\\u%04X", character);
                    result += escaped;
                } else {
                    result += static_cast<char>(character);
                }
        }
    }
    return result;
}

std::string Utf8(const wchar_t* text) {
    if (text == nullptr) return {};
    const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1, nullptr, 0, nullptr, nullptr);
    if (count <= 1) return {};
    std::string result(static_cast<size_t>(count), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1, result.data(), count, nullptr, nullptr);
    result.resize(static_cast<size_t>(count - 1));
    return result;
}

void PrintError(const char* code, const std::string& message) {
    std::printf("{\"ok\":false,\"error\":\"%s\",\"message\":\"%s\"}\n",
        code, JsonEscape(message).c_str());
}

int Inspect(const wchar_t* path) {
    omsi_patch::PeImage image;
    std::string error;
    if (!omsi_patch::LoadPeImage(path, &image, &error)) {
        PrintError("invalid-pe", error);
        return 2;
    }
    const omsi_patch::PeIdentity& identity = image.identity;
    std::printf(
        "{\"ok\":true,\"path\":\"%s\",\"machine\":\"0x%04X\","
        "\"timeDateStamp\":\"0x%08X\",\"sizeOfImage\":\"0x%08X\","
        "\"fileSize\":%llu,\"largeAddressAware\":%s,\"sha256\":\"%s\"}\n",
        JsonEscape(Utf8(path)).c_str(), identity.machine, identity.timeDateStamp,
        identity.sizeOfImage, static_cast<unsigned long long>(identity.fileSize),
        identity.IsLargeAddressAware() ? "true" : "false", identity.sha256.c_str());
    return 0;
}

int ResolveRva(const wchar_t* path, const wchar_t* rvaText) {
    errno = 0;
    wchar_t* end = nullptr;
    const unsigned long parsed = wcstoul(rvaText, &end, 0);
    if (errno != 0 || end == rvaText || *end != L'\0') {
        PrintError("invalid-rva", "RVA must be an unsigned integer such as 0x00428140");
        return 2;
    }
    omsi_patch::PeImage image;
    std::string error;
    if (!omsi_patch::LoadPeImage(path, &image, &error)) {
        PrintError("invalid-pe", error);
        return 2;
    }
    uint32_t offset = 0;
    if (!omsi_patch::RvaToFileOffset(image, static_cast<uint32_t>(parsed), &offset)) {
        PrintError("unmapped-rva", "RVA does not map to bytes in a PE section");
        return 3;
    }
    std::printf("{\"ok\":true,\"rva\":\"0x%08lX\",\"fileOffset\":\"0x%08X\"}\n", parsed, offset);
    return 0;
}

}  // namespace

int main() {
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == nullptr) {
        PrintError("command-line", "Windows could not parse the command line");
        return 1;
    }
    int result = 1;
    int command = 1;
    if (argc > 2 && _wcsicmp(argv[1], L"inspect") != 0 && _wcsicmp(argv[1], L"rva") != 0 &&
        (_wcsicmp(argv[2], L"inspect") == 0 || _wcsicmp(argv[2], L"rva") == 0)) {
        command = 2;
    }
    if (argc == command + 2 && _wcsicmp(argv[command], L"inspect") == 0) {
        result = Inspect(argv[command + 1]);
    } else if (argc == command + 3 && _wcsicmp(argv[command], L"rva") == 0) {
        result = ResolveRva(argv[command + 1], argv[command + 2]);
    } else {
        std::string message = "Usage: OmsiPatchTool inspect <pe-path> | rva <pe-path> <rva>; received argc=" +
            std::to_string(argc) + " commandLine=" + Utf8(GetCommandLineW());
        PrintError("usage", message);
    }
    LocalFree(argv);
    return result;
}
