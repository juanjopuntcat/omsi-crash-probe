#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <cstdio>
#include <cstring>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "user32.lib")

// OmsiCrashProbe is intentionally passive:
// - it does not patch OMSI;
// - it does not catch or suppress exceptions;
// - it only observes selected first-chance exceptions and lets the normal
//   Windows/Delphi/OMSI handlers continue afterwards.

// Handle returned by AddVectoredExceptionHandler. We keep it so the handler can
// be removed cleanly when OMSI unloads/finalizes the plugin.
static PVOID g_vectoredHandler = nullptr;

// The exception handler may be called from different OMSI threads. This lock
// serializes writes to probe.log so log lines from different threads do not
// interleave.
static CRITICAL_SECTION g_logLock;
static bool g_lockReady = false;

// Absolute path to <OMSI root>\OmsiCrashProbe\probe.log, built at runtime from
// the path of the running Omsi.exe.
static char g_logPath[MAX_PATH] = {};

// Thread-local reentrancy guard. If logging itself triggers another exception,
// the nested call returns immediately instead of recursively logging forever.
static __declspec(thread) bool g_insideHandler = false;

// Limit how many repeated signatures we remember in one OMSI process. This is
// deliberately fixed-size and allocation-free because exception logging should
// not depend on heap allocation while the process may already be unstable.
static const int kMaxSignatureStats = 128;
static const int kMaxStackCandidates = 48;

struct StackCandidate {
    DWORD stackOffset;
    uintptr_t value;
    uintptr_t rva;
    char module[MAX_PATH];
};

// A stable-ish identity for repeated first-chance exceptions. Delphi exception
// parameter p1 is often an object/string pointer and changes frequently, so this
// signature focuses on code-site style values: exception code, raise-site RVA,
// Delphi p0/p2, and the first two Omsi.exe stack candidates.
struct ExceptionSignature {
    DWORD code;
    uintptr_t exceptionRva;
    uintptr_t param0;
    uintptr_t param2;
    uintptr_t firstOmsiRva;
    uintptr_t secondOmsiRva;
};

struct SignatureStats {
    bool used;
    ExceptionSignature signature;
    DWORD count;
    SYSTEMTIME firstSeen;
    SYSTEMTIME lastSeen;
};

static SignatureStats g_signatureStats[kMaxSignatureStats] = {};

struct AddressSpaceSnapshot {
    unsigned long long freeBytes;
    unsigned long long largestFreeBytes;
};

static void FormatSystemTime(const SYSTEMTIME& time, char* buffer, size_t bufferSize);

// Append one CRLF-terminated line to probe.log. This function avoids C++ iostreams
// and heap-heavy logging so it remains small and predictable inside OMSI.
static void AppendLine(const char* line) {
    if (!g_lockReady || !g_logPath[0]) {
        return;
    }

    EnterCriticalSection(&g_logLock);
    HANDLE file = CreateFileA(
        g_logPath,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (file != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(file, line, static_cast<DWORD>(strlen(line)), &written, nullptr);
        WriteFile(file, "\r\n", 2, &written, nullptr);
        CloseHandle(file);
    }
    LeaveCriticalSection(&g_logLock);
}

static unsigned long long BytesToKB(unsigned long long bytes) {
    return bytes / 1024ULL;
}

static unsigned long long BytesToMB(unsigned long long bytes) {
    return bytes / (1024ULL * 1024ULL);
}

// Walk the current 32-bit process address space and measure free virtual
// address ranges. This is more expensive than reading process counters, so it
// is only called for startup/shutdown and selected full exception captures.
static AddressSpaceSnapshot QueryAddressSpaceSnapshot() {
    AddressSpaceSnapshot snapshot = {};

    SYSTEM_INFO systemInfo = {};
    GetSystemInfo(&systemInfo);

    uintptr_t address = 0x10000;
    uintptr_t maxAddress = reinterpret_cast<uintptr_t>(systemInfo.lpMaximumApplicationAddress);

    while (address < maxAddress) {
        MEMORY_BASIC_INFORMATION mbi = {};
        SIZE_T querySize = VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi));
        if (querySize == 0) {
            address += 0x10000;
            continue;
        }

        uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        uintptr_t next = base + mbi.RegionSize;
        if (mbi.State == MEM_FREE) {
            unsigned long long regionSize = static_cast<unsigned long long>(mbi.RegionSize);
            snapshot.freeBytes += regionSize;
            if (regionSize > snapshot.largestFreeBytes) {
                snapshot.largestFreeBytes = regionSize;
            }
        }

        if (next <= address) {
            break;
        }
        address = next;
    }

    return snapshot;
}

// Capture the resource picture around important moments. The private/working
// set counters explain process pressure, GDI/USER counts catch bitmap/window
// leaks, and the largest free virtual block is often the useful 32-bit limit.
static void LogMemorySnapshot(const char* reason) {
    PROCESS_MEMORY_COUNTERS_EX processMemory = {};
    processMemory.cb = sizeof(processMemory);
    BOOL hasProcessMemory = GetProcessMemoryInfo(
        GetCurrentProcess(),
        reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&processMemory),
        sizeof(processMemory));

    MEMORYSTATUSEX systemMemory = {};
    systemMemory.dwLength = sizeof(systemMemory);
    BOOL hasSystemMemory = GlobalMemoryStatusEx(&systemMemory);

    DWORD gdiObjects = GetGuiResources(GetCurrentProcess(), GR_GDIOBJECTS);
    DWORD userObjects = GetGuiResources(GetCurrentProcess(), GR_USEROBJECTS);
    AddressSpaceSnapshot addressSpace = QueryAddressSpaceSnapshot();

    SYSTEMTIME now = {};
    GetLocalTime(&now);
    char timestamp[64] = {};
    FormatSystemTime(now, timestamp, sizeof(timestamp));

    char line[1024] = {};
    snprintf(
        line,
        sizeof(line),
        "MemorySnapshot time=\"%s\" reason=\"%s\" privateKB=%llu workingSetKB=%llu peakWorkingSetKB=%llu pagefileKB=%llu commitAvailMB=%llu physAvailMB=%llu vasFreeMB=%llu vasLargestFreeMB=%llu gdiObjects=%lu userObjects=%lu countersOk=%lu systemOk=%lu",
        timestamp,
        reason ? reason : "<unknown>",
        hasProcessMemory ? BytesToKB(static_cast<unsigned long long>(processMemory.PrivateUsage)) : 0ULL,
        hasProcessMemory ? BytesToKB(static_cast<unsigned long long>(processMemory.WorkingSetSize)) : 0ULL,
        hasProcessMemory ? BytesToKB(static_cast<unsigned long long>(processMemory.PeakWorkingSetSize)) : 0ULL,
        hasProcessMemory ? BytesToKB(static_cast<unsigned long long>(processMemory.PagefileUsage)) : 0ULL,
        hasSystemMemory ? BytesToMB(systemMemory.ullAvailPageFile) : 0ULL,
        hasSystemMemory ? BytesToMB(systemMemory.ullAvailPhys) : 0ULL,
        BytesToMB(addressSpace.freeBytes),
        BytesToMB(addressSpace.largestFreeBytes),
        gdiObjects,
        userObjects,
        static_cast<unsigned long>(hasProcessMemory),
        static_cast<unsigned long>(hasSystemMemory));
    AppendLine(line);
}

// Build the log directory and file path beside Omsi.exe. GetModuleFileNameA with
// a null module handle returns the executable path for the current process.
static void BuildLogPath() {
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);

    char* lastSlash = strrchr(exePath, '\\');
    if (lastSlash) {
        *(lastSlash + 1) = '\0';
    }

    char dir[MAX_PATH] = {};
    snprintf(dir, sizeof(dir), "%sOmsiCrashProbe", exePath);
    CreateDirectoryA(dir, nullptr);
    snprintf(g_logPath, sizeof(g_logPath), "%s\\probe.log", dir);
}

// Convert common Windows/Delphi exception codes into stable names for the log.
// 0x0EEDFADE is Delphi's generic exception code, so it is the most important one
// for OMSI's "Fehler bei..." style runtime errors.
static const char* ExceptionName(DWORD code) {
    switch (code) {
        case 0x0EEDFADE: return "DelphiException";
        case EXCEPTION_ACCESS_VIOLATION: return "AccessViolation";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: return "ArrayBoundsExceeded";
        case EXCEPTION_INT_DIVIDE_BY_ZERO: return "IntegerDivideByZero";
        case EXCEPTION_INT_OVERFLOW: return "IntegerOverflow";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO: return "FloatDivideByZero";
        case EXCEPTION_FLT_INVALID_OPERATION: return "FloatInvalidOperation";
        case EXCEPTION_ILLEGAL_INSTRUCTION: return "IllegalInstruction";
        case EXCEPTION_STACK_OVERFLOW: return "StackOverflow";
        default: return "Other";
    }
}

// Keep the log focused. Many applications raise benign first-chance exceptions;
// this whitelist records the classes that are likely relevant to OMSI engine
// faults or Delphi runtime errors.
static bool IsInterestingException(DWORD code) {
    switch (code) {
        case 0x0EEDFADE:
        case EXCEPTION_ACCESS_VIOLATION:
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
        case EXCEPTION_INT_OVERFLOW:
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
        case EXCEPTION_FLT_INVALID_OPERATION:
        case EXCEPTION_ILLEGAL_INSTRUCTION:
        case EXCEPTION_STACK_OVERFLOW:
            return true;
        default:
            return false;
    }
}

// Read process memory from the current process without trusting the pointer.
// Delphi exception parameters often point at runtime objects; a bad guess here
// must never turn the logger itself into the source of a new crash.
static bool SafeReadMemory(uintptr_t address, void* out, size_t size) {
    if (!address || !out || !size) {
        return false;
    }

    __try {
        memcpy(out, reinterpret_cast<const void*>(address), size);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool SafeReadByte(uintptr_t address, BYTE* out) {
    return SafeReadMemory(address, out, sizeof(*out));
}

static bool SafeReadDword(uintptr_t address, DWORD* out) {
    return SafeReadMemory(address, out, sizeof(*out));
}

static bool IsLoggableByte(BYTE value) {
    return value >= 32 && value != 127;
}

static bool IsAsciiIdentifierByte(BYTE value) {
    return (value >= 'A' && value <= 'Z') ||
        (value >= 'a' && value <= 'z') ||
        (value >= '0' && value <= '9') ||
        value == '_';
}

// Copy bytes into a single log-line-safe string. Keep extended ANSI bytes as-is
// because OMSI/Delphi messages may be localized, but replace control characters
// that would break probe.log formatting.
static void CopyLoggableBytes(const char* source, size_t length, char* out, size_t outSize) {
    if (!out || outSize == 0) {
        return;
    }

    size_t used = 0;
    for (size_t i = 0; i < length && used + 1 < outSize; ++i) {
        BYTE value = static_cast<BYTE>(source[i]);
        out[used++] = IsLoggableByte(value) ? static_cast<char>(value) : '.';
    }
    out[used] = '\0';
}

static bool LooksLikeAnsiBytes(const char* text, size_t length) {
    if (!text || length < 2) {
        return false;
    }

    int printable = 0;
    int zeros = 0;
    int total = 0;
    for (size_t i = 0; i < length; ++i) {
        BYTE value = static_cast<BYTE>(text[i]);
        total += 1;
        if (value == 0) {
            zeros += 1;
            continue;
        }
        if (IsLoggableByte(value)) {
            printable += 1;
        }
    }

    // UTF-16 misread as AnsiString looks like printable byte, zero byte,
    // printable byte, zero byte. Reject that pattern so Unicode gets a chance.
    if (zeros * 100 / total > 20) {
        return false;
    }

    return printable * 100 / total >= 80;
}

static bool LooksLikeDelphiClassName(const char* text) {
    if (!text || !text[0]) {
        return false;
    }

    size_t length = strlen(text);
    if (length < 2 || length > 80) {
        return false;
    }

    BYTE first = static_cast<BYTE>(text[0]);
    if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z'))) {
        return false;
    }

    for (size_t i = 1; i < length; ++i) {
        if (!IsAsciiIdentifierByte(static_cast<BYTE>(text[i]))) {
            return false;
        }
    }

    return true;
}

// Delphi VMTs store the class name as a ShortString at a negative offset from
// the VMT pointer in classic 32-bit Delphi. If the layout guess is wrong, the
// length/readability checks make this return false.
static bool TryReadDelphiClassName(uintptr_t objectPtr, char* out, size_t outSize) {
    if (!out || outSize == 0) {
        return false;
    }
    out[0] = '\0';

    DWORD vmt = 0;
    if (!SafeReadDword(objectPtr, &vmt) || !vmt) {
        return false;
    }

    BYTE length = 0;
    uintptr_t className = static_cast<uintptr_t>(vmt) - 56;
    if (!SafeReadByte(className, &length) || length == 0 || length > 80) {
        return false;
    }

    char raw[96] = {};
    if (!SafeReadMemory(className + 1, raw, length)) {
        return false;
    }

    char candidate[96] = {};
    CopyLoggableBytes(raw, length, candidate, sizeof(candidate));
    if (!LooksLikeDelphiClassName(candidate)) {
        return false;
    }

    lstrcpynA(out, candidate, static_cast<int>(outSize));
    return true;
}

// Classic Delphi AnsiString points at character data, with byte length stored
// four bytes before the data pointer. This is the likely representation for
// OMSI-era Delphi exception messages.
static bool TryReadDelphiAnsiString(uintptr_t stringPtr, char* out, size_t outSize) {
    if (!out || outSize == 0) {
        return false;
    }
    out[0] = '\0';

    DWORD length = 0;
    if (!SafeReadDword(stringPtr - 4, &length) || length == 0 || length > 512) {
        return false;
    }

    char raw[513] = {};
    if (!SafeReadMemory(stringPtr, raw, length)) {
        return false;
    }

    if (!LooksLikeAnsiBytes(raw, length)) {
        return false;
    }

    CopyLoggableBytes(raw, length, out, outSize);
    return true;
}

// Newer Delphi UnicodeString also stores length at data-4, but the data is
// UTF-16. OMSI looks older than this, yet trying it safely costs little and may
// help with third-party modules.
static bool TryReadDelphiUnicodeString(uintptr_t stringPtr, char* out, size_t outSize) {
    if (!out || outSize == 0) {
        return false;
    }
    out[0] = '\0';

    DWORD charCount = 0;
    if (!SafeReadDword(stringPtr - 4, &charCount) || charCount == 0 || charCount > 256) {
        return false;
    }

    WCHAR wide[257] = {};
    if (!SafeReadMemory(stringPtr, wide, charCount * sizeof(WCHAR))) {
        return false;
    }

    char convertedRaw[1024] = {};
    int converted = WideCharToMultiByte(
        CP_ACP,
        0,
        wide,
        static_cast<int>(charCount),
        convertedRaw,
        static_cast<int>(sizeof(convertedRaw) - 1),
        nullptr,
        nullptr);
    if (converted <= 0) {
        out[0] = '\0';
        return false;
    }

    convertedRaw[converted] = '\0';
    if (!LooksLikeAnsiBytes(convertedRaw, strlen(convertedRaw))) {
        return false;
    }

    CopyLoggableBytes(convertedRaw, strlen(convertedRaw), out, outSize);
    return true;
}

// Try to decode the Delphi exception object carried by 0x0EEDFADE. Empirically
// Delphi passes the exception object in parameter 1; for Exception descendants,
// the first instance field is usually the message string.
static void LogDelphiExceptionDetails(EXCEPTION_RECORD* er) {
    if (er->ExceptionCode != 0x0EEDFADE || er->NumberParameters <= 1) {
        return;
    }

    uintptr_t objectPtr = er->ExceptionInformation[1];
    if (!objectPtr) {
        return;
    }

    char className[96] = {};
    TryReadDelphiClassName(objectPtr, className, sizeof(className));

    DWORD messagePtr = 0;
    char message[512] = {};
    const char* messageKind = nullptr;
    if (SafeReadDword(objectPtr + 4, &messagePtr) && messagePtr) {
        if (TryReadDelphiUnicodeString(messagePtr, message, sizeof(message))) {
            messageKind = "UnicodeString";
        }
        else if (TryReadDelphiAnsiString(messagePtr, message, sizeof(message))) {
            messageKind = "AnsiString";
        }
    }

    if (!className[0] && !message[0]) {
        return;
    }

    char line[1024] = {};
    snprintf(
        line,
        sizeof(line),
        "  delphi object=0x%08p class=\"%s\" message=\"%s\" messageKind=%s",
        reinterpret_cast<void*>(objectPtr),
        className[0] ? className : "<unknown>",
        message[0] ? message : "<unreadable>",
        messageKind ? messageKind : "<unknown>");
    AppendLine(line);
}

// Minimal module description used to normalize absolute addresses to
// module-relative RVAs. RVAs are stable across ASLR/session base changes.
struct ModuleInfo {
    char name[MAX_PATH];
    char path[MAX_PATH];
    uintptr_t base;
    DWORD size;
};

// Resolving a stack address by taking a Toolhelp module snapshot is expensive.
// We cache the module list once at PluginStart, then the exception path only
// performs a small linear scan over this fixed-size table.
static const int kMaxCachedModules = 256;
static ModuleInfo g_moduleCache[kMaxCachedModules] = {};
static int g_moduleCacheCount = 0;

struct KnownOmsiRva {
    uintptr_t start;
    uintptr_t end;
    const char* system;
    const char* note;
    bool callerContextMatters;
};

// Human labels for RVAs we have already inspected in Ghidra. These labels are
// deliberately descriptive, not corrective: the probe still only observes
// exceptions, but repeated signatures become easier to group by subsystem.
static const KnownOmsiRva kKnownOmsiRvas[] = {
    {0x000048B4, 0x00004939, "Delphi/memory copy helper", "Generic runtime helper; caller/input is more useful than this RVA alone.", true},
    {0x00004C7C, 0x00004CA9, "Delphi x87 float-to-int conversion", "Matches FISTP conversion sites; look up caller for the original numeric operation.", true},
    {0x00006B0C, 0x00006B17, "Delphi object cleanup/destructor helper", "Calls through [vtable-4]; caller likely owns the bad object pointer.", true},
    {0x00006E68, 0x00006E99, "Delphi object dispatch/null-object helper", "Dereferences an object pointer before dispatch; null or stale owner pointer suspected.", true},
    {0x00007E8C, 0x00007EF7, "Delphi active exception raiser", "Common final frame for a Delphi exception after the specific exception object has already been constructed.", true},
    {0x0000884C, 0x0000885A, "Delphi managed string refcount helper", "Reads string metadata at [ptr-8]; caller likely passed an invalid managed string.", true},
    {0x00011610, 0x00011611, "Delphi invalid-float exception class", "Referenced by the string-to-float parser when conversion fails, usually producing invalid Gleitkommawert.", true},
    {0x000120A0, 0x000120A1, "Delphi invalid-integer exception class", "Referenced by integer conversion wrappers when conversion fails, usually producing invalid Integer-Wert.", true},
    {0x00021124, 0x00021145, "Delphi exception raise helper", "Marker for a raised Delphi exception, not usually the root cause.", true},
    {0x0002237C, 0x00022433, "Delphi conversion wrapper", "Raises through the Delphi exception helper when conversion reports an error.", true},
    {0x00024F68, 0x00024FA9, "String-to-float parser", "Candidate for invalid Gleitkommawert / decimal parsing errors.", true},
    {0x00028EA4, 0x00028EB6, "Delphi out-of-memory exception constructor", "Constructs the Zu wenig Arbeitsspeicher resource-backed exception object.", true},
    {0x0002A000, 0x0002A09E, "Delphi system-error raiser", "Uses GetLastError and raises Systemfehler / OS error exceptions such as Code 8.", true},
    {0x0002ADCC, 0x0002C81F, "Delphi range-check string/list helper cluster", "Constructs ERangeError for negative index, upper-bound, and slice/length violations in Delphi collection/string helpers.", true},
    {0x00030ADC, 0x00030CF9, "Delphi resource exception constructor path", "Builds localized resource-backed exception objects, including Zu wenig Arbeitsspeicher variants.", false},
    {0x0004DD85, 0x0004DDA9, "Delphi explicit Bereichspruefung raise site", "Constructs ERangeError with the exact Fehler bei Bereichspruefung resource string.", true},
    {0x0004DF1C, 0x0004DF70, "Stream read error helper", "Raises Stream-Lesefehler when a stream read callback returns no positive byte count.", true},
    {0x0004DF7C, 0x0004DFD0, "Stream read error helper 2", "Raises Stream-Lesefehler through an alternate stream callback path.", true},
    {0x0004EB15, 0x0004EB34, "Memory stream expansion failure path", "Raises the Speicher-Stream wegen Speichermangel resource after a stream grow/allocation attempt fails.", true},
    {0x0004FF78, 0x0004FFAA, "Stream read error path", "Raises Stream-Lesefehler after a read/fill operation returns zero.", true},
    {0x00052684, 0x000527B6, "Stream read validation path", "Raises Stream-Lesefehler after a stream validation/read helper reports failure.", true},
    {0x0005284C, 0x00052A38, "Stream read block path", "Raises Stream-Lesefehler after a block read helper reports failure.", true},
    {0x00054ADC, 0x00054B2E, "Stream write error path", "Raises Stream-Schreibfehler after a write helper reports failure.", true},
    {0x000B57F4, 0x000B58ED, "Delphi list bounds helper", "Constructs EListError around list index checks; a caller above this frame is usually the useful owner.", true},
    {0x00070890, 0x000708B2, "Bitmap invalid helper", "Raises the Bitmap ist ungueltig resource through a graphic exception helper.", true},
    {0x000708CC, 0x00070916, "System resources exhausted graphics helper", "Raises the Systemressourcen erschoepft resource through the graphics exception path.", true},
    {0x00072F90, 0x00073009, "Unknown image extension path", "Raises Unbekannte Bilddateierweiterung for unsupported image extensions such as PNG in older paths.", true},
    {0x000769E4, 0x0007720C, "BMP/GDI bitmap load path", "Loads bitmap data through GDI; CreateDIBSection/CreateDIBitmap failure can raise Systemfehler Code 8.", false},
    {0x00078964, 0x0007899F, "Invalid image path", "Raises Ungueltiges Bild after image flag/state validation fails.", true},
    {0x00098000, 0x00098017, "Window device context creation failure", "Raises Fehler beim Erstellen des Fenster-Geraetekontexts after a DC acquisition call returns null.", true},
    {0x00120818, 0x00120863, "OMSI list access path", "Observed constructing EListError from a negative or invalid lookup result before list access continues.", false},
    {0x0011FF8C, 0x001243B7, "Argument bounds checking cluster", "Observed constructing EArgumentOutOfRangeException around index/length checks.", false},
    {0x0013AFC8, 0x0013B018, "System resources exhausted init path", "Raises Systemressourcen erschoepft after an initialization/allocation call leaves an object field null.", true},
    {0x0020AEA4, 0x0020CC14, "Argument bounds checking cluster 2", "Observed constructing EArgumentOutOfRangeException with Argument ausserhalb des Bereichs around indexed access.", false},
    {0x002D753C, 0x002D77B3, "Request not enough memory resource path", "References the Fuer diese Anforderung steht nicht genuegend Speicher zur Verfuegung resource.", true},
    {0x002F9F89, 0x002FA083, "Texture manager memory report path", "Formats Speicherbedarf Texturmanager and related memory accounting output.", false},
    {0x001AB9B8, 0x001AEA0D, "High-volume numeric parser cluster A", "Calls the string-to-float parser repeatedly and stores parsed float fields into an object.", false},
    {0x001CE730, 0x001CFC4F, "High-volume numeric parser cluster B", "Repeatedly converts grouped string values into floating-point fields.", false},
    {0x001D6140, 0x001D661C, "Sky/environment data parser", "Parses sky/environment data and uses Delphi strings heavily.", false},
    {0x001D78D0, 0x001D82A2, "helper\\stars.dat parser", "Parses star data, converts floats, builds a vertex buffer.", false},
    {0x001EFB98, 0x001F80B7, "Very large numeric parser cluster", "Largest observed string-to-float caller cluster; Ghidra decompiler output overflowed.", false},
    {0x00224B40, 0x002256FC, "Object float property parser", "Converts many string values and stores floats at object-field offsets.", false},
    {0x00241C38, 0x002425A8, "Vehicle/script state stringvars path", "Walks vehicle state and [stringvars]-style data.", false},
    {0x00243F10, 0x00243F7B, "D3DX texture creation call site", "Builds D3DXCreateTextureFromFileExW arguments and calls the imported texture creation thunk.", true},
    {0x0024307C, 0x00244AB3, "Wide texture load/numeric parser path", "Calls D3DXCreateTextureFromFileExW and repeatedly parses float fields.", false},
    {0x002793A8, 0x0027992B, "Direct3D device creation path", "Calls a Direct3D interface method and raises 'Error while creating Direct3D-Device' on failure.", false},
    {0x0034B148, 0x0034C858, "Argument bounds checking cluster 3", "Observed constructing EArgumentOutOfRangeException with Argument ausserhalb des Bereichs around indexed access.", false},
    {0x0034D878, 0x0034F188, "Numeric bounds/parser cluster", "Parses float groups and compares parsed values against bounds.", false},
    {0x00353658, 0x00353CEE, "Compact object float table parser", "Parses strings into a compact set of object float fields.", false},
    {0x003860B0, 0x0038AE21, "High-volume numeric parser cluster C", "Large parser cluster with many string-to-float conversions and scaling operations.", false},
    {0x003922A0, 0x00395FCF, "High-volume numeric parser cluster D", "Large parser cluster with repeated indexed float-field writes.", false},
    {0x0039F6B4, 0x0039F7A9, "Texture load error wrapper", "Labels operation as texture load and formats Direct9 errors.", false},
    {0x003B432C, 0x003B90B0, "High-volume numeric parser cluster E", "Second-largest decompiled string-to-float caller cluster.", false},
    {0x003BB224, 0x003BBDE1, "Script texture validation path", "Contains invalid [scripttexture] entry reporting.", false},
    {0x003C3FA8, 0x003C41D9, "Object/list access path", "Bounds-checks object-owned list data before virtual calls.", true},
    {0x003F891C, 0x003F933B, "ANSI texture/image load path", "Calls D3DXGetImageInfoFromFileA and D3DXCreateTextureFromFileExA.", false},
    {0x003FCC08, 0x003FCC2F, "Texture stage limit guard", "Raises/logs Too high texture stage index when a stage counter reaches 8.", true},
    {0x004029AC, 0x00402B80, "Direct9 error formatter", "Builds Direct9 Error text through DXGetErrorString9W.", false},
    {0x00405D60, 0x004060DE, "WAV/DirectSound load path", "Loads RIFF/WAVE data and creates or locks DirectSound buffers.", false},
    {0x0042695C, 0x00429302, "World/UI status update path", "Large update path with guarded divisions and deep object chains.", true},
    {0x00429FD8, 0x0042A412, "Direct3D device lost/reset path", "Logs device lost/resetted and formats reset failures through the Direct9 error formatter.", false},
};

static void CacheModule(const MODULEENTRY32& module) {
    if (g_moduleCacheCount >= kMaxCachedModules) {
        return;
    }

    ModuleInfo* slot = &g_moduleCache[g_moduleCacheCount++];
    memset(slot, 0, sizeof(*slot));
    lstrcpynA(slot->name, module.szModule, MAX_PATH);
    lstrcpynA(slot->path, module.szExePath, MAX_PATH);
    slot->base = reinterpret_cast<uintptr_t>(module.modBaseAddr);
    slot->size = module.modBaseSize;
}

static bool FindModuleInCache(uintptr_t address, ModuleInfo* out) {
    for (int i = 0; i < g_moduleCacheCount; ++i) {
        const ModuleInfo& module = g_moduleCache[i];
        uintptr_t end = module.base + module.size;
        if (address >= module.base && address < end) {
            if (out) {
                *out = module;
            }
            return true;
        }
    }

    return false;
}

static void RefreshModuleCache() {
    g_moduleCacheCount = 0;
    memset(g_moduleCache, 0, sizeof(g_moduleCache));

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    MODULEENTRY32 module = {};
    module.dwSize = sizeof(module);

    if (Module32First(snapshot, &module)) {
        do {
            CacheModule(module);
        } while (Module32Next(snapshot, &module));
    }

    CloseHandle(snapshot);
}

// Resolve an address inside the current process to the loaded module that owns
// it. This lets the log say "Omsi.exe+0x123456" instead of only "0x00523456".
static bool FindModuleForAddress(uintptr_t address, ModuleInfo* out) {
    return FindModuleInCache(address, out);
}

static const KnownOmsiRva* DescribeOmsiRva(uintptr_t rva) {
    for (int i = 0; i < static_cast<int>(sizeof(kKnownOmsiRvas) / sizeof(kKnownOmsiRvas[0])); ++i) {
        if (rva >= kKnownOmsiRvas[i].start && rva <= kKnownOmsiRvas[i].end) {
            return &kKnownOmsiRvas[i];
        }
    }
    return nullptr;
}

static const char* KnownOmsiRvaSystem(uintptr_t rva) {
    const KnownOmsiRva* known = DescribeOmsiRva(rva);
    return known ? known->system : "";
}

static void LogKnownOmsiRva(const char* source, uintptr_t rva, DWORD stackOffset) {
    const KnownOmsiRva* known = DescribeOmsiRva(rva);
    if (!known) {
        return;
    }

    char line[1024] = {};
    if (stackOffset == 0xFFFFFFFF) {
        snprintf(
            line,
            sizeof(line),
            "  known-rva source=%s rva=0x%08X system=\"%s\" callerContext=%s note=\"%s\"",
            source,
            static_cast<unsigned>(rva),
            known->system,
            known->callerContextMatters ? "important" : "normal",
            known->note);
    }
    else {
        snprintf(
            line,
            sizeof(line),
            "  known-rva source=%s esp+0x%02X rva=0x%08X system=\"%s\" callerContext=%s note=\"%s\"",
            source,
            stackOffset,
            static_cast<unsigned>(rva),
            known->system,
            known->callerContextMatters ? "important" : "normal",
            known->note);
    }
    AppendLine(line);
}

static void LogKnownOmsiRvaContext(
    const char* exceptionModule,
    uintptr_t exceptionRva,
    const StackCandidate* candidates,
    int candidateCount) {
    uintptr_t logged[8] = {};
    int loggedCount = 0;

    if (exceptionModule && lstrcmpiA(exceptionModule, "Omsi.exe") == 0 && DescribeOmsiRva(exceptionRva)) {
        LogKnownOmsiRva("exception", exceptionRva, 0xFFFFFFFF);
        logged[loggedCount++] = exceptionRva;
    }

    for (int i = 0; i < candidateCount && loggedCount < static_cast<int>(sizeof(logged) / sizeof(logged[0])); ++i) {
        if (lstrcmpiA(candidates[i].module, "Omsi.exe") != 0 || !DescribeOmsiRva(candidates[i].rva)) {
            continue;
        }

        bool duplicate = false;
        for (int j = 0; j < loggedCount; ++j) {
            if (logged[j] == candidates[i].rva) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            continue;
        }

        LogKnownOmsiRva("stack", candidates[i].rva, candidates[i].stackOffset);
        logged[loggedCount++] = candidates[i].rva;
    }
}

static bool SameSignature(const ExceptionSignature& a, const ExceptionSignature& b) {
    return a.code == b.code &&
        a.exceptionRva == b.exceptionRva &&
        a.param0 == b.param0 &&
        a.param2 == b.param2 &&
        a.firstOmsiRva == b.firstOmsiRva &&
        a.secondOmsiRva == b.secondOmsiRva;
}

static bool ShouldWriteRepeatedSummary(DWORD count) {
    return count == 10 ||
        count == 25 ||
        count == 50 ||
        count == 100 ||
        count == 250 ||
        count == 500 ||
        count == 1000 ||
        (count > 1000 && (count % 1000) == 0);
}

// Render SYSTEMTIME in a compact, sortable form for final summaries. The normal
// exception records already include timestamps; this helper keeps summary rows
// readable without duplicating the larger report format.
static void FormatSystemTime(const SYSTEMTIME& time, char* buffer, size_t bufferSize) {
    snprintf(
        buffer,
        bufferSize,
        "%04u-%02u-%02u %02u:%02u:%02u.%03u",
        time.wYear,
        time.wMonth,
        time.wDay,
        time.wHour,
        time.wMinute,
        time.wSecond,
        time.wMilliseconds);
}

// Update per-signature counters. Returns true when this occurrence should be
// written to the log. For noisy handled exceptions we write the first few full
// reports, then only compact milestone summaries.
static bool UpdateSignatureStats(const ExceptionSignature& signature, DWORD* occurrence, bool* summaryOnly) {
    *occurrence = 0;
    *summaryOnly = false;

    SYSTEMTIME now = {};
    GetLocalTime(&now);

    EnterCriticalSection(&g_logLock);

    SignatureStats* slot = nullptr;
    for (int i = 0; i < kMaxSignatureStats; ++i) {
        if (g_signatureStats[i].used && SameSignature(g_signatureStats[i].signature, signature)) {
            slot = &g_signatureStats[i];
            break;
        }
    }

    if (!slot) {
        for (int i = 0; i < kMaxSignatureStats; ++i) {
            if (!g_signatureStats[i].used) {
                slot = &g_signatureStats[i];
                slot->used = true;
                slot->signature = signature;
                slot->count = 0;
                slot->firstSeen = now;
                break;
            }
        }
    }

    if (!slot) {
        // If all slots are full, prefer preserving signal over dropping data.
        LeaveCriticalSection(&g_logLock);
        *occurrence = 1;
        return true;
    }

    slot->count += 1;
    slot->lastSeen = now;
    *occurrence = slot->count;

    bool shouldWrite = slot->count <= 3 || ShouldWriteRepeatedSummary(slot->count);
    *summaryOnly = slot->count > 3;

    LeaveCriticalSection(&g_logLock);
    return shouldWrite;
}

// Emit one final table at plugin shutdown. Milestone lines keep runtime logging
// cheap, but this summary gives us the true final count for each signature after
// a long OMSI session.
static void LogSignatureSummary() {
    if (!g_lockReady) {
        return;
    }

    AppendLine("Exception signature summary:");

    int usedSlots = 0;
    for (int i = 0; i < kMaxSignatureStats; ++i) {
        if (!g_signatureStats[i].used) {
            continue;
        }

        usedSlots += 1;
        const SignatureStats& stats = g_signatureStats[i];

        char firstSeen[32] = {};
        char lastSeen[32] = {};
        FormatSystemTime(stats.firstSeen, firstSeen, sizeof(firstSeen));
        FormatSystemTime(stats.lastSeen, lastSeen, sizeof(lastSeen));

        char line[1024] = {};
        snprintf(
            line,
            sizeof(line),
            "  count=%lu code=%s/0x%08X raiseRva=0x%08X p0=0x%08p p2=0x%08p omsi1=0x%08X omsi2=0x%08X first=\"%s\" last=\"%s\"",
            stats.count,
            ExceptionName(stats.signature.code),
            stats.signature.code,
            static_cast<unsigned>(stats.signature.exceptionRva),
            reinterpret_cast<void*>(stats.signature.param0),
            reinterpret_cast<void*>(stats.signature.param2),
            static_cast<unsigned>(stats.signature.firstOmsiRva),
            static_cast<unsigned>(stats.signature.secondOmsiRva),
            firstSeen,
            lastSeen);
        AppendLine(line);

        const char* omsi1System = KnownOmsiRvaSystem(stats.signature.firstOmsiRva);
        const char* omsi2System = KnownOmsiRvaSystem(stats.signature.secondOmsiRva);
        if (omsi1System[0] || omsi2System[0]) {
            snprintf(
                line,
                sizeof(line),
                "    known omsi1=\"%s\" omsi2=\"%s\"",
                omsi1System[0] ? omsi1System : "<unknown>",
                omsi2System[0] ? omsi2System : "<unknown>");
            AppendLine(line);
        }
    }

    if (usedSlots == 0) {
        AppendLine("  <none>");
    }
}

static bool OmsiRvaInRange(uintptr_t rva, uintptr_t start, uintptr_t end) {
    return rva >= start && rva <= end;
}

static bool IsSystemErrorCode8Signature(const ExceptionSignature& signature) {
    if (signature.code != 0x0EEDFADE || signature.param2 != 8) {
        return false;
    }

    return OmsiRvaInRange(signature.firstOmsiRva, 0x0002A000, 0x0002A09E) ||
        OmsiRvaInRange(signature.secondOmsiRva, 0x0002A000, 0x0002A09E);
}

// Memory snapshots are intentionally sparse. A virtual-address walk is useful
// but not free, so repeated noisy exceptions only trigger it while the full
// report is still being written.
static bool ShouldLogMemorySnapshotForException(
    const EXCEPTION_RECORD* er,
    const ExceptionSignature& signature,
    DWORD occurrence) {
    if (occurrence == 1) {
        return true;
    }

    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        return true;
    }

    if (IsSystemErrorCode8Signature(signature)) {
        return true;
    }

    return false;
}

static void BuildSignature(
    EXCEPTION_RECORD* er,
    uintptr_t exceptionRva,
    const StackCandidate* candidates,
    int candidateCount,
    ExceptionSignature* signature) {
    memset(signature, 0, sizeof(*signature));

    signature->code = er->ExceptionCode;
    signature->exceptionRva = exceptionRva;
    signature->param0 = er->NumberParameters > 0 ? er->ExceptionInformation[0] : 0;
    signature->param2 = er->NumberParameters > 2 ? er->ExceptionInformation[2] : 0;

    for (int i = 0; i < candidateCount; ++i) {
        if (lstrcmpiA(candidates[i].module, "Omsi.exe") == 0) {
            if (!signature->firstOmsiRva) {
                signature->firstOmsiRva = candidates[i].rva;
            }
            else if (candidates[i].rva != signature->firstOmsiRva) {
                signature->secondOmsiRva = candidates[i].rva;
                break;
            }
        }
    }
}

// Collect stack values that point inside loaded modules. For Delphi exceptions,
// these candidates are often more useful than ExceptionAddress because the
// exception itself is raised through KERNELBASE!RaiseException.
static int CollectStackCandidates(CONTEXT* ctx, StackCandidate* candidates, int maxCandidates) {
#if defined(_M_IX86)
    int count = 0;
    DWORD* stack = reinterpret_cast<DWORD*>(ctx->Esp);
    for (int i = 0; i < kMaxStackCandidates && count < maxCandidates; ++i) {
        DWORD value = 0;
        __try {
            value = stack[i];
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }

        ModuleInfo stackModule = {};
        if (FindModuleForAddress(value, &stackModule)) {
            candidates[count].stackOffset = i * 4;
            candidates[count].value = value;
            candidates[count].rva = value - stackModule.base;
            lstrcpynA(candidates[count].module, stackModule.name, MAX_PATH);
            count += 1;
        }
    }
    return count;
#else
    (void)ctx;
    (void)candidates;
    (void)maxCandidates;
    return 0;
#endif
}

// Snapshot loaded modules once at plugin startup. This gives us base addresses
// for Omsi.exe, bundled DLLs, GPU driver DLLs, and installed OMSI plugins.
static void LogLoadedModules() {
    AppendLine("Loaded modules:");

    if (g_moduleCacheCount == 0) {
        RefreshModuleCache();
    }

    if (g_moduleCacheCount == 0) {
        AppendLine("  <module cache empty>");
        return;
    }

    for (int i = 0; i < g_moduleCacheCount; ++i) {
        const ModuleInfo& module = g_moduleCache[i];
        char line[1024] = {};
        snprintf(
            line,
            sizeof(line),
            "  %s base=0x%08p size=0x%08X path=%s",
            module.name,
            reinterpret_cast<void*>(module.base),
            module.size,
            module.path);
        AppendLine(line);
    }
}

// Write the main exception report. The exception address for Delphi exceptions is
// usually KERNELBASE!RaiseException, so the stack scan below is what helps us
// find return addresses that point back into Omsi.exe or related DLLs.
static void LogContext(PEXCEPTION_POINTERS info) {
    EXCEPTION_RECORD* er = info->ExceptionRecord;
    CONTEXT* ctx = info->ContextRecord;
    uintptr_t address = reinterpret_cast<uintptr_t>(er->ExceptionAddress);

    SYSTEMTIME now = {};
    GetLocalTime(&now);

    ModuleInfo module = {};
    bool hasModule = FindModuleForAddress(address, &module);
    uintptr_t exceptionRva = hasModule ? address - module.base : 0;

    StackCandidate candidates[kMaxStackCandidates] = {};
    int candidateCount = CollectStackCandidates(ctx, candidates, kMaxStackCandidates);

    ExceptionSignature signature = {};
    BuildSignature(er, exceptionRva, candidates, candidateCount, &signature);

    DWORD occurrence = 0;
    bool summaryOnly = false;
    if (!UpdateSignatureStats(signature, &occurrence, &summaryOnly)) {
        return;
    }

    char line[2048] = {};

    if (summaryOnly) {
        snprintf(
            line,
            sizeof(line),
            "Repeated exception signature count=%lu code=0x%08X raiseRva=0x%08X p0=0x%08p p2=0x%08p omsi1=0x%08X omsi2=0x%08X omsi1System=\"%s\" omsi2System=\"%s\"",
            occurrence,
            signature.code,
            static_cast<unsigned>(signature.exceptionRva),
            reinterpret_cast<void*>(signature.param0),
            reinterpret_cast<void*>(signature.param2),
            static_cast<unsigned>(signature.firstOmsiRva),
            static_cast<unsigned>(signature.secondOmsiRva),
            KnownOmsiRvaSystem(signature.firstOmsiRva),
            KnownOmsiRvaSystem(signature.secondOmsiRva));
        AppendLine(line);
        return;
    }

    snprintf(
        line,
        sizeof(line),
        "[%04u-%02u-%02u %02u:%02u:%02u.%03u] exception=%s occurrence=%lu code=0x%08X address=0x%08p module=%s base=0x%08p rva=0x%08X flags=0x%08X params=%lu",
        now.wYear,
        now.wMonth,
        now.wDay,
        now.wHour,
        now.wMinute,
        now.wSecond,
        now.wMilliseconds,
        ExceptionName(er->ExceptionCode),
        occurrence,
        er->ExceptionCode,
        er->ExceptionAddress,
        hasModule ? module.name : "<unknown>",
        hasModule ? reinterpret_cast<void*>(module.base) : nullptr,
        static_cast<unsigned>(exceptionRva),
        er->ExceptionFlags,
        er->NumberParameters);
    AppendLine(line);

    // Delphi exceptions carry useful metadata through exception parameters. We
    // always keep the raw pointers for debugger/Ghidra correlation, and then
    // attempt a guarded best-effort decode of the Exception object below.
    if (er->NumberParameters > 0) {
        char params[2048] = {};
        size_t used = 0;
        used += snprintf(params + used, sizeof(params) - used, "  params:");
        for (DWORD i = 0; i < er->NumberParameters && used < sizeof(params); ++i) {
            used += snprintf(
                params + used,
                sizeof(params) - used,
                " p%lu=0x%08p",
                i,
                reinterpret_cast<void*>(er->ExceptionInformation[i]));
        }
        AppendLine(params);
    }

    LogDelphiExceptionDetails(er);

    // Access violations encode read/write/execute plus the faulting target
    // address in ExceptionInformation[0..1].
    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2) {
        snprintf(
            line,
            sizeof(line),
            "  access=%s target=0x%08p",
            er->ExceptionInformation[0] == 0 ? "read" :
            er->ExceptionInformation[0] == 1 ? "write" :
            er->ExceptionInformation[0] == 8 ? "execute" : "unknown",
            reinterpret_cast<void*>(er->ExceptionInformation[1]));
        AppendLine(line);
    }

    if (ShouldLogMemorySnapshotForException(er, signature, occurrence)) {
        char reason[128] = {};
        snprintf(
            reason,
            sizeof(reason),
            "%s occurrence=%lu",
            ExceptionName(er->ExceptionCode),
            occurrence);
        LogMemorySnapshot(reason);
    }

#if defined(_M_IX86)
    // OMSI is a 32-bit process, so the x86 register set is the one we need.
    // These registers are especially useful for access violations and range
    // checks once we map the fault to disassembly.
    snprintf(
        line,
        sizeof(line),
        "  regs eax=0x%08X ebx=0x%08X ecx=0x%08X edx=0x%08X esi=0x%08X edi=0x%08X ebp=0x%08X esp=0x%08X eip=0x%08X eflags=0x%08X",
        ctx->Eax,
        ctx->Ebx,
        ctx->Ecx,
        ctx->Edx,
        ctx->Esi,
        ctx->Edi,
        ctx->Ebp,
        ctx->Esp,
        ctx->Eip,
        ctx->EFlags);
    AppendLine(line);
#else
    snprintf(line, sizeof(line), "  non-x86 build: context logging is limited");
    AppendLine(line);
#endif

    if (hasModule) {
        snprintf(line, sizeof(line), "  modulePath=%s", module.path);
        AppendLine(line);
    }

    LogKnownOmsiRvaContext(hasModule ? module.name : nullptr, exceptionRva, candidates, candidateCount);

#if defined(_M_IX86)
    // For Delphi's 0x0EEDFADE exceptions, the exception address often points at
    // KERNELBASE!RaiseException. Scanning stack values for module-owned addresses
    // gives us candidate return addresses, usually including the OMSI call site
    // that raised the Delphi exception.
    AppendLine("  stack return candidates:");
    for (int i = 0; i < candidateCount; ++i) {
        snprintf(
            line,
            sizeof(line),
            "    esp+0x%02X value=0x%08X module=%s rva=0x%08X",
            candidates[i].stackOffset,
            static_cast<unsigned>(candidates[i].value),
            candidates[i].module,
            static_cast<unsigned>(candidates[i].rva));
        AppendLine(line);
    }
#endif
}

// Vectored exception handler installed process-wide. Returning
// EXCEPTION_CONTINUE_SEARCH is critical: it means "we only observed this; keep
// dispatching to OMSI/Delphi/Windows exactly as before."
static LONG CALLBACK VectoredExceptionHandler(PEXCEPTION_POINTERS info) {
    if (g_insideHandler) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    DWORD code = info->ExceptionRecord->ExceptionCode;
    if (IsInterestingException(code)) {
        g_insideHandler = true;
        LogContext(info);
        g_insideHandler = false;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// OMSI plugin entry point. Existing plugins show that OMSI calls PluginStart
// with one 32-bit argument, so the export is __stdcall(void*).
extern "C" void __stdcall PluginStart(void* omsiContext) {
    (void)omsiContext;

    if (!g_lockReady) {
        InitializeCriticalSection(&g_logLock);
        g_lockReady = true;
    }

    BuildLogPath();
    AppendLine("OmsiCrashProbe PluginStart");
    LogMemorySnapshot("PluginStart");

    // Install with first priority so we can see first-chance exceptions before
    // OMSI's own handlers turn them into generic popups or logfile messages.
    if (!g_vectoredHandler) {
        g_vectoredHandler = AddVectoredExceptionHandler(1, VectoredExceptionHandler);
        AppendLine(g_vectoredHandler ? "Vectored exception handler installed" : "Failed to install vectored exception handler");
    }

    RefreshModuleCache();
    LogLoadedModules();
}

// OMSI plugin shutdown hook. Remove the vectored handler and destroy the lock so
// a clean OMSI exit does not leave process-global state dangling.
extern "C" void __stdcall PluginFinalize() {
    if (g_vectoredHandler) {
        RemoveVectoredExceptionHandler(g_vectoredHandler);
        g_vectoredHandler = nullptr;
    }

    AppendLine("OmsiCrashProbe PluginFinalize");
    LogMemorySnapshot("PluginFinalize");
    LogSignatureSummary();

    if (g_lockReady) {
        DeleteCriticalSection(&g_logLock);
        g_lockReady = false;
    }
}

// Keep DllMain tiny: doing real work in DllMain is risky because the Windows
// loader lock is held. PluginStart/PluginFinalize do the real initialization.
BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
    (void)module;
    (void)reserved;

    if (reason == DLL_PROCESS_DETACH && g_vectoredHandler) {
        RemoveVectoredExceptionHandler(g_vectoredHandler);
        g_vectoredHandler = nullptr;
    }

    return TRUE;
}
