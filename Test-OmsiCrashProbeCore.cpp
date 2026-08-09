// Offline white-box tests for fixed-size handler data structures. Including
// the implementation keeps production helpers static and avoids exporting a
// test API from the OMSI plugin DLL.
#include "OmsiCrashProbe.cpp"

#include <cstdio>

static HANDLE g_testLockHeld = nullptr;
static HANDLE g_testReleaseLock = nullptr;

static DWORD WINAPI HoldProbeLock(LPVOID) {
    EnterCriticalSection(&g_logLock);
    SetEvent(g_testLockHeld);
    WaitForSingleObject(g_testReleaseLock, INFINITE);
    LeaveCriticalSection(&g_logLock);
    return 0;
}

static bool Check(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "FAILED: %s\n", message);
        return false;
    }
    return true;
}

int main() {
    bool ok = true;
    InitializeCriticalSection(&g_logLock);
    g_lockReady = true;

    volatile LONG saturating = LONG_MAX - 1;
    IncrementSaturating(&saturating);
    IncrementSaturating(&saturating);
    ok &= Check(saturating == LONG_MAX, "saturating counter must stop at LONG_MAX");

    DWORD words[kMaxStackCandidates] = {};
    for (int i = 0; i < kMaxStackCandidates; ++i) {
        words[i] = 0x1000u + static_cast<DWORD>(i * 4);
    }
    ExceptionSignature signature = {};
    signature.code = 0x0EEDFADE;
    signature.exceptionRva = 0x21124;
    signature.param2 = 8;
    signature.firstOmsiRva = 0x3D620D;

    StoreStackSignatureCache(
        signature.code, signature.exceptionRva, signature.param0, signature.param2,
        words, kMaxStackCandidates, signature);
    ExceptionSignature cached = {};
    ok &= Check(
        TryGetStackSignatureCache(
            signature.code, signature.exceptionRva, signature.param0, signature.param2,
            words, kMaxStackCandidates, &cached),
        "exact stack cache lookup must hit");
    ok &= Check(SameSignature(signature, cached), "stack cache must preserve the exact signature");

    DWORD collidingWords[kMaxStackCandidates] = {};
    memcpy(collidingWords, words, sizeof(words));
    unsigned originalIndex = StackSignatureCacheIndex(
        signature.code, signature.exceptionRva, signature.param0, signature.param2,
        words, kMaxStackCandidates);
    do {
        collidingWords[0] += 1;
    } while (StackSignatureCacheIndex(
        signature.code, signature.exceptionRva, signature.param0, signature.param2,
        collidingWords, kMaxStackCandidates) != originalIndex);
    StoreStackSignatureCache(
        signature.code, signature.exceptionRva, signature.param0, signature.param2,
        collidingWords, kMaxStackCandidates, signature);
    ok &= Check(
        !TryGetStackSignatureCache(
            signature.code, signature.exceptionRva, signature.param0, signature.param2,
            words, kMaxStackCandidates, &cached),
        "direct-mapped collision must not return a false hit");

    memset(g_signatureStats, 0, sizeof(g_signatureStats));
    g_signatureTableOverflowOccurrences = 0;
    for (int i = 0; i < kMaxSignatureStats; ++i) {
        ExceptionSignature item = {};
        item.code = EXCEPTION_ACCESS_VIOLATION;
        item.firstOmsiRva = static_cast<uintptr_t>(i + 1);
        DWORD itemOccurrence = 0;
        bool itemSummaryOnly = false;
        ok &= Check(UpdateSignatureStats(item, &itemOccurrence, &itemSummaryOnly), "new signature slot must be accepted");
        ok &= Check(itemOccurrence == 1 && !itemSummaryOnly, "new signature must request one full record");
    }
    ExceptionSignature overflow = {};
    overflow.code = EXCEPTION_ILLEGAL_INSTRUCTION;
    DWORD occurrence = 0;
    bool summaryOnly = false;
    ok &= Check(
        !UpdateSignatureStats(overflow, &occurrence, &summaryOnly),
        "full signature table must drop rather than emit an unbounded full record");
    ok &= Check(g_signatureTableOverflowOccurrences == 1, "signature overflow must be counted");

    memset(g_signatureStats, 0, sizeof(g_signatureStats));
    g_droppedSignatureUpdates = 0;
    g_testLockHeld = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    g_testReleaseLock = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    HANDLE thread = CreateThread(nullptr, 0, HoldProbeLock, nullptr, 0, nullptr);
    WaitForSingleObject(g_testLockHeld, INFINITE);
    g_insideHandler = true;
    ok &= Check(
        !UpdateSignatureStats(signature, &occurrence, &summaryOnly),
        "handler-side lock contention must not block or update");
    g_insideHandler = false;
    ok &= Check(g_droppedSignatureUpdates == 1, "contended signature update must be counted");
    SetEvent(g_testReleaseLock);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    CloseHandle(g_testLockHeld);
    CloseHandle(g_testReleaseLock);

    g_lockReady = false;
    DeleteCriticalSection(&g_logLock);
    if (!ok) {
        return 1;
    }

    std::puts("All probe core offline tests passed.");
    return 0;
}
