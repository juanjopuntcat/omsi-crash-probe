#pragma once

#include <array>
#include <cstdint>
#include <string>

// Confidence describes evidence identification, never permission to patch.
// Zero means no reliable code RVA; literal pointers stay in the finding text.
struct BugEntry {
    uint32_t rva;
    const wchar_t* title;
    const wchar_t* category;
    const wchar_t* status;
    const wchar_t* confidence;
    const wchar_t* anchor;
    const wchar_t* description;
    const char* patchId;
};

inline constexpr std::array<BugEntry, 42> kBugs = {{
    // H01: see documented-exception-audit.md.
    {0x00405D60, L"DirectSound AV at 6738C862", L"Audio", L"Deferred", L"Medium", L"0x00405D60",
        L"The OMSI WAV/DirectSound loader is mapped at RVA 0x00405D60 (context only). Unresolved: The reported DLL build, load base, registers and caller are unknown; the DLL address cannot be mapped to this OMSI RVA.", nullptr},
    // H02: see documented-exception-audit.md.
    {0x002421CE, L"Omsi AV at 006421CE", L"Access violation", L"Deferred", L"High", L"0x002421CE",
        L"The CALL at 006421CE reaches a nested line writer in situation-file serialization; its string and destination context are traced. Unresolved: The reported read from 0x28 still does not match the local instruction path. Original build and fault registers are missing.", nullptr},
    // H03: see documented-exception-audit.md.
    {0x00024F68, L"Invalid floating-point value", L"Parser", L"Deferred", L"High", L"0x00024F68",
        L"The shared text-to-float parser has numerous loader callers. Unresolved: The token, locale, field contract and owning loader are missing; a default value has no justified semantics.", nullptr},
    // H04: see documented-exception-audit.md.
    {0x00000000, L"Unmapped AV at 3212AF30", L"Unknown module", L"Deferred", L"Low", L"Unresolved",
        L"The report supplies an instruction address and a read address only. Unresolved: The containing module, image base and binary version are absent. No local RVA can be assigned.", nullptr},
    // H05: see documented-exception-audit.md.
    {0x0042ADE3, L"AI cleanup missing list head", L"Access violation", L"Deferred", L"High", L"0x0042ADE3",
        L"Prior disassembly reads [head+0x20] after a global dereference; a branch reaches RVA 0x0042AE5D. Unresolved: The owner's lifetime and null-state contract are unproven. The car log pointer at 0x0042AE2C precedes that target; calling the target the car-cleanup entry was unjustified.", "omsi-ai-cleanup-null-list-head"},
    // H06: see documented-exception-audit.md.
    {0x002EFD03, L"RS.HumansOutside null list entry", L"Access violation", L"Deferred", L"High", L"0x002EFD03",
        L"Prior disassembly reads [EAX+0x5BC] after selecting a list entry. Zero EAX explains the reported access on a matching build. Unresolved: It remains unproven that null is a valid skippable entry rather than broken ownership. Complete loop invariants and the continuation at 0x002EFEFC are unresolved.", "omsi-humans-outside-null-entry"},
    // H07: see documented-exception-audit.md.
    {0x00006E6C, L"visu drivers translate 2 AV", L"Delphi runtime", L"Deferred", L"High", L"0x00006E6C",
        L"Ghidra confirms MOV EAX,[EAX] inside the shared helper at RVA 0x00006E68. Unresolved: The originating object and caller are unknown; the context literal was not found by the focused string pass.", nullptr},
    // H08: see documented-exception-audit.md.
    {0x00028E06, L"External exception C06D007E", L"External module", L"Deferred", L"Medium-low", L"0x00028E06",
        L"RVA 0x00028E06 is associated with generic external-exception formatting. Unresolved: The throwing module and actual dependency failure are not established. A dependency-load explanation remains a hypothesis.", nullptr},
    // H09: see documented-exception-audit.md.
    {0x00000000, L"The requested resource is in use", L"Resources", L"Deferred", L"Low", L"Unresolved",
        L"The supplied text has no module, numeric error code or stack; the focused string pass found no match. Unresolved: Resource contention, an API failure and its owner cannot be distinguished from this text.", nullptr},
    // H10: see documented-exception-audit.md.
    {0x0042A386, L"Reset failed: D3DERR_DEVICELOST", L"Direct3D", L"Deferred", L"High", L"0x0042A386",
        L"Prior analysis maps the reset call/result branch near RVA 0x0042A386. Unresolved: The device state, reset preconditions, resource ownership and correct retry policy are unproven.", nullptr},
    // H11: see documented-exception-audit.md.
    {0x0042A386, L"Reset failed: Unknown", L"Direct3D", L"Deferred", L"Medium", L"0x0042A386",
        L"The reset error formatter is mapped, but this report only contains Unknown. Unresolved: The original numeric HRESULT is missing; it cannot be assumed to equal DEVICELOST or INVALIDCALL.", nullptr},
    // H12: see documented-exception-audit.md.
    {0x0042A386, L"Reset failed: D3DERR_INVALIDCALL", L"Direct3D", L"Deferred", L"High", L"0x0042A386",
        L"The mapped reset-result branch formats this reported HRESULT. Unresolved: The violated reset precondition is unknown; retained resources and invalid parameters have not been distinguished.", nullptr},
    // H13: see documented-exception-audit.md.
    {0x0004DD85, L"Range-check error", L"Delphi runtime", L"Deferred", L"High", L"0x0004DD85",
        L"The exception catalog and explicit range-check raise path are mapped. Unresolved: The failing index/value and OMSI owner are absent. Suppressing this guard has no established valid result.", nullptr},
    // H14: see documented-exception-audit.md.
    {0x00429FD8, L"Direct3D device lost notification", L"Direct3D", L"Deferred", L"High", L"0x00429FD8",
        L"RVA 0x00429FD8 is a logging/dispatch path for the device-lost message. Unresolved: The notification alone does not establish a fatal error or a defective recovery branch.", nullptr},
    // H15: see documented-exception-audit.md.
    {0x00070890, L"Invalid bitmap", L"Graphics resources", L"Deferred", L"High", L"0x00070890",
        L"The bitmap-invalid helper is mapped. Unresolved: Invalid input, an allocation failure and invalid object state remain distinct possible causes; the loader is unknown.", nullptr},
    // H16: see documented-exception-audit.md.
    {0x0011FF8C, L"Argument outside range", L"Delphi runtime", L"Deferred", L"High", L"0x0011FF8C",
        L"The message is shared by many argument checks; the RVA is one diagnostic cluster. Unresolved: The specific method and argument contract are missing.", nullptr},
    // H17: see documented-exception-audit.md.
    {0x00000000, L"Missing context-sensitive help", L"Help", L"Deferred", L"Medium", L"Unresolved",
        L"Ghidra finds the PascalUnicode resource at data RVA 0x004CB6BE, with no useful xref in this pass. Unresolved: A help-provider registration or missing installation component is possible; no failing engine instruction is identified.", nullptr},
    // H18: see documented-exception-audit.md.
    {0x00008850, L"Delphi helper AV at 00408850", L"Delphi runtime", L"Deferred", L"High", L"0x00008850",
        L"Ghidra confirms MOV EDX,[EAX-8] in shared helper FUN_0040884C. Unresolved: The report is consistent with EAX=0x3F800000 on this build, but neither value origin nor object type is known.", nullptr},
    // H19: see documented-exception-audit.md.
    {0x0002A000, L"Systemfehler Code 8", L"Memory / resources", L"Deferred", L"High", L"0x0002A000",
        L"The system-error wrapper is mapped. The trailing OS message is localized and is not a stable identifier. Unresolved: Code 8 does not distinguish address-space pressure, fragmentation, graphics resources or the owning allocation.", nullptr},
    // H20: see documented-exception-audit.md.
    {0x00011610, L"Floating-point division by zero", L"Calculation", L"Deferred", L"High", L"0x00011610",
        L"The generic floating-point exception path is mapped. Unresolved: The originating arithmetic operation and a valid zero-denominator policy are unknown.", nullptr},
    // H21: see documented-exception-audit.md.
    {0x003C400E, L"POI.GHAA - C access violation", L"Access violation", L"Deferred", L"High", L"0x003C400E",
        L"A triangle-normal routine reloads owner+0xA0 after a mesh-buffer call and dereferences it at 007C400E. Lock results are unchecked. Unresolved: Pointer lifetime, lock cleanup and caller output validity are unproven; a null-skip is not justified.", nullptr},
    // H22: see documented-exception-audit.md.
    {0x000B57F4, L"List index exceeds maximum", L"Delphi runtime", L"Deferred", L"High", L"0x000B57F4",
        L"The shared list-error machinery is mapped. Unresolved: The list owner, index and expected behavior for a missing element are absent.", nullptr},
    // H23: see documented-exception-audit.md.
    {0x00428140, L"World/UI missing text subobject", L"Access violation", L"Deferred", L"High", L"0x00428140",
        L"Prior Ghidra analysis maps the +0x100 / +0x5C / +0x1F0 object chain. Unresolved: A null child explains this access on a matching build; an empty Delphi string is still an unproven fallback with unresolved ownership and later UI invariants.", "omsi-world-ui-null-subobject"},
    // H24: see documented-exception-audit.md.
    {0x00000000, L"T.PlugInRefrVars zero-address AV", L"Plugins", L"Deferred", L"Medium", L"Unresolved",
        L"Ghidra finds the context literal at data RVA 0x002F5F2C and a pointer at 0x002F4F1D. Unresolved: A null callback is only a hypothesis. Address zero is not a module RVA; the callback contract, plugin and stack are unknown.", nullptr},
    // H25: see documented-exception-audit.md.
    {0x00000000, L"d3d9 AV: CMOI.R.3", L"Direct3D", L"Deferred", L"Low", L"Unresolved",
        L"The report identifies d3d9.dll and a CMOI.R.3 context. The focused string pass found no exact CMOI.R.3 literal. Unresolved: The original DLL hash/load base and OMSI caller are missing; a DLL RVA and object lifetime cannot be inferred.", nullptr},
    // H26: see documented-exception-audit.md.
    {0x00000000, L"d3d9 AV: RS.SkyLights", L"Direct3D", L"Deferred", L"Medium", L"Unresolved",
        L"Ghidra finds RS.SkyLights at data RVA 0x002F27BC and a log pointer at 0x002F166D. Unresolved: The log pointer is not the d3d9 fault location. The DLL build, load base and calling object are unknown.", nullptr},
    // H27: see documented-exception-audit.md.
    {0x00004911, L"EZeroDivide reported at offset 00004911", L"Calculation", L"Deferred", L"Medium", L"0x00004911",
        L"Treating 00004911 as an RVA yields FILD qword ptr [EAX] in FUN_004048B4 in the local binary. Unresolved: That instruction is not a division. The report's address convention, build and original floating-point fault context are unverified.", nullptr},
    // H28: see documented-exception-audit.md.
    {0x00000000, L"Out of memory: P.KillNotNeededBuses", L"Memory / resources", L"Deferred", L"Medium", L"Unresolved",
        L"Ghidra reconfirms the log pointer at RVA 0x0042ADA0. Unresolved: This is an OOM report, distinct from the head-null AV. The failing allocation and cleanup owner's full state are unknown.", nullptr},
    // H29: see documented-exception-audit.md.
    {0x00000000, L"Out of memory: P.KNNC.KM", L"Memory / resources", L"Deferred", L"Low", L"Unresolved",
        L"The context is recorded verbatim; the focused defined-string pass found no exact match. Unresolved: The label's owner and failing allocation remain unresolved. A negative string search does not prove absence from the executable.", nullptr},
    // H30: see documented-exception-audit.md.
    {0x00000000, L"Out of memory: CV.Calculate - I", L"Simulation", L"Deferred", L"Medium", L"Unresolved",
        L"Ghidra finds the context string at RVA 0x003D8DA0 and a log pointer at 0x003D60A4. Unresolved: The checkpoint is not an allocation site; the allocator, requested size and cause of failure are unknown.", nullptr},
    // H31: see documented-exception-audit.md.
    {0x00000000, L"Range check: CV.Calculate - J2", L"Simulation", L"Deferred", L"Medium", L"Unresolved",
        L"Ghidra reconfirms the log pointer at RVA 0x003D620D inside the wider calculation region. Unresolved: The specific checked index and exception origin are unknown; nearby exception-handling code cannot be treated as the failing operation.", nullptr},
    // H32: see documented-exception-audit.md.
    {0x00000000, L"Range check: CMO.UnschedClearSteuerl", L"Simulation", L"Deferred", L"Medium", L"Unresolved",
        L"Ghidra finds the context at RVA 0x003032F0 with pointers at 0x003013E9, 0x00301468, 0x003014E7 and 0x00301566. Unresolved: Four log sites do not identify which bounds check failed or the correct scheduling-state recovery.", nullptr},
    // H33: see documented-exception-audit.md.
    {0x00072F90, L"Unknown image extension (.png)", L"Graphics resources", L"Deferred", L"High", L"0x00072F90",
        L"The unsupported-extension path is mapped separately from the invalid-bitmap helper. Unresolved: The active loader and its registered decoders are unknown. Extension acceptance alone cannot provide PNG decoding.", nullptr},
    // H34: see documented-exception-audit.md.
    {0x00000000, L"NVIDIA driver AV at 5FC7184E", L"Graphics driver", L"Deferred", L"Low", L"Unresolved",
        L"The report names the NVIDIA user-mode driver and two addresses. Unresolved: The driver version, hash, base address and preceding graphics calls are missing; responsibility cannot be assigned to the driver or OMSI.", nullptr},
    // H35: see documented-exception-audit.md.
    {0x00000000, L"Unmapped AV at 7CC92950", L"Unknown module", L"Deferred", L"Low", L"Unresolved",
        L"The report gives equal instruction/read addresses without a module. Unresolved: Equality alone does not establish an execution violation. The exception record, memory map and module are unknown.", nullptr},
    // H36: see documented-exception-audit.md.
    {0x001D378D, L"Invalid script variable or command", L"Script parser", L"Deferred", L"High", L"0x001D378D",
        L"Prior Ghidra analysis maps negative symbol lookups in the script parser. Unresolved: A parser defect has not been demonstrated; the command, declaration and script compatibility contract are unknown.", nullptr},
    // H37: see documented-exception-audit.md.
    {0x001D49B0, L"Omsi AV at 005D49B0", L"Access violation", L"Deferred", L"High", L"0x001D49B0",
        L"Ghidra confirms RET at the reported local-build address. Unresolved: A RET alone does not prove stack corruption or explain this read. The report's build and exception registers are absent.", nullptr},
    // H38: see documented-exception-audit.md.
    {0x00429C09, L"Omsi AV at 00829C09", L"Access violation", L"Deferred", L"Medium", L"0x00429C09",
        L"The clean Ghidra listing still marks byte D8 as undefined here. Older linear-disassembly notes suggest a floating-point field access. Unresolved: Instruction boundaries, pointer ownership and the public report's build are unresolved; a stale pointer has not been proven.", nullptr},
    // H39: see documented-exception-audit.md.
    {0x00006B14, L"Delphi helper AV at 00406B14", L"Delphi runtime", L"Deferred", L"High", L"0x00006B14",
        L"Ghidra confirms CALL dword ptr [ECX-4] in FUN_00406B0C. Unresolved: Zero ECX explains the read on this build, but its producing caller, object contract and valid recovery are unknown.", nullptr},
    // E01: see documented-exception-audit.md.
    {0x0024307C, L"Direct3D texture allocation failure", L"Memory / graphics", L"Deferred", L"High", L"0x0024307C",
        L"Prior analysis maps the D3DX texture loaders and release paths. Unresolved: Allocation pressure, retained references and address-space fragmentation are not distinguished.", nullptr},
    // E02: see documented-exception-audit.md.
    {0x0004DF1C, L"Stream read or write failure", L"File I/O", L"Deferred", L"High", L"0x0004DF1C",
        L"Prior analysis maps shared stream helpers with many independent callers. Unresolved: The loader, requested byte count and source-data validity are unknown; successful recovery is unproven.", nullptr},
    // E03: see documented-exception-audit.md.
    {0x003D5374, L"Map or vehicle update failure", L"Simulation", L"Deferred", L"Medium", L"0x003D5374",
        L"The existing catalog includes a broad simulation owner and separate map/tile contexts. Unresolved: This family is broader than the individual CV.Calculate checkpoints; the failing operation is unresolved.", nullptr},
}};

// A shared context RVA must never attach a fix to another reported failure.
// Binary identity/bytes and installation state are still audited by PatchCore.
inline bool MatchesBugPatch(
    const BugEntry& bug, const std::string& id, uint32_t rva, const std::wstring& target) {
    return bug.patchId != nullptr && id == bug.patchId &&
        bug.rva != 0 && rva == bug.rva && target == L"Omsi.exe";
}
