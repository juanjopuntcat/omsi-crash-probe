#include "PatchCore.h"
#include "PatchManifest.h"

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <string>
#include <vector>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")

namespace {

constexpr wchar_t kWindowClass[] = L"OmsiCrashProbeGuiWindow";
constexpr wchar_t kKnownHash[] = L"7DAB063D1F62E73B3A2C7A6AC1921D7EDF5E5DB0FBC731481D117EEC8DE7D759";

enum ControlId {
    IdPath = 1001,
    IdBrowse,
    IdInspect,
    IdBugList,
    IdApply,
    IdFilter
};

enum DialogButtonId {
    IdDialogApply = 2001,
    IdDialogRollback
};

struct BugDialogState {
    bool canApply;
    bool canRollback;
};

struct BugEntry {
    uint32_t rva;
    const wchar_t* title;
    const wchar_t* category;
    const wchar_t* status;
    const wchar_t* confidence;
    const wchar_t* anchor;
    const wchar_t* description;
    bool fixAvailable;
};

constexpr std::array<BugEntry, 17> kBugs = {{
    {0x002EFD03, L"RS.HumansOutside null list entry", L"Access violation", L"Control-flow analysis", L"High", L"0x002EFD03", L"A null list entry is read at object field +0x5BC.", false},
    {0x00428140, L"World/UI missing text subobject", L"Access violation", L"Trampoline design", L"High", L"0x00428140", L"A missing +0x5C subobject is used as a UI string source.", false},
    {0x0042ADE3, L"AI cleanup missing list head", L"Access violation", L"Control-flow analysis", L"Medium", L"0x0042ADE3", L"Bus cleanup dereferences a missing global list head.", false},
    {0x00429FD8, L"Direct3D device lost or reset", L"Direct3D", L"Documented", L"High", L"0x00429FD8", L"Device reset can fail with DEVICELOST, INVALIDCALL, or unknown HRESULT.", false},
    {0x0024307C, L"Direct3D texture allocation failure", L"Memory / graphics", L"Documented", L"High", L"0x0024307C", L"Texture creation fails under allocation pressure or fragmented address space.", false},
    {0x0002A000, L"Systemfehler Code 8", L"Memory / resources", L"Documented", L"High", L"0x0002A000", L"Windows cannot provide enough memory resources for the requested operation.", false},
    {0x00070890, L"Invalid bitmap or image", L"Graphics resources", L"Documented", L"High", L"0x00070890", L"Bitmap state, extension, GDI allocation, or image validation fails.", false},
    {0x0004DD85, L"Range-check error", L"Delphi runtime", L"Documented", L"High", L"0x0004DD85", L"An index or numeric operation violates a compiled Delphi range check.", false},
    {0x000B57F4, L"List index exceeds maximum", L"Delphi runtime", L"Documented", L"High", L"0x000B57F4", L"A list is accessed outside its valid bounds.", false},
    {0x0011FF8C, L"Argument outside range", L"Delphi runtime", L"Documented", L"High", L"0x0011FF8C", L"A method receives an index or length outside its accepted range.", false},
    {0x00024F68, L"Invalid floating-point value", L"Parser", L"Documented", L"High", L"0x00024F68", L"Text input cannot be converted to the expected floating-point value.", false},
    {0x00011610, L"Floating-point division by zero", L"Calculation", L"Documented", L"High", L"0x00011610", L"A vehicle or engine calculation divides by zero.", false},
    {0x0004DF1C, L"Stream read or write failure", L"File I/O", L"Documented", L"Medium-high", L"0x0004DF1C", L"A generic stream operation cannot read or write the requested data.", false},
    {0x001D378D, L"Invalid script variable or command", L"Script parser", L"Documented", L"High", L"0x001D378D", L"A script refers to an unknown variable, macro, constant, or function.", false},
    {0x003D5374, L"Map or vehicle update failure", L"Simulation", L"Documented", L"Medium", L"0x003D5374", L"Failures around map translation, tile refresh, or CV.Calculate.", false},
    {0x00405D60, L"DirectSound access violation", L"Audio", L"Documented", L"Medium", L"0x00405D60", L"A sound load or DirectSound buffer operation reaches invalid state.", false},
    {0x00028E06, L"External exception C06D007E", L"External module", L"Documented", L"Medium-low", L"0x00028E06", L"An external dependency or delayed import cannot be resolved.", false}
}};

HWND g_path = nullptr;
HWND g_browse = nullptr;
HWND g_inspect = nullptr;
HWND g_list = nullptr;
HWND g_apply = nullptr;
HWND g_identity = nullptr;
HWND g_compatibility = nullptr;
HWND g_fixSummary = nullptr;
HWND g_title = nullptr;
HWND g_subtitle = nullptr;
HWND g_pathLabel = nullptr;
HWND g_bugsLabel = nullptr;
HWND g_filter = nullptr;
HFONT g_uiFont = nullptr;
HFONT g_titleFont = nullptr;
HFONT g_sectionFont = nullptr;
HBRUSH g_backgroundBrush = nullptr;
HBRUSH g_headerBrush = nullptr;
HBRUSH g_panelBrush = nullptr;
omsi_patch::PatchManifest g_manifest;
enum class FixState { None, Incompatible, Available, Applied };
std::array<int, kBugs.size()> g_bugPatchIndex = {};
std::array<FixState, kBugs.size()> g_fixStates = {};
std::wstring g_omsiRoot;
bool g_manifestLoaded = false;
int g_sortColumn = 0;
bool g_sortAscending = true;

constexpr COLORREF kBackground = RGB(244, 246, 247);
constexpr COLORREF kHeader = RGB(34, 39, 41);
constexpr COLORREF kPanel = RGB(255, 255, 255);
constexpr COLORREF kText = RGB(35, 42, 45);
constexpr COLORREF kMuted = RGB(102, 113, 118);
constexpr COLORREF kAccent = RGB(20, 126, 116);
constexpr COLORREF kAccentPressed = RGB(15, 103, 95);
constexpr COLORREF kBorder = RGB(216, 222, 224);

std::wstring Wide(const std::string& text) {
    if (text.empty()) return {};
    const int count = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring result(static_cast<size_t>(count), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), result.data(), count);
    return result;
}

void SetFont(HWND control, HFONT font = nullptr) {
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font ? font : g_uiFont), TRUE);
}

HWND AddControl(HWND parent, const wchar_t* cls, const wchar_t* text, DWORD style, int id = 0) {
    HWND control = CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style,
        0, 0, 0, 0, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), nullptr);
    SetFont(control);
    return control;
}

void AddColumn(int index, int width, const wchar_t* title) {
    LVCOLUMNW column = {};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    column.pszText = const_cast<wchar_t*>(title);
    column.cx = width;
    column.iSubItem = index;
    ListView_InsertColumn(g_list, index, &column);
}

void FillSolidRect(HDC dc, const RECT& rect, COLORREF color) {
    HBRUSH brush = CreateSolidBrush(color);
    FillRect(dc, &rect, brush);
    DeleteObject(brush);
}

void DrawPanel(HDC dc, const RECT& rect) {
    FillRect(dc, &rect, g_panelBrush);
    HPEN pen = CreatePen(PS_SOLID, 1, kBorder);
    HGDIOBJ oldPen = SelectObject(dc, pen);
    HGDIOBJ oldBrush = SelectObject(dc, GetStockObject(NULL_BRUSH));
    RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, 8, 8);
    SelectObject(dc, oldBrush);
    SelectObject(dc, oldPen);
    DeleteObject(pen);
}

void DrawButton(const DRAWITEMSTRUCT& item) {
    const bool disabled = (item.itemState & ODS_DISABLED) != 0;
    const bool pressed = (item.itemState & ODS_SELECTED) != 0;
    COLORREF background = disabled ? RGB(222, 226, 227) : (pressed ? kAccentPressed : kAccent);
    COLORREF foreground = disabled ? RGB(143, 151, 154) : RGB(255, 255, 255);
    FillSolidRect(item.hDC, item.rcItem, kBackground);
    HBRUSH brush = CreateSolidBrush(background);
    HPEN pen = CreatePen(PS_SOLID, 1, background);
    HGDIOBJ oldBrush = SelectObject(item.hDC, brush);
    HGDIOBJ oldPen = SelectObject(item.hDC, pen);
    RoundRect(item.hDC, item.rcItem.left, item.rcItem.top, item.rcItem.right,
        item.rcItem.bottom, 7, 7);
    SelectObject(item.hDC, oldPen);
    SelectObject(item.hDC, oldBrush);
    DeleteObject(pen);
    DeleteObject(brush);
    wchar_t text[96] = {};
    GetWindowTextW(item.hwndItem, text, static_cast<int>(std::size(text)));
    SetBkMode(item.hDC, TRANSPARENT);
    SetTextColor(item.hDC, foreground);
    SelectObject(item.hDC, g_uiFont);
    RECT textRect = item.rcItem;
    DrawTextW(item.hDC, text, -1, &textRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    if ((item.itemState & ODS_FOCUS) != 0 && !disabled) {
        RECT focus = item.rcItem;
        InflateRect(&focus, -4, -4);
        DrawFocusRect(item.hDC, &focus);
    }
}

LRESULT DrawBugList(NMLVCUSTOMDRAW* draw) {
    switch (draw->nmcd.dwDrawStage) {
        case CDDS_PREPAINT:
            return CDRF_NOTIFYITEMDRAW;
        case CDDS_ITEMPREPAINT:
            return CDRF_NOTIFYSUBITEMDRAW;
        case CDDS_ITEMPREPAINT | CDDS_SUBITEM: {
            const size_t row = static_cast<size_t>(draw->nmcd.dwItemSpec);
            LVITEMW item = {};
            item.mask = LVIF_PARAM;
            item.iItem = static_cast<int>(row);
            ListView_GetItem(g_list, &item);
            const size_t bugIndex = static_cast<size_t>(item.lParam);
            draw->clrText = kText;
            draw->clrTextBk = row % 2 == 0 ? RGB(255, 255, 255) : RGB(248, 250, 250);
            if (draw->iSubItem == 2 && bugIndex < g_fixStates.size()) {
                if (g_fixStates[bugIndex] == FixState::Available) draw->clrText = RGB(0, 112, 83);
                if (g_fixStates[bugIndex] == FixState::Applied) draw->clrText = RGB(30, 92, 165);
                if (g_fixStates[bugIndex] == FixState::Incompatible) draw->clrText = RGB(170, 68, 45);
            }
            return CDRF_NEWFONT;
        }
    }
    return CDRF_DODEFAULT;
}

const wchar_t* FixStatus(size_t bugIndex) {
    if (g_fixStates[bugIndex] == FixState::Available) return L"Available";
    if (g_fixStates[bugIndex] == FixState::Applied) return L"Applied";
    if (g_fixStates[bugIndex] == FixState::Incompatible) return L"Incompatible";
    if (g_bugPatchIndex[bugIndex] >= 0) return L"Fix documented";
    return kBugs[bugIndex].status;
}

bool BugIndexFromRow(int row, size_t* bugIndex) {
    if (row < 0 || bugIndex == nullptr) return false;
    LVITEMW item = {};
    item.mask = LVIF_PARAM;
    item.iItem = row;
    if (!ListView_GetItem(g_list, &item)) return false;
    const size_t index = static_cast<size_t>(item.lParam);
    if (index >= kBugs.size()) return false;
    *bugIndex = index;
    return true;
}

int CompareBugs(size_t left, size_t right) {
    const BugEntry& a = kBugs[left];
    const BugEntry& b = kBugs[right];
    if (g_sortColumn == 4) {
        if (a.rva < b.rva) return -1;
        if (a.rva > b.rva) return 1;
        return 0;
    }
    const wchar_t* leftText = a.title;
    const wchar_t* rightText = b.title;
    if (g_sortColumn == 1) { leftText = a.category; rightText = b.category; }
    if (g_sortColumn == 2) { leftText = FixStatus(left); rightText = FixStatus(right); }
    if (g_sortColumn == 3) { leftText = a.confidence; rightText = b.confidence; }
    if (g_sortColumn == 5) { leftText = a.description; rightText = b.description; }
    return _wcsicmp(leftText, rightText);
}

void UpdateSortIndicator() {
    HWND header = ListView_GetHeader(g_list);
    const int count = Header_GetItemCount(header);
    for (int column = 0; column < count; ++column) {
        HDITEMW item = {};
        item.mask = HDI_FORMAT;
        Header_GetItem(header, column, &item);
        item.fmt &= ~(HDF_SORTUP | HDF_SORTDOWN);
        if (column == g_sortColumn) item.fmt |= g_sortAscending ? HDF_SORTUP : HDF_SORTDOWN;
        Header_SetItem(header, column, &item);
    }
}

void UpdateActionButton();

void PopulateBugs() {
    size_t selectedBug = kBugs.size();
    BugIndexFromRow(ListView_GetNextItem(g_list, -1, LVNI_SELECTED), &selectedBug);
    const int filter = g_filter == nullptr ? 0 : static_cast<int>(SendMessageW(g_filter, CB_GETCURSEL, 0, 0));
    std::vector<size_t> visible;
    for (size_t index = 0; index < kBugs.size(); ++index) {
        const bool hasFix = g_bugPatchIndex[index] >= 0;
        if ((filter == 1 && !hasFix) || (filter == 2 && hasFix)) continue;
        visible.push_back(index);
    }
    std::stable_sort(visible.begin(), visible.end(), [](size_t left, size_t right) {
        const int comparison = CompareBugs(left, right);
        return g_sortAscending ? comparison < 0 : comparison > 0;
    });
    ListView_DeleteAllItems(g_list);
    for (size_t rowIndex = 0; rowIndex < visible.size(); ++rowIndex) {
        const size_t index = visible[rowIndex];
        const BugEntry& bug = kBugs[index];
        LVITEMW item = {};
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = static_cast<int>(rowIndex);
        item.pszText = const_cast<wchar_t*>(bug.title);
        item.lParam = static_cast<LPARAM>(index);
        const int row = ListView_InsertItem(g_list, &item);
        ListView_SetItemText(g_list, row, 1, const_cast<wchar_t*>(bug.category));
        ListView_SetItemText(g_list, row, 2, const_cast<wchar_t*>(FixStatus(index)));
        ListView_SetItemText(g_list, row, 3, const_cast<wchar_t*>(bug.confidence));
        ListView_SetItemText(g_list, row, 4, const_cast<wchar_t*>(bug.anchor));
        ListView_SetItemText(g_list, row, 5, const_cast<wchar_t*>(bug.description));
        if (index == selectedBug) ListView_SetItemState(g_list, row, LVIS_SELECTED | LVIS_FOCUSED,
            LVIS_SELECTED | LVIS_FOCUSED);
    }
    UpdateSortIndicator();
    UpdateActionButton();
}

std::wstring SelectedPath() {
    const int length = GetWindowTextLengthW(g_path);
    std::wstring path(static_cast<size_t>(length + 1), L'\0');
    GetWindowTextW(g_path, path.data(), length + 1);
    path.resize(static_cast<size_t>(length));
    return path;
}

std::wstring PatchTarget(const omsi_patch::ManifestPatch& patch) {
    return (std::filesystem::path(g_omsiRoot) / patch.target).lexically_normal().wstring();
}

bool IsOmsiRunning() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    // Failing closed prevents mutation when Windows cannot prove OMSI is absent.
    if (snapshot == INVALID_HANDLE_VALUE) return true;
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    bool running = false;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, L"Omsi.exe") == 0) {
                running = true;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return running;
}

void UpdateActionButton() {
    const int row = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
    SetWindowTextW(g_apply, L"Review selected bug");
    EnableWindow(g_apply, row >= 0);
}

void ClassifyFixes() {
    size_t available = 0;
    size_t applied = 0;
    for (size_t row = 0; row < kBugs.size(); ++row) {
        g_fixStates[row] = FixState::None;
        const int patchIndex = g_bugPatchIndex[row];
        if (patchIndex < 0 || g_omsiRoot.empty()) {
            continue;
        }
        const auto& patch = g_manifest.patches[static_cast<size_t>(patchIndex)];
        const std::wstring target = PatchTarget(patch);
        omsi_patch::PeImage targetImage;
        omsi_patch::PatchRequest request;
        std::string error;
        if (omsi_patch::LoadPeImage(target, &targetImage, &error) &&
            omsi_patch::PreparePatchRequest(patch, targetImage.identity, &request, &error) &&
            omsi_patch::AuditPatch(target, request, &error)) {
            g_fixStates[row] = FixState::Available;
            ++available;
            continue;
        }
        const std::wstring backup = omsi_patch::BackupPath(target, patch.id);
        omsi_patch::PeImage backupImage;
        if (omsi_patch::LoadPeImage(backup, &backupImage, &error) &&
            omsi_patch::PreparePatchRequest(patch, backupImage.identity, &request, &error) &&
            omsi_patch::AuditPatch(backup, request, &error) &&
            omsi_patch::LoadPeImage(target, &targetImage, &error) &&
            omsi_patch::BytesMatch(targetImage, request.fileOffset, request.replacementBytes)) {
            g_fixStates[row] = FixState::Applied;
            ++applied;
            continue;
        }
        g_fixStates[row] = FixState::Incompatible;
    }
    wchar_t summary[200] = {};
    swprintf_s(summary, L"%zu approved fixes in manifest  |  %zu available  |  %zu applied",
        g_manifest.patches.size(), available, applied);
    SetWindowTextW(g_fixSummary, summary);
    PopulateBugs();
}

std::wstring FindOmsiExecutable() {
    wchar_t modulePath[MAX_PATH] = {};
    if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH) == 0) return {};
    std::filesystem::path directory = std::filesystem::path(modulePath).parent_path();
    for (int level = 0; level < 4; ++level) {
        const std::filesystem::path candidate = directory / L"Omsi.exe";
        const DWORD attributes = GetFileAttributesW(candidate.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            return candidate.wstring();
        }
        if (!directory.has_parent_path()) break;
        directory = directory.parent_path();
    }
    return {};
}

std::wstring FileBesideExecutable(const wchar_t* name) {
    wchar_t modulePath[MAX_PATH] = {};
    if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH) == 0) return {};
    return (std::filesystem::path(modulePath).parent_path() / name).wstring();
}

void LoadManifestStatus() {
    g_bugPatchIndex.fill(-1);
    g_fixStates.fill(FixState::None);
    g_manifestLoaded = false;
    std::string error;
    const std::wstring path = FileBesideExecutable(L"patch-manifest.json");
    if (path.empty() || !omsi_patch::LoadPatchManifest(path, &g_manifest, &error)) {
        const std::wstring message = L"Patching disabled: " + Wide(error.empty() ? "patch-manifest.json not found" : error);
        SetWindowTextW(g_fixSummary, message.c_str());
        EnableWindow(g_apply, FALSE);
        return;
    }
    g_manifestLoaded = true;
    for (size_t patchIndex = 0; patchIndex < g_manifest.patches.size(); ++patchIndex) {
        for (size_t row = 0; row < kBugs.size(); ++row) {
            if (g_manifest.patches[patchIndex].rva == kBugs[row].rva) {
                g_bugPatchIndex[row] = static_cast<int>(patchIndex);
                break;
            }
        }
    }
    wchar_t summary[160] = {};
    swprintf_s(summary, L"%zu approved fixes in manifest", g_manifest.patches.size());
    SetWindowTextW(g_fixSummary, summary);
    PopulateBugs();
    EnableWindow(g_apply, FALSE);
}

void InspectSelectedFile(HWND window) {
    const std::wstring path = SelectedPath();
    g_omsiRoot.clear();
    omsi_patch::PeImage image;
    std::string error;
    if (!omsi_patch::LoadPeImage(path, &image, &error)) {
        SetWindowTextW(g_identity, L"Executable: invalid or unreadable PE32 file");
        SetWindowTextW(g_compatibility, Wide(error).c_str());
        if (g_manifestLoaded) ClassifyFixes();
        else EnableWindow(g_apply, FALSE);
        return;
    }
    g_omsiRoot = std::filesystem::path(path).parent_path().wstring();
    wchar_t identity[256] = {};
    swprintf_s(identity, L"Executable: x86  |  %llu bytes  |  PE timestamp 0x%08X  |  LAA %s",
        static_cast<unsigned long long>(image.identity.fileSize), image.identity.timeDateStamp,
        image.identity.IsLargeAddressAware() ? L"enabled" : L"disabled");
    SetWindowTextW(g_identity, identity);
    const std::wstring hash = Wide(image.identity.sha256);
    if (_wcsicmp(hash.c_str(), kKnownHash) == 0) {
        SetWindowTextW(g_compatibility, L"Compatibility: known OMSI 2 profile. Fix eligibility is shown in the table below.");
    } else {
        SetWindowTextW(g_compatibility, L"Compatibility: unknown executable profile. Only exact manifest matches are eligible.");
    }
    if (g_manifestLoaded) ClassifyFixes();
    else EnableWindow(g_apply, FALSE);
    InvalidateRect(window, nullptr, TRUE);
}

bool PerformSelectedAction(HWND window, size_t bugIndex) {
    if (bugIndex >= kBugs.size()) return false;
    const int patchIndex = g_bugPatchIndex[bugIndex];
    const FixState state = g_fixStates[bugIndex];
    if (patchIndex < 0 || (state != FixState::Available && state != FixState::Applied)) return false;
    if (IsOmsiRunning()) {
        MessageBoxW(window, L"Close OMSI 2 before changing any game file.", L"OMSI is running", MB_OK | MB_ICONWARNING);
        return false;
    }
    const auto& patch = g_manifest.patches[static_cast<size_t>(patchIndex)];
    const std::wstring target = PatchTarget(patch);
    const std::wstring backup = omsi_patch::BackupPath(target, patch.id);
    omsi_patch::PeImage original;
    omsi_patch::PatchRequest request;
    std::string error;
    const std::wstring identitySource = state == FixState::Applied ? backup : target;
    bool ok = omsi_patch::LoadPeImage(identitySource, &original, &error) &&
        omsi_patch::PreparePatchRequest(patch, original.identity, &request, &error);
    if (ok && state == FixState::Applied) {
        omsi_patch::PeImage current;
        ok = omsi_patch::LoadPeImage(target, &current, &error) &&
            omsi_patch::BytesMatch(current, request.fileOffset, request.replacementBytes);
        if (!ok && error.empty()) error = "Current target no longer contains the approved replacement bytes";
    }
    if (ok) {
        ok = state == FixState::Applied
            ? omsi_patch::RollbackPatch(target, request, &error)
            : omsi_patch::ApplyPatch(target, request, &error);
    }
    MessageBoxW(window, ok ? (state == FixState::Applied ? L"Original file restored." : L"Fix applied successfully.")
        : Wide(error).c_str(), ok ? L"Operation complete" : L"Operation failed", MB_OK | (ok ? MB_ICONINFORMATION : MB_ICONERROR));
    InspectSelectedFile(window);
    return ok;
}

HRESULT CALLBACK BugDialogCallback(HWND dialog, UINT notification, WPARAM, LPARAM, LONG_PTR data) {
    if (notification == TDN_CREATED) {
        const auto* state = reinterpret_cast<const BugDialogState*>(data);
        SendMessageW(dialog, TDM_ENABLE_BUTTON, IdDialogApply, state->canApply);
        SendMessageW(dialog, TDM_ENABLE_BUTTON, IdDialogRollback, state->canRollback);
    }
    return S_OK;
}

void ShowSelectedBugDialog(HWND window) {
    const int row = ListView_GetNextItem(g_list, -1, LVNI_SELECTED);
    size_t bugIndex = 0;
    if (!BugIndexFromRow(row, &bugIndex)) return;
    const BugEntry& bug = kBugs[bugIndex];
    const FixState state = g_fixStates[bugIndex];
    const int patchIndex = g_bugPatchIndex[bugIndex];

    std::wstring instruction = bug.title;
    std::wstring content = L"Bug description\n" + std::wstring(bug.description) +
        L"\n\nCategory: " + bug.category + L"\nConfidence: " + bug.confidence +
        L"\nRVA: " + bug.anchor;
    std::wstring expanded;
    BugDialogState dialogState = {
        state == FixState::Available,
        state == FixState::Applied
    };

    if (patchIndex < 0) {
        content += L"\n\nProposed solution\nNo fix has been approved for this bug yet. The finding is available for diagnosis only.";
    } else {
        const auto& patch = g_manifest.patches[static_cast<size_t>(patchIndex)];
        const std::wstring target = PatchTarget(patch);
        content += L"\n\nProposed solution\n" + Wide(patch.rationale);
        expanded = L"Patch ID: " + Wide(patch.id) + L"\nTarget: " + target +
            L"\nBackup: " + omsi_patch::BackupPath(target, patch.id);
        if (state == FixState::Available) {
            content += L"\n\nStatus: compatible and ready to apply.";
        } else if (state == FixState::Applied) {
            content += L"\n\nStatus: this fix is currently applied.";
        } else {
            content += L"\n\nStatus: incompatible with the selected installation. No file will be changed.";
        }
    }
    const TASKDIALOG_BUTTON actions[] = {
        {IdDialogApply, L"Apply fix\nCreate a verified backup and patch this installation"},
        {IdDialogRollback, L"Rollback fix\nRestore the verified original backup"}
    };

    TASKDIALOGCONFIG dialog = {sizeof(dialog)};
    dialog.hwndParent = window;
    dialog.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_SIZE_TO_CONTENT |
        TDF_EXPAND_FOOTER_AREA | TDF_USE_COMMAND_LINKS;
    dialog.dwCommonButtons = TDCBF_CLOSE_BUTTON;
    dialog.pszWindowTitle = L"OMSI Crash Probe - Bug review";
    dialog.pszMainIcon = state == FixState::Available ? TD_SHIELD_ICON : TD_INFORMATION_ICON;
    dialog.pszMainInstruction = instruction.c_str();
    dialog.pszContent = content.c_str();
    dialog.pszExpandedInformation = expanded.empty() ? nullptr : expanded.c_str();
    dialog.pszExpandedControlText = L"Show technical details";
    dialog.pszCollapsedControlText = L"Hide technical details";
    dialog.pszFooter = L"Actions are enabled only for an exact audited state. OMSI must be closed before files can change.";
    dialog.cButtons = static_cast<UINT>(std::size(actions));
    dialog.pButtons = actions;
    dialog.nDefaultButton = IDCLOSE;
    dialog.pfCallback = BugDialogCallback;
    dialog.lpCallbackData = reinterpret_cast<LONG_PTR>(&dialogState);
    int pressed = IDCLOSE;
    if (SUCCEEDED(TaskDialogIndirect(&dialog, &pressed, nullptr, nullptr)) &&
        (pressed == IdDialogApply || pressed == IdDialogRollback)) {
        PerformSelectedAction(window, bugIndex);
    }
}

void BrowseForOmsi(HWND window) {
    wchar_t path[MAX_PATH] = L"Omsi.exe";
    OPENFILENAMEW dialog = {sizeof(dialog)};
    dialog.hwndOwner = window;
    dialog.lpstrFilter = L"OMSI executable (Omsi.exe)\0Omsi.exe\0Windows executables (*.exe)\0*.exe\0\0";
    dialog.lpstrFile = path;
    dialog.nMaxFile = MAX_PATH;
    dialog.lpstrTitle = L"Select Omsi.exe";
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    if (GetOpenFileNameW(&dialog)) {
        SetWindowTextW(g_path, path);
        InspectSelectedFile(window);
    }
}

void Layout(HWND window) {
    RECT client = {};
    GetClientRect(window, &client);
    const int width = client.right;
    const int height = client.bottom;
    MoveWindow(g_title, 28, 14, 420, 32, TRUE);
    MoveWindow(g_subtitle, 29, 45, width - 58, 20, TRUE);
    MoveWindow(g_pathLabel, 28, 92, 180, 20, TRUE);
    MoveWindow(g_path, 28, 116, (std::max)(260, width - 326), 32, TRUE);
    MoveWindow(g_browse, width - 290, 116, 118, 32, TRUE);
    MoveWindow(g_inspect, width - 160, 114, 132, 36, TRUE);
    MoveWindow(g_identity, 40, 169, width - 80, 24, TRUE);
    MoveWindow(g_compatibility, 40, 197, width - 80, 24, TRUE);
    MoveWindow(g_bugsLabel, 28, 242, 300, 28, TRUE);
    MoveWindow(g_filter, width - 266, 238, 238, 220, TRUE);
    MoveWindow(g_list, 28, 276, width - 56, (std::max)(160, height - 358), TRUE);
    MoveWindow(g_fixSummary, 34, height - 61, width - 250, 30, TRUE);
    MoveWindow(g_apply, width - 210, height - 68, 182, 40, TRUE);
}

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_CREATE: {
            g_backgroundBrush = CreateSolidBrush(kBackground);
            g_headerBrush = CreateSolidBrush(kHeader);
            g_panelBrush = CreateSolidBrush(kPanel);
            g_uiFont = CreateFontW(-16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
            g_titleFont = CreateFontW(-25, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
            g_sectionFont = CreateFontW(-19, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
            g_title = AddControl(window, L"STATIC", L"OMSI Crash Probe", SS_LEFT);
            SetFont(g_title, g_titleFont);
            g_subtitle = AddControl(window, L"STATIC", L"Diagnostics and guarded patch manager", SS_LEFT);
            g_pathLabel = AddControl(window, L"STATIC", L"OMSI installation", SS_LEFT);
            SetFont(g_pathLabel, g_sectionFont);
            g_path = AddControl(window, L"EDIT", L"",
                WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL, IdPath);
            g_browse = AddControl(window, L"BUTTON", L"Browse...", WS_TABSTOP | BS_PUSHBUTTON, IdBrowse);
            g_inspect = AddControl(window, L"BUTTON", L"Inspect", WS_TABSTOP | BS_OWNERDRAW, IdInspect);
            g_identity = AddControl(window, L"STATIC", L"Executable: not inspected", SS_LEFT);
            g_compatibility = AddControl(window, L"STATIC", L"Compatibility: unknown", SS_LEFT);
            g_bugsLabel = AddControl(window, L"STATIC", L"Documented bugs", SS_LEFT);
            SetFont(g_bugsLabel, g_sectionFont);
            g_filter = AddControl(window, WC_COMBOBOXW, L"",
                WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL, IdFilter);
            SendMessageW(g_filter, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"All bugs"));
            SendMessageW(g_filter, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"With approved fix"));
            SendMessageW(g_filter, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Without approved fix"));
            SendMessageW(g_filter, CB_SETCURSEL, 0, 0);
            g_list = CreateWindowExW(0, WC_LISTVIEWW, L"",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                0, 0, 0, 0, window, reinterpret_cast<HMENU>(IdBugList), GetModuleHandleW(nullptr), nullptr);
            SetFont(g_list);
            ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
            ListView_SetBkColor(g_list, kPanel);
            ListView_SetTextBkColor(g_list, kPanel);
            ListView_SetTextColor(g_list, kText);
            AddColumn(0, 250, L"Bug");
            AddColumn(1, 140, L"Category");
            AddColumn(2, 150, L"Fix status");
            AddColumn(3, 90, L"Confidence");
            AddColumn(4, 100, L"RVA");
            AddColumn(5, 430, L"Finding");
            PopulateBugs();
            g_fixSummary = AddControl(window, L"STATIC", L"0 approved fixes available", SS_LEFT | SS_CENTERIMAGE);
            g_apply = AddControl(window, L"BUTTON", L"Review selected bug", WS_TABSTOP | BS_OWNERDRAW, IdApply);
            EnableWindow(g_apply, FALSE);
            LoadManifestStatus();
            Layout(window);
            const std::wstring detectedOmsi = FindOmsiExecutable();
            if (!detectedOmsi.empty()) {
                SetWindowTextW(g_path, detectedOmsi.c_str());
                InspectSelectedFile(window);
            } else {
                SetWindowTextW(g_compatibility, L"Compatibility: select Omsi.exe to inspect this installation.");
            }
            return 0;
        }
        case WM_SIZE:
            Layout(window);
            return 0;
        case WM_GETMINMAXINFO: {
            auto* limits = reinterpret_cast<MINMAXINFO*>(lParam);
            limits->ptMinTrackSize.x = 900;
            limits->ptMinTrackSize.y = 640;
            return 0;
        }
        case WM_ERASEBKGND: {
            RECT client = {};
            GetClientRect(window, &client);
            FillRect(reinterpret_cast<HDC>(wParam), &client, g_backgroundBrush);
            return 1;
        }
        case WM_PAINT: {
            PAINTSTRUCT paint = {};
            HDC dc = BeginPaint(window, &paint);
            RECT client = {};
            GetClientRect(window, &client);
            RECT header = {0, 0, client.right, 76};
            FillRect(dc, &header, g_headerBrush);
            RECT accent = {0, 72, client.right, 76};
            FillSolidRect(dc, accent, kAccent);
            RECT details = {28, 160, client.right - 28, 228};
            DrawPanel(dc, details);
            RECT footer = {28, client.bottom - 76, client.right - 28, client.bottom - 20};
            DrawPanel(dc, footer);
            EndPaint(window, &paint);
            return 0;
        }
        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(wParam);
            HWND control = reinterpret_cast<HWND>(lParam);
            SetBkMode(dc, TRANSPARENT);
            if (control == g_title) {
                SetTextColor(dc, RGB(255, 255, 255));
                return reinterpret_cast<INT_PTR>(g_headerBrush);
            }
            if (control == g_subtitle) {
                SetTextColor(dc, RGB(190, 201, 204));
                return reinterpret_cast<INT_PTR>(g_headerBrush);
            }
            SetTextColor(dc, control == g_fixSummary ? kMuted : kText);
            if (control == g_identity || control == g_compatibility || control == g_fixSummary)
                return reinterpret_cast<INT_PTR>(g_panelBrush);
            return reinterpret_cast<INT_PTR>(g_backgroundBrush);
        }
        case WM_CTLCOLOREDIT: {
            HDC dc = reinterpret_cast<HDC>(wParam);
            SetTextColor(dc, kText);
            SetBkColor(dc, kPanel);
            return reinterpret_cast<INT_PTR>(g_panelBrush);
        }
        case WM_DRAWITEM:
            if (wParam == IdInspect || wParam == IdApply) {
                DrawButton(*reinterpret_cast<DRAWITEMSTRUCT*>(lParam));
                return TRUE;
            }
            break;
        case WM_COMMAND:
            if (LOWORD(wParam) == IdBrowse) BrowseForOmsi(window);
            if (LOWORD(wParam) == IdInspect) InspectSelectedFile(window);
            if (LOWORD(wParam) == IdApply) ShowSelectedBugDialog(window);
            if (LOWORD(wParam) == IdFilter && HIWORD(wParam) == CBN_SELCHANGE) PopulateBugs();
            return 0;
        case WM_NOTIFY:
            if (reinterpret_cast<NMHDR*>(lParam)->hwndFrom == g_list) {
                if (reinterpret_cast<NMHDR*>(lParam)->code == LVN_ITEMCHANGED) UpdateActionButton();
                if (reinterpret_cast<NMHDR*>(lParam)->code == LVN_ITEMACTIVATE) ShowSelectedBugDialog(window);
                if (reinterpret_cast<NMHDR*>(lParam)->code == LVN_COLUMNCLICK) {
                    const int column = reinterpret_cast<NMLISTVIEW*>(lParam)->iSubItem;
                    if (g_sortColumn == column) g_sortAscending = !g_sortAscending;
                    else { g_sortColumn = column; g_sortAscending = true; }
                    PopulateBugs();
                }
                if (reinterpret_cast<NMHDR*>(lParam)->code == NM_CUSTOMDRAW)
                    return DrawBugList(reinterpret_cast<NMLVCUSTOMDRAW*>(lParam));
            }
            return 0;
        case WM_DESTROY:
            DeleteObject(g_uiFont);
            DeleteObject(g_titleFont);
            DeleteObject(g_sectionFont);
            DeleteObject(g_backgroundBrush);
            DeleteObject(g_headerBrush);
            DeleteObject(g_panelBrush);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(window, message, wParam, lParam);
}

}  // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand) {
    INITCOMMONCONTROLSEX controls = {sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&controls);
    WNDCLASSEXW windowClass = {sizeof(windowClass)};
    windowClass.lpfnWndProc = WindowProc;
    windowClass.hInstance = instance;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    windowClass.hIconSm = LoadIconW(nullptr, IDI_APPLICATION);
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    windowClass.lpszClassName = kWindowClass;
    if (!RegisterClassExW(&windowClass)) return 1;
    HWND window = CreateWindowExW(0, kWindowClass, L"OMSI Crash Probe",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT, 1180, 760,
        nullptr, nullptr, instance, nullptr);
    if (window == nullptr) return 2;
    ShowWindow(window, showCommand);
    UpdateWindow(window);
    MSG message = {};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return static_cast<int>(message.wParam);
}
