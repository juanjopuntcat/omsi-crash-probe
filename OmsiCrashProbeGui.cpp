#include "PatchCore.h"

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

#include <array>
#include <filesystem>
#include <string>

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
    IdApply
};

struct BugEntry {
    const wchar_t* title;
    const wchar_t* category;
    const wchar_t* status;
    const wchar_t* confidence;
    const wchar_t* anchor;
    const wchar_t* description;
    bool fixAvailable;
};

constexpr std::array<BugEntry, 17> kBugs = {{
    {L"RS.HumansOutside null list entry", L"Access violation", L"Control-flow analysis", L"High", L"0x002EFD03", L"A null list entry is read at object field +0x5BC.", false},
    {L"World/UI missing text subobject", L"Access violation", L"Trampoline design", L"High", L"0x00428140", L"A missing +0x5C subobject is used as a UI string source.", false},
    {L"AI cleanup missing list head", L"Access violation", L"Control-flow analysis", L"Medium", L"0x0042ADE3", L"Bus cleanup dereferences a missing global list head.", false},
    {L"Direct3D device lost or reset", L"Direct3D", L"Documented", L"High", L"0x00429FD8", L"Device reset can fail with DEVICELOST, INVALIDCALL, or unknown HRESULT.", false},
    {L"Direct3D texture allocation failure", L"Memory / graphics", L"Documented", L"High", L"0x0024307C", L"Texture creation fails under allocation pressure or fragmented address space.", false},
    {L"Systemfehler Code 8", L"Memory / resources", L"Documented", L"High", L"0x0002A000", L"Windows cannot provide enough memory resources for the requested operation.", false},
    {L"Invalid bitmap or image", L"Graphics resources", L"Documented", L"High", L"0x00070890", L"Bitmap state, extension, GDI allocation, or image validation fails.", false},
    {L"Range-check error", L"Delphi runtime", L"Documented", L"High", L"0x0004DD85", L"An index or numeric operation violates a compiled Delphi range check.", false},
    {L"List index exceeds maximum", L"Delphi runtime", L"Documented", L"High", L"0x000B57F4", L"A list is accessed outside its valid bounds.", false},
    {L"Argument outside range", L"Delphi runtime", L"Documented", L"High", L"0x0011FF8C", L"A method receives an index or length outside its accepted range.", false},
    {L"Invalid floating-point value", L"Parser", L"Documented", L"High", L"0x00024F68", L"Text input cannot be converted to the expected floating-point value.", false},
    {L"Floating-point division by zero", L"Calculation", L"Documented", L"High", L"0x00011610", L"A vehicle or engine calculation divides by zero.", false},
    {L"Stream read or write failure", L"File I/O", L"Documented", L"Medium-high", L"0x0004DF1C", L"A generic stream operation cannot read or write the requested data.", false},
    {L"Invalid script variable or command", L"Script parser", L"Documented", L"High", L"0x001D378D", L"A script refers to an unknown variable, macro, constant, or function.", false},
    {L"Map or vehicle update failure", L"Simulation", L"Documented", L"Medium", L"0x003D5374", L"Failures around map translation, tile refresh, or CV.Calculate.", false},
    {L"DirectSound access violation", L"Audio", L"Documented", L"Medium", L"0x00405D60", L"A sound load or DirectSound buffer operation reaches invalid state.", false},
    {L"External exception C06D007E", L"External module", L"Documented", L"Medium-low", L"0x00028E06", L"An external dependency or delayed import cannot be resolved.", false}
}};

HWND g_path = nullptr;
HWND g_browse = nullptr;
HWND g_inspect = nullptr;
HWND g_list = nullptr;
HWND g_apply = nullptr;
HWND g_identity = nullptr;
HWND g_compatibility = nullptr;
HWND g_fixSummary = nullptr;
HFONT g_uiFont = nullptr;
HFONT g_titleFont = nullptr;

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

void PopulateBugs() {
    ListView_DeleteAllItems(g_list);
    for (size_t index = 0; index < kBugs.size(); ++index) {
        const BugEntry& bug = kBugs[index];
        LVITEMW item = {};
        item.mask = LVIF_TEXT | LVIF_PARAM;
        item.iItem = static_cast<int>(index);
        item.pszText = const_cast<wchar_t*>(bug.title);
        item.lParam = static_cast<LPARAM>(index);
        const int row = ListView_InsertItem(g_list, &item);
        ListView_SetItemText(g_list, row, 1, const_cast<wchar_t*>(bug.category));
        ListView_SetItemText(g_list, row, 2, const_cast<wchar_t*>(bug.status));
        ListView_SetItemText(g_list, row, 3, const_cast<wchar_t*>(bug.confidence));
        ListView_SetItemText(g_list, row, 4, const_cast<wchar_t*>(bug.anchor));
        ListView_SetItemText(g_list, row, 5, const_cast<wchar_t*>(bug.description));
    }
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

void InspectSelectedFile(HWND window) {
    const int length = GetWindowTextLengthW(g_path);
    std::wstring path(static_cast<size_t>(length + 1), L'\0');
    GetWindowTextW(g_path, path.data(), length + 1);
    path.resize(static_cast<size_t>(length));
    omsi_patch::PeImage image;
    std::string error;
    if (!omsi_patch::LoadPeImage(path, &image, &error)) {
        SetWindowTextW(g_identity, L"Executable: invalid or unreadable PE32 file");
        SetWindowTextW(g_compatibility, Wide(error).c_str());
        return;
    }
    wchar_t identity[256] = {};
    swprintf_s(identity, L"Executable: x86  |  %llu bytes  |  PE timestamp 0x%08X  |  LAA %s",
        static_cast<unsigned long long>(image.identity.fileSize), image.identity.timeDateStamp,
        image.identity.IsLargeAddressAware() ? L"enabled" : L"disabled");
    SetWindowTextW(g_identity, identity);
    const std::wstring hash = Wide(image.identity.sha256);
    if (_wcsicmp(hash.c_str(), kKnownHash) == 0) {
        SetWindowTextW(g_compatibility, L"Compatibility: known OMSI 2 profile. Diagnostics available; no approved fixes yet.");
    } else {
        SetWindowTextW(g_compatibility, L"Compatibility: unknown executable profile. Patching remains disabled.");
    }
    EnableWindow(g_apply, FALSE);
    InvalidateRect(window, nullptr, TRUE);
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
    MoveWindow(g_path, 24, 76, (std::max)(260, width - 300), 30, TRUE);
    MoveWindow(g_browse, width - 264, 76, 112, 30, TRUE);
    MoveWindow(g_inspect, width - 144, 76, 120, 30, TRUE);
    MoveWindow(g_identity, 24, 122, width - 48, 24, TRUE);
    MoveWindow(g_compatibility, 24, 148, width - 48, 24, TRUE);
    MoveWindow(g_list, 24, 202, width - 48, (std::max)(160, height - 278), TRUE);
    MoveWindow(g_fixSummary, 24, height - 56, width - 220, 30, TRUE);
    MoveWindow(g_apply, width - 188, height - 62, 164, 36, TRUE);
}

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_CREATE: {
            g_uiFont = CreateFontW(-16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
            g_titleFont = CreateFontW(-25, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
            HWND title = AddControl(window, L"STATIC", L"OMSI Crash Probe", SS_LEFT);
            SetFont(title, g_titleFont);
            MoveWindow(title, 24, 20, 420, 34, TRUE);
            HWND pathLabel = AddControl(window, L"STATIC", L"OMSI executable", SS_LEFT);
            MoveWindow(pathLabel, 24, 56, 180, 20, TRUE);
            g_path = AddControl(window, L"EDIT", L"",
                WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL, IdPath);
            g_browse = AddControl(window, L"BUTTON", L"Browse...", WS_TABSTOP | BS_PUSHBUTTON, IdBrowse);
            g_inspect = AddControl(window, L"BUTTON", L"Inspect", WS_TABSTOP | BS_DEFPUSHBUTTON, IdInspect);
            g_identity = AddControl(window, L"STATIC", L"Executable: not inspected", SS_LEFT);
            g_compatibility = AddControl(window, L"STATIC", L"Compatibility: unknown", SS_LEFT);
            HWND bugsLabel = AddControl(window, L"STATIC", L"Documented bugs", SS_LEFT);
            SetFont(bugsLabel, g_titleFont);
            MoveWindow(bugsLabel, 24, 174, 300, 30, TRUE);
            g_list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                0, 0, 0, 0, window, reinterpret_cast<HMENU>(IdBugList), GetModuleHandleW(nullptr), nullptr);
            SetFont(g_list);
            ListView_SetExtendedListViewStyle(g_list, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
            AddColumn(0, 250, L"Bug");
            AddColumn(1, 140, L"Category");
            AddColumn(2, 150, L"Fix status");
            AddColumn(3, 90, L"Confidence");
            AddColumn(4, 100, L"RVA");
            AddColumn(5, 430, L"Finding");
            PopulateBugs();
            g_fixSummary = AddControl(window, L"STATIC", L"0 approved fixes available", SS_LEFT | SS_CENTERIMAGE);
            g_apply = AddControl(window, L"BUTTON", L"Apply selected fixes", WS_TABSTOP | BS_PUSHBUTTON, IdApply);
            EnableWindow(g_apply, FALSE);
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
        case WM_COMMAND:
            if (LOWORD(wParam) == IdBrowse) BrowseForOmsi(window);
            if (LOWORD(wParam) == IdInspect) InspectSelectedFile(window);
            return 0;
        case WM_DESTROY:
            DeleteObject(g_uiFont);
            DeleteObject(g_titleFont);
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
