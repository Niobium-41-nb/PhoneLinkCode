#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <objbase.h>
#include <string>
#include <vector>

enum {
    IDI_APPICON = 1,
    IDR_APP_EXE = 201,
    IDR_README = 202
};

enum {
    IDC_TITLE = 1001,
    IDC_SUBTITLE,
    IDC_LABEL_PATH,
    IDC_EDIT_PATH,
    IDC_BTN_BROWSE,
    IDC_CHK_LAUNCH,
    IDC_NOTE,
    IDC_STATUS,
    IDC_APP_ICON_CTL
};

static const wchar_t* kClassName = L"PhoneLinkCodeSetupWindow";
static const wchar_t* kAppWindowClass = L"PhoneLinkCodeHiddenWindow";
static const wchar_t* kUninstallKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PhoneLinkCode";

static HINSTANCE g_inst = nullptr;
static HWND g_hwnd = nullptr;
static HWND g_editPath = nullptr;
static HWND g_chkLaunch = nullptr;
static HWND g_btnInstall = nullptr;
static HWND g_btnCancel = nullptr;
static HWND g_btnBrowse = nullptr;
static HWND g_status = nullptr;
static HWND g_subtitle = nullptr;
static HWND g_note = nullptr;
static HFONT g_font = nullptr;
static HFONT g_fontTitle = nullptr;
static int g_dpi = 96;
static bool g_installing = false;

static int S(int value) { return MulDiv(value, g_dpi, 96); }

static std::wstring GetEnvString(const wchar_t* name) {
    wchar_t buffer[32768];
    DWORD length = GetEnvironmentVariableW(name, buffer, 32768);
    return length > 0 ? std::wstring(buffer, length) : std::wstring();
}

static std::wstring GetSelfPath() {
    wchar_t buffer[32768];
    DWORD length = GetModuleFileNameW(nullptr, buffer, 32768);
    return std::wstring(buffer, length);
}

static std::wstring DefaultInstallDir() {
    std::wstring local = GetEnvString(L"LOCALAPPDATA");
    if (!local.empty()) return local + L"\\Programs\\PhoneLinkCode";
    std::wstring self = GetSelfPath();
    size_t slash = self.find_last_of(L"\\/");
    return (slash == std::wstring::npos ? std::wstring() : self.substr(0, slash)) + L"\\PhoneLinkCode";
}

static bool IsAppRunning() {
    return FindWindowW(kAppWindowClass, nullptr) != nullptr;
}

static bool WriteResourceToFile(int resourceId, const std::wstring& path, std::wstring& error) {
    HRSRC resource = FindResourceW(g_inst, MAKEINTRESOURCEW(resourceId), RT_RCDATA);
    if (!resource) {
        error = L"安装包内嵌资源缺失，文件可能已损坏。";
        return false;
    }
    DWORD size = SizeofResource(g_inst, resource);
    HGLOBAL handle = LoadResource(g_inst, resource);
    const void* data = handle ? LockResource(handle) : nullptr;
    if (!data || size == 0) {
        error = L"读取安装包资源失败。";
        return false;
    }
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = L"无法写入文件：\n" + path;
        return false;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(file, data, size, &written, nullptr);
    CloseHandle(file);
    if (!ok || written != size) {
        DeleteFileW(path.c_str());
        error = L"写入文件失败：\n" + path;
        return false;
    }
    return true;
}

static bool CreateStartMenuShortcut(const std::wstring& target, const std::wstring& workingDir, std::wstring& error) {
    std::wstring appData = GetEnvString(L"APPDATA");
    if (appData.empty()) {
        error = L"无法获取当前用户的开始菜单目录。";
        return false;
    }
    std::wstring menu = appData + L"\\Microsoft\\Windows\\Start Menu\\Programs";
    SHCreateDirectoryExW(nullptr, menu.c_str(), nullptr);
    std::wstring linkPath = menu + L"\\PhoneLinkCode.lnk";

    IShellLinkW* link = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW, reinterpret_cast<void**>(&link));
    if (FAILED(hr) || !link) {
        error = L"创建开始菜单快捷方式失败。";
        return false;
    }
    link->SetPath(target.c_str());
    link->SetWorkingDirectory(workingDir.c_str());
    link->SetDescription(L"PhoneLinkCode 验证码助手");
    link->SetIconLocation(target.c_str(), 0);

    IPersistFile* persist = nullptr;
    bool ok = false;
    if (SUCCEEDED(link->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&persist))) && persist) {
        ok = SUCCEEDED(persist->Save(linkPath.c_str(), TRUE));
        persist->Release();
    }
    link->Release();
    if (!ok) error = L"写入开始菜单快捷方式失败。";
    return ok;
}

static bool WriteUninstallEntry(const std::wstring& installDir, const std::wstring& uninstaller, std::wstring& error) {
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kUninstallKey, 0, nullptr, 0, KEY_WRITE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
        error = L"写入卸载信息失败，请检查当前用户注册表权限。";
        return false;
    }
    auto setString = [&](const wchar_t* name, const std::wstring& value) {
        RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()),
                       static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
    };
    setString(L"DisplayName", L"PhoneLinkCode");
    setString(L"DisplayVersion", L"1.0.0");
    setString(L"Publisher", L"Niobium-41-nb");
    setString(L"DisplayIcon", installDir + L"\\PhoneLinkCode.exe");
    setString(L"InstallLocation", installDir);
    setString(L"UninstallString", L"\"" + uninstaller + L"\" --uninstall");
    setString(L"QuietUninstallString", L"\"" + uninstaller + L"\" --uninstall --silent");
    DWORD one = 1;
    RegSetValueExW(key, L"NoModify", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&one), sizeof(one));
    RegSetValueExW(key, L"NoRepair", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&one), sizeof(one));
    RegCloseKey(key);
    return true;
}

static bool InstallTo(const std::wstring& installDir, bool launch, std::wstring& error) {
    if (installDir.size() < 3 || (installDir[1] != L':' && installDir.rfind(L"\\\\", 0) != 0)) {
        error = L"请选择有效的安装位置。";
        return false;
    }
    if (IsAppRunning()) {
        error = L"PhoneLinkCode 正在运行。\n请先从系统托盘退出，然后重试。";
        return false;
    }
    int result = SHCreateDirectoryExW(nullptr, installDir.c_str(), nullptr);
    if (result != ERROR_SUCCESS && result != ERROR_ALREADY_EXISTS && result != ERROR_FILE_EXISTS) {
        error = L"无法创建安装目录：\n" + installDir;
        return false;
    }

    std::wstring exePath = installDir + L"\\PhoneLinkCode.exe";
    std::wstring readmePath = installDir + L"\\README.md";
    std::wstring uninstallerPath = installDir + L"\\Uninstall.exe";

    if (!WriteResourceToFile(IDR_APP_EXE, exePath, error)) return false;
    if (!WriteResourceToFile(IDR_README, readmePath, error)) return false;
    if (!CopyFileW(GetSelfPath().c_str(), uninstallerPath.c_str(), FALSE)) {
        error = L"无法复制卸载程序到安装目录。";
        return false;
    }
    if (!CreateStartMenuShortcut(exePath, installDir, error)) return false;
    if (!WriteUninstallEntry(installDir, uninstallerPath, error)) return false;

    if (launch) {
        ShellExecuteW(nullptr, L"open", exePath.c_str(), nullptr, installDir.c_str(), SW_SHOWNORMAL);
    }
    return true;
}

static std::wstring ReadInstallLocation() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kUninstallKey, 0, KEY_READ, &key) != ERROR_SUCCESS) return std::wstring();
    wchar_t buffer[32768];
    DWORD type = 0;
    DWORD size = sizeof(buffer);
    std::wstring result;
    if (RegQueryValueExW(key, L"InstallLocation", nullptr, &type, reinterpret_cast<BYTE*>(buffer), &size) == ERROR_SUCCESS && type == REG_SZ) {
        result.assign(buffer);
    }
    RegCloseKey(key);
    return result;
}

static void RunHiddenAndWait(const std::wstring& commandLine, const std::wstring& workingDir, DWORD timeoutMs) {
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION process{};
    std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back(0);
    if (CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                       workingDir.empty() ? nullptr : workingDir.c_str(), &startup, &process)) {
        WaitForSingleObject(process.hProcess, timeoutMs);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
}

static bool UninstallFrom(const std::wstring& requestedDir, std::wstring& error) {
    std::wstring installDir = requestedDir;
    if (installDir.empty()) installDir = ReadInstallLocation();
    if (installDir.empty()) {
        std::wstring self = GetSelfPath();
        size_t slash = self.find_last_of(L"\\/");
        installDir = slash == std::wstring::npos ? std::wstring() : self.substr(0, slash);
    }
    if (IsAppRunning()) {
        error = L"PhoneLinkCode 正在运行。\n请先从系统托盘退出，然后重试。";
        return false;
    }

    std::wstring exePath = installDir + L"\\PhoneLinkCode.exe";
    if (GetFileAttributesW(exePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        RunHiddenAndWait(L"\"" + exePath + L"\" --uninstall", installDir, 5000);
    }

    std::wstring appData = GetEnvString(L"APPDATA");
    if (!appData.empty()) {
        DeleteFileW((appData + L"\\Microsoft\\Windows\\Start Menu\\Programs\\PhoneLinkCode.lnk").c_str());
    }
    RegDeleteTreeW(HKEY_CURRENT_USER, kUninstallKey);
    DeleteFileW((installDir + L"\\README.md").c_str());
    DeleteFileW(exePath.c_str());

    RunHiddenAndWait(L"cmd.exe /c cd /d \"%TEMP%\" >nul & ping 127.0.0.1 -n 3 >nul & del /f /q \"" + installDir + L"\\Uninstall.exe\" & rmdir \"" + installDir + L"\" 2>nul",
                     std::wstring(), 0);
    return true;
}

static void BrowseForFolder(HWND owner) {
    BROWSEINFOW info{};
    info.hwndOwner = owner;
    info.lpszTitle = L"选择 PhoneLinkCode 的安装位置";
    info.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    PIDLIST_ABSOLUTE item = SHBrowseForFolderW(&info);
    if (!item) return;
    wchar_t path[MAX_PATH] = {};
    if (SHGetPathFromIDListW(item, path)) SetWindowTextW(g_editPath, path);
    CoTaskMemFree(item);
}

static void BeginInstall(HWND owner) {
    if (g_installing) return;
    wchar_t buffer[32768] = {};
    GetWindowTextW(g_editPath, buffer, 32768);
    std::wstring installDir(buffer);

    g_installing = true;
    EnableWindow(g_editPath, FALSE);
    EnableWindow(g_btnBrowse, FALSE);
    EnableWindow(g_chkLaunch, FALSE);
    EnableWindow(g_btnInstall, FALSE);
    EnableWindow(g_btnCancel, FALSE);
    SetWindowTextW(g_status, L"正在安装…");
    UpdateWindow(owner);

    bool launch = SendMessageW(g_chkLaunch, BM_GETCHECK, 0, 0) == BST_CHECKED;
    std::wstring error;
    bool ok = InstallTo(installDir, launch, error);

    if (ok) {
        MessageBoxW(owner, L"PhoneLinkCode 已安装完成。\n\n可以从开始菜单启动，也可以通过托盘菜单管理邮箱。",
                    L"安装完成", MB_OK | MB_ICONINFORMATION);
        DestroyWindow(owner);
        return;
    }

    g_installing = false;
    EnableWindow(g_editPath, TRUE);
    EnableWindow(g_btnBrowse, TRUE);
    EnableWindow(g_chkLaunch, TRUE);
    EnableWindow(g_btnInstall, TRUE);
    EnableWindow(g_btnCancel, TRUE);
    SetWindowTextW(g_status, L"");
    MessageBoxW(owner, error.c_str(), L"安装失败", MB_OK | MB_ICONERROR);
}

static HWND MakeControl(DWORD exStyle, const wchar_t* className, const wchar_t* text, DWORD style,
                        int x, int y, int width, int height, int id) {
    HWND control = CreateWindowExW(exStyle, className, text, WS_CHILD | WS_VISIBLE | style,
                                   S(x), S(y), S(width), S(height), g_hwnd,
                                   reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), g_inst, nullptr);
    if (control && g_font) SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(g_font), TRUE);
    return control;
}

static void CreateUi() {
    NONCLIENTMETRICSW metrics{};
    metrics.cbSize = sizeof(metrics);
    if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0)) {
        LOGFONTW font = metrics.lfMessageFont;
        g_font = CreateFontIndirectW(&font);
        font.lfWeight = FW_SEMIBOLD;
        font.lfHeight = -MulDiv(-metrics.lfMessageFont.lfHeight, 13, 9);
        g_fontTitle = CreateFontIndirectW(&font);
    }

    HWND icon = MakeControl(0, L"STATIC", nullptr, SS_ICON, 24, 22, 56, 56, IDC_APP_ICON_CTL);
    HICON bigIcon = static_cast<HICON>(LoadImageW(g_inst, MAKEINTRESOURCEW(IDI_APPICON), IMAGE_ICON,
                                                 S(48), S(48), LR_DEFAULTCOLOR));
    if (icon && bigIcon) SendMessageW(icon, STM_SETICON, reinterpret_cast<WPARAM>(bigIcon), 0);

    HWND title = MakeControl(0, L"STATIC", L"PhoneLinkCode 1.0.0", SS_LEFT, 94, 24, 430, 30, IDC_TITLE);
    if (title && g_fontTitle) SendMessageW(title, WM_SETFONT, reinterpret_cast<WPARAM>(g_fontTitle), TRUE);

    g_subtitle = MakeControl(0, L"STATIC", L"把短信和邮箱验证码自动放进剪贴板", SS_LEFT, 94, 56, 430, 22, IDC_SUBTITLE);
    MakeControl(0, L"STATIC", L"安装位置", SS_LEFT, 24, 108, 80, 22, IDC_LABEL_PATH);
    g_editPath = MakeControl(WS_EX_CLIENTEDGE, L"EDIT", DefaultInstallDir().c_str(),
                             ES_LEFT | ES_AUTOHSCROLL | WS_TABSTOP, 108, 104, 340, 26, IDC_EDIT_PATH);
    g_btnBrowse = MakeControl(0, L"BUTTON", L"更改…", BS_PUSHBUTTON | WS_TABSTOP, 460, 103, 78, 28, IDC_BTN_BROWSE);
    g_chkLaunch = MakeControl(0, L"BUTTON", L"安装完成后启动 PhoneLinkCode", BS_AUTOCHECKBOX | WS_TABSTOP,
                              24, 148, 320, 24, IDC_CHK_LAUNCH);
    SendMessageW(g_chkLaunch, BM_SETCHECK, BST_CHECKED, 0);

    g_note = MakeControl(0, L"STATIC",
                         L"按当前用户安装，不需要管理员权限。\n邮箱配置与日志保存在 %LOCALAPPDATA%\\PhoneLinkCode。",
                         SS_LEFT, 24, 184, 512, 40, IDC_NOTE);

    g_status = MakeControl(0, L"STATIC", L"", SS_LEFT, 24, 228, 330, 22, IDC_STATUS);

    g_btnInstall = MakeControl(0, L"BUTTON", L"安装", BS_DEFPUSHBUTTON | WS_TABSTOP, 352, 254, 88, 30, IDOK);
    g_btnCancel = MakeControl(0, L"BUTTON", L"取消", BS_PUSHBUTTON | WS_TABSTOP, 452, 254, 88, 30, IDCANCEL);

    SetFocus(g_btnInstall);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE:
        g_hwnd = hwnd;
        CreateUi();
        return 0;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        HWND control = reinterpret_cast<HWND>(lParam);
        SetBkMode(dc, TRANSPARENT);
        if (control == g_subtitle || control == g_note || control == g_status) {
            SetTextColor(dc, RGB(96, 104, 100));
        }
        return reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_WINDOW));
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK:
            BeginInstall(hwnd);
            return 0;
        case IDCANCEL:
            if (!g_installing) DestroyWindow(hwnd);
            return 0;
        case IDC_BTN_BROWSE:
            BrowseForFolder(hwnd);
            return 0;
        default:
            break;
        }
        break;
    case WM_CLOSE:
        if (!g_installing) DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        if (g_font) DeleteObject(g_font);
        if (g_fontTitle) DeleteObject(g_fontTitle);
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return DefWindowProcW(hwnd, message, wParam, lParam);
}

static void ShowInstallerWindow() {
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = g_inst;
    wc.hIcon = LoadIconW(g_inst, MAKEINTRESOURCEW(IDI_APPICON));
    wc.hIconSm = wc.hIcon;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = GetSysColorBrush(COLOR_WINDOW);
    wc.lpszClassName = kClassName;
    if (!RegisterClassExW(&wc)) return;

    RECT rect{0, 0, S(560), S(300)};
    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU;
    DWORD exStyle = WS_EX_CONTROLPARENT;
    AdjustWindowRectEx(&rect, style, FALSE, exStyle);
    int width = rect.right - rect.left;
    int height = rect.bottom - rect.top;
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    int x = (screenW - width) / 2;
    int y = (screenH - height) / 2;

    HWND hwnd = CreateWindowExW(exStyle, kClassName, L"PhoneLinkCode 安装程序", style,
                                x, y, width, height, nullptr, nullptr, g_inst, nullptr);
    if (!hwnd) return;
    SendMessageW(hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(wc.hIcon));
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR, int) {
    g_inst = instance;
    SetProcessDPIAware();
    g_dpi = GetDpiForSystem();
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    bool uninstallMode = false;
    bool silent = false;
    std::wstring dirArgument;

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        for (int i = 1; i < argc; ++i) {
            std::wstring arg = argv[i];
            if (_wcsicmp(arg.c_str(), L"--uninstall") == 0) uninstallMode = true;
            else if (_wcsicmp(arg.c_str(), L"--silent") == 0 || _wcsicmp(arg.c_str(), L"/S") == 0) silent = true;
            else if (arg.rfind(L"/D=", 0) == 0 || arg.rfind(L"--dir=", 0) == 0) {
                dirArgument = arg.substr(arg.find(L'=') + 1);
            }
        }
        LocalFree(argv);
    }

    int exitCode = 0;
    if (uninstallMode) {
        if (!silent && MessageBoxW(nullptr, L"确定要卸载 PhoneLinkCode 吗？\n\n邮箱配置与日志会被保留。",
                                   L"卸载 PhoneLinkCode", MB_YESNO | MB_ICONQUESTION) != IDYES) {
            CoUninitialize();
            return 0;
        }
        std::wstring error;
        bool ok = UninstallFrom(dirArgument, error);
        if (!ok) {
            exitCode = 1;
            if (!silent) MessageBoxW(nullptr, error.c_str(), L"卸载失败", MB_OK | MB_ICONERROR);
        } else if (!silent) {
            MessageBoxW(nullptr, L"PhoneLinkCode 已卸载。\n\n邮箱配置与日志仍保留在 %LOCALAPPDATA%\\PhoneLinkCode。",
                        L"卸载完成", MB_OK | MB_ICONINFORMATION);
        }
        CoUninitialize();
        return exitCode;
    }

    if (silent) {
        std::wstring dir = dirArgument.empty() ? DefaultInstallDir() : dirArgument;
        std::wstring error;
        exitCode = InstallTo(dir, false, error) ? 0 : 1;
        CoUninitialize();
        return exitCode;
    }

    ShowInstallerWindow();
    CoUninitialize();
    return 0;
}
