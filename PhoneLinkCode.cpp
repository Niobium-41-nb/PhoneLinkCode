// PhoneLinkCode.cpp
// 手机连接（Phone Link）短信验证码自动复制工具。
// 原理：Windows 会把「手机连接」收到的短信以 toast 通知写入本机通知数据库
//       (%LOCALAPPDATA%\Microsoft\Windows\Notifications\wpndatabase.db)，
//       该库为明文 SQLite。程序轮询该库，解析短信正文，提取验证码并写入剪贴板。
// 依赖：Windows 10 1709+ 自带的 winsqlite3.dll，无需第三方库。

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <shellapi.h>
#include <knownfolders.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cwchar>

#include "MailImap.h"

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")

using std::wstring;
using std::string;
using std::vector;

static const wchar_t* kAppTitle = L"手机连接验证码助手";
static const wchar_t* kRunKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
static const wchar_t* kRunValue = L"PhoneLinkCode";

static const UINT kPollIntervalMs = 2000;
static const UINT_PTR kTimerId = 1;
static const UINT kTrayMsg = WM_APP + 1;
static const int kMaxCodeAgeMinutes = 10;

// ---------------------------------------------------------------------------
// 字符串与文件工具
// ---------------------------------------------------------------------------

static bool IsAsciiDigit(wchar_t c) { return c >= L'0' && c <= L'9'; }

static string WideToUtf8(const wstring& s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    string out((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n, nullptr, nullptr);
    return out;
}

static wstring Utf8ToWide(const string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n);
    return out;
}

static bool IsSpaceW(wchar_t c) {
    return c == L' ' || c == L'\t' || c == L'\r' || c == L'\n' || c == 0x3000;
}

static void Trim(wstring& s) {
    size_t b = 0, e = s.size();
    while (b < e && IsSpaceW(s[b])) b++;
    while (e > b && IsSpaceW(s[e - 1])) e--;
    s = s.substr(b, e - b);
}

static wstring OneLine(const wstring& s, size_t maxLen = 100) {
    wstring out;
    bool lastSpace = false;
    for (wchar_t c : s) {
        wchar_t x = (c == L'\r' || c == L'\n' || c == L'\t') ? L' ' : c;
        if (IsSpaceW(x)) {
            if (lastSpace) continue;
            lastSpace = true;
        } else {
            lastSpace = false;
        }
        out += x;
        if (out.size() >= maxLen) { out += L"..."; break; }
    }
    Trim(out);
    return out;
}

static wstring TimeString(long long fileTime100ns) {
    if (fileTime100ns <= 0) return L"-";
    FILETIME ft;
    ft.dwLowDateTime = (DWORD)(fileTime100ns & 0xFFFFFFFF);
    ft.dwHighDateTime = (DWORD)((fileTime100ns >> 32) & 0xFFFFFFFF);
    FILETIME local;
    SYSTEMTIME st;
    if (!FileTimeToLocalFileTime(&ft, &local) || !FileTimeToSystemTime(&local, &st)) return L"-";
    wchar_t buf[64];
    swprintf_s(buf, L"%04d-%02d-%02d %02d:%02d:%02d",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static wstring NowString() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[64];
    swprintf_s(buf, L"%04d-%02d-%02d %02d:%02d:%02d",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static int AgeMinutes(long long arrivalFileTime) {
    if (arrivalFileTime <= 0) return 0;
    FILETIME nowFt;
    GetSystemTimeAsFileTime(&nowFt);
    ULARGE_INTEGER a, b;
    a.LowPart = nowFt.dwLowDateTime;
    a.HighPart = nowFt.dwHighDateTime;
    b.QuadPart = (ULONGLONG)arrivalFileTime;
    if (a.QuadPart <= b.QuadPart) return 0;
    return (int)((a.QuadPart - b.QuadPart) / 600000000ULL);
}

static void EnsureDir(const wstring& dir) {
    CreateDirectoryW(dir.c_str(), nullptr);
}

static bool FileExists(const wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

static bool AppendFile(const wstring& path, const wstring& text) {
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    string u8 = WideToUtf8(text);
    DWORD written = 0;
    BOOL ok = WriteFile(h, u8.data(), (DWORD)u8.size(), &written, nullptr);
    CloseHandle(h);
    return ok != FALSE;
}

static wstring ReadAllText(const wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};
    LARGE_INTEGER size{};
    GetFileSizeEx(h, &size);
    if (size.QuadPart <= 0 || size.QuadPart > 1024 * 1024) { CloseHandle(h); return {}; }
    string data((size_t)size.QuadPart, '\0');
    DWORD read = 0;
    ReadFile(h, data.data(), (DWORD)data.size(), &read, nullptr);
    CloseHandle(h);
    data.resize(read);
    return Utf8ToWide(data);
}

static wstring GetEnvVar(const wchar_t* name) {
    wchar_t buf[1024];
    DWORD n = GetEnvironmentVariableW(name, buf, 1024);
    if (n == 0 || n >= 1024) return {};
    return wstring(buf, n);
}

// ---------------------------------------------------------------------------
// 日志与命令行输出
// ---------------------------------------------------------------------------

static wstring g_homeDir, g_logPath, g_statePath, g_dbPath;
static bool g_consoleReady = false;

static void Log(const wstring& line) {
    static wstring lastDate;
    wstring stamp = NowString();
    wstring date = stamp.substr(0, 10);
    if (date != lastDate) {
        lastDate = date;
        // 简单的按天分隔，不额外清理
        AppendFile(g_logPath, L"\r\n========== " + date + L" ==========\r\n");
    }
    AppendFile(g_logPath, L"[" + stamp + L"] " + line + L"\r\n");
}

static void Print(const wstring& s) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!h || h == INVALID_HANDLE_VALUE) {
        OutputDebugStringW(s.c_str());
        return;
    }
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode)) {
        DWORD written = 0;
        WriteConsoleW(h, s.c_str(), (DWORD)s.size(), &written, nullptr);
    } else {
        string u8 = WideToUtf8(s);
        DWORD written = 0;
        WriteFile(h, u8.data(), (DWORD)u8.size(), &written, nullptr);
    }
}

static void EnsureConsole() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE) return;
    if (AttachConsole(ATTACH_PARENT_PROCESS)) return;
    AllocConsole();
}

// ---------------------------------------------------------------------------
// winsqlite3.dll 动态加载（Windows 自带，无需链接 sqlite3）
// ---------------------------------------------------------------------------

namespace sql {

struct sqlite3;
struct sqlite3_stmt;

typedef int (*fn_open_v2)(const char*, sqlite3**, int, const char*);
typedef int (*fn_close)(sqlite3*);
typedef int (*fn_prepare_v2)(sqlite3*, const char*, int, sqlite3_stmt**, const char**);
typedef int (*fn_bind_int64)(sqlite3_stmt*, int, long long);
typedef int (*fn_step)(sqlite3_stmt*);
typedef long long (*fn_column_int64)(sqlite3_stmt*, int);
typedef const unsigned char* (*fn_column_text)(sqlite3_stmt*, int);
typedef int (*fn_column_bytes)(sqlite3_stmt*, int);
typedef int (*fn_finalize)(sqlite3_stmt*);
typedef const char* (*fn_errmsg)(sqlite3*);

enum {
    SQLITE_OK = 0,
    SQLITE_ROW = 100,
    SQLITE_DONE = 101,
    SQLITE_OPEN_READONLY = 0x00000001,
};

static fn_open_v2 open_v2 = nullptr;
static fn_close close_db = nullptr;
static fn_prepare_v2 prepare_v2 = nullptr;
static fn_bind_int64 bind_int64 = nullptr;
static fn_step step = nullptr;
static fn_column_int64 column_int64 = nullptr;
static fn_column_text column_text = nullptr;
static fn_column_bytes column_bytes = nullptr;
static fn_finalize finalize = nullptr;
static fn_errmsg errmsg = nullptr;

static bool Load() {
    static bool loaded = false, ok = false;
    if (loaded) return ok;
    loaded = true;
    HMODULE m = LoadLibraryW(L"winsqlite3.dll");
    if (!m) return false;
    open_v2 = (fn_open_v2)GetProcAddress(m, "sqlite3_open_v2");
    close_db = (fn_close)GetProcAddress(m, "sqlite3_close");
    prepare_v2 = (fn_prepare_v2)GetProcAddress(m, "sqlite3_prepare_v2");
    bind_int64 = (fn_bind_int64)GetProcAddress(m, "sqlite3_bind_int64");
    step = (fn_step)GetProcAddress(m, "sqlite3_step");
    column_int64 = (fn_column_int64)GetProcAddress(m, "sqlite3_column_int64");
    column_text = (fn_column_text)GetProcAddress(m, "sqlite3_column_text");
    column_bytes = (fn_column_bytes)GetProcAddress(m, "sqlite3_column_bytes");
    finalize = (fn_finalize)GetProcAddress(m, "sqlite3_finalize");
    errmsg = (fn_errmsg)GetProcAddress(m, "sqlite3_errmsg");
    ok = open_v2 && close_db && prepare_v2 && bind_int64 && step && column_int64 &&
         column_text && column_bytes && finalize && errmsg;
    return ok;
}

} // namespace sql

struct DbHandle {
    sql::sqlite3* db = nullptr;
    ~DbHandle() { if (db) sql::close_db(db); }

    bool Open(const wstring& path, wstring& err) {
        if (!sql::Load()) {
            err = L"无法加载 winsqlite3.dll（需要 Windows 10 1709 及以上）";
            return false;
        }
        string utf8 = WideToUtf8(path);
        sql::sqlite3* d = nullptr;
        int rc = sql::open_v2(utf8.c_str(), &d, sql::SQLITE_OPEN_READONLY, nullptr);
        if (rc != sql::SQLITE_OK) {
            if (d) sql::close_db(d);
            err = L"无法只读打开通知数据库: " + path;
            return false;
        }
        db = d;
        return true;
    }
};

struct SmsRow {
    long long id = 0;
    long long arrival = 0;
    wstring handler;
    string payload;
};

static bool QueryRows(const wstring& sqlText, bool hasBind, long long bindValue,
                      vector<SmsRow>& rows, wstring& err) {
    DbHandle h;
    if (!h.Open(g_dbPath, err)) return false;

    sql::sqlite3_stmt* st = nullptr;
    string q = WideToUtf8(sqlText);
    int rc = sql::prepare_v2(h.db, q.c_str(), -1, &st, nullptr);
    if (rc != sql::SQLITE_OK) {
        err = L"SQL 准备失败: " + Utf8ToWide(sql::errmsg(h.db));
        return false;
    }
    if (hasBind) sql::bind_int64(st, 1, bindValue);

    while ((rc = sql::step(st)) == sql::SQLITE_ROW) {
        SmsRow r;
        r.id = sql::column_int64(st, 0);
        r.arrival = sql::column_int64(st, 1);
        const unsigned char* htext = sql::column_text(st, 2);
        int hlen = sql::column_bytes(st, 2);
        if (htext && hlen > 0) r.handler = Utf8ToWide(string((const char*)htext, (size_t)hlen));
        const unsigned char* ptext = sql::column_text(st, 3);
        int plen = sql::column_bytes(st, 3);
        if (ptext && plen > 0) r.payload.assign((const char*)ptext, (size_t)plen);
        rows.push_back(std::move(r));
    }
    int doneRc = rc;
    sql::finalize(st);
    if (doneRc != sql::SQLITE_DONE) {
        err = L"查询通知数据库失败 (rc=" + std::to_wstring(doneRc) + L")";
        return false;
    }
    return true;
}

static const wchar_t* kBaseWhere =
    L"FROM Notification n JOIN NotificationHandler h ON h.RecordId = n.HandlerId "
    L"WHERE n.Type = 'toast' AND n.Payload IS NOT NULL AND length(n.Payload) > 0 "
    L"AND h.PrimaryId LIKE 'Microsoft.YourPhone_8wekyb3d8bbwe!%' ";

static bool QueryNewer(long long afterId, vector<SmsRow>& rows, wstring& err) {
    wstring sql = wstring(L"SELECT n.Id, n.ArrivalTime, h.PrimaryId, n.Payload ") + kBaseWhere +
                  L"AND n.Id > ?1 ORDER BY n.Id ASC";
    return QueryRows(sql, true, afterId, rows, err);
}

static bool QueryRecent(int limit, vector<SmsRow>& rows, wstring& err) {
    wstring sql = wstring(L"SELECT n.Id, n.ArrivalTime, h.PrimaryId, n.Payload ") + kBaseWhere +
                  L"ORDER BY n.Id DESC LIMIT ?1";
    return QueryRows(sql, true, limit, rows, err);
}

static bool QueryMaxId(long long& maxId, wstring& err) {
    wstring sql = wstring(L"SELECT COALESCE(MAX(n.Id), 0) ") + kBaseWhere;
    // QueryRows 固定读 4 列，这里单独实现一个轻量查询
    DbHandle h;
    if (!h.Open(g_dbPath, err)) return false;
    sql::sqlite3_stmt* st = nullptr;
    string q = WideToUtf8(sql);
    int rc = sql::prepare_v2(h.db, q.c_str(), -1, &st, nullptr);
    if (rc != sql::SQLITE_OK) {
        err = L"SQL 准备失败: " + Utf8ToWide(sql::errmsg(h.db));
        return false;
    }
    if (sql::step(st) == sql::SQLITE_ROW) maxId = sql::column_int64(st, 0);
    sql::finalize(st);
    return true;
}

// ---------------------------------------------------------------------------
// 通知 XML 解析
// ---------------------------------------------------------------------------

static void StripTags(wstring& s) {
    wstring out;
    bool inTag = false;
    for (wchar_t c : s) {
        if (c == L'<') { inTag = true; continue; }
        if (c == L'>' && inTag) { inTag = false; continue; }
        if (!inTag) out += c;
    }
    s.swap(out);
}

static void UnescapeXml(wstring& s) {
    wstring out;
    for (size_t i = 0; i < s.size();) {
        if (s[i] == L'&') {
            size_t semi = s.find(L';', i);
            if (semi != wstring::npos && semi - i <= 10) {
                wstring ent = s.substr(i + 1, semi - i - 1);
                wchar_t ch = 0;
                bool ok = true;
                if (ent == L"amp") ch = L'&';
                else if (ent == L"lt") ch = L'<';
                else if (ent == L"gt") ch = L'>';
                else if (ent == L"quot") ch = L'"';
                else if (ent == L"apos") ch = L'\'';
                else if (ent.size() > 1 && ent[0] == L'#') {
                    unsigned long v = 0;
                    wchar_t* endp = nullptr;
                    if (ent[1] == L'x' || ent[1] == L'X')
                        v = wcstoul(ent.c_str() + 2, &endp, 16);
                    else
                        v = wcstoul(ent.c_str() + 1, &endp, 10);
                    if (endp && *endp == L'\0' && v > 0 && v <= 0xFFFF) ch = (wchar_t)v;
                    else ok = false;
                } else {
                    ok = false;
                }
                if (ok) { out += ch; i = semi + 1; continue; }
            }
        }
        out += s[i++];
    }
    s.swap(out);
}

// Payload 一般是 UTF-8 XML，兼容 UTF-16LE 与 BOM
static wstring PayloadToXml(const string& payload) {
    const unsigned char* b = (const unsigned char*)payload.data();
    size_t n = payload.size();
    if (n >= 2 && b[0] == 0xFF && b[1] == 0xFE)
        return wstring((const wchar_t*)(b + 2), (n - 2) / 2);
    if (n >= 2 && b[0] == '<' && b[1] == 0)
        return wstring((const wchar_t*)b, n / 2);
    size_t off = (n >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF) ? 3 : 0;
    return Utf8ToWide(payload.substr(off));
}

static vector<wstring> CollectTextNodes(const wstring& xml) {
    vector<wstring> nodes;
    size_t pos = 0;
    while (true) {
        size_t lt = xml.find(L"<text", pos);
        if (lt == wstring::npos) break;
        size_t gt = xml.find(L'>', lt);
        if (gt == wstring::npos) break;
        if (gt > lt + 5 && xml[gt - 1] == L'/') { pos = gt + 1; continue; }
        size_t end = xml.find(L"</text>", gt);
        if (end == wstring::npos) break;
        wstring inner = xml.substr(gt + 1, end - gt - 1);
        StripTags(inner);
        UnescapeXml(inner);
        Trim(inner);
        if (!inner.empty()) nodes.push_back(inner);
        pos = end + 7;
    }
    return nodes;
}

static bool IsSenderLike(const wstring& s) {
    if (s.size() < 4 || s.size() > 24) return false;
    bool hasDigit = false;
    for (wchar_t c : s) {
        if (IsAsciiDigit(c)) { hasDigit = true; continue; }
        if (c == L'+' || c == L'-' || c == L' ' || c == L'(' || c == L')' || c == L'.') continue;
        return false;
    }
    return hasDigit;
}

static wstring JoinBody(const vector<wstring>& nodes) {
    wstring sender;
    if (!nodes.empty() && IsSenderLike(nodes[0])) sender = nodes[0];
    wstring body;
    for (const auto& node : nodes) {
        if (!sender.empty() && node == sender) continue;
        if (!body.empty()) body += L'\n';
        body += node;
    }
    return body;
}

// ---------------------------------------------------------------------------
// 验证码提取
// ---------------------------------------------------------------------------

static wstring NormalizeDigits(const wstring& s) {
    wstring t = s;
    for (wchar_t& c : t) {
        if (c >= 0xFF10 && c <= 0xFF19) c = (wchar_t)(c - 0xFF10 + L'0');
    }
    return t;
}

static wstring AsciiLower(const wstring& s) {
    wstring t = s;
    for (wchar_t& c : t) {
        if (c >= L'A' && c <= L'Z') c = (wchar_t)(c - L'A' + L'a');
    }
    return t;
}

struct CodeHit {
    wstring code;
    int score = 0;
};

static void ConsiderDigits(const wstring& t, size_t start, int baseScore, size_t kwPos, CodeHit& best) {
    if (start >= t.size() || !IsAsciiDigit(t[start])) return;
    size_t s = start, e = start;
    while (s > 0 && IsAsciiDigit(t[s - 1])) s--;
    while (e < t.size() && IsAsciiDigit(t[e])) e++;
    size_t len = e - s;
    if (len < 4 || len > 8) return;
    size_t dist = (s >= kwPos) ? (s - kwPos) : (kwPos - e);
    int score = baseScore - (int)std::min<size_t>(25, dist);
    if (score > best.score) {
        best.score = score;
        best.code = t.substr(s, len);
    }
}

static const wchar_t* kKeywords[] = {
    L"验证码", L"校验码", L"动态码", L"动态密码", L"确认码", L"激活码", L"安全码",
    L"提取码", L"登录码", L"验证口令", L"一次性密码",
    L"verification code", L"one-time code", L"otp", L"code", L"passcode",
};

static bool AsciiWordBoundaryOk(const wstring& lower, size_t pos, size_t len) {
    if (pos > 0) {
        wchar_t p = lower[pos - 1];
        if (p >= L'a' && p <= L'z') return false;
    }
    size_t after = pos + len;
    if (after < lower.size()) {
        wchar_t n = lower[after];
        if (n >= L'a' && n <= L'z') return false;
    }
    return true;
}

static bool HasBlacklistContext(const wstring& t, size_t pos) {
    static const wchar_t* kWords[] = {
        L"尾号", L"单号", L"订单", L"编号", L"工单", L"金额", L"余额", L"积分",
        L"航班", L"车次", L"房间", L"取件", L"取货", L"货号", L"快递", L"邮编",
        L"电话", L"手机号", L"身份证", L"座位", L"房号",
    };
    size_t from = (pos > 10) ? pos - 10 : 0;
    wstring before = t.substr(from, pos - from);
    for (const wchar_t* w : kWords) {
        if (before.find(w) != wstring::npos) return true;
    }
    if (pos < t.size()) {
        wstring after = t.substr(pos, std::min<size_t>(3, t.size() - pos));
        static const wchar_t* kSuffix[] = { L"元", L"块", L"折", L"%", L"月", L"日", L"年", L"小时", L"分钟", L"秒", L"万人" };
        for (const wchar_t* s : kSuffix) {
            if (after.rfind(s, 0) == 0) return true;
        }
    }
    return false;
}

static wstring ExtractCode(const wstring& rawText) {
    wstring t = NormalizeDigits(rawText);
    if (t.empty()) return {};
    wstring lower = AsciiLower(t);

    CodeHit best;
    for (const wchar_t* kw : kKeywords) {
        wstring keyword(kw);
        size_t kwLen = keyword.size();
        size_t p = 0;
        while ((p = lower.find(keyword, p)) != wstring::npos) {
            bool asciiWord = keyword[0] < 0x80;
            if (asciiWord && !AsciiWordBoundaryOk(lower, p, kwLen)) {
                p += kwLen;
                continue;
            }
            // 关键词后面紧跟的验证码（"验证码：123456"）
            size_t j = p + kwLen;
            int steps = 0;
            while (j < t.size() && !IsAsciiDigit(t[j]) && t[j] != L'\n' && steps < 16) { j++; steps++; }
            if (j < t.size() && IsAsciiDigit(t[j])) ConsiderDigits(t, j, 300 - steps, p, best);

            // 关键词前面的验证码（"123456 is your code"）
            size_t k = p;
            steps = 0;
            while (k > 0 && !IsAsciiDigit(t[k - 1]) && t[k - 1] != L'\n' && steps < 16) { k--; steps++; }
            if (k > 0 && IsAsciiDigit(t[k - 1])) ConsiderDigits(t, k - 1, 260 - steps, p, best);

            p += kwLen;
        }
    }
    if (!best.code.empty()) return best.code;

    // 没有关键词时，仅在全文只有一个可信候选时采用
    struct Cand { wstring code; size_t pos; };
    vector<Cand> cands;
    for (size_t i = 0; i < t.size();) {
        if (!IsAsciiDigit(t[i])) { i++; continue; }
        size_t s = i;
        while (i < t.size() && IsAsciiDigit(t[i])) i++;
        size_t len = i - s;
        if (len < 4 || len > 8) continue;
        wstring code = t.substr(s, len);
        if (len == 4 || len == 8) {
            if (code.rfind(L"19", 0) == 0 || code.rfind(L"20", 0) == 0) continue; // 年份/日期
        }
        if (HasBlacklistContext(t, s)) continue;
        cands.push_back({ code, s });
    }
    if (cands.size() == 1) return cands[0].code;
    if (cands.size() > 1) {
        vector<const Cand*> six;
        for (const auto& c : cands) if (c.code.size() == 6) six.push_back(&c);
        if (six.size() == 1) return six[0]->code;
        bool allSame = true;
        for (const auto& c : cands) if (c.code != cands[0].code) allSame = false;
        if (allSame) return cands[0].code;
    }
    return {};
}

// ---------------------------------------------------------------------------
// 剪贴板 / 托盘 / 自启动
// ---------------------------------------------------------------------------

static bool CopyToClipboard(const wstring& text) {
    for (int attempt = 0; attempt < 10; ++attempt) {
        if (OpenClipboard(nullptr)) {
            bool ok = false;
            if (EmptyClipboard()) {
                size_t bytes = (text.size() + 1) * sizeof(wchar_t);
                HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
                if (mem) {
                    void* p = GlobalLock(mem);
                    if (p) {
                        memcpy(p, text.c_str(), bytes);
                        GlobalUnlock(mem);
                        if (SetClipboardData(CF_UNICODETEXT, mem)) ok = true;
                        else GlobalFree(mem);
                    } else {
                        GlobalFree(mem);
                    }
                }
            }
            CloseClipboard();
            if (ok) return true;
        }
        Sleep(20);
    }
    return false;
}

static NOTIFYICONDATAW g_nid = {};
static bool g_trayAdded = false;
static HWND g_hwnd = nullptr;

static void Balloon(const wstring& title, const wstring& text) {
    if (!g_trayAdded) return;
    NOTIFYICONDATAW d = g_nid;
    d.uFlags = NIF_INFO;
    d.dwInfoFlags = NIIF_INFO;
    wcsncpy_s(d.szInfoTitle, title.c_str(), _TRUNCATE);
    wstring body = text.size() > 200 ? text.substr(0, 200) : text;
    wcsncpy_s(d.szInfo, body.c_str(), _TRUNCATE);
    Shell_NotifyIconW(NIM_MODIFY, &d);
}

static bool IsAutostartEnabled() {
    wchar_t buf[1024];
    DWORD size = sizeof(buf);
    return RegGetValueW(HKEY_CURRENT_USER, kRunKey, kRunValue, RRF_RT_REG_SZ, nullptr, buf, &size) == ERROR_SUCCESS;
}

static bool SetAutostart(bool enable) {
    if (!enable) {
        HKEY key = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kRunKey, 0, KEY_SET_VALUE, &key) == ERROR_SUCCESS) {
            RegDeleteValueW(key, kRunValue);
            RegCloseKey(key);
        }
        return true;
    }
    wchar_t exe[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, exe, MAX_PATH)) return false;
    wstring cmd = L"\"" + wstring(exe) + L"\"";
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kRunKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS)
        return false;
    LONG rc = RegSetValueExW(key, kRunValue, 0, REG_SZ, (const BYTE*)cmd.c_str(),
                             (DWORD)((cmd.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
    return rc == ERROR_SUCCESS;
}

// ---------------------------------------------------------------------------
// 状态文件
// ---------------------------------------------------------------------------

static long long g_lastId = 0;

static bool LoadState() {
    wstring text = ReadAllText(g_statePath);
    size_t p = text.find(L"last_id=");
    if (p == wstring::npos) return false;
    g_lastId = wcstoll(text.c_str() + p + 8, nullptr, 10);
    return true;
}

static void SaveState() {
    HANDLE h = CreateFileW(g_statePath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    string u8 = WideToUtf8(L"last_id=" + std::to_wstring(g_lastId) + L"\r\n");
    DWORD written = 0;
    WriteFile(h, u8.data(), (DWORD)u8.size(), &written, nullptr);
    CloseHandle(h);
}

// ---------------------------------------------------------------------------
// 核心轮询逻辑
// ---------------------------------------------------------------------------

static bool IsMessageToast(const SmsRow& row, const wstring& xml) {
    if (row.handler.find(L"YourPhoneMessages") != wstring::npos) return true;
    if (row.handler.size() >= 4 && row.handler.compare(row.handler.size() - 4, 4, L"!App") == 0) {
        return xml.find(L"ms-phone:messages") != wstring::npos;
    }
    return false;
}

// 返回 true 表示处理了新通知（需要保存状态）
static bool PollNewNotifications(bool quietStart) {
    wstring err;
    // 通知库被系统重置后 Id 会重新计数，这里兜底复位，避免永远读不到新短信
    long long dbMax = 0;
    if (QueryMaxId(dbMax, err) && dbMax > 0 && dbMax < g_lastId) {
        Log(L"检测到通知数据库已重置，重新定位 (last_id=" + std::to_wstring(g_lastId) + L")");
        g_lastId = 0;
        SaveState();
    }

    vector<SmsRow> rows;
    if (!QueryNewer(g_lastId, rows, err)) {
        Log(L"读取通知数据库失败: " + err);
        return false;
    }
    if (rows.empty()) return false;

    for (const auto& row : rows) {
        if (row.id <= g_lastId) continue;
        g_lastId = row.id;

        wstring xml = PayloadToXml(row.payload);
        if (!IsMessageToast(row, xml)) continue;

        wstring body = JoinBody(CollectTextNodes(xml));
        wstring code = ExtractCode(body);
        if (code.empty()) {
            Log(L"新短信未找到验证码: " + OneLine(body));
            continue;
        }
        int age = AgeMinutes(row.arrival);
        if (age > kMaxCodeAgeMinutes) {
            Log(L"短信验证码已过期(" + std::to_wstring(age) + L"分钟)，跳过: " + code);
            continue;
        }
        if (CopyToClipboard(code)) {
            Log(L"已复制验证码 " + code + L" | 来源: " + OneLine(body));
            if (!quietStart) Balloon(L"验证码已复制", code);
        } else {
            Log(L"复制验证码失败: " + code);
            if (!quietStart) Balloon(L"复制验证码失败", code);
        }
    }
    SaveState();
    return true;
}

// ---------------------------------------------------------------------------
// 命令：--list
// ---------------------------------------------------------------------------

static int CommandList(int limit) {
    vector<SmsRow> rows;
    wstring err;
    if (!QueryRecent(limit, rows, err)) {
        Print(L"错误: " + err + L"\r\n");
        return 1;
    }
    std::reverse(rows.begin(), rows.end());

    int shown = 0;
    for (const auto& row : rows) {
        wstring xml = PayloadToXml(row.payload);
        if (!IsMessageToast(row, xml)) continue;
        vector<wstring> nodes = CollectTextNodes(xml);
        wstring sender = (!nodes.empty() && IsSenderLike(nodes[0])) ? nodes[0] : L"";
        wstring body = JoinBody(nodes);
        wstring code = ExtractCode(body);

        Print(L"[" + TimeString(row.arrival) + L"]  Id=" + std::to_wstring(row.id) + L"\r\n");
        Print(L"  处理者: " + row.handler + L"\r\n");
        if (!sender.empty()) Print(L"  发送方: " + sender + L"\r\n");
        Print(L"  正文  : " + OneLine(body, 300) + L"\r\n");
        Print(L"  验证码: " + (code.empty() ? wstring(L"（未找到）") : code) + L"\r\n\r\n");
        shown++;
    }
    if (shown == 0) Print(L"最近 " + std::to_wstring(limit) + L" 条通知中没有找到手机连接的短信。\r\n");
    return 0;
}

// ---------------------------------------------------------------------------
// 供邮箱模块（MailImap.cpp）调用的公共能力
// ---------------------------------------------------------------------------

void AppLog(const std::wstring& line) { Log(line); }
void AppPrint(const std::wstring& text) { Print(text); }
void AppEnsureConsole() { EnsureConsole(); }
bool AppCopyToClipboard(const std::wstring& text) { return CopyToClipboard(text); }
std::wstring AppExtractCode(const std::wstring& text) { return ExtractCode(text); }

// ---------------------------------------------------------------------------
// 后台模式
// ---------------------------------------------------------------------------

static void OpenLog() {
    if (FileExists(g_logPath)) ShellExecuteW(nullptr, L"open", g_logPath.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

static void ShowTrayMenu() {
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, 1, L"立即扫描");
    AppendMenuW(menu, MF_STRING, 2, L"打开日志");
    AppendMenuW(menu, MF_STRING | (IsAutostartEnabled() ? MF_CHECKED : 0), 3, L"开机自动启动");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, 5, MailIsEnabled() ? L"管理邮箱验证码..." : L"设置邮箱验证码监控...");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, 4, L"退出");

    POINT pt;
    GetCursorPos(&pt);
    SetForegroundWindow(g_hwnd);
    int cmd = (int)TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
                                  pt.x, pt.y, 0, g_hwnd, nullptr);
    DestroyMenu(menu);

    if (cmd == 1) {
        PollNewNotifications(false);
    } else if (cmd == 2) {
        OpenLog();
    } else if (cmd == 3) {
        bool enable = !IsAutostartEnabled();
        if (SetAutostart(enable)) Log(enable ? L"已开启开机自启" : L"已关闭开机自启");
    } else if (cmd == 5) {
        wchar_t exe[MAX_PATH];
        if (GetModuleFileNameW(nullptr, exe, MAX_PATH)) {
            wstring cmdLine = L"\"" + wstring(exe) + L"\" --mail-setup";
            STARTUPINFOW si = { sizeof(si) };
            PROCESS_INFORMATION pi = {};
            if (CreateProcessW(nullptr, cmdLine.data(), nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE,
                               nullptr, nullptr, &si, &pi)) {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                Balloon(kAppTitle, L"请在打开的控制台窗口完成邮箱设置，设置后重启本程序生效");
            }
        }
    } else if (cmd == 4) {
        DestroyWindow(g_hwnd);
    }
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_TIMER:
        if (wParam == kTimerId) PollNewNotifications(false);
        return 0;
    case kTrayMsg: {
        UINT ev = LOWORD(lParam);
        if (ev == WM_RBUTTONUP || ev == WM_CONTEXTMENU) ShowTrayMenu();
        else if (ev == WM_LBUTTONDBLCLK) OpenLog();
        return 0;
    }
    case kMailNotifyMsg: {
        MailNotification* n = reinterpret_cast<MailNotification*>(lParam);
        if (n) {
            Balloon(kAppTitle, L"邮箱验证码已复制：" + n->code + L"\n" + n->account);
            delete n;
        }
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static int RunDaemon() {
    HANDLE instance = CreateMutexW(nullptr, FALSE, L"Local\\PhoneLinkCode_SingleInstance");
    if (instance && GetLastError() == ERROR_ALREADY_EXISTS) return 0;

    if (!sql::Load()) {
        MessageBoxW(nullptr, L"无法加载 winsqlite3.dll。\n该组件由 Windows 10 1709 及以上自带。", kAppTitle, MB_ICONERROR);
        return 1;
    }
    if (!FileExists(g_dbPath)) {
        MessageBoxW(nullptr, (L"未找到 Windows 通知数据库：\n" + g_dbPath).c_str(), kAppTitle, MB_ICONERROR);
        return 1;
    }

    if (LoadState()) {
        Log(L"启动，从上次位置继续监听 (last_id=" + std::to_wstring(g_lastId) + L")");
    } else {
        wstring err;
        if (!QueryMaxId(g_lastId, err)) {
            MessageBoxW(nullptr, (L"读取通知数据库失败：\n" + err).c_str(), kAppTitle, MB_ICONERROR);
            return 1;
        }
        SaveState();
        Log(L"首次运行，从当前最新通知开始监听 (last_id=" + std::to_wstring(g_lastId) + L")");
    }

    const wchar_t* cls = L"PhoneLinkCodeHiddenWindow";
    HICON appIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(1));
    if (!appIcon) appIcon = LoadIconW(nullptr, IDI_APPLICATION);
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = cls;
    wc.hIcon = appIcon;
    wc.hIconSm = appIcon;
    RegisterClassExW(&wc);

    g_hwnd = CreateWindowExW(WS_EX_TOOLWINDOW, cls, kAppTitle, 0, 0, 0, 0, 0,
                             nullptr, nullptr, wc.hInstance, nullptr);
    if (!g_hwnd) return 1;

    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = g_hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = kTrayMsg;
    g_nid.hIcon = appIcon;
    wcsncpy_s(g_nid.szTip, L"手机连接验证码助手（双击打开日志）", _TRUNCATE);
    g_trayAdded = Shell_NotifyIconW(NIM_ADD, &g_nid) != FALSE;

    SetTimer(g_hwnd, kTimerId, kPollIntervalMs, nullptr);
    PollNewNotifications(true);
    MailStartWorker(g_hwnd);
    if (MailIsEnabled()) {
        int n = MailEnabledCount();
        Balloon(kAppTitle, L"已启动：短信和 " + std::to_wstring(n) + L" 个邮箱的验证码都会自动复制到剪贴板");
    } else
        Balloon(kAppTitle, L"已启动，收到短信验证码后将自动复制到剪贴板");

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    MailStopWorker();
    if (g_trayAdded) Shell_NotifyIconW(NIM_DELETE, &g_nid);
    if (instance) CloseHandle(instance);
    return 0;
}

// ---------------------------------------------------------------------------
// 入口
// ---------------------------------------------------------------------------

static void ShowUsage() {
    Print(
        L"手机连接验证码助手\r\n"
        L"从「手机连接」的短信通知或邮箱（IMAP 只读）中提取验证码，并自动复制到剪贴板。\r\n\r\n"
        L"用法:\r\n"
        L"  PhoneLinkCode.exe                后台运行（托盘图标，每 2 秒检查短信，按间隔检查邮箱）\r\n"
        L"  PhoneLinkCode.exe --list [N]     列出最近 N 条手机连接短信及提取结果（默认 10）\r\n"
        L"  PhoneLinkCode.exe --extract TEXT 测试验证码提取逻辑，不修改剪贴板\r\n"
        L"  PhoneLinkCode.exe --install      加入当前用户的开机启动项\r\n"
        L"  PhoneLinkCode.exe --uninstall    移除开机启动项\r\n\r\n"
        L"邮箱（可配置多个账号，浏览器网页邮箱也可用，需开启 IMAP）:\r\n"
        L"  PhoneLinkCode.exe --mail-setup   交互式添加/更新邮箱（授权码用 DPAPI 加密保存在本机）\r\n"
        L"  PhoneLinkCode.exe --mail-list    列出已配置的邮箱\r\n"
        L"  PhoneLinkCode.exe --mail-check [N]  立即检查所有邮箱最近 N 封邮件（默认 5）\r\n"
        L"  PhoneLinkCode.exe --mail-parse FILE 解析 .eml 文件并测试验证码提取\r\n"
        L"  PhoneLinkCode.exe --mail-ping HOST[:PORT] 测试 IMAP TLS 连接（默认 imap.qq.com:993）\r\n"
        L"  PhoneLinkCode.exe --mail-disable [EMAIL] 关闭邮箱监控（省略 EMAIL 则全部关闭）\r\n"
        L"  PhoneLinkCode.exe --mail-remove EMAIL    删除指定邮箱配置\r\n"
        L"  提示: QQ/163 需在邮箱设置中开启 IMAP 并使用“授权码”；Gmail 需使用应用专用密码;\r\n"
        L"        Microsoft 账号(outlook/hotmail)已基本停用密码登录，暂不支持 OAuth。\r\n\r\n"
        L"状态与日志目录: %LOCALAPPDATA%\\PhoneLinkCode\\\r\n"
        L"  app.log 运行日志   state.txt 短信进度   mail.ini 邮箱配置\r\n"
        L"环境变量（调试用）: PHONELINKCODE_DB、PHONELINKCODE_HOME 可覆盖数据库/状态目录\r\n");
}

int APIENTRY wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return 1;

    // 路径初始化
    PWSTR localAppData = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &localAppData))) {
        wstring base(localAppData);
        CoTaskMemFree(localAppData);
        wstring homeOverride = GetEnvVar(L"PHONELINKCODE_HOME");
        wstring dbOverride = GetEnvVar(L"PHONELINKCODE_DB");
        g_homeDir = homeOverride.empty() ? base + L"\\PhoneLinkCode" : homeOverride;
        g_dbPath = dbOverride.empty()
                       ? base + L"\\Microsoft\\Windows\\Notifications\\wpndatabase.db"
                       : dbOverride;
        EnsureDir(g_homeDir);
        g_logPath = g_homeDir + L"\\app.log";
        g_statePath = g_homeDir + L"\\state.txt";
        MailInit(g_homeDir);
    } else {
        LocalFree(argv);
        return 1;
    }

    auto argIs = [&](const wchar_t* s) { return _wcsicmp(argv[1], s) == 0; };

    if (argc >= 2) {
        if (argIs(L"--help") || argIs(L"-h") || argIs(L"/?")) {
            EnsureConsole();
            ShowUsage();
            LocalFree(argv);
            return 0;
        }
        if (argIs(L"--list")) {
            EnsureConsole();
            int limit = 10;
            if (argc >= 3) {
                int v = _wtoi(argv[2]);
                if (v > 0 && v <= 500) limit = v;
            }
            int rc = CommandList(limit);
            LocalFree(argv);
            return rc;
        }
        if (argIs(L"--extract")) {
            EnsureConsole();
            if (argc >= 3) {
                wstring code = ExtractCode(argv[2]);
                Print(code.empty() ? L"（未找到验证码）\r\n" : (code + L"\r\n"));
            } else {
                Print(L"用法: PhoneLinkCode.exe --extract \"短信文本\"\r\n");
            }
            LocalFree(argv);
            return 0;
        }
        if (argIs(L"--mail-setup")) {
            EnsureConsole();
            MailSetupInteractive();
            LocalFree(argv);
            return 0;
        }
        if (argIs(L"--mail-check")) {
            EnsureConsole();
            int n = 5;
            if (argc >= 3) {
                int v = _wtoi(argv[2]);
                if (v > 0 && v <= 50) n = v;
            }
            MailCheckRecent(n);
            LocalFree(argv);
            return 0;
        }
        if (argIs(L"--mail-disable")) {
            EnsureConsole();
            MailDisable(argc >= 3 ? argv[2] : L"");
            LocalFree(argv);
            return 0;
        }
        if (argIs(L"--mail-remove")) {
            EnsureConsole();
            if (argc >= 3) MailRemove(argv[2]);
            else Print(L"用法: PhoneLinkCode.exe --mail-remove someone@example.com\r\n");
            LocalFree(argv);
            return 0;
        }
        if (argIs(L"--mail-list")) {
            EnsureConsole();
            MailList();
            LocalFree(argv);
            return 0;
        }
        if (argIs(L"--mail-parse")) {
            EnsureConsole();
            if (argc >= 3) MailParseFile(argv[2]);
            else Print(L"用法: PhoneLinkCode.exe --mail-parse 邮件.eml\r\n");
            LocalFree(argv);
            return 0;
        }
        if (argIs(L"--mail-ping")) {
            EnsureConsole();
            wstring target = argc >= 3 ? argv[2] : L"imap.qq.com:993";
            MailPing(target);
            LocalFree(argv);
            return 0;
        }
        if (argIs(L"--install") || argIs(L"--uninstall")) {
            EnsureConsole();
            bool enable = argIs(L"--install");
            if (SetAutostart(enable)) {
                Log(enable ? L"已加入开机启动项" : L"已移除开机启动项");
                Print(enable ? L"已加入开机启动项（当前用户）。\r\n" : L"已移除开机启动项。\r\n");
            } else {
                Print(L"设置开机启动失败（请检查注册表权限）。\r\n");
            }
            LocalFree(argv);
            return 0;
        }
    }

    LocalFree(argv);
    return RunDaemon();
}
