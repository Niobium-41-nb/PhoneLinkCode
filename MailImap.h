#pragma once
#include <windows.h>
#include <string>
#include <vector>

// 主程序提供的公共能力
void AppLog(const std::wstring& line);
void AppPrint(const std::wstring& text);
void AppEnsureConsole();
bool AppCopyToClipboard(const std::wstring& text);
std::wstring AppExtractCode(const std::wstring& text);

// 邮箱监控通知消息：lParam 为 new MailNotification*，由 UI 线程 delete
constexpr UINT kMailNotifyMsg = WM_APP + 10;

struct MailNotification {
    std::wstring code;
    std::wstring account;
};

void MailInit(const std::wstring& homeDir);
bool MailIsEnabled();
int MailEnabledCount();
bool MailSetupInteractive();
bool MailDisable(const std::wstring& email);   // 空串表示关闭全部
bool MailList();
bool MailRemove(const std::wstring& email);
void MailCheckRecent(int count);
bool MailParseFile(const std::wstring& path);
bool MailPing(const std::wstring& hostPort);
void MailStartWorker(HWND notifyWnd);
void MailStopWorker();

// 图形界面（邮箱管理窗口）使用的接口
struct MailAccountInfo {
    std::wstring email;
    std::wstring host;
    int port = 993;
    bool enabled = false;
    bool hasSecret = false;
};

std::vector<MailAccountInfo> MailGetAccounts();
std::wstring MailGuessHost(const std::wstring& email);

// secretOwnerEmail：授权码留空时复用该账号已保存的授权码（新账号传空串）
bool MailTestAccount(const std::wstring& secretOwnerEmail, const std::wstring& email,
                     const std::wstring& host, int port, const std::wstring& secret,
                     std::wstring& message, long long& uidValidity, long long& uidNext);
// oldEmail 为空表示新增账号；secret 为空表示沿用已保存的授权码
bool MailSaveAccount(const std::wstring& oldEmail, const std::wstring& email,
                     const std::wstring& host, int port, const std::wstring& secret,
                     bool enabled, long long uidValidity, long long uidNext,
                     std::wstring& message);
bool MailSetEnabled(const std::wstring& email, bool enabled, std::wstring& message);
bool MailRemoveAccount(const std::wstring& email, std::wstring& message);
// 重新读取配置并重启后台监控线程，修改邮箱后立即生效
void MailReloadWorkers(HWND notifyWnd);
