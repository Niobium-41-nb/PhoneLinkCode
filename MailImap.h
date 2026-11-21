#pragma once
#include <windows.h>
#include <string>

// 主程序提供的公共能力
void AppLog(const std::wstring& line);
void AppPrint(const std::wstring& text);
void AppEnsureConsole();
bool AppCopyToClipboard(const std::wstring& text);
std::wstring AppExtractCode(const std::wstring& text);

// 邮箱监控通知消息：lParam 为 new wstring*(验证码)，由 UI 线程 delete
constexpr UINT kMailNotifyMsg = WM_APP + 10;

void MailInit(const std::wstring& homeDir);
bool MailIsEnabled();
bool MailSetupInteractive();
bool MailDisable();
void MailCheckRecent(int count);
bool MailParseFile(const std::wstring& path);
bool MailPing(const std::wstring& hostPort);
void MailStartWorker(HWND notifyWnd);
void MailStopWorker();
