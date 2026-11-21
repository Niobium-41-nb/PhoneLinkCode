# 手机连接验证码助手 (PhoneLinkCode)

一个常驻托盘的 Windows 小工具：从「手机连接」(Phone Link) 镜像来的**短信**，以及通过 **IMAP 只读**方式监控的**邮箱**里自动提取验证码，并直接写入剪贴板。收到验证码时托盘弹出提示，登录时直接 `Ctrl+V` 即可。

纯 Win32 + C++17 实现，不依赖任何第三方库（SQLite 走系统自带的 `winsqlite3.dll`，TLS 走系统 Schannel）。

## 功能

- **短信**：轮询 Windows 通知数据库 `wpndatabase.db`，只读取「手机连接」写入的短信通知，按「验证码/校验码/动态码/code…」等关键字邻近规则提取 4–8 位数字。
- **邮箱**：IMAP over TLS 只读监控（`EXAMINE INBOX` + `BODY.PEEK[]`，**不会把邮件标记为已读**），支持 QQ / 163 / 126 / 企业微信邮箱 / 139 / 阿里 / Gmail 等。
- 支持 multipart、base64、quoted-printable、RFC 2047 编码主题、UTF-8/GBK/GB18030/Big5 等字符集，以及 HTML 邮件（验证码被 `<span>` 拆开也能合并识别）。
- 只处理 **10 分钟内**的新消息，避免把历史验证码误贴进剪贴板。
- 托盘图标、单实例、开机自启、日志查看。
- 授权码用 **Windows DPAPI** 加密后保存在本机，不明文落盘、不写日志、不进仓库。

## 环境要求

- Windows 10 1709 及以上（需要系统自带 `winsqlite3.dll`）或 Windows 11。
- 手机上安装「连接至 Windows」/ Link to Windows，PC 上安装并登录「手机连接」，且允许短信通知（可在「手机连接」设置中开启）。
- 编译需要 Visual Studio 2019/2022 的 C++ 生成工具（MSVC x64）。

## 编译

在项目目录直接运行：

```bat
build.bat
```

脚本会通过 `vswhere` 定位最新的 MSVC，调用 `vcvars64.bat`，先用 `rc.exe` 编译 `app.rc`（内嵌图标 `app.ico`），再执行：

```bat
cl /nologo /W4 /O2 /MT /std:c++17 /EHsc /utf-8 /DUNICODE /D_UNICODE ^
   PhoneLinkCode.cpp MailImap.cpp app.res ^
   /Fe:PhoneLinkCode.exe ^
   /link /SUBSYSTEM:WINDOWS user32.lib shell32.lib advapi32.lib ole32.lib ^
   ws2_32.lib crypt32.lib secur32.lib
```

成功后得到 `PhoneLinkCode.exe`：`/MT` 静态链接 C/C++ 运行库，导入表里只有 `user32/shell32/advapi32/ole32/ws2_32/crypt32/secur32/kernel32`，拷到别的 Windows 机器上无需安装 VC++ 运行库。

> 源码含中文，必须保留 `/utf-8`，否则会出现乱码或 C4819 警告。

## 使用

### 1. 启动后台模式

双击 `PhoneLinkCode.exe`（或命令行不带参数运行）。程序没有主窗口，只出现在托盘：

- 右键托盘图标：立即扫描 / 打开日志 / 开机自动启动 / 设置（或重新设置）邮箱验证码监控 / 退出。
- 双击托盘图标：打开 `app.log`。
- 托盘提示（Win11 里可能在折叠区）：每次复制验证码都会弹出气泡。

开机自启：

```bat
PhoneLinkCode.exe --install
PhoneLinkCode.exe --uninstall
```

写入的是 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`，仅当前用户，无需管理员权限。

### 2. 短信验证码（无需额外配置）

只要「手机连接」能收到短信并在 Windows 弹出通知，程序每 2 秒检查一次通知数据库即可。可以先用下面的命令确认能读到短信并看到提取结果（只读，不改剪贴板）：

```bat
PhoneLinkCode.exe --list         :: 最近 10 条
PhoneLinkCode.exe --list 50      :: 最近 50 条（上限 500）
```

```bat
PhoneLinkCode.exe --extract "【某网站】您的验证码是 847219，10 分钟内有效"
:: 输出: 847219
```

### 3. 邮箱验证码配置

程序不依赖网页邮箱页面，直接连邮箱的 IMAP 服务器，所以先在邮箱里**开启 IMAP 并拿到授权码/应用密码**：

| 邮箱 | 开启位置 | 登录凭证 |
| --- | --- | --- |
| QQ 邮箱 | 设置 → 账号 → 开启 IMAP/SMTP 服务 | 生成的**授权码** |
| 163 / 126 | 设置 → POP3/SMTP/IMAP → 开启 IMAP | **授权密码** |
| 企业微信邮箱 (exmail.qq.com) | 同 QQ 邮箱企业版设置 | 授权码 |
| Gmail | 设置 → 转发和 POP/IMAP → 启用 IMAP | 需先开两步验证，用**应用专用密码** |
| 139 / 阿里云邮箱 | 邮箱设置中开启 IMAP | 邮箱生成的授权码 |

然后在控制台运行交互式配置：

```bat
PhoneLinkCode.exe --mail-setup
```

依次输入：

1. **邮箱地址**（如 `someone@qq.com`）
2. **IMAP 服务器**：自动按域名猜测（qq.com → `imap.qq.com`，163 → `imap.163.com`，gmail → `imap.gmail.com`，其他默认 `imap.<域名>`），直接回车采用
3. **端口**：默认 `993`（SSL/TLS）
4. **授权码/密码**：输入时不回显

程序会实际连接、登录并打开收件箱验证一遍，通过后把配置写入 `mail.ini`，从**当前最新一封邮件之后**开始监听（不会把旧验证码贴出来）。

> 修改配置后需要重启后台程序（托盘右键 → 退出，再打开）才会生效。

验证与排错命令：

```bat
PhoneLinkCode.exe --mail-check 5          :: 立即拉取最近 5 封邮件，显示发件人/主题/提取到的验证码
PhoneLinkCode.exe --mail-ping             :: 测试 imap.qq.com:993 的 TLS 握手
PhoneLinkCode.exe --mail-ping imap.163.com:993
PhoneLinkCode.exe --mail-parse 示例.eml   :: 离线解析 .eml 文件，验证编码/HTML 提取
PhoneLinkCode.exe --mail-disable          :: 关闭邮箱监控（保留已保存的配置）
```

再次运行 `--mail-setup` 可换邮箱或更新授权码。

> Microsoft 个人账号（outlook.com / hotmail.com）已基本停用密码方式登录 IMAP，本程序暂不支持 OAuth，因此不建议用这类邮箱。

## 命令行参数一览

| 参数 | 说明 |
| --- | --- |
| *(无参数)* | 后台托盘运行：每 2 秒查短信，按 `poll_seconds`（默认 10 秒）查邮箱 |
| `--list [N]` | 列出最近 N 条手机连接短信及提取结果，默认 10，最大 500 |
| `--extract "文本"` | 测试验证码提取逻辑，只打印结果，不写剪贴板 |
| `--mail-setup` | 交互式配置邮箱监控 |
| `--mail-check [N]` | 立即检查最近 N 封邮件，默认 5，最大 50 |
| `--mail-ping [HOST[:PORT]]` | 测试 IMAP TLS 连接，默认 `imap.qq.com:993` |
| `--mail-parse FILE` | 解析 `.eml` 文件并测试验证码提取 |
| `--mail-disable` | 关闭邮箱监控 |
| `--install` / `--uninstall` | 添加 / 移除当前用户开机自启 |
| `--help` / `-h` / `/?` | 显示帮助 |

## 数据与安全

所有运行数据在 `%LOCALAPPDATA%\PhoneLinkCode\`：

| 文件 | 内容 |
| --- | --- |
| `app.log` | 运行日志（不含授权码） |
| `state.txt` | 已处理到的短信通知 ID |
| `mail.ini` | 邮箱配置；`[imap] secret` 是 DPAPI 加密的授权码，`[state]` 记录 UIDVALIDITY / 最后处理的 UID |

- DPAPI 密文与当前 Windows 用户绑定，拷到别的机器/账户无法解密；泄漏 `mail.ini` 也拿不到授权码明文。
- 邮箱全程**只读**：只发 `EXAMINE`（非 `SELECT`）和 `BODY.PEEK[]`，不改已读状态、不删信、不发信。
- 短信侧以 `SQLITE_OPEN_READONLY` 只读打开 `wpndatabase.db`，不会改动通知数据库。
- 程序只处理 10 分钟内的新消息。
- 调试用环境变量：`PHONELINKCODE_HOME`（改状态目录）、`PHONELINKCODE_DB`（改通知数据库路径）。

## 验证码提取规则

1. 优先找关键字（验证码、校验码、动态码、确认码、激活码、一次性密码、verification code、otp、code、passcode…）前后 16 个字符内的 4–8 位数字，距离越近得分越高。
2. 关键词得分相同时偏好 6 位数字。
3. 没有关键字时，只有全文**唯一**一个可信候选时才采用，并排除「尾号、订单、金额、积分、快递、电话」等上下文和 `19xx/20xx` 年份数字。
4. 全角数字会先归一化为半角。

因此「尾号 1234 的卡消费 100 元」这类短信不会被误判；如果某些服务的短信模板识别不准，可用 `--extract "短信原文"` 快速调试。

## 常见问题

- **短信收不到**：确认「手机连接」能在 PC 弹出短信通知；Windows 通知被关闭/免打扰时不会写入数据库。用 `--list` 自查。
- **邮箱登录失败**：绝大多数情况是用了登录密码而不是授权码，或没在邮箱设置里开启 IMAP。用 `--mail-ping` 先确认网络/TLS 可达。
- **163 邮箱超时**：程序已优先使用 IPv4（部分邮箱的 IPv6 入口能握手但不返回 IMAP 问候）；仍失败时检查本机 IPv6 代理/防火墙。
- **修改 `mail.ini` 或重新 `--mail-setup` 后不生效**：退出托盘程序再启动。
- **想清空历史状态**：关闭程序后删除 `%LOCALAPPDATA%\PhoneLinkCode\state.txt`（短信进度）或 `mail.ini` 中的 `[state]` 段即可。
