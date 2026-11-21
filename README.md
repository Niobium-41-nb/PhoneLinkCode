# 手机连接验证码助手 (PhoneLinkCode)

一个常驻托盘的 Windows 小工具：从「手机连接」(Phone Link) 镜像来的**短信**，以及通过 **IMAP 只读**方式监控的**邮箱**里自动提取验证码，并直接写入剪贴板。收到验证码时托盘弹出提示，登录时直接 `Ctrl+V` 即可。

纯 Win32 + C++17 实现，不依赖任何第三方库（SQLite 走系统自带的 `winsqlite3.dll`，TLS 走系统 Schannel）。

## 下载

- 最新发行版：[GitHub Releases](https://github.com/Niobium-41-nb/PhoneLinkCode/releases/latest)
- v1.0.0 安装包：[PhoneLinkCode-Setup-1.0.0.exe](https://github.com/Niobium-41-nb/PhoneLinkCode/releases/download/v1.0.0/PhoneLinkCode-Setup-1.0.0.exe)（双击安装，自动创建开始菜单快捷方式；静态链接运行库，无需安装 VC++ 运行库；无需管理员权限）

```powershell
# 静默安装 / 卸载
PhoneLinkCode-Setup-1.0.0.exe /S
PhoneLinkCode-Setup-1.0.0.exe --uninstall --silent
```

## 功能

- **短信**：轮询 Windows 通知数据库 `wpndatabase.db`，只读取「手机连接」写入的短信通知，按「验证码/校验码/动态码/code…」等关键字邻近规则提取 4–8 位数字。
- **邮箱**：IMAP over TLS 只读监控（`EXAMINE INBOX` + `BODY.PEEK[]`，**不会把邮件标记为已读**），支持 QQ / 163 / 126 / 企业微信邮箱 / 139 / 阿里 / Gmail 等。每个账号保持长连接、每 2 秒检查一次新邮件。
- **多邮箱并行**：可添加任意多个邮箱账号，每个账号独立线程、独立监听进度，一个账号故障不影响其他账号。
- **原生图形界面配置**：托盘右键「管理邮箱验证码…」或运行 `--mail-ui` 打开 Win32 窗口，添加、编辑、停用、删除邮箱；保存前先实际连接登录验证，配置修改后立即生效，无需重启程序。
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
   /link /SUBSYSTEM:WINDOWS user32.lib gdi32.lib shell32.lib advapi32.lib ole32.lib ^
   ws2_32.lib crypt32.lib secur32.lib
```

成功后得到 `PhoneLinkCode.exe`：`/MT` 静态链接 C/C++ 运行库，导入表里只有 `user32/gdi32/shell32/advapi32/ole32/ws2_32/crypt32/secur32/kernel32`，拷到别的 Windows 机器上无需安装 VC++ 运行库。

> 源码含中文，必须保留 `/utf-8`，否则会出现乱码或 C4819 警告。

## 制作安装包

在 `PhoneLinkCode.exe` 构建完成后运行：

```bat
build-installer.bat
```

输出 `PhoneLinkCode-Setup-1.0.0.exe`。安装包内嵌程序、README 与图标，不依赖 Inno Setup / NSIS：按用户安装到 `%LOCALAPPDATA%\Programs\PhoneLinkCode`，创建开始菜单快捷方式与「应用和功能」卸载项，无需管理员权限；支持 `/S` 静默安装、`--uninstall --silent` 静默卸载，卸载时保留邮箱配置与日志。

## 使用

### 1. 启动后台模式

双击 `PhoneLinkCode.exe`（或命令行不带参数运行）。程序没有主窗口，只出现在托盘：

- 右键托盘图标：立即扫描 / 打开日志 / 开机自动启动 / 管理邮箱验证码（原生窗口） / 退出。
- 双击托盘图标：打开 `app.log`。
- 托盘提示（Win11 里可能在折叠区）：每次复制验证码都会弹出气泡。

也可以从终端打开邮箱管理窗口：

```bat
PhoneLinkCode.exe --mail-ui
```

若后台程序已在运行，会直接把它的管理窗口叫到前台；未运行则按后台模式启动并打开窗口。

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

### 3. 邮箱验证码配置（支持多个邮箱）

程序不依赖网页邮箱页面，直接连邮箱的 IMAP 服务器，所以先在邮箱里**开启 IMAP 并拿到授权码/应用密码**：

| 邮箱 | 开启位置 | 登录凭证 |
| --- | --- | --- |
| QQ 邮箱 | 设置 → 账号 → 开启 IMAP/SMTP 服务 | 生成的**授权码** |
| 163 / 126 | 设置 → POP3/SMTP/IMAP → 开启 IMAP | **授权密码** |
| 企业微信邮箱 (exmail.qq.com) | 同 QQ 邮箱企业版设置 | 授权码 |
| Gmail | 设置 → 转发和 POP/IMAP → 启用 IMAP | 需先开两步验证，用**应用专用密码** |
| 139 / 阿里云邮箱 | 邮箱设置中开启 IMAP | 邮箱生成的授权码 |

然后在托盘右键选择「管理邮箱验证码…」（或运行 `PhoneLinkCode.exe --mail-ui`）打开管理窗口：

- 列表显示已配置的邮箱、服务器和启停状态；选中后可「编辑…」「删除」或「启用/停用」。
- 「添加邮箱…」打开表单，填写邮箱地址、IMAP 服务器（按域名自动带出）、端口和授权码/密码。
- 点「测试并保存」会先连接邮箱、登录并打开收件箱验证；验证通过才写入配置并立即重启后台监控，**无需退出程序**。
- 编辑已有邮箱时授权码留空即沿用已保存的授权码（不会显示明文）。

也可以在控制台运行交互式配置（功能相同，适合远程/无桌面环境）：

```bat
PhoneLinkCode.exe --mail-setup
```

先会列出已配置的邮箱，然后依次输入：

1. **邮箱地址**（如 `someone@qq.com`）：输入**新邮箱**即新增一个账号；输入**已有邮箱**则更新该账号（授权码留空可沿用原值）
2. **IMAP 服务器**：自动按域名猜测（qq.com → `imap.qq.com`，163 → `imap.163.com`，gmail → `imap.gmail.com`，其他默认 `imap.<域名>`），直接回车采用
3. **端口**：默认 `993`（SSL/TLS）
4. **授权码/密码**：输入时不回显

程序会实际连接、登录并打开收件箱验证一遍，通过后写入 `mail.ini`。新账号从**当前最新一封邮件之后**开始监听（不会把旧验证码贴出来）。

重复运行 `--mail-setup` 即可继续添加更多邮箱。每个账号在后台各有一个监控线程，日志和托盘气泡都会带上邮箱地址；某个账号连不上不会影响其他账号。

> 用 `--mail-setup` 或手工修改 `mail.ini` 后，需要重启后台程序（托盘右键 → 退出，再打开）才会生效；在图形界面里保存的配置会立即生效。

验证与排错命令：

```bat
PhoneLinkCode.exe --mail-list             :: 查看已配置的邮箱及监听进度
PhoneLinkCode.exe --mail-check 5          :: 依次检查所有邮箱最近 5 封邮件
PhoneLinkCode.exe --mail-ping             :: 测试 imap.qq.com:993 的 TLS 握手
PhoneLinkCode.exe --mail-ping imap.163.com:993
PhoneLinkCode.exe --mail-parse 示例.eml   :: 离线解析 .eml 文件，验证编码/HTML 提取
PhoneLinkCode.exe --mail-disable          :: 关闭全部邮箱监控
PhoneLinkCode.exe --mail-disable someone@qq.com   :: 只关闭指定邮箱
PhoneLinkCode.exe --mail-remove someone@qq.com    :: 删除指定邮箱配置
```

> Microsoft 个人账号（outlook.com / hotmail.com）已基本停用密码方式登录 IMAP，本程序暂不支持 OAuth，因此不建议用这类邮箱。

## 命令行参数一览

| 参数 | 说明 |
| --- | --- |
| *(无参数)* | 后台托盘运行：每 2 秒查短信；邮箱每 2 秒检查一次（`poll_seconds` 可调，默认 2 秒） |
| `--list [N]` | 列出最近 N 条手机连接短信及提取结果，默认 10，最大 500 |
| `--extract "文本"` | 测试验证码提取逻辑，只打印结果，不写剪贴板 |
| `--mail-ui` | 打开邮箱管理窗口（已运行时叫出它现有的窗口，否则后台启动并打开） |
| `--mail-setup` | 交互式添加 / 更新邮箱（可配置多个） |
| `--mail-list` | 列出已配置的邮箱、服务器、启停状态与监听进度 |
| `--mail-check [N]` | 依次检查所有邮箱最近 N 封邮件，默认 5，最大 50 |
| `--mail-ping [HOST[:PORT]]` | 测试 IMAP TLS 连接，默认 `imap.qq.com:993` |
| `--mail-parse FILE` | 解析 `.eml` 文件并测试验证码提取 |
| `--mail-disable [EMAIL]` | 关闭指定邮箱；省略 EMAIL 则关闭全部 |
| `--mail-remove EMAIL` | 删除指定邮箱配置 |
| `--install` / `--uninstall` | 添加 / 移除当前用户开机自启 |
| `--help` / `-h` / `/?` | 显示帮助 |

## 数据与安全

所有运行数据在 `%LOCALAPPDATA%\PhoneLinkCode\`：

| 文件 | 内容 |
| --- | --- |
| `app.log` | 运行日志（不含授权码） |
| `state.txt` | 已处理到的短信通知 ID |
| `mail.ini` | 邮箱配置：每个邮箱一个 `[mail.N]` 段，含地址、服务器、DPAPI 加密的授权码，以及该账号的 UIDVALIDITY / 最后处理的 UID |
| `mail.ini.bak` | 旧版单邮箱格式迁移为多邮箱时自动备份的原文件 |

`mail.ini` 中每个账号形如：

```ini
[mail.1]
enabled=1
email=someone@qq.com
host=imap.qq.com
port=993
secret=<DPAPI 密文>
poll_seconds=10
uidvalidity=1795259864
last_uid=1524
```

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
- **修改 `mail.ini` 或重新 `--mail-setup` 后不生效**：退出托盘程序再启动；用图形界面修改的配置保存后已自动生效。
- **某个邮箱停止检查**：看 `app.log` 中该邮箱的日志；`--mail-check` 会逐个账号显示连接/登录错误。某个账号失败不会影响其他账号。
- **想清空历史状态**：关闭程序后删除 `%LOCALAPPDATA%\PhoneLinkCode\state.txt`（短信进度），或删除 `mail.ini` 中对应 `[mail.N]` 段的 `uidvalidity`/`last_uid` 两行（该邮箱从最新邮件重新开始）。
