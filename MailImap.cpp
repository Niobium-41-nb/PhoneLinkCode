// MailImap.cpp
// 只读 IMAP 邮箱验证码监控：Schannel TLS + IMAP4rev1 + MIME 解码。
// 支持 QQ / 163 / 126 / Gmail(应用专用密码) 等常见 IMAP 服务。
// 凭据使用 Windows DPAPI 加密后保存在 %LOCALAPPDATA%\PhoneLinkCode\mail.ini。

#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include "MailImap.h"

#define SECURITY_WIN32
#include <sspi.h>
#include <schannel.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <algorithm>
#include <memory>
#include <mutex>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

using std::wstring;
using std::string;
using std::vector;

// ---------------------------------------------------------------------------
// 字符串工具
// ---------------------------------------------------------------------------

static bool IsDigitA(char c) { return c >= '0' && c <= '9'; }

static bool IsSpaceW(wchar_t c) {
    return c == L' ' || c == L'\t' || c == L'\r' || c == L'\n';
}

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

static string LowerAscii(string s) {
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return s;
}

static string TrimAscii(const string& s) {
    size_t b = 0, e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) b++;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) e--;
    return s.substr(b, e - b);
}

static wstring SafeOneLine(const wstring& s, size_t maxLen = 120) {
    wstring out;
    bool lastSpace = false;
    for (wchar_t c : s) {
        wchar_t x = (c == L'\r' || c == L'\n' || c == L'\t') ? L' ' : c;
        if (x == L' ' || x == 0x3000) {
            if (lastSpace) continue;
            lastSpace = true;
        } else {
            lastSpace = false;
        }
        out += x;
        if (out.size() >= maxLen) { out += L"..."; break; }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Base64
// ---------------------------------------------------------------------------

static const char kBase64Chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static string Base64Encode(const unsigned char* data, size_t len) {
    string out;
    out.reserve((len + 2) / 3 * 4);
    for (size_t i = 0; i < len; i += 3) {
        unsigned v = data[i] << 16;
        if (i + 1 < len) v |= data[i + 1] << 8;
        if (i + 2 < len) v |= data[i + 2];
        out += kBase64Chars[(v >> 18) & 63];
        out += kBase64Chars[(v >> 12) & 63];
        out += (i + 1 < len) ? kBase64Chars[(v >> 6) & 63] : '=';
        out += (i + 2 < len) ? kBase64Chars[v & 63] : '=';
    }
    return out;
}

static int Base64Value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static string Base64Decode(const string& s) {
    string out;
    int val = 0, bits = 0;
    for (char c : s) {
        if (c == '=') break;
        int v = Base64Value(c);
        if (v < 0) continue;
        val = (val << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out += (char)((val >> bits) & 0xFF);
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// 配置（mail.ini）+ DPAPI
// ---------------------------------------------------------------------------

struct MailConfig {
    wstring section;            // mail.1 / mail.2 ...
    bool enabled = false;
    wstring email;
    wstring host;
    int port = 993;
    wstring secretB64;          // DPAPI 加密后的授权码
    int pollSeconds = 10;
    long long uidValidity = 0;
    long long lastUid = 0;
};

static vector<MailConfig> g_cfgs;
static wstring g_cfgPath;
static std::mutex g_iniLock;

static int IniInt(const wstring& sec, const wchar_t* key, int def) {
    return (int)GetPrivateProfileIntW(sec.c_str(), key, def, g_cfgPath.c_str());
}

static wstring IniString(const wstring& sec, const wchar_t* key) {
    wchar_t buf[2048] = {};
    GetPrivateProfileStringW(sec.c_str(), key, L"", buf, 2048, g_cfgPath.c_str());
    return buf;
}

static void IniWrite(const wstring& sec, const wstring& key, const wstring& value) {
    std::lock_guard<std::mutex> lock(g_iniLock);
    WritePrivateProfileStringW(sec.c_str(), key.c_str(), value.c_str(), g_cfgPath.c_str());
}

static void IniDeleteSection(const wstring& sec) {
    std::lock_guard<std::mutex> lock(g_iniLock);
    WritePrivateProfileStringW(sec.c_str(), nullptr, nullptr, g_cfgPath.c_str());
}

static vector<wstring> IniSections() {
    vector<wstring> out;
    DWORD size = 4096;
    vector<wchar_t> buf;
    for (int tries = 0; tries < 4; ++tries) {
        buf.assign(size, L'\0');
        DWORD n = GetPrivateProfileSectionNamesW(buf.data(), size, g_cfgPath.c_str());
        if (n >= size - 2) { size *= 2; continue; }
        for (DWORD i = 0; i < n;) {
            wstring s(buf.data() + i);
            i += (DWORD)s.size() + 1;
            if (!s.empty()) out.push_back(s);
        }
        return out;
    }
    return out;
}

static bool SectionLess(const wstring& a, const wstring& b) {
    long long na = _wtoi64(a.c_str() + 5);
    long long nb = _wtoi64(b.c_str() + 5);
    if (na != nb) return na < nb;
    return a < b;
}

static MailConfig LoadAccount(const wstring& sec) {
    MailConfig c;
    c.section = sec;
    c.enabled = IniInt(sec, L"enabled", 0) != 0;
    c.email = IniString(sec, L"email");
    c.host = IniString(sec, L"host");
    int port = IniInt(sec, L"port", 993);
    c.port = port > 0 && port < 65536 ? port : 993;
    c.secretB64 = IniString(sec, L"secret");
    int poll = IniInt(sec, L"poll_seconds", 10);
    c.pollSeconds = poll < 3 ? 3 : (poll > 300 ? 300 : poll);
    c.uidValidity = _wtoi64(IniString(sec, L"uidvalidity").c_str());
    c.lastUid = _wtoi64(IniString(sec, L"last_uid").c_str());
    return c;
}

static void SaveState(const MailConfig& c) {
    IniWrite(c.section, L"uidvalidity", std::to_wstring(c.uidValidity));
    IniWrite(c.section, L"last_uid", std::to_wstring(c.lastUid));
}

static void SaveAccount(const MailConfig& c) {
    IniWrite(c.section, L"enabled", c.enabled ? L"1" : L"0");
    IniWrite(c.section, L"email", c.email);
    IniWrite(c.section, L"host", c.host);
    IniWrite(c.section, L"port", std::to_wstring(c.port));
    IniWrite(c.section, L"secret", c.secretB64);
    IniWrite(c.section, L"poll_seconds", std::to_wstring(c.pollSeconds));
    SaveState(c);
}

static bool ConfigComplete(const MailConfig& c) {
    return !c.email.empty() && !c.host.empty() && !c.secretB64.empty();
}

static MailConfig* FindAccount(const wstring& email) {
    for (auto& c : g_cfgs)
        if (!c.email.empty() && _wcsicmp(c.email.c_str(), email.c_str()) == 0) return &c;
    return nullptr;
}

// 旧版单邮箱配置（[imap]/[state]）自动迁移为 [mail.1]
static void MigrateLegacyConfig() {
    wstring email = IniString(L"imap", L"email");
    if (email.empty()) return;

    wstring backup = g_cfgPath + L".bak";
    CopyFileW(g_cfgPath.c_str(), backup.c_str(), FALSE);

    MailConfig c;
    c.section = L"mail.1";
    c.enabled = IniInt(L"imap", L"enabled", 0) != 0;
    c.email = email;
    c.host = IniString(L"imap", L"host");
    int port = IniInt(L"imap", L"port", 993);
    c.port = port > 0 && port < 65536 ? port : 993;
    c.secretB64 = IniString(L"imap", L"secret");
    int poll = IniInt(L"imap", L"poll_seconds", 10);
    c.pollSeconds = poll < 3 ? 3 : (poll > 300 ? 300 : poll);
    c.uidValidity = _wtoi64(IniString(L"state", L"uidvalidity").c_str());
    c.lastUid = _wtoi64(IniString(L"state", L"last_uid").c_str());
    c.enabled = c.enabled && ConfigComplete(c);

    SaveAccount(c);
    IniDeleteSection(L"state");
    IniDeleteSection(L"imap");
    g_cfgs.push_back(c);
    AppLog(L"已将单邮箱配置迁移为多邮箱格式 [mail.1]，原文件备份为 mail.ini.bak");
}

static void LoadConfig() {
    g_cfgs.clear();
    vector<wstring> secs;
    for (const auto& s : IniSections())
        if (s.rfind(L"mail.", 0) == 0) secs.push_back(s);
    std::sort(secs.begin(), secs.end(), SectionLess);
    for (const auto& s : secs) {
        MailConfig c = LoadAccount(s);
        if (!c.email.empty()) g_cfgs.push_back(c);
    }
    if (g_cfgs.empty()) MigrateLegacyConfig();
}

static string ProtectSecret(const wstring& plain) {
    DATA_BLOB in = { (DWORD)(plain.size() * sizeof(wchar_t)), (BYTE*)plain.data() };
    DATA_BLOB out = {};
    if (!CryptProtectData(&in, L"PhoneLinkCode IMAP", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &out))
        return {};
    string b64 = Base64Encode(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return b64;
}

static bool UnprotectSecret(const string& b64, wstring& out) {
    string blob = Base64Decode(b64);
    if (blob.empty()) return false;
    DATA_BLOB in = { (DWORD)blob.size(), (BYTE*)blob.data() };
    DATA_BLOB plain = {};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &plain))
        return false;
    out.assign((const wchar_t*)plain.pbData, plain.cbData / sizeof(wchar_t));
    LocalFree(plain.pbData);
    return true;
}

// ---------------------------------------------------------------------------
// TLS 客户端（Schannel）
// ---------------------------------------------------------------------------

static string SecStatusText(SECURITY_STATUS ss) {
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%08lX", (unsigned long)ss);
    return buf;
}

class TlsSocket {
public:
    ~TlsSocket() { Close(); }

    bool Connect(const wstring& host, int port, wstring& err);
    void Close();
    bool SendAll(const string& data, wstring& err) { return SendEncrypted(data, err); }
    bool ReadLine(string& line, wstring& err);
    bool ReadExact(size_t n, string& out, wstring& err);

private:
    SOCKET sock_ = INVALID_SOCKET;
    CredHandle cred_ = {};
    CtxtHandle ctx_ = {};
    bool credOk_ = false;
    bool ctxOk_ = false;
    string plain_;
    string raw_;

    bool Handshake(const wstring& host, wstring& err);
    bool ValidateCert(const wstring& host, wstring& err);
    bool NetSend(const char* data, size_t len, wstring& err);
    bool NetRecv(string& out, wstring& err);
    bool DecryptPending(wstring& err);
    bool Fill(wstring& err);
    bool SendEncrypted(const string& data, wstring& err);
};

static bool WsaInit() {
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        WSADATA wd;
        ok = WSAStartup(MAKEWORD(2, 2), &wd) == 0;
    });
    return ok;
}

bool TlsSocket::Connect(const wstring& host, int port, wstring& err) {
    Close();
    if (!WsaInit()) { err = L"Winsock 初始化失败"; return false; }

    wchar_t portStr[16];
    swprintf_s(portStr, L"%d", port);

    auto tryFamily = [&](int family) -> SOCKET {
        addrinfoW hints = {};
        hints.ai_family = family;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        addrinfoW* res = nullptr;
        if (GetAddrInfoW(host.c_str(), portStr, &hints, &res) != 0) return INVALID_SOCKET;

        SOCKET s = INVALID_SOCKET;
        for (addrinfoW* p = res; p; p = p->ai_next) {
            s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (s == INVALID_SOCKET) continue;
            u_long nb = 1;
            ioctlsocket(s, FIONBIO, &nb);
            int rc = connect(s, p->ai_addr, (int)p->ai_addrlen);
            if (rc == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
                fd_set wr;
                FD_ZERO(&wr);
                FD_SET(s, &wr);
                timeval tv = { 10, 0 };
                rc = select(0, nullptr, &wr, nullptr, &tv);
                if (rc > 0) {
                    int soErr = 0;
                    int len = sizeof(soErr);
                    getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&soErr, &len);
                    rc = (soErr == 0) ? 0 : SOCKET_ERROR;
                } else {
                    rc = SOCKET_ERROR;
                }
            }
            if (rc == 0) break;
            closesocket(s);
            s = INVALID_SOCKET;
        }
        FreeAddrInfoW(res);
        return s;
    };

    // 优先 IPv4：部分邮箱服务器的 IPv6 入口能完成 TLS 握手但不返回 IMAP 问候
    SOCKET s = tryFamily(AF_INET);
    if (s == INVALID_SOCKET) s = tryFamily(AF_UNSPEC);
    if (s == INVALID_SOCKET) {
        err = L"连接服务器失败: " + host + L":" + std::to_wstring(port);
        return false;
    }
    u_long nb = 0;
    ioctlsocket(s, FIONBIO, &nb);
    DWORD timeout = 25000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    sock_ = s;

    return Handshake(host, err);
}

void TlsSocket::Close() {
    if (ctxOk_) { DeleteSecurityContext(&ctx_); ctxOk_ = false; }
    if (credOk_) { FreeCredentialsHandle(&cred_); credOk_ = false; }
    if (sock_ != INVALID_SOCKET) { closesocket(sock_); sock_ = INVALID_SOCKET; }
    plain_.clear();
    raw_.clear();
}

bool TlsSocket::NetSend(const char* data, size_t len, wstring& err) {
    size_t sent = 0;
    while (sent < len) {
        int n = send(sock_, data + sent, (int)(len - sent), 0);
        if (n <= 0) { err = L"TLS 发送失败"; return false; }
        sent += (size_t)n;
    }
    return true;
}

bool TlsSocket::NetRecv(string& out, wstring& err) {
    char buf[16384];
    int n = recv(sock_, buf, sizeof(buf), 0);
    if (n <= 0) {
        err = (n == 0) ? L"服务器关闭了连接" : L"TLS 接收超时或失败";
        return false;
    }
    out.append(buf, (size_t)n);
    return true;
}

bool TlsSocket::Handshake(const wstring& host, wstring& err) {
    SCHANNEL_CRED sc = {};
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    sc.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_USE_STRONG_CRYPTO;
    sc.dwMinimumCipherStrength = 128;

    TimeStamp expiry;
    SECURITY_STATUS ss = AcquireCredentialsHandleW(
        nullptr, const_cast<LPWSTR>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND, nullptr,
        &sc, nullptr, nullptr, &cred_, &expiry);
    if (ss != SEC_E_OK) { err = L"初始化 Schannel 失败: " + Utf8ToWide(SecStatusText(ss)); return false; }
    credOk_ = true;

    DWORD flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                  ISC_REQ_STREAM | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_EXTENDED_ERROR |
                  ISC_REQ_MANUAL_CRED_VALIDATION;

    string recvBuf;
    while (true) {
        SecBuffer out = { 0, SECBUFFER_TOKEN, nullptr };
        SecBufferDesc outDesc = { SECBUFFER_VERSION, 1, &out };
        SecBuffer in[2] = { { 0, SECBUFFER_EMPTY, nullptr }, { 0, SECBUFFER_EMPTY, nullptr } };
        SecBufferDesc inDesc = { SECBUFFER_VERSION, 2, in };
        bool hasInput = !recvBuf.empty();
        if (hasInput) {
            in[0].BufferType = SECBUFFER_TOKEN;
            in[0].pvBuffer = recvBuf.data();
            in[0].cbBuffer = (unsigned long)recvBuf.size();
        }
        unsigned long outFlags = 0;
        ss = InitializeSecurityContextW(&cred_, ctxOk_ ? &ctx_ : nullptr,
                                        const_cast<SEC_WCHAR*>(host.c_str()), flags, 0, 0,
                                        hasInput ? &inDesc : nullptr, 0, &ctx_, &outDesc,
                                        &outFlags, nullptr);
        if (ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED) ctxOk_ = true;

        if (out.pvBuffer) {
            bool ok = NetSend((const char*)out.pvBuffer, out.cbBuffer, err);
            FreeContextBuffer(out.pvBuffer);
            if (!ok) return false;
        }

        if (ss != SEC_E_OK && ss != SEC_I_CONTINUE_NEEDED && ss != SEC_E_INCOMPLETE_MESSAGE) {
            err = L"TLS 握手失败: " + Utf8ToWide(SecStatusText(ss));
            return false;
        }

        if (ss == SEC_E_INCOMPLETE_MESSAGE) {
            // 证书链较大时一个 TLS 记录会跨多个 TCP 段，必须保留已收到的数据继续追加
            string more;
            if (!NetRecv(more, err)) return false;
            recvBuf += more;
            continue;
        }

        size_t extra = 0;
        if (hasInput) {
            for (int i = 0; i < 2; ++i) {
                if (in[i].BufferType == SECBUFFER_EXTRA) extra = in[i].cbBuffer;
            }
        }

        if (ss == SEC_E_OK) {
            if (extra > 0 && extra <= recvBuf.size())
                raw_.assign(recvBuf.data() + recvBuf.size() - extra, extra);
            break;
        }

        if (extra > 0 && extra <= recvBuf.size()) recvBuf.erase(0, recvBuf.size() - extra);
        else recvBuf.clear();

        if (!hasInput || recvBuf.empty()) {
            string more;
            if (!NetRecv(more, err)) return false;
            recvBuf += more;
        }
    }

    return ValidateCert(host, err);
}

bool TlsSocket::ValidateCert(const wstring& host, wstring& err) {
    PCCERT_CONTEXT cert = nullptr;
    if (QueryContextAttributesW(&ctx_, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &cert) != SEC_E_OK || !cert) {
        err = L"无法获取服务器证书";
        return false;
    }

    CERT_CHAIN_PARA chainPara = {};
    chainPara.cbSize = sizeof(chainPara);
    chainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
    LPSTR serverAuthOid = const_cast<LPSTR>(szOID_PKIX_KP_SERVER_AUTH);
    chainPara.RequestedUsage.Usage.cUsageIdentifier = 1;
    chainPara.RequestedUsage.Usage.rgpszUsageIdentifier = &serverAuthOid;

    PCCERT_CHAIN_CONTEXT chain = nullptr;
    BOOL gotChain = CertGetCertificateChain(nullptr, cert, nullptr, nullptr, &chainPara, 0, nullptr, &chain);

    bool ok = false;
    if (gotChain && chain) {
        SSL_EXTRA_CERT_CHAIN_POLICY_PARA sslExtra = {};
        sslExtra.cbStruct = sizeof(sslExtra);
        sslExtra.dwAuthType = AUTHTYPE_SERVER;
        sslExtra.pwszServerName = const_cast<LPWSTR>(host.c_str());

        CERT_CHAIN_POLICY_PARA policyPara = {};
        policyPara.cbSize = sizeof(policyPara);
        policyPara.pvExtraPolicyPara = &sslExtra;

        CERT_CHAIN_POLICY_STATUS status = {};
        status.cbSize = sizeof(status);
        if (CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain, &policyPara, &status) &&
            status.dwError == 0) {
            ok = true;
        } else {
            err = L"服务器证书校验失败 (" + host + L", 错误 " +
                  std::to_wstring(status.dwError) + L")";
        }
        CertFreeCertificateChain(chain);
    } else {
        err = L"无法构建服务器证书链";
    }
    CertFreeCertificateContext(cert);
    return ok;
}

bool TlsSocket::DecryptPending(wstring& err) {
    while (!raw_.empty()) {
        SecBuffer bufs[4] = {};
        bufs[0].BufferType = SECBUFFER_DATA;
        bufs[0].pvBuffer = raw_.data();
        bufs[0].cbBuffer = (unsigned long)raw_.size();
        bufs[1].BufferType = SECBUFFER_EMPTY;
        bufs[2].BufferType = SECBUFFER_EMPTY;
        bufs[3].BufferType = SECBUFFER_EMPTY;
        SecBufferDesc desc = { SECBUFFER_VERSION, 4, bufs };

        SECURITY_STATUS ss = DecryptMessage(&ctx_, &desc, 0, nullptr);
        if (ss == SEC_E_INCOMPLETE_MESSAGE) return true;
        if (ss == SEC_I_CONTEXT_EXPIRED) { err = L"服务器关闭了 TLS 连接"; return false; }
        if (ss == SEC_I_RENEGOTIATE) { err = L"TLS 重新协商，稍后重连"; return false; }
        if (ss != SEC_E_OK) { err = L"TLS 解密失败: " + Utf8ToWide(SecStatusText(ss)); return false; }

        size_t extra = 0;
        for (int i = 0; i < 4; ++i) {
            if (bufs[i].BufferType == SECBUFFER_DATA && bufs[i].cbBuffer > 0)
                plain_.append((const char*)bufs[i].pvBuffer, bufs[i].cbBuffer);
            if (bufs[i].BufferType == SECBUFFER_EXTRA) extra = bufs[i].cbBuffer;
        }
        if (extra > 0) raw_.erase(0, raw_.size() - extra);
        else raw_.clear();
        if (plain_.size() > 8 * 1024 * 1024) { err = L"TLS 明文缓冲异常"; return false; }
    }
    return true;
}

bool TlsSocket::Fill(wstring& err) {
    if (!DecryptPending(err)) return false;
    // 已解出的明文可能只是半行（服务器按自身缓冲切分记录），此时必须继续读网络，
    // 否则调用方 snoop 到非空 plain_ 会原地空转
    size_t before = plain_.size();
    while (plain_.size() == before) {
        string more;
        if (!NetRecv(more, err)) return false;
        raw_ += more;
        if (!DecryptPending(err)) return false;
    }
    return true;
}

bool TlsSocket::ReadLine(string& line, wstring& err) {
    while (true) {
        size_t pos = plain_.find('\n');
        if (pos != string::npos) {
            line = plain_.substr(0, pos);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            plain_.erase(0, pos + 1);
            return true;
        }
        if (plain_.size() > 4 * 1024 * 1024) { err = L"IMAP 响应行过长"; return false; }
        if (!Fill(err)) return false;
    }
}

bool TlsSocket::ReadExact(size_t n, string& out, wstring& err) {
    while (plain_.size() < n) {
        if (!Fill(err)) return false;
    }
    out = plain_.substr(0, n);
    plain_.erase(0, n);
    return true;
}

bool TlsSocket::SendEncrypted(const string& data, wstring& err) {
    if (!ctxOk_) { err = L"TLS 未建立"; return false; }
    SecPkgContext_StreamSizes sizes = {};
    if (QueryContextAttributesW(&ctx_, SECPKG_ATTR_STREAM_SIZES, &sizes) != SEC_E_OK) {
        err = L"查询 TLS 流参数失败";
        return false;
    }

    const char* p = data.data();
    size_t left = data.size();
    while (left > 0) {
        size_t chunk = std::min<size_t>(left, sizes.cbMaximumMessage);
        vector<char> header(sizes.cbHeader), trailer(sizes.cbTrailer);
        SecBuffer bufs[4] = {};
        bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
        bufs[0].pvBuffer = header.data();
        bufs[0].cbBuffer = sizes.cbHeader;
        bufs[1].BufferType = SECBUFFER_DATA;
        bufs[1].pvBuffer = const_cast<char*>(p);
        bufs[1].cbBuffer = (unsigned long)chunk;
        bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
        bufs[2].pvBuffer = trailer.data();
        bufs[2].cbBuffer = sizes.cbTrailer;
        bufs[3].BufferType = SECBUFFER_EMPTY;
        SecBufferDesc desc = { SECBUFFER_VERSION, 4, bufs };

        SECURITY_STATUS ss = EncryptMessage(&ctx_, 0, &desc, 0);
        if (ss != SEC_E_OK) { err = L"TLS 加密失败: " + Utf8ToWide(SecStatusText(ss)); return false; }

        if (!NetSend((const char*)bufs[0].pvBuffer, bufs[0].cbBuffer, err)) return false;
        if (!NetSend((const char*)bufs[1].pvBuffer, bufs[1].cbBuffer, err)) return false;
        if (!NetSend((const char*)bufs[2].pvBuffer, bufs[2].cbBuffer, err)) return false;

        p += chunk;
        left -= chunk;
    }
    return true;
}

// ---------------------------------------------------------------------------
// IMAP 客户端
// ---------------------------------------------------------------------------

struct ImapResp {
    string text;
    vector<string> literals;
    string statusLine;
    string status;
};

class ImapClient {
public:
    bool Connect(const wstring& host, int port, wstring& err);
    bool Login(const wstring& user, const wstring& pass, wstring& err);
    bool Examine(long long& uidValidity, long long& uidNext, wstring& err);
    bool SearchRange(long long fromUid, long long toUid, vector<long long>& uids, wstring& err);
    bool SearchNew(long long afterUid, vector<long long>& uids, wstring& err);
    bool FetchSize(long long uid, long long& size, wstring& err);
    bool FetchRaw(long long uid, size_t maxSize, string& raw, wstring& err);
    void Logout();

private:
    TlsSocket tls_;
    int tag_ = 0;
    string lastErr_;

    bool Command(const string& cmd, ImapResp& resp, wstring& err);
};

static string QuoteImap(const string& s) {
    string out = "\"";
    for (char c : s) {
        if (c == '\\' || c == '"') out += '\\';
        out += c;
    }
    out += '"';
    return out;
}

bool ImapClient::Command(const string& cmd, ImapResp& resp, wstring& err) {
    resp = ImapResp();
    tag_++;
    string tag = "a" + std::to_string(tag_);
    if (!tls_.SendAll(tag + " " + cmd + "\r\n", err)) return false;

    while (true) {
        string line;
        if (!tls_.ReadLine(line, err)) return false;
        resp.text += line;
        resp.text += "\r\n";

        if (!line.empty() && line.back() == '}') {
            size_t b = line.rfind('{');
            if (b != string::npos) {
                long n = strtol(line.c_str() + b + 1, nullptr, 10);
                if (n > 0) {
                    if (n > 16 * 1024 * 1024) { err = L"IMAP 字面量过大"; return false; }
                    string lit;
                    if (!tls_.ReadExact((size_t)n, lit, err)) return false;
                    resp.literals.push_back(lit);
                    resp.text += lit;
                    continue;
                }
            }
        }

        if (line.size() >= tag.size() && line.compare(0, tag.size(), tag) == 0 &&
            (line.size() == tag.size() || line[tag.size()] == ' ')) {
            resp.statusLine = line;
            size_t sp1 = line.find(' ');
            if (sp1 != string::npos) {
                size_t sp2 = line.find(' ', sp1 + 1);
                resp.status = line.substr(sp1 + 1, sp2 == string::npos ? string::npos : sp2 - sp1 - 1);
            }
            lastErr_ = line;
            return true;
        }
    }
}

bool ImapClient::Connect(const wstring& host, int port, wstring& err) {
    if (!tls_.Connect(host, port, err)) return false;
    string greeting;
    if (!tls_.ReadLine(greeting, err)) return false;
    if (greeting.rfind("* OK", 0) != 0 && greeting.rfind("* PREAUTH", 0) != 0) {
        err = L"IMAP 服务器问候异常: " + Utf8ToWide(greeting);
        return false;
    }
    // 163/126 要求先发送 ID 命令，否则登录会被拒绝；其它服务器即使不支持也无妨
    ImapResp r;
    wstring ignore;
    Command("ID (\"name\" \"PhoneLinkCode\" \"version\" \"1.0\" \"vendor\" \"PhoneLinkCode\")", r, ignore);
    return true;
}

bool ImapClient::Login(const wstring& user, const wstring& pass, wstring& err) {
    ImapResp r;
    if (!Command("LOGIN " + QuoteImap(WideToUtf8(user)) + " " + QuoteImap(WideToUtf8(pass)), r, err))
        return false;
    if (r.status != "OK") {
        err = L"IMAP 登录失败: " + Utf8ToWide(r.statusLine);
        return false;
    }
    // 163/126 要求登录后再次发送 ID，否则后续命令报 "Unsafe Login"
    wstring idErr;
    Command("ID (\"name\" \"PhoneLinkCode\" \"version\" \"1.0\" \"vendor\" \"PhoneLinkCode\")", r, idErr);
    return true;
}

bool ImapClient::Examine(long long& uidValidity, long long& uidNext, wstring& err) {
    ImapResp r;
    if (!Command("EXAMINE INBOX", r, err)) return false;
    if (r.status != "OK") { err = L"打开收件箱失败: " + Utf8ToWide(r.statusLine); return false; }

    uidValidity = 0;
    uidNext = 0;
    size_t p = r.text.find("[UIDVALIDITY ");
    if (p != string::npos) uidValidity = _strtoi64(r.text.c_str() + p + 13, nullptr, 10);
    p = r.text.find("[UIDNEXT ");
    if (p != string::npos) uidNext = _strtoi64(r.text.c_str() + p + 9, nullptr, 10);
    return true;
}

static void ParseUidList(const string& text, vector<long long>& uids) {
    size_t pos = 0;
    while ((pos = text.find("* SEARCH", pos)) != string::npos) {
        size_t eol = text.find("\r\n", pos);
        string line = text.substr(pos + 8, eol == string::npos ? string::npos : eol - pos - 8);
        const char* p = line.c_str();
        while (*p) {
            while (*p == ' ') p++;
            if (!IsDigitA(*p)) break;
            char* end = nullptr;
            long long v = _strtoi64(p, &end, 10);
            if (end == p) break;
            uids.push_back(v);
            p = end;
        }
        pos += 8;
    }
}

bool ImapClient::SearchRange(long long fromUid, long long toUid, vector<long long>& uids, wstring& err) {
    ImapResp r;
    string cmd = "UID SEARCH UID " + std::to_string(fromUid) + ":" + std::to_string(toUid);
    if (!Command(cmd, r, err)) return false;
    if (r.status != "OK") { err = L"搜索邮件失败: " + Utf8ToWide(r.statusLine); return false; }
    ParseUidList(r.text, uids);
    return true;
}

bool ImapClient::SearchNew(long long afterUid, vector<long long>& uids, wstring& err) {
    ImapResp r;
    string cmd = "UID SEARCH UID " + std::to_string(afterUid + 1) + ":*";
    if (!Command(cmd, r, err)) return false;
    if (r.status != "OK") { err = L"搜索新邮件失败: " + Utf8ToWide(r.statusLine); return false; }
    ParseUidList(r.text, uids);
    // 有些服务器在范围无匹配时会返回当前最大 UID，这里过滤掉
    uids.erase(std::remove_if(uids.begin(), uids.end(),
                             [&](long long u) { return u <= afterUid; }),
               uids.end());
    std::sort(uids.begin(), uids.end());
    return true;
}

bool ImapClient::FetchSize(long long uid, long long& size, wstring& err) {
    ImapResp r;
    if (!Command("UID FETCH " + std::to_string(uid) + " (UID RFC822.SIZE)", r, err)) return false;
    if (r.status != "OK") { err = L"读取邮件大小失败: " + Utf8ToWide(r.statusLine); return false; }
    size = -1;
    size_t p = r.text.find("RFC822.SIZE ");
    if (p != string::npos) size = _strtoi64(r.text.c_str() + p + 12, nullptr, 10);
    return true;
}

bool ImapClient::FetchRaw(long long uid, size_t maxSize, string& raw, wstring& err) {
    raw.clear();
    long long size = -1;
    if (!FetchSize(uid, size, err)) return false;
    if (size > (long long)maxSize) return true;
    ImapResp r;
    if (!Command("UID FETCH " + std::to_string(uid) + " (UID BODY.PEEK[])", r, err)) return false;
    if (r.status != "OK") { err = L"读取邮件内容失败: " + Utf8ToWide(r.statusLine); return false; }
    const string* best = nullptr;
    for (const auto& lit : r.literals)
        if (!best || lit.size() > best->size()) best = &lit;
    if (best) raw = *best;
    return true;
}

void ImapClient::Logout() {
    ImapResp r;
    wstring ignore;
    Command("LOGOUT", r, ignore);
}

// ---------------------------------------------------------------------------
// MIME 解码
// ---------------------------------------------------------------------------

static UINT CharsetToCodepage(const string& cs) {
    string c = LowerAscii(cs);
    size_t semi = c.find(';');
    if (semi != string::npos) c = c.substr(0, semi);
    c = TrimAscii(c);
    if (c == "utf-8" || c == "utf8") return CP_UTF8;
    if (c == "gb2312" || c == "gbk" || c == "x-gbk" || c == "gb_2312-80" || c == "cp936") return 936;
    if (c == "gb18030") return 54936;
    if (c == "big5" || c == "cp950") return 950;
    if (c == "us-ascii" || c == "ascii") return 20127;
    if (c == "iso-8859-1" || c == "latin1") return 28591;
    if (c == "windows-1252" || c == "cp1252") return 1252;
    if (c == "koi8-r") return 20866;
    if (c == "shift_jis" || c == "sjis") return 932;
    return 0;
}

static wstring BytesToWide(const string& bytes, const string& charset) {
    if (bytes.empty()) return {};
    UINT cp = CharsetToCodepage(charset);
    if (cp == 0) cp = CP_UTF8;
    int n = MultiByteToWideChar(cp, cp == CP_UTF8 ? MB_ERR_INVALID_CHARS : 0,
                                bytes.data(), (int)bytes.size(), nullptr, 0);
    if (n <= 0 && cp == CP_UTF8) {
        n = MultiByteToWideChar(936, 0, bytes.data(), (int)bytes.size(), nullptr, 0);
        cp = 936;
    }
    if (n <= 0) return {};
    wstring out((size_t)n, L'\0');
    MultiByteToWideChar(cp, 0, bytes.data(), (int)bytes.size(), out.data(), n);
    return out;
}

static void SplitHeadersBody(const string& raw, string& hdrs, string& body) {
    size_t p = raw.find("\r\n\r\n");
    size_t sep = 4;
    if (p == string::npos) { p = raw.find("\n\n"); sep = 2; }
    if (p == string::npos) { hdrs = raw; body.clear(); return; }
    hdrs = raw.substr(0, p);
    body = raw.substr(p + sep);
}

static string HeaderValue(const string& hdrs, const char* name) {
    string target = LowerAscii(name) + ":";
    size_t pos = 0;
    while (pos <= hdrs.size()) {
        size_t eol = hdrs.find('\n', pos);
        string line = hdrs.substr(pos, eol == string::npos ? string::npos : eol - pos);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        string lower = LowerAscii(line);
        if (lower.rfind(target, 0) == 0) {
            string val = line.substr(target.size());
            size_t next = (eol == string::npos) ? hdrs.size() : eol + 1;
            while (next < hdrs.size()) {
                size_t e2 = hdrs.find('\n', next);
                string l2 = hdrs.substr(next, e2 == string::npos ? string::npos : e2 - next);
                if (!l2.empty() && l2.back() == '\r') l2.pop_back();
                if (!l2.empty() && (l2[0] == ' ' || l2[0] == '\t')) {
                    val += " ";
                    val += TrimAscii(l2);
                } else {
                    break;
                }
                next = (e2 == string::npos) ? hdrs.size() : e2 + 1;
            }
            return TrimAscii(val);
        }
        if (eol == string::npos) break;
        pos = eol + 1;
    }
    return {};
}

static bool ParseContentType(const string& value, string& type, string& boundary, string& charset) {
    string v = TrimAscii(value);
    size_t semi = v.find(';');
    string params;
    if (semi != string::npos) {
        params = v.substr(semi + 1);
        type = TrimAscii(v.substr(0, semi));
    } else {
        type = v;
    }
    type = LowerAscii(type);
    if (type.find('/') == string::npos) type = "text/plain";

    size_t pos = 0;
    while (pos < params.size()) {
        size_t next = params.find(';', pos);
        string kv = params.substr(pos, next == string::npos ? string::npos : next - pos);
        size_t eq = kv.find('=');
        if (eq != string::npos) {
            string key = LowerAscii(TrimAscii(kv.substr(0, eq)));
            string val = TrimAscii(kv.substr(eq + 1));
            if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
                val = val.substr(1, val.size() - 2);
            if (key == "boundary") boundary = val;
            else if (key == "charset") charset = LowerAscii(val);
        }
        if (next == string::npos) break;
        pos = next + 1;
    }
    return true;
}

static string DecodeQuotedPrintable(const string& in) {
    string out;
    for (size_t i = 0; i < in.size(); ++i) {
        char c = in[i];
        if (c == '=') {
            if (i + 1 < in.size() && in[i + 1] == '\r' && i + 2 < in.size() && in[i + 2] == '\n') {
                i += 2;
                continue;
            }
            if (i + 1 < in.size() && in[i + 1] == '\n') { i += 1; continue; }
            if (i + 2 < in.size() && isxdigit((unsigned char)in[i + 1]) && isxdigit((unsigned char)in[i + 2])) {
                auto hex = [](char h) -> int {
                    if (h >= '0' && h <= '9') return h - '0';
                    if (h >= 'a' && h <= 'f') return h - 'a' + 10;
                    if (h >= 'A' && h <= 'F') return h - 'A' + 10;
                    return 0;
                };
                out += (char)(hex(in[i + 1]) * 16 + hex(in[i + 2]));
                i += 2;
                continue;
            }
        }
        out += c;
    }
    return out;
}

static string DecodeTransfer(const string& encIn, const string& data) {
    string enc = LowerAscii(TrimAscii(encIn));
    if (enc == "base64") return Base64Decode(data);
    if (enc == "quoted-printable") return DecodeQuotedPrintable(data);
    return data;
}

static bool DecodeEncodedQ(const string& data, string& out) {
    out.clear();
    for (size_t i = 0; i < data.size(); ++i) {
        char c = data[i];
        if (c == '_') { out += ' '; continue; }
        if (c == '=' && i + 2 < data.size() && isxdigit((unsigned char)data[i + 1]) &&
            isxdigit((unsigned char)data[i + 2])) {
            auto hex = [](char h) -> int {
                if (h >= '0' && h <= '9') return h - '0';
                if (h >= 'a' && h <= 'f') return h - 'a' + 10;
                return h - 'A' + 10;
            };
            out += (char)(hex(data[i + 1]) * 16 + hex(data[i + 2]));
            i += 2;
            continue;
        }
        out += c;
    }
    return true;
}

static wstring DecodeMimeHeader(const string& v) {
    wstring out;
    string plain;
    auto flush = [&]() {
        if (!plain.empty()) {
            out += BytesToWide(plain, "utf-8");
            plain.clear();
        }
    };

    size_t i = 0;
    while (i < v.size()) {
        size_t p = v.find("=?", i);
        if (p == string::npos) { plain += v.substr(i); break; }
        plain += v.substr(i, p - i);
        size_t q1 = v.find('?', p + 2);
        size_t q2 = (q1 == string::npos) ? string::npos : v.find('?', q1 + 1);
        size_t end = (q2 == string::npos) ? string::npos : v.find("?=", q2 + 1);
        if (q1 == string::npos || q2 == string::npos || end == string::npos) {
            plain += v.substr(p);
            break;
        }
        string charset = v.substr(p + 2, q1 - p - 2);
        string enc = LowerAscii(v.substr(q1 + 1, q2 - q1 - 1));
        string data = v.substr(q2 + 1, end - q2 - 1);
        flush();
        string decoded;
        if (enc == "b") decoded = Base64Decode(data);
        else if (enc == "q") DecodeEncodedQ(data, decoded);
        else decoded = data;
        out += BytesToWide(decoded, charset);
        i = end + 2;

        size_t j = i;
        while (j < v.size() && (v[j] == ' ' || v[j] == '\t' || v[j] == '\r' || v[j] == '\n')) j++;
        if (j < v.size() && v.compare(j, 2, "=?") == 0) i = j;
    }
    flush();
    return out;
}

static void UnescapeEntities(wstring& s) {
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
                else if (ent == L"nbsp") ch = L' ';
                else if (ent.size() > 1 && ent[0] == L'#') {
                    unsigned long v = 0;
                    wchar_t* endp = nullptr;
                    if (ent[1] == L'x' || ent[1] == L'X') v = wcstoul(ent.c_str() + 2, &endp, 16);
                    else v = wcstoul(ent.c_str() + 1, &endp, 10);
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

static wstring HtmlToText(const wstring& html) {
    wstring noScript;
    wstring lower = html;
    for (wchar_t& c : lower) if (c >= L'A' && c <= L'Z') c = (wchar_t)(c - L'A' + L'a');
    size_t pos = 0;
    while (pos < html.size()) {
        size_t a = lower.find(L"<script", pos);
        size_t b = lower.find(L"<style", pos);
        size_t start = wstring::npos;
        if (a != wstring::npos && (b == wstring::npos || a < b)) {
            start = a;
            size_t end = lower.find(L"</script", start);
            if (end == wstring::npos) break;
            size_t tagEnd = lower.find(L'>', end);
            noScript += html.substr(pos, start - pos);
            pos = (tagEnd == wstring::npos) ? html.size() : tagEnd + 1;
        } else if (b != wstring::npos) {
            start = b;
            size_t end = lower.find(L"</style", start);
            if (end == wstring::npos) break;
            size_t tagEnd = lower.find(L'>', end);
            noScript += html.substr(pos, start - pos);
            pos = (tagEnd == wstring::npos) ? html.size() : tagEnd + 1;
        } else {
            noScript += html.substr(pos);
            break;
        }
    }

    wstring text;
    bool inTag = false;
    wstring tagName;
    for (size_t i = 0; i < noScript.size(); ++i) {
        wchar_t c = noScript[i];
        if (!inTag) {
            if (c == L'<') { inTag = true; tagName.clear(); }
            else text += c;
        } else {
            if (c == L'>') {
                inTag = false;
                wstring tn = tagName;
                for (wchar_t& t : tn) if (t >= L'A' && t <= L'Z') t = (wchar_t)(t - L'A' + L'a');
                if (tn.rfind(L"br", 0) == 0 || tn.rfind(L"p", 0) == 0 || tn.rfind(L"div", 0) == 0 ||
                    tn.rfind(L"tr", 0) == 0 || tn.rfind(L"td", 0) == 0 || tn.rfind(L"li", 0) == 0 ||
                    tn.rfind(L"h1", 0) == 0 || tn.rfind(L"h2", 0) == 0 || tn.rfind(L"h3", 0) == 0) {
                    text += L' ';
                }
            } else if (tagName.size() < 16 && c != L'/' && !IsSpaceW(c)) {
                tagName += c;
            }
        }
    }
    UnescapeEntities(text);

    wstring collapsed;
    bool lastSpace = false;
    for (wchar_t c : text) {
        if (c == L'\r' || c == L'\n' || c == L'\t' || c == L' ' || c == 0x3000) {
            if (lastSpace) continue;
            lastSpace = true;
            collapsed += L' ';
        } else {
            lastSpace = false;
            collapsed += c;
        }
    }
    return collapsed;
}

static void WalkMime(const string& hdrs, const string& body, wstring& plain, wstring& html, int depth) {
    if (depth > 6) return;
    string ctValue = HeaderValue(hdrs, "content-type");
    string type, boundary, charset;
    ParseContentType(ctValue.empty() ? "text/plain; charset=us-ascii" : ctValue, type, boundary, charset);

    if (type.rfind("multipart/", 0) == 0 && !boundary.empty()) {
        string delim = "--" + boundary;
        size_t pos = 0;
        while (true) {
            size_t b = body.find(delim, pos);
            while (b != string::npos && b != 0 && body[b - 1] != '\n')
                b = body.find(delim, b + delim.size());
            if (b == string::npos) break;
            size_t lineEnd = body.find('\n', b);
            if (lineEnd == string::npos) break;
            string rest = TrimAscii(body.substr(b + delim.size(), lineEnd - (b + delim.size())));
            if (rest.rfind("--", 0) == 0) break;

            size_t contentStart = lineEnd + 1;
            size_t nb = body.find(delim, contentStart);
            while (nb != string::npos && body[nb - 1] != '\n')
                nb = body.find(delim, nb + delim.size());
            size_t contentEnd = (nb == string::npos) ? body.size() : nb;
            string part = body.substr(contentStart, contentEnd - contentStart);
            while (!part.empty() && (part.back() == '\n' || part.back() == '\r')) part.pop_back();

            string ph, pb;
            SplitHeadersBody(part, ph, pb);
            WalkMime(ph, pb, plain, html, depth + 1);

            if (nb == string::npos) break;
            pos = nb;
        }
        return;
    }

    if (type == "text/plain" || type == "text/html") {
        string data = DecodeTransfer(HeaderValue(hdrs, "content-transfer-encoding"), body);
        wstring w = BytesToWide(data, charset);
        if (type == "text/plain") {
            plain += w;
            plain += L'\n';
        } else {
            html += HtmlToText(w);
            html += L'\n';
        }
    } else if (type == "message/rfc822") {
        string ph, pb;
        SplitHeadersBody(body, ph, pb);
        WalkMime(ph, pb, plain, html, depth + 1);
    }
}

static bool ParseRfc2822Date(const string& v, FILETIME& ft) {
    size_t comma = v.find(',');
    string s = (comma == string::npos) ? v : v.substr(comma + 1);
    int day = 0, year = 0, hh = 0, mm = 0, ss = 0;
    char mon[16] = {}, tz[16] = {};
    int got = sscanf(s.c_str(), " %d %15s %d %d:%d:%d %15s", &day, mon, &year, &hh, &mm, &ss, tz);
    if (got < 6) return false;
    if (year < 100) year += 2000;

    static const char* months[] = { "jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec" };
    string m = LowerAscii(mon).substr(0, 3);
    int month = 0;
    for (int i = 0; i < 12; ++i) if (m == months[i]) month = i + 1;
    if (!month) return false;

    int offsetMin = 0;
    string zone = tz;
    if (zone.size() >= 5 && (zone[0] == '+' || zone[0] == '-')) {
        int oh = atoi(zone.substr(1, 2).c_str());
        int om = atoi(zone.substr(3, 2).c_str());
        offsetMin = oh * 60 + om;
        if (zone[0] == '-') offsetMin = -offsetMin;
    }

    SYSTEMTIME st = {};
    st.wYear = (WORD)year;
    st.wMonth = (WORD)month;
    st.wDay = (WORD)day;
    st.wHour = (WORD)hh;
    st.wMinute = (WORD)mm;
    st.wSecond = (WORD)ss;
    if (!SystemTimeToFileTime(&st, &ft)) return false;
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    long long delta = (long long)offsetMin * 60LL * 10000000LL;
    if ((long long)u.QuadPart < delta) return false;
    u.QuadPart -= (ULONGLONG)delta;
    ft.dwLowDateTime = u.LowPart;
    ft.dwHighDateTime = u.HighPart;
    return true;
}

struct ParsedMail {
    wstring from;
    wstring subject;
    wstring body;
    bool hasDate = false;
    ULONGLONG dateFileTime = 0;
    string dateRaw;
};

static bool ParseMail(const string& raw, ParsedMail& out) {
    string hdrs, body;
    SplitHeadersBody(raw, hdrs, body);
    out.subject = DecodeMimeHeader(HeaderValue(hdrs, "subject"));
    out.from = DecodeMimeHeader(HeaderValue(hdrs, "from"));
    string dateHdr = HeaderValue(hdrs, "date");
    out.dateRaw = dateHdr;
    FILETIME ft;
    if (!dateHdr.empty() && ParseRfc2822Date(dateHdr, ft)) {
        out.hasDate = true;
        ULARGE_INTEGER u;
        u.LowPart = ft.dwLowDateTime;
        u.HighPart = ft.dwHighDateTime;
        out.dateFileTime = u.QuadPart;
    }
    wstring plain, html;
    WalkMime(hdrs, body, plain, html, 0);
    out.body = plain.empty() ? html : plain;
    return !(out.subject.empty() && out.body.empty());
}

static int MailAgeMinutes(ULONGLONG fileTime) {
    FILETIME nowFt;
    GetSystemTimeAsFileTime(&nowFt);
    ULARGE_INTEGER now;
    now.LowPart = nowFt.dwLowDateTime;
    now.HighPart = nowFt.dwHighDateTime;
    if (now.QuadPart <= fileTime) return 0;
    return (int)((now.QuadPart - fileTime) / 600000000ULL);
}

// ---------------------------------------------------------------------------
// 服务器推断 / 配置界面
// ---------------------------------------------------------------------------

static wstring GuessImapHost(const wstring& email) {
    wstring lower = email;
    for (wchar_t& c : lower) if (c >= L'A' && c <= L'Z') c = (wchar_t)(c - L'A' + L'a');
    size_t at = lower.find(L'@');
    wstring domain = (at == wstring::npos) ? lower : lower.substr(at + 1);
    if (domain == L"qq.com") return L"imap.qq.com";
    if (domain == L"exmail.qq.com" || domain.find(L".exmail.qq.com") != wstring::npos)
        return L"imap.exmail.qq.com";
    if (domain == L"163.com") return L"imap.163.com";
    if (domain == L"126.com") return L"imap.126.com";
    if (domain == L"yeah.net") return L"imap.yeah.net";
    if (domain == L"188.com") return L"imap.188.com";
    if (domain == L"gmail.com" || domain == L"googlemail.com") return L"imap.gmail.com";
    if (domain == L"outlook.com" || domain == L"hotmail.com" || domain == L"live.com")
        return L"imap-mail.outlook.com";
    if (domain == L"139.com") return L"imap.139.com";
    if (domain == L"aliyun.com") return L"imap.aliyun.com";
    return L"imap." + domain;
}

static wstring ReadConsoleLine(const wstring& prompt, bool secret) {
    AppPrint(prompt);
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    if (!in || in == INVALID_HANDLE_VALUE) return {};
    DWORD mode = 0;
    bool restore = false;
    if (secret && GetConsoleMode(in, &mode)) {
        SetConsoleMode(in, mode & ~ENABLE_ECHO_INPUT);
        restore = true;
    }
    wchar_t buf[1024] = {};
    DWORD read = 0;
    BOOL ok = ReadConsoleW(in, buf, 1023, &read, nullptr);
    if (restore) {
        SetConsoleMode(in, mode);
        AppPrint(L"\r\n");
    }
    if (!ok) return {};
    wstring s(buf, read);
    while (!s.empty() && (s.back() == L'\r' || s.back() == L'\n' || s.back() == L' ')) s.pop_back();
    return s;
}

static void PrintAccountList() {
    if (g_cfgs.empty()) {
        AppPrint(L"（尚未配置邮箱）\r\n");
        return;
    }
    for (size_t i = 0; i < g_cfgs.size(); ++i) {
        const MailConfig& c = g_cfgs[i];
        AppPrint(L"  " + std::to_wstring(i + 1) + L") " + c.email + L"  " + c.host + L":" +
                 std::to_wstring(c.port) + (c.enabled ? L"  [启用]" : L"  [已关闭]") + L"\r\n");
    }
}

static int NextSectionNumber() {
    int next = 1;
    for (const auto& c : g_cfgs) {
        int n = _wtoi(c.section.c_str() + 5);
        if (n >= next) next = n + 1;
    }
    return next;
}

bool MailSetupInteractive() {
    AppEnsureConsole();
    LoadConfig();
    AppPrint(L"=== 邮箱验证码监控设置（IMAP 只读，可添加多个邮箱） ===\r\n"
             L"说明：程序只读取新邮件正文用于提取验证码，不会修改已读状态。\r\n"
             L"授权码会使用 Windows DPAPI 加密后仅保存在本机。\r\n\r\n"
             L"QQ 邮箱：设置 -> 账号 -> 开启 IMAP/SMTP -> 生成授权码\r\n"
             L"163 邮箱：设置 -> POP3/SMTP/IMAP -> 开启 IMAP -> 新增授权密码\r\n"
             L"Gmail：需开启两步验证后使用“应用专用密码”\r\n\r\n");
    AppPrint(L"已配置邮箱：\r\n");
    PrintAccountList();
    AppPrint(L"\r\n输入已有邮箱可更新其配置；输入新邮箱则新增一个账号。\r\n");

    wstring email = ReadConsoleLine(L"邮箱地址: ", false);
    if (email.empty()) { AppPrint(L"已取消。\r\n"); return false; }
    MailConfig* existing = FindAccount(email);

    wstring hostDef = existing && !existing->host.empty() ? existing->host : GuessImapHost(email);
    wstring host = ReadConsoleLine(L"IMAP 服务器 [" + hostDef + L"]: ", false);
    if (host.empty()) host = hostDef;

    int portDef = existing ? existing->port : 993;
    wstring portStr = ReadConsoleLine(L"端口 [" + std::to_wstring(portDef) + L"]: ", false);
    int port = portStr.empty() ? portDef : _wtoi(portStr.c_str());
    if (port <= 0 || port > 65535) port = portDef;

    wstring prompt = existing
        ? L"授权码/密码（输入不显示，留空沿用已保存的）: "
        : L"授权码/密码（输入不显示）: ";
    wstring secret = ReadConsoleLine(prompt, true);
    if (secret.empty() && existing) {
        if (!UnprotectSecret(WideToUtf8(existing->secretB64), secret) || secret.empty()) {
            AppPrint(L"无法复用已保存的授权码，请重新输入。\r\n");
            secret = ReadConsoleLine(L"授权码/密码（输入不显示）: ", true);
        }
    }
    if (secret.empty()) { AppPrint(L"已取消。\r\n"); return false; }

    AppPrint(L"正在连接并测试登录...\r\n");
    ImapClient imap;
    wstring err;
    bool ok = imap.Connect(host, port, err);
    if (!ok) {
        AppPrint(L"连接失败: " + err + L"\r\n");
        return false;
    }
    if (!imap.Login(email, secret, err)) {
        AppPrint(L"登录失败: " + err + L"\r\n"
                 L"提示：请确认使用的是“授权码/应用专用密码”，并已在邮箱设置中开启 IMAP。\r\n");
        return false;
    }
    long long uidValidity = 0, uidNext = 0;
    if (!imap.Examine(uidValidity, uidNext, err)) {
        AppPrint(L"打开收件箱失败: " + err + L"\r\n");
        return false;
    }
    imap.Logout();

    string blob = ProtectSecret(secret);
    if (blob.empty()) {
        AppPrint(L"凭据加密保存失败。\r\n");
        return false;
    }

    MailConfig c;
    if (existing) {
        c = *existing;
        bool sameMailbox = _wcsicmp(existing->email.c_str(), email.c_str()) == 0 &&
                           _wcsicmp(existing->host.c_str(), host.c_str()) == 0 && existing->port == port;
        if (!sameMailbox) { c.uidValidity = uidValidity; c.lastUid = uidNext > 0 ? uidNext - 1 : 0; }
    } else {
        c.section = L"mail." + std::to_wstring(NextSectionNumber());
        c.uidValidity = uidValidity;
        c.lastUid = uidNext > 0 ? uidNext - 1 : 0;
        c.pollSeconds = 10;
    }
    c.enabled = true;
    c.email = email;
    c.host = host;
    c.port = port;
    c.secretB64 = Utf8ToWide(blob);
    SaveAccount(c);

    LoadConfig();
    AppPrint(L"\r\n设置成功（" + (existing ? wstring(L"已更新") : wstring(L"已新增")) + L"）。当前邮箱：\r\n");
    PrintAccountList();
    AppPrint(L"\r\n如果程序已在后台运行，请退出托盘图标后重新启动以生效。\r\n"
             L"可用 --mail-check 立即检查各邮箱最近几封邮件是否包含验证码。\r\n");
    return true;
}

bool MailDisable(const wstring& email) {
    LoadConfig();
    if (email.empty()) {
        for (auto& c : g_cfgs) {
            c.enabled = false;
            IniWrite(c.section, L"enabled", L"0");
        }
        AppPrint(g_cfgs.empty() ? L"尚未配置邮箱。\r\n" : L"已关闭全部邮箱监控。\r\n");
        return true;
    }
    MailConfig* c = FindAccount(email);
    if (!c) { AppPrint(L"未找到邮箱: " + email + L"\r\n"); return false; }
    c->enabled = false;
    IniWrite(c->section, L"enabled", L"0");
    AppPrint(L"已关闭邮箱监控: " + email + L"\r\n");
    return true;
}

bool MailRemove(const wstring& email) {
    LoadConfig();
    MailConfig* c = FindAccount(email);
    if (!c) { AppPrint(L"未找到邮箱: " + email + L"\r\n"); return false; }
    wstring section = c->section;
    IniDeleteSection(section);
    LoadConfig();
    AppPrint(L"已删除邮箱配置: " + email + L"\r\n"
             L"如果程序已在后台运行，请退出托盘图标后重新启动以生效。\r\n");
    return true;
}

bool MailList() {
    LoadConfig();
    if (g_cfgs.empty()) {
        AppPrint(L"尚未配置邮箱，请先运行: PhoneLinkCode.exe --mail-setup\r\n");
        return true;
    }
    AppPrint(L"已配置 " + std::to_wstring(g_cfgs.size()) + L" 个邮箱（配置段 / 地址 / 服务器 / 状态）：\r\n");
    for (const auto& c : g_cfgs) {
        AppPrint(L"  [" + c.section + L"] " + c.email + L"  " + c.host + L":" +
                 std::to_wstring(c.port) + (c.enabled ? L"  启用" : L"  已关闭") +
                 L"  轮询 " + std::to_wstring(c.pollSeconds) + L"s" +
                 L"  last_uid=" + std::to_wstring(c.lastUid) + L"\r\n");
    }
    return true;
}

static void CheckOneAccount(const MailConfig& c, int count) {
    AppPrint(L"\r\n========== " + c.email + L" (" + c.host + L":" + std::to_wstring(c.port) + L") ==========\r\n");
    wstring secret;
    if (!UnprotectSecret(WideToUtf8(c.secretB64), secret)) {
        AppPrint(L"无法解密已保存的授权码，请重新运行 --mail-setup。\r\n");
        return;
    }

    ImapClient imap;
    wstring err;
    if (!imap.Connect(c.host, c.port, err)) { AppPrint(L"连接失败: " + err + L"\r\n"); return; }
    if (!imap.Login(c.email, secret, err)) { AppPrint(L"登录失败: " + err + L"\r\n"); return; }
    long long uv = 0, un = 0;
    if (!imap.Examine(uv, un, err)) { AppPrint(L"打开收件箱失败: " + err + L"\r\n"); return; }

    long long maxUid = un > 0 ? un - 1 : 0;
    vector<long long> uids;
    if (maxUid >= 1) {
        long long from = maxUid - count + 1;
        if (from < 1) from = 1;
        if (!imap.SearchRange(from, maxUid, uids, err)) { AppPrint(L"搜索失败: " + err + L"\r\n"); return; }
    }

    if (uids.empty()) {
        AppPrint(L"收件箱里没有可显示的邮件。\r\n");
        imap.Logout();
        return;
    }

    AppPrint(L"最近 " + std::to_wstring(uids.size()) + L" 封邮件：\r\n\r\n");
    for (long long uid : uids) {
        string raw;
        if (!imap.FetchRaw(uid, 1024 * 1024, raw, err)) {
            AppPrint(L"UID " + std::to_wstring(uid) + L" 读取失败: " + err + L"\r\n");
            continue;
        }
        if (raw.empty()) continue;
        ParsedMail mail;
        ParseMail(raw, mail);
        wstring code = AppExtractCode(mail.subject + L"\r\n" + mail.body);
        AppPrint(L"UID " + std::to_wstring(uid) + L"\r\n");
        AppPrint(L"  发件人: " + SafeOneLine(mail.from, 120) + L"\r\n");
        AppPrint(L"  主题  : " + SafeOneLine(mail.subject, 120) + L"\r\n");
        wstring dateInfo = mail.dateRaw.empty() ? L"（无 Date 头）" : Utf8ToWide(mail.dateRaw);
        if (mail.hasDate) {
            dateInfo += L"（" + std::to_wstring(MailAgeMinutes(mail.dateFileTime)) + L" 分钟前）";
        }
        AppPrint(L"  时间  : " + SafeOneLine(dateInfo, 160) + L"\r\n");
        AppPrint(L"  验证码: " + (code.empty() ? wstring(L"（未找到）") : code) + L"\r\n\r\n");
    }
    imap.Logout();
}

void MailCheckRecent(int count) {
    LoadConfig();
    if (g_cfgs.empty()) {
        AppPrint(L"尚未配置邮箱，请先运行: PhoneLinkCode.exe --mail-setup\r\n");
        return;
    }
    for (const auto& c : g_cfgs) CheckOneAccount(c, count);
}

bool MailPing(const wstring& hostPort) {
    wstring host = hostPort;
    int port = 993;
    size_t colon = hostPort.rfind(L':');
    if (colon != wstring::npos && colon + 1 < hostPort.size()) {
        host = hostPort.substr(0, colon);
        port = _wtoi(hostPort.substr(colon + 1).c_str());
        if (port <= 0 || port > 65535) port = 993;
    }
    if (hostPort.empty()) { AppPrint(L"目标为空。\r\n"); return false; }
    ImapClient imap;
    wstring err;
    if (!imap.Connect(host, port, err)) { AppPrint(L"IMAP 连接失败: " + err + L"\r\n"); return false; }
    AppPrint(L"IMAP 握手成功（TLS + 服务器问候）: " + host + L":" + std::to_wstring(port) + L"\r\n");
    imap.Logout();
    return true;
}

bool MailParseFile(const wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        AppPrint(L"无法打开文件: " + path + L"\r\n");
        return false;
    }
    LARGE_INTEGER size = {};
    GetFileSizeEx(h, &size);
    if (size.QuadPart <= 0 || size.QuadPart > 10 * 1024 * 1024) {
        CloseHandle(h);
        AppPrint(L"文件为空或过大。\r\n");
        return false;
    }
    string data((size_t)size.QuadPart, '\0');
    DWORD read = 0;
    ReadFile(h, data.data(), (DWORD)data.size(), &read, nullptr);
    CloseHandle(h);
    data.resize(read);

    ParsedMail mail;
    if (!ParseMail(data, mail)) {
        AppPrint(L"解析失败或邮件为空。\r\n");
        return false;
    }
    wstring code = AppExtractCode(mail.subject + L"\r\n" + mail.body);
    AppPrint(L"发件人: " + SafeOneLine(mail.from, 200) + L"\r\n");
    AppPrint(L"主题  : " + SafeOneLine(mail.subject, 200) + L"\r\n");
    AppPrint(L"验证码: " + (code.empty() ? wstring(L"（未找到）") : code) + L"\r\n");
    AppPrint(L"正文  : " + SafeOneLine(mail.body, 300) + L"\r\n");
    return true;
}

// ---------------------------------------------------------------------------
// 后台线程
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 后台线程（每个启用邮箱一个线程）
// ---------------------------------------------------------------------------

static HANDLE g_stopEvent = nullptr;
static vector<HANDLE> g_workers;
static HWND g_notifyWnd = nullptr;

struct WorkerCtx {
    MailConfig cfg;
    ULONGLONG lastConnectLog = 0;
    ULONGLONG lastAuthLog = 0;
};

static bool StopRequested() {
    return g_stopEvent && WaitForSingleObject(g_stopEvent, 0) == WAIT_OBJECT_0;
}

static bool SleepStop(int ms) {
    if (!g_stopEvent) { Sleep((DWORD)ms); return false; }
    return WaitForSingleObject(g_stopEvent, (DWORD)ms) == WAIT_OBJECT_0;
}

static void LogThrottled(ULONGLONG& last, const wstring& msg, int seconds) {
    ULONGLONG now = GetTickCount64();
    if (now - last >= (ULONGLONG)seconds * 1000) {
        last = now;
        AppLog(msg);
    }
}

static wstring AccountTag(const MailConfig& c) {
    return L"[" + c.email + L"] ";
}

static void NotifyCode(const MailConfig& c, const wstring& code) {
    if (g_notifyWnd) {
        MailNotification* n = new MailNotification{ code, c.email };
        PostMessageW(g_notifyWnd, kMailNotifyMsg, 0, (LPARAM)n);
    }
}

static void HandleMailMessage(MailConfig& c, const string& raw) {
    ParsedMail mail;
    if (!ParseMail(raw, mail)) return;

    wstring text = mail.subject + L"\r\n" + mail.body;
    wstring code = AppExtractCode(text);
    if (code.empty()) {
        AppLog(AccountTag(c) + L"新邮件未找到验证码 | 主题: " + SafeOneLine(mail.subject, 80));
        return;
    }
    if (mail.hasDate) {
        int age = MailAgeMinutes(mail.dateFileTime);
        if (age > 10) {
            AppLog(AccountTag(c) + L"邮箱验证码已过期(" + std::to_wstring(age) + L"分钟)，跳过: " + code);
            return;
        }
    }
    if (AppCopyToClipboard(code)) {
        AppLog(AccountTag(c) + L"已复制邮箱验证码 " + code + L" | 主题: " + SafeOneLine(mail.subject, 80));
        NotifyCode(c, code);
    } else {
        AppLog(AccountTag(c) + L"复制邮箱验证码失败: " + code);
    }
}

// 返回 false 表示需要重连
static bool MailSessionLoop(WorkerCtx& ctx, const wstring& secret) {
    MailConfig& c = ctx.cfg;
    ImapClient imap;
    wstring err;
    if (!imap.Connect(c.host, c.port, err)) {
        LogThrottled(ctx.lastConnectLog, AccountTag(c) + L"IMAP 连接失败: " + err, 300);
        return false;
    }
    if (!imap.Login(c.email, secret, err)) {
        LogThrottled(ctx.lastAuthLog, AccountTag(c) + L"IMAP 登录失败: " + err, 300);
        return false;
    }
    AppLog(AccountTag(c) + L"IMAP 已连接 @ " + c.host);

    long long uidValidity = 0, uidNext = 0;
    if (!imap.Examine(uidValidity, uidNext, err)) {
        AppLog(AccountTag(c) + L"打开收件箱失败: " + err);
        return false;
    }

    if (c.uidValidity != uidValidity) {
        if (c.uidValidity != 0) AppLog(AccountTag(c) + L"邮箱 UIDVALIDITY 变化，重置监听位置");
        c.uidValidity = uidValidity;
        c.lastUid = uidNext > 0 ? uidNext - 1 : 0;
        SaveState(c);
    }

    while (!StopRequested()) {
        vector<long long> uids;
        if (!imap.SearchNew(c.lastUid, uids, err)) {
            AppLog(AccountTag(c) + L"搜索新邮件失败: " + err);
            return false;
        }
        if (uids.size() > 20) uids.erase(uids.begin(), uids.end() - 20);
        for (long long uid : uids) {
            if (StopRequested()) return true;
            string raw;
            if (!imap.FetchRaw(uid, 1024 * 1024, raw, err)) {
                AppLog(AccountTag(c) + L"读取邮件失败(UID " + std::to_wstring(uid) + L"): " + err);
                return false;
            }
            c.lastUid = uid;
            SaveState(c);
            if (!raw.empty()) HandleMailMessage(c, raw);
        }
        if (SleepStop(c.pollSeconds * 1000)) break;
    }
    imap.Logout();
    return true;
}

static DWORD WINAPI MailThread(LPVOID param) {
    std::unique_ptr<WorkerCtx> ctx(static_cast<WorkerCtx*>(param));
    wstring secret;
    if (!UnprotectSecret(WideToUtf8(ctx->cfg.secretB64), secret)) {
        AppLog(AccountTag(ctx->cfg) + L"无法解密邮箱授权码，请重新运行 --mail-setup");
        return 0;
    }

    int backoff = 5;
    while (!StopRequested()) {
        if (MailSessionLoop(*ctx, secret)) {
            backoff = 5;
        } else {
            if (SleepStop(backoff * 1000)) break;
            backoff = backoff * 2 > 60 ? 60 : backoff * 2;
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// 对外接口
// ---------------------------------------------------------------------------

void MailInit(const wstring& homeDir) {
    g_cfgPath = homeDir + L"\\mail.ini";
    LoadConfig();
}

int MailEnabledCount() {
    int n = 0;
    for (const auto& c : g_cfgs)
        if (c.enabled && ConfigComplete(c)) ++n;
    return n;
}

bool MailIsEnabled() {
    bool incomplete = false;
    for (const auto& c : g_cfgs)
        if (c.enabled && !ConfigComplete(c)) incomplete = true;
    if (incomplete)
        AppLog(L"有邮箱配置不完整，已跳过对应账号（可用 --mail-setup 重新配置）");
    return MailEnabledCount() > 0;
}

void MailStartWorker(HWND notifyWnd) {
    if (!g_workers.empty()) return;
    if (!MailIsEnabled()) return;
    g_notifyWnd = notifyWnd;
    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    int started = 0;
    for (const auto& c : g_cfgs) {
        if (!c.enabled || !ConfigComplete(c)) continue;
        WorkerCtx* ctx = new WorkerCtx{ c };
        HANDLE h = CreateThread(nullptr, 0, MailThread, ctx, 0, nullptr);
        if (!h) { delete ctx; continue; }
        g_workers.push_back(h);
        ++started;
        AppLog(L"邮箱验证码监控已启动: " + c.email);
    }
    AppLog(L"邮箱验证码监控启动完成，共 " + std::to_wstring(started) + L" 个邮箱");
}

void MailStopWorker() {
    if (g_workers.empty()) return;
    vector<HANDLE> workers;
    workers.swap(g_workers);   // 超时则放弃等待，线程会在网络超时后自行退出
    if (g_stopEvent) SetEvent(g_stopEvent);
    DWORD rc = WAIT_FAILED;
    if (workers.size() <= MAXIMUM_WAIT_OBJECTS)
        rc = WaitForMultipleObjects((DWORD)workers.size(), workers.data(), TRUE, 5000);
    if (rc == WAIT_OBJECT_0) {
        for (HANDLE h : workers) CloseHandle(h);
        if (g_stopEvent) { CloseHandle(g_stopEvent); g_stopEvent = nullptr; }
    }
}
