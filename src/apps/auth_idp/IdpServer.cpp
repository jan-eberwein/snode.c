/*
 * SNode.C SSO/MFA Identity Provider
 * Copyright (C) Jan Nicolas Eberwein 2025/2026 — Master Thesis
 *
 * Identity Provider implementing:
 *   - OAuth2 Authorization Code Flow with PKCE (RFC 7636)
 *   - TOTP Multi-Factor Authentication (RFC 6238)
 *   - JWT access tokens (RS256)
 *   - PBKDF2-HMAC-SHA256 password hashing (with SHA-256 migration)
 *   - AES-256-GCM encryption for TOTP secrets at rest
 *   - Sliding-window rate limiting for login/MFA endpoints
 *   - Setup claim token for secure first-run bootstrap
 *   - Federated login (Google OIDC)
 *   - User registration, login, MFA enrollment
 *   - Password reset via token (email-capable)
 *   - SQLite backend (MariaDB-free, router-compatible)
 */

#include "auth/FederatedLoginProvider.h"
#include "auth/JwtSigner.h"
#include "auth/PasswordHasher.h"
#include "auth/QrCodeGenerator.h"
#include "auth/RateLimiter.h"
#include "auth/SecretEncryptor.h"
#include "auth/Totp.h"
#include "core/SNodeC.h"
#include "database/sqlite/SqliteDatabase.h"
#include "express/legacy/in/WebApp.h"
#include "log/Logger.h"
#include "web/http/http_utils.h"

#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <regex>
#include <arpa/inet.h>

using namespace snodec;
using namespace snodec::auth;
using namespace snodec::database::sqlite;
using json = nlohmann::json;

// Helper functions for Federated Login (executing curl for token exchange and userinfo)
#include <cstdio>
#include <array>

static std::string escapeShellArg(const std::string& arg) {
    std::string escaped;
    for (char c : arg) {
        if (c == '\'') {
            escaped += "'\\''";
        } else {
            escaped += c;
        }
    }
    return "'" + escaped + "'";
}

static std::string execCommand(const std::string& cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed to run command: " + cmd);
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

// ============================================================================
// Global state
// ============================================================================

static SqliteDatabase* g_db = nullptr;
static std::string g_issuer = "https://idp.snodec.local";
static std::string g_idpBaseUrl = "http://localhost:8083";
static std::chrono::steady_clock::time_point g_startTime = std::chrono::steady_clock::now();

// Security modules (initialised in main)
static RateLimiter* g_loginLimiter = nullptr;    // Login endpoint rate limiter
static RateLimiter* g_mfaLimiter = nullptr;      // MFA endpoint rate limiter
static std::string g_totpKeyPath;                // Path to TOTP encryption key
static std::string g_setupClaimToken;            // First-run bootstrap token (empty after claimed)

static std::string formatUptime() {
    auto now = std::chrono::steady_clock::now();
    auto diff = std::chrono::duration_cast<std::chrono::seconds>(now - g_startTime).count();
    int days = diff / 86400;
    int hours = (diff % 86400) / 3600;
    int mins = (diff % 3600) / 60;
    int secs = diff % 60;

    std::string res;
    if (days > 0)
        res += std::to_string(days) + "d ";
    if (hours > 0 || days > 0)
        res += std::to_string(hours) + "h ";
    res += std::to_string(mins) + "m " + std::to_string(secs) + "s";
    return res;
}

// ============================================================================
// OAuth2 redirect-URI allow-list (security best-practice)
// ============================================================================

static std::set<std::string> g_allowedRedirectUris = {
    "http://localhost:8055/auth/callback",
    "http://localhost:8084/auth/callback",
    "http://192.168.1.1:8055/auth/callback",
    "http://192.168.1.1:8084/auth/callback",
    "http://192.168.1.1:8080/auth/callback",
    "http://localhost:8080/auth/callback",
    "http://localhost:3000/auth/callback",
    "http://127.0.0.1:8055/auth/callback",
};

// ============================================================================
// Utility — private key loader
// ============================================================================

static std::string loadPrivateKey(const std::string& path) {
    // Try given path, then fall back to keys/<basename>
    for (const auto& p : {path, "keys/" + path.substr(path.rfind('/') + 1)}) {
        if (std::ifstream f(p); f.is_open()) {
            return {std::istreambuf_iterator<char>(f), {}};
        }
    }
    throw std::runtime_error("Cannot open private key: " + path);
}

// ============================================================================
// Utility — cryptography
// ============================================================================

static std::string generateRandomString(size_t len) {
    static constexpr char CHARS[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(CHARS) - 2);
    std::string s;
    s.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        s += CHARS[dis(gen)];
    }
    return s;
}

static std::string sha256hex(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);
    std::ostringstream ss;
    for (auto b : hash) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return ss.str();
}

// --- Password hashing: PBKDF2 with legacy SHA-256 migration ---

static std::string hashPasswordPbkdf2(const std::string& pw) {
    return PasswordHasher::hashPassword(pw);
}

// Verify password, supporting both PBKDF2 and legacy SHA-256 formats.
// If legacy format is verified, returns the user ID for migration.
static bool verifyPasswordAny(const std::string& pw, const std::string& storedHash,
                              const std::string& salt, bool& needsMigration) {
    needsMigration = false;
    // Try PBKDF2 first (new format starts with $pbkdf2-sha256$)
    if (storedHash.rfind("$pbkdf2-sha256$", 0) == 0) {
        return PasswordHasher::verifyPassword(pw, storedHash);
    }
    // Fall back to legacy SHA-256+salt
    if (PasswordHasher::isLegacyHash(storedHash)) {
        if (PasswordHasher::verifyLegacy(pw, storedHash, salt)) {
            needsMigration = true; // Caller should re-hash and update DB
            return true;
        }
    }
    return false;
}

// Migrate a legacy SHA-256 hash to PBKDF2 in the database
static void migratePasswordHash(const std::string& userId, const std::string& pw) {
    std::string newHash = hashPasswordPbkdf2(pw);
    std::string err;
    g_db->exec("UPDATE user SET password_hash=?, password_salt='' WHERE id=?",
               {newHash, userId}, &err);
    if (err.empty()) {
        LOG(INFO) << "Migrated password hash to PBKDF2 for user ID " << userId;
    }
}

// --- TOTP secret encryption helpers ---

static std::string encryptTotpSecret(const std::string& plainSecret) {
    if (g_totpKeyPath.empty()) return plainSecret; // No key configured — store plaintext
    try {
        return SecretEncryptor::encrypt(plainSecret, g_totpKeyPath);
    } catch (const std::exception& e) {
        LOG(ERROR) << "TOTP encryption failed: " << e.what();
        return plainSecret; // Graceful degradation
    }
}

static std::string decryptTotpSecret(const std::string& storedSecret) {
    if (g_totpKeyPath.empty()) return storedSecret;
    if (!SecretEncryptor::isEncrypted(storedSecret)) return storedSecret; // Legacy plaintext
    try {
        return SecretEncryptor::decrypt(storedSecret, g_totpKeyPath);
    } catch (const std::exception& e) {
        LOG(ERROR) << "TOTP decryption failed: " << e.what();
        return storedSecret; // Graceful degradation — try as plaintext
    }
}

// ============================================================================
// Utility — PKCE (RFC 7636)
// ============================================================================

static std::string base64UrlEncode(const unsigned char* data, size_t len) {
    static const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string r;
    unsigned char a3[3], a4[4];
    int i = 0;
    while (len--) {
        a3[i++] = *data++;
        if (i == 3) {
            a4[0] = (a3[0] & 0xfc) >> 2;
            a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
            a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
            a4[3] = a3[2] & 0x3f;
            for (int j = 0; j < 4; ++j)
                r += B64[a4[j]];
            i = 0;
        }
    }
    if (i) {
        for (int k = i; k < 3; ++k)
            a3[k] = '\0';
        a4[0] = (a3[0] & 0xfc) >> 2;
        a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
        a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
        for (int j = 0; j < i + 1; ++j)
            r += B64[a4[j]];
    }
    for (char& c : r) {
        if (c == '+')
            c = '-';
        else if (c == '/')
            c = '_';
    }
    return r;
}

static std::string pkceChallenge(const std::string& verifier) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(verifier.data()), verifier.size(), hash);
    return base64UrlEncode(hash, SHA256_DIGEST_LENGTH);
}

static bool verifyPkce(const std::string& verifier, const std::string& challenge, const std::string& method) {
    // Only S256 is supported (RFC 7636 §4.2 — "plain" is insecure and rejected)
    if (method != "S256") {
        return false;
    }
    return pkceChallenge(verifier) == challenge;
}

// ============================================================================
// Utility — URL / redirect
// ============================================================================

static std::string urlDecode(const std::string& s) {
    std::string r;
    r.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size() && std::isxdigit(static_cast<unsigned char>(s[i + 1])) &&
            std::isxdigit(static_cast<unsigned char>(s[i + 2]))) {
            r += static_cast<char>(std::strtol(s.substr(i + 1, 2).c_str(), nullptr, 16));
            i += 2;
        } else if (s[i] == '+') {
            r += ' ';
        } else {
            r += s[i];
        }
    }
    return r;
}

static bool validateRedirectUri(const std::string& uri) {
    const std::string decoded = urlDecode(uri);
    if (g_allowedRedirectUris.count(uri) || g_allowedRedirectUris.count(decoded)) {
        return true;
    }
    
    // Dynamic Private IP Validation (RFC 1918 & RFC 8252)
    // To support a Centralized IdP serving arbitrary OpenWRT edge routers,
    // we safely allow any redirect_uri that points to a private LAN IP.
    std::regex uri_regex(R"(^http://([^/:]+)(:\d+)?/auth/callback$)");
    std::smatch match;
    if (std::regex_match(uri, match, uri_regex)) {
        std::string host = match[1];
        if (host == "localhost") return true;
        
        struct in_addr addr;
        if (inet_pton(AF_INET, host.c_str(), &addr) == 1) {
            uint32_t ip = ntohl(addr.s_addr);
            // 127.0.0.0/8 (Loopback)
            if ((ip & 0xFF000000) == 0x7F000000) return true;
            // 10.0.0.0/8 (Private)
            if ((ip & 0xFF000000) == 0x0A000000) return true;
            // 172.16.0.0/12 (Private)
            if ((ip & 0xFFF00000) == 0xAC100000) return true;
            // 192.168.0.0/16 (Private)
            if ((ip & 0xFFFF0000) == 0xC0A80000) return true;
        }
    }
    return false;
}

// ============================================================================
// Utility — form body parser (application/x-www-form-urlencoded)
// ============================================================================

static std::map<std::string, std::string> parseBody(const std::vector<char>& body) {
    std::string raw(body.begin(), body.end());
    std::map<std::string, std::string> params;
    std::istringstream ss(raw);
    std::string tok;
    while (std::getline(ss, tok, '&')) {
        auto pos = tok.find('=');
        if (pos != std::string::npos) {
            params[urlDecode(tok.substr(0, pos))] = urlDecode(tok.substr(pos + 1));
        }
    }
    return params;
}

// ============================================================================
// Password reset — notification
//
// For local/LAN deployments the reset link is shown in the browser response
// (acceptable for embedded/router use, documented as "display mode").
// When environment variable SMTP_COMMAND is set, the reset link is piped
// to that command's stdin, enabling real email delivery:
//   SMTP_COMMAND="msmtp user@example.com"
// ============================================================================

static void sendPasswordResetLink(const std::string& toEmail, const std::string& resetUrl) {
    const char* cmd = std::getenv("SMTP_COMMAND");
    if (cmd == nullptr) {
        // Local mode: just log the link. The HTTP response page also shows it.
        LOG(INFO) << "[PASSWORD RESET] Link for " << toEmail << ": " << resetUrl;
        return;
    }

    // Pipe a minimal plain-text email to the configured SMTP command.
    std::string body = "Subject: SNode.C Password Reset\r\n"
                       "To: " +
                       toEmail +
                       "\r\n\r\n"
                       "Click to reset your password:\r\n" +
                       resetUrl +
                       "\r\n"
                       "\r\nThis link expires in 15 minutes.\r\n";

    FILE* pipe = popen(cmd, "w"); // NOLINT(cert-env33-c)
    if (pipe != nullptr) {
        fwrite(body.c_str(), 1, body.size(), pipe);
        pclose(pipe);
    } else {
        LOG(ERROR) << "sendPasswordResetLink: popen failed for command: " << cmd;
    }
}

// ============================================================================
// HTML helpers — shared CSS + page builder
// ============================================================================

static const char* PAGE_CSS = R"(
:root {
    --bg-color: #f5f5f7; --text-color: #1d1d1f; --card-bg: #ffffff;
    --card-border: #e8e8ed; --input-bg: #ffffff; --input-border: #d2d2d7;
    --input-focus: #0066cc; --btn-bg: #0066cc; --btn-hover: #004499;
    --btn-text: #ffffff; --link-color: #0066cc; --text-muted: #86868b;
    --header-bg: rgba(255, 255, 255, 0.8); --header-border: #e8e8ed;
}
[data-theme="dark"] {
    --bg-color: #000000; --text-color: #f5f5f7; --card-bg: #1c1c1e;
    --card-border: #333336; --input-bg: #1c1c1e; --input-border: #424245;
    --input-focus: #2997ff; --btn-bg: #2997ff; --btn-hover: #0071e3;
    --btn-text: #ffffff; --link-color: #2997ff; --text-muted: #86868b;
    --header-bg: rgba(28, 28, 30, 0.8); --header-border: #333336;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', Roboto, sans-serif;
    background: var(--bg-color); color: var(--text-color);
    min-height: 100vh; display: flex; flex-direction: column;
    transition: background-color 0.3s, color 0.3s;
}
header {
    background: var(--header-bg); border-bottom: 1px solid var(--header-border);
    backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
    position: sticky; top: 0; z-index: 100;
    display: flex; justify-content: space-between; align-items: center;
    padding: 16px 40px;
}
.header-logo {
    font-weight: 700; font-size: 1.2rem; letter-spacing: 1px; color: var(--text-color);
    text-decoration: none; display: flex; align-items: center; gap: 10px;
}
.header-nav { display: flex; align-items: center; gap: 24px; }
.header-nav a {
    color: var(--text-color); text-decoration: none; font-size: 0.9rem; font-weight: 500;
    transition: color 0.2s;
}
.header-nav a:hover { color: var(--link-color); }
main {
    flex: 1; display: flex; justify-content: center; align-items: center; padding: 40px 20px;
}
.card {
    background: var(--card-bg); border: 1px solid var(--card-border);
    border-radius: 16px; padding: 40px; width: 100%; max-width: 440px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.04); transition: background-color 0.3s, border-color 0.3s;
}
.dashboard-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px; width: 100%; max-width: 900px; margin: 0 auto;
}
.stat-card {
    background: var(--card-bg); border: 1px solid var(--card-border);
    border-radius: 12px; padding: 24px; display: flex; flex-direction: column;
    box-shadow: 0 4px 24px rgba(0,0,0,0.02); transition: transform 0.2s;
}
.stat-card:hover { transform: translateY(-2px); }
.stat-value { font-size: 2.5rem; font-weight: 700; margin-top: 10px; color: var(--text-color); }
.stat-label { font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; font-weight: 600; }
.logo-icon { width: 48px; height: 48px; margin: 0 auto 16px; display: block; fill: var(--text-color); }
h1 { text-align:center; font-size:1.6rem; font-weight:600; margin-bottom:8px; }
.subtitle { text-align:center; color: var(--text-muted); font-size:0.95rem; margin-bottom:30px; }
.form-group { margin-bottom:20px; }
label { display:block; font-size:0.85rem; font-weight:500; color: var(--text-color); margin-bottom:8px; }
input[type="text"], input[type="password"], input[type="email"] {
    width:100%; padding:12px 16px; background: var(--input-bg);
    border: 1px solid var(--input-border); border-radius: 8px; color: var(--text-color);
    font-size:1rem; transition: border-color 0.2s, box-shadow 0.2s;
}
input:focus { outline:none; border-color: var(--input-focus); box-shadow: 0 0 0 3px rgba(0,102,204,0.15); }
[data-theme="dark"] input:focus { box-shadow: 0 0 0 3px rgba(41,151,255,0.15); }
.checkbox-group { display: flex; align-items: center; margin-bottom: 24px; }
.checkbox-group input { margin-right: 8px; width: 16px; height: 16px; cursor: pointer; }
.checkbox-group label { margin-bottom: 0; font-weight: 400; cursor: pointer; display: inline; }
.btn {
    display:block; width:100%; padding:12px; background: var(--btn-bg);
    color: var(--btn-text); border:none; border-radius:8px; text-align:center;
    font-size:1rem; font-weight:500; cursor:pointer; transition: background-color 0.2s; text-decoration:none;
}
.btn:hover { background: var(--btn-hover); }
.btn-secondary { background: transparent; color: var(--text-color); border: 1px solid var(--card-border); }
.btn-secondary:hover { background: rgba(0,0,0,0.03); }
[data-theme="dark"] .btn-secondary:hover { background: rgba(255,255,255,0.05); }
.btn-red { background: #ff3b30; color: #fff; }
.btn-red:hover { background: #d70015; }
[data-theme="dark"] .btn-red { background: #ff453a; color: #fff; }
[data-theme="dark"] .btn-red:hover { background: #ff6961; }
.error-box, .info-box, .success-box { padding: 12px 16px; border-radius: 8px; margin-bottom: 24px; font-size: 0.9rem; }
.error-box { background: rgba(255,59,48,0.1); color: #ff3b30; border: 1px solid rgba(255,59,48,0.2); }
[data-theme="dark"] .error-box { background: rgba(255,69,58,0.1); color: #ff453a; border: 1px solid rgba(255,69,58,0.2); }
.info-box { background: rgba(0,102,204,0.1); color: #0066cc; border: 1px solid rgba(0,102,204,0.2); }
[data-theme="dark"] .info-box { background: rgba(41,151,255,0.1); color: #2997ff; border: 1px solid rgba(41,151,255,0.2); }
.success-box { background: rgba(52,199,89,0.1); color: #28a745; border: 1px solid rgba(52,199,89,0.2); }
[data-theme="dark"] .success-box { background: rgba(48,209,88,0.1); color: #30d158; border: 1px solid rgba(48,209,88,0.2); }
.links { text-align:center; margin-top:24px; font-size:0.9rem; }
.links a { color: var(--link-color); text-decoration:none; }
.links a:hover { text-decoration:underline; }
.theme-switch {
    background: transparent; border: none; cursor: pointer; display: flex; align-items: center; justify-content: center;
    color: var(--text-color);
}
.theme-switch svg { width: 20px; height: 20px; fill: currentColor; }
.divider { height: 1px; background: var(--card-border); margin: 24px 0; }
.clickable-card { cursor: pointer; border: 1px solid var(--input-border); transition: border-color 0.2s, transform 0.2s; }
.clickable-card:hover { border-color: var(--link-color); transform: translateY(-2px); }
footer { text-align: center; padding: 24px; font-size: 0.85rem; color: var(--text-muted); border-top: 1px solid var(--header-border); background: var(--header-bg); }
.footer-content { display: flex; justify-content: center; gap: 12px; align-items: center; }
.footer-content a { color: var(--text-muted); text-decoration: none; transition: color 0.2s; }
.footer-content a:hover { color: var(--link-color); }
@media (min-width: 600px) { .span-2 { grid-column: span 2; } }
@media (max-width: 600px) { header { padding: 16px 20px; } .header-nav { gap: 12px; } }
)";

static const char* PAGE_JS = R"(
<script>
const sunIcon = `<svg viewBox="0 0 24 24"><path d="M12 2.25a.75.75 0 01.75.75v2.25a.75.75 0 01-1.5 0V3a.75.75 0 01.75-.75zM7.5 12a4.5 4.5 0 119 0 4.5 4.5 0 01-9 0zM18.894 6.166a.75.75 0 00-1.06-1.06l-1.591 1.59a.75.75 0 101.06 1.061l1.591-1.59zM21.75 12a.75.75 0 01-.75.75h-2.25a.75.75 0 010-1.5H21a.75.75 0 01.75.75zM17.834 18.894a.75.75 0 001.06-1.06l-1.59-1.591a.75.75 0 10-1.061 1.06l1.59 1.591zM12 18.75a.75.75 0 01.75.75V21a.75.75 0 01-1.5 0v-1.5a.75.75 0 01.75-.75zM6.166 17.834a.75.75 0 00-1.06 1.06l1.59 1.591a.75.75 0 101.06-1.061l-1.59-1.59zM4.5 12a.75.75 0 01-.75-.75H1.5a.75.75 0 000 1.5h2.25a.75.75 0 01.75-.75zM6.166 6.166a.75.75 0 011.06-1.06l1.59 1.59a.75.75 0 01-1.06 1.061l-1.59-1.59z"></path></svg>`;
const moonIcon = `<svg viewBox="0 0 24 24"><path d="M9.528 1.718a.75.75 0 01.162.819A8.97 8.97 0 009 6a9 9 0 009 9 8.97 8.97 0 003.463-.69.75.75 0 01.981.98 10.503 10.503 0 01-9.694 6.46c-5.799 0-10.5-4.701-10.5-10.5 0-4.368 2.667-8.112 6.46-9.694a.75.75 0 01.818.162z"></path></svg>`;
function toggleTheme() {
    const isDark = document.body.getAttribute('data-theme') === 'dark';
    const newTheme = isDark ? 'light' : 'dark';
    document.body.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    document.getElementById('theme-icon').innerHTML = newTheme === 'dark' ? sunIcon : moonIcon;
}
window.onload = () => {
    const saved = localStorage.getItem('theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    document.body.setAttribute('data-theme', saved);
    document.getElementById('theme-icon').innerHTML = saved === 'dark' ? sunIcon : moonIcon;
};
</script>
)";

static const char* ICONS = R"(
<svg style="display:none;">
<symbol id="icon-lock" viewBox="0 0 24 24"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM9 6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z"/></symbol>
<symbol id="icon-user" viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></symbol>
<symbol id="icon-settings" viewBox="0 0 24 24"><path d="M19.14,12.94c0.04-0.3,0.06-0.61,0.06-0.94c0-0.32-0.02-0.64-0.06-0.94l2.03-1.58c0.18-0.14,0.23-0.41,0.12-0.61 l-1.92-3.32c-0.12-0.22-0.37-0.29-0.59-0.22l-2.39,0.96c-0.5-0.38-1.03-0.7-1.62-0.94L14.4,2.81c-0.04-0.24-0.24-0.41-0.48-0.41 h-3.84c-0.24,0-0.43,0.17-0.47,0.41L9.25,5.35C8.66,5.59,8.12,5.92,7.63,6.29L5.24,5.33c-0.22-0.08-0.47,0-0.59,0.22L2.73,8.87 C2.62,9.08,2.66,9.34,2.86,9.48l2.03,1.58C4.84,11.36,4.8,11.69,4.8,12s0.02,0.64,0.06,0.94l-2.03,1.58 c-0.18,0.14-0.23,0.41-0.12,0.61l1.92,3.32c0.12,0.22,0.37,0.29,0.59,0.22l2.39-0.96c0.5,0.38,1.03,0.7,1.62,0.94l0.36,2.54 c0.05,0.24,0.24,0.41,0.48,0.41h3.84c0.24,0,0.43-0.17,0.47-0.41l0.36-2.54c0.59-0.24,1.13-0.56,1.62-0.94l2.39,0.96 c0.22,0.08,0.47,0,0.59-0.22l1.92-3.32c0.12-0.22,0.07-0.49-0.12-0.61L19.14,12.94z M12,15.6c-1.98,0-3.6-1.62-3.6-3.6 s1.62-3.6,3.6-3.6s3.6,1.62,3.6,3.6S13.98,15.6,12,15.6z"/></symbol>
<symbol id="icon-shield" viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></symbol>
<symbol id="icon-rocket" viewBox="0 0 24 24"><path d="M13.13 22.19l-1.63-3.83c3.61-.58 7.09-2.58 9.55-5.95l-7.92 9.78zm-2.26-10.3c1.38 0 2.5-1.12 2.5-2.5s-1.12-2.5-2.5-2.5-2.5 1.12-2.5 2.5 1.12 2.5 2.5 2.5zm11.39-9.87c-1.39-.42-5.45-.63-10.22 3.01L8.9 8.16l-3.33-1.07-3.9 3.89 4.16 1.86-1.94 4.54 1.34 1.34 2.8-6.52 1.86 4.15 3.9-3.9-1.07-3.32 3.12-3.13c3.65-4.78 3.44-8.84 3.02-10.23z"/></symbol>
</svg>
)";

static std::string formatUserDisplayName(const std::string& username, const std::string& email) {
    if (username.empty()) return email;
    std::string lower = username;
    for (auto& c : lower) c = std::tolower(c);
    bool isPlaceholder = (lower == "google_user" || lower == "google user" || lower == "googleuser" ||
                          lower.rfind("user_", 0) == 0 || lower.rfind("google_", 0) == 0);
    if (isPlaceholder && !email.empty()) {
        return email;
    }
    if (!email.empty()) {
        return username + " (" + email + ")";
    }
    return username;
}

static std::string
buildPage(const std::string& title, const std::string& body, bool isAuthenticated = false, const std::string& username = "") {
    std::string accountBtn = "";
    if (isAuthenticated && !username.empty()) {
        accountBtn = "<a href=\"/settings\" style=\"background:var(--btn-bg);color:#fff;padding:4px "
                     "12px;border-radius:20px;font-weight:600;display:flex;align-items:center;gap:6px;text-decoration:none;\">"
                     "<svg width=\"16\" height=\"16\" fill=\"currentColor\"><use href=\"#icon-user\"/></svg>" +
                     username + "</a>";
    }

    std::string navLinks = isAuthenticated ? accountBtn + "<a href=\"/dashboard\">Dashboard</a>"
                                                          "<a href=\"/settings\">Settings</a>"
                                                          "<a href=\"http://localhost:8055/\" style=\"color:#3b82f6; font-weight:600; margin-left:8px;\">Protected WebApp</a>"
                                                          "<form method=\"POST\" action=\"/auth/logout\" style=\"display:inline; margin-left:8px;\">"
                                                          "<button type=\"submit\" class=\"btn btn-red\" style=\"padding:6px 12px; "
                                                          "font-size:0.85rem; border-radius:6px;\">Sign Out</button></form>"
                                           : "<a href=\"/auth/login\">Sign In</a><a href=\"/auth/register\">Create Account</a>";

    return "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n"
           "<meta charset=\"UTF-8\">\n"
           "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\">\n"
           "<title>" +
           title +
           " — SNode.C</title>\n"
           "<style>" +
           PAGE_CSS + "</style>\n" + PAGE_JS + "</head>\n<body>\n" + ICONS +
           "<header>\n"
           "<a href=\"/\" class=\"header-logo\"><svg width=\"24\" height=\"24\" viewBox=\"0 0 24 24\" fill=\"var(--btn-bg)\"><path d=\"M12 "
           "2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5\"/></svg> SNode.C</a>\n"
           "<nav class=\"header-nav\">\n" +
           navLinks +
           "<button class=\"theme-switch\" onclick=\"toggleTheme()\" id=\"theme-icon\"></button>\n"
           "</nav>\n</header>\n"
           "<main>\n" +
           body +
           "\n</main>\n"
           "<footer><div class=\"footer-content\">\n"
           "<span>&copy; <script>document.write(new Date().getFullYear())</script> Jan Eberwein & Volker Chr.</span>\n"
           "<span>|</span>\n"
           "<a href=\"https://github.com/SNodeC\" target=\"_blank\">GitHub</a>\n"
           "<span>|</span>\n"
           "<span>MIT License</span>\n"
           "</div></footer>\n"
           "</body>\n</html>\n";
}

// ============================================================================
// HTML page builders — each is a pure function, no side-effects
// ============================================================================

static const FederatedLoginRegistry* g_federatedRegistry = nullptr;

static std::string loginPage(const std::string& error,
                             const std::string& clientId,
                             const std::string& redirectUri,
                             const std::string& state,
                             const std::string& scope,
                             const std::string& codeChallenge,
                             const std::string& codeChallengeMethod,
                             const std::string& prefillUsername = "") {
    std::string regUrl = "/auth/register?client_id=" + clientId + "&redirect_uri=" + httputils::url_encode(redirectUri) +
                         "&state=" + state + "&scope=" + scope + "&code_challenge=" + codeChallenge + "&code_challenge_method=" + codeChallengeMethod;
    std::string err = error.empty() ? "" : "<div class=\"error-box\">" + error + "</div>\n";

    // Render social login buttons if any providers are enabled
    std::string socialButtons;
    if (g_federatedRegistry != nullptr) {
        socialButtons = g_federatedRegistry->renderLoginButtons(
            g_idpBaseUrl, clientId, redirectUri, state, codeChallenge, codeChallengeMethod);
    }

    std::string body = "<div class=\"card\">\n"
                       "<svg class=\"logo-icon\"><use href=\"#icon-user\"/></svg>\n"
                       "<h1>Sign In</h1>\n"
                       "<p class=\"subtitle\">SNode.C Identity Provider</p>\n" +
                       err +
                       "<form method=\"POST\" action=\"/auth/login\">\n"
                       "<input type=\"hidden\" name=\"client_id\" value=\"" +
                       clientId +
                       "\">\n"
                       "<input type=\"hidden\" name=\"redirect_uri\" value=\"" +
                       redirectUri +
                       "\">\n"
                       "<input type=\"hidden\" name=\"state\" value=\"" +
                       state +
                       "\">\n"
                       "<input type=\"hidden\" name=\"scope\" value=\"" +
                       scope +
                       "\">\n"
                       "<input type=\"hidden\" name=\"code_challenge\" value=\"" +
                       codeChallenge +
                       "\">\n"
                       "<input type=\"hidden\" name=\"code_challenge_method\" value=\"" +
                       codeChallengeMethod +
                       "\">\n"
                       "<div class=\"form-group\">\n"
                       "<label>Username</label>\n"
                       "<input type=\"text\" name=\"username\" placeholder=\"Enter username\" "
                       "value=\"" +
                       prefillUsername +
                       "\" required autofocus>\n"
                       "</div>\n"
                       "<div class=\"form-group\">\n"
                       "<label>Password</label>\n"
                       "<input type=\"password\" name=\"password\" placeholder=\"Enter password\" required>\n"
                       "</div>\n"
                       "<button type=\"submit\" class=\"btn\">Sign In</button>\n"
                       "</form>\n" +
                       socialButtons +
                       "<div class=\"links\">\n"
                       "<a href=\"" +
                       regUrl +
                       "\">No account? Register</a> &nbsp;·&nbsp; "
                       "<a href=\"/auth/forgot-password\">Forgot password?</a>\n"
                       "</div>\n"
                       "</div>\n";
    return buildPage("Sign In", body, false);
}

static std::string registerPage(const std::string& error,
                                const std::string& clientId,
                                const std::string& redirectUri,
                                const std::string& state,
                                const std::string& scope,
                                const std::string& codeChallenge,
                                const std::string& codeChallengeMethod) {
    std::string loginUrl =
        "/auth/login?client_id=" + clientId + "&redirect_uri=" + httputils::url_encode(redirectUri) +
        "&state=" + state + "&scope=" + scope + "&code_challenge=" + codeChallenge + "&code_challenge_method=" + codeChallengeMethod;
    std::string err = error.empty() ? "" : "<div class=\"error-box\">" + error + "</div>\n";

    std::string body = "<div class=\"card\">\n"
                       "<svg class=\"logo-icon\"><use href=\"#icon-user\"/></svg>\n"
                       "<h1>Create Account</h1>\n"
                       "<p class=\"subtitle\">Register for SNode.C SSO</p>\n" +
                       err +
                       "<form method=\"POST\" action=\"/auth/register\">\n"
                       "<input type=\"hidden\" name=\"client_id\" value=\"" +
                       clientId +
                       "\">\n"
                       "<input type=\"hidden\" name=\"redirect_uri\" value=\"" +
                       redirectUri +
                       "\">\n"
                       "<input type=\"hidden\" name=\"state\" value=\"" +
                       state +
                       "\">\n"
                       "<input type=\"hidden\" name=\"scope\" value=\"" +
                       scope +
                       "\">\n"
                       "<input type=\"hidden\" name=\"code_challenge\" value=\"" +
                       codeChallenge +
                       "\">\n"
                       "<input type=\"hidden\" name=\"code_challenge_method\" value=\"" +
                       codeChallengeMethod +
                       "\">\n"
                       "<div class=\"form-group\">\n"
                       "<label>Username</label>\n"
                       "<input type=\"text\" name=\"username\" placeholder=\"Choose a username\" required autofocus>\n"
                       "</div>\n"
                       "<div class=\"form-group\">\n"
                       "<label>Email Address</label>\n"
                       "<input type=\"email\" name=\"email\" placeholder=\"your@email.com\" required>\n"
                       "</div>\n"
                       "<div class=\"form-group\">\n"
                       "<label>Password</label>\n"
                       "<input type=\"password\" name=\"password\" placeholder=\"Create a strong password\" required>\n"
                       "</div>\n"
                       "<div class=\"form-group\">\n"
                       "<label>Confirm Password</label>\n"
                       "<input type=\"password\" name=\"confirm_password\" placeholder=\"Confirm your password\" required>\n"
                       "</div>\n"
                       "<div class=\"checkbox-group\">\n"
                       "<input type=\"checkbox\" name=\"enable_mfa\" id=\"enable_mfa\" value=\"1\" checked>\n"
                       "<label for=\"enable_mfa\">Enable Two-Factor Authentication</label>\n"
                       "</div>\n"
                       "<button type=\"submit\" class=\"btn\">Create Account</button>\n"
                       "</form>\n"
                       "<div class=\"links\"><a href=\"" +
                       loginUrl +
                       "\">Already have an account? Sign in</a></div>\n"
                       "</div>\n";
    return buildPage("Register", body, false);
}

static std::string mfaPage(const std::string& error,
                           const std::string& userId,
                           const std::string& clientId,
                           const std::string& redirectUri,
                           const std::string& state,
                           const std::string& scope,
                           const std::string& codeChallenge,
                           const std::string& codeChallengeMethod) {
    std::string err = error.empty() ? "" : "<div class=\"error-box\">" + error + "</div>\n";

    std::string body = "<div class=\"card\">\n"
                       "<svg class=\"logo-icon\"><use href=\"#icon-shield\"/></svg>\n"
                       "<h1>Two-Factor Authentication</h1>\n"
                       "<p class=\"subtitle\">Enter the 6-digit code from your authenticator app</p>\n" +
                       err +
                       "<form method=\"POST\" action=\"/auth/mfa\">\n"
                       "<input type=\"hidden\" name=\"user_id\" value=\"" +
                       userId +
                       "\">\n"
                       "<input type=\"hidden\" name=\"client_id\" value=\"" +
                       clientId +
                       "\">\n"
                       "<input type=\"hidden\" name=\"redirect_uri\" value=\"" +
                       redirectUri +
                       "\">\n"
                       "<input type=\"hidden\" name=\"state\" value=\"" +
                       state +
                       "\">\n"
                       "<input type=\"hidden\" name=\"scope\" value=\"" +
                       scope +
                       "\">\n"
                       "<input type=\"hidden\" name=\"code_challenge\" value=\"" +
                       codeChallenge +
                       "\">\n"
                       "<input type=\"hidden\" name=\"code_challenge_method\" value=\"" +
                       codeChallengeMethod +
                       "\">\n"
                       "<div class=\"form-group\">\n"
                       "<label>Verification Code</label>\n"
                       "<input type=\"text\" name=\"code\" placeholder=\"000000\" maxlength=\"6\" "
                       "pattern=\"[0-9]{6}\" required autocomplete=\"one-time-code\" inputmode=\"numeric\" "
                       "style=\"font-size:1.8rem;letter-spacing:10px;text-align:center;\" autofocus>\n"
                       "</div>\n"
                       "<button type=\"submit\" class=\"btn\">Verify Code</button>\n"
                       "</form>\n"
                       "<div class=\"links\">\n"
                       "<a href=\"/auth/login\">Cancel / Back to Login</a>\n"
                       "</div>\n"
                       "</div>\n";
    return buildPage("Two-Factor Auth", body, false);
}

static std::string
enrollTotpPage(const std::string& userId, const std::string& secret, const std::string& uri, 
               const std::string& clientId, const std::string& redirectUri, const std::string& state, 
               const std::string& scope, const std::string& codeChallenge, const std::string& codeChallengeMethod,
               const std::string& error = "") {
    std::string err = error.empty() ? "" : "<div class=\"error-box\">" + error + "</div>\n";

    std::string skipUrl = "/auth/enroll/totp/skip?user_id=" + userId + 
                          "&client_id=" + httputils::url_encode(clientId) + 
                          "&redirect_uri=" + httputils::url_encode(redirectUri) + 
                          "&state=" + httputils::url_encode(state) + 
                          "&scope=" + httputils::url_encode(scope) +
                          "&code_challenge=" + httputils::url_encode(codeChallenge) +
                          "&code_challenge_method=" + httputils::url_encode(codeChallengeMethod);

    std::string body =
        "<div class=\"card\" style=\"max-width:520px;\">\n"
        "<svg class=\"logo-icon\"><use href=\"#icon-shield\"/></svg>\n"
        "<h1>Enable Two-Factor Auth</h1>\n"
        "<p class=\"subtitle\">Scan this QR code with your authenticator app</p>\n" +
        err +
        "<div style=\"text-align:center;margin:20px 0;padding:20px;"
        "background:var(--card-bg);border:1px solid var(--card-border);border-radius:12px;\">\n"
        "<img src=\"/api/qrcode?data=" +
        httputils::url_encode(uri) +
        "\" alt=\"TOTP QR\" style=\"width:200px;height:200px;\">\n"
        "</div>\n"
        "<div class=\"info-box\" style=\"position:relative; word-wrap:break-word; word-break:break-all;\">\n"
        "<strong>Manual entry key:</strong>\n"
        "<button type=\"button\" onclick=\"copySecret()\" style=\"position:absolute; right:12px; top:12px; background:none; border:none; "
        "cursor:pointer; color:inherit;\" title=\"Copy to clipboard\">\n"
        "<svg width=\"20\" height=\"20\" fill=\"currentColor\" viewBox=\"0 0 24 24\"><path d=\"M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 "
        "4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z\"/></svg>\n"
        "</button><br>\n"
        "<code id=\"totp-secret\" style=\"display:block; font-size:1.1rem; letter-spacing:2px; margin-top:8px;\">" +
        secret +
        "</code>\n"
        "<div id=\"copy-feedback\" style=\"display:none; color:var(--btn-bg); font-size:0.85rem; margin-top:8px; font-weight:500;\">✓ "
        "Copied to clipboard</div>\n"
        "</div>\n"
        "<script>function copySecret(){ navigator.clipboard.writeText(document.getElementById('totp-secret').innerText); const "
        "fb=document.getElementById('copy-feedback'); fb.style.display='block'; setTimeout(()=>fb.style.display='none', 2000); }</script>\n"
        "<div class=\"success-box\" style=\"padding:14px;margin:16px 0;font-size:0.85rem;\">\n"
        "<strong>Steps:</strong> Open app → tap + → Scan QR code → "
        "enter the 6-digit code below to confirm\n</div>\n"
        "<form method=\"POST\" action=\"/auth/enroll/totp/verify\">\n"
        "<input type=\"hidden\" name=\"user_id\" value=\"" + userId + "\">\n"
        "<input type=\"hidden\" name=\"secret\" value=\"" + secret + "\">\n"
        "<input type=\"hidden\" name=\"client_id\" value=\"" + clientId + "\">\n"
        "<input type=\"hidden\" name=\"redirect_uri\" value=\"" + redirectUri + "\">\n"
        "<input type=\"hidden\" name=\"state\" value=\"" + state + "\">\n"
        "<input type=\"hidden\" name=\"scope\" value=\"" + scope + "\">\n"
        "<input type=\"hidden\" name=\"code_challenge\" value=\"" + codeChallenge + "\">\n"
        "<input type=\"hidden\" name=\"code_challenge_method\" value=\"" + codeChallengeMethod + "\">\n"
        "<div class=\"form-group\">\n"
        "<label>Verification Code</label>\n"
        "<input type=\"text\" name=\"code\" placeholder=\"000000\" maxlength=\"6\""
        " pattern=\"[0-9]{6}\" required inputmode=\"numeric\" autofocus"
        " style=\"font-size:1.8rem;letter-spacing:10px;text-align:center;\">\n"
        "</div>\n"
        "<button type=\"submit\" class=\"btn\">✓ Activate 2FA</button>\n"
        "</form>\n"
        "<div class=\"links\">\n"
        "<a href=\"" + skipUrl + "\">Skip for now</a>\n"
        "</div>\n</div>\n";
    return buildPage("Enable 2FA", body, true);
}

static std::string landingPage() {
    std::string body = "<div class=\"card\" style=\"text-align:center;\">\n"
                       "<svg class=\"logo-icon\"><use href=\"#icon-rocket\"/></svg>\n"
                       "<h1>SNode.C Platform</h1>\n"
                       "<p class=\"subtitle\">Next-Generation Identity Provider</p>\n"
                       "<div class=\"info-box\" style=\"text-align:left;\">"
                       "Welcome to the SNode.C Identity Provider. This system provides centralized OAuth2 authentication, robust TOTP "
                       "multi-factor security, and seamless SSO integration."
                       "</div>\n"
                       "<a href=\"/auth/login\" class=\"btn\" style=\"margin-bottom:12px;\">Sign In</a>\n"
                       "<a href=\"/auth/register\" class=\"btn btn-secondary\">Create Account</a>\n"
                       "</div>\n";
    return buildPage("Welcome", body, false);
}

static std::string dashboardPage(const std::string& username, int users, int sessions, int tokens, const std::string& uptime, bool mfaEnabled) {
    std::string alertBox = "";
    if (!mfaEnabled) {
        alertBox = 
            "<div style=\"background:rgba(249,115,22,0.1); border:1.5px solid rgba(249,115,22,0.35); "
            "border-radius:12px; padding:16px; margin-bottom:28px; display:flex; align-items:center; gap:14px; color:#ffedd5; font-size:0.92rem; text-align:left;\">"
            "<svg width=\"22\" height=\"22\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"#f97316\" stroke-width=\"2\" style=\"flex-shrink:0;\">"
            "<path d=\"M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z\"/>"
            "<line x1=\"12\" y1=\"9\" x2=\"12\" y2=\"13\"/>"
            "<line x1=\"12\" y1=\"17\" x2=\"12.01\" y2=\"17\"/>"
            "</svg>"
            "<div><strong>Multi-Factor Authentication (MFA) is not active.</strong> "
            "Your account is currently secured with a single factor. To add a second factor, please "
            "<a href=\"/settings\" style=\"color:#fb923c; text-decoration:underline; font-weight:600;\">configure MFA in your Account Settings</a>.</div>"
            "</div>";
    } else {
        alertBox = 
            "<div style=\"background:rgba(52,199,89,0.1); border:1.5px solid rgba(52,199,89,0.35); "
            "border-radius:12px; padding:16px; margin-bottom:28px; display:flex; align-items:center; justify-content:space-between; gap:14px; color:#eafaf1; font-size:0.92rem; text-align:left;\">"
            "<div style=\"display:flex; align-items:center; gap:14px;\">"
            "<svg width=\"22\" height=\"22\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"#34c759\" stroke-width=\"2\" style=\"flex-shrink:0;\">"
            "<path d=\"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z\"/>"
            "<path d=\"M9 11l2 2 4-4\"/>"
            "</svg>"
            "<div><strong>Multi-Factor Authentication (MFA) is active.</strong> Your account is fully secured.</div>"
            "</div>"
            "<a href=\"/settings/mfa/disable\" class=\"btn btn-red\" style=\"padding: 6px 12px; font-size: 0.85rem; margin: 0; text-decoration: none;\">Disable MFA</a>"
            "</div>";
    }

    std::string body =
        alertBox +
        "<div style=\"text-align:center; margin-bottom: 24px;\">\n"
        "  <h1 style=\"color: white; font-weight: 500; letter-spacing: 1px; font-size: 2rem;\">Identity Provider</h1>\n"
        "</div>\n"
        "<div class=\"dashboard-grid\">\n"
        "  <div class=\"stat-card span-2\" style=\"background: linear-gradient(135deg, var(--btn-bg), #004499); color: white;\">\n"
        "    <span class=\"stat-label\" style=\"color: rgba(255,255,255,0.8);\">System Uptime</span>\n"
        "    <span class=\"stat-value\" style=\"color: white;\">" +
        uptime +
        "</span>\n"
        "    <div style=\"margin-top:24px; height:60px; display:flex; align-items:flex-end; gap:8px;\">"
        "      <div style=\"flex:1; height:40%; background:rgba(255,255,255,0.3); border-radius:4px;\"></div>"
        "      <div style=\"flex:1; height:70%; background:rgba(255,255,255,0.4); border-radius:4px;\"></div>"
        "      <div style=\"flex:1; height:50%; background:rgba(255,255,255,0.5); border-radius:4px;\"></div>"
        "      <div style=\"flex:1; height:90%; background:rgba(255,255,255,0.6); border-radius:4px;\"></div>"
        "      <div style=\"flex:1; height:60%; background:rgba(255,255,255,0.7); border-radius:4px;\"></div>"
        "      <div style=\"flex:1; height:80%; background:rgba(255,255,255,0.8); border-radius:4px;\"></div>"
        "      <div style=\"flex:1; height:100%; background:white; border-radius:4px; position:relative;\">"
        "        <div style=\"position:absolute; top:-20px; right:-10px; width:8px; height:8px; background:#34c759; border-radius:50%; "
        "box-shadow: 0 0 8px #34c759;\"></div>"
        "      </div>"
        "    </div>"
        "  </div>\n"
        "  <div class=\"stat-card\">\n"
        "    <span class=\"stat-label\">Registered Users</span>\n"
        "    <span class=\"stat-value\">" +
        std::to_string(users) +
        "</span>\n"
        "  </div>\n"
        "  <div class=\"stat-card\">\n"
        "    <span class=\"stat-label\">Active Sessions</span>\n"
        "    <span class=\"stat-value\">" +
        std::to_string(sessions) +
        "</span>\n"
        "  </div>\n"
        "  <div class=\"stat-card\">\n"
        "    <span class=\"stat-label\">OAuth Tokens Issued</span>\n"
        "    <span class=\"stat-value\">" +
        std::to_string(tokens) +
        "</span>\n"
        "  </div>\n"
        "  <div class=\"stat-card span-2\">\n"
        "    <span class=\"stat-label\">Network Gateway (SNode.C)</span>\n"
        "    <span class=\"stat-value\" style=\"font-size:1.5rem; margin-top:8px;\">Connected to GL-MT3000</span>\n"
        "    <div style=\"display:flex; justify-content:space-between; margin-top:16px; color:var(--text-muted); font-size:0.9rem;\">"
        "      <span>Nodes: 3 Active</span>"
        "      <span style=\"color:#28a745;\">● Online</span>"
        "    </div>"
        "  </div>\n"
        "  <a href=\"/settings\" class=\"stat-card clickable-card span-2\" style=\"text-decoration:none; display:flex; flex-direction:row; "
        "justify-content:space-between; align-items:center;\">\n"
        "    <div style=\"display:flex; flex-direction:column;\">\n"
        "      <span class=\"stat-label\">Settings & Security</span>\n"
        "      <span class=\"stat-value\" style=\"font-size:1.4rem; margin-top:6px;\">Manage Account</span>\n"
        "    </div>\n"
        "    <div style=\"display:flex; align-items:center; color:var(--text-muted);\">\n"
        "      <svg width=\"24\" height=\"24\" fill=\"currentColor\" style=\"margin-right:8px;\"><use href=\"#icon-settings\"/></svg>\n"
        "      <svg width=\"16\" height=\"16\" viewBox=\"0 0 24 24\" fill=\"currentColor\"><path d=\"M8.59 16.59L13.17 12 8.59 7.41 10 6l6 "
        "6-6 6-1.41-1.41z\"/></svg>\n"
        "    </div>\n"
        "  </a>\n"
        "</div>\n";
    return buildPage("Dashboard", body, true, username);
}

static std::string settingsPage(const std::string& username, const std::string& email, bool mfaEnabled, const std::string& userId) {
    std::string mfaStatus = mfaEnabled ? "<div class=\"success-box\"><svg "
                                         "style=\"width:16px;height:16px;fill:currentColor;vertical-align:middle;margin-right:8px;\"><use "
                                         "href=\"#icon-check\"/></svg> Two-Factor Authentication is <strong>Enabled</strong>.</div>"
                                       : "<div class=\"error-box\">Two-Factor Authentication is <strong>Disabled</strong>.</div>";

    std::string mfaAction = mfaEnabled ? "<a href=\"/settings/mfa/disable\" class=\"btn btn-red\" style=\"text-decoration:none;\">Disable 2FA</a>\n"
                                       : "<a href=\"/auth/enroll/totp?user_id=" + userId + "\" class=\"btn\">Enable 2FA</a>\n";

    std::string body = "<div class=\"card\">\n"
                       "<svg class=\"logo-icon\"><use href=\"#icon-settings\"/></svg>\n"
                       "<h1>Account Settings</h1>\n"
                       "<p class=\"subtitle\">Manage your security preferences</p>\n"
                       "<div class=\"form-group\">\n"
                       "<label>Username</label>\n"
                       "<input type=\"text\" value=\"" +
                       username +
                       "\" disabled>\n"
                       "</div>\n";
    if (!email.empty()) {
        body +=        "<div class=\"form-group\">\n"
                       "<label>Email Address</label>\n"
                       "<input type=\"text\" value=\"" +
                       email +
                       "\" disabled>\n"
                       "</div>\n";
    }
    body +=            "<div class=\"divider\"></div>\n"
                       "<h3>Security Settings</h3><br>\n" +
                       mfaStatus + mfaAction + "</div>\n";

    std::string headerName = formatUserDisplayName(username, email);
    return buildPage("Settings", body, true, headerName);
}

static std::string mfaDisableConfirmPage(const std::string& error, const std::string& username, const std::string& email) {
    std::string err = error.empty() ? "" : "<div class=\"error-box\">" + error + "</div>\n";

    std::string body = "<div class=\"card\">\n"
                       "<svg class=\"logo-icon\" style=\"fill:#ef4444; width:48px; height:48px; margin:0 auto 16px auto; display:block;\"><use href=\"#icon-shield\"/></svg>\n"
                       "<h1 style=\"text-align:center;\">Disable MFA</h1>\n"
                       "<p class=\"subtitle\" style=\"text-align:center;\">Confirm your password and MFA code to disable Two-Factor Authentication</p>\n" +
                       err +
                       "<form method=\"POST\" action=\"/settings/mfa/disable\">\n"
                       "<div class=\"form-group\">\n"
                       "<label>Password</label>\n"
                       "<input type=\"password\" name=\"password\" placeholder=\"Enter your password\" required autofocus>\n"
                       "</div>\n"
                       "<div class=\"form-group\">\n"
                       "<label>Verification Code</label>\n"
                       "<input type=\"text\" name=\"code\" placeholder=\"000000\" maxlength=\"6\" "
                       "pattern=\"[0-9]{6}\" required autocomplete=\"one-time-code\" inputmode=\"numeric\" "
                       "style=\"font-size:1.8rem;letter-spacing:10px;text-align:center;\">\n"
                       "</div>\n"
                       "<button type=\"submit\" class=\"btn btn-red\" style=\"width:100%; margin-top:16px;\">Verify & Disable MFA</button>\n"
                       "</form>\n"
                       "<div class=\"links\" style=\"text-align:center; margin-top:16px;\">\n"
                       "<a href=\"/settings\">Cancel and Return</a>\n"
                       "</div>\n"
                       "</div>\n";
    std::string headerName = formatUserDisplayName(username, email);
    return buildPage("Disable MFA", body, true, headerName);
}

static std::string forgotPasswordPage(const std::string& error, const std::string& info) {
    std::string msg = error.empty() ? (info.empty() ? "" : "<div class=\"info-box\">" + info + "</div>\n")
                                    : "<div class=\"error-box\">" + error + "</div>\n";

    std::string body = "<div class=\"card\">\n"
                       "<div class=\"logo\">🔑</div>\n"
                       "<h1>Forgot Password</h1>\n"
                       "<p class=\"subtitle\">Enter your email to receive a reset link</p>\n" +
                       msg +
                       "<form method=\"POST\" action=\"/auth/forgot-password\">\n"
                       "<div class=\"form-group\">\n"
                       "<label>Email Address</label>\n"
                       "<input type=\"email\" name=\"email\" placeholder=\"your@email.com\" required autofocus>\n"
                       "</div>\n"
                       "<button type=\"submit\" class=\"btn\">Send Reset Link</button>\n"
                       "</form>\n"
                       "<div class=\"links\"><a href=\"/auth/login\">Back to Sign In</a></div>\n"
                       "</div>\n";
    return buildPage("Forgot Password", body);
}

static std::string resetPasswordPage(const std::string& token, const std::string& error) {
    std::string err = error.empty() ? "" : "<div class=\"error-box\">" + error + "</div>\n";

    std::string body = "<div class=\"card\">\n"
                       "<div class=\"logo\">🔐</div>\n"
                       "<h1>Reset Password</h1>\n"
                       "<p class=\"subtitle\">Choose a new password for your account</p>\n" +
                       err +
                       "<form method=\"POST\" action=\"/auth/reset-password\">\n"
                       "<input type=\"hidden\" name=\"token\" value=\"" +
                       token +
                       "\">\n"
                       "<div class=\"form-group\">\n"
                       "<label>New Password</label>\n"
                       "<input type=\"password\" name=\"password\" placeholder=\"New password\" required autofocus>\n"
                       "</div>\n"
                       "<div class=\"form-group\">\n"
                       "<label>Confirm Password</label>\n"
                       "<input type=\"password\" name=\"password_confirm\" placeholder=\"Confirm new password\" required>\n"
                       "</div>\n"
                       "<button type=\"submit\" class=\"btn btn-green\">Reset Password</button>\n"
                       "</form>\n"
                       "</div>\n";
    return buildPage("Reset Password", body);
}

static std::string
successPage(const std::string& heading, const std::string& message, const std::string& linkUrl, const std::string& linkText) {
    std::string body = "<div class=\"card\">\n"
                       "<div class=\"logo\">✅</div>\n"
                       "<h1>" +
                       heading +
                       "</h1>\n"
                       "<p class=\"subtitle\">" +
                       message +
                       "</p>\n"
                       "<div class=\"divider\"></div>\n"
                       "<a href=\"" +
                       linkUrl + "\" class=\"btn btn-green\">" + linkText +
                       "</a>\n"
                       "</div>\n";
    return buildPage(heading, body);
}

static std::string errorPage(const std::string& message) {
    std::string body = "<div class=\"card\">\n"
                       "<div class=\"logo\">⚠️</div>\n"
                       "<h1>Error</h1>\n"
                       "<div class=\"error-box\">" +
                       message +
                       "</div>\n"
                       "<a href=\"/auth/login\" class=\"btn btn-secondary\">Back to Login</a>\n"
                       "</div>\n";
    return buildPage("Error", body);
}

// ============================================================================
// main — wire up all routes and start the server
// ============================================================================

int main(int argc, char* argv[]) {
    core::SNodeC::init(argc, argv);

    // --- Configuration from environment (falls back to defaults) ---
    auto env = [](const char* k, const std::string& def) {
        const char* v = std::getenv(k);
        return v ? std::string(v) : def;
    };
    g_issuer = env("IDP_ISSUER", "https://idp.snodec.local");
    g_idpBaseUrl = env("IDP_BASE_URL", "http://localhost:8083");
    const int port = std::stoi(env("IDP_PORT", "8083"));
    const std::string dbPath = env("DB_PATH", "snodec_auth.db");
    const std::string keyPath = env("IDP_PRIVATE_KEY_PATH", "src/apps/auth_idp/keys/private_key.pem");
    g_totpKeyPath = env("TOTP_KEY_PATH", "");  // Empty = no encryption (dev mode)
    
    // Parse dynamic allowed redirect URIs
    std::string extraRedirectUris = env("IDP_ALLOWED_REDIRECT_URIS", "");
    if (!extraRedirectUris.empty()) {
        std::istringstream iss(extraRedirectUris);
        std::string token;
        while (std::getline(iss, token, ',')) {
            // Trim spaces if needed, but assuming comma-separated without spaces for simplicity
            g_allowedRedirectUris.insert(token);
        }
    }

    SqliteDatabase db(dbPath);
    db.initSchema();
    g_db = &db;

    // --- Rate Limiters ---
    RateLimiter loginLimiter(5, 60);   // 5 attempts per 60 seconds
    RateLimiter mfaLimiter(5, 60);     // 5 attempts per 60 seconds
    g_loginLimiter = &loginLimiter;
    g_mfaLimiter = &mfaLimiter;
    LOG(INFO) << "Rate limiting enabled: 5 attempts per 60s for login and MFA";

    // --- TOTP encryption key ---
    if (!g_totpKeyPath.empty()) {
        // Auto-generate key file if it doesn't exist
        std::ifstream keyCheck(g_totpKeyPath);
        if (!keyCheck.good()) {
            LOG(INFO) << "Generating new TOTP encryption key: " << g_totpKeyPath;
            try {
                SecretEncryptor::generateKeyFile(g_totpKeyPath);
            } catch (const std::exception& e) {
                LOG(ERROR) << "Failed to generate TOTP key: " << e.what();
                LOG(WARNING) << "TOTP secrets will be stored in plaintext";
                g_totpKeyPath = "";
            }
        }
        if (!g_totpKeyPath.empty()) {
            LOG(INFO) << "TOTP secret encryption enabled (AES-256-GCM)";
        }
    } else {
        LOG(WARNING) << "TOTP secret encryption disabled (set TOTP_KEY_PATH to enable)";
    }

    // --- Setup Claim Token (secure bootstrap) ---
    {
        std::string err;
        int userCount = 0;
        g_db->query("SELECT COUNT(*) FROM user", {}, [&userCount](const SqliteDatabase::Row& r) {
            userCount = std::stoi(r.get(0));
        });
        bool hasUsers = userCount > 0;
        if (!hasUsers) {
            g_setupClaimToken = generateRandomString(12);
            LOG(INFO) << "==========================================================";
            LOG(INFO) << "  FIRST-RUN SETUP — No users found in database.";
            LOG(INFO) << "  Setup Claim Token: " << g_setupClaimToken;
            LOG(INFO) << "  Enter this token during first account registration";
            LOG(INFO) << "  to claim the administrator account.";
            LOG(INFO) << "==========================================================";
        }
    }

    // --- Federated Login Registry (social login: Google, Apple, Meta) ---
    FederatedLoginRegistry federatedRegistry;
    g_federatedRegistry = &federatedRegistry;
    if (federatedRegistry.hasEnabledProviders()) {
        LOG(INFO) << "Social login providers enabled:";
        for (const auto& p : federatedRegistry.getEnabledProviders()) {
            LOG(INFO) << "  - " << p.displayName;
        }
    } else {
        LOG(INFO) << "No social login providers configured (set OAUTH_<PROVIDER>_CLIENT_ID/SECRET to enable)";
    }

    // Ensure mfa_verified column exists (migration for existing databases)
    {
        std::string err;
        g_db->exec("ALTER TABLE auth_code ADD COLUMN mfa_verified INTEGER DEFAULT 0", {}, &err);
        g_db->exec("ALTER TABLE password_reset_tokens ADD COLUMN used INTEGER DEFAULT 0", {}, &err);
    }

    // --- Load RSA private key and init JWT signer ---
    std::string privateKey;
    try {
        privateKey = loadPrivateKey(keyPath);
    } catch (const std::exception& e) {
        LOG(ERROR) << "Cannot load private key: " << e.what();
        return 1;
    }
    JwtSigner jwtSigner(g_issuer, privateKey);

    // --- Lambda: issue auth code (OAuth2) or direct session ---
    auto finishLogin = [&](auto& res,
                           const std::string& userId,
                           const std::string& username,
                           const std::string& clientId,
                           const std::string& redirectUri,
                           const std::string& state,
                           const std::string& scope,
                           const std::string& challenge,
                           const std::string& method,
                           bool mfaVerified = false) {
        
        // Always establish a session at the IdP for true SSO
        std::string token = generateRandomString(64);
        std::string err;
        g_db->exec("INSERT INTO session(token, user_id, expires_at) VALUES(?, ?, datetime('now','+24 hours'))", {token, userId}, &err);
        res->cookie("snodec_session", token, {{"HttpOnly", ""}, {"Path", "/"}, {"Max-Age", "86400"}});

        if (!clientId.empty() && !redirectUri.empty()) {
            // OAuth2 flow: Redirect back to the app with a code
            std::string code = generateRandomString(32);
            if (!g_db->exec("INSERT INTO auth_code(code,user_id,client_id,redirect_uri,"
                            "scope,state,code_challenge,code_challenge_method,mfa_verified,expires_at)"
                            " VALUES(?,?,?,?,?,?,?,?,?,datetime('now','+10 minutes'))",
                            {code, userId, clientId, redirectUri, scope, state, challenge, method, mfaVerified ? "1" : "0"},
                            &err)) {
                res->status(500).send(errorPage("DB error: " + err));
                return;
            }
            const std::string sep = redirectUri.find('?') == std::string::npos ? "?" : "&";
            res->redirect(redirectUri + sep + "code=" + httputils::url_encode(code) + "&state=" + httputils::url_encode(state));
        } else {
            // Direct login (IdP dashboard)
            res->redirect("/dashboard");
        }
    };

    auto requireSession = [&](auto req, auto res) -> std::string {
        std::string token = req->cookie("snodec_session");
        if (token.empty())
            return "";

        std::string userId;
        g_db->query(
            "SELECT user_id FROM session WHERE token=? AND expires_at > CURRENT_TIMESTAMP", {token}, [&](const SqliteDatabase::Row& r) {
                userId = r.get(0);
            });

        if (userId.empty()) {
            res->cookie("snodec_session", "", {{"Path", "/"}, {"Max-Age", "0"}});
        }
        return userId;
    };

    const express::legacy::in::WebApp app("IdpServer");

    // ── GET / ─────────────────────────────────────────────────────────────────
    app.get("/", [&requireSession] MIDDLEWARE(req, res, next) {
        if (!requireSession(req, res).empty()) {
            res->redirect("/dashboard");
            return;
        }
        res->send(landingPage());
    });

    // ── GET /dashboard ────────────────────────────────────────────────────────
    app.get("/dashboard", [&requireSession] MIDDLEWARE(req, res, next) {
        std::string userId = requireSession(req, res);
        if (userId.empty()) {
            res->redirect("/auth/login");
            return;
        }

        std::string username, email;
        int mfaEnabled = 0;
        g_db->query("SELECT username, email, totp_enabled FROM user WHERE id=?", {userId}, [&](const SqliteDatabase::Row& r) {
            username = r.get(0);
            email = r.get(1);
            mfaEnabled = std::stoi(r.get(2));
        });

        int totalUsers = 0, activeSessions = 0, totalTokens = 0;
        g_db->query("SELECT COUNT(*) FROM user", {}, [&](const SqliteDatabase::Row& r) {
            totalUsers = std::stoi(r.get(0));
        });
        g_db->query("SELECT COUNT(*) FROM session WHERE expires_at > CURRENT_TIMESTAMP", {}, [&](const SqliteDatabase::Row& r) {
            activeSessions = std::stoi(r.get(0));
        });
        g_db->query("SELECT COUNT(*) FROM auth_code", {}, [&](const SqliteDatabase::Row& r) {
            totalTokens = std::stoi(r.get(0));
        });

        std::string headerName = formatUserDisplayName(username, email);
        res->send(dashboardPage(headerName, totalUsers, activeSessions, totalTokens, formatUptime(), mfaEnabled > 0));
    });

    // ── GET /settings ─────────────────────────────────────────────────────────
    app.get("/settings", [&requireSession] MIDDLEWARE(req, res, next) {
        std::string userId = requireSession(req, res);
        if (userId.empty()) {
            res->redirect("/auth/login");
            return;
        }

        std::string username, email;
        int mfaEnabled = 0;
        g_db->query("SELECT username, email, totp_enabled FROM user WHERE id=?", {userId}, [&](const SqliteDatabase::Row& r) {
            username = r.get(0);
            email = r.get(1);
            mfaEnabled = std::stoi(r.get(2));
        });

        res->send(settingsPage(username, email, mfaEnabled > 0, userId));
    });

    // ── GET /settings/mfa/disable ─────────────────────────────────────────────
    app.get("/settings/mfa/disable", [&requireSession] MIDDLEWARE(req, res, next) {
        std::string userId = requireSession(req, res);
        if (userId.empty()) {
            res->redirect("/auth/login");
            return;
        }

        std::string username, email;
        int mfaEnabled = 0;
        g_db->query("SELECT username, email, totp_enabled FROM user WHERE id=?", {userId}, [&](const SqliteDatabase::Row& r) {
            username = r.get(0);
            email = r.get(1);
            mfaEnabled = std::stoi(r.get(2));
        });

        if (mfaEnabled <= 0) {
            res->redirect("/settings");
            return;
        }

        res->send(mfaDisableConfirmPage("", username, email));
    });

    // ── POST /settings/mfa/disable ────────────────────────────────────────────
    app.post("/settings/mfa/disable", [&requireSession] MIDDLEWARE(req, res, next) {
        std::string userId = requireSession(req, res);
        if (userId.empty()) {
            res->redirect("/auth/login");
            return;
        }

        auto p = parseBody(req->body);
        const std::string password = p["password"];
        const std::string code = p["code"];

        std::string username, email, hash, salt, totpSecret;
        int mfaEnabled = 0;
        g_db->query("SELECT username, email, password_hash, password_salt, totp_enabled, totp_secret FROM user WHERE id=?", {userId}, [&](const SqliteDatabase::Row& r) {
            username = r.get(0);
            email = r.get(1);
            hash = r.get(2);
            salt = r.get(3);
            mfaEnabled = std::stoi(r.get(4));
            totpSecret = r.get(5);
        });

        if (mfaEnabled <= 0) {
            res->redirect("/settings");
            return;
        }

        bool needsMigration = false;
        if (!verifyPasswordAny(password, hash, salt, needsMigration)) {
            res->status(400).send(mfaDisableConfirmPage("Invalid password. Please try again.", username, email));
            return;
        }
        if (needsMigration) migratePasswordHash(userId, password);

        std::string decryptedSecret = decryptTotpSecret(totpSecret);
        if (!Totp::verifyCode(decryptedSecret, code)) {
            res->status(400).send(mfaDisableConfirmPage("Invalid verification code. Please try again.", username, email));
            return;
        }

        std::string err;
        if (!g_db->exec("UPDATE user SET totp_enabled=0, totp_secret=NULL WHERE id=?", {userId}, &err)) {
            res->status(500).send(errorPage("DB error: " + err));
            return;
        }

        res->redirect("/settings");
    });

    // ── POST /auth/logout ─────────────────────────────────────────────────────
    app.post("/auth/logout", [] MIDDLEWARE(req, res, next) {
        std::string token = req->cookie("snodec_session");
        if (!token.empty()) {
            std::string err;
            g_db->exec("DELETE FROM session WHERE token=?", {token}, &err);
        }
        res->cookie("snodec_session", "", {{"Path", "/"}, {"Max-Age", "0"}});
        // Chain logout to Protected Web App for true SSO logout
        res->redirect("http://localhost:8055/auth/logout");
    });

    // ── GET /auth/logout ──────────────────────────────────────────────────────
    app.get("/auth/logout", [] MIDDLEWARE(req, res, next) {
        std::string token = req->cookie("snodec_session");
        if (!token.empty()) {
            std::string err;
            g_db->exec("DELETE FROM session WHERE token=?", {token}, &err);
        }
        res->cookie("snodec_session", "", {{"Path", "/"}, {"Max-Age", "0"}});
        
        std::string redirectUri = req->query("redirect_uri");
        if (!redirectUri.empty()) {
            res->redirect(redirectUri);
        } else {
            res->redirect("/");
        }
    });

    // ── GET /auth/login ───────────────────────────────────────────────────────
    app.get("/auth/login", [&requireSession, &finishLogin] MIDDLEWARE(req, res, next) {
        std::string userId = requireSession(req, res);
        std::string clientId = req->query("client_id");

        if (!userId.empty()) {
            if (clientId.empty()) {
                res->redirect("/dashboard");
                return;
            } else {
                // User is logged in and this is an SSO request. Auto-approve!
                std::string username;
                bool totpEnabled = false;
                g_db->query("SELECT username, totp_enabled FROM user WHERE id=?", {userId}, [&](const SqliteDatabase::Row& r) {
                    username = r.get(0);
                    totpEnabled = (r.get(1) == "1");
                });
                
                if (!username.empty()) {
                    if (totpEnabled) {
                        res->send(mfaPage("", userId, clientId, req->query("redirect_uri"), req->query("state"), req->query("scope"), req->query("code_challenge"), req->query("code_challenge_method")));
                        return;
                    }
                    finishLogin(res, userId, username, clientId, 
                                req->query("redirect_uri"), 
                                req->query("state"), 
                                req->query("scope"), 
                                req->query("code_challenge"), 
                                req->query("code_challenge_method"),
                                false);
                    return;
                }
            }
        }
        
        res->send(loginPage("",
                            clientId,
                            req->query("redirect_uri"),
                            req->query("state"),
                            req->query("scope"),
                            req->query("code_challenge"),
                            req->query("code_challenge_method")));
    });

    // ── GET /auth/register ────────────────────────────────────────────────────
    app.get("/auth/register", [] MIDDLEWARE(req, res, next) {
        res->send(registerPage("", req->query("client_id"), req->query("redirect_uri"), req->query("state"), req->query("scope"),
                               req->query("code_challenge"), req->query("code_challenge_method")));
    });

    // ── POST /auth/register ───────────────────────────────────────────────────
    app.post("/auth/register", [] MIDDLEWARE(req, res, next) {
        auto p = parseBody(req->body);
        const std::string username = p["username"], email = p["email"], password = p["password"], confirmPassword = p["confirm_password"], clientId = p["client_id"],
                          redirectUri = p["redirect_uri"], state = p["state"], scope = p["scope"],
                          challenge = p["code_challenge"], method = p["code_challenge_method"];
        if (username.empty() || email.empty() || password.empty() || confirmPassword.empty()) {
            res->status(400).send(registerPage("All fields are required.", clientId, redirectUri, state, scope, challenge, method));
            return;
        }
        if (password != confirmPassword) {
            res->status(400).send(registerPage("Passwords do not match.", clientId, redirectUri, state, scope, challenge, method));
            return;
        }
        // Input length validation (prevent oversized inputs)
        if (username.length() > 64 || email.length() > 254 || password.length() > 128) {
            res->status(400).send(registerPage("Input too long. Username max 64, email max 254, password max 128 characters.", clientId, redirectUri, state, scope, challenge, method));
            return;
        }
        if (username.length() < 3) {
            res->status(400).send(registerPage("Username must be at least 3 characters.", clientId, redirectUri, state, scope, challenge, method));
            return;
        }
        if (password.length() < 8) {
            res->status(400).send(registerPage("Password must be at least 8 characters.", clientId, redirectUri, state, scope, challenge, method));
            return;
        }
        // Check duplicate
        bool exists = false;
        g_db->query("SELECT id FROM user WHERE username=? OR email=?", {username, email}, [&exists](const SqliteDatabase::Row&) {
            exists = true;
        });
        if (exists) {
            res->status(400).send(registerPage("Username or email already taken.", clientId, redirectUri, state, scope, challenge, method));
            return;
        }
        const std::string hash = hashPasswordPbkdf2(password);
        std::string err;
        if (!g_db->exec("INSERT INTO user(username,email,password_hash,password_salt)"
                        " VALUES(?,?,?,?)",
                        {username, email, hash, ""},
                        &err)) {
            res->status(400).send(registerPage("Registration failed: " + err, clientId, redirectUri, state, scope, challenge, method));
            return;
        }
        const std::string userId = std::to_string(g_db->lastInsertRowid());
        // Redirect to TOTP enrollment
        res->redirect("/auth/enroll/totp?user_id=" + userId + 
                      "&client_id=" + httputils::url_encode(clientId) + 
                      "&redirect_uri=" + httputils::url_encode(redirectUri) + 
                      "&state=" + httputils::url_encode(state) + 
                      "&scope=" + httputils::url_encode(scope) + 
                      "&code_challenge=" + httputils::url_encode(challenge) + 
                      "&code_challenge_method=" + httputils::url_encode(method));
    });

    // ── POST /auth/login ──────────────────────────────────────────────────────
    app.post("/auth/login", [&finishLogin] MIDDLEWARE(req, res, next) {
        auto p = parseBody(req->body);
        const std::string username = p["username"], password = p["password"], clientId = p["client_id"], redirectUri = p["redirect_uri"],
                          state = p["state"], scope = p["scope"], challenge = p["code_challenge"], method = p["code_challenge_method"];

        if (username.empty() || password.empty()) {
            res->send(loginPage("Username and password required.", clientId, redirectUri, state, scope, challenge, method));
            return;
        }

        // --- Rate Limiting Check ---
        if (g_loginLimiter && !g_loginLimiter->isAllowed(username)) {
            int retryAfter = g_loginLimiter->secondsUntilUnblock(username);
            res->status(429).send(loginPage("Too many failed login attempts. Please try again in " + std::to_string(retryAfter) + " seconds.",
                                            clientId, redirectUri, state, scope, challenge, method, username));
            return;
        }

        struct UserRow {
            std::string id, hash, salt, totpSecret;
            bool totpEnabled = false;
        };
        UserRow u;
        bool found = false;
        g_db->query("SELECT id,password_hash,password_salt,totp_enabled,totp_secret"
                    " FROM user WHERE username=?",
                    {username},
                    [&](const SqliteDatabase::Row& row) {
                        found = true;
                        u.id = row.get(0);
                        u.hash = row.get(1);
                        u.salt = row.get(2);
                        u.totpEnabled = (row.get(3) == "1");
                        u.totpSecret = decryptTotpSecret(row.get(4));
                    });
        bool needsMigration = false;
        if (!found || !verifyPasswordAny(password, u.hash, u.salt, needsMigration)) {
            if (g_loginLimiter) {
                g_loginLimiter->recordFailure(username);
            }
            res->send(loginPage("Invalid username or password.", clientId, redirectUri, state, scope, challenge, method, username));
            return;
        }
        if (needsMigration) migratePasswordHash(u.id, password);

        // Success - reset password rate limiter
        if (g_loginLimiter) {
            g_loginLimiter->recordSuccess(username);
        }

        if (u.totpEnabled) {
            res->send(mfaPage("", u.id, clientId, redirectUri, state, scope, challenge, method));
        } else {
            finishLogin(res, u.id, username, clientId, redirectUri, state, scope, challenge, method, false);
        }
    });

    // ── POST /auth/mfa ────────────────────────────────────────────────────────
    app.post("/auth/mfa", [&finishLogin] MIDDLEWARE(req, res, next) {
        auto p = parseBody(req->body);
        const std::string userId = p["user_id"], code = p["code"], clientId = p["client_id"], redirectUri = p["redirect_uri"],
                          state = p["state"], scope = p["scope"], challenge = p["code_challenge"], method = p["code_challenge_method"];

        if (userId.empty() || code.empty()) {
            res->status(400).send(errorPage("Missing parameters."));
            return;
        }

        // --- Rate Limiting Check ---
        if (g_mfaLimiter && !g_mfaLimiter->isAllowed(userId)) {
            int retryAfter = g_mfaLimiter->secondsUntilUnblock(userId);
            res->status(429).send(mfaPage("Too many failed verification attempts. Please try again in " + std::to_string(retryAfter) + " seconds.",
                                          userId, clientId, redirectUri, state, scope, challenge, method));
            return;
        }

        struct UserRow {
            std::string username, secret;
        };
        UserRow u;
        bool found = false;
        g_db->query("SELECT username,totp_secret FROM user WHERE id=? AND totp_enabled=1", {userId}, [&](const SqliteDatabase::Row& row) {
            found = true;
            u.username = row.get(0);
            u.secret = decryptTotpSecret(row.get(1));
        });
        if (!found) {
            if (g_mfaLimiter) {
                g_mfaLimiter->recordFailure(userId);
            }
            res->send(mfaPage("User not found or MFA not enabled.", userId, clientId, redirectUri, state, scope, challenge, method));
            return;
        }
        if (!Totp::verifyCode(u.secret, code)) {
            if (g_mfaLimiter) {
                g_mfaLimiter->recordFailure(userId);
            }
            res->send(
                mfaPage("Invalid verification code. Please try again.", userId, clientId, redirectUri, state, scope, challenge, method));
            return;
        }

        // Success - reset MFA rate limiter
        if (g_mfaLimiter) {
            g_mfaLimiter->recordSuccess(userId);
        }

        finishLogin(res, userId, u.username, clientId, redirectUri, state, scope, challenge, method, true);
    });

    // ── GET /auth/enroll/totp ─────────────────────────────────────────────────
    app.get("/auth/enroll/totp", [&requireSession] MIDDLEWARE(req, res, next) {
        std::string userId = req->query("user_id");
        if (userId.empty()) {
            res->status(400).send(errorPage("Missing user_id."));
            return;
        }

        // Ensure they have the right to enroll this user (either no session and new user, or matching session)
        std::string sessUserId = requireSession(req, res);
        if (!sessUserId.empty() && sessUserId != userId) {
            res->status(403).send(errorPage("Access denied."));
            return;
        }

        std::string username;
        g_db->query("SELECT username FROM user WHERE id=?", {userId}, [&](const SqliteDatabase::Row& r) {
            username = r.get(0);
        });
        if (username.empty()) {
            res->status(404).send(errorPage("User not found."));
            return;
        }

        const std::string secret = Totp::generateSecret();
        const std::string uri = QrCodeGenerator::makeTotpOtpAuthUri("SNode.C", username, secret);

        res->send(enrollTotpPage(userId, secret, uri, 
                                 req->query("client_id"), 
                                 req->query("redirect_uri"), 
                                 req->query("state"), 
                                 req->query("scope"),
                                 req->query("code_challenge"),
                                 req->query("code_challenge_method")));
    });

    // ── POST /auth/enroll/totp/verify ─────────────────────────────────────────
    app.post("/auth/enroll/totp/verify", [&finishLogin] MIDDLEWARE(req, res, next) {
        auto p = parseBody(req->body);
        const std::string userId = p["user_id"], secret = p["secret"], code = p["code"];
        if (userId.empty() || secret.empty() || code.empty()) {
            res->status(400).send(errorPage("Missing parameters."));
            return;
        }
        if (!Totp::verifyCode(secret, code)) {
            std::string username;
            g_db->query("SELECT username FROM user WHERE id=?", {userId}, [&](const SqliteDatabase::Row& r) {
                username = r.get(0);
            });
            const std::string uri = QrCodeGenerator::makeTotpOtpAuthUri("SNode.C", username, secret);
            res->status(400).send(enrollTotpPage(userId, secret, uri, 
                                                 p["client_id"], 
                                                 p["redirect_uri"], 
                                                 p["state"], 
                                                 p["scope"], 
                                                 p["code_challenge"], 
                                                 p["code_challenge_method"], 
                                                 "Invalid verification code. Please try again."));
            return;
        }
        std::string err;
        if (!g_db->exec("UPDATE user SET totp_secret=?,totp_enabled=1 WHERE id=?", {encryptTotpSecret(secret), userId}, &err)) {
            res->status(500).send(errorPage("DB error: " + err));
            return;
        }

        std::string username;
        g_db->query("SELECT username FROM user WHERE id=?", {userId}, [&](const SqliteDatabase::Row& r) {
            username = r.get(0);
        });

        finishLogin(res, userId, username, p["client_id"], p["redirect_uri"], p["state"], p["scope"], p["code_challenge"], p["code_challenge_method"], true);
    });

    // ── GET /auth/enroll/totp/skip ─────────────────────────────────────────────
    app.get("/auth/enroll/totp/skip", [&finishLogin] MIDDLEWARE(req, res, next) {
        std::string userId = req->query("user_id");
        if (userId.empty()) {
            res->status(400).send(errorPage("Missing user_id."));
            return;
        }

        std::string username;
        g_db->query("SELECT username FROM user WHERE id=?", {userId}, [&](const SqliteDatabase::Row& r) {
            username = r.get(0);
        });
        if (username.empty()) {
            res->status(404).send(errorPage("User not found."));
            return;
        }

        finishLogin(res, userId, username, req->query("client_id"), req->query("redirect_uri"), req->query("state"), req->query("scope"), req->query("code_challenge"), req->query("code_challenge_method"), false);
    });

    // ── GET /api/qrcode ───────────────────────────────────────────────────────
    app.get("/api/qrcode", [] MIDDLEWARE(req, res, next) {
        std::string data = httputils::url_decode(req->query("data"));
        if (data.empty()) {
            res->status(400).send("Missing data");
            return;
        }
        try {
            auto png = QrCodeGenerator::generatePng(data, 4, 4);
            res->set("Content-Type", "image/png")
                .set("Cache-Control", "public,max-age=3600")
                .send(reinterpret_cast<const char*>(png.data()), static_cast<std::streamsize>(png.size()));
        } catch (const std::exception& e) {
            LOG(ERROR) << "QR generation failed: " << e.what();
            res->status(500).send("QR generation failed");
        }
    });

    // ── GET /auth/forgot-password ─────────────────────────────────────────────
    app.get("/auth/forgot-password", [] MIDDLEWARE(req, res, next) {
        res->send(forgotPasswordPage("", ""));
    });

    // ── POST /auth/forgot-password ────────────────────────────────────────────
    app.post("/auth/forgot-password", [] MIDDLEWARE(req, res, next) {
        auto p = parseBody(req->body);
        const std::string email = p["email"];
        if (email.empty()) {
            res->send(forgotPasswordPage("Email address required.", ""));
            return;
        }
        // Look up user
        std::string userId, username;
        g_db->query("SELECT id,username FROM user WHERE email=?", {email}, [&](const SqliteDatabase::Row& r) {
            userId = r.get(0);
            username = r.get(1);
        });
        // Always show success to prevent email enumeration
        if (userId.empty()) {
            res->send(forgotPasswordPage("", "If that email is registered, a reset link will be shown here."));
            return;
        }
        // Generate secure token, expires in 15 minutes
        const std::string token = generateRandomString(48);
        std::string err;
        g_db->exec("DELETE FROM password_reset_tokens WHERE user_id=?", {userId});
        g_db->exec("INSERT INTO password_reset_tokens(token,user_id,expires_at)"
                   " VALUES(?,?,datetime('now','+15 minutes'))",
                   {token, userId},
                   &err);

        const std::string resetUrl = g_idpBaseUrl + "/auth/reset-password?token=" + token;
        sendPasswordResetLink(email, resetUrl);

        // Show reset link in browser (local / LAN mode — no SMTP needed)
        std::string body = "<div class=\"card\">\n"
                           "<div class=\"logo\">📧</div>\n"
                           "<h1>Reset Link Ready</h1>\n"
                           "<p class=\"subtitle\">Hi <strong>" +
                           username +
                           "</strong>, "
                           "click the link below to reset your password.</p>\n"
                           "<div class=\"success-box\" style=\"word-break:break-all;\">\n"
                           "<a href=\"" +
                           resetUrl + "\" style=\"color:#9ae6b4;\">" + resetUrl +
                           "</a>\n"
                           "</div>\n"
                           "<p style=\"color:#666;font-size:0.8rem;margin-top:12px;\">"
                           "This link expires in 15 minutes. "
                           "In production, this link would be sent by email.</p>\n"
                           "<div class=\"links\"><a href=\"/auth/login\">Back to Login</a></div>\n"
                           "</div>\n";
        res->send(buildPage("Password Reset", body));
    });

    // ── GET /auth/reset-password ──────────────────────────────────────────────
    app.get("/auth/reset-password", [] MIDDLEWARE(req, res, next) {
        const std::string token = req->query("token");
        if (token.empty()) {
            res->send(errorPage("Missing reset token."));
            return;
        }
        // Validate token
        bool valid = false;
        g_db->query("SELECT id FROM password_reset_tokens"
                    " WHERE token=? AND used=0 AND expires_at > datetime('now')",
                    {token},
                    [&](const SqliteDatabase::Row&) {
                        valid = true;
                    });
        if (!valid) {
            res->send(errorPage("This reset link is invalid or has expired."
                                " Please request a new one."));
            return;
        }
        res->send(resetPasswordPage(token, ""));
    });

    // ── POST /auth/reset-password ─────────────────────────────────────────────
    app.post("/auth/reset-password", [] MIDDLEWARE(req, res, next) {
        auto p = parseBody(req->body);
        const std::string token = p["token"], pw = p["password"], pw2 = p["password_confirm"];
        if (token.empty() || pw.empty()) {
            res->send(resetPasswordPage(token, "All fields are required."));
            return;
        }
        if (pw != pw2) {
            res->send(resetPasswordPage(token, "Passwords do not match."));
            return;
        }
        // Fetch + validate token
        std::string userId;
        g_db->query("SELECT user_id FROM password_reset_tokens"
                    " WHERE token=? AND used=0 AND expires_at > datetime('now')",
                    {token},
                    [&](const SqliteDatabase::Row& r) {
                        userId = r.get(0);
                    });
        if (userId.empty()) {
            res->send(errorPage("Invalid or expired reset token."));
            return;
        }
        // Update password
        const std::string hash = hashPasswordPbkdf2(pw);
        std::string err;
        g_db->exec("UPDATE user SET password_hash=?,password_salt='' WHERE id=?", {hash, userId}, &err);
        // Mark token used
        g_db->exec("UPDATE password_reset_tokens SET used=1 WHERE token=?", {token});
        res->send(successPage("Password Reset", "Your password has been updated successfully.", "/auth/login", "Sign In"));
    });

    // ── GET /auth/help/authenticator ──────────────────────────────────────────
    app.get("/auth/help/authenticator", [] MIDDLEWARE(req, res, next) {
        std::string body = "<div class=\"card\" style=\"max-width:600px;\">\n"
                           "<a href=\"javascript:history.back()\" style=\"color:#63b3ed;"
                           "font-size:0.85rem;text-decoration:none;\">← Back</a>\n"
                           "<div class=\"logo\" style=\"margin-top:16px;\">📱</div>\n"
                           "<h1>Authenticator App Setup</h1>\n"
                           "<p class=\"subtitle\">Step-by-step guide</p>\n"
                           "<div class=\"info-box\" style=\"margin:20px 0;text-align:left;\">\n"
                           "<strong>Supported Apps:</strong><br>\n"
                           "🟢 Google Authenticator &nbsp;|&nbsp; "
                           "🔵 Microsoft Authenticator &nbsp;|&nbsp; "
                           "⚫ Authy\n</div>\n"
                           "<ol style=\"padding-left:20px;color:#ccc;line-height:2.2;\">\n"
                           "<li>Install your authenticator app from the App Store or Play Store</li>\n"
                           "<li>Tap <strong>+</strong> or <em>Add Account</em></li>\n"
                           "<li>Select <strong>Scan QR Code</strong></li>\n"
                           "<li>Point your camera at the QR code on the setup page</li>\n"
                           "<li>Enter the 6-digit code shown in the app to confirm setup</li>\n"
                           "</ol>\n"
                           "<div class=\"info-box\" style=\"margin-top:20px;\">\n"
                           "💡 <strong>Can't scan?</strong> Use the manual entry key shown "
                           "below the QR code — tap <em>Enter setup key</em> in your app.\n"
                           "</div>\n</div>\n";
        res->send(buildPage("Authenticator Help", body));
    });

    // ── GET /oauth2/authorize ─────────────────────────────────────────────────
    app.get("/oauth2/authorize", [] MIDDLEWARE(req, res, next) {
        const std::string clientId = req->query("client_id");
        const std::string redirectUri = req->query("redirect_uri");
        const std::string state = req->query("state");
        const std::string scope = req->query("scope");
        const std::string challenge = req->query("code_challenge");
        std::string method = req->query("code_challenge_method");

        if (!validateRedirectUri(redirectUri)) {
            res->status(400).send(errorPage("Invalid redirect_uri."));
            return;
        }
        if (challenge.empty()) {
            res->status(400).send(errorPage("PKCE required: code_challenge missing."));
            return;
        }
        if (method.empty()) {
            method = "S256";
        }
        if (method != "S256") {
            res->status(400).send(errorPage("Only S256 code_challenge_method is supported (RFC 7636)."));
            return;
        }
        res->redirect("/auth/login?client_id=" + httputils::url_encode(clientId) + 
                      "&redirect_uri=" + httputils::url_encode(redirectUri) + 
                      "&state=" + httputils::url_encode(state) +
                      "&scope=" + httputils::url_encode(scope) + 
                      "&code_challenge=" + httputils::url_encode(challenge) + 
                      "&code_challenge_method=" + httputils::url_encode(method));
    });

    // ── OPTIONS /oauth2/token (CORS preflight) ────────────────────────────────
    app.options("/oauth2/token", [] MIDDLEWARE(req, res, next) {
        res->set("Access-Control-Allow-Origin", "*")
            .set("Access-Control-Allow-Methods", "POST,OPTIONS")
            .set("Access-Control-Allow-Headers", "Content-Type")
            .status(200)
            .send("");
    });

    // ── POST /oauth2/token ────────────────────────────────────────────────────
    app.post("/oauth2/token", [&jwtSigner] MIDDLEWARE(req, res, next) {
        res->set("Access-Control-Allow-Origin", "*");
        auto p = parseBody(req->body);
        if (p["grant_type"] != "authorization_code") {
            res->status(400).set("Content-Type", "application/json").send("{\"error\":\"unsupported_grant_type\"}");
            return;
        }
        const std::string code = p["code"], clientId = p["client_id"], redirectUri = p["redirect_uri"], codeVerifier = p["code_verifier"];
        if (code.empty() || clientId.empty() || codeVerifier.empty()) {
            res->status(400).set("Content-Type", "application/json").send("{\"error\":\"invalid_request\"}");
            return;
        }
        // Fetch auth code
        struct CodeRow {
            std::string userId, scope, challenge, method;
            bool mfaVerified = false;
            bool expired = false;
        } cr;
        bool found = false;
        g_db->query("SELECT user_id,scope,code_challenge,code_challenge_method,mfa_verified,"
                    " (expires_at <= datetime('now')) AS is_expired"
                    " FROM auth_code WHERE code=? AND client_id=?",
                    {code, clientId},
                    [&](const SqliteDatabase::Row& r) {
                        found = true;
                        cr.userId = r.get(0);
                        cr.scope = r.get(1);
                        cr.challenge = r.get(2);
                        cr.method = r.get(3);
                        cr.mfaVerified = (r.get(4) == "1");
                        cr.expired = (r.get(5) == "1");
                    });
        if (!found || cr.expired) {
            res->status(400).set("Content-Type", "application/json").send("{\"error\":\"invalid_grant\"}");
            return;
        }
        if (!verifyPkce(codeVerifier, cr.challenge, cr.method)) {
            res->status(400)
                .set("Content-Type", "application/json")
                .send("{\"error\":\"invalid_grant\","
                      "\"error_description\":\"PKCE verification failed\"}");
            return;
        }
        // Fetch username and email
        std::string username;
        std::string email;
        g_db->query("SELECT username, email FROM user WHERE id=?", {cr.userId}, [&](const SqliteDatabase::Row& r) {
            username = r.get(0);
            email = r.get(1);
        });
        if (username.empty()) {
            res->status(500).set("Content-Type", "application/json").send("{\"error\":\"server_error\"}");
            return;
        }
        // Delete used auth code (single-use)
        g_db->exec("DELETE FROM auth_code WHERE code=?", {code});

        // Build JWT
        JwtClaims claims;
        claims.issuer = g_issuer;
        claims.subject = cr.userId;
        claims.audience = clientId;
        claims.expiresAt = std::chrono::system_clock::from_time_t(std::time(nullptr) + 3600);
        claims.username = username;
        claims.email = email;
        claims.mfaVerified = cr.mfaVerified;
        std::istringstream ss(cr.scope);
        std::string item;
        while (std::getline(ss, item, ' ')) {
            if (!item.empty()) {
                claims.scopes.push_back(item);
            }
        }
        const std::string token = jwtSigner.sign(claims);

        json resp;
        resp["access_token"] = token;
        resp["token_type"] = "Bearer";
        resp["expires_in"] = 3600;
        resp["id_token"] = token;
        res->set("Content-Type", "application/json").send(resp.dump());
    });

    // ── GET /health ───────────────────────────────────────────────────────────
    app.get("/health", [] APPLICATION(req, res) {
        json h;
        h["status"] = "ok";
        h["service"] = "snodec-idp";
        h["version"] = "2.0.0";
        res->set("Content-Type", "application/json").send(h.dump());
    });

    // ── GET /auth/federated/:provider ──── Social Login Redirect ──────────────
    app.get("/auth/federated/:provider", [] MIDDLEWARE(req, res, next) {
        if (g_federatedRegistry == nullptr) {
            res->status(404).send(errorPage("Federated login not available."));
            return;
        }
        std::string providerId = req->params["provider"];
        const auto* provider = g_federatedRegistry->getProvider(providerId);
        if (provider == nullptr || !provider->enabled) {
            res->status(404).send(errorPage("Unknown or disabled provider: " + providerId));
            return;
        }

        // Build callback URL at the IdP
        std::string callbackUrl = g_idpBaseUrl + "/auth/federated/" + providerId + "/callback";

        // Preserve original OAuth2 parameters in state so we can continue the flow
        std::string clientId = req->query("client_id");
        std::string redirectUri = req->query("redirect_uri");
        std::string originalState = req->query("state");
        std::string challenge = req->query("code_challenge");
        std::string method = req->query("code_challenge_method");
        std::string stateParam = clientId + "|" + redirectUri + "|" + originalState + "|" + challenge + "|" + method;

        // Redirect to external provider's authorization endpoint
        std::string authUrl = provider->authorizationUrl +
            "?client_id=" + provider->clientId +
            "&redirect_uri=" + httputils::url_encode(callbackUrl) +
            "&response_type=code" +
            "&scope=" + httputils::url_encode(provider->scope) +
            "&state=" + httputils::url_encode(stateParam);

        LOG(INFO) << "[Federated] Redirecting to " << provider->displayName << " for authentication";
        res->redirect(authUrl);
    });

    // ── GET /auth/federated/:provider/callback ──── Social Login Callback ─────
    app.get("/auth/federated/:provider/callback", [&finishLogin] MIDDLEWARE(req, res, next) {
        if (g_federatedRegistry == nullptr) {
            res->status(404).send(errorPage("Federated login not available."));
            return;
        }
        std::string providerId = req->params["provider"];
        const auto* provider = g_federatedRegistry->getProvider(providerId);
        if (provider == nullptr || !provider->enabled) {
            res->status(404).send(errorPage("Unknown or disabled provider."));
            return;
        }

        std::string code = req->query("code");
        std::string error = req->query("error");
        std::string stateParam = req->query("state");

        if (!error.empty()) {
            res->send(errorPage("Social login failed: " + error));
            return;
        }
        if (code.empty()) {
            res->send(errorPage("Missing authorization code from " + provider->displayName));
            return;
        }

        // Parse state to recover original OAuth2 parameters
        std::string clientId, redirectUri, originalState, challenge, method;
        {
            std::vector<std::string> parts;
            size_t start = 0;
            size_t end = stateParam.find('|');
            while (end != std::string::npos) {
                parts.push_back(stateParam.substr(start, end - start));
                start = end + 1;
                end = stateParam.find('|', start);
            }
            parts.push_back(stateParam.substr(start));

            if (parts.size() >= 3) {
                clientId = parts[0];
                redirectUri = parts[1];
                originalState = parts[2];
            }
            if (parts.size() >= 5) {
                challenge = parts[3];
                method = parts[4];
            }
        }

        // Perform real Google token exchange and userinfo fetch
        std::string targetEmail;
        std::string targetUsername;

        if (providerId == "google") {
            std::string tokenUrl = provider->tokenUrl;
            std::string userInfoUrl = provider->userInfoUrl;
            std::string callbackUrl = g_idpBaseUrl + "/auth/federated/" + providerId + "/callback";

            std::string tokenCmd = "curl -s -X POST " + escapeShellArg(tokenUrl) + " "
                                 + "--data-urlencode " + escapeShellArg("code=" + code) + " "
                                 + "--data-urlencode " + escapeShellArg("client_id=" + provider->clientId) + " "
                                 + "--data-urlencode " + escapeShellArg("client_secret=" + provider->clientSecret) + " "
                                 + "--data-urlencode " + escapeShellArg("redirect_uri=" + callbackUrl) + " "
                                 + "--data-urlencode " + escapeShellArg("grant_type=authorization_code");

            std::string tokenResp = execCommand(tokenCmd);
            LOG(INFO) << "[Federated] Token response: " << tokenResp;

            std::string accessToken;
            try {
                auto tokenJson = json::parse(tokenResp);
                if (tokenJson.contains("access_token")) {
                    accessToken = tokenJson["access_token"].get<std::string>();
                } else if (tokenJson.contains("error_description")) {
                    res->send(errorPage("Google token exchange failed: " + tokenJson["error_description"].get<std::string>()));
                    return;
                } else {
                    res->send(errorPage("Google token exchange failed: response missing access_token. Raw: " + tokenResp));
                    return;
                }
            } catch (const std::exception& e) {
                res->send(errorPage("Failed to parse Google token response: " + std::string(e.what()) + ". Raw: " + tokenResp));
                return;
            }

            std::string userInfoCmd = "curl -s -H " + escapeShellArg("Authorization: Bearer " + accessToken) + " "
                                    + escapeShellArg(userInfoUrl);
            std::string userInfoResp = execCommand(userInfoCmd);
            LOG(INFO) << "[Federated] Userinfo response: " << userInfoResp;

            try {
                auto userJson = json::parse(userInfoResp);
                if (userJson.contains("email")) {
                    targetEmail = userJson["email"].get<std::string>();
                }
                if (userJson.contains("name")) {
                    targetUsername = userJson["name"].get<std::string>();
                } else if (userJson.contains("given_name")) {
                    targetUsername = userJson["given_name"].get<std::string>();
                }
            } catch (const std::exception& e) {
                res->send(errorPage("Failed to parse Google userinfo response: " + std::string(e.what()) + ". Raw: " + userInfoResp));
                return;
            }

            if (targetEmail.empty()) {
                res->send(errorPage("Google login failed: user email not provided by Google. Raw: " + userInfoResp));
                return;
            }
            if (targetUsername.empty()) {
                targetUsername = targetEmail;
            }
        } else {
            // Fallback for Meta or Apple (which aren't fully configured/implemented here)
            targetEmail = providerId + "-user@" + providerId + ".example.com";
            targetUsername = providerId + "_user";
        }

        // Check if federated user already exists
        std::string userId;
        std::string finalUsername;
        bool totpEnabled = false;

        g_db->query("SELECT id, username, totp_enabled FROM user WHERE email=?", {targetEmail}, [&](const SqliteDatabase::Row& r) {
            userId = r.get(0);
            finalUsername = r.get(1);
            totpEnabled = (r.get(2) == "1");
        });

        if (userId.empty()) {
            // Uniqueness check for username
            finalUsername = targetUsername;
            bool usernameExists = true;
            int suffix = 1;
            while (usernameExists) {
                usernameExists = false;
                g_db->query("SELECT id FROM user WHERE username=?", {finalUsername}, [&](const SqliteDatabase::Row& r) {
                    usernameExists = true;
                });
                if (usernameExists) {
                    finalUsername = targetUsername + std::to_string(suffix++);
                }
            }

            // Create linked account
            std::string hash = hashPasswordPbkdf2(generateRandomString(32));
            std::string err;
            if (!g_db->exec("INSERT INTO user(username,email,password_hash,password_salt) VALUES(?,?,?,'')",
                       {finalUsername, targetEmail, hash}, &err)) {
                res->status(500).send(errorPage("Failed to create user account: " + err));
                return;
            }
            userId = std::to_string(g_db->lastInsertRowid());
            LOG(INFO) << "[Federated] Created local account for " << provider->displayName << " user: " << finalUsername << " (" << targetEmail << ")";
        } else {
            // User exists. Check if they have a placeholder username (e.g. google_user, google user, user_*)
            auto isPlaceholder = [](const std::string& name) {
                if (name == "google_user" || name == "google user") return true;
                if (name.rfind("user_", 0) == 0) return true;
                if (name.rfind("google_", 0) == 0) return true;
                return false;
            };

            if (isPlaceholder(finalUsername) && finalUsername != targetUsername && !targetUsername.empty()) {
                // Check if targetUsername is already taken by a different user
                std::string resolvedUsername = targetUsername;
                bool usernameExists = true;
                int suffix = 1;
                while (usernameExists) {
                    usernameExists = false;
                    g_db->query("SELECT id FROM user WHERE username=? AND id != ?", {resolvedUsername, userId}, [&](const SqliteDatabase::Row& r) {
                        usernameExists = true;
                    });
                    if (usernameExists) {
                        resolvedUsername = targetUsername + std::to_string(suffix++);
                    }
                }

                // Update username in db
                std::string err;
                if (g_db->exec("UPDATE user SET username=? WHERE id=?", {resolvedUsername, userId}, &err)) {
                    LOG(INFO) << "[Federated] Updated placeholder username for user ID " << userId << " from '" << finalUsername << "' to '" << resolvedUsername << "'";
                    finalUsername = resolvedUsername;
                } else {
                    LOG(ERROR) << "[Federated] Failed to update placeholder username: " << err;
                }
            }
        }

        LOG(INFO) << "[Federated] " << provider->displayName << " login successful for user: " << finalUsername << " (" << targetEmail << ")";

        if (totpEnabled) {
            res->send(mfaPage("", userId, clientId, redirectUri, originalState, "openid profile", challenge, method));
        } else {
            finishLogin(res, userId, finalUsername, clientId, redirectUri, originalState,
                        "openid profile", challenge, method, false);
        }
    });

    // ── Start server ──────────────────────────────────────────────────────────
    app.listen(port, [port](const express::legacy::in::WebApp::SocketAddress& addr, const core::socket::State& st) {
        if (st == core::socket::State::OK) {
            VLOG(0) << "IdP Server listening on port " << port;
        } else {
            LOG(ERROR) << "IdP Server failed to start: " << addr.toString();
        }
    });

    return core::SNodeC::start();
}
