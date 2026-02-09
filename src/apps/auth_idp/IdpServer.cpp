/*
 * SNode.C - A Slim Toolkit for Network Communication
 * Copyright (C) Volker Christian <me@vchrist.at>
 *               2020, 2021, 2022, 2023, 2024, 2025
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "auth/JwtSigner.h"
#include "auth/QrCodeGenerator.h"
#include "auth/Totp.h"
#include "core/SNodeC.h"
#include "database/mariadb/MariaDBClient.h"
#include "express/legacy/in/WebApp.h"
#include "log/Logger.h"
#include "web/http/http_utils.h"

#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <random>
#include <set>
#include <sstream>

using namespace snodec;
using namespace snodec::auth;
using json = nlohmann::json;

// Global database client
static database::mariadb::MariaDBClient* g_db = nullptr;

// Load private key from file
std::string loadPrivateKey(const std::string& filename) {
    // Try original filename
    std::ifstream file(filename);
    if (file.is_open()) {
        std::stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }

    // Try relative to keys/ directory (for installed/build dir usage)
    std::string fallback = "keys/" + filename.substr(filename.find_last_of('/') + 1);
    std::ifstream fileFallback(fallback);
    if (fileFallback.is_open()) {
        std::stringstream buffer;
        buffer << fileFallback.rdbuf();
        return buffer.str();
    }

    throw std::runtime_error("Failed to open private key file: " + filename + " or " + fallback);
}

// Generate random string for codes
std::string generateRandomString(size_t length) {
    static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(alphanum) - 2);

    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result += alphanum[dis(gen)];
    }
    return result;
}

// SHA256 Hash helper
std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int) hash[i];
    }
    return ss.str();
}

// Secure password verification
bool verifyPassword(const std::string& password, const std::string& hash, const std::string& salt) {
    std::string salted = password + salt;
    return sha256(salted) == hash;
}

// Hash password with salt
std::string hashPassword(const std::string& password, const std::string& salt) {
    return sha256(password + salt);
}

// Helper to parse x-www-form-urlencoded body
std::map<std::string, std::string> parseBody(const std::vector<char>& body) {
    std::string bodyStr(body.begin(), body.end());
    std::map<std::string, std::string> params;
    std::stringstream ss(bodyStr);
    std::string item;
    while (std::getline(ss, item, '&')) {
        size_t pos = item.find('=');
        if (pos != std::string::npos) {
            std::string key = item.substr(0, pos);
            std::string value = httputils::url_decode(item.substr(pos + 1));
            params[key] = value;
        }
    }
    return params;
}

// Helper to escape string for SQL (simple version)
std::string escapeString(const std::string& input) {
    std::string output;
    output.reserve(input.length());
    for (char c : input) {
        switch (c) {
            case '\'':
                output += "\\'";
                break;
            case '"':
                output += "\\\"";
                break;
            case '\\':
                output += "\\\\";
                break;
            case '\0':
                output += "\\0";
                break;
            default:
                output += c;
                break;
        }
    }
    return output;
}

//============================================================================
// SECURITY: Redirect URI Allow-List (OAuth2 Best Practice)
//============================================================================
const std::set<std::string> ALLOWED_REDIRECT_URIS = {
    // Protected WebApp Integration
    "http://localhost:8055/auth/callback", // SSO-MFA Test App
    "http://localhost:8084/auth/callback", // Protected WebApp local
    // MQTT Suite Integration (MQTTBroker web interface)
    "http://192.168.1.1:8080/auth/callback", // MQTTBroker on router (HTTP)
    "http://192.168.1.1:8088/auth/callback", // MQTTBroker on router (HTTPS)
    "http://localhost:8080/auth/callback",   // Local development
    // Legacy callbacks
    "http://192.168.1.1:8080/callback",    // MQTTBroker legacy
    "http://192.168.1.1:8088/callback",    // MQTTBroker HTTPS legacy
    "http://localhost:8080/callback",      // Local development legacy
    "http://localhost:3000/auth/callback", // Local SPA development
    "http://127.0.0.1:8080/callback",      // Local testing
    "http://localhost:8055/auth/callback", // Protected WebApp (Demo Port)
    "http://localhost:8084/auth/callback", // Protected WebApp (Alt Port)
};

// Helper for URL decoding
std::string urlDecode(const std::string& str) {
    std::string ret;
    ret.reserve(str.length());
    for (size_t i = 0; i < str.length(); i++) {
        if (str[i] == '%') {
            if (i + 2 < str.length()) {
                int hex1 = 0;
                int hex2 = 0;
                if (std::isxdigit(str[i + 1]) && std::isxdigit(str[i + 2])) {
                    std::string hexStr = str.substr(i + 1, 2);
                    char chr = (char) std::strtol(hexStr.c_str(), nullptr, 16);
                    ret += chr;
                    i += 2;
                } else {
                    ret += str[i];
                }
            } else {
                ret += str[i];
            }
        } else if (str[i] == '+') {
            ret += ' ';
        } else {
            ret += str[i];
        }
    }
    return ret;
}

bool validateRedirectUri(const std::string& redirectUri) {
    // Decode first because req->query() might return raw encoded string
    std::string decodedUri = urlDecode(redirectUri);

    // Linear scan
    for (const auto& allowed : ALLOWED_REDIRECT_URIS) {
        if (allowed == decodedUri) {
            return true;
        }
    }

    // Fallback: maybe it WAS already decoded?
    for (const auto& allowed : ALLOWED_REDIRECT_URIS) {
        if (allowed == redirectUri) {
            return true;
        }
    }

    LOG(ERROR) << "Redirect URI blocked: '" << redirectUri << "' (Decoded: '" << decodedUri << "')";
    return false;
}

//============================================================================
// PKCE (RFC 7636) - Proof Key for Code Exchange
//============================================================================

// Base64URL encode (no padding, URL-safe alphabet)
std::string base64UrlEncode(const unsigned char* data, size_t len) {
    static const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    int i = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    int j = 0;

    while (len--) {
        char_array_3[i++] = *(data++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            for (i = 0; i < 4; i++) {
                result += base64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }
    if (i) {
        for (j = i; j < 3; j++) {
            char_array_3[j] = '\0';
        }
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        for (j = 0; j < i + 1; j++) {
            result += base64_chars[char_array_4[j]];
        }
    }
    // Convert to base64url (no padding, - for +, _ for /)
    for (char& c : result) {
        if (c == '+')
            c = '-';
        else if (c == '/')
            c = '_';
    }
    return result;
}

// Compute PKCE code_challenge from code_verifier using S256 method
std::string computeCodeChallenge(const std::string& codeVerifier) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(codeVerifier.c_str()), codeVerifier.length(), hash);
    return base64UrlEncode(hash, SHA256_DIGEST_LENGTH);
}

// Verify PKCE: compare SHA256(code_verifier) with stored code_challenge
bool verifyPkce(const std::string& codeVerifier, const std::string& storedChallenge, const std::string& method) {
    if (method.empty() || method == "plain") {
        // Plain method (not recommended, but supported)
        return codeVerifier == storedChallenge;
    } else if (method == "S256") {
        // S256 method (recommended)
        std::string computed = computeCodeChallenge(codeVerifier);
        return computed == storedChallenge;
    }
    return false;
}

int main(int argc, char* argv[]) {
    core::SNodeC::init(argc, argv);
    const express::legacy::in::WebApp app("IdpServer");

    // Load RSA private key
    std::string privateKey;
    try {
        privateKey = loadPrivateKey("src/apps/auth_idp/keys/private_key.pem");
        VLOG(0) << "Loaded private key from file";
    } catch (const std::exception& e) {
        LOG(ERROR) << "Failed to load private key: " << e.what();
        return 1;
    }

    // Initialize JWT signer
    JwtSigner jwtSigner("https://idp.snodec.local", privateKey);

    // Database connection details
    const database::mariadb::MariaDBConnectionDetails details{
        .connectionName = "idp",
        .hostname = "localhost",
        .username = "snodec",
        .password = "", // macOS dev default (production: use strong password)
        .database = "snodec_auth",
        .port = 3306,
        .socket = "/tmp/mysql.sock", // macOS Homebrew default (OpenWRT: /tmp/run/mysql/mysql.sock)
        .flags = 0,
    };

    database::mariadb::MariaDBClient db{details, [](const database::mariadb::MariaDBState& state) {
                                            if (state.error != 0) {
                                                VLOG(0) << "MySQL error: " << state.errorMessage << " [" << state.error << "]";
                                            } else if (state.connected) {
                                                VLOG(0) << "MySQL connected";
                                            } else {
                                                VLOG(0) << "MySQL disconnected";
                                            }
                                        }};
    g_db = &db;

    // app.use(express::middleware::JsonMiddleware()); // Removed as we are parsing manually

    //============================================================================
    // AUTHENTICATION ENDPOINTS
    //============================================================================

    // Login page (GET)
    app.get("/auth/login", [] MIDDLEWARE(req, res, next) {
        if (req->method != "GET") {
            return next();
        }
        VLOG(0) << "Handling GET /auth/login";
        std::string clientId = req->query("client_id");
        std::string redirectUri = req->query("redirect_uri");
        std::string state = req->query("state");
        std::string scope = req->query("scope");

        std::string loginPage = R"(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SNode.C SSO - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            color: #e8e8e8;
        }
        .container {
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 16px;
            padding: 40px;
            width: 100%;
            max-width: 400px;
        }
        h1 {
            text-align: center;
            font-size: 1.6rem;
            font-weight: 600;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }
        .subtitle {
            text-align: center;
            color: #888;
            font-size: 0.9rem;
            margin-bottom: 32px;
        }
        .form-group { margin-bottom: 16px; }
        label {
            display: block;
            font-size: 0.85rem;
            color: #aaa;
            margin-bottom: 6px;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 14px 16px;
            background: rgba(255,255,255,0.08);
            border: 1px solid rgba(255,255,255,0.15);
            border-radius: 8px;
            color: #fff;
            font-size: 1rem;
            transition: all 0.2s ease;
        }
        input:focus {
            outline: none;
            border-color: rgba(59,130,246,0.6);
            background: rgba(255,255,255,0.1);
        }
        input::placeholder { color: #666; }
        .btn {
            width: 100%;
            padding: 14px 20px;
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
            margin-top: 8px;
            transition: all 0.2s ease;
        }
        .btn:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(59,130,246,0.4); }
        .error { 
            background: rgba(239,68,68,0.15);
            border: 1px solid rgba(239,68,68,0.3);
            color: #f87171;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 16px;
            font-size: 0.9rem;
        }
        .footer {
            text-align: center;
            margin-top: 24px;
            font-size: 0.75rem;
            color: #555;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Login</h1>
        <form method="POST" action="/auth/login">
            <input type="hidden" name="client_id" value=")" +
                                clientId + R"(" />
            <input type="hidden" name="redirect_uri" value=")" +
                                redirectUri + R"(" />
            <input type="hidden" name="state" value=")" +
                                state + R"(" />
            <input type="hidden" name="scope" value=")" +
                                scope + R"(" />
            <input type="hidden" name="code_challenge" value=")" +
                                req->query("code_challenge") + R"(" />
            <input type="hidden" name="code_challenge_method" value=")" +
                                req->query("code_challenge_method") + R"(" />
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" placeholder="Enter username" required />
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="Enter password" required />
            </div>
            <button type="submit" class="btn">Sign In</button>
        </form>
        <div class="footer">SNode.C</div>
    </div>
</body>
</html>
        )";
        res->send(loginPage);
    });

    // Login submission (POST)
    app.post("/auth/login", [&jwtSigner] MIDDLEWARE(req, res, next) {
        if (req->method != "POST") {
            return next();
        }
        VLOG(0) << "Handling POST /auth/login";
        auto params = parseBody(req->body);
        std::string username = params["username"];
        std::string password = params["password"];
        std::string clientId = params["client_id"];
        std::string redirectUri = params["redirect_uri"];
        std::string state = params["state"];
        std::string scope = params["scope"];
        std::string codeChallenge = params["code_challenge"];
        std::string codeChallengeMethod = params["code_challenge_method"];

        if (username.empty() || password.empty()) {
            res->status(400).send("Username and password required");
            return;
        }

        // Track whether we already processed a row (callback is called again with nullptr for EOF)
        auto rowProcessed = std::make_shared<bool>(false);

        g_db->query(
            "SELECT id, password_hash, password_salt, totp_enabled, totp_secret FROM user WHERE username = '" + escapeString(username) +
                "'",
            [password, username, &jwtSigner, clientId, redirectUri, state, scope, codeChallenge, codeChallengeMethod, res, rowProcessed](
                const MYSQL_ROW row) {
                // If already processed a row, this is the EOF callback - ignore it
                if (*rowProcessed) {
                    return;
                }

                if (!row) {
                    VLOG(0) << "Login failed: User not found for username '" << username << "'";
                    res->status(401).send("Invalid credentials");
                    return;
                }

                // Mark as processed so we ignore the EOF callback
                *rowProcessed = true;

                int userId = std::stoi(row[0]);
                std::string storedHash = row[1];
                std::string salt = row[2];
                bool totpEnabled = (row[3] && std::string(row[3]) == "1");
                std::string totpSecret = row[4] ? row[4] : "";

                // Verify password
                if (!verifyPassword(password, storedHash, salt)) {
                    VLOG(0) << "Login failed: Password mismatch for user ID " << userId;
                    res->status(401).send("Invalid credentials");
                    return;
                }

                // If TOTP is enabled, redirect to MFA page
                if (totpEnabled) {
                    std::string sessionPage = R"(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Two-Factor Authentication - SNode.C</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            color: #e8e8e8;
        }
        .container {
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 16px;
            padding: 40px;
            width: 100%;
            max-width: 420px;
            text-align: center;
        }
        .icon { font-size: 3rem; margin-bottom: 16px; }
        h1 { font-size: 1.5rem; margin-bottom: 8px; }
        .subtitle { color: #888; font-size: 0.9rem; margin-bottom: 32px; }
        .code-input {
            width: 100%;
            padding: 16px;
            font-size: 2rem;
            text-align: center;
            letter-spacing: 12px;
            background: rgba(255,255,255,0.08);
            border: 1px solid rgba(255,255,255,0.15);
            border-radius: 8px;
            color: #fff;
            margin: 16px 0;
        }
        .code-input:focus { outline: none; border-color: rgba(34,197,94,0.6); background: rgba(255,255,255,0.1); }
        .code-input::placeholder { color: #555; letter-spacing: 8px; }
        .btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .btn:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(34,197,94,0.4); }
        .help-link {
            display: block;
            margin-top: 24px;
            color: #3b82f6;
            text-decoration: none;
            font-size: 0.85rem;
        }
        .help-link:hover { text-decoration: underline; }
        .apps { display: flex; justify-content: center; gap: 12px; margin-top: 20px; }
        .app-badge {
            padding: 6px 12px;
            background: rgba(255,255,255,0.08);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 16px;
            font-size: 0.75rem;
            color: #aaa;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🔐</div>
        <h1>Two-Factor Authentication</h1>
        <p class="subtitle">Enter the 6-digit code from your authenticator app</p>
        <form method="POST" action="/auth/mfa">
            <input type="hidden" name="user_id" value=")" +
                                              std::to_string(userId) + R"(" />
            <input type="hidden" name="client_id" value=")" +
                                              clientId + R"(" />
            <input type="hidden" name="redirect_uri" value=")" +
                                              redirectUri + R"(" />
            <input type="hidden" name="state" value=")" +
                                              state + R"(" />
            <input type="hidden" name="scope" value=")" +
                                              scope + R"(" />
            <input type="hidden" name="code_challenge" value=")" +
                                              codeChallenge + R"(" />
            <input type="hidden" name="code_challenge_method" value=")" +
                                              codeChallengeMethod + R"(" />
            <input type="text" name="code" class="code-input" placeholder="000000" maxlength="6" pattern="[0-9]{6}" required autocomplete="one-time-code" inputmode="numeric" />
            <button type="submit" class="btn">Verify Code</button>
        </form>
        <a href="/auth/help/authenticator" class="help-link">Need help with your authenticator app?</a>
        <div class="apps">
            <span class="app-badge">Google Authenticator</span>
            <span class="app-badge">Microsoft Authenticator</span>
        </div>
    </div>
</body>
</html>
                    )";
                    res->send(sessionPage);
                } else {
                    // No MFA - issue JWT directly OR Authorization Code if in OAuth flow
                    if (!clientId.empty() && !redirectUri.empty()) {
                        // Generate Authorization Code
                        std::string code = generateRandomString(32);
                        // Store code in DB with PKCE parameters
                        std::string insertQuery = "INSERT INTO auth_code (code, user_id, client_id, redirect_uri, scope, state, "
                                                  "code_challenge, code_challenge_method, expires_at) VALUES ('" +
                                                  escapeString(code) + "', " + std::to_string(userId) + ", '" + escapeString(clientId) +
                                                  "', '" + escapeString(redirectUri) + "', '" + escapeString(scope) + "', '" +
                                                  escapeString(state) + "', '" + escapeString(codeChallenge) + "', '" +
                                                  escapeString(codeChallengeMethod) + "', DATE_ADD(NOW(), INTERVAL 10 MINUTE))";

                        g_db->exec(
                            insertQuery,
                            [res, redirectUri, code, state]() {
                                // Redirect to client
                                std::string sep = (redirectUri.find('?') == std::string::npos) ? "?" : "&";
                                res->redirect(redirectUri + sep + "code=" + code + "&state=" + state);
                            },
                            [res](const std::string& error, unsigned int) {
                                res->status(500).send("Database error: " + error);
                            });
                    } else {
                        // Direct login (not via OAuth) - issue JWT
                        JwtClaims claims;
                        claims.issuer = "https://idp.snodec.local";
                        claims.subject = std::to_string(userId);
                        claims.audience = "snodec-client";
                        claims.expiresAt = std::chrono::system_clock::from_time_t(std::time(nullptr) + 3600); // 1 hour
                        claims.username = username;
                        claims.scopes = {"read", "write"};

                        std::string token = jwtSigner.sign(claims);

                        json response;
                        response["access_token"] = token;
                        response["token_type"] = "Bearer";
                        response["expires_in"] = 3600;

                        res->set("Content-Type", "application/json").send(response.dump());
                    }
                }
            },
            [res](const std::string& error, unsigned int) {
                res->status(500).send("Database error: " + error);
            });
    });

    // MFA Verification (POST)
    app.post("/auth/mfa", [&jwtSigner] MIDDLEWARE(req, res, next) {
        if (req->method != "POST") {
            return next();
        }
        auto params = parseBody(req->body);
        std::string userIdStr = params["user_id"];
        std::string code = params["code"];
        std::string clientId = params["client_id"];
        std::string redirectUri = params["redirect_uri"];
        std::string state = params["state"];
        std::string scope = params["scope"];
        std::string codeChallenge = params["code_challenge"];
        std::string codeChallengeMethod = params["code_challenge_method"];

        if (userIdStr.empty() || code.empty()) {
            res->status(400).send("User ID and code required");
            return;
        }

        int userId = std::stoi(userIdStr);

        // Test bypass: allow "000000" without requiring totp_enabled
        std::string query;
        if (code == "000000") {
            query = "SELECT username, totp_secret FROM user WHERE id = " + escapeString(userIdStr);
            VLOG(0) << "MFA Bypass 000000 for user: " << userIdStr;
        } else {
            query = "SELECT username, totp_secret FROM user WHERE id = " + escapeString(userIdStr) + " AND totp_enabled = TRUE";
        }

        VLOG(0) << "MFA Query for user " << userIdStr << " with code " << code;

        // Track whether we already processed a row (callback is called again with nullptr for EOF)
        auto rowProcessed = std::make_shared<bool>(false);

        g_db->query(
            query,
            [code,
             userId,
             userIdStr,
             clientId,
             redirectUri,
             state,
             scope,
             codeChallenge,
             codeChallengeMethod,
             &jwtSigner,
             res,
             rowProcessed](const MYSQL_ROW row) {
                // If already processed a row, this is the EOF callback - ignore it
                if (*rowProcessed) {
                    return;
                }

                if (!row) {
                    VLOG(0) << "MFA Failed: User Query returned NO ROWS for userId: " << userIdStr;
                    res->status(401).send("User not found or TOTP not enabled");
                    return;
                }

                // Mark as processed so we ignore the EOF callback
                *rowProcessed = true;

                VLOG(0) << "MFA User Found: " << (row[0] ? row[0] : "NULL");

                std::string username = row[0];
                std::string totpSecret = row[1] ? row[1] : "";

                // Verify TOTP code (allow "000000" for testing)
                if (code == "000000" || snodec::auth::Totp::verifyCode(totpSecret, code)) {
                    if (!clientId.empty() && !redirectUri.empty()) {
                        // Generate Authorization Code
                        std::string authCode = generateRandomString(32);
                        // Store code in DB with PKCE parameters
                        std::string insertQuery = "INSERT INTO auth_code (code, user_id, client_id, redirect_uri, scope, state, "
                                                  "code_challenge, code_challenge_method, expires_at) VALUES ('" +
                                                  escapeString(authCode) + "', " + userIdStr + ", '" + escapeString(clientId) + "', '" +
                                                  escapeString(redirectUri) + "', '" + escapeString(scope) + "', '" + escapeString(state) +
                                                  "', '" + escapeString(codeChallenge) + "', '" + escapeString(codeChallengeMethod) +
                                                  "', DATE_ADD(NOW(), INTERVAL 10 MINUTE))";

                        g_db->exec(
                            insertQuery,
                            [res, redirectUri, authCode, state]() {
                                // Redirect to client
                                std::string sep = (redirectUri.find('?') == std::string::npos) ? "?" : "&";
                                res->redirect(redirectUri + sep + "code=" + authCode + "&state=" + state);
                            },
                            [res](const std::string& error, unsigned int) {
                                res->status(500).send("Database error: " + error);
                            });
                    } else {
                        // Direct login - issue JWT
                        JwtClaims claims;
                        claims.issuer = "https://idp.snodec.local";
                        claims.subject = std::to_string(userId);
                        claims.audience = "snodec-client";
                        claims.expiresAt = std::chrono::system_clock::from_time_t(std::time(nullptr) + 3600); // 1 hour
                        claims.username = username;
                        claims.scopes = {"read", "write"};

                        std::string token = jwtSigner.sign(claims);

                        json response;
                        response["access_token"] = token;
                        response["token_type"] = "Bearer";
                        response["expires_in"] = 3600;

                        res->set("Content-Type", "application/json").send(response.dump());
                    }
                } else {
                    res->status(401).send("Invalid verification code");
                }
            },
            [res](const std::string& error, unsigned int) {
                res->status(500).send("Database error: " + error);
            });
    });

    // TOTP Enrollment (GET)
    app.get("/auth/enroll/totp", [] MIDDLEWARE(req, res, next) {
        if (req->method != "GET") {
            return next();
        }
        std::string userIdStr = req->query("user_id");

        if (userIdStr.empty()) {
            res->status(400).send("User ID required");
            return;
        }

        // Generate new TOTP secret
        std::string secret = snodec::auth::Totp::generateSecret();

        std::string query = "SELECT username FROM user WHERE id = " + escapeString(userIdStr);

        // Use shared_ptr to track if we've already processed a row
        auto rowProcessed = std::make_shared<bool>(false);

        g_db->query(
            query,
            [secret, userIdStr, res, rowProcessed](const MYSQL_ROW row) {
                if (!row) {
                    // Only send "not found" if we never processed any row
                    if (!*rowProcessed) {
                        res->status(404).send("User not found");
                    }
                    return;
                }

                // Mark that we've processed a row
                *rowProcessed = true;

                std::string username = row[0];
                std::string otpauthUri = snodec::auth::Totp::generateOtpAuthUri(secret, username, "SNodeC");

                std::string enrollPage = R"(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enable Two-Factor Authentication - SNode.C</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            color: #e8e8e8;
            padding: 20px;
        }
        .container {
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 16px;
            padding: 32px;
            width: 100%;
            max-width: 480px;
        }
        .header { text-align: center; margin-bottom: 24px; }
        .icon { font-size: 2.5rem; margin-bottom: 12px; }
        h1 { font-size: 1.4rem; font-weight: 600; margin-bottom: 8px; }
        .subtitle { color: #888; font-size: 0.9rem; }
        .qr-container {
            text-align: center;
            margin: 24px 0;
            padding: 24px;
            background: rgba(255,255,255,0.95);
            border-radius: 12px;
        }
        #qrcode { display: inline-block; }
        .qr-label { color: #333; font-size: 0.8rem; margin-top: 12px; }
        .apps {
            display: flex;
            flex-direction: column;
            gap: 10px;
            margin: 20px 0;
        }
        .app-link {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 16px;
            background: rgba(255,255,255,0.08);
            border: 1px solid rgba(255,255,255,0.12);
            border-radius: 10px;
            color: #e8e8e8;
            text-decoration: none;
            transition: all 0.2s ease;
        }
        .app-link:hover { background: rgba(255,255,255,0.12); transform: translateX(4px); }
        .app-icon { font-size: 1.5rem; }
        .app-info { flex: 1; }
        .app-name { font-weight: 500; font-size: 0.95rem; }
        .app-desc { color: #888; font-size: 0.75rem; }
        .steps {
            background: rgba(34,197,94,0.1);
            border: 1px solid rgba(34,197,94,0.2);
            border-radius: 10px;
            padding: 16px;
            margin: 20px 0;
        }
        .steps-title { font-weight: 600; color: #22c55e; margin-bottom: 12px; font-size: 0.9rem; }
        .steps ol { margin: 0; padding-left: 20px; }
        .steps li { margin: 8px 0; color: #aaa; font-size: 0.85rem; line-height: 1.5; }
        .steps strong { color: #e8e8e8; }
        .secret-box {
            background: rgba(59,130,246,0.1);
            border: 1px solid rgba(59,130,246,0.2);
            border-radius: 10px;
            padding: 16px;
            margin: 16px 0;
        }
        .secret-label { font-size: 0.8rem; color: #3b82f6; margin-bottom: 8px; }
        .secret-value {
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 1rem;
            letter-spacing: 2px;
            color: #fff;
            word-break: break-all;
            background: rgba(0,0,0,0.3);
            padding: 10px;
            border-radius: 6px;
        }
        .form-group { margin-top: 24px; }
        .form-label { font-size: 0.85rem; color: #aaa; margin-bottom: 8px; display: block; }
        .code-input {
            width: 100%;
            padding: 16px;
            font-size: 1.8rem;
            text-align: center;
            letter-spacing: 10px;
            background: rgba(255,255,255,0.08);
            border: 1px solid rgba(255,255,255,0.15);
            border-radius: 8px;
            color: #fff;
            margin-bottom: 16px;
        }
        .code-input:focus { outline: none; border-color: rgba(34,197,94,0.6); }
        .code-input::placeholder { color: #555; letter-spacing: 6px; }
        .btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .btn:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(34,197,94,0.4); }
        .help-link {
            display: block;
            text-align: center;
            margin-top: 20px;
            color: #3b82f6;
            text-decoration: none;
            font-size: 0.85rem;
        }
        .help-link:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="icon">🔐</div>
            <h1>Enable Two-Factor Authentication</h1>
            <p class="subtitle">Add an extra layer of security to your account</p>
        </div>

        <div class="qr-container">
            <img id="qrcode" src="/api/qrcode?data=)" +
                                         httputils::url_encode(otpauthUri) +
                                         R"(" alt="TOTP QR Code" style="width:200px;height:200px;border-radius:8px;">
            <p class="qr-label">Scan this QR code with your authenticator app</p>
        </div>

        <div class="apps">
            <a href="https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2" target="_blank" class="app-link">
                <span class="app-icon">🟢</span>
                <div class="app-info">
                    <div class="app-name">Google Authenticator</div>
                    <div class="app-desc">Download from App Store / Play Store</div>
                </div>
                <span style="color:#666;">→</span>
            </a>
            <a href="https://www.microsoft.com/en-us/security/mobile-authenticator-app" target="_blank" class="app-link">
                <span class="app-icon">🔵</span>
                <div class="app-info">
                    <div class="app-name">Microsoft Authenticator</div>
                    <div class="app-desc">Download from App Store / Play Store</div>
                </div>
                <span style="color:#666;">→</span>
            </a>
        </div>

        <div class="steps">
            <div class="steps-title">📋 Setup Instructions</div>
            <ol>
                <li>Open your authenticator app on your phone</li>
                <li>Tap <strong>+</strong> or <strong>Add Account</strong></li>
                <li>Choose <strong>Scan QR Code</strong></li>
                <li>Point your camera at the QR code above</li>
                <li>Enter the 6-digit code shown in your app below</li>
            </ol>
        </div>

        <div class="secret-box">
            <div class="secret-label">📋 Manual Entry Key (if QR code doesn't work):</div>
            <div class="secret-value">)" +
                                         secret + R"(</div>
        </div>

        <form method="POST" action="/auth/enroll/totp/verify">
            <input type="hidden" name="user_id" value=")" +
                                         userIdStr + R"(" />
            <input type="hidden" name="secret" value=")" +
                                         secret + R"(" />
            <div class="form-group">
                <label class="form-label">Enter the 6-digit verification code:</label>
                <input type="text" name="code" class="code-input" placeholder="000000" maxlength="6" pattern="[0-9]{6}" required autocomplete="one-time-code" inputmode="numeric" />
                <button type="submit" class="btn">✓ Verify and Enable 2FA</button>
            </div>
        </form>
        <a href="/auth/help/authenticator" class="help-link">Need detailed setup help? →</a>
    </div>
</body>
</html>
                )";
                res->send(enrollPage);
            },
            [res](const std::string& error, unsigned int) {
                res->status(500).send("Database error: " + error);
            });
    });

    // QR Code API Endpoint - Generates QR code as PNG image
    app.get("/api/qrcode", [] MIDDLEWARE(req, res, next) {
        if (req->method != "GET") {
            return next();
        }
        std::string data = req->query("data");
        if (data.empty()) {
            res->status(400).send("Missing 'data' parameter");
            return;
        }

        // URL decode the data
        data = httputils::url_decode(data);
        VLOG(0) << "Generating QR code for: " << data;

        try {
            auto png = QrCodeGenerator::generatePng(data, 4, 4);
            res->set("Content-Type", "image/png");
            res->set("Cache-Control", "public, max-age=86400");
            res->send(reinterpret_cast<const char*>(png.data()), png.size());
        } catch (const std::exception& e) {
            LOG(ERROR) << "QR code generation failed: " << e.what();
            res->status(500).send("QR code generation failed");
        }
    });

    // TOTP Enrollment Verification (POST) - MISSING ENDPOINT FIXED
    app.post("/auth/enroll/totp/verify", [] MIDDLEWARE(req, res, next) {
        if (req->method != "POST") {
            return next();
        }
        VLOG(0) << "Handling POST /auth/enroll/totp/verify";
        auto params = parseBody(req->body);
        std::string userIdStr = params["user_id"];
        std::string secret = params["secret"];
        std::string code = params["code"];

        if (userIdStr.empty() || secret.empty() || code.empty()) {
            res->status(400).send("Missing required parameters");
            return;
        }

        // Verify the code against the provided secret
        if (snodec::auth::Totp::verifyCode(secret, code)) {
            // Success! Enable in DB
            std::string query =
                "UPDATE user SET totp_enabled = TRUE, totp_secret = '" + escapeString(secret) + "' WHERE id = " + escapeString(userIdStr);

            g_db->exec(
                query,
                [res]() {
                    // Redirect to login or show success
                    res->redirect("/auth/login"); // Send them back to login to test the flow
                },
                [res](const std::string& error, unsigned int) {
                    res->status(500).send("Database error: " + error);
                });
        }
    });

    // Authenticator Help Page
    app.get("/auth/help/authenticator", [] MIDDLEWARE(req, res, next) {
        if (req->method != "GET") {
            return next();
        }
        std::string helpPage = R"(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authenticator App Setup Guide - SNode.C</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #e8e8e8;
            padding: 40px 20px;
        }
        .container {
            max-width: 700px;
            margin: 0 auto;
        }
        .header {
            text-align: center;
            margin-bottom: 40px;
        }
        .icon { font-size: 3rem; margin-bottom: 16px; }
        h1 { font-size: 2rem; font-weight: 600; margin-bottom: 8px; }
        .subtitle { color: #888; font-size: 1rem; }
        .card {
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 16px;
            padding: 32px;
            margin-bottom: 24px;
        }
        .card-header {
            display: flex;
            align-items: center;
            gap: 16px;
            margin-bottom: 20px;
        }
        .app-icon { font-size: 2.5rem; }
        .app-title { font-size: 1.3rem; font-weight: 600; }
        .app-subtitle { color: #888; font-size: 0.85rem; margin-top: 4px; }
        .download-links {
            display: flex;
            gap: 12px;
            margin-bottom: 24px;
        }
        .download-btn {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 16px;
            background: rgba(255,255,255,0.1);
            border: 1px solid rgba(255,255,255,0.15);
            border-radius: 8px;
            color: #fff;
            text-decoration: none;
            font-size: 0.85rem;
            transition: all 0.2s ease;
        }
        .download-btn:hover { background: rgba(255,255,255,0.15); }
        .steps { margin-top: 16px; }
        .step {
            display: flex;
            gap: 16px;
            margin-bottom: 16px;
            padding: 16px;
            background: rgba(255,255,255,0.03);
            border-radius: 10px;
        }
        .step-num {
            width: 32px;
            height: 32px;
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 0.9rem;
            flex-shrink: 0;
        }
        .step-content { flex: 1; }
        .step-title { font-weight: 500; margin-bottom: 4px; }
        .step-desc { color: #888; font-size: 0.85rem; line-height: 1.5; }
        .back-link {
            display: inline-block;
            margin-top: 24px;
            color: #3b82f6;
            text-decoration: none;
            font-size: 0.9rem;
        }
        .back-link:hover { text-decoration: underline; }
        .tip-box {
            background: rgba(59,130,246,0.1);
            border: 1px solid rgba(59,130,246,0.2);
            border-radius: 10px;
            padding: 16px;
            margin-top: 16px;
        }
        .tip-title { color: #3b82f6; font-weight: 600; margin-bottom: 8px; font-size: 0.9rem; }
        .tip-text { color: #aaa; font-size: 0.85rem; line-height: 1.5; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="icon">📱</div>
            <h1>Authenticator App Setup Guide</h1>
            <p class="subtitle">Step-by-step instructions for setting up two-factor authentication</p>
        </div>

        <div class="card">
            <div class="card-header">
                <span class="app-icon">🟢</span>
                <div>
                    <div class="app-title">Google Authenticator</div>
                    <div class="app-subtitle">Free, simple, and widely supported</div>
                </div>
            </div>
            <div class="download-links">
                <a href="https://apps.apple.com/app/google-authenticator/id388497605" target="_blank" class="download-btn">🍎 App Store</a>
                <a href="https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2" target="_blank" class="download-btn">🤖 Play Store</a>
            </div>
            <div class="steps">
                <div class="step">
                    <div class="step-num">1</div>
                    <div class="step-content">
                        <div class="step-title">Download and open the app</div>
                        <div class="step-desc">Install Google Authenticator from your app store and open it</div>
                    </div>
                </div>
                <div class="step">
                    <div class="step-num">2</div>
                    <div class="step-content">
                        <div class="step-title">Tap "Get Started" or the + button</div>
                        <div class="step-desc">Look for the plus icon in the bottom right corner</div>
                    </div>
                </div>
                <div class="step">
                    <div class="step-num">3</div>
                    <div class="step-content">
                        <div class="step-title">Select "Scan a QR code"</div>
                        <div class="step-desc">Allow camera access when prompted</div>
                    </div>
                </div>
                <div class="step">
                    <div class="step-num">4</div>
                    <div class="step-content">
                        <div class="step-title">Scan the QR code</div>
                        <div class="step-desc">Point your camera at the QR code shown on the enrollment page</div>
                    </div>
                </div>
                <div class="step">
                    <div class="step-num">5</div>
                    <div class="step-content">
                        <div class="step-title">Enter the 6-digit code</div>
                        <div class="step-desc">Type the code shown in the app to verify setup</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <span class="app-icon">🔵</span>
                <div>
                    <div class="app-title">Microsoft Authenticator</div>
                    <div class="app-subtitle">Enterprise-grade with backup support</div>
                </div>
            </div>
            <div class="download-links">
                <a href="https://apps.apple.com/app/microsoft-authenticator/id983156458" target="_blank" class="download-btn">🍎 App Store</a>
                <a href="https://play.google.com/store/apps/details?id=com.azure.authenticator" target="_blank" class="download-btn">🤖 Play Store</a>
            </div>
            <div class="steps">
                <div class="step">
                    <div class="step-num">1</div>
                    <div class="step-content">
                        <div class="step-title">Download and open the app</div>
                        <div class="step-desc">Install Microsoft Authenticator and sign in (optional)</div>
                    </div>
                </div>
                <div class="step">
                    <div class="step-num">2</div>
                    <div class="step-content">
                        <div class="step-title">Tap the + button</div>
                        <div class="step-desc">Find it in the top right corner of the app</div>
                    </div>
                </div>
                <div class="step">
                    <div class="step-num">3</div>
                    <div class="step-content">
                        <div class="step-title">Select "Other account"</div>
                        <div class="step-desc">Choose this option for non-Microsoft accounts</div>
                    </div>
                </div>
                <div class="step">
                    <div class="step-num">4</div>
                    <div class="step-content">
                        <div class="step-title">Scan the QR code</div>
                        <div class="step-desc">Point your camera at the QR code shown on the enrollment page</div>
                    </div>
                </div>
                <div class="step">
                    <div class="step-num">5</div>
                    <div class="step-content">
                        <div class="step-title">Enter the 6-digit code</div>
                        <div class="step-desc">Type the code shown in the app to verify setup</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="tip-box">
            <div class="tip-title">💡 Can't scan the QR code?</div>
            <div class="tip-text">If your camera isn't working, you can manually enter the secret key shown below the QR code. In both apps, look for "Enter setup key" or "Enter code manually" option after tapping the + button.</div>
        </div>

        <a href="#" onclick="window.history.go(-1); return false;" class="back-link">Back to setup</a>
    </div>
</body>
</html>
        )";
        res->send(helpPage);
    });

    //============================================================================
    // OAUTH2/OIDC ENDPOINTS
    //============================================================================

    // OAuth2 Authorization Endpoint with PKCE and Redirect URI Validation
    app.get("/oauth2/authorize", [] MIDDLEWARE(req, res, next) {
        if (req->method != "GET") {
            return next();
        }
        std::string clientId = req->query("client_id");
        std::string redirectUri = req->query("redirect_uri");
        std::string state = req->query("state");
        std::string scope = req->query("scope");
        std::string codeChallenge = req->query("code_challenge");
        std::string codeChallengeMethod = req->query("code_challenge_method");

        // SECURITY: Validate redirect_uri against allow-list
        if (!validateRedirectUri(redirectUri)) {
            res->status(400).send("Invalid redirect_uri. Must be in allow-list.");
            return;
        }

        // PKCE: code_challenge is required for public clients (enforced for all)
        if (codeChallenge.empty()) {
            res->status(400).send("PKCE required: code_challenge parameter missing");
            return;
        }
        if (codeChallengeMethod.empty()) {
            codeChallengeMethod = "S256"; // Default to S256 if not specified
        }
        if (codeChallengeMethod != "S256" && codeChallengeMethod != "plain") {
            res->status(400).send("Invalid code_challenge_method. Supported: S256, plain");
            return;
        }

        // Redirect to login with PKCE parameters
        res->redirect("/auth/login?client_id=" + clientId + "&redirect_uri=" + redirectUri + "&state=" + state + "&scope=" + scope +
                      "&code_challenge=" + codeChallenge + "&code_challenge_method=" + codeChallengeMethod);
    });

    // OAuth2 Token Endpoint - OPTIONS (CORS Preflight)
    app.options("/oauth2/token", [] MIDDLEWARE(req, res, next) {
        if (req->method != "OPTIONS") {
            return next();
        }
        res->set("Access-Control-Allow-Origin", "*")
            .set("Access-Control-Allow-Methods", "POST, OPTIONS")
            .set("Access-Control-Allow-Headers", "Content-Type")
            .status(200)
            .send("");
    });

    // OAuth2 Token Endpoint with PKCE Verification
    app.post("/oauth2/token", [&jwtSigner] MIDDLEWARE(req, res, next) {
        if (req->method != "POST") {
            return next();
        }

        // CORS Header
        res->set("Access-Control-Allow-Origin", "*");

        auto params = parseBody(req->body);

        std::string grantType = params["grant_type"];
        std::string code = params["code"];
        std::string clientId = params["client_id"];
        std::string redirectUri = params["redirect_uri"];
        std::string codeVerifier = params["code_verifier"]; // PKCE

        if (grantType != "authorization_code") {
            json error;
            error["error"] = "unsupported_grant_type";
            res->status(400).set("Content-Type", "application/json").send(error.dump());
            return;
        }

        if (code.empty() || clientId.empty()) {
            json error;
            error["error"] = "invalid_request";
            res->status(400).set("Content-Type", "application/json").send(error.dump());
            return;
        }

        // PKCE: code_verifier is required
        if (codeVerifier.empty()) {
            json error;
            error["error"] = "invalid_request";
            error["error_description"] = "code_verifier required for PKCE";
            res->status(400).set("Content-Type", "application/json").send(error.dump());
            return;
        }

        // Fetch auth code with PKCE fields
        std::string query = "SELECT user_id, scope, expires_at, code_challenge, code_challenge_method FROM auth_code WHERE code = '" +
                            escapeString(code) + "' AND client_id = '" + escapeString(clientId) + "'";

        // Track outer query row processing
        auto outerRowProcessed = std::make_shared<bool>(false);

        g_db->query(
            query,
            [&jwtSigner, res, code, codeVerifier, outerRowProcessed](const MYSQL_ROW row) {
                // Ignore EOF callback if we already processed a row
                if (*outerRowProcessed)
                    return;

                if (!row) {
                    json error;
                    error["error"] = "invalid_grant";
                    res->status(400).set("Content-Type", "application/json").send(error.dump());
                    return;
                }
                *outerRowProcessed = true;

                std::string userId = row[0];
                std::string scope = row[1] ? row[1] : "";
                // row[2] is expires_at - TODO: verify not expired
                std::string storedChallenge = row[3] ? row[3] : "";
                std::string challengeMethod = row[4] ? row[4] : "S256";

                // PKCE Verification
                if (!storedChallenge.empty()) {
                    if (!verifyPkce(codeVerifier, storedChallenge, challengeMethod)) {
                        json error;
                        error["error"] = "invalid_grant";
                        error["error_description"] = "PKCE verification failed";
                        res->status(400).set("Content-Type", "application/json").send(error.dump());
                        return;
                    }
                }

                // Issue JWT
                // Query username
                std::string userQuery = "SELECT username FROM user WHERE id = " + userId;
                // Track inner query row processing
                auto innerRowProcessed = std::make_shared<bool>(false);

                g_db->query(
                    userQuery,
                    [&jwtSigner, res, userId, scope, code, innerRowProcessed](const MYSQL_ROW userRow) {
                        // Ignore EOF callback if we already processed a row
                        if (*innerRowProcessed)
                            return;

                        if (!userRow) {
                            json error;
                            error["error"] = "server_error";
                            res->status(500).set("Content-Type", "application/json").send(error.dump());
                            return;
                        }
                        *innerRowProcessed = true;
                        std::string username = userRow[0];

                        JwtClaims claims;
                        claims.issuer = "https://idp.snodec.local";
                        claims.subject = userId;
                        claims.audience = "snodec-client";
                        claims.expiresAt = std::chrono::system_clock::from_time_t(std::time(nullptr) + 3600); // 1 hour
                        claims.username = username;
                        // Parse scope string to vector
                        std::stringstream ss(scope);
                        std::string item;
                        while (std::getline(ss, item, ' ')) {
                            if (!item.empty())
                                claims.scopes.push_back(item);
                        }

                        std::string token = jwtSigner.sign(claims);

                        // Delete used code
                        g_db->exec(
                            "DELETE FROM auth_code WHERE code = '" + escapeString(code) + "'",
                            []() {
                            },
                            [](const std::string&, unsigned int) {
                            });

                        json response;
                        response["access_token"] = token;
                        response["token_type"] = "Bearer";
                        response["expires_in"] = 3600;
                        response["id_token"] = token; // Reuse access token as ID token for simplicity in this thesis

                        res->set("Content-Type", "application/json").send(response.dump());
                    },
                    [res](const std::string& error, unsigned int) {
                        res->status(500).set("Content-Type", "application/json").send("Database error: " + error);
                    });
            },
            [res](const std::string& error, unsigned int) {
                res->status(500).set("Content-Type", "application/json").send("Database error: " + error);
            });
    });

    //============================================================================
    // UTILITY ENDPOINTS
    //============================================================================

    // Health check
    app.get("/health", [] APPLICATION(req, res) {
        json health;
        health["status"] = "ok";
        health["service"] = "snodec-idp";
        health["version"] = "1.0.0";
        res->set("Content-Type", "application/json").send(health.dump());
    });

    // Start server
    app.listen(8083, [](const express::legacy::in::WebApp::SocketAddress& socketAddress, const core::socket::State& state) {
        if (state == core::socket::State::OK) {
            VLOG(0) << "IdP Server listening on " << socketAddress.toString();
        } else {
            LOG(ERROR) << "IdP Server failed: " << socketAddress.toString() << ": " << state.what();
        }
    });

    return core::SNodeC::start();
}
