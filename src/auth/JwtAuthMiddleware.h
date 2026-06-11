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

/*
 * JWT Authentication Middleware for SNode.C Express
 *
 * Features:
 *   - Bearer token extraction from Authorization header
 *   - Cookie-based token extraction for browser flows
 *   - OAuth2 redirect with PKCE support
 *   - Configurable IdP URL and client settings
 */

#pragma once

#include "auth/JwtVerifier.h"

#include <cstdlib>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <openssl/sha.h>
#include <random>
#include <sstream>
#include <string>

#include "log/Logger.h"

namespace snodec {
    namespace auth {
        namespace middleware {

            /**
             * JWT Authentication Middleware for SNode.C Express
             *
             * Usage:
             *   JwtAuthMiddleware authMiddleware(issuer, audience, publicKeyPem);
             *   authMiddleware.setIdpBaseUrl("http://192.168.1.1:8083");
             *   authMiddleware.setClientId("mqttbroker");
             *   authMiddleware.setCallbackPath("/auth/callback");
             *   router.use("/protected", authMiddleware);
             */
            class JwtAuthMiddleware {
            public:
                JwtAuthMiddleware(const std::string& issuer, const std::string& audience, const std::string& publicKeyPem)
                    : verifier_(issuer, audience, publicKeyPem)
                    , idpBaseUrl_("http://localhost:8083")
                    , clientId_("snodec-client")
                    , callbackPath_("/auth/callback")
                    , cookieName_("access_token") {
                }

                // Configure IdP base URL (e.g., "http://192.168.1.1:8083")
                void setIdpBaseUrl(const std::string& url) {
                    idpBaseUrl_ = url;
                }

                // Configure OAuth2 client ID
                void setClientId(const std::string& clientId) {
                    clientId_ = clientId;
                }

                // Configure callback path on this server (e.g., "/auth/callback")
                void setCallbackPath(const std::string& path) {
                    callbackPath_ = path;
                }

                // Configure cookie name for token storage
                void setCookieName(const std::string& name) {
                    cookieName_ = name;
                }

                // Legacy method for compatibility
                void setIdpLoginUrl(const std::string& url) {
                    idpBaseUrl_ = url;
                }

                // Middleware function - integrate with SNode.C Express Router
                template <typename Request, typename Response, typename Next>
                void operator()(Request& req, Response& res, Next& next) {
                    std::string token = extractToken(req);

                    VLOG(2) << "[JwtAuthMiddleware] Token extracted: "
                              << (token.empty() ? "EMPTY" : "present (" + std::to_string(token.length()) + " chars)");

                    if (token.empty()) {
                        // No token - redirect to IdP for OAuth2 login
                        VLOG(2) << "[JwtAuthMiddleware] No token found, redirecting to IdP";
                        redirectToIdp(req, res);
                        return;
                    }

                    JwtClaims claims;
                    std::string error;

                    if (!verifier_.verify(token, claims, error)) {
                        // Invalid or expired token - clear cookie and redirect
                        VLOG(2) << "[JwtAuthMiddleware] Token verification FAILED: " << error;
                        res->set("Set-Cookie", cookieName_ + "=; Path=/; Max-Age=0; HttpOnly");
                        redirectToIdp(req, res);
                        return;
                    }

                    VLOG(2) << "[JwtAuthMiddleware] Token verified for user: " << claims.username;

                    // Token valid - store claims in request for downstream handlers
                    req->template setAttribute<std::string>(claims.subject, "X-User-Id");
                    req->template setAttribute<std::string>(claims.username, "X-Username");
                    req->template setAttribute<std::string>(claims.email, "X-Email");
                    req->template setAttribute<bool>(claims.mfaVerified, "X-MfaVerified");

                    // Continue to next middleware/handler
                    next();
                }

            private:
                JwtVerifier verifier_;
                std::string idpBaseUrl_;
                std::string clientId_;
                std::string callbackPath_;
                std::string cookieName_;

                // Extract token from Authorization header or cookie
                template <typename Request>
                std::string extractToken(Request& req) {
                    // First try Authorization header (API clients)
                    std::string authHeader = req->get("Authorization");
                    if (!authHeader.empty() && authHeader.length() > 7 && authHeader.substr(0, 7) == "Bearer ") {
                        return authHeader.substr(7);
                    }

                    // Fall back to cookie (browser clients)
                    // Use SNode.C's built-in cookie() method which handles parsing
                    std::string cookieValue = req->cookie(cookieName_);
                    if (!cookieValue.empty()) {
                        return cookieValue;
                    }

                    // Also try manually parsing if cookie() doesn't work
                    std::string cookieHeader = req->get("Cookie");
                    if (!cookieHeader.empty()) {
                        VLOG(2) << "[JwtAuthMiddleware] Cookie header: " << cookieHeader;
                        return extractCookieValue(cookieHeader, cookieName_);
                    }

                    return "";
                }

                // Parse a specific cookie value from Cookie header
                static std::string extractCookieValue(const std::string& cookieHeader, const std::string& name) {
                    std::string searchKey = name + "=";
                    size_t start = cookieHeader.find(searchKey);
                    if (start == std::string::npos) {
                        return "";
                    }
                    start += searchKey.length();
                    size_t end = cookieHeader.find(';', start);
                    if (end == std::string::npos) {
                        end = cookieHeader.length();
                    }
                    return cookieHeader.substr(start, end - start);
                }

                // Build OAuth2 authorize URL and redirect
                template <typename Request, typename Response>
                void redirectToIdp(Request& req, Response& res) {
                    // Build the callback URL for this request
                    std::string host = req->get("Host");
                    if (host.empty()) {
                        host = "localhost:8080";
                    }

                    // Determine scheme (check X-Forwarded-Proto or default to http)
                    std::string scheme = req->get("X-Forwarded-Proto");
                    if (scheme.empty()) {
                        scheme = "http";
                    }

                    std::string redirectUri = scheme + "://" + host + callbackPath_;

                    // Generate PKCE code_verifier and code_challenge
                    std::string codeVerifier = generateCodeVerifier();
                    std::string codeChallenge = computeCodeChallenge(codeVerifier);

                    // Generate state parameter (includes original URL for redirect after auth)
                    std::string originalUrl = req->url;
                    std::string state = urlEncode(originalUrl);

                    // Store code_verifier in cookie for token exchange
                    // This is secure because it's HttpOnly and same-site
                    res->set("Set-Cookie", "pkce_verifier=" + codeVerifier + "; Path=/; Max-Age=600; HttpOnly; SameSite=Lax");

                    // Build OAuth2 authorize URL
                    std::string authorizeUrl = idpBaseUrl_ +
                                               "/oauth2/authorize"
                                               "?response_type=code"
                                               "&client_id=" +
                                               urlEncode(clientId_) + "&redirect_uri=" + urlEncode(redirectUri) +
                                               "&scope=openid%20profile" + "&state=" + state + "&code_challenge=" + codeChallenge +
                                               "&code_challenge_method=S256";

                    res->redirect(authorizeUrl);
                }

                // Generate random code verifier for PKCE (43-128 chars, base64url)
                static std::string generateCodeVerifier() {
                    static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
                    const size_t length = 64;

                    std::random_device rd;
                    std::mt19937 gen(rd());
                    std::uniform_int_distribution<size_t> dist(0, sizeof(charset) - 2);

                    std::string verifier;
                    verifier.reserve(length);
                    for (size_t i = 0; i < length; ++i) {
                        verifier += charset[dist(gen)];
                    }
                    return verifier;
                }

                // Compute S256 code challenge from verifier
                static std::string computeCodeChallenge(const std::string& verifier) {
                    // SHA256 hash
                    unsigned char hash[32];
                    SHA256(reinterpret_cast<const unsigned char*>(verifier.c_str()), verifier.length(), hash);

                    // Base64URL encode
                    return base64UrlEncode(hash, 32);
                }

                // Base64URL encode (no padding)
                static std::string base64UrlEncode(const unsigned char* data, size_t len) {
                    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

                    std::string result;
                    result.reserve(((len + 2) / 3) * 4);

                    for (size_t i = 0; i < len; i += 3) {
                        unsigned int n = static_cast<unsigned int>(data[i]) << 16;
                        if (i + 1 < len)
                            n |= static_cast<unsigned int>(data[i + 1]) << 8;
                        if (i + 2 < len)
                            n |= static_cast<unsigned int>(data[i + 2]);

                        result += b64[(n >> 18) & 0x3F];
                        result += b64[(n >> 12) & 0x3F];
                        if (i + 1 < len)
                            result += b64[(n >> 6) & 0x3F];
                        if (i + 2 < len)
                            result += b64[n & 0x3F];
                    }

                    // Convert to base64url (replace + with -, / with _)
                    for (char& c : result) {
                        if (c == '+')
                            c = '-';
                        else if (c == '/')
                            c = '_';
                    }

                    return result;
                }

                // URL encode a string
                static std::string urlEncode(const std::string& value) {
                    std::ostringstream escaped;
                    escaped.fill('0');
                    escaped << std::hex;

                    for (char c : value) {
                        if (isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == '~') {
                            escaped << c;
                        } else {
                            escaped << '%' << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c));
                        }
                    }

                    return escaped.str();
                }
            };

            // Helper to load public key from file
            inline std::string loadPublicKey(const std::string& filename) {
                std::ifstream file(filename);
                if (!file.is_open()) {
                    throw std::runtime_error("Failed to open public key file: " + filename);
                }
                std::stringstream buffer;
                buffer << file.rdbuf();
                return buffer.str();
            }

        } // namespace middleware
    } // namespace auth
} // namespace snodec
