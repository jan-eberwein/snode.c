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
 * OAuth2 Callback Handler
 *
 * Exchanges OAuth2 authorization codes for access tokens
 * and sets them as cookies for browser-based authentication.
 */

#pragma once

#include <functional>
#include <iomanip>
#include <openssl/sha.h>
#include <sstream>
#include <string>

// Forward declaration for HTTP client (implemented separately)
namespace snodec {
    namespace auth {
        namespace callback {

            /**
             * OAuth2 Callback Handler for SNode.C Express
             *
             * Handles the /auth/callback endpoint that IdP redirects to after
             * successful authentication. Exchanges authorization code for tokens.
             *
             * Usage:
             *   OAuth2CallbackHandler callbackHandler(idpTokenUrl, clientId);
             *   router.get("/auth/callback", callbackHandler);
             */
            class OAuth2CallbackHandler {
            public:
                OAuth2CallbackHandler(const std::string& idpTokenUrl, const std::string& clientId)
                    : idpTokenUrl_(idpTokenUrl)
                    , clientId_(clientId)
                    , cookieName_("access_token")
                    , defaultRedirect_("/") {
                }

                // Configure cookie name for token storage
                void setCookieName(const std::string& name) {
                    cookieName_ = name;
                }

                // Configure default redirect after login
                void setDefaultRedirect(const std::string& path) {
                    defaultRedirect_ = path;
                }

                // Handler function for GET /auth/callback
                template <typename Request, typename Response>
                void operator()(Request& req, Response& res) {
                    std::string code = req->query("code");
                    std::string state = req->query("state");
                    std::string error = req->query("error");

                    // Check for OAuth2 error
                    if (!error.empty()) {
                        std::string errorDesc = req->query("error_description");
                        res->status(401).send("OAuth2 Error: " + error + " - " + errorDesc);
                        return;
                    }

                    // Check for authorization code
                    if (code.empty()) {
                        res->status(400).send("Missing authorization code");
                        return;
                    }

                    // Get code_verifier from cookie (stored during redirect to IdP)
                    // Use SNode.C built-in cookie() method
                    std::string codeVerifier = req->cookie("pkce_verifier");

                    if (codeVerifier.empty()) {
                        res->status(400).send("Missing PKCE verifier - please try logging in again");
                        return;
                    }

                    // Build the callback URL for token exchange
                    std::string host = req->get("Host");
                    if (host.empty()) {
                        host = "localhost:8080";
                    }
                    std::string scheme = req->get("X-Forwarded-Proto");
                    if (scheme.empty()) {
                        scheme = "http";
                    }
                    std::string redirectUri = scheme + "://" + host + "/auth/callback";

                    // For this prototype, we'll use a simple approach:
                    // Build a form that POSTs to the IdP token endpoint
                    // In production, this should be a server-side HTTP request
                    //
                    // NOTE: For a complete implementation, you would use an HTTP client
                    // to make a POST request to the IdP's /oauth2/token endpoint.
                    // Since SNode.C HTTP client may not be available here, we use
                    // a JavaScript-based approach for the browser flow.

                    std::string tokenExchangePage = R"(
<!DOCTYPE html>
<html>
<head>
    <title>Completing Login...</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }
        .loader {
            text-align: center;
        }
        .spinner {
            width: 50px;
            height: 50px;
            border: 4px solid #e0e0e0;
            border-top: 4px solid #007bff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .error { color: #dc3545; display: none; }
    </style>
</head>
<body>
    <div class="loader">
        <div class="spinner"></div>
        <p>Completing authentication...</p>
        <p class="error" id="error"></p>
    </div>
    <script>
        // Exchange authorization code for access token
        async function exchangeToken() {
            const tokenUrl = ')" + idpTokenUrl_ + R"(';
            const params = new URLSearchParams({
                grant_type: 'authorization_code',
                code: ')" + code + R"(',
                client_id: ')" + clientId_ + R"(',
                redirect_uri: ')" + redirectUri + R"(',
                code_verifier: ')" + codeVerifier + R"('
            });

            try {
                const response = await fetch(tokenUrl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: params.toString()
                });

                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.error_description || error.error || 'Token exchange failed');
                }

                const data = await response.json();
                
                // Set the access token as a cookie
                const expiresIn = data.expires_in || 3600;
                const expires = new Date(Date.now() + expiresIn * 1000);
                document.cookie = ')" + cookieName_ +
                                                    R"(=' + data.access_token +
                    '; path=/; expires=' + expires.toUTCString() + '; SameSite=Lax';

                // Make the signed-in identity available to the frontend UI.
                // The access token is treated as opaque (a relying party may
                // re-issue it as an HttpOnly cookie that scripts cannot read),
                // so we additionally store a small, non-sensitive cookie with
                // the display name and email decoded from the JWT payload. Any
                // SNode.C frontend can read "snodec_user" to render account UI
                // without parsing or verifying tokens itself.
                try {
                    var b64 = data.access_token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
                    while (b64.length % 4) { b64 += '='; }
                    var claims = JSON.parse(decodeURIComponent(escape(atob(b64))));
                    var who = encodeURIComponent(JSON.stringify({
                        username: claims.username || claims.preferred_username || claims.sub || '',
                        email: claims.email || ''
                    }));
                    document.cookie = 'snodec_user=' + who +
                        '; path=/; expires=' + expires.toUTCString() + '; SameSite=Lax';
                } catch (e) { /* identity cookie is best-effort; ignore decode errors */ }

                // Clear the PKCE verifier cookie
                document.cookie = 'pkce_verifier=; path=/; max-age=0';

                // Redirect to original URL or default
                let targetUrl = decodeURIComponent(')" +
                                                    state + R"(');
                // Validate targetUrl - must start with / or http, otherwise use default
                if (!targetUrl || (!targetUrl.startsWith('/') && !targetUrl.startsWith('http'))) {
                    targetUrl = ')" + defaultRedirect_ +
                                                    R"(';
                }
                window.location.href = targetUrl;

            } catch (error) {
                document.getElementById('error').style.display = 'block';
                document.getElementById('error').textContent = 'Login failed: ' + error.message;
                document.querySelector('.spinner').style.display = 'none';
            }
        }

        exchangeToken();
    </script>
</body>
</html>
                    )";

                    res->send(tokenExchangePage);
                }

            private:
                std::string idpTokenUrl_;
                std::string clientId_;
                std::string cookieName_;
                std::string defaultRedirect_;

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
            };

        } // namespace callback
    } // namespace auth
} // namespace snodec
