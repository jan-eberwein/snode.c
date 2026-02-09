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
 * MQTT Suite SSO Integration Example
 *
 * This file shows the minimal code changes needed to add SSO/MFA protection
 * to the MQTT Suite web interface. These changes should be applied to
 * mqtt-suite/apps/mqttbroker/mqttbroker.cpp
 *
 * ============================================================================
 * INTEGRATION INSTRUCTIONS
 * ============================================================================
 *
 * 1. Copy the auth headers to MQTT Suite:
 *    cp snode.c/src/auth/*.h mqtt-suite/src/auth/
 *
 * 2. Copy the public key:
 *    cp snode.c/src/apps/auth_idp/keys/public_key.pem mqtt-suite/apps/mqttbroker/keys/
 *
 * 3. Add the following includes at the top of mqttbroker.cpp:
 *      #include "auth/JwtAuthMiddleware.h"
 *      #include "auth/OAuth2CallbackHandler.h"
 *
 * 4. Add the SSO configuration and middleware (see code below)
 *
 * 5. Rebuild MQTT Suite with additional CMake flags:
 *      cmake -DWITH_SSO=ON ..
 *
 * ============================================================================
 */

// ============================================================================
// ADD TO mqttbroker.cpp - Configuration Section
// ============================================================================

// SSO/MFA Configuration
namespace sso_config {
    // IdP configuration - change these for your deployment
    constexpr const char* IDP_BASE_URL = "http://192.168.1.1:8083"; // IdP server URL
    constexpr const char* IDP_TOKEN_URL = "http://192.168.1.1:8083/oauth2/token";
    constexpr const char* JWT_ISSUER = "https://idp.snodec.local";
    constexpr const char* JWT_AUDIENCE = "snodec-client";
    constexpr const char* CLIENT_ID = "mqttbroker";

    // Paths
    constexpr const char* PUBLIC_KEY_PATH = "keys/public_key.pem";
    constexpr const char* CALLBACK_PATH = "/auth/callback";

    // Web interface paths to protect
    constexpr const char* PROTECTED_PATHS[] = {"/clients", "/api/mqtt", "/admin"};
} // namespace sso_config

// ============================================================================
// ADD TO mqttbroker.cpp - After app initialization, before route definitions
// ============================================================================

/*
 * Example integration code - add after WebApp initialization:
 *
 * ```cpp
 * // ... existing code ...
 *
 * const express::legacy::in::WebApp app("MQTTBroker");
 *
 * // === BEGIN SSO INTEGRATION ===
 *
 * // Load IdP public key for JWT verification
 * std::string publicKey;
 * try {
 *     publicKey = snodec::auth::middleware::loadPublicKey(sso_config::PUBLIC_KEY_PATH);
 *     VLOG(0) << "Loaded IdP public key for SSO";
 * } catch (const std::exception& e) {
 *     // SSO disabled if key not found
 *     LOG(WARNING) << "SSO disabled: " << e.what();
 * }
 *
 * // Initialize JWT middleware (only if public key loaded)
 * std::unique_ptr<snodec::auth::middleware::JwtAuthMiddleware> authMiddleware;
 * if (!publicKey.empty()) {
 *     authMiddleware = std::make_unique<snodec::auth::middleware::JwtAuthMiddleware>(
 *         sso_config::JWT_ISSUER,
 *         sso_config::JWT_AUDIENCE,
 *         publicKey
 *     );
 *     authMiddleware->setIdpBaseUrl(sso_config::IDP_BASE_URL);
 *     authMiddleware->setClientId(sso_config::CLIENT_ID);
 *     authMiddleware->setCallbackPath(sso_config::CALLBACK_PATH);
 * }
 *
 * // OAuth2 callback handler
 * snodec::auth::callback::OAuth2CallbackHandler callbackHandler(
 *     sso_config::IDP_TOKEN_URL,
 *     sso_config::CLIENT_ID
 * );
 *
 * // === END SSO INTEGRATION ===
 *
 * // ... existing route definitions ...
 * ```
 */

// ============================================================================
// ADD TO mqttbroker.cpp - Route Registration Section
// ============================================================================

/*
 * Example route protection:
 *
 * ```cpp
 * // OAuth2 callback endpoint (must be BEFORE protected routes)
 * app.get("/auth/callback", [&callbackHandler] APPLICATION(req, res) {
 *     callbackHandler(req, res);
 * });
 *
 * // Logout endpoint
 * app.get("/auth/logout", [] APPLICATION(req, res) {
 *     // Clear the access token cookie
 *     res->set("Set-Cookie", "access_token=; Path=/; Max-Age=0; HttpOnly");
 *     res->redirect("/");
 * });
 *
 * // Protect web interface routes
 * if (authMiddleware) {
 *     // Apply SSO middleware to protected paths
 *     app.use("/clients", [&authMiddleware] APPLICATION(req, res, next) {
 *         (*authMiddleware)(req, res, next);
 *     });
 *
 *     app.use("/api/mqtt", [&authMiddleware] APPLICATION(req, res, next) {
 *         (*authMiddleware)(req, res, next);
 *     });
 *
 *     app.use("/admin", [&authMiddleware] APPLICATION(req, res, next) {
 *         (*authMiddleware)(req, res, next);
 *     });
 * }
 *
 * // ... existing route handlers ...
 * ```
 */

// ============================================================================
// OPTIONAL: Add user info to protected pages
// ============================================================================

/*
 * After authentication, user info is available in request headers:
 *
 * ```cpp
 * app.get("/clients", [] APPLICATION(req, res) {
 *     std::string userId = req->get("X-User-Id");
 *     std::string username = req->get("X-Username");
 *
 *     // Use user info in your response
 *     std::string page = "<h1>Welcome, " + username + "</h1>";
 *     // ... rest of page ...
 *     res->send(page);
 * });
 * ```
 */
