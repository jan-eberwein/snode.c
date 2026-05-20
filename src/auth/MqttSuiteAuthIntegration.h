/*
 * SNode.C SSO/MFA — MQTT Suite Auth Integration
 * Copyright (C) Jan Nicolas Eberwein 2025/2026 — Master Thesis
 *
 * This file demonstrates how to integrate the SNode.C SSO/MFA authentication
 * system with the MQTTSuite broker's HTTP management interface.
 *
 * The integration adds JWT-based authentication to the broker's web management
 * endpoints, enabling SSO across the MQTT broker and other SNode.C applications.
 *
 * USAGE:
 *   Include this file in the MQTT broker's management server setup.
 *   The JwtAuthMiddleware will intercept unauthenticated requests and redirect
 *   to the Identity Provider for authentication via OAuth 2.0 + PKCE.
 *
 * REQUIREMENTS:
 *   - Link against the 'auth' static library
 *   - Provide the IdP's RSA public key (public_key.pem)
 *   - Configure the IdP base URL and client credentials
 */

#include "auth/JwtAuthMiddleware.h"
#include "auth/OAuth2CallbackHandler.h"

#include <express/legacy/in/WebApp.h>
#include <core/SNodeC.h>
#include <log/Logger.h>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

namespace snodec {
    namespace mqtt {
        namespace auth {

            /**
             * Helper: Read file contents to string.
             */
            static std::string readFile(const std::string& path) {
                std::ifstream f(path);
                if (!f.is_open()) {
                    throw std::runtime_error("Cannot open file: " + path);
                }
                std::stringstream buf;
                buf << f.rdbuf();
                return buf.str();
            }

            /**
             * Configure SSO/MFA authentication for an MQTT broker's HTTP management
             * interface. This function registers the necessary middleware and callback
             * routes on the provided WebApp instance.
             *
             * @param app        The SNode.C WebApp instance for the MQTT management interface.
             * @param publicKeyPath  Path to the IdP's RSA public key (PEM format).
             * @param idpBaseUrl     Base URL of the Identity Provider (e.g., "http://localhost:8083").
             * @param clientId       OAuth 2.0 client ID for this application.
             * @param callbackPath   Path for the OAuth 2.0 callback (default: "/auth/callback").
             * @param managementPort Port number the management interface listens on.
             *
             * After calling this function, all routes registered on the WebApp will
             * require a valid JWT token. Unauthenticated users will be redirected to
             * the IdP for login.
             *
             * Example usage:
             * @code
             *   express::legacy::in::WebApp mgmtApp("MQTTBrokerMgmt");
             *
             *   // Register management routes FIRST
             *   mgmtApp.get("/", [] APPLICATION(req, res) {
             *       res->send("<h1>MQTT Broker Management</h1>");
             *   });
             *
             *   // Then enable SSO authentication
             *   snodec::mqtt::auth::enableSsoAuth(
             *       mgmtApp,
             *       "keys/public_key.pem",
             *       "http://localhost:8083",
             *       "mqtt-broker",
             *       "/auth/callback",
             *       8080
             *   );
             * @endcode
             */
            static void enableSsoAuth(
                express::legacy::in::WebApp& app,
                const std::string& publicKeyPath,
                const std::string& idpBaseUrl,
                const std::string& clientId,
                const std::string& callbackPath = "/auth/callback",
                int managementPort = 8080)
            {
                // Load IdP public key
                std::string publicKey;
                try {
                    publicKey = readFile(publicKeyPath);
                } catch (const std::exception& e) {
                    LOG(ERROR) << "[MQTT Auth] Cannot load public key: " << e.what();
                    return;
                }

                // Determine the redirect URI for OAuth2 callback
                auto envFn = [](const char* k, const std::string& def) {
                    const char* v = std::getenv(k);
                    return v ? std::string(v) : def;
                };

                std::string host = envFn("MQTT_MGMT_HOST", "localhost");
                std::string redirectUri = "http://" + host + ":"
                    + std::to_string(managementPort) + callbackPath;

                std::string issuer = envFn("IDP_ISSUER", "https://idp.snodec.local");

                LOG(INFO) << "[MQTT Auth] Enabling SSO authentication";
                LOG(INFO) << "[MQTT Auth] IdP: " << idpBaseUrl;
                LOG(INFO) << "[MQTT Auth] Client ID: " << clientId;
                LOG(INFO) << "[MQTT Auth] Callback: " << redirectUri;

                // Register OAuth2 callback handler (must be registered before the auth middleware)
                OAuth2CallbackHandler::registerRoutes(
                    app,
                    callbackPath,
                    idpBaseUrl + "/oauth2/token",
                    clientId,
                    redirectUri
                );

                // Register the JWT authentication middleware for all routes
                // This must come after the callback handler so the callback
                // endpoint itself is accessible without authentication.
                JwtAuthMiddleware authMiddleware(
                    publicKey,
                    issuer,
                    clientId,          // audience
                    idpBaseUrl,
                    clientId,
                    redirectUri
                );

                app.use(authMiddleware.middleware());

                LOG(INFO) << "[MQTT Auth] SSO authentication enabled for MQTT management interface";
            }

            /**
             * Register a logout route that chains to the IdP's logout endpoint.
             *
             * @param app        The SNode.C WebApp instance.
             * @param idpBaseUrl Base URL of the Identity Provider.
             * @param logoutPath Path for the local logout endpoint (default: "/auth/logout").
             */
            static void registerLogout(
                express::legacy::in::WebApp& app,
                const std::string& idpBaseUrl,
                const std::string& logoutPath = "/auth/logout")
            {
                app.get(logoutPath, [idpBaseUrl] APPLICATION(req, res) {
                    // Clear local access token cookie
                    res->cookie("access_token", "", {{"Path", "/"}, {"Max-Age", "0"}});

                    // Chain logout to IdP
                    std::string localUrl = "http://" + req->header("Host");
                    res->redirect(idpBaseUrl + "/auth/logout?redirect_uri=" + localUrl);
                });
            }

        } // namespace auth
    } // namespace mqtt
} // namespace snodec
