/*
 * SNode.C SSO/MFA — Federated Login Provider Abstraction
 * Copyright (C) Jan Nicolas Eberwein 2025/2026 — Master Thesis
 *
 * Generic OAuth2/OIDC provider abstraction for social login
 * (Google, Apple, Meta/Facebook). Providers are disabled by default
 * and enabled only when proper environment variables are configured.
 *
 * No secrets are hardcoded. All credentials come from environment variables.
 */

#pragma once

#include <cstdlib>
#include <map>
#include <string>
#include <vector>
#include "web/http/http_utils.h"

namespace snodec {
    namespace auth {

        /**
         * Represents a federated OAuth2/OIDC identity provider.
         * Each provider is configured from environment variables and
         * disabled unless all required variables are set.
         */
        struct FederatedProvider {
            std::string id;               // "google", "apple", "meta"
            std::string displayName;      // "Google", "Apple", "Meta"
            std::string clientId;         // From env: OAUTH_<ID>_CLIENT_ID
            std::string clientSecret;     // From env: OAUTH_<ID>_CLIENT_SECRET
            std::string authorizationUrl; // Provider's OAuth2 authorize endpoint
            std::string tokenUrl;         // Provider's OAuth2 token endpoint
            std::string userInfoUrl;      // Provider's userinfo / profile endpoint
            std::string scope;            // OAuth2 scopes to request
            bool enabled = false;         // Only true when credentials are configured

            // SVG icon for login button (inline, no external dependencies)
            std::string svgIcon;

            // CSS color for the button
            std::string buttonColor;
            std::string buttonTextColor;
        };

        /**
         * Registry of federated login providers.
         * Reads configuration from environment variables at construction time.
         * Providers without valid credentials are kept but marked as disabled.
         *
         * Environment variable naming convention:
         *   OAUTH_GOOGLE_CLIENT_ID, OAUTH_GOOGLE_CLIENT_SECRET
         *   OAUTH_APPLE_CLIENT_ID, OAUTH_APPLE_CLIENT_SECRET
         *   OAUTH_META_CLIENT_ID, OAUTH_META_CLIENT_SECRET
         */
        class FederatedLoginRegistry {
        public:
            FederatedLoginRegistry() {
                // ── Google ─────────────────────────────────────────────────
                FederatedProvider google;
                google.id = "google";
                google.displayName = "Google";
                google.authorizationUrl = "https://accounts.google.com/o/oauth2/v2/auth";
                google.tokenUrl = "https://oauth2.googleapis.com/token";
                google.userInfoUrl = "https://openidconnect.googleapis.com/v1/userinfo";
                google.scope = "openid email profile";
                google.buttonColor = "#ffffff";
                google.buttonTextColor = "#1f1f1f";
                google.svgIcon = R"(<svg viewBox="0 0 24 24" width="20" height="20">
                    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/>
                    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
                    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                </svg>)";
                loadFromEnv(google);
                providers_["google"] = google;

                // ── Apple ──────────────────────────────────────────────────
                FederatedProvider apple;
                apple.id = "apple";
                apple.displayName = "Apple";
                apple.authorizationUrl = "https://appleid.apple.com/auth/authorize";
                apple.tokenUrl = "https://appleid.apple.com/auth/token";
                apple.userInfoUrl = ""; // Apple returns user info in the ID token
                apple.scope = "name email";
                apple.buttonColor = "#000000";
                apple.buttonTextColor = "#ffffff";
                apple.svgIcon = R"(<svg viewBox="0 0 24 24" width="20" height="20" fill="white">
                    <path d="M17.05 20.28c-.98.95-2.05.88-3.08.4-1.09-.5-2.08-.48-3.24 0-1.44.62-2.2.44-3.06-.4C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.54 4.09zM12.03 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25z"/>
                </svg>)";
                loadFromEnv(apple);
                providers_["apple"] = apple;

                // ── Meta (Facebook) ────────────────────────────────────────
                FederatedProvider meta;
                meta.id = "meta";
                meta.displayName = "Meta";
                meta.authorizationUrl = "https://www.facebook.com/v19.0/dialog/oauth";
                meta.tokenUrl = "https://graph.facebook.com/v19.0/oauth/access_token";
                meta.userInfoUrl = "https://graph.facebook.com/me?fields=id,name,email";
                meta.scope = "email public_profile";
                meta.buttonColor = "#1877F2";
                meta.buttonTextColor = "#ffffff";
                meta.svgIcon = R"(<svg viewBox="0 0 24 24" width="20" height="20" fill="white">
                    <path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/>
                </svg>)";
                loadFromEnv(meta);
                providers_["meta"] = meta;
            }

            // Get all providers (enabled and disabled)
            std::vector<FederatedProvider> getAllProviders() const {
                std::vector<FederatedProvider> result;
                for (const auto& [_, p] : providers_) {
                    result.push_back(p);
                }
                return result;
            }

            // Get only enabled providers
            std::vector<FederatedProvider> getEnabledProviders() const {
                std::vector<FederatedProvider> result;
                for (const auto& [_, p] : providers_) {
                    if (p.enabled) {
                        result.push_back(p);
                    }
                }
                return result;
            }

            // Look up provider by ID
            const FederatedProvider* getProvider(const std::string& id) const {
                auto it = providers_.find(id);
                if (it != providers_.end()) {
                    return &it->second;
                }
                return nullptr;
            }

            // Check if any federated providers are enabled
            bool hasEnabledProviders() const {
                for (const auto& [_, p] : providers_) {
                    if (p.enabled) return true;
                }
                return false;
            }

            // Generate HTML for social login buttons (only enabled providers)
            std::string renderLoginButtons(const std::string& idpBaseUrl,
                                            const std::string& clientId,
                                            const std::string& redirectUri,
                                            const std::string& state,
                                            const std::string& codeChallenge,
                                            const std::string& codeChallengeMethod) const {
                auto enabled = getEnabledProviders();
                if (enabled.empty()) {
                    return "";
                }

                std::string html;
                html += "<div class=\"divider\" style=\"position:relative;\">"
                        "<span style=\"position:absolute;top:-10px;left:50%;transform:translateX(-50%);"
                        "background:var(--card-bg);padding:0 16px;color:var(--text-muted);font-size:0.85rem;\">"
                        "or continue with</span></div>\n";
                html += "<div style=\"display:flex;flex-direction:column;gap:10px;\">\n";

                for (const auto& p : enabled) {
                    html += "<a href=\"" + idpBaseUrl + "/auth/federated/" + p.id
                         +  "?client_id=" + clientId
                         +  "&redirect_uri=" + redirectUri
                         +  "&state=" + state
                         +  "&code_challenge=" + httputils::url_encode(codeChallenge)
                         +  "&code_challenge_method=" + httputils::url_encode(codeChallengeMethod)
                         +  "\" class=\"btn\" style=\"display:flex;align-items:center;"
                         +  "justify-content:center;gap:10px;background:" + p.buttonColor
                         +  ";color:" + p.buttonTextColor
                         +  ";border:1px solid var(--card-border);\">"
                         +  p.svgIcon + " Sign in with " + p.displayName + "</a>\n";
                }

                html += "</div>\n";
                return html;
            }

        private:
            std::map<std::string, FederatedProvider> providers_;

            // Load client credentials from environment variables
            static void loadFromEnv(FederatedProvider& provider) {
                std::string prefix = "OAUTH_";
                // Convert id to uppercase for env var lookup
                std::string upperID;
                for (char c : provider.id) {
                    upperID += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                }
                prefix += upperID + "_";

                const char* clientId = std::getenv((prefix + "CLIENT_ID").c_str());
                const char* clientSecret = std::getenv((prefix + "CLIENT_SECRET").c_str());

                if (clientId != nullptr && clientSecret != nullptr) {
                    provider.clientId = clientId;
                    provider.clientSecret = clientSecret;
                    provider.enabled = true;
                }
            }
        };

    } // namespace auth
} // namespace snodec
