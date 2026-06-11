/*
 * SNode.C - A Slim Toolkit for Network Communication
 * Protected Web App — SSO/MFA Demo
 *
 * Demonstrates OAuth2 Authorization Code + PKCE flow against the SNode.C IdP.
 * Auto-redirects unauthenticated users to the IdP; Single Logout chains back.
 */

#include "auth/JwtAuthMiddleware.h"
#include "auth/OAuth2CallbackHandler.h"
#include "core/SNodeC.h"
#include "express/legacy/in/WebApp.h"
#include "log/Logger.h"

#include <fstream>
#include <iostream>
#include <openssl/sha.h>
#include <random>
#include <sstream>
#include <string>
#include <vector>

using namespace snodec;
using namespace snodec::auth::middleware;
using namespace snodec::auth::callback;

constexpr int APP_PORT = 8055;
constexpr int IDP_PORT = 8083;

static std::string loadPubKeyFile(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) {
        throw std::runtime_error("Cannot open: " + path);
    }
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

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

int main(int argc, char* argv[]) {
    core::SNodeC::init(argc, argv);
    express::legacy::in::WebApp app("SSO-MFA-Test");

    // ── Load public key ──────────────────────────────────────────────────────
    std::string publicKey;
    {
        std::vector<std::string> keyPaths = {
            "keys/public_key.pem",
            "src/apps/auth_idp/keys/public_key.pem",
            "../auth_idp/keys/public_key.pem",
        };
        bool loaded = false;
        for (const auto& path : keyPaths) {
            try {
                publicKey = loadPubKeyFile(path);
                VLOG(0) << "Loaded public key from: " << path;
                loaded = true;
                break;
            } catch (...) {
                continue;
            }
        }
        if (!loaded) {
            LOG(ERROR) << "Failed to load public key from any configured path";
            return 1;
        }
    }

    // ── Configuration ─────────────────────────────────────────────────────────
    auto getEnv = [](const char* name, const std::string& def) -> std::string {
        const char* val = std::getenv(name);
        return val ? std::string(val) : def;
    };
    std::string idpIssuer      = getEnv("IDP_ISSUER",    "https://auth.janeberwein.at");
    std::string idpBaseUrl     = getEnv("IDP_BASE_URL",  "https://auth.janeberwein.at");
    std::string appBaseUrl     = getEnv("APP_BASE_URL",  "http://localhost:" + std::to_string(APP_PORT));
    std::string webappClientId = getEnv("WEBAPP_CLIENT_ID", "snodec-webapp");

    // ── Middleware ─────────────────────────────────────────────────────────────
    JwtAuthMiddleware authMiddleware(idpIssuer, webappClientId, publicKey);
    authMiddleware.setIdpBaseUrl(idpBaseUrl);
    authMiddleware.setClientId(webappClientId);
    authMiddleware.setCallbackPath("/auth/callback");

    OAuth2CallbackHandler callbackHandler(idpBaseUrl + "/oauth2/token", webappClientId);
    snodec::auth::JwtVerifier jwtVerifier(idpIssuer, webappClientId, publicKey);

    // ── Shared CSS (matches IdP dark/minimal design) ───────────────────────────
    auto sharedCss = []() -> std::string {
        return R"(
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',system-ui,sans-serif;background:#0f1117;color:#e8e9ed;min-height:100vh}
a{text-decoration:none;color:inherit}
header{display:flex;align-items:center;justify-content:space-between;padding:0 32px;height:56px;
  background:rgba(255,255,255,0.03);border-bottom:1px solid rgba(255,255,255,0.08);
  position:sticky;top:0;z-index:100;backdrop-filter:blur(10px)}
.header-logo{display:flex;align-items:center;gap:10px;font-size:1rem;font-weight:600;color:#e8e9ed}
.header-logo svg{color:#3b82f6}
.header-badge{font-size:0.7rem;padding:2px 8px;background:rgba(59,130,246,0.15);color:#3b82f6;
  border:1px solid rgba(59,130,246,0.3);border-radius:20px;margin-left:6px}
.header-nav{display:flex;align-items:center;gap:8px}
.nav-user{display:flex;align-items:center;gap:8px;padding:5px 14px;
  border:1.5px solid rgba(59,130,246,0.5);border-radius:20px;font-size:0.85rem;
  font-weight:500;color:#3b82f6}
.nav-btn{padding:7px 14px;border-radius:8px;font-size:0.85rem;font-weight:500;
  background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.1);
  color:#e8e9ed;transition:.15s;cursor:pointer}
.nav-btn:hover{background:rgba(255,255,255,0.1)}
.nav-btn.danger{color:#f87171;border-color:rgba(239,68,68,0.25)}
.nav-btn.danger:hover{background:rgba(239,68,68,0.1)}
main{max-width:960px;margin:0 auto;padding:40px 24px}
.page-title{font-size:1.5rem;font-weight:700;letter-spacing:-0.5px;margin-bottom:4px}
.page-subtitle{color:#6b7280;font-size:0.9rem;margin-bottom:32px}
.card{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:24px}
.grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(200px,1fr))}
.tile{background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);
  border-radius:14px;padding:22px;transition:.2s}
.tile:hover{background:rgba(255,255,255,0.07);border-color:rgba(255,255,255,0.14)}
.tile-label{font-size:0.72rem;text-transform:uppercase;letter-spacing:1px;color:#6b7280;margin-bottom:8px}
.tile-value{font-size:1.5rem;font-weight:700;letter-spacing:-0.5px}
.tile-sub{font-size:0.8rem;color:#6b7280;margin-top:4px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.green{color:#4ade80}.green .dot,.dot-green{background:#22c55e}
.orange{color:#fb923c}.orange .dot,.dot-orange{background:#f97316}
.info-row{display:flex;justify-content:space-between;align-items:center;
  padding:12px 0;border-bottom:1px solid rgba(255,255,255,0.06);font-size:0.9rem}
.info-row:last-child{border:0}
.info-label{color:#6b7280}
.btn{display:inline-block;padding:10px 20px;border-radius:8px;font-size:0.9rem;
  font-weight:500;cursor:pointer;border:none;transition:.15s;text-decoration:none}
.btn-primary{background:#2563eb;color:#fff}.btn-primary:hover{background:#1d4ed8}
.btn-secondary{background:rgba(255,255,255,0.07);border:1px solid rgba(255,255,255,0.12);color:#e8e9ed}
.btn-secondary:hover{background:rgba(255,255,255,0.12)}
.btn-danger{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.25);color:#f87171}
.btn-danger:hover{background:rgba(239,68,68,0.18)}
hr{border:0;border-top:1px solid rgba(255,255,255,0.07);margin:24px 0}
.actions{display:flex;gap:12px;flex-wrap:wrap;margin-top:16px}
footer{text-align:center;padding:24px;font-size:0.78rem;color:#374151;
  border-top:1px solid rgba(255,255,255,0.06);margin-top:40px}
        )";
    };

    // ── Page builder ─────────────────────────────────────────────────────────
    auto buildPage = [&sharedCss](const std::string& title,
                                   const std::string& body,
                                   const std::string& username) -> std::string {
        std::stringstream nav;
        if (!username.empty()) {
            nav << "<span class='nav-user'>"
                << "<svg width='14' height='14' viewBox='0 0 24 24' fill='none' "
                << "stroke='currentColor' stroke-width='2'>"
                << "<circle cx='12' cy='8' r='4'/>"
                << "<path d='M4 20c0-4 3.6-7 8-7s8 3 8 7'/></svg> "
                << username << "</span>"
                << "<a href='/auth/logout' class='nav-btn danger'>Sign Out</a>";
        }

        std::stringstream html;
        html << "<!DOCTYPE html><html lang='en'><head>"
             << "<meta charset='UTF-8'>"
             << "<meta name='viewport' content='width=device-width,initial-scale=1'>"
             << "<title>" << title << " — SNode.C</title>"
             << "<link rel='preconnect' href='https://fonts.googleapis.com'>"
             << "<style>" << sharedCss() << "</style>"
             << "</head><body>"
             << "<header>"
             << "<a href='/' class='header-logo'>"
             << "<svg width='22' height='22' viewBox='0 0 24 24' fill='none' "
             << "stroke='currentColor' stroke-width='2'>"
             << "<path d='M12 2L2 7l10 5 10-5-10-5M2 17l10 5 10-5M2 12l10 5 10-5'/>"
             << "</svg>SNode.C <span class='header-badge'>Protected App</span>"
             << "</a>"
             << "<nav class='header-nav'>" << nav.str() << "</nav>"
             << "</header>"
             << "<main>" << body << "</main>"
             << "<footer>SNode.C Protected Web App &nbsp;|&nbsp; "
             << "SSO/MFA Demo &nbsp;|&nbsp; Master Thesis Jan Eberwein</footer>"
             << "</body></html>";
        return html.str();
    };

    // ── PKCE helper: generate verifier + challenge ────────────────────────────
    auto generatePkce = [](std::string& verifier, std::string& challenge) {
        static constexpr char CHARS[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, static_cast<int>(sizeof(CHARS)) - 2);
        verifier.clear();
        verifier.reserve(64);
        for (int i = 0; i < 64; ++i) {
            verifier += CHARS[dis(gen)];
        }

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(verifier.data()), verifier.size(), hash);

        static constexpr char B64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        challenge.clear();
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i += 3) {
            unsigned int b = (static_cast<unsigned int>(hash[i]) << 16)
                | (i + 1 < SHA256_DIGEST_LENGTH
                    ? static_cast<unsigned int>(hash[i + 1]) << 8 : 0U)
                | (i + 2 < SHA256_DIGEST_LENGTH
                    ? static_cast<unsigned int>(hash[i + 2]) : 0U);
            int rem = SHA256_DIGEST_LENGTH - i;
            challenge += B64[(b >> 18) & 0x3F];
            challenge += B64[(b >> 12) & 0x3F];
            if (rem > 1) { challenge += B64[(b >> 6) & 0x3F]; }
            if (rem > 2) { challenge += B64[b        & 0x3F]; }
        }
        for (char& c : challenge) {
            if (c == '+') { c = '-'; }
            else if (c == '/') { c = '_'; }
        }
    };

    // ========== ROUTES ==========

    // GET / — auto-redirect to SSO if no token, else show dashboard
    app.get("/", [&buildPage, &jwtVerifier, idpBaseUrl, appBaseUrl] APPLICATION(req, res) {
        std::string token = req->cookie("access_token");
        if (token.empty()) {
            res->redirect("/login");
            return;
        }

        snodec::auth::JwtClaims claims;
        std::string err;
        bool mfaVerified = false;
        std::string userEmail;
        if (jwtVerifier.verify(token, claims, err)) {
            mfaVerified = claims.mfaVerified;
            userEmail = claims.email;
        }

        std::string mfaStatus = mfaVerified ? "Verified" : "Single Factor";
        std::string mfaClass = mfaVerified ? "green" : "orange";
        std::string mfaDot = mfaVerified ? "dot-green" : "dot-orange";
        std::string mfaSub = mfaVerified ? "JWT · SSO · TOTP" : "JWT · SSO (No MFA)";

        std::string alertBox = "";
        if (!mfaVerified) {
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
                "<a href=\"" + idpBaseUrl + "/settings\" style=\"color:#fb923c; text-decoration:underline; font-weight:600;\">configure MFA in your Account Settings on the IdP</a>.</div>"
                "</div>";
        }

        std::string body =
            alertBox +
            "<h1 class='page-title'>Dashboard</h1>"
            "<p class='page-subtitle'>You are authenticated via the SNode.C Identity Provider</p>"
            "<div class='grid'>"
              "<div class='tile'>"
                "<div class='tile-label'>Auth Status</div>"
                "<div class='tile-value " + mfaClass + "'><span class='dot " + mfaDot + "'></span>" + mfaStatus + "</div>"
                "<div class='tile-sub'>" + mfaSub + "</div>"
              "</div>"
              "<div class='tile'>"
                "<div class='tile-label'>Protocol</div>"
                "<div class='tile-value'>OAuth 2.0</div>"
                "<div class='tile-sub'>Authorization Code + PKCE</div>"
              "</div>"
              "<div class='tile'>"
                "<div class='tile-label'>Second Factor</div>"
                "<div class='tile-value'>" + std::string(mfaVerified ? "TOTP" : "None") + "</div>"
                "<div class='tile-sub'>" + std::string(mfaVerified ? "RFC 6238 · HMAC-SHA1" : "MFA not configured or skipped") + "</div>"
              "</div>"
              "<div class='tile'>"
                "<div class='tile-label'>Token</div>"
                "<div class='tile-value'>JWT</div>"
                "<div class='tile-sub'>RS256 · Signed by IdP</div>"
              "</div>"
            "</div>"
            "<h2 style='font-size:1rem;font-weight:600;margin-bottom:16px'>Service Status</h2>"
            "<div class='card'>"
              "<div class='info-row'>"
                "<span class='info-label'>Identity Provider</span>"
                "<span class='green'><span class='dot dot-green'></span>Online · " + idpBaseUrl + "</span>"
              "</div>"
              "<div class='info-row'>"
                "<span class='info-label'>MFA Enforcement</span>"
                "<span class='" + mfaClass + "'><span class='dot " + mfaDot + "'></span>" + (mfaVerified ? "TOTP Verified" : "Single Factor Only") + "</span>"
              "</div>"
              "<div class='info-row'>"
                "<span class='info-label'>Protected App</span>"
                "<span class='green'><span class='dot dot-green'></span>Online · " + appBaseUrl + "</span>"
              "</div>"
            "</div>"
            "<div class='actions'>"
              "<a href='/' class='btn btn-secondary'>Refresh Dashboard</a>"
              + std::string(mfaVerified ? "" : "<a href='" + idpBaseUrl + "/settings' class='btn btn-primary' target='_blank'>Configure MFA (IdP Settings)</a>") +
              "<a href='" + idpBaseUrl + "/dashboard' class='btn btn-secondary' target='_blank'>"
                "Open IdP Dashboard</a>"
            "</div>";

        std::string headerName = formatUserDisplayName(claims.username, userEmail);
        res->send(buildPage("Dashboard", body, headerName));
    });

    // GET /login — initiate OAuth2 + PKCE flow
    app.get("/login", [&generatePkce, idpBaseUrl, appBaseUrl] APPLICATION(req, res) {
        std::string verifier, challenge;
        generatePkce(verifier, challenge);

        const char* httpsEnv = std::getenv("HTTPS_ENABLED");
        std::string secureFlag = (httpsEnv && std::string(httpsEnv) == "true") ? "; Secure" : "";
        res->set("Set-Cookie",
                 "pkce_verifier=" + verifier +
                 "; Path=/; HttpOnly; SameSite=Lax; Max-Age=600" + secureFlag);

        std::stringstream authUrl;
        authUrl << idpBaseUrl << "/oauth2/authorize"
                << "?client_id=" << "snodec-webapp"
                << "&redirect_uri=" << appBaseUrl << "/auth/callback"
                << "&response_type=code"
                << "&state=%2F"
                << "&code_challenge=" << challenge
                << "&code_challenge_method=S256";

        res->redirect(authUrl.str());
    });

    // GET /auth/callback — IdP redirects here after login
    app.get("/auth/callback", callbackHandler);

    // GET /auth/logout — clear local token, then chain to IdP for global SLO
    app.get("/auth/logout", [idpBaseUrl, appBaseUrl] APPLICATION(req, res) {
        const char* httpsEnv = std::getenv("HTTPS_ENABLED");
        std::string secureFlag = (httpsEnv && std::string(httpsEnv) == "true") ? "; Secure" : "";
        res->set("Set-Cookie",
                 "access_token=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax" + secureFlag);

        std::stringstream logoutUrl;
        logoutUrl << idpBaseUrl << "/auth/logout"
                  << "?redirect_uri=" << appBaseUrl << "/";
        res->redirect(logoutUrl.str());
    });

    // GET /profile — protected, shows JWT-extracted username
    app.get("/profile", authMiddleware, [&buildPage] APPLICATION(req, res) {
        std::string username, email;
        req->getAttribute<std::string>(
            [&username](std::string& val) { username = val; }, "X-Username");
        req->getAttribute<std::string>(
            [&email](std::string& val) { email = val; }, "X-Email");
        bool mfaVerified = false;
        req->getAttribute<bool>([&mfaVerified](bool val) { mfaVerified = val; }, "X-MfaVerified");

        std::stringstream body;
        body << "<h1 class='page-title'>User Profile</h1>"
             << "<p class='page-subtitle'>Your identity as verified by the SNode.C IdP</p>"
             << "<div class='card'>"
             << "<div class='info-row'><span class='info-label'>Username</span>"
             << "<span>" << (username.empty() ? "Unknown" : username) << "</span></div>";
        if (!email.empty()) {
            body << "<div class='info-row'><span class='info-label'>Email Address</span>"
                 << "<span>" << email << "</span></div>";
        }
        body << "<div class='info-row'><span class='info-label'>Authentication</span>"
             << "<span class='green'><span class='dot dot-green'></span>JWT + SSO</span></div>"
             << "<div class='info-row'><span class='info-label'>Second Factor Status</span>"
             << "<span class='" << (mfaVerified ? "green" : "orange") << "'><span class='dot " << (mfaVerified ? "dot-green" : "dot-orange") << "'></span>"
             << (mfaVerified ? "TOTP Verified" : "Single Factor (MFA Skipped/Not Enabled)") << "</span></div>"
             << "<div class='info-row'><span class='info-label'>Token Format</span>"
             << "<span>RS256 JWT</span></div>"
             << "</div>"
             << "<div class='actions'><a href='/' class='btn btn-secondary'>← Dashboard</a></div>";

        std::string headerName = formatUserDisplayName(username, email);
        res->send(buildPage("Profile", body.str(), headerName));
    });

    // GET /mfa/status — protected, shows MFA info
    app.get("/mfa/status", authMiddleware, [&buildPage] APPLICATION(req, res) {
        std::string username, email;
        req->getAttribute<std::string>(
            [&username](std::string& val) { username = val; }, "X-Username");
        req->getAttribute<std::string>(
            [&email](std::string& val) { email = val; }, "X-Email");
        bool mfaVerified = false;
        req->getAttribute<bool>([&mfaVerified](bool val) { mfaVerified = val; }, "X-MfaVerified");

        std::stringstream body;
        body << "<h1 class='page-title'>MFA Status</h1>"
             << "<p class='page-subtitle'>Multi-Factor Authentication configuration</p>"
             << "<div class='card'>"
             << "<div class='info-row'><span class='info-label'>TOTP (RFC 6238)</span>"
             << "<span class='green'><span class='dot dot-green'></span>Enabled</span></div>"
             << "<div class='info-row'><span class='info-label'>Algorithm</span>"
             << "<span>HMAC-SHA1</span></div>"
             << "<div class='info-row'><span class='info-label'>Validity Window</span>"
             << "<span>30 seconds</span></div>"
             << "<div class='info-row'><span class='info-label'>Compatible Apps</span>"
             << "<span>Google Authenticator, Authy</span></div>"
             << "</div>"
             << "<div class='actions'><a href='/' class='btn btn-secondary'>← Dashboard</a></div>";

        std::string headerName = formatUserDisplayName(username, email);
        res->send(buildPage("MFA Status", body.str(), headerName));
    });

    // ── Start server ──────────────────────────────────────────────────────────
    app.listen(APP_PORT,
               [](const express::legacy::in::WebApp::SocketAddress& addr,
                  const core::socket::State& state) {
                   if (state == core::socket::State::OK) {
                       VLOG(0) << "SSO-MFA Protected App listening on " << addr.toString();
                   } else {
                       LOG(ERROR) << "Failed to start: " << addr.toString();
                   }
               });

    return core::SNodeC::start();
}
