#include "auth/JwtAuthMiddleware.h"
#include "auth/OAuth2CallbackHandler.h"
#include "core/SNodeC.h"
#include "express/legacy/in/WebApp.h"
#include "log/Logger.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

using namespace snodec;
using namespace snodec::auth::middleware;
using namespace snodec::auth::callback;

// Configuration
constexpr int APP_PORT = 8055;
constexpr int IDP_PORT = 8083;

int main(int argc, char* argv[]) {
    core::SNodeC::init(argc, argv);
    express::legacy::in::WebApp app("SSO-MFA-Test");

    // Load public key for JWT verification
    std::string publicKey;
    try {
        // Try multiple paths for public key
        std::vector<std::string> keyPaths = {
            "keys/public_key.pem",                   // Local (production/build)
            "src/apps/auth_idp/keys/public_key.pem", // Development (from project root)
            "../auth_idp/keys/public_key.pem"        // Development (relative sibling)
        };

        bool loaded = false;
        for (const auto& path : keyPaths) {
            try {
                publicKey = loadPublicKey(path);
                VLOG(0) << "Loaded public key from: " << path;
                loaded = true;
                break;
            } catch (...) {
                continue;
            }
        }

        if (!loaded) {
            throw std::runtime_error("Failed to load public key from any configured path");
        }
    } catch (const std::exception& e) {
        LOG(ERROR) << "Failed to load public key: " << e.what();
        return 1;
    }

    // JWT Auth Middleware
    JwtAuthMiddleware authMiddleware("https://idp.snodec.local", "snodec-webapp", publicKey);
    authMiddleware.setIdpBaseUrl("http://localhost:" + std::to_string(IDP_PORT));
    authMiddleware.setClientId("snodec-webapp");
    authMiddleware.setCallbackPath("/auth/callback");

    // OAuth2 Callback Handler
    OAuth2CallbackHandler callbackHandler("http://localhost:" + std::to_string(IDP_PORT) + "/oauth2/token", "snodec-webapp");

    // ========== ROUTES ==========

    // Main Page - Clean modern SSO/MFA Test UI
    app.get("/", [] APPLICATION(req, res) {
        // Check if user has valid token (cookie)
        // Check if user has valid token (cookie)
        std::string token = req->cookie("access_token");
        bool isLoggedIn = !token.empty();

        std::stringstream html;
        html << R"(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSO - MFA - SNode.C TEST</title>
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
            max-width: 480px;
            text-align: center;
        }
        h1 {
            font-size: 1.8rem;
            font-weight: 600;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }
        .subtitle {
            color: #888;
            font-size: 0.9rem;
            margin-bottom: 24px;
        }
        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 500;
            margin-bottom: 32px;
        }
        .status-badge.logged-out {
            background: rgba(239,68,68,0.15);
            color: #f87171;
            border: 1px solid rgba(239,68,68,0.3);
        }
        .status-badge.logged-in {
            background: rgba(34,197,94,0.15);
            color: #4ade80;
            border: 1px solid rgba(34,197,94,0.3);
        }
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }
        .logged-out .status-dot { background: #ef4444; }
        .logged-in .status-dot { background: #22c55e; }
        .divider {
            height: 1px;
            background: rgba(255,255,255,0.1);
            margin: 24px 0;
        }
        .section-title {
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #666;
            margin-bottom: 16px;
        }
        .btn {
            display: block;
            width: 100%;
            padding: 14px 20px;
            border: none;
            border-radius: 8px;
            font-size: 0.95rem;
            font-weight: 500;
            cursor: pointer;
            text-decoration: none;
            margin-bottom: 12px;
            transition: all 0.2s ease;
        }
        .btn-primary {
            background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
            color: white;
        }
        .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(59,130,246,0.4); }
        .btn-secondary {
            background: rgba(255,255,255,0.08);
            color: #e8e8e8;
            border: 1px solid rgba(255,255,255,0.15);
        }
        .btn-secondary:hover { background: rgba(255,255,255,0.12); }
        .btn-danger {
            background: rgba(239,68,68,0.15);
            color: #f87171;
            border: 1px solid rgba(239,68,68,0.3);
        }
        .btn-danger:hover { background: rgba(239,68,68,0.25); }
        .btn-success {
            background: rgba(34,197,94,0.15);
            color: #4ade80;
            border: 1px solid rgba(34,197,94,0.3);
        }
        .btn-success:hover { background: rgba(34,197,94,0.25); }
        .footer {
            margin-top: 32px;
            font-size: 0.75rem;
            color: #555;
        }
        .hidden { display: none !important; }
    </style>
</head>
<body>
    <div class="container">
        <h1>SSO / MFA Test</h1>
        
        <div class="status-badge )"
             << (isLoggedIn ? "logged-in" : "logged-out") << R"(">
            <span class="status-dot"></span>
            )"
             << (isLoggedIn ? "Authenticated" : "Not Authenticated") << R"(
        </div>

        <div class="divider"></div>

        <p class="section-title">Authentication</p>
        )" << (isLoggedIn ? "" : R"(<a href="/login" class="btn btn-primary">Login with SSO</a>)")
             << R"(
        )" << (isLoggedIn ? R"(<a href="/auth/logout" class="btn btn-danger">Logout</a>)" : "")
             << R"(

        <div class="divider"></div>

        <p class="section-title">Protected Resources</p>
        <a href="/profile" class="btn btn-secondary">View Profile</a>
        <a href="/dashboard" class="btn btn-secondary">Dashboard</a>

        )"
             << (isLoggedIn ? R"(
        <div class="divider"></div>
        <p class="section-title">MFA Settings</p>
        <a href="/mfa/status" class="btn btn-success">MFA Status</a>
        <a href="/mfa/setup" class="btn btn-secondary">Setup TOTP</a>
        <a href="/mfa/disable" class="btn btn-secondary">Disable MFA</a>
        )"
                            : "")
             << R"(

        <div class="footer">SNode.C</div>
    </div>
</body>
</html>)";
        res->send(html.str());
    });

    // Login redirect (initiates OAuth2 flow with PKCE)
    app.get("/login", [] APPLICATION(req, res) {
        // PKCE values - in production, generate randomly per request
        // code_verifier is the secret, code_challenge = base64url(sha256(code_verifier))
        // For demo: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" -> "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        std::string codeVerifier = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        std::string codeChallenge = "DSmbHrVIcI0EU05-BQxCe1bt-hXRNjejSEvdYbq_g4Q";
        std::string state = "sso_test_state";

        // Store code_verifier in cookie for callback handler to use
        res->set("Set-Cookie", "pkce_verifier=" + codeVerifier + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=600");

        std::stringstream authUrl;
        authUrl << "http://localhost:" << IDP_PORT << "/oauth2/authorize"
                << "?client_id=snodec-webapp"
                << "&redirect_uri=http://localhost:" << APP_PORT << "/auth/callback"
                << "&response_type=code"
                << "&state=" << state << "&code_challenge=" << codeChallenge << "&code_challenge_method=S256";

        res->redirect(authUrl.str());
    });

    // OAuth2 Callback
    app.get("/auth/callback", callbackHandler);

    // Logout
    app.get("/auth/logout", [] APPLICATION(req, res) {
        res->set("Set-Cookie", "access_token=; Path=/; Max-Age=0; HttpOnly");
        res->redirect("/");
    });

    // Profile (Protected)
    app.get("/profile", authMiddleware, [] APPLICATION(req, res) {
        std::string username;
        req->getAttribute<std::string>(
            [&username](std::string& val) {
                username = val;
            },
            "X-Username");

        std::stringstream html;
        html << R"(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Profile - SSO/MFA Test</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #1a1a2e; color: #e8e8e8; min-height: 100vh; display: flex; justify-content: center; align-items: center; }
        .card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 40px; max-width: 400px; text-align: center; }
        h1 { margin-bottom: 24px; }
        .info { background: rgba(34,197,94,0.15); border: 1px solid rgba(34,197,94,0.3); border-radius: 8px; padding: 16px; margin: 16px 0; }
        a { color: #3b82f6; text-decoration: none; }
    </style>
</head>
<body>
    <div class="card">
        <h1>User Profile</h1>
        <div class="info">
            <p><strong>Username:</strong> )"
             << (username.empty() ? "Unknown" : username) << R"(</p>
            <p><strong>Auth:</strong> JWT + SSO</p>
        </div>
        <a href="/">← Back to Home</a>
    </div>
</body>
</html>)";
        res->send(html.str());
    });

    // Dashboard (Protected)
    app.get("/dashboard", authMiddleware, [] APPLICATION(req, res) {
        std::string html = R"(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard - SSO/MFA Test</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #1a1a2e; color: #e8e8e8; min-height: 100vh; display: flex; justify-content: center; align-items: center; }
        .card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 40px; max-width: 500px; }
        h1 { margin-bottom: 24px; text-align: center; }
        .status { display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid rgba(255,255,255,0.1); }
        .status:last-child { border: none; }
        .ok { color: #4ade80; }
        a { color: #3b82f6; text-decoration: none; display: block; text-align: center; margin-top: 24px; }
    </style>
</head>
<body>
    <div class="card">
        <h1>System Dashboard</h1>
        <div class="status"><span>IdP Server</span><span class="ok">● Online</span></div>
        <div class="status"><span>JWT Verification</span><span class="ok">● Active</span></div>
        <div class="status"><span>TOTP Service</span><span class="ok">● Ready</span></div>
        <div class="status"><span>Session</span><span class="ok">● Valid</span></div>
        <a href="/">← Back to Home</a>
    </div>
</body>
</html>)";
        res->send(html);
    });

    // MFA Status
    app.get("/mfa/status", authMiddleware, [] APPLICATION(req, res) {
        std::string html = R"(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>MFA Status</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #1a1a2e; color: #e8e8e8; min-height: 100vh; display: flex; justify-content: center; align-items: center; }
        .card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 40px; max-width: 400px; text-align: center; }
        h1 { margin-bottom: 16px; }
        .badge { display: inline-block; padding: 8px 16px; border-radius: 20px; font-size: 0.9rem; margin: 16px 0; }
        .enabled { background: rgba(34,197,94,0.15); color: #4ade80; border: 1px solid rgba(34,197,94,0.3); }
        .disabled { background: rgba(239,68,68,0.15); color: #f87171; border: 1px solid rgba(239,68,68,0.3); }
        a { color: #3b82f6; text-decoration: none; display: block; margin-top: 24px; }
    </style>
</head>
<body>
    <div class="card">
        <h1>MFA Status</h1>
        <p>Multi-Factor Authentication</p>
        <div class="badge enabled">TOTP Enabled</div>
        <p style="color:#888; font-size: 0.85rem;">Using Google/Microsoft Authenticator</p>
        <a href="/">← Back to Home</a>
    </div>
</body>
</html>)";
        res->send(html);
    });

    // MFA Setup - Redirect to IdP for TOTP enrollment
    app.get("/mfa/setup", authMiddleware, [] APPLICATION(req, res) {
        // Get user_id from JWT claims (would need to extract from token in production)
        // For now, show instructions and link to IdP enrollment
        std::string html = R"(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Setup TOTP - SSO/MFA Test</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #1a1a2e; color: #e8e8e8; min-height: 100vh; display: flex; justify-content: center; align-items: center; }
        .card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 40px; max-width: 450px; text-align: center; }
        h1 { margin-bottom: 16px; }
        .info { background: rgba(59,130,246,0.15); border: 1px solid rgba(59,130,246,0.3); border-radius: 8px; padding: 16px; margin: 20px 0; text-align: left; }
        .info p { margin: 8px 0; color: #93c5fd; font-size: 0.9rem; }
        .btn { display: inline-block; padding: 14px 28px; background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 1rem; text-decoration: none; margin: 8px; }
        .btn:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(34,197,94,0.4); }
        .btn-secondary { background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.15); }
        a.back { color: #3b82f6; text-decoration: none; display: block; margin-top: 24px; }
    </style>
</head>
<body>
    <div class="card">
        <h1>🔐 Setup Two-Factor Authentication</h1>
        <p style="color:#888;">Add an extra layer of security to your account</p>
        
        <div class="info">
            <p><strong>How it works:</strong></p>
            <p>1. You'll scan a QR code with your authenticator app</p>
            <p>2. Enter the 6-digit code to verify setup</p>
            <p>3. Future logins will require both password + code</p>
        </div>
        
        <a href="http://localhost:)" +
                           std::to_string(IDP_PORT) + R"(/auth/enroll/totp?user_id=1" class="btn">Setup TOTP Now</a>
        
        <a href="/" class="back">← Back to Home</a>
    </div>
</body>
</html>)";
        res->send(html);
    });

    // MFA Disable - Simulated
    app.get("/mfa/disable", authMiddleware, [] APPLICATION(req, res) {
        std::string html = R"(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>MFA Disabled</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #1a1a2e; color: #e8e8e8; min-height: 100vh; display: flex; justify-content: center; align-items: center; }
        .card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 40px; max-width: 450px; text-align: center; }
        h1 { margin-bottom: 16px; color: #f87171; }
        p { color: #aaa; margin-bottom: 24px; }
        .btn { display: inline-block; padding: 12px 24px; background: rgba(255,255,255,0.08); color: #e8e8e8; border: 1px solid rgba(255,255,255,0.15); border-radius: 8px; text-decoration: none; }
        .btn:hover { background: rgba(255,255,255,0.12); }
    </style>
</head>
<body>
    <div class="card">
        <h1>MFA Disabled</h1>
        <p>Multi-Factor Authentication has been disabled for your account (Simulated).</p>
        <p style="font-size: 0.8rem; opacity: 0.7;">Note: In a real environment, this would call the IdP API.</p>
        <a href="/" class="btn">Return Home</a>
    </div>
</body>
</html>)";
        res->send(html);
    });

    // Start server
    app.listen(APP_PORT, [](const express::legacy::in::WebApp::SocketAddress& socketAddress, const core::socket::State& state) {
        if (state == core::socket::State::OK) {
            VLOG(0) << "SSO-MFA Test App listening on " << socketAddress.toString();
        } else {
            LOG(ERROR) << "Failed to start: " << socketAddress.toString();
        }
    });

    return core::SNodeC::start();
}
