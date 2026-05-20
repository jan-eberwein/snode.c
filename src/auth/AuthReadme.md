# SNode.C Authentication & SSO System

This directory contains the bespoke, embedded-friendly Identity Provider (IdP) and Authentication Toolkit built for the SNode.C ecosystem. It provides robust OAuth 2.0 based Single Sign-On (SSO) with Multi-Factor Authentication (MFA) specifically designed for constrained environments (like the GL.iNet Beryl AX router).

## 1. System Overview

The auth system consists of two main components:
1.  **IdP Server (`src/apps/auth_idp`)**: The central authority that handles user registration, password hashing (SHA-256), TOTP generation/verification, session management, and issues signed JSON Web Tokens (JWTs).
2.  **Auth Middleware Toolkit (`src/auth`)**: A set of reusable C++ header-only libraries (`JwtAuthMiddleware.h`, `OAuth2CallbackHandler.h`) that any other SNode.C application can include to become a "Protected App".

## 2. Authentication Flow

The system implements the **OAuth 2.0 Authorization Code Flow with PKCE** (Proof Key for Code Exchange). 
1.  **Access**: A user visits a Protected App (e.g., MQTT Suite). The `JwtAuthMiddleware` checks for a valid JWT cookie.
2.  **Redirect**: If missing/invalid, it redirects to the IdP's `/oauth2/authorize` endpoint, securely passing a PKCE challenge.
3.  **Login**: The user authenticates at the IdP.
4.  **MFA**: If enabled, the user is prompted for a TOTP code. The IdP tracks MFA completion status.
5.  **Callback**: The IdP redirects back to the Protected App's callback URL with a short-lived authorization code.
6.  **Exchange**: The `OAuth2CallbackHandler` exchanges the code for a signed JWT (which includes the `mfa_verified` claim).
7.  **Protection**: Subsequent requests pass through the middleware, which validates the JWT signature cryptographically using the IdP's public key.

## 3. Integrating into Other SNode.C Projects (e.g., MQTT Suite)

Integrating this SSO system into another SNode.C project requires **minimal code changes**. You do not need to implement any login UIs or password databases in the connected app.

### Step 1: Include Headers
Include the middleware headers in your main application file:
```cpp
#include "auth/JwtAuthMiddleware.h"
#include "auth/OAuth2CallbackHandler.h"
```

### Step 2: Load the IdP Public Key
Load the RSA public key that the IdP uses to sign tokens:
```cpp
std::string publicKey = loadPubKeyFile("path/to/public_key.pem");
```

### Step 3: Configure the Middleware
Instantiate the middleware with the IdP details and your app's Client ID:
```cpp
using namespace snodec::auth::middleware;
using namespace snodec::auth::callback;

std::string idpBaseUrl = "http://192.168.8.1:8083"; // Router IP
std::string clientId = "mqtt-suite-client";

JwtAuthMiddleware authMiddleware("https://idp.snodec.local", clientId, publicKey);
authMiddleware.setIdpBaseUrl(idpBaseUrl);
authMiddleware.setCallbackPath("/auth/callback");

OAuth2CallbackHandler callbackHandler(idpBaseUrl + "/oauth2/token", clientId);
```

### Step 4: Protect Your Routes
Use SNode.C Express to mount the middleware on any route you want to protect. Unauthenticated users will automatically be redirected to the IdP.
```cpp
// 1. Mount the callback handler to process the return from IdP
app.get("/auth/callback", callbackHandler);

// 2. Protect sensitive routes
app.get("/dashboard", authMiddleware, [](req, res) {
    // Access verified claims injected by the middleware
    std::string username;
    req->getAttribute<std::string>([&username](std::string& val) { username = val; }, "X-Username");
    
    bool mfaVerified = false;
    req->getAttribute<bool>([&mfaVerified](bool val) { mfaVerified = val; }, "X-MfaVerified");

    // Implement Route-Level Authorization (e.g., demand MFA for admin routes)
    if (!mfaVerified) {
        res->status(403).send("MFA required for this action.");
        return;
    }

    res->send("Welcome to MQTT Suite, " + username);
});
```

### Step 5: Implement Single Logout (SLO)
To log out across the entire ecosystem, clear the local cookie and redirect to the IdP's logout endpoint:
```cpp
app.get("/logout", [idpBaseUrl](req, res) {
    res->set("Set-Cookie", "access_token=; Path=/; Max-Age=0; HttpOnly");
    res->redirect(idpBaseUrl + "/auth/logout?redirect_uri=http://your-app-url/");
});
```

## 4. MFA Behavior Across Connected Apps

The MFA logic is strictly handled by the IdP. The connected apps (like MQTT Suite) only read the resulting `mfa_verified` boolean claim from the JWT.
*   If an app requires high security, it can check `X-MfaVerified == true`. If false, the app can deny access or redirect the user to the IdP's `/auth/mfa` endpoint.
*   The SSO session spans all apps: logging into the Protected App automatically logs you into MQTT Suite without re-entering passwords or OTPs (assuming cookies are shared or the IdP session is active).
