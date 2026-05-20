# SSO and Multi-Factor Authentication for SNode.C Framework

**Author:** Jan Eberwein  

---

### Canonical Environment Configuration

| Environment | IdP Base URL | IdP Port | Protected App Port | JWT Issuer | Database |
|-------------|--------------|----------|-------------------|------------|----------|
| **Local Development** | `http://localhost:8083` | 8083 | 8084 | `http://localhost:8083` | `localhost:3306` |
| **Production** | `https://idp.snodec.io` | 443 | 8084 | `https://idp.snodec.io` | Cloud DB |
| **Standalone Mode** | N/A (no auth) | N/A | 8080 | N/A | N/A |

### Repository Structure

```
snode.c/
├── src/
│   ├── auth/              # SSO/MFA library (JWT, TOTP, middleware)
│   │   ├── JwtSigner.cpp/h
│   │   ├── JwtVerifier.cpp/h
│   │   ├── Totp.cpp/h
│   │   └── AuthMiddleware.cpp/h
│   ├── apps/
│   │   ├── auth_idp/      # Identity Provider (entrypoint: IdpServer.cpp)
│   │   └── protected_webapp/  # Example protected app
│   ├── core/              # Event loop (platform-aware: epoll/select)
│   └── net/               # Networking layer
├── build/                 # Build output (created by cmake)
└── keys/                  # RSA keys for JWT signing
```

### Run Order (Local Development)

```bash
# 1. Start MariaDB
brew services start mariadb  # macOS
# OR
sudo systemctl start mariadb  # Linux

# 2. Initialize database
mysql -u root -e "CREATE DATABASE IF NOT EXISTS snodec_auth;"
mysql -u root snodec_auth < src/apps/auth_idp/database/schema.sql
mysql -u root snodec_auth < src/apps/auth_idp/database/seed.sql

# 3. Start IdP (MUST start first)
cd build
./src/apps/auth_idp/auth_idp
# Should see: "IdP listening on port 8083"

# 4. Start protected app (in new terminal)
./src/apps/protected_webapp/protected_webapp
# Should see: "Protected app listening on port 8084"

# 5. Access
open http://localhost:8084
# Will redirect to http://localhost:8083/oauth2/authorize
```

### Smoke Tests

```bash
# Health check
curl http://localhost:8083/health
# Expected: {"status":"ok","service":"snodec-idp","version":"1.0.0"}

# Login flow (interactive)
curl -c cookies.txt -L http://localhost:8084/dashboard
# Should redirect to IdP login page

# Token endpoint (after getting auth code)
curl -X POST http://localhost:8083/oauth2/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "code_verifier=PKCE_VERIFIER" \
  -d "redirect_uri=http://localhost:8084/callback"
# Expected: {"access_token":"eyJ...","token_type":"Bearer","expires_in":3600}
```

### Critical Invariants

> [!CAUTION]
> **Breaking these will cause authentication failures**

1. **Redirect URI Exact Match**: `redirect_uri` parameter must exactly match an entry in the IdP's allow-list (no trailing slashes, no query params)
2. **PKCE S256 Default**: All OAuth2 flows REQUIRE `code_challenge` with method `S256` (SHA-256)
3. **JWT Signature Verification**: Protected apps MUST verify JWT signature with IdP's public key
4. **Cookie Flags**: Session cookies MUST have `HttpOnly` flag; `Secure` flag required in production (HTTPS)
5. **TOTP Time Sync**: Server and client clocks must be within ±30 seconds for MFA codes
6. **Authorization Code TTL**: Auth codes expire in 10 minutes and are single-use only

---

## Table of Contents

1. [Introduction & Overview](#1-introduction--overview)
2. [Architecture](#2-architecture)
3. [Implementation Details](#3-implementation-details)
4. [Security Measures](#4-security-measures)
5. [Build & Development](#5-build--development)
6. [OpenWRT Deployment](#6-openwrt-deployment)
7. [Testing & Verification](#7-testing--verification)
8. [Known Limitations & Non-Goals](#8-known-limitations--non-goals)
9. [How to Extend](#9-how-to-extend)
10. [Future Work](#10-future-work)
11. [Appendix](#11-appendix)

---

## 1. Introduction & Overview

### 1.1 SNode.C Framework

SNode.C is a lightweight, event-driven C++ framework for building HTTP, WebSocket, and MQTT servers. It is designed for embedded systems and IoT applications, with a focus on:

- **Modular architecture** with express-like middleware
- **Cross-platform support** (Linux, OpenWRT, macOS for development)
- **Low memory footprint** suitable for embedded devices
- **Event-driven I/O** using epoll (Linux) or select (macOS/portable)

### 1.2 Thesis Objectives

This thesis extends SNode.C with a modern **Single Sign-On (SSO)** and **Multi-Factor Authentication (MFA)** system:

| Feature | Standard | Status |
|---------|----------|--------|
| OAuth2 Authorization Code Flow | RFC 6749 | ✅ Implemented |
| JWT Access Tokens | RFC 7519 | ✅ Implemented |
| TOTP Multi-Factor Authentication | RFC 6238 | ✅ Implemented |
| PKCE for Public Clients | RFC 7636 | ✅ Implemented |
| Auth Middleware | Express-style | ✅ Implemented |

> [!NOTE]
> **This is OAuth2 + JWT, NOT full OpenID Connect (OIDC)**
> 
> **Implemented:** OAuth2 authorization code flow, JWT access tokens, PKCE
> 
> **NOT Implemented:** OIDC `id_token`, `/.well-known/openid-configuration` discovery endpoint, `/userinfo` endpoint, OIDC scopes (`openid`, `profile`, `email`)
> 
> This design choice keeps the implementation lightweight and suitable for embedded systems. If you need OIDC features, see [Future Work](#10-future-work).

### 1.3 Target Environments

| Environment | Purpose | I/O Multiplexer | Notes |
|-------------|---------|-----------------|-------|
| **macOS** | Local development | `select` | `epoll` not available on macOS; `select` is portable fallback |
| **Linux** | Testing/CI | `epoll` | High-performance multiplexer |
| **OpenWRT** | Production deployment (GL.iNet Beryl AX) | `epoll` | Compiled for aarch64/mips |

---

## 2. Architecture

### 2.1 SSO/MFA as an Optional Extension

SNode.C can operate in two modes:

| Mode | Description | IdP Required |
|------|-------------|--------------|
| **Standalone Mode** | SNode.C runs without authentication. Applications are accessible directly on the local network. This is the default behavior of the original SNode.C framework. | No |
| **SSO/MFA Mode** | Applications are protected by OAuth2/JWT authentication with optional TOTP multi-factor authentication. Requires a centralized, always-online Identity Provider. | Yes (cloud-hosted) |

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     SNODE.C OPERATING MODES                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   MODE A: STANDALONE (No Authentication)                                     │
│   ───────────────────────────────────────                                    │
│                                                                              │
│   ┌───────────────┐                                                         │
│   │  Home Router  │     User accesses apps directly                         │
│   │  ───────────  │     No login required                                   │
│   │  SNode.C      │     Suitable for private/trusted networks               │
│   │  + MQTT Suite │                                                         │
│   │  + Dashboard  │◄────── http://192.168.1.1:8080 (port 8080)             │
│   └───────────────┘                                                         │
│                                                                              │
│   ════════════════════════════════════════════════════════════════════════  │
│                                                                              │
│   MODE B: SSO/MFA ENABLED (Requires Always-Online IdP)                       │
│   ─────────────────────────────────────────────────────                      │
│                                                                              │
│   ┌──────────────────────────────────────────────────────────┐              │
│   │          CENTRAL IDENTITY PROVIDER (Cloud)                │              │
│   │          https://idp.snodec.io (port 443)                │              │
│   │          Always Online - Handles all authentication       │              │
│   │                                                           │              │
│   │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │              │
│   │   │   Login     │  │ Registration│  │   Password  │      │              │
│   │   │   + MFA     │  │             │  │   Recovery  │      │              │
│   │   └─────────────┘  └─────────────┘  └─────────────┘      │              │
│   │                                                           │              │
│   │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │              │
│   │   │  OAuth2     │  │    TOTP     │  │    User     │      │              │
│   │   │  Tokens     │  │  Enrollment │  │  Database   │      │              │
│   │   └─────────────┘  └─────────────┘  └─────────────┘      │              │
│   │                                                           │              │
│   └──────────────────────────┬───────────────────────────────┘              │
│                              │ HTTPS (JWT tokens)                            │
│         ┌────────────────────┼────────────────────┐                         │
│         ▼                    ▼                    ▼                         │
│   ┌───────────────┐   ┌───────────────┐   ┌───────────────┐                 │
│   │  User A's     │   │  User B's     │   │  User C's     │                 │
│   │  Home Router  │   │  Home Router  │   │  Home Router  │                 │
│   │  ───────────  │   │  ───────────  │   │  ───────────  │                 │
│   │  SNode.C      │   │  SNode.C      │   │  SNode.C      │                 │
│   │  + SSO/MFA    │   │  + SSO/MFA    │   │  + SSO/MFA    │                 │
│   │  + Protected  │   │  + MQTT Suite │   │  + IoT Apps   │                 │
│   │    Apps       │   │  + Dashboard  │   │  + Dashboard  │                 │
│   │               │   │               │   │               │                 │
│   │  192.168.x.1  │   │  192.168.x.1  │   │  192.168.x.1  │                 │
│   └───────────────┘   └───────────────┘   └───────────────┘                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 When to Use SSO/MFA Mode

| Use Case | Recommended Mode |
|----------|------------------|
| Private home network, single user | Standalone |
| Shared home network, multiple users | SSO/MFA |
| Remote access to home router apps | SSO/MFA |
| IoT dashboard for family members | SSO/MFA |
| Development and testing | Standalone |
| Production deployment with security requirements | SSO/MFA |

**Important Requirements for SSO/MFA Mode:**

1. **Always-Online IdP**: The central Identity Provider must be accessible 24/7. If the IdP is down, users cannot authenticate to any SNode.C installation.

2. **Internet Connectivity**: The user's router must have internet access to communicate with the cloud-hosted IdP during login.

3. **Single Account, Multiple Routers**: Once registered at the IdP, a user can authenticate to any SNode.C installation using the same credentials.

### 2.3 Component Responsibilities

| Component | Location | Responsibility |
|-----------|----------|----------------|
| **Identity Provider** | Cloud (always online) | User registration, login, MFA, password reset, JWT issuance |
| **SNode.C Apps** | User's home router | Protected applications, JWT verification only (public key) |
| **User Database** | Cloud (with IdP) | Centralized user accounts accessible from anywhere |

### 2.4 IdP Deployment Options

For SSO/MFA mode, the IdP must be hosted on an always-online server:

#### Option A: Cloud VPS

Deploy the IdP binary to any cloud VPS (Hetzner, DigitalOcean, AWS, etc.):

```bash
# Deploy IdP to cloud VPS
ssh root@your-vps-ip
apt install mariadb-server
# Copy binaries, setup database, run IdP on port 443
systemctl enable snodec-idp
```

#### Option B: Cloudflare Tunnel

Zero-config secure tunnel from your local machine to the internet (useful for demos):

```bash
# Install Cloudflare Tunnel
brew install cloudflared     # macOS
apt install cloudflared      # Linux

# Create persistent tunnel
cloudflared tunnel login
cloudflared tunnel create snodec-idp

# Run tunnel (exposes localhost:8083 globally)
cloudflared tunnel --url http://localhost:8083
# Output: https://random-name.cfargotunnel.com
```

Benefits of Cloudflare Tunnel:
- Free tier available
- Automatic HTTPS
- No port forwarding needed
- Works behind NAT/firewalls

### 2.5 How It Works for End Users

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           END USER FLOW                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   1. USER INSTALLS SNODE.C ON THEIR ROUTER                                  │
│      ─────────────────────────────────────────                              │
│      • Downloads pre-compiled binary for OpenWRT                            │
│      • Configures IdP URL: https://idp.snodec.io                           │
│      • Copies public key for JWT verification                               │
│                                                                              │
│   2. USER REGISTERS (ONE-TIME) AT CENTRAL IDP                               │
│      ─────────────────────────────────────────                              │
│      • Visits https://idp.snodec.io/auth/register                          │
│      • Creates account with email/password                                  │
│      • Optionally enables TOTP MFA                                         │
│                                                                              │
│   3. USER ACCESSES THEIR LOCAL SNODE.C APP                                  │
│      ─────────────────────────────────────────                              │
│      • Opens http://192.168.1.1:8084 (local router)                        │
│      • SNode.C redirects to https://idp.snodec.io/oauth2/authorize         │
│      • User logs in at central IdP                                         │
│      • Receives JWT, redirected back to local app                          │
│      • Local SNode.C verifies JWT with public key                          │
│      • Access granted!                                                      │
│                                                                              │
│   4. FORGOT PASSWORD / ACCOUNT RECOVERY                                     │
│      ─────────────────────────────────────────                              │
│      • User visits https://idp.snodec.io/auth/forgot-password              │
│      • Receives email with reset link                                       │
│      • Resets password at central IdP                                       │
│      • Can now login from any SNode.C installation                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.6 Component Diagram (Detailed)

```
┌─────────────────────────────────────────────────────────────────────┐
│                         USER'S BROWSER                               │
└─────────────────────┬───────────────────────────────────┬───────────┘
                      │                               │
                      ▼                               ▼
┌─────────────────────────────┐     ┌─────────────────────────────────┐
│   LOCAL SNODE.C APP         │     │   CENTRAL IDENTITY PROVIDER     │
│   (User's Router)           │     │   (Cloud - Always Online)       │
│   Port: 8084                │     │   https://idp.snodec.io:443     │
│                             │     │                                 │
│   ┌───────────────────────┐ │     │   Endpoints:                    │
│   │    AuthMiddleware     │ │     │   • /auth/login                 │
│   │    ↓                  │ │────►│   • /auth/register              │
│   │    JwtVerifier        │ │ JWT │   • /auth/forgot-password       │
│   │    (Public Key Only)  │ │     │   • /auth/mfa                   │
│   └───────────────────────┘ │     │   • /auth/enroll/totp           │
│                             │     │   • /oauth2/authorize           │
│   Protected Routes:         │     │   • /oauth2/token               │
│   • /dashboard              │     │                                 │
│   • /devices                │     │   ┌──────────────────────┐      │
│   • /settings               │     │   │    JwtSigner         │      │
│   • /api/*                  │     │   │    (Private Key)     │      │
│                             │     │   └──────────────────────┘      │
│   Config:                   │     │                                 │
│   IDP_URL=https://idp...    │     │                                 │
│   PUBLIC_KEY=/etc/snodec/.. │     │                                 │
└─────────────────────────────┘     └────────────────┬────────────────┘
                                                     │
                                                     ▼
                                    ┌─────────────────────────────────┐
                                     │   Cloud Database                │
                                     │   (MariaDB / PostgreSQL)        │
                                     │                                 │
                                     │   Tables:                       │
                                     │   • user                        │
                                     │   • auth_code                   │
                                     │   • password_reset_token        │
                                     │   • email_verification          │
                                     │                                 │
                                     │   Note: JWTs are stateless,     │
                                     │   no access_token table needed  │
                                     └─────────────────────────────────┘
```

### 2.7 Authentication Flow

```
1. User visits protected page → No token → Redirect to IdP
2. User enters username/password at /auth/login
3. IdP verifies credentials (SHA-256 hash comparison)
4. If TOTP enabled → Show MFA page → User enters 6-digit code
5. IdP generates authorization code → Redirect to client with PKCE
6. Client exchanges code at /oauth2/token → Receives JWT
7. JWT stored in cookie → Access granted
```

### 2.8 Database Schema

#### Table: `user`
```sql
CREATE TABLE user (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,    -- SHA256 hash
    password_salt VARCHAR(255) NOT NULL,    -- Random salt
    totp_secret VARCHAR(32) DEFAULT NULL,   -- Base32 encoded
    totp_enabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

#### Table: `auth_code` (with PKCE support)
```sql
CREATE TABLE auth_code (
    id INT AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(255) NOT NULL UNIQUE,
    user_id INT NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope VARCHAR(255),
    state VARCHAR(255),
    code_challenge VARCHAR(255),             -- PKCE
    code_challenge_method VARCHAR(10),       -- S256 or plain
    expires_at TIMESTAMP NOT NULL,           -- 10 minute expiry
    FOREIGN KEY (user_id) REFERENCES user(id)
);
```

#### Table: `password_reset_token`
```sql
CREATE TABLE password_reset_token (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,     -- Secure random token
    expires_at TIMESTAMP NOT NULL,          -- 1 hour expiry
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user(id)
);
```

#### Table: `email_verification`
```sql
CREATE TABLE email_verification (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    verified BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMP NOT NULL,          -- 24 hour expiry
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user(id)
);
```

---

## 3. Implementation Details

### 3.1 Auth Library (`src/auth/`)

| File | Purpose |
|------|---------|
| `Totp.h/.cpp` | TOTP generation/verification (RFC 6238) |
| `JwtSigner.h/.cpp` | JWT token signing with RS256 |
| `JwtVerifier.h/.cpp` | JWT token verification |
| `AuthMiddleware.h/.cpp` | Express middleware for route protection |
| `UserContext.h/.cpp` | User identity container |
| `JwtAuthMiddleware.h` | Cookie extraction, PKCE generation, OAuth2 redirect |
| `OAuth2CallbackHandler.h` | Token exchange, cookie setting |

### 3.2 TOTP Implementation (RFC 6238)

```
Algorithm:   HMAC-SHA1
Secret:      160 bits (Base32 encoded)
Time Step:   30 seconds
Digits:      6
Drift:       ±1 step (accepts codes from -30s to +30s)
```

**QR Code URI Format:**
```
otpauth://totp/SNodeC:<username>?secret=<BASE32_SECRET>&issuer=SNodeC
```

### 3.3 JWT Structure

**Header:**
```json
{"alg":"RS256","typ":"JWT","kid":"snodec-key-2024"}
```

**Payload (Local Development):**
```json
{
  "iss": "http://localhost:8083",
  "sub": "user_id",
  "aud": "snodec-client",
  "exp": 1700000000,
  "username": "testuser",
  "scope": ["read", "write"]
}
```

**Payload (Production):**
```json
{
  "iss": "https://idp.snodec.io",
  "sub": "user_id",
  "aud": "snodec-client",
  "exp": 1700000000,
  "username": "testuser",
  "scope": ["read", "write"]
}
```

> [!IMPORTANT]
> The `iss` (issuer) claim MUST exactly match your IdP's configured base URL.

### 3.4 Identity Provider Endpoints

#### Core Authentication Endpoints

##### `GET /auth/login`

**Purpose:** Display login form

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `redirect` | string | No | URL to redirect after successful login |

**Response:**
- **200 OK**: HTML login form
- **Cookies:** None set at this stage

---

##### `POST /auth/login`

**Purpose:** Verify user credentials

**Parameters (form-encoded):**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `username` | string | Yes | User's username |
| `password` | string | Yes | User's password (plain text, hashed server-side) |
| `redirect` | string | No | URL to redirect after login |

**Security Checks:**
1. SHA-256 password hash comparison
2. Account lock after 5 failed attempts (future feature)

**Response:**
- **302 Found**: Redirect to `/auth/mfa` if TOTP enabled, or to `redirect` URL with session cookie
- **401 Unauthorized**: Invalid credentials
- **Cookies Set:** `session_id` (HttpOnly, SameSite=Lax)

**Example:**
```bash
curl -X POST http://localhost:8083/auth/login \
  -d "username=testuser" \
  -d "password=password" \
  -d "redirect=/dashboard"
# Response: 302 to /auth/mfa (if MFA enabled)
```

---

##### `POST /auth/mfa`

**Purpose:** Verify TOTP code

**Parameters (form-encoded):**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `totp_code` | string | Yes | 6-digit TOTP code |

**Security Checks:**
1. Session must exist from `/auth/login`
2. TOTP code verified with ±30s drift tolerance
3. Code is single-use (replay protection)

**Response:**
- **302 Found**: Redirect to original destination with authenticated session
- **401 Unauthorized**: Invalid TOTP code
- **Cookies Updated:** `session_id` upgraded to authenticated

**Example:**
```bash
curl -X POST http://localhost:8083/auth/mfa \
  -b "session_id=SESSION_FROM_LOGIN" \
  -d "totp_code=123456"
# Response: 302 to original redirect URL
```

---

##### `GET /auth/enroll/totp`

**Purpose:** Display TOTP enrollment (QR code)

**Authentication:** Requires valid session

**Response:**
- **200 OK**: HTML with TOTP secret and QR code
- **401 Unauthorized**: Not authenticated

**QR Code Format:**
```
otpauth://totp/SNodeC:<username>?secret=<BASE32_SECRET>&issuer=SNodeC
```

---

##### `POST /auth/enroll/totp/verify`

**Purpose:** Confirm TOTP setup by verifying first code

**Parameters (form-encoded):**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `totp_code` | string | Yes | 6-digit verification code |

**Security Checks:**
1. Verify code matches generated secret
2. Update user record to enable TOTP

**Response:**
- **302 Found**: Redirect to dashboard, TOTP enabled
- **400 Bad Request**: Invalid code

---

#### User Management Endpoints (Planned Future Work)

> [!NOTE]
> The following endpoints are specified for future implementation to allow self-service registration. Currently, users are managed via database seeding or CLI tools.

##### `GET /auth/register`

**Purpose:** Display registration form

**Response:**
- **200 OK**: HTML registration form

---

##### `POST /auth/register`

**Purpose:** Create new user account

**Parameters (form-encoded):**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `username` | string | Yes | Desired username (alphanumeric, 3-20 chars) |
| `email` | string | Yes | Valid email address |
| `password` | string | Yes | Password (min 8 chars) |
| `password_confirm` | string | Yes | Must match `password` |

**Security Checks:**
1. Username/email uniqueness
2. Password strength validation
3. Email format validation

**Response:**
- **302 Found**: Redirect to login, verification email sent
- **400 Bad Request**: Validation errors (username taken, weak password, etc.)

**Example:**
```bash
curl -X POST http://localhost:8083/auth/register \
  -d "username=newuser" \
  -d "email=user@example.com" \
  -d "password=SecurePass123" \
  -d "password_confirm=SecurePass123"
# Response: 302 to /auth/login
```

---

##### `GET /auth/verify-email?token=<TOKEN>`

**Purpose:** Verify email address via link

**Parameters (query string):**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | Yes | Email verification token from database |

**Response:**
- **200 OK**: Email verified, account activated
- **400 Bad Request**: Invalid or expired token

---

##### `GET /auth/forgot-password`

**Purpose:** Display password reset request form

**Response:**
- **200 OK**: HTML form

---

##### `POST /auth/forgot-password`

**Purpose:** Send password reset email

**Parameters (form-encoded):**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `email` | string | Yes | User's registered email |

**Response:**
- **200 OK**: "Check your email" message (even if email doesn't exist, to prevent enumeration)

**Example:**
```bash
curl -X POST http://localhost:8083/auth/forgot-password \
  -d "email=testuser@example.com"
# Response: 200 OK (reset email sent if account exists)
```

---

##### `GET /auth/reset-password?token=<TOKEN>`

**Purpose:** Display password reset form

**Parameters (query string):**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | Yes | Reset token from email |

**Response:**
- **200 OK**: HTML password reset form
- **400 Bad Request**: Invalid or expired token

---

##### `POST /auth/reset-password`

**Purpose:** Set new password

**Parameters (form-encoded):**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token` | string | Yes | Reset token |
| `password` | string | Yes | New password |
| `password_confirm` | string | Yes | Must match `password` |

**Response:**
- **302 Found**: Redirect to login, password updated
- **400 Bad Request**: Invalid token or weak password

---

#### OAuth2 Endpoints

##### `GET /oauth2/authorize`

**Purpose:** OAuth2 authorization endpoint (PKCE required)

**Parameters (query string):**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `response_type` | string | Yes | Must be `code` |
| `client_id` | string | Yes | Client identifier |
| `redirect_uri` | string | Yes | Must match allow-list exactly |
| `scope` | string | No | Space-separated scopes (default: `read write`) |
| `state` | string | Yes | CSRF token, returned unchanged |
| `code_challenge` | string | Yes | Base64URL(SHA256(code_verifier)) |
| `code_challenge_method` | string | Yes | Must be `S256` |

**Security Checks:**
1. `redirect_uri` exact match against allow-list
2. PKCE `code_challenge` required
3. User must be authenticated (redirects to `/auth/login` if not)

**Response:**
- **302 Found**: Redirect to `redirect_uri?code=AUTH_CODE&state=STATE`
- **400 Bad Request**: Missing or invalid parameters
- **403 Forbidden**: Invalid `redirect_uri`

**Example:**
```bash
curl -L "http://localhost:8083/oauth2/authorize
response_type=code
&client_id=snodec-client
&redirect_uri=http://localhost:8084/callback
&scope=read write
&state=random_state
&code_challenge=CHALLENGE
&code_challenge_method=S256"
# Response: 302 to login (if not authenticated)
# After login: 302 to http://localhost:8084/callback?code=...&state=random_state
```

---

##### `POST /oauth2/token`

**Purpose:** Exchange authorization code for JWT access token

**Parameters (form-encoded):**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `grant_type` | string | Yes | Must be `authorization_code` |
| `code` | string | Yes | Authorization code from `/oauth2/authorize` |
| `redirect_uri` | string | Yes | Must match the original request |
| `code_verifier` | string | Yes | PKCE verifier (SHA-256 must match challenge) |
| `client_id` | string | Yes | Client identifier |

**Security Checks:**
1. Authorization code valid and not expired (10 min TTL)
2. Code is single-use
3. `redirect_uri` matches original request
4. PKCE: `SHA256(code_verifier) == code_challenge`

**Response (Success):**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InNub2RlYy1rZXktMjAyNCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**Response (Error):**
```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code expired"
}
```

**Status Codes:**
- **200 OK**: Token issued successfully
- **400 Bad Request**: Invalid parameters or PKCE verification failed
- **401 Unauthorized**: Invalid or expired authorization code

**Example:**
```bash
curl -X POST http://localhost:8083/oauth2/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE_FROM_CALLBACK" \
  -d "redirect_uri=http://localhost:8084/callback" \
  -d "code_verifier=ORIGINAL_VERIFIER" \
  -d "client_id=snodec-client"
# Response: {"access_token":"eyJ...","token_type":"Bearer","expires_in":3600}
```

---

##### `GET /health`

**Purpose:** Health check endpoint

**Response:**
```json
{
  "status": "ok",
  "service": "snodec-idp",
  "version": "1.0.0"
}
```

### 3.5 Registration Flow

```
1. User visits https://idp.snodec.io/auth/register
2. User enters: username, email, password
3. IdP creates user with email_verified=false
4. IdP sends verification email with token link
5. User clicks link → email verified
6. User can now login from any SNode.C installation
```

### 3.6 Password Recovery Flow

```
1. User visits https://idp.snodec.io/auth/forgot-password
2. User enters email address
3. IdP generates password_reset_token (1 hour expiry)
4. IdP sends reset link via email
5. User clicks link → enters new password
6. Password updated, token marked as used
7. User can login with new password
```

---

## 4. Security Measures

### 4.1 PKCE Enforcement (RFC 7636)

| Aspect | Implementation |
|--------|----------------|
| **Authorize Endpoint** | Requires `code_challenge` parameter |
| **Token Endpoint** | Verifies `code_verifier` against stored challenge |
| **Supported Methods** | S256 (default), plain |
| **Enforcement** | Required for ALL clients |

### 4.2 Redirect URI Validation

Exact-match allow-list prevents open redirect attacks:

```cpp
const std::set<std::string> ALLOWED_REDIRECT_URIS = {
    // Local development
    "http://localhost:8084/callback",      // Protected webapp (dev)
    "http://127.0.0.1:8084/callback",      // Protected webapp (IPv4 localhost)
    
    // Production examples (update for your deployment)
    "http://192.168.1.1:8084/callback",    // Protected webapp on router
    "http://192.168.1.1:8080/callback",    // Legacy dashboard (standalone mode)
};
```

> [!WARNING]
> **Trailing slashes and query parameters are NOT allowed**
> 
> ✅ Valid: `http://localhost:8084/callback`
> 
> ❌ Invalid: `http://localhost:8084/callback/`, `http://localhost:8084/callback?foo=bar`

### 4.3 Password Hashing

| Aspect | Implementation |
|--------|----------------|
| **Algorithm** | SHA256 with per-user salt |
| **Format** | `SHA256(password + salt)` |
| **Storage** | 64-character hex string |

> **Note:** SHA-256 was chosen for OpenWRT resource constraints. For production with more resources, Argon2id (OWASP recommended) should be considered.

### 4.4 Token & Code Lifetimes

| Token/Code | TTL | Security Rationale |
|------------|-----|-------------------|
| **Access Token** | 1 hour | Limits exposure window |
| **Authorization Code** | 10 minutes | Single-use, short-lived |
| **TOTP Window** | ±30 seconds | Handles clock drift |

### 4.5 OWASP Alignment

| OWASP Category | Implementation |
|----------------|----------------|
| **A01 Broken Access Control** | Auth middleware on all protected routes |
| **A02 Cryptographic Failures** | RS256 JWT signing, salted password hashes |
| **A05 Security Misconfiguration** | Redirect URI allow-list, PKCE enforcement |
| **A07 Identification Failures** | TOTP MFA, session management |

---

## 5. Build & Development

### 5.1 Cross-Platform Architecture

SNode.C is designed to run on both **Apple Silicon Macs** (for development) and **Linux/OpenWRT** (for production). This dual-platform support required specific adaptations.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      CROSS-PLATFORM BUILD MATRIX                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────────────┐          ┌───────────────────────────────────┐   │
│  │  DEVELOPMENT          │          │  PRODUCTION                       │   │
│  │  ─────────────        │          │  ──────────                       │   │
│  │                       │          │                                   │   │
│  │  macOS (Apple Silicon)│          │  Linux / OpenWRT                  │   │
│  │  • M1, M2, M3, M4    │          │  • x86_64, ARM64 (aarch64)        │   │
│  │  • Homebrew deps      │          │  • apt/opkg packages              │   │
│  │  • Native compilation │          │  • Native or cross-compilation   │   │
│  │                       │          │                                   │   │
│  │  I/O: select          │          │  I/O: epoll                       │   │
│  │  SSL: OpenSSL 3.x     │          │  SSL: OpenSSL 1.1/3.x             │   │
│  │  DB: MariaDB          │          │  DB: MariaDB                      │   │
│  │                       │          │                                   │   │
│  └───────────────────────┘          └───────────────────────────────────┘   │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    SHARED CODEBASE                                   │    │
│  │                                                                      │    │
│  │   • src/auth/        → JWT, TOTP, Middleware (platform-agnostic)    │    │
│  │   • src/apps/        → IdP, Protected WebApp (platform-agnostic)    │    │
│  │   • src/net/         → Networking layer (platform-aware)            │    │
│  │   • src/core/        → Event loop (platform-aware)                  │    │
│  │                                                                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Platform Differences

| Feature | macOS (Apple Silicon) | Linux / OpenWRT |
|---------|----------------------|-----------------|
| **I/O Multiplexer** | `select` (portable) | `epoll` (high performance) |
| **Socket Flags** | `O_NONBLOCK` via `fcntl()` | `SOCK_NONBLOCK` (native) |
| **Poll Events** | Standard `poll()` | `POLLRDHUP` (connection close) |
| **Architecture** | arm64 (Apple Silicon) | x86_64, aarch64, mips |
| **Package Manager** | Homebrew | apt, opkg |
| **SSL Library** | OpenSSL via Homebrew | System OpenSSL |

### 5.3 Code Changes for Dual-Platform Support

To enable SNode.C to compile and run on both platforms, the following modifications were made:

#### 5.3.1 CMake Configuration

The I/O multiplexer is selected at compile time:

```cmake
# In top-level CMakeLists.txt
option(SNODEC_IO_MULTIPLEXER "I/O multiplexer to use" "epoll")

if(APPLE)
    # macOS: epoll not available, use select
    set(SNODEC_IO_MULTIPLEXER "select" CACHE STRING "" FORCE)
elseif(UNIX)
    # Linux: use high-performance epoll
    set(SNODEC_IO_MULTIPLEXER "epoll" CACHE STRING "" FORCE)
endif()
```

#### 5.3.2 Include Path Fixes

Modified `src/net/CMakeLists.txt` for portable include paths:

```cmake
# Before (Linux-only):
target_include_directories(net PUBLIC "${PROJECT_SOURCE_DIR}")

# After (cross-platform):
target_include_directories(
    net PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>"
               "$<INSTALL_INTERFACE:include/snode.c>"
)
```

Modified `src/auth/CMakeLists.txt`:

```cmake
target_include_directories(auth PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>"
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>"
    "$<BUILD_INTERFACE:${OPENSSL_INCLUDE_DIRS}>"
    "$<INSTALL_INTERFACE:include/snode.c>"
)
```

#### 5.3.3 Platform-Specific Code (Core Framework)

The SNode.C core framework handles platform differences internally:

```cpp
// src/core/EventMultiplexer.cpp (conceptual)
#if defined(__linux__)
    #include <sys/epoll.h>
    // Use epoll for high-performance I/O
#elif defined(__APPLE__)
    #include <sys/select.h>
    // Use select for portability
#endif
```

### 5.4 Apple Silicon Mac Setup

#### Prerequisites

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install cmake openssl@3 mariadb libmagic nlohmann-json

# Start MariaDB
brew services start mariadb
```

#### Build Commands

```bash
cd snode.c
mkdir -p build && cd build

# Configure with select multiplexer (required for macOS)
cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DSNODEC_SSO_MFA=ON \
    -DSNODEC_IO_MULTIPLEXER=select \
    -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)

# Build using all CPU cores
cmake --build . -j$(sysctl -n hw.ncpu)
```

#### Run Locally

```bash
# Terminal 1: Start IdP
./src/apps/auth_idp/auth_idp

# Terminal 2: Start Protected WebApp
./src/apps/protected_webapp/protected_webapp

# Access in browser
open http://localhost:8084
```

#### Database Setup

```bash
# Create database and tables
mysql -u root -e "CREATE DATABASE IF NOT EXISTS snodec_auth;"
mysql -u root snodec_auth < src/apps/auth_idp/database/schema.sql
mysql -u root snodec_auth < src/apps/auth_idp/database/seed.sql

# Verify users were created
mysql -u root snodec_auth -e "SELECT id, username, email FROM user;"
```

### 5.5 Linux Native Build

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt update
sudo apt install cmake g++ libssl-dev libmariadb-dev libmagic-dev nlohmann-json-dev

# Build with epoll (default on Linux)
cd snode.c
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DSNODEC_SSO_MFA=ON
cmake --build . -j$(nproc)
```

### 5.6 Development Workflow

The recommended workflow for developing on Mac and deploying to OpenWRT:

```
┌────────────────────────────────────────────────────────────────────────┐
│                    DEVELOPMENT → PRODUCTION WORKFLOW                    │
├────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   1. DEVELOP ON MAC                                                     │
│      ─────────────────                                                  │
│      • Write code on Apple Silicon Mac                                  │
│      • Build with: cmake .. -DSNODEC_IO_MULTIPLEXER=select             │
│      • Test locally with MariaDB                                        │
│      • Debug with Xcode or lldb                                         │
│                                                                         │
│   2. CROSS-COMPILE FOR OPENWRT                                          │
│      ──────────────────────────                                         │
│      • Use Docker-based cross-compilation environment                   │
│      • Build with: cmake .. -DSNODEC_IO_MULTIPLEXER=epoll              │
│      • Target: aarch64 (ARM64) or mips (depending on router)           │
│                                                                         │
│   3. DEPLOY TO ROUTER                                                   │
│      ────────────────────                                               │
│      • scp binaries to router                                           │
│      • Install dependencies (MariaDB, OpenSSL)                          │
│      • Copy RSA keys and database schema                                │
│      • Start services                                                   │
│                                                                         │
│   4. TEST END-TO-END                                                    │
│      ─────────────────                                                  │
│      • Access protected app via router IP                               │
│      • Verify OAuth2 flow with central IdP                              │
│      • Test MFA enrollment and verification                             │
│                                                                         │
└────────────────────────────────────────────────────────────────────────┘
```

### 5.7 Problems Encountered & Solutions

#### Problem 1: `sys/epoll.h` file not found (macOS)

**Error:**
```
fatal error: 'sys/epoll.h' file not found
```

**Cause:** `epoll` is Linux-only. macOS uses `kqueue`.

**Solution:** Use `select` multiplexer for local development:
```bash
cmake .. -DSNODEC_IO_MULTIPLEXER=select
```

---

#### Problem 2: `SOCK_NONBLOCK` undeclared (macOS)

**Error:**
```
use of undeclared identifier 'SOCK_NONBLOCK'
```

**Cause:** Linux-specific socket flag.

**Solution:** Same as Problem 1 - use cross-compilation for production.

---

#### Problem 3: `POLLRDHUP` not found (macOS)

**Error:**
```
use of undeclared identifier 'POLLRDHUP'
```

**Solution:** Use `select` multiplexer or cross-compile.

---

#### Problem 4: `net/phy/PhysicalSocket.h` file not found

**Error:**
```
fatal error: 'net/phy/PhysicalSocket.h' file not found
```

**Cause:** CMake include path using `${PROJECT_SOURCE_DIR}` instead of relative path.

**Solution:** Modified `src/net/CMakeLists.txt`:
```cmake
target_include_directories(
    net PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>"
               "$<INSTALL_INTERFACE:include/snode.c>"
)
```

---

#### Problem 5: `utils/base64.h` not found

**Cause:** Include path not configured correctly.

**Solution:** Updated `src/auth/CMakeLists.txt`:
```cmake
target_include_directories(auth PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>"
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>"
)
```

---

#### Problem 6: MySQL connection refused

**Error:**
```
MySQL error: Can't connect to MySQL server on 'localhost' (61)
```

**Solution:**
```bash
brew services start mariadb
mysql -u root -e "CREATE DATABASE snodec_auth;"
```

---

#### Problem 7: TOTP code always rejected

**Cause:** Time synchronization issue.

**Solution:**
1. Sync server time: `ntpdate pool.ntp.org`
2. Implementation accepts ±1 time step drift

---

#### Problem 8: No QR code displayed

**Cause:** Initial implementation lacked QR generation.

**Solution:** Added client-side QR code generation using qrcode.js:
```html
<script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js"></script>
```

---

## 6. OpenWRT Deployment

### 6.1 Target Hardware

- **Router:** GL.iNet Beryl AX (MT3000)
- **Architecture:** aarch64 (ARM64)
- **OpenWRT Version:** 24.10.x
- **Target Platform:** `mediatek/filogic`

### 6.2 Cross-Compilation with Docker

```bash
# Build using Docker-based cross-compilation
docker run --name snodec-builder-manual --platform linux/amd64 --rm \
    -v openwrt-sdk-data:/openwrt/sdk \
    -v $(pwd):/src \
    openwrt-build /src/docker/build-manual.sh
```

### 6.3 Deployment Steps

```bash
ROUTER="root@192.168.1.1"

# Upload binaries
scp build-openwrt/src/apps/auth_idp/auth_idp $ROUTER:/usr/bin/
scp build-openwrt/src/apps/protected_webapp/protected_webapp $ROUTER:/usr/bin/

# Set permissions
ssh $ROUTER 'chmod +x /usr/bin/auth_idp /usr/bin/protected_webapp'

# Deploy keys
ssh $ROUTER 'mkdir -p /etc/snodec/keys'
scp src/apps/auth_idp/keys/*.pem $ROUTER:/etc/snodec/keys/

# Start services
ssh $ROUTER '/usr/bin/auth_idp &'
ssh $ROUTER '/usr/bin/protected_webapp &'
```

### 6.4 Router Database Setup

```bash
ssh $ROUTER 'opkg update && opkg install mariadb-server mariadb-client'
ssh $ROUTER 'mysql_install_db --user=root && /etc/init.d/mysqld start'
ssh $ROUTER 'mysql -e "CREATE DATABASE snodec_auth;"'
scp src/apps/auth_idp/database/schema.sql $ROUTER:/tmp/
ssh $ROUTER 'mysql snodec_auth < /tmp/schema.sql'
```

---

## 7. Testing & Verification

### 7.1 Test Credentials

| Username | Password | TOTP Secret | TOTP Enabled |
|----------|----------|-------------|--------------|
| testuser | password | JBSWY3DPEHPK3PXP | Yes |
| normaluser | password | - | No |
| admin | admin123 | KRUGC43FMZRW63LM | Yes |

### 7.2 Health Check

```bash
curl http://localhost:8083/health
# Expected: {"status":"ok","service":"snodec-idp","version":"1.0.0"}
```

### 7.3 Local Testing with Fake IdP (Localhost)

> [!TIP]
> **Complete from-scratch setup for local development on macOS or Linux**

#### Step 1: Install Dependencies

**macOS:**
```bash
brew install cmake openssl@3 mariadb libmagic nlohmann-json
brew services start mariadb
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt update
sudo apt install cmake g++ libssl-dev libmariadb-dev libmagic-dev nlohmann-json3-dev
sudo systemctl start mariadb
```

#### Step 2: Clone and Build

```bash
# Clone repository
git clone <your-repo-url> snode.c
cd snode.c

# Create build directory
mkdir -p build && cd build

# Configure (macOS)
cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DSNODEC_SSO_MFA=ON \
    -DSNODEC_IO_MULTIPLEXER=select \
    -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)

# Configure (Linux)
cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DSNODEC_SSO_MFA=ON \
    -DSNODEC_IO_MULTIPLEXER=epoll

# Build
cmake --build . -j$(nproc)  # Linux
# OR
cmake --build . -j$(sysctl -n hw.ncpu)  # macOS
```

#### Step 3: Initialize Database

```bash
# Create database
mysql -u root -e "CREATE DATABASE IF NOT EXISTS snodec_auth;"

# Load schema
mysql -u root snodec_auth < ../src/apps/auth_idp/database/schema.sql

# Load test users
mysql -u root snodec_auth < ../src/apps/auth_idp/database/seed.sql

# Verify users were created
mysql -u root snodec_auth -e "SELECT id, username, email, totp_enabled FROM user;"
# Expected output:
# +----+------------+------------------------+--------------+
# | id | username   | email                  | totp_enabled |
# +----+------------+------------------------+--------------+
# |  1 | testuser   | testuser@example.com   |            1 |
# |  2 | normaluser | normaluser@example.com |            0 |
# |  3 | admin      | admin@example.com      |            1 |
# +----+------------+------------------------+--------------+
```

#### Step 4: Generate RSA Keys (if not present)

```bash
cd ../src/apps/auth_idp/keys/
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem
cd ../../../../build
```

#### Step 5: Start Services

**Terminal 1 - Start IdP:**
```bash
./src/apps/auth_idp/auth_idp
# Expected output:
# [INFO] IdP Server starting...
# [INFO] Database connected: snodec_auth
# [INFO] Loaded RSA keys: kid=snodec-key-2024
# [INFO] Server listening on http://localhost:8083
```

**Terminal 2 - Start Protected App:**
```bash
./src/apps/protected_webapp/protected_webapp
# Expected output:
# [INFO] Protected WebApp starting...
# [INFO] IdP URL: http://localhost:8083
# [INFO] Loaded public key for JWT verification
# [INFO] Server listening on http://localhost:8084
```

#### Step 6: Smoke Test

```bash
# Test 1: Health check
curl http://localhost:8083/health
# Expected: {"status":"ok","service":"snodec-idp","version":"1.0.0"}

# Test 2: Protected page redirects to login
curl -v http://localhost:8084/dashboard 2>&1 | grep Location
# Expected: Location: http://localhost:8083/oauth2/authorize?...

# Test 3: Login page loads
curl http://localhost:8083/auth/login | grep "<form"
# Expected: HTML login form

# Test 4: Full OAuth2 flow (interactive - open in browser)
open http://localhost:8084/dashboard
# 1. Browser redirects to IdP login
# 2. Enter: testuser / password
# 3. MFA page appears → Enter TOTP code (use authenticator app)
# 4. Redirected back to /dashboard → Access granted!
```

#### Test User Credentials

| Username | Password | TOTP Secret | TOTP Enabled | Notes |
|----------|----------|-------------|--------------|-------|
| `testuser` | `password` | `JBSWY3DPEHPK3PXP` | Yes | For testing MFA flow |
| `normaluser` | `password` | - | No | For testing without MFA |
| `admin` | `admin123` | `KRUGC43FMZRW63LM` | Yes | Admin user with MFA |

**Generate TOTP codes:**
```bash
# Option 1: Use authenticator app (Google Authenticator, Authy, etc.)
# Scan QR code at http://localhost:8083/auth/enroll/totp

# Option 2: Command-line (requires oathtool)
oathtool --totp -b JBSWY3DPEHPK3PXP
# Output: 123456 (6-digit code, changes every 30s)
```

#### Common Local Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| `Address already in use` | Previous instance still running | `lsof -ti:8083 \| xargs kill -9` |
| `MySQL connection refused` | MariaDB not running | `brew services start mariadb` (macOS) |
| `User not found` | Database not seeded | Re-run `seed.sql` |
| `Invalid TOTP code` | Clock skew | Sync system time: `sudo sntp -sS time.apple.com` |
| `JWT signature invalid` | Public key mismatch | Verify `public_key.pem` matches `private_key.pem` |

---

### 7.4 Production Testing with Real IdP (V-Server + Domain)

> [!IMPORTANT]
> **Deploying to a real V-Server with domain for production testing**

#### Prerequisites

- VPS (Virtual Private Server) from Hetzner, DigitalOcean, AWS, etc.
- Domain name (e.g., `idp.snodec.io`)
- SSH access to server
- Basic server administration knowledge

#### Step 1: Server Setup

```bash
# SSH into server
ssh root@YOUR_SERVER_IP

# Update system
apt update && apt upgrade -y

# Install dependencies
apt install -y \
    build-essential \
    cmake \
    libssl-dev \
    libmariadb-dev \
    libmagic-dev \
    nlohmann-json3-dev \
    mariadb-server \
    nginx \
    certbot \
    python3-certbot-nginx

# Secure MariaDB
mysql_secure_installation
# Set root password, remove test databases, disable remote root login
```

#### Step 2: Configure DNS

**At your domain registrar (Namecheap, Cloudflare, etc.):**

```
Type: A
Name: idp
Value: YOUR_SERVER_IP
TTL: 300
```

**Verify DNS propagation:**
```bash
dig idp.snodec.io +short
# Should output: YOUR_SERVER_IP
```

#### Step 3: Build and Deploy IdP

```bash
# On local machine: build for Linux
docker run --rm -v$(pwd):/src -w /src \
    ubuntu:22.04 bash -c "\
    apt update && apt install -y cmake g++ libssl-dev libmariadb-dev && \
    mkdir -p build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release -DSNODEC_SSO_MFA=ON && \
    cmake --build . -j4"

# Copy binary to server
scp build/src/apps/auth_idp/auth_idp root@YOUR_SERVER_IP:/usr/local/bin/
scp -r src/apps/auth_idp/keys root@YOUR_SERVER_IP:/etc/snodec/
scp src/apps/auth_idp/database/*.sql root@YOUR_SERVER_IP:/tmp/

# On server: set permissions
chmod +x /usr/local/bin/auth_idp
chmod 600 /etc/snodec/keys/private_key.pem
```

#### Step 4: Configure Database

```bash
# On server
mysql -u root -p

CREATE DATABASE snodec_auth;
CREATE USER 'snodec'@'localhost' IDENTIFIED BY 'SECURE_PASSWORD_HERE';
GRANT ALL PRIVILEGES ON snodec_auth.* TO 'snodec'@'localhost';
FLUSH PRIVILEGES;
EXIT;

# Load schema
mysql -u snodec -p snodec_auth < /tmp/schema.sql

# Create production admin user (DO NOT use seed.sql in production!)
mysql -u snodec -p snodec_auth
INSERT INTO user (username, email, password_hash, password_salt, totp_enabled) 
VALUES (
    'admin',
    'admin@yourdomain.com',
    SHA2(CONCAT('YOUR_SECURE_PASSWORD', 'random_salt'), 256),
    'random_salt',
    TRUE
);
EXIT;
```

#### Step 5: Configure HTTPS with Let's Encrypt

```bash
# Install SSL certificate
certbot --nginx -d idp.snodec.io

# Create nginx config
cat > /etc/nginx/sites-available/idp << 'EOF'
server {
    listen 443 ssl http2;
    server_name idp.snodec.io;
    
    ssl_certificate /etc/letsencrypt/live/idp.snodec.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/idp.snodec.io/privkey.pem;
    
    location / {
        proxy_pass http://localhost:8083;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name idp.snodec.io;
    return 301 https://$server_name$request_uri;
}
EOF

# Enable site
ln -s /etc/nginx/sites-available/idp /etc/nginx/sites-enabled/
nginx -t  # Test configuration
systemctl reload nginx
```

#### Step 6: Create Systemd Service

```bash
cat > /etc/systemd/system/snodec-idp.service << 'EOF'
[Unit]
Description=SNode.C Identity Provider
After=network.target mariadb.service

[Service]
Type=simple
User=root
WorkingDirectory=/usr/local/bin
ExecStart=/usr/local/bin/auth_idp
Restart=on-failure
RestartSec=10

Environment="IDP_BASE_URL=https://idp.snodec.io"
Environment="DB_HOST=localhost"
Environment="DB_USER=snodec"
Environment="DB_PASSWORD=SECURE_PASSWORD_HERE"
Environment="DB_NAME=snodec_auth"
Environment="JWT_PRIVATE_KEY_PATH=/etc/snodec/keys/private_key.pem"

[Install]
WantedBy=multi-user.target
EOF

# Start service
systemctl daemon-reload
systemctl enable snodec-idp
systemctl start snodec-idp

# Check status
systemctl status snodec-idp
journalctl -u snodec-idp -f  # View logs
```

#### Step 7: Production Verification Checklist

```bash
# ✅ 1. Health check
curl https://idp.snodec.io/health
# Expected: {"status":"ok","service":"snodec-idp","version":"1.0.0"}

# ✅ 2. HTTPS certificate valid
curl -I https://idp.snodec.io | grep "HTTP/2 200"
openssl s_client -connect idp.snodec.io:443 -servername idp.snodec.io < /dev/null | grep "Verify return code"
# Expected: Verify return code: 0 (ok)

# ✅ 3. Login page loads
curl https://idp.snodec.io/auth/login | grep "<form"

# ✅ 4. Registration works
curl -X POST https://idp.snodec.io/auth/register \
  -d "username=testprod" \
  -d "email=test@example.com" \
  -d "password=SecurePass123" \
  -d "password_confirm=SecurePass123"
# Expected: 302 redirect

# ✅ 5. User can login (interactive)
# Open: https://idp.snodec.io/auth/login
# Enter credentials → Should succeed

# ✅ 6. OAuth2 flow works
# Configure protected app with IDP_URL=https://idp.snodec.io
# Access protected app → Should redirect to IdP → Login → Redirect back

# ✅ 7. JWT signature validates
curl -X POST https://idp.snodec.io/oauth2/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "code_verifier=VERIFIER" \
  -d "redirect_uri=..." \
  | jq -r '.access_token' > token.txt

# Verify token locally (requires public key)
# JWT should have iss: "https://idp.snodec.io"
```

#### Production Security Checklist

- [x] HTTPS enabled (not HTTP)
- [x] SSL certificate valid (Let's Encrypt)
- [x] Firewall configured (only 80, 443, 22 open)
- [x] Database uses strong password
- [x] Admin user has strong password + MFA
- [x] `Secure` cookie flag enabled
- [x] Private key has restricted permissions (600)
- [x] Nginx security headers configured
- [x] Regular backups configured
- [x] Monitoring/logging enabled

---

### 7.4 Performance Estimates

| Metric | Estimated Value |
|--------|-----------------|
| Login Latency (median) | 15-50ms |
| Token Endpoint Throughput | 200-500 req/s |
| JWT Verification Overhead | 2-5ms |
| TOTP Generation Time | <1ms |
| Memory Footprint (IdP) | 8-20MB RSS |

### 7.5 Configuration Reference

> [!TIP]
> **Complete configuration reference for all deployments**

#### Environment Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `IDP_BASE_URL` | string | `http://localhost:8083` | IdP base URL (must match JWT `iss`) |
| `DB_HOST` | string | `localhost` | Database hostname |
| `DB_PORT` | integer | `3306` | Database port |
| `DB_NAME` | string | `snodec_auth` | Database name |
| `DB_USER` | string | `root` | Database username |
| `DB_PASSWORD` | string | *(empty)* | Database password |
| `JWT_PRIVATE_KEY_PATH` | string | `keys/private_key.pem` | Path to RSA private key (IdP only) |
| `JWT_PUBLIC_KEY_PATH` | string | `keys/public_key.pem` | Path to RSA public key (all apps) |
| `JWT_KEY_ID` | string | `snodec-key-2024` | JWT `kid` header value |
| `JWT_AUDIENCE` | string | `snodec-client` | JWT `aud` claim |
| `JWT_TTL_SECONDS` | integer | `3600` | Access token lifetime (1 hour) |
| `AUTH_CODE_TTL_SECONDS` | integer | `600` | Authorization code lifetime (10 minutes) |
| `SESSION_COOKIE_NAME` | string | `session_id` | Session cookie name |
| `SESSION_TTL_SECONDS` | integer | `3600` | Session lifetime |
| `PROTECTED_APP_PORT` | integer | `8084` | Protected application port |
| `IDP_PORT` | integer | `8083` | IdP server port |

#### File Paths (Relative to Project Root)

| Path | Purpose |
|------|---------|
| `src/apps/auth_idp/IdpServer.cpp` | IdP server entrypoint |
| `src/apps/protected_webapp/ProtectedWebApp.cpp` | Example protected app |
| `src/auth/JwtSigner.{h,cpp}` | JWT signing implementation |
| `src/auth/JwtVerifier.{h,cpp}` | JWT verification implementation |
| `src/auth/Totp.{h,cpp}` | TOTP implementation |
| `src/auth/AuthMiddleware.{h,cpp}` | Express-style auth middleware |
| `src/apps/auth_idp/keys/private_key.pem` | RSA private key (2048-bit) |
| `src/apps/auth_idp/keys/public_key.pem` | RSA public key |
| `src/apps/auth_idp/database/schema.sql` | Database schema |
| `src/apps/auth_idp/database/seed.sql` | Test user data |

#### Cookie Configuration

| Cookie Name | HttpOnly | Secure | SameSite | Max-Age | Purpose |
|-------------|----------|--------|----------|---------|---------|
| `session_id` | ✅ Yes | Production only | `Lax` | 3600s | Session token after login |
| `access_token` | ✅ Yes | Production only | `Lax` | 3600s | JWT access token (alternative to Authorization header) |

> [!IMPORTANT]
> **Cookie Flags in Production**
> - `Secure` flag MUST be enabled for HTTPS deployments
> - `HttpOnly` flag prevents XSS attacks
> - `SameSite=Lax` prevents CSRF while allowing OAuth callbacks

#### Security Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| **Password Hash** | SHA-256 + per-user salt | OpenWRT resource constraints (Argon2id preferred for production) |
| **JWT Signature Algorithm** | RS256 (RSA-SHA256) | Assymetric signing allows public verification |
| **RSA Key Size** | 2048 bits | Industry standard (3072 bits for high security) |
| **TOTP Algorithm** | HMAC-SHA1 | RFC 6238 standard |
| **TOTP Time Step** | 30 seconds | RFC 6238 default |
| **TOTP Drift Tolerance** | ±1 step (±30s) | Compensates for clock skew |
| **PKCE Challenge Method** | S256 (SHA-256) | Required for all clients |
| **Authorization Code Lifetime** | 10 minutes | Single-use, short-lived |
| **Access Token Lifetime** | 1 hour | Balance between UX and security |

---

## 8. Known Limitations & Non-Goals

> [!NOTE]
> **Understanding what's NOT included helps prevent scope creep and sets clear expectations**

### Not Implemented (By Design)

| Feature | Reason |
|---------|--------|
| **OpenID Connect (OIDC)** | Out of scope; OAuth2 + JWT sufficient for this use case |
| `id_token` | OIDC-specific, not needed for stateless JWT access tokens |
| `/.well-known/openid-configuration` | OIDC discovery endpoint, not part of OAuth2 |
| `/userinfo` endpoint | OIDC-specific, user data in JWT claims instead |
| **Refresh Tokens** | Complexity vs benefit; short-lived sessions acceptable for routers |
| **Token Revocation** | JWTs are stateless; revocation requires database/cache (see Future Work) |
| **WebAuthn / FIDO2** | Hardware token support beyond thesis scope |
| **OAuth2 Scopes Enforcement** | Scopes stored in JWT but not enforced (application-level decision) |
| **Rate Limiting** | Production hardening feature (see Future Work) |
| **Account Lockout** | Future security enhancement |
| **Password Complexity Rules** | Basic length check only (8+ chars) |
| **Email SMTP Integration** | Email features stubbed (verification, password reset) |
| **Admin UI** | CLI/SQL for user management |
| **Multi-Tenancy** | Single IdP instance for all users |

### Platform Limitations

| Limitation | Affected Platform | Workaround |
|------------|-------------------|------------|
| **`epoll` not available** | macOS | Use `select` multiplexer (auto-detected by CMake) |
| **Cross-compilation complexity** | All platforms | Docker-based build environment |
| **OpenWRT package size** | OpenWRT routers | Static linking, stripped binaries |
| **Database on router** | OpenWRT routers | Cloud database recommended for IdP |

### Known Issues

> [!CAUTION]
> **Current implementation limitations**

1. **No HTTPS in Dev Mode**: Local development uses HTTP for simplicity; production MUST use HTTPS
2. **Hardcoded Allow-List**: Redirect URIs are compiled into source; requires rebuild to change
3. **Single Private Key**: No key rotation mechanism; key compromise requires full redeployment
4. **No Logout Endpoint**: Stateless JWTs cannot be invalidated without database-backed revocation
5. **Clock Skew Sensitivity**: TOTP requires client/server clocks within ±30s

### Non-Goals (Out of Scope)

- OAuth2 client credentials flow (server-to-server auth)
- OAuth2 implicit flow (deprecated, insecure)
- SAML integration
- LDAP/Active Directory integration
- Multi-factor options beyond TOTP (SMS, email codes, etc.)

---

## 9. How to Extend

> [!TIP]
> **Step-by-step recipes for common extension scenarios**

### Recipe 1: Add a Protected Route

**Goal:** Protect a new HTTP endpoint with JWT authentication

**Steps:**

1. **Add route in your application** (e.g., `ProtectedWebApp.cpp`):
   ```cpp
   app.get("/api/data", [](Request& req, Response& res) {
       res.json({{"data", "sensitive information"}});
   });
   ```

2. **Wrap route with AuthMiddleware**:
   ```cpp
   #include "auth/AuthMiddleware.h"
   
   auto authMiddleware = std::make_shared<AuthMiddleware>(
       "path/to/public_key.pem",
       "http://localhost:8083"  // Expected issuer
   );
   
   app.get("/api/data", authMiddleware, [](Request& req, Response& res) {
       // Access user info from context
       auto userCtx = req.context<UserContext>();
       res.json({
           {"data", "sensitive information"},
           {"user", userCtx->username}
       });
   });
   ```

3. **Test**:
   ```bash
   # Without token → 401
   curl http://localhost:8084/api/data
   # Expected: 401 Unauthorized
   
   # With valid token → 200
   curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
        http://localhost:8084/api/data
   # Expected: {"data":"sensitive information","user":"testuser"}
   ```

**Acceptance Criteria:**
- ✅ Unauthenticated requests return 401
- ✅ Requests with invalid JWT return 401
- ✅ Requests with valid JWT return 200 + data
- ✅ User context available in route handler

---

### Recipe 2: Add a New JWT Claim

**Goal:** Include custom user metadata in JWT tokens

**Steps:**

1. **Modify `JwtSigner.cpp`** to add claim during token generation:
   ```cpp
   // In sign() method, after existing claims:
   nlohmann::json claims = {
       {"iss", issuer},
       {"sub", userId},
       {"aud", audience},
       {"exp", expirationTime},
       {"username", username},
       {"scope", scopes},
       
       // Add custom claim:
       {"user_role", userRole},        // NEW
       {"account_tier", accountTier}   // NEW
   };
   ```

2. **Update database query** in `IdpServer.cpp` to fetch new fields:
   ```sql
   SELECT id, username, email, user_role, account_tier 
   FROM user WHERE username = ?
   ```

3. **Access claim in protected app** via `JwtVerifier`:
   ```cpp
   auto claims = jwtVerifier.verify(token);
   std::string role = claims["user_role"].get<std::string>();
   
   if (role == "admin") {
       // Admin-only logic
   }
   ```

4. **Test**:
   ```bash
   # Decode JWT to verify new claims
   curl -X POST http://localhost:8083/oauth2/token \
     -d "grant_type=authorization_code" \
     -d "code=..." -d "code_verifier=..." \
     | jq -r '.access_token' \
     | base64 -d | jq
   
   # Should show: {"user_role":"admin","account_tier":"premium",...}
   ```

**Acceptance Criteria:**
- ✅ JWT payload includes new claims
- ✅ New claims decoded correctly by `JwtVerifier`
- ✅ Application logic can access and use new claims
- ✅ No breaking changes to existing claims

---

### Recipe 3: Add Scope Enforcement

**Goal:** Restrict endpoints based on OAuth2 scopes

**Steps:**

1. **Create `ScopeMiddleware.h`**:
   ```cpp
   class ScopeMiddleware {
   public:
       ScopeMiddleware(std::vector<std::string> requiredScopes)
           : requiredScopes_(requiredScopes) {}
       
       void operator()(Request& req, Response& res, Next& next) {
           auto userCtx = req.context<UserContext>();
           if (!userCtx) {
               return res.status(401).send("Unauthorized");
           }
           
           // Check if user has any of the required scopes
           for (const auto& scope : requiredScopes_) {
               if (std::find(userCtx->scopes.begin(), 
                            userCtx->scopes.end(), 
                            scope) != userCtx->scopes.end()) {
                   return next();  // Scope found, continue
               }
           }
           
           res.status(403).send("Forbidden: insufficient scopes");
       }
   private:
       std::vector<std::string> requiredScopes_;
   };
   ```

2. **Apply to routes**:
   ```cpp
   auto writeScope = std::make_shared<ScopeMiddleware>(
       std::vector<std::string>{"write"}
   );
   
   app.post("/api/update", 
            authMiddleware,   // First: authenticate
            writeScope,       // Then: check scope
            [](Request& req, Response& res) {
       res.json({{"status", "updated"}});
   });
   ```

3. **Update authorization request** to include scope:
   ```
   /oauth2/authorize?...&scope=read write admin
   ```

4. **Test**:
   ```bash
   # Token with "read" scope only → 403
   curl -H "Authorization: Bearer READ_ONLY_TOKEN" \
        -X POST http://localhost:8084/api/update
   # Expected: 403 Forbidden: insufficient scopes
   
   # Token with "write" scope → 200
   curl -H "Authorization: Bearer WRITE_TOKEN" \
        -X POST http://localhost:8084/api/update
   # Expected: 200 {"status":"updated"}
   ```

**Acceptance Criteria:**
- ✅ Requests without required scope return 403
- ✅ Requests with required scope return 200
- ✅ Multiple scopes work (OR logic)
- ✅ Scope validation happens AFTER authentication

---

## 10. Future Work

| Feature | Priority | Notes |
|---------|----------|-------|
| **Rate Limiting** | High | Prevent brute-force attacks |
| **Argon2id Password Hashing** | Medium | OWASP recommended |
| **Token Revocation** | Medium | Logout/invalidation support |
| **Refresh Tokens** | Medium | Extended session support |
| **FIDO2/WebAuthn** | Low | Hardware token support |
| **Rate Limiting** | High | Prevent brute-force attacks |
| **User Registration** | High | Self-service account creation (currently seeded) |
| **Social Login** | High | OIDC integration (Google, GitHub, etc.) |
| **Argon2id Password Hashing** | Medium | OWASP recommended |
| **Token Revocation** | Medium | Logout/invalidation support |
| **Refresh Tokens** | Medium | Extended session support |
| **FIDO2/WebAuthn** | Low | Hardware token support |
| **Admin UI** | Low | User management interface |

---

## 11. Appendix

### 9.1 File Locations

| Component | Path |
|-----------|------|
| **IdP Server** | `src/apps/auth_idp/IdpServer.cpp` |
| **Protected WebApp** | `src/apps/protected_webapp/ProtectedWebApp.cpp` |
| **JWT Signer** | `src/auth/JwtSigner.h`, `src/auth/JwtSigner.cpp` |
| **JWT Verifier** | `src/auth/JwtVerifier.h`, `src/auth/JwtVerifier.cpp` |
| **TOTP Library** | `src/auth/Totp.h`, `src/auth/Totp.cpp` |
| **Auth Middleware** | `src/auth/AuthMiddleware.h`, `src/auth/AuthMiddleware.cpp` |
| **Private Key** | `src/apps/auth_idp/keys/private_key.pem` |
| **Public Key** | `src/apps/auth_idp/keys/public_key.pem` |
| **DB Schema** | `src/apps/auth_idp/database/schema.sql` |

### 9.2 RSA Key Generation

```bash
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

### 9.3 Original Documentation

All original source documentation files are preserved in the `implementation_docs/` folder:
- `answers.md` - Thesis reviewer Q&A
- `demo.md` - Mac local development guide
- `presentation.md` - Slide-format overview
- `snodecinstallation.md` - Installation guide

Additional documentation in `snode.c/`:
- `IMPLEMENTATION.md` - Detailed implementation docs
- `PROBLEMS.md` - Build issues and solutions
- `DOCUMENTATION.md` - Setup and usage guide
- `DEPLOYMENT.md` - OpenWRT deployment
- `SPECIFICATION MASTER THESIS.md` - Original requirements
