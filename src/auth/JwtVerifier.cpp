#include "JwtVerifier.h"

#include "utils/base64.h"

#include <algorithm>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <sstream>
#include <vector>

namespace snodec {
    namespace auth {

        JwtVerifier::JwtVerifier(const std::string& issuer, const std::string& audience, const std::string& publicKeyPem)
            : issuer_(issuer)
            , audience_(audience)
            , publicKeyPem_(publicKeyPem) {
        }

        std::string JwtVerifier::base64UrlDecode(const std::string& input) {
            std::string base64 = input;
            std::replace(base64.begin(), base64.end(), '-', '+');
            std::replace(base64.begin(), base64.end(), '_', '/');
            while ((base64.length() % 4) != 0) {
                base64 += '=';
            }
            return base64::base64_decode(base64);
        }

        // Simple helper to extract a string value from JSON by key
        // This is NOT a full JSON parser and assumes flat structure or unique keys
        static std::string getJsonString(const std::string& json, const std::string& key) {
            std::string searchKey = "\"" + key + "\":";
            size_t pos = json.find(searchKey);
            if (pos == std::string::npos) {
                return "";
            }

            pos += searchKey.length();
            // Skip whitespace
            while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n')) {
                pos++;
            }

            if (pos >= json.length()) {
                return "";
            }

            if (json[pos] == '"') {
                // String value
                pos++;
                size_t end = json.find('"', pos);
                if (end == std::string::npos) {
                    return "";
                }
                return json.substr(pos, end - pos);
            } else {
                // Number or boolean (simplified)
                size_t end = json.find_first_of(",}", pos);
                if (end == std::string::npos) {
                    return "";
                }
                return json.substr(pos, end - pos);
            }
        }

        // Helper to extract array of strings
        static std::vector<std::string> getJsonStringArray(const std::string& json, const std::string& key) {
            std::vector<std::string> result;
            std::string searchKey = "\"" + key + "\":";
            size_t pos = json.find(searchKey);
            if (pos == std::string::npos) {
                return result;
            }

            pos += searchKey.length();
            while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n')) {
                pos++;
            }

            if (pos < json.length() && json[pos] == '[') {
                pos++;
                while (pos < json.length() && json[pos] != ']') {
                    if (json[pos] == '"') {
                        pos++;
                        size_t end = json.find('"', pos);
                        if (end != std::string::npos) {
                            result.push_back(json.substr(pos, end - pos));
                            pos = end + 1;
                        }
                    }
                    pos++;
                }
            }
            return result;
        }

        bool JwtVerifier::verify(const std::string& token, JwtClaims& outClaims, std::string& error) {
            // 1. Split token
            size_t firstDot = token.find('.');
            size_t secondDot = token.find('.', firstDot + 1);

            if (firstDot == std::string::npos || secondDot == std::string::npos) {
                error = "Invalid token format";
                return false;
            }

            std::string headerB64 = token.substr(0, firstDot);
            std::string payloadB64 = token.substr(firstDot + 1, secondDot - firstDot - 1);
            std::string signatureB64 = token.substr(secondDot + 1);

            // 2. Verify header algorithm (prevent algorithm confusion attacks, RFC 7515)
            std::string headerJson = base64UrlDecode(headerB64);
            std::string alg = getJsonString(headerJson, "alg");
            if (alg != "RS256") {
                error = "Unsupported algorithm: " + alg + " (expected RS256)";
                return false;
            }

            // 3. Verify Signature
            std::string signedData = token.substr(0, secondDot);
            std::string signature = base64UrlDecode(signatureB64);

            BIO* bio = BIO_new_mem_buf(publicKeyPem_.data(), static_cast<int>(publicKeyPem_.length()));
            EVP_PKEY* pubKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);

            if (pubKey == nullptr) {
                error = "Failed to load public key";
                return false;
            }

            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (ctx == nullptr) {
                EVP_PKEY_free(pubKey);
                error = "Failed to create EVP context";
                return false;
            }

            if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pubKey) <= 0) {
                EVP_MD_CTX_free(ctx);
                EVP_PKEY_free(pubKey);
                error = "EVP init failed";
                return false;
            }

            if (EVP_DigestVerifyUpdate(ctx, signedData.data(), signedData.length()) <= 0) {
                EVP_MD_CTX_free(ctx);
                EVP_PKEY_free(pubKey);
                error = "EVP update failed";
                return false;
            }

            int verifyResult = EVP_DigestVerifyFinal(ctx, reinterpret_cast<const unsigned char*>(signature.data()), signature.length());

            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(pubKey);

            if (verifyResult != 1) {
                error = "Invalid signature";
                return false;
            }

            // 3. Parse Payload
            std::string payloadJson = base64UrlDecode(payloadB64);

            // 4. Verify Claims
            std::string iss = getJsonString(payloadJson, "iss");
            std::string aud = getJsonString(payloadJson, "aud");
            std::string expStr = getJsonString(payloadJson, "exp");

            if (iss != issuer_) {
                error = "Invalid issuer: " + iss;
                return false;
            }

            if (aud != audience_) {
                error = "Invalid audience: " + aud;
                return false;
            }

            long long exp = 0;
            try {
                exp = std::stoll(expStr);
            } catch (...) {
                error = "Invalid expiration";
                return false;
            }

            auto now = std::chrono::system_clock::now();
            auto expTime = std::chrono::system_clock::from_time_t(exp);

            if (now > expTime) {
                error = "Token expired";
                return false;
            }

            // 5b. Validate not-before (nbf) if present
            std::string nbfStr = getJsonString(payloadJson, "nbf");
            if (!nbfStr.empty()) {
                long long nbf = 0;
                try {
                    nbf = std::stoll(nbfStr);
                } catch (...) {
                    error = "Invalid nbf claim";
                    return false;
                }
                auto nbfTime = std::chrono::system_clock::from_time_t(nbf);
                if (now < nbfTime) {
                    error = "Token not yet valid (nbf)";
                    return false;
                }
            }

            // 5. Fill outClaims
            outClaims.issuer = iss;
            outClaims.audience = aud;
            outClaims.expiresAt = expTime;
            outClaims.subject = getJsonString(payloadJson, "sub");
            outClaims.username = getJsonString(payloadJson, "username"); // or preferred_username
            if (outClaims.username.empty()) {
                outClaims.username = getJsonString(payloadJson, "preferred_username");
            }
            outClaims.email = getJsonString(payloadJson, "email");
            std::string mfaVer = getJsonString(payloadJson, "mfa_verified");
            outClaims.mfaVerified = (mfaVer == "true");
            outClaims.scopes = getJsonStringArray(payloadJson, "scope"); // or scopes
            if (outClaims.scopes.empty()) {
                // Try space-separated string if array failed or empty
                std::string scopeStr = getJsonString(payloadJson, "scope");
                if (!scopeStr.empty()) {
                    std::stringstream ss(scopeStr);
                    std::string item;
                    while (std::getline(ss, item, ' ')) {
                        if (!item.empty()) {
                            outClaims.scopes.push_back(item);
                        }
                    }
                }
            }

            return true;
        }

    } // namespace auth
} // namespace snodec
