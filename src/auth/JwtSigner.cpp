#include "JwtSigner.h"

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

        JwtSigner::JwtSigner(const std::string& issuer, const std::string& privateKeyPem)
            : issuer_(issuer)
            , privateKeyPem_(privateKeyPem) {
        }

        std::string JwtSigner::base64UrlEncode(const std::string& input) {
            std::string base64 = base64::base64_encode(reinterpret_cast<const unsigned char*>(input.data()), input.length());
            std::replace(base64.begin(), base64.end(), '+', '-');
            std::replace(base64.begin(), base64.end(), '/', '_');
            base64.erase(std::remove(base64.begin(), base64.end(), '='), base64.end());
            return base64;
        }

        std::string JwtSigner::sign(const JwtClaims& claims) {
            // 1. Header with kid (Key ID) for key rotation support
            std::string headerJson = R"({"alg":"RS256","typ":"JWT","kid":"snodec-key-2024"})";
            std::string headerB64 = base64UrlEncode(headerJson);

            // 2. Payload (RFC 7519 registered claims)
            std::stringstream ss;
            ss << "{";
            ss << "\"iss\":\"" << issuer_ << "\",";
            ss << "\"sub\":\"" << claims.subject << "\",";
            ss << "\"aud\":\"" << claims.audience << "\",";

            auto exp = std::chrono::system_clock::to_time_t(claims.expiresAt);
            auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            ss << "\"exp\":" << exp << ",";
            ss << "\"iat\":" << now << ",";  // Issued At (RFC 7519 §4.1.6)
            ss << "\"nbf\":" << now << ",";  // Not Before (RFC 7519 §4.1.5)

            ss << "\"username\":\"" << claims.username << "\",";
            if (!claims.email.empty()) {
                ss << "\"email\":\"" << claims.email << "\",";
            }
            ss << "\"mfa_verified\":" << (claims.mfaVerified ? "true" : "false") << ",";

            ss << "\"scope\":[";
            for (size_t i = 0; i < claims.scopes.size(); ++i) {
                ss << "\"" << claims.scopes[i] << "\"";
                if (i < claims.scopes.size() - 1)
                    ss << ",";
            }
            ss << "]";

            ss << "}";
            std::string payloadJson = ss.str();
            std::string payloadB64 = base64UrlEncode(payloadJson);

            // 3. Sign
            std::string dataToSign = headerB64 + "." + payloadB64;

            BIO* bio = BIO_new_mem_buf(privateKeyPem_.data(), static_cast<int>(privateKeyPem_.length()));
            EVP_PKEY* privKey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);

            if (!privKey) {
                std::cerr << "Failed to load private key" << std::endl;
                return "";
            }

            EVP_MD_CTX* ctx = EVP_MD_CTX_new();
            if (!ctx) {
                EVP_PKEY_free(privKey);
                return "";
            }

            if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, privKey) <= 0) {
                EVP_MD_CTX_free(ctx);
                EVP_PKEY_free(privKey);
                return "";
            }

            if (EVP_DigestSignUpdate(ctx, dataToSign.data(), dataToSign.length()) <= 0) {
                EVP_MD_CTX_free(ctx);
                EVP_PKEY_free(privKey);
                return "";
            }

            size_t sigLen = 0;
            if (EVP_DigestSignFinal(ctx, nullptr, &sigLen) <= 0) {
                EVP_MD_CTX_free(ctx);
                EVP_PKEY_free(privKey);
                return "";
            }

            std::vector<unsigned char> signature(sigLen);
            if (EVP_DigestSignFinal(ctx, signature.data(), &sigLen) <= 0) {
                EVP_MD_CTX_free(ctx);
                EVP_PKEY_free(privKey);
                return "";
            }

            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(privKey);

            std::string signatureStr(reinterpret_cast<char*>(signature.data()), sigLen);
            std::string signatureB64 = base64UrlEncode(signatureStr);

            return headerB64 + "." + payloadB64 + "." + signatureB64;
        }

    } // namespace auth
} // namespace snodec
