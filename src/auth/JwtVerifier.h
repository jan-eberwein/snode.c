#pragma once

#include "UserContext.h"

#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace snodec {
    namespace auth {

        struct JwtClaims {
            std::string subject;
            std::string username;
            std::vector<std::string> scopes;
            std::chrono::system_clock::time_point expiresAt;
            std::string issuer;
            std::string audience;
        };

        class JwtVerifier {
        public:
            JwtVerifier(const std::string& issuer, const std::string& audience, const std::string& publicKeyPem);

            bool verify(const std::string& token, JwtClaims& outClaims, std::string& error);

        private:
            std::string issuer_;
            std::string audience_;
            std::string publicKeyPem_;

            // Helper to decode base64url
            static std::string base64UrlDecode(const std::string& input);
        };

    } // namespace auth
} // namespace snodec
