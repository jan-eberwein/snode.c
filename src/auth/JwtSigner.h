#pragma once

#include "JwtVerifier.h"

#include <string>

namespace snodec {
    namespace auth {

        class JwtSigner {
        public:
            JwtSigner(const std::string& issuer, const std::string& privateKeyPem);

            std::string sign(const JwtClaims& claims);

        private:
            std::string issuer_;
            std::string privateKeyPem_;

            static std::string base64UrlEncode(const std::string& input);
        };

    } // namespace auth
} // namespace snodec
