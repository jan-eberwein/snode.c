#pragma once

#include "JwtVerifier.h"
#include "UserContext.h"
#include "express/Next.h"
#include "express/Request.h"
#include "express/Response.h"

#include <functional>
#include <memory>
#include <string>

namespace snodec {
    namespace auth {

        class AuthMiddleware {
        public:
            explicit AuthMiddleware(JwtVerifier& jwtVerifier);

            std::function<void(const std::shared_ptr<express::Request>&, const std::shared_ptr<express::Response>&, express::Next&)>
            handler();

            static const UserContext* getUser(const std::shared_ptr<express::Request>& req);

        private:
            JwtVerifier& jwtVerifier_;
        };

    } // namespace auth
} // namespace snodec
