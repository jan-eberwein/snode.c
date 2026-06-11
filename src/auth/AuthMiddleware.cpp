#include "AuthMiddleware.h"

#include "express/legacy/in/WebApp.h" // For MIDDLEWARE macro and other express types

#include <iostream>

namespace snodec {
    namespace auth {

        AuthMiddleware::AuthMiddleware(JwtVerifier& jwtVerifier)
            : jwtVerifier_(jwtVerifier) {
        }

        std::function<void(const std::shared_ptr<express::Request>&, const std::shared_ptr<express::Response>&, express::Next&)>
        AuthMiddleware::handler() {
            return [this] MIDDLEWARE(req, res, next) {
                std::string token;

                // 1. Check Authorization header
                if (req->headers.contains("Authorization")) {
                    std::string authHeader = req->headers["Authorization"];
                    if (authHeader.find("Bearer ") == 0) { // starts_with replacement
                        token = authHeader.substr(7);
                    }
                }

                // 2. Check Cookie (fallback)
                if (token.empty() && req->cookies.contains("access_token")) {
                    token = req->cookies["access_token"];
                }

                if (token.empty()) {
                    res->status(401).send("Unauthorized: No token provided");
                    return;
                }

                JwtClaims claims;
                std::string error;
                if (jwtVerifier_.verify(token, claims, error)) {
                    // Attach user context to request
                    UserContext userContext;
                    userContext.id = claims.subject;
                    userContext.username = claims.username;
                    userContext.scopes = claims.scopes;
                    userContext.email = claims.email;

                    req->setAttribute<UserContext>(userContext);
                    next();
                } else {
                    res->status(401).send("Unauthorized: " + error);
                }
            };
        }

        const UserContext* AuthMiddleware::getUser(const std::shared_ptr<express::Request>& req) {
            const UserContext* user = nullptr;
            req->getAttribute<UserContext>([&user](UserContext& ctx) {
                user = &ctx;
            });
            return user;
        }

    } // namespace auth
} // namespace snodec
