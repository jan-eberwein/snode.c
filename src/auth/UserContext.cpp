#include "UserContext.h"

#include <algorithm>

namespace snodec {
    namespace auth {

        bool UserContext::hasScope(const std::string& scope) const {
            return std::find(scopes.begin(), scopes.end(), scope) != scopes.end();
        }

    } // namespace auth
} // namespace snodec
