/*
 * SNode.C - A Slim Toolkit for Network Communication
 * Copyright (C) Volker Christian <me@vchrist.at>
 *               2020, 2021, 2022, 2023, 2024, 2025, 2026
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#define _DARWIN_C_SOURCE
#include "core/system/poll.h"

#include <csignal>
#include <ctime>
#include <sys/poll.h>

#ifndef DOXYGEN_SHOULD_SKIP_THIS

#include <cerrno>

// IWYU pragma: no_include <time.h>

#endif /* DOXYGEN_SHOULD_SKIP_THIS */

namespace core::system {

    int poll(pollfd* fds, nfds_t nfds, int timeout) {
        errno = 0;
        return ::poll(fds, nfds, timeout);
    }

    int ppoll(struct pollfd* fds, nfds_t nfds, const timespec* timeout, const sigset_t* sigMask) {
        errno = 0;
#if defined(__APPLE__)
        int timeout_ms = -1;
        if (timeout) {
            timeout_ms = timeout->tv_sec * 1000 + timeout->tv_nsec / 1000000;
        }
        if (sigMask) {
            sigset_t oldMask;
            pthread_sigmask(SIG_SETMASK, sigMask, &oldMask);
            int ret = ::poll(fds, nfds, timeout_ms);
            pthread_sigmask(SIG_SETMASK, &oldMask, nullptr);
            return ret;
        }
        return ::poll(fds, nfds, timeout_ms);
#else
        return ::ppoll(fds, nfds, timeout, sigMask);
#endif
    }

} // namespace core::system
