/*
 * snodec-auth.js — drop-in account UI for SNode.C SSO frontends.
 *
 * Renders two buttons next to each other:
 *   • Account — shows the signed-in username, opens the identity provider's
 *     account settings (enable MFA, change password/email, delete account).
 *   • Logout  — clears the local relying-party session and the central IdP
 *     session, then returns to the app so single sign-on re-initiates cleanly.
 *
 * The signed-in identity is read without any token parsing on the developer's
 * part: the widget first looks for the small, readable "snodec_user" cookie set
 * by the SNode.C OAuth2 callback handler, and falls back to decoding the
 * username/email claims out of the "access_token" JWT cookie. No verification is
 * done client-side — these values are used only to label the UI; every request
 * is still authorised server-side by the auth middleware.
 *
 * Usage (any SNode.C frontend) — just add the script tag:
 *   <script src="/snodec-auth.js"
 *           data-idp="https://auth.example.at"
 *           data-anchor="Connected"
 *           data-return="/clients/index.html"></script>
 *
 * Or mount it yourself into a toolbar element:
 *   <script src="/snodec-auth.js" data-auto="false"></script>
 *   <script>SnodecAuth.mount(document.getElementById('toolbar'));</script>
 */
(function (global) {
    'use strict';

    // ── Configuration ────────────────────────────────────────────────────────
    // Read from the <script> tag's data-* attributes, overridable through a
    // global SNODEC_AUTH_CONFIG object. Every value has a sensible default.
    function currentScript() {
        if (document.currentScript) {
            return document.currentScript;
        }
        var all = document.getElementsByTagName('script');
        for (var i = all.length - 1; i >= 0; i--) {
            if (/snodec-auth\.js(\?|$)/.test(all[i].src)) {
                return all[i];
            }
        }
        return null;
    }

    var ds = (currentScript() || {}).dataset || {};
    var ovr = global.SNODEC_AUTH_CONFIG || {};
    var CFG = {
        idpBaseUrl: (ovr.idpBaseUrl || ds.idp || '').replace(/\/+$/, ''),
        accountPath: ovr.accountPath || ds.account || '/settings',
        idpLogoutPath: ovr.idpLogoutPath || ds.logout || '/auth/logout',
        localLogoutPath: ovr.localLogoutPath || ds.localLogout || '/auth/logout',
        returnPath: ovr.returnPath || ds.return || '/',
        anchorText: ovr.anchorText || ds.anchor || 'Connected',
        autoInject: !(ovr.autoInject === false || ds.auto === 'false')
    };

    // ── Identity ─────────────────────────────────────────────────────────────
    function readCookie(name) {
        var m = document.cookie.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'));
        return m ? m[1] : '';
    }

    // Decode a JWT payload without verifying it (display only).
    function decodeJwtPayload(jwt) {
        var part = jwt.split('.')[1];
        if (!part) {
            return null;
        }
        var b64 = part.replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4) {
            b64 += '=';
        }
        try {
            return JSON.parse(decodeURIComponent(escape(atob(b64))));
        } catch (e) {
            return null;
        }
    }

    function getUser() {
        // Preferred: the purpose-built identity cookie.
        var raw = readCookie('snodec_user');
        if (raw) {
            try {
                var obj = JSON.parse(decodeURIComponent(raw));
                if (obj && (obj.username || obj.email)) {
                    return { username: obj.username || '', email: obj.email || '' };
                }
            } catch (e) { /* fall through to the token */ }
        }
        // Fallback: decode the access-token JWT, if it is readable.
        var token = readCookie('access_token');
        if (token) {
            var claims = decodeJwtPayload(decodeURIComponent(token));
            if (claims) {
                return {
                    username: claims.username || claims.preferred_username || claims.sub || '',
                    email: claims.email || ''
                };
            }
        }
        return { username: '', email: '' };
    }

    function idpUrl(path) {
        return /^https?:\/\//.test(path) ? path : CFG.idpBaseUrl + path;
    }

    // ── Actions ──────────────────────────────────────────────────────────────
    function openAccount() {
        // Carry the current page as a return target so the IdP settings page
        // can offer a "back to the application" link.
        var base = idpUrl(CFG.accountPath);
        var sep = base.indexOf('?') === -1 ? '?' : '&';
        window.location.href = base + sep + 'return=' + encodeURIComponent(window.location.href);
    }

    function logout(btn) {
        if (btn) {
            btn.disabled = true;
            var lbl = btn.querySelector('span');
            if (lbl) {
                lbl.textContent = 'Logging out…';
            }
        }
        // Drop the local identity cookie immediately.
        document.cookie = 'snodec_user=; path=/; max-age=0';
        var idpLogout = idpUrl(CFG.idpLogoutPath) + '?redirect_uri=' +
            encodeURIComponent(window.location.origin + CFG.returnPath);
        // 1) Clear the relying party's (possibly HttpOnly) session cookie
        //    server-side, without following its redirect back into the app.
        fetch(CFG.localLogoutPath, { credentials: 'include', redirect: 'manual' })
            .catch(function () { /* ignore network errors on logout */ })
            .then(function () {
                // 2) Clear the central IdP session, then return to the app.
                window.location.href = idpLogout;
            });
    }

    // ── Rendering ────────────────────────────────────────────────────────────
    var BTN_BASE = [
        'display:inline-flex', 'align-items:center', 'gap:7px',
        'margin-left:10px', 'padding:9px 16px', 'border-radius:12px',
        'font:600 13px/1 inherit', 'font-family:inherit', 'cursor:pointer',
        'white-space:nowrap', 'transition:background .15s,border-color .15s'
    ].join(';');

    function makeAccountButton(user) {
        var btn = document.createElement('button');
        btn.id = 'snodec-account-btn';
        btn.type = 'button';
        btn.title = 'Account settings';
        btn.style.cssText = BTN_BASE +
            ';background:rgba(148,163,184,0.16);color:#cbd5e1;border:1px solid rgba(148,163,184,0.38);max-width:220px';
        var name = user.username || user.email || 'Account';
        btn.innerHTML =
            '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
            'stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
            '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>' +
            '<span style="overflow:hidden;text-overflow:ellipsis">' + escapeHtml(name) + '</span>';
        btn.onmouseenter = function () {
            btn.style.background = 'rgba(148,163,184,0.28)';
            btn.style.borderColor = 'rgba(148,163,184,0.6)';
        };
        btn.onmouseleave = function () {
            btn.style.background = 'rgba(148,163,184,0.16)';
            btn.style.borderColor = 'rgba(148,163,184,0.38)';
        };
        btn.onclick = openAccount;
        return btn;
    }

    function makeLogoutButton() {
        var btn = document.createElement('button');
        btn.id = 'snodec-logout-btn';
        btn.type = 'button';
        btn.title = 'Sign out and return to the identity provider';
        btn.style.cssText = BTN_BASE +
            ';background:rgba(239,68,68,0.12);color:#ef4444;border:1px solid rgba(239,68,68,0.35)';
        btn.innerHTML =
            '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
            'stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
            '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>' +
            '<polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>' +
            '<span>Logout</span>';
        btn.onmouseenter = function () {
            btn.style.background = 'rgba(239,68,68,0.22)';
            btn.style.borderColor = 'rgba(239,68,68,0.6)';
        };
        btn.onmouseleave = function () {
            btn.style.background = 'rgba(239,68,68,0.12)';
            btn.style.borderColor = 'rgba(239,68,68,0.35)';
        };
        btn.onclick = function () { logout(btn); };
        return btn;
    }

    function escapeHtml(s) {
        return String(s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }

    // Mount the Account + Logout pair into a container element.
    function mount(container) {
        if (!container || document.getElementById('snodec-account-btn')) {
            return false;
        }
        var user = getUser();
        container.appendChild(makeAccountButton(user));
        container.appendChild(makeLogoutButton());
        return true;
    }

    // ── Auto-injection for compiled single-page dashboards ────────────────────
    // The dashboard renders its status badge at runtime, so we locate the badge
    // by its text and insert the buttons right after it: [Connected] [Account] [Logout].
    function findAnchor() {
        var els = document.querySelectorAll('div,span,button');
        for (var i = 0; i < els.length; i++) {
            var el = els[i];
            var txt = (el.textContent || '').trim();
            if (txt.indexOf(CFG.anchorText) === 0 && txt.length < 32 && el.children.length <= 3) {
                return el;
            }
        }
        return null;
    }

    function autoInject() {
        if (document.getElementById('snodec-account-btn')) {
            return true;
        }
        var anchor = findAnchor();
        if (!anchor || !anchor.parentNode) {
            return false;
        }
        var user = getUser();
        var account = makeAccountButton(user);
        var logoutBtn = makeLogoutButton();
        anchor.parentNode.insertBefore(account, anchor.nextSibling);
        account.parentNode.insertBefore(logoutBtn, account.nextSibling);
        return true;
    }

    function startAutoInject() {
        var tries = 0;
        var iv = setInterval(function () {
            if (autoInject() || ++tries > 80) {
                clearInterval(iv);
            }
        }, 400);
        if (global.MutationObserver) {
            new MutationObserver(function () { autoInject(); })
                .observe(document.documentElement, { childList: true, subtree: true });
        }
    }

    // ── Public API ───────────────────────────────────────────────────────────
    global.SnodecAuth = {
        mount: mount,
        logout: logout,
        openAccount: openAccount,
        getUser: getUser,
        config: CFG
    };

    if (CFG.autoInject) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', startAutoInject);
        } else {
            startAutoInject();
        }
    }
})(window);
