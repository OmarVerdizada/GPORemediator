# 3.8.1 - Single domain sign-in

Entering the domain account once now both opens the workspace and creates the AD/GPO connection. The duplicate dashboard credential form has been removed. Disconnect or session expiry offers the same sign-in screen. A service restart requires fresh sign-in; refresh preserves a valid session.

Windows Negotiate and operator roles remain mandatory. The submitted domain account is the execution identity and cannot change application roles. Startup access is granted only after read-only AD discovery succeeds. Passwords are not cached in browser storage or memory for later replay; the established encrypted server credential keeps its existing idle/absolute expiry. Initial Setup retains launcher-owner confirmation before a domain is configured.

Validation covers failed/successful unified sign-in, both session cookies, identity/CSRF boundaries, reconnect through one form and refresh/restart behavior. Actual domain authentication still requires domain-lab acceptance testing.
