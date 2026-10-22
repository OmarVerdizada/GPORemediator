/* Shared transport. Never retry mutations automatically: their outcome can be uncertain. */
(() => {
  'use strict';
  const active = new Set();
  // Browser-tab memory only. The delegated password is never written to
  // sessionStorage/localStorage/disk. This short-lived cache exists only so a
  // launcher-managed backend restart does not force the operator to type the
  // same account again during one remediation workflow.
  let delegatedSecret = null;
  const credentialIdleMs = 30 * 60 * 1000;
  const ephemeralCredential = {
    set(userName, password) {
      this.clear();
      const bytes = new TextEncoder().encode(String(password || ''));
      delegatedSecret = { userName: String(userName || ''), bytes, lastUsed: Date.now() };
    },
    get() {
      if (!delegatedSecret) return null;
      if (Date.now() - delegatedSecret.lastUsed > credentialIdleMs) { this.clear(); return null; }
      delegatedSecret.lastUsed = Date.now();
      return { userName: delegatedSecret.userName, password: new TextDecoder().decode(delegatedSecret.bytes) };
    },
    touch() { if (delegatedSecret) delegatedSecret.lastUsed = Date.now(); },
    clear() {
      if (delegatedSecret?.bytes) delegatedSecret.bytes.fill(0);
      delegatedSecret = null;
    },
    available() { return !!this.get(); }
  };
  const storage = {
    get(key, fallback) { try { return sessionStorage.getItem(key) ?? fallback; } catch { return fallback; } },
    set(key, value) { try { sessionStorage.setItem(key, value); } catch { /* Storage may be disabled. */ } },
    favorites() { try { const value = JSON.parse(this.get('gr-favorites', '[]')); return Array.isArray(value) ? value.filter(x => typeof x === 'string') : []; } catch { return []; } }
  };
  function localize() { document.documentElement.lang='en'; storage.set('gr-lang','en'); }
  const errors = {
    GPO_EDIT_ACCESS_DENIED:"You cannot edit the selected GPO. Ask an administrator to open GPMC > Group Policy Objects > selected GPO > Delegation > Add and grant your execution account or group Edit settings. Read and Apply Group Policy do not grant editing rights. Sign out and back in before retrying.",
    OU_LINK_ACCESS_DENIED:"You cannot change GPO links on this OU/domain. Ask an administrator to grant Link GPOs on the selected OU/domain in GPMC > Delegation. This permission is separate from Edit settings on the GPO. Sign in again after delegation changes.",
    SYSVOL_WRITE_ACCESS_DENIED:"You cannot write the selected GPO files in SYSVOL. Ask an administrator to check Edit settings delegation and NTFS Effective Access for this GPO. Repair permissions only for the selected GPO, then sign in again.",
    GPO_ACCESS_UNVERIFIED:"Effective write access could not be verified, so no plan was created. Check GPO Edit settings delegation, SYSVOL Effective Access, Link GPOs on the selected OU/domain, metadata read access and DC connectivity. Sign in again and retry.",
    DOMAIN_POLICY_PRIORITY_REQUIRED:"Domain password/lockout policy requires the selected GPO to be enabled at link order 1 on the domain root.",
    DOMAIN_REFRESH_SCOPE_INVALID:"Computer OU refresh does not apply to domain account policy. Refresh the PDC or wait for the normal policy cycle.",
    PASSWORD_SCOPE_MISMATCH:"This control requires the domain root. Choose a compatible target; this is a scope mismatch.",
    GPO_OU_REQUIRED:"This computer/user control requires an OU. Choose the appropriate OU instead of the domain root.",
    GPO_LOGIN_REQUIRED:"The execution session expired or the service restarted. The sign-in screen will open.",
    GPO_AUTH_FAILED:"The delegated account was rejected. Check DOMAIN\\user or UPN, the password and PowerShell remoting access on the DC.",
    GPO_DNS_FAILED:"The DC FQDN cannot be resolved from this host. Configure AD DNS and check the domain and DC names.",
    GPO_WINRM_UNREACHABLE:"The DC resolves, but TCP/5985 is unreachable. Enable WinRM/PowerShell Remoting and the Windows Remote Management HTTP-In firewall rule on the DC.",
    GPO_WINRM_HTTP_REQUIRED:"Only TCP/5986 is available. This version uses Kerberos with WinRM HTTP/5985. Enable the 5985 listener and firewall rule.",
    GPO_KERBEROS_FAILED:"WinRM is reachable, but Kerberos authentication failed. Check AD DNS, synchronized time, TCP/88 and WSMAN/HTTP SPNs for the DC FQDN.",
    GPO_REMOTING_FAILED:"TCP/5985 is reachable, but the PowerShell session failed. Check the WinRM listener, endpoint permissions and delegated account.",
    GPO_READINESS_FAILED:"Domain sign-in succeeded, but readiness checks did not complete. Refresh the application and check readiness again.",
    GPO_DISCOVERY_FAILED:"The GPO inventory could not be loaded. Check the ActiveDirectory and GroupPolicy modules and read permissions on the DC.",
    GPO_PREVIEW_FAILED:"The plan could not be generated. Reselect the GPO and target, and check SYSVOL read access.",
    WRITES_DISABLED:"The production change gate is disabled. Approve the specific GPO and OU scope, then enable writes.",
    ENVIRONMENT_NOT_READY:"Resolve the issues reported by the readiness checks first.",
    WRITE_SCOPE_UNRESTRICTED:"Production write scope must be restricted to specific GPO GUIDs and OU/domain DNs instead of wildcards.",
    WRITE_GATE_TRANSITION_BLOCKED:"The previous change-gate transition did not complete. Automatic retry is blocked. Check service and configuration status in Settings and the Local Control Center.",
    WINDOWS_MODE_REQUIRED:"The application is in configuration mode. Save the domain/DC settings and choose Start Windows / AD. Check windows-startup-error.log and bootstrap.log if startup fails.",
    SERVICE_RESTARTED:"The Windows / AD service restarted. Sign in again because delegated credentials are stored only in memory.",
    SERVICE_RESTARTING:"The Windows / AD service is restarting. Wait for it to become available.",
    SERVICE_UNREACHABLE:"The backend is unreachable. Check service status and windows-startup-error.log, server-error.log and bootstrap.log in the Local Control Center.",
    CSRF_INVALID:"Your session needs to be refreshed. Reload the page and try again.",
    INVALID_DOMAIN:"Enter a domain and its DC FQDN, for example example.local and dc01.example.local.",
  };
  function policy(path) {
    if (/\/gpo\/[^/]+\/(apply|rollback)$/.test(path)) return { timeout: 980000, label: 'Backup, policy change and verification', cancelable: false };
    if (/\/gpo\/[^/]+\/refresh$/.test(path)) return { timeout: 760000, label: 'Scheduling gpupdate and re-verifying policy', cancelable: false };
    if (/\/gpo\/(target-access|preview|[^/]+\/(verify|replan|rollback-preview))$/.test(path)) return { timeout: 620000, label: 'Reading policy and verifying scope', cancelable: true };
    if (/\/gpo\/(connect|discover|readiness)$/.test(path)) return { timeout: 110000, label: path.endsWith('/readiness') ? 'Checking AD readiness' : 'Connecting to AD and loading GPOs', cancelable: true };
    if (/\/setup\/write-mode$/.test(path)) return { timeout: 120000, label: 'Checking readiness and updating write mode', cancelable: false };
    return { timeout: 20000, label: 'Loading application data', cancelable: true };
  }
  async function request(path, { body, csrfToken, ...options } = {}) {
    const settings = { ...policy(path), ...options };
    if (body !== undefined && !/^\/api\/gpo\/(connect|discover|preview|[^/]+\/(verify|replan))$/.test(path)) settings.cancelable = false;
    const controller = new AbortController();
    const pending = { controller, path, ...settings, started: Date.now() };
    active.add(pending);
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, settings.timeout);
    try {
      const response = await fetch(path, {
        method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
        headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken || '' }) },
        body: body === undefined ? undefined : JSON.stringify(body)
      });
      const text = await response.text();
      let data;
      try { data = JSON.parse(text); } catch {
        throw new Error(response.status === 401 ? 'Windows authentication is required. Reopen the app with an allowed Windows account.' : `The server returned an invalid response (HTTP ${response.status}). Check the service and reload.`);
      }
      if (!response.ok) {
        const error = new Error(errors[data.code] || data.message || `Request failed (HTTP ${response.status}).`);
        error.code = data.code; error.status = response.status;
        if(data.code==='OPERATOR_CONFIRMATION_REQUIRED')window.GpoOperatorSignIn?.reconfirm();
        error.correlationId = data.correlationId || response.headers.get('X-Correlation-ID');
        throw error;
      }
      if (path.startsWith('/api/gpo/') && !path.endsWith('/disconnect')) ephemeralCredential.touch();
      return data;
    } catch (error) {
      if (controller.signal.aborted) {
        const e = new Error(timedOut
          ? `Request timed out after ${Math.round(settings.timeout / 1000)} seconds. ${settings.cancelable ? 'Check the service, DC and Kerberos/WinRM connection, then retry.' : 'The operation may still be running. Review Operations before submitting it again.'}`
          : 'Stopped waiting for the response. No new operation was submitted; the server may still be completing work.');
        e.code = timedOut ? 'REQUEST_TIMEOUT' : 'REQUEST_CANCELLED';
        throw e;
      }
      if (error instanceof TypeError) {
        const e = new Error('The GPO Remediator backend connection was lost. If the service is restarting, wait for it to return; otherwise check service status, windows-startup-error.log and bootstrap.log in Local Control Center.');
        e.code = 'SERVICE_UNREACHABLE';
        throw e;
      }
      throw error;
    } finally { clearTimeout(timer); active.delete(pending); }
  }
  let reconnectPending = null;
  function reconnectDelegated() {
    if (!reconnectPending) reconnectPending = restoreDelegated().finally(() => { reconnectPending = null; });
    return reconnectPending;
  }
  async function restoreDelegated() {
    const credential = ephemeralCredential.get();
    if (!credential) return null;
    try {
      const session = await request('/api/session', { timeout: 5000 });
      const inventory = await request('/api/gpo/connect', { body: credential, csrfToken: session.csrfToken, timeout: 110000 });
      credential.password = '';
      const gpoSession = await request('/api/gpo/session', { timeout: 5000 });
      return { session, inventory, gpoSession };
    } catch (error) {
      credential.password = '';
      if (/AUTH|CREDENTIAL|LOGIN/.test(String(error?.code || ''))) ephemeralCredential.clear();
      throw error;
    }
  }
  window.GpoClient = {
    request, storage, localize, ephemeralCredential, reconnectDelegated,
    progress() { return [...active].at(-1); },
    cancelReadOnly() { for (const p of active) if (p.cancelable) p.controller.abort(); }
  };
})();
