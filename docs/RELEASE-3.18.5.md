# GPO Remediator 3.18.5

An operator who reconnects after restarting the service can restore a recorded single or bulk operation with the original account and configuration. The recorded operation and explicit confirmation govern recovery. The Windows worker rechecks the backup, current GPO and link state, and restore permissions. Recovery does not authorize forward Apply in the new session.

Rollback availability reports when the retained native backup files are unavailable or the connected account lacks the required GPO or link permissions. Link restoration requests delegation only when the recorded link needs to change. A verified snapshot can remain restored while endpoint verification is incomplete or reports a mismatch. The workflow and operation details show those outcomes separately.

An interrupted write still requires read-only re-verification before a new approved recovery. Existing endpoint repair commands continue to require a known pre-change value and separate operator confirmation.
