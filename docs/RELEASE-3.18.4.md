# GPO Remediator 3.18.4

Rollback captures typed registry readings for sampled computers for single-value DWORD and MultiString mappings. It distinguishes an absent value, an empty MultiString, and a populated list. On 2.3.10.7, a restored GPO can have no `NullSessionPipes` entry while the endpoint still holds an empty `REG_MULTI_SZ`.

When the GPO restore and controller replication are verified, an eligible endpoint mismatch can offer **Restore saved endpoint registry value** under **Operations → View details**. The current value must still match the recorded Apply value. Review which policy applies on that computer before copying the command into elevated Windows PowerShell. The command checks the computer name, re-reads the current value and type, restores only the captured registry value, and checks it again. Type `RESTORE` to confirm. Run **Re-verify** to collect fresh evidence in the app.

The command covers eligible sampled Computer registry controls. Defender, Spooler, other handlers and unsampled devices use their existing verification and recovery paths. A legacy MultiString record preserves the displayed reading but cannot prove the original typed list for a local write. Older single-value DWORD readings are supported when their exact prior value is available.
