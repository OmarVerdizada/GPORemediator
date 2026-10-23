# 3.14.6 — Persistent delegated backup access

The launcher previously hardened the complete `C:\ProgramData\GpoRemediator` tree on every start. That recursive pass also replaced the explicitly delegated ACL on `Backups`, removing the operator group's Modify permission and causing backup, ACL, and free-space readiness failures after a restart.

This release excludes the backup repository from recursive private-state ACL replacement. The administrator-managed backup ACL is preserved while Config, State, Data, Recovery, Scripts, and runtime files continue to be protected. A Windows ACL regression test now verifies that a delegated Modify ACE survives secure-state initialization.

After upgrading an installation whose ACL was already removed, grant the intended operator group Modify once. Subsequent starts and restarts preserve that grant.
