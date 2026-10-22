# 3.14.3 — Persistent backup delegation and compatible targets

Application startup no longer replaces the administrator-managed ACL on `C:\ProgramData\GpoRemediator\Backups`. The delegated execution account or group keeps its explicit Modify permission after a control-plane restart. Other private application state directories remain protected as before, and readiness continues to reject broad write grants on the backup repository.

Target selection now normalizes domain password and lockout controls to the domain root. OU inventory remains visible for context but cannot be selected for a domain-only control. Computer and user controls likewise accept only OU targets. Workflow captions, action labels and step completion now reflect the actual target type.

## Upgrade

Pull `main` or replace the installation with the complete updated package and restart `GpoRemediator.cmd`. Grant the delegated operator group Modify on the backup directory once. Version 3.14.3 preserves that ACL on subsequent restarts.
