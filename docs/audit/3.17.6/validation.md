# 3.17.6 validation

All 72 checks in scripts/Invoke-FullAuditTests.ps1 passed. The complete worker fixture matrix covers 405 controls in 413 scope cases; the exact endpoint matrix has 1,148 cases. Per-command hashes, per-control results and selected output are retained here.

The reported 30/30/0 incident now returns an actionable prerequisite preview. Direct Apply remains blocked without GPO/AD changes. Separate explicit window and duration applications produce AD duration 15, retain the unrelated threshold, reject peer-state drift and preserve rollback checks. The reverse dependency and duration 0 are covered too.

Server tests check blocked submission, legacy preview serialization and current-connection/actor isolation. Frontend tests verify authorization precedes refresh submission and denied preflight prevents rollback submission. Actual Chromium tests check the related preview, unchanged GPO/domain, no automatic writes, an early return remaining blocked, original live re-preview, fresh approval and desktop/mobile fit. Existing recovery/refresh tests also pass.

Tests use mocked directory, GPMC and endpoint interfaces with private filesystem/ACL fixtures and loopback browser APIs. Live AD, real DC replication and Sechard comparison were not run. Successful local tests are not a production-domain application claim.
