# Tests and validation

`Test.ps1` əsas validation entry point-dir. Test yolu production Node/npm/pnpm dependency-si istifadə etmir.

## Test layers

| Layer | Main coverage |
| --- | --- |
| `tests/InvariantTests` | Catalog mapping, policy types, SID normalization/set comparison, adapter selection, account/role/manual gates, restart metadata, credential redaction, append-only audit, tamper detection, SQLite persistence |
| PowerShell HTTP smoke suite | Isolated MOCK server, session/CSRF acquisition, control catalog, environment readiness, target scan, finding creation, one-click safe plan və `writes=0` assertion |
| Manual workflow acceptance | Preview/apply/verification/rollback lifecycle, pending restart/no-refresh behavior, audit review |
| Disposable-domain acceptance | Real AD/GPO permissions, RSoP, SYSVOL/DC behavior, WinRM, endpoint verification and rollback conflicts |

## `Test.ps1` safety model

Test script:

1. backend-i Release build edir;
2. .NET invariant tests-i işlədir;
3. ayrıca temporary SQLite DB ilə MOCK backend başladır;
4. loopback `/api/session`-dan CSRF cookie/token alır;
5. readiness → target scan → safe-plan smoke flow işlədib `dryRun=true` və `writes=0` olduğunu yoxlayır;
6. test müddətində heç bir real AD/GPO provider istifadə etmir.

Test server ayrıca `work\\test-*` qovluğunda evidence/log saxlayır.

## Manual demo acceptance

`GpoRemediator.cmd` başladın, MOCK label-i təsdiqləyin və Automation Center istifadə edin:

1. `Overview → Run checks`;
2. `Target scan` ilə demo host scan edin;
3. yaranan finding-i açın;
4. `Safe plan` ilə zero-write plan hazırlayın;
5. base finding UI-da preview/apply workflow-u yoxlayın;
6. backup, layered verification, PASS və audit trail-i təsdiqləyin;
7. rollback edin və original state-in qaytarıldığını yoxlayın.

## Real-domain acceptance

Mock suite AD cmdlet-ləri icra etmir. Disposable Windows/AD lab-da ayrıca bunları doğrulayın:

- service/process identity delegation;
- exact host/OU/GPO allowlist sərhədləri;
- RSoP applied-GPO discovery və precedence;
- GPO security template/registry preservation;
- AD/SYSVOL version və replication;
- pinned writable DC behavior;
- WinRM/gpupdate;
- endpoint effective state;
- concurrent-admin rollback conflict protection;
- HTTPS certificate və Windows authentication.

## Current handoff validation boundary

Bu handoff mühiti Windows PowerShell və .NET SDK vermədiyi üçün newest backend burada compile edilə bilmir. Ona görə stale runtime daxil edilmir. First Windows launch cari source-dan fingerprint-matched backend publish edir. Frontend isə artıq prepackaged static source-dur və package registry tələb etmir.

Bu handoff zamanı aşağıdakılar static şəkildə yoxlanır:

- `automation.js` JavaScript syntax;
- frontend source/dist fingerprint uyğunluğu;
- JSON config/example parsing;
- local documentation links;
- PowerShell brace/delimiter sanity;
- ZIP integrity.

Trusted Windows host-da `GpoRemediator.ps1 -Mode Test` disposable-domain acceptance-dan əvvəl işlədilməlidir.
