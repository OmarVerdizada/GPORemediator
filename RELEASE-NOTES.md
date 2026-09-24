## Password pilot — 2026-09-24

- Automatic, cached setup metadata detection with manual overrides; password pilot no longer requires GPO GUID/OU/host allowlists.
- Six password-policy settings for one selected non-privileged test user through a dedicated PSO. No inventory/compliance scans or unrelated policy writes.
- Before/after plan, 15-minute freshness, explicit Apply, durable backup, exact assignment and resultant-policy verification.
- Conflict-aware rollback and a standalone backup-based recovery helper. Other settings are copied from the existing effective user policy.
- Fixed embedded benchmark source exclusion from Git and portable SDK discovery for source tests.
- Tests: .NET invariants, isolated HTTP flow, PowerShell dispatcher with AD doubles, browser demo flow. Real AD acceptance remains a test-domain step.

# Operator interfeysi yenilənməsi — 2026-09-23

- `GpoRemediator.cmd` vizual idarəetmə panelini açır: başlatma, status, brauzer, restart, dayandırma və loglar.
- Azərbaycan dilində başlanğıc səhifəsi, modul kataloqu, axtarış və dəstək filtri əlavə edildi.
- Əməliyyat panelində daha böyük mətn/düymələr, tapıntı seçimi, saxlanan forma məlumatları, Escape və klaviatura fokus idarəetməsi var.
- OU distinguished name daxilindəki vergüllər artıq ayrıca allowlist elementi yaratmır.
- Oxunmayan və sıfır nəticəli skanlar PASS kimi göstərilmir.
- Aktiv GPO işi lifecycle əməliyyatlarını bloklayır; qəbul edilən stop/restart yeni job qəbulunu bağlayır. Setup restart da bu yoxlamadan keçir.
- Stop utiliti geniş proses axtarışı əvəzinə layihə yolu, PID və başlanğıc vaxtını yoxlayıb qorunan API-yə müraciət edir.
- Eyni layihənin ikinci launcher prosesi paralel build/start etmir. Backend hazırlığı API ilə yoxlanır.
- PowerShell 7-dən başlayan Windows PowerShell proseslərində sistem modullarının seçilməsi düzəldildi.
- Build: 0 warning / 0 error. 26 invariant testi və isolated HTTP smoke testləri keçdi. Demo skanı, zero-write plan, forma xətası, modul axtarışı, restart və stop yoxlandı. Masaüstü panelin XAML görünüşü render edildi; real domain əməliyyatı icra edilmədi.

Yeni benchmark modulları və istifadəçi PowerShell skriptləri bu mərhələdə əlavə edilməyib. Növbəti mərhələ `docs/MODULES.md`-də təsvir olunur.

---
# GPO Remediator – no-pnpm bootstrap release

## Why this build exists

A corporate network can permit the Microsoft .NET download while blocking `registry.npmjs.org`. Previous bootstraps attempted to install pnpm/Corepack during first run, so the product stopped before the backend started.

## What changed

- Production bootstrap no longer installs or invokes Node.js, npm, pnpm or Corepack.
- The current Web UI is shipped under `frontend/source` and pre-staged under `frontend/dist` with a source fingerprint.
- `Build-Portable.ps1` copies that static UI locally and builds only the .NET backend.
- The Automation Center remains available: Setup, readiness, target scan, one-click safe plan, write-mode control and explicit Apply.
- Explicit Apply still requires the saved preview, confirmation and backend safety validation; planning itself remains zero-write.
- `.NET` dependencies are cached under `.tools\nuget` after the first successful restore.
- A NuGet/network failure now produces a specific diagnostic instead of an npm/pnpm error.

## Upgrade from the failed pnpm build

Extract this release over the existing `GpoRemediator` directory and replace files. Do **not** delete `.tools\dotnet`; the launcher will reuse the already installed .NET 8 SDK. Old `.tools\node` or `.tools\pnpm` directories can remain because this release ignores them.

Run only:

```text
GpoRemediator.cmd
```

A normal rebuild should no longer print `Installing pnpm` or contact `registry.npmjs.org`.

## 2026-09-23 - HTML rendering hotfix
- Fixed SPA fallback response MIME type so `index.html` is rendered as HTML instead of displayed as plain text in Edge/Chrome.
- No GPO write logic changed.
