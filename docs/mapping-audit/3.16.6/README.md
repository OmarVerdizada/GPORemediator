# Per-control mapping-source review — Windows Server 2019

The review covers every one of the 405 controls in the supplied catalog, not 405 separate GPOs. Windows Server 2019 is the operator-confirmed target. It does not bind the catalog to an independently obtained original CIS PDF or claim that these 405 entries are the whole Windows Server 2019 benchmark.

Open **mapping-review.csv** for one row per control, or **mapping-review.json** for the corresponding source locations and reference evidence. **mapping-review.md** summarizes all 19 headings. Each row includes scope, mechanism, complete policy address/value/type, comparator and input/restart flags, authored source location, dependencies and review limitations. Eleven role/update-sensitive controls remain guided.

## Findings and repairs

Two effective write recipes were corrected: ASR Office-macro rule identity (18.10.43.6.1.2) and Remote Encryption versus Brute Force feature identity (18.10.43.11.1.1.2). Other effective changes are dependency warnings; see **mapping-changes.json** for exact before/after fields. Old TSV and inline generator records were aligned with the previously reviewed final output so regeneration cannot resurrect stale IDs/addresses/types/values. The generator now rejects unknown IDs, missing files, malformed rows and duplicates.

The ASR recipe now selects the 12 rule IDs in the imported recommendation. It does not delete unrelated existing policy entries. The Microsoft WMI ASR support matrix specifically distinguishes Server 1903 SAC from Server 2019 LTSC 17763; that exception is surfaced in the control warnings. LAPS, Defender, printer, VBS and update settings require the relevant component/update/parent-policy checks before relying on runtime enforcement.

## Primary reference evidence

- Microsoft's [Windows Server 2019 security baseline publication](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/security-baseline-final-for-windows-10-v1809-and-windows-server-2019/701082) and [Security Compliance Toolkit download](https://www.microsoft.com/en-us/download/details.aspx?id=55319). The selected ZIP is **Windows 10 Version 1809 and Windows Server 2019 Security Baseline.zip**, SHA-256 `575DDAF39EF364EA6DA678E22B0A988EA316EB240F73FBF618092A02647245BC`.
- The ZIP's Windows Server 2019 workbook, Member Server PolicyRules, SecGuide and MSS-Legacy templates; installed Windows ADMX and the Microsoft Defender template reference. Exact input hashes are recorded in **mapping-review.json**. Modern templates can expose settings that an older target does not consume.
- Native `auditpol /list /subcategory:* /r` data for audit GUID/name identity, plus the imported recommendation for Success/Failure masks. PNP Activity is a display-name alias for Plug and Play Events. No audit policy was changed.
- Microsoft protocol and policy references listed per control/family in **backend/data/mapping_sources/review-evidence.json** and in the detailed review output.

Reference identity, scope/type and legal-value checks are distinct from recommended-value choices. The imported catalog supplies the CIS desired values; a different Microsoft baseline value is not automatically treated as a mapping error. `CONFIGURATION_REFERENCE_REVIEWED` records the configuration-source review, not target compatibility or operational compliance. `Server2019OriginalReference` means a reference was identified in the original 2019 baseline data, not that all applicability conditions have been satisfied.

## Reproduce

Use Python with openpyxl for the optional Microsoft workbook and an approved local copy of the SCT ZIP. Read the ZIP as data; do not run any included installation scripts.

```powershell
python scripts/Build-ProductionMappings.py --check
python scripts/Test-MappingSources.py
auditpol.exe /list /subcategory:* /r > work/audit-subcategories.csv
python scripts/Audit-MappingSources.py --reference-zip '<SCT ZIP path>' --audit-list work/audit-subcategories.csv --output work/mapping-source-review
```

`--extra-admx` accepts an additional local Microsoft template directory. Hashes and results can differ with the template set installed on the audit machine. The baseline ZIP is not redistributed in this report.

## Test evidence

**writer-tests.txt**, **endpoint-tests.txt** and **manual-tests.txt** contain the isolated test results; their source hashes are recorded in **test-evidence.json**. All Windows/AD mutation APIs in those scenarios are mocked. A live pilot still needs to validate actual Server 2019 build/role support, SYSVOL/AD processing, security filtering, RSoP, service/engine state, restarts/logons and rollback.
