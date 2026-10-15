# GPORemediator — Domain / GPO skript izolyasiyası

## Qovluq strukturu

`C:\ProgramData\GpoRemediator\Scripts\<domain-dns-name>\<gpo-guid>\`

Hər bir domain üzrə bütün aşkar edilmiş GPO-lar üçün ayrı qovluq yaradılır. Hər birində:

- `Invoke-Gpo.ps1` — yalnız həmin domain və GPO GUID-sinə bağlı ayrıca icra giriş skripti;
- `scope.json` — domain, GPO GUID və skriptin SHA-256 bütövlük məlumatı (şifrə yoxdur).

Məsələn:

```text
C:\ProgramData\GpoRemediator\Scripts\
├── prosol.local\
│   ├── 31b2f340-016d-11d2-945f-00c04fb984f9\
│   │   ├── Invoke-Gpo.ps1
│   │   └── scope.json
│   └── 483fcf29-...\
│       ├── Invoke-Gpo.ps1
│       └── scope.json
└── shamsi.local\
    └── 6ac1786c-016f-11d2-945f-00c04fb984f9\
        ├── Invoke-Gpo.ps1
        └── scope.json
```

## İcra prinsipi

1. Domen sessiyası başladıldıqda bütün həmin domenin GPO GUID-ləri ayrıca qovluqlara sinxronlaşdırılır. Aşkar edilən yeni GPO-lar `Discover` ilə əlavə olunur.
2. Preview / Apply / Verify / Rollback / Rollback inspection / Refresh üçün backend seçimdən domen və GPO ID-sini oxuyur, müvafiq GPO-ya aid `Invoke-Gpo.ps1` faylını seçir.
3. Backend fayl məzmununu və scope manifestini gözlənilən *tam baytlarla* yoxlayır; dəyişiklik aşkar edilərsə **icra bloklanır**. Symlink/junction bloklanır. DACL lokal xidmət hesabı, SYSTEM və Administrators ilə məhdudlaşdırılır.
4. Per-GPO launcher sorğunun domain və GPO GUID-sini yenidən təsdiqləyir. Yanlış domain/GPO sorğusu rədd edilir.
5. PowerShell əməliyyatlarının əsas məntiqi əvvəlki kimi yalnız `.NET` build-ə daxil edilmiş, SHA-256 ilə yoxlanan **ortaq trusted engine** içində qalır. İstifadəçi skriptləri, şifrələr, seçilən dəyərlər və komanda parametrləri diskə yazılmır.
6. Inventory və readiness əməliyyatlarının konkret GPO-si olmadığı üçün onlar ortaq read-only bootstrap ilə işləyir.

## Vacib məhdudiyyətlər

- Bu, **fayl və icra kontekstinin ayrılmasıdır**, ayrıca Windows sandbox, ayrı process account və ya ayrı AD authentication context deyil. Ayrı AD domenlərinin security boundary-si yalnız GPO-ya verilmiş real AD icazələri ilə qorunur.
- Hazırkı backend eyni anda yalnız bir aktiv `Windows:Domain` / `Windows:DomainController` konfiqurasiyası dəstəkləyir. Köhnə domain qovluqları silinmir, yeni domen seçilərsə yeni folder yaranır. Bu patch eyni anda multi-domain connection əlavə etmir.
- Source patch quraşdırıldıqdan sonra Windows .NET 10 backend **yenidən build** edilməlidir. Köhnə EXE bu dəyişiklikləri işlətmir.
- `C:\ProgramData\...\Scripts` içində faylları əl ilə düzəltmə. Mətn dəyişəndə tətbiq təhlükəsizlik məqsədilə icranı dayandırır. Köçürmə və yenilənmə yalnız clean release və təsdiqlənmiş prosedurla edilməlidir.
- Çox böyük domenlərdə (minlərlə GPO) ilk inventar sinxronizasiyası disk və ACL əməliyyatları səbəbi ilə vaxt ala bilər.
- Test əvvəlcə virtual/lab AD-də aparılmalıdır; real domain/rollback təsdiqi bu paketlə avtomatik icra olunmayıb.
