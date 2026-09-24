# GPO Remediator – istifadə və avtomatlaşdırılmış setup

## 1. Ən qısa yol

ZIP-i Windows management host-a çıxarın və yalnız bunu başladın:

```text
GpoRemediator.cmd
```

Normal operator istifadəsi üçün başqa script işlətməyə ehtiyac yoxdur.

Açılan idarəetmə panelində:

1. **Demo** (AD-ni dəyişməyən sınaq), **Avtomatik** (saxlanmış konfiqurasiya) və ya **Windows / Active Directory** rejimini seçin.
2. **Başlat** düyməsini basın. İlk build zamanı gedişat **Son fəaliyyət** bölməsində görünür.
3. Xidmət hazır olduqda **Brauzerdə aç** düyməsini basın.
4. Dayandırmaq üçün paneldə və ya brauzerin üst hissəsində **Dayandır** seçin. Aktiv GPO işi varsa sorğu rədd olunur; əvvəl əməliyyatın tamamlanmasını gözləyin.
5. **Yenidən başlat** cari rejimdə xidməti yenidən açır. Rejimi dəyişmək üçün əvvəl dayandırın, yeni rejimi seçin və başladın.

Panel və ya brauzer pəncərəsini bağlamaq xidməti dayandırmır. Paneli yenidən açanda işləyən xidmət görünəcək. **Log qovluğu** başlanğıc və server loglarını açır.

Brauzer xidmət dayanandan sonra onu işə sala bilmir. Yenidən başlamaq üçün `GpoRemediator.cmd` panelində **Başlat** istifadə olunur.

### Yeni başlanğıc səhifəsi

**Başlanğıc → Modullar** ilə başlayın. Hədəfin DNS adını yazın, benchmark parametrini tapın və **Seç və planı aç** seçin. Sonra **Planı hazırla və yoxla → APPLY → Təsdiqlə və tətbiq et** ardıcıllığı ilə davam edin. İlkin scan tələb edilmir. 397 parametr kataloqdadır, hazırda 3 parametrin remediation adapteri aktivdir. Digərləri **Adapter yoxdur** kimi göstərilir. Ətraflı: [benchmark axını](docs/BENCHMARK-FLOW.md).

## 2. İlk start zamanı nə baş verir?

Launcher source fingerprint-lərini yoxlayır. Cari backend build yoxdursa:

- sistemdə uyğun .NET 8 SDK varsa istifadə edir;
- yoxdursa portable `.NET 8 SDK`-nı `.tools\dotnet` altında quraşdırır;
- `frontend\source` static UI-ni `frontend\dist`-ə kopyalayır;
- backend-i self-contained Windows x64 runtime kimi publish edir;
- fingerprint-lər uyğun gəlməsə app-i başlamır.

Frontend üçün **Node.js/npm/pnpm/Corepack istifadə olunmur** və `registry.npmjs.org` çıxışı lazım deyil.

İlk .NET provision üçün internet tələb oluna bilər. Səndə `.tools\dotnet` artıq varsa launcher həmin cache-i istifadə edəcək.

## 3. MOCK onboarding

`backend\appsettings.Local.json` yoxdursa launcher təhlükəsiz MOCK mode açır.

MOCK mode:

- Active Directory-yə yazmır;
- GPO dəyişmir;
- local demo datası ilə workflow-u göstərir;
- Automation Center-dən setup hazırlamağa imkan verir.

UI açıldıqda **Hədəfi skan et**, sağ aşağıdakı **Əməliyyatlar** və ya sidebar-dakı **Əməliyyat mərkəzi** istifadə olunur. Təlimatdakı “Automation Center” bu panelin əvvəlki adıdır.

## 4. Setup UI

Automation Center → **Setup** bölməsində bunları doldurun:

- Management HTTPS URL, məsələn `https://gpo-remediator.prosol.az:5443`
- AD domain, məsələn `prosol.az`
- Writable domain controller, məsələn `dc01.prosol.az`
- Backup path, məsələn `C:\ProgramData\GpoRemediator\Backups`
- Approved remediation GPO GUID-ləri
- Authorized OU distinguished name-ləri
- Allowed target FQDN-ləri
- Allowed Windows operator-ları, məsələn `PROSOL\omar.verdizada`

Allowlist sahələrində hər elementi ayrıca sətirdə yazın. OU ünvanının daxilindəki vergülləri saxlayın: `OU=Servers,DC=prosol,DC=az` bir elementdir.

`Validate, save & restart`:

1. input format/allowlist validation edir;
2. protected default domain GPO GUID-lərini rədd edir;
3. `backend\appsettings.Local.json` yaradır;
4. `EnableWrites=false` saxlayır;
5. controlled restart marker yaradır;
6. launcher Windows mode-a keçməyə çalışır.

Browser configured HTTPS URL-ni avtomatik açmağa çalışır.

## 5. Real Windows prerequisites

Windows mode üçün management host-da:

- domain connectivity;
- `ActiveDirectory` PowerShell module;
- `GroupPolicy` PowerShell module;
- configured writable DC;
- process/service identity üçün delegated read/edit scope;
- target-lərə lazım olan WinRM/Kerberos/RSoP access;
- backup path access

tələb olunur.

RSAT yoxdursa launcher UAC-approved prerequisite helper vasitəsilə quraşdırmağa çalışır.

### HTTPS certificate

Configured URL host adı üçün uyğun certificate `LocalMachine\My` store-da private key ilə mövcud olmalıdır. Product özbaşına trusted root/self-signed enterprise certificate yaratmır.

## 6. Readiness

Automation Center → **Overview** və ya **Setup** → `Run checks`.

Required check-lər PASS olmadan write mode enable edilmir.

## 7. Target Scan

Automation Center → **Target scan**:

1. Target FQDN daxil edin.
2. Role üçün `Auto`, `MemberServer`, `DomainController` və ya `Workstation` seçin.
3. `Scan target & create findings` basın.

Scan read-only-dur. Endpoint setting-i doğrulana bilmirsə `UNAVAILABLE` göstərilir, saxta PASS verilmir.

## 8. Safe Plan

Finding-i base UI-dan açın və Automation Center → **Safe plan** seçin. Current finding ID avtomatik götürülür.

Yenilənmiş paneldə bu bölmə **2 · Plan və tətbiq** adlanır. Tapıntını siyahıdan seçmək mümkündür; ID-ni əllə köçürmək lazım deyil. Başqa tapıntı seçiləndə əvvəlki plan ləğv olunur. Eyni plan üzrə əməliyyat yaradıldıqdan sonra ikinci dəfə təsdiq düyməsi bağlanır.

`Analyze & prepare safe plan` bunları bir əməliyyatda edir:

`RSoP/source analysis → approved safe GPO selection → impact preview → preflight → dry run`

Dry run üçün `writes = 0` olmalıdır. Bu mərhələ Apply job yaratmır. Plan hazır olduqdan sonra eyni Automation Center-də ayrıca **Apply** formu görünür; `APPLY` typed confirmation, gpupdate/restart seçimləri və broad-impact acknowledgement tələb olunur. Job yarandıqdan sonra execution record linki açılır.

## 9. Controlled Write Mode

Real Windows mode-da Setup bölməsində write gate görünür.

Enable üçün exact:

```text
ENABLE WRITES
```

yazılır. Disable üçün:

```text
DISABLE WRITES
```

Write gate açıq olsa belə Apply ayrıca preview ID, explicit operator action, backup və verification guardrail-lərini tələb edir.

## 10. Apply və verification

Base finding workflow-dan Apply ediləndə:

1. preview/fingerprint yenidən yoxlanır;
2. permission və scope preflight edilir;
3. GPO backup alınır;
4. policy-specific adapter write edir;
5. stored GPO state yoxlanır;
6. scope/link/filter yoxlanır;
7. lazım olsa gpupdate/restart flow işləyir;
8. RSoP yoxlanır;
9. endpoint effective state yoxlanır;
10. yalnız bundan sonra `PASS / COMPLIANT` verilir.

## 11. Rollback

Rollback explicit acknowledgement tələb edir. Full-GPO snapshot restore edə bildiyi üçün product backup-dan sonra başqa dəyişiklik olub-olmadığını yoxlayır və conflict varsa fail-closed dayanır.

## 12. Developer / validation əmrləri

Operator bunları işlətmir. Lazım olduqda:

```powershell
.\GpoRemediator.ps1 -Mode Build
.\GpoRemediator.ps1 -Mode Test
```

`-Mode Test` .NET invariant tests və isolated MOCK backend üzərində PowerShell HTTP smoke tests işlədir. Node test runner tələb etmir.

## 13. Troubleshooting

Əsas loglar:

```text
work\bootstrap.log
work\server.log
work\server-error.log
```

Əgər əvvəlki versiyadan `.tools\node` və `.tools\pnpm` qovluqları qalıbsa silmək məcburi deyil; yeni launcher onları istifadə etmir.

Əgər build `.NET` mərhələsində dayanırsa `work\bootstrap.log`-a baxın. Bootstrap mərhələsində heç bir GPO policy write edilmir.

## 14. Production qeydləri

- Birbaşa production-dan başlamayın; staging OU/server istifadə edin.
- Dedicated remediation GPO modeli üstün tutulur.
- Default domain GPO-ları remediation allowlist-ə daxil etməyin.
- Management host, backup path və audit DB ACL-lərini harden edin.
- Domain Admin gündəlik execution identity kimi istifadə edilməməlidir.
- Production auditini SIEM/WORM sink-ə forward etmək local hash-chain-dən daha güclü assurance verir.
