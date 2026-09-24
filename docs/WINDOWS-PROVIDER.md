# Windows / Active Directory provider

Bu sənəd `Mode=Windows` rejiminin necə işlədiyini və real domenə keçməzdən əvvəl hansı şərtlərin ödənməli olduğunu izah edir. **MOCK nəticəsi real AD qəbul sınağını əvəz etmir.** İlk real yoxlamanı ayrıca laboratoriya domenində və `Windows.EnableWrites=false` ilə aparın.

## 1. İcra modeli

Tətbiq iki ayrı kimlikdən istifadə edir:

- **Operator identity** — brauzer sorğusunu Windows Integrated Authentication ilə edən istifadəçidir. `Windows.AllowedOperators` server-side allowlist ilə məhdudlaşdırılır.
- **Execution identity** — ASP.NET prosesinin / Windows service-in domen hesabıdır. GPO, AD, SYSVOL, WinRM və backup əməliyyatlarını bu hesab icra edir.

Brauzerdən parol, PowerShell scripti, GPO yolu və ya ixtiyari registry əmri qəbul edilmir. Backend yalnız kataloqda əvvəlcədən nəzərdən keçirilmiş control adapterlərini sabit PowerShell əməliyyatlarına çevirir.

Tövsiyə olunan production modeli ayrıca least-privilege service hesabı və ya gMSA-dır. Domain Admin gündəlik icra hesabı kimi nəzərdə tutulmayıb.

## 2. Minimum platform tələbləri

Real execution host üçün:

- domain member Windows Server;
- Windows PowerShell 5.1;
- `ActiveDirectory` və `GroupPolicy` PowerShell modulları;
- writable DC-yə DNS/Kerberos, LDAP/AD və SYSVOL çıxışı;
- target serverlərə WinRM/Kerberos çıxışı;
- endpoint-də `root\rsop\computer` RSoP oxuma imkanı;
- HTTPS üçün etibarlı server sertifikatı;
- service identity üçün qorunan backup qovluğuna write hüququ;
- yalnız konkret host, OU və GPO-lar üçün delegasiya edilmiş hüquqlar.

Target FQDN-ləri və DC FQDN-i DNS-də düzgün resolve olunmalıdır. IP ilə Kerberos iş axını nəzərdə tutulmayıb.

## 3. Konfiqurasiya və unified launcher

Operatorun normal istifadəsində JSON-u əl ilə kopyalamaq lazım deyil. `GpoRemediator.cmd` ilk dəfə safe MOCK UI açır; `Setup & settings` wizard domain/DC, approved GPO GUID, OU, host, operator, backup path və HTTPS URL-ni validate edib `backend/appsettings.Local.json` yaradır. Save əməliyyatı həmişə `EnableWrites=false` saxlayır və controlled restart marker vasitəsilə eyni launcher-i Windows mode-a keçirir.

Konfiqurasiyanın mahiyyəti aşağıdakı kimidir:

```json
{
  "Mode": "Windows",
  "Urls": "https://management.example.com:5443",
  "Windows": {
    "EnableWrites": false,
    "Domain": "example.com",
    "DomainController": "dc01.example.com",
    "ApprovedGpoIds": ["11111111-2222-3333-4444-555555555555"],
    "AuthorizedOus": ["OU=Servers,DC=example,DC=com"],
    "AllowedHosts": ["srv-app-01.example.com"],
    "AllowedOperators": ["EXAMPLE\\gpo.operator"],
    "AllowCreateGpo": false,
    "BackupPath": "C:\\ProgramData\\GpoRemediator\\Backups"
  }
}
```

`ApprovedGpoIds`, `AuthorizedOus`, `AllowedHosts` və `AllowedOperators` exact allowlist-dir. Default Domain Policy və Default Domain Controllers Policy write üçün rədd olunur.

Windows mode-da readiness PASS olduqdan sonra UI-də `ENABLE WRITES` typed confirmation ilə write gate açıla bilər; dəyişiklik controlled restart ilə tətbiq olunur. `DISABLE WRITES` eyni qaydada gate-i bağlayır.

## 4. HTTPS və authentication

Windows rejimi HTTP ilə başlamamalıdır. `Urls` `https://` olmalı, sertifikat server DNS adına uyğun gəlməli və process identity private key-i oxuya bilməlidir.

Remote operator istifadəsində Windows Integrated Authentication aktiv olur. `AllowedOperators` ayrıca tətbiq səviyyəsində yoxlanılır; yalnız AD login olmaq GPO write icazəsi vermir.

## 5. GPO discovery: selector-a nə düşür?

Selector sadəcə GPMC-də OU/domain-a link edilmiş bütün GPO-ları göstərmir. Real provider target kompüterin **logging-mode RSoP** məlumatını oxuyur:

1. `RSOP_GPLink` içindən `enabled=true` və `appliedOrder > 0` olan linklər götürülür.
2. Onlar `RSOP_GPO` obyektləri ilə resolve edilir.
3. disabled, access-denied və WMI filter-dan keçməyən obyektlər actionable siyahıya daxil edilmir.
4. Seçilən konkret setting üçün ayrıca RSoP class oxunur; `precedence=1` olan tək instance winning GPO kimi qəbul edilir.
5. RSoP oxunmursa və ya nəticə qeyri-müəyyəndirsə tətbiq təhlükəsiz şəkildə `AMBIGUOUS` qaytarır və real GPO seçim vermir.

Bu yanaşma “link edilmişdir” ilə “bu endpoint-ə faktiki tətbiq olunmuşdur” anlayışlarını ayırır. Yenə də RSoP son policy cycle-a aiddir; dəyişiklikdən sonra `gpupdate`, yeni RSoP və endpoint verification məcburidir.

## 6. Mövcud production adapterləri

MVP-də write adapterləri qəsdən məhduddur:

- `USER_RIGHTS_ASSIGNMENT` — hazır nümunədə `SeNetworkLogonRight`, security template (`GptTmpl.inf`) vasitəsilə;
- bəzi `SECURITY_OPTION` DWORD parametrləri — security template `Registry Values` bölməsi;
- nəzərdən keçirilmiş `REGISTRY_POLICY` / `ADMINISTRATIVE_TEMPLATE` nümunələri — GroupPolicy registry cmdlet-ləri.

Account Policy/PSO, Advanced Audit Policy, Firewall, Service Configuration, Registry Preference və sərbəst PowerShell bu MVP-də generic writer kimi açılmır. Hər yeni policy family ayrıca adapter, backup və verification modelinə malik olmalıdır.

## 7. Preflight

Real `Apply`-dan əvvəl ən azı bunlar PASS olmalıdır:

- target server server-side allowlist-dədir və AD-də dəqiq bir computer object kimi tapılır;
- actual OU `AuthorizedOus` içindədir;
- target role/profile AD-dən müəyyən edilən rolle uyğun gəlir;
- GPO GUID `ApprovedGpoIds` içindədir;
- protected GPO deyil;
- execution identity GPO-nu oxuya və tələb olunan halda redaktə edə bilir;
- AD/SYSVOL GPO version məlumatı oxunur;
- endpoint WinRM/Kerberos və RSoP verification yolu işləyir;
- backup qovluğu əlçatandır.

Preflight xətasını brauzerdən “override” etmək nəzərdə tutulmayıb.

## 8. Apply workflow

Normal dəyişiklik axını:

`Analyze → Preview → Dry Run → Preflight → Backup-GPO → Write → GPO verify → Scope verify → gpupdate → RSoP verify → Endpoint verify → PASS`

Əsas təhlükəsizlik qaydaları:

- preview fingerprint köhnəlibsə apply rədd olunur;
- apply-dan dərhal əvvəl GPO version yenidən yoxlanır;
- write-dan əvvəl tam `Backup-GPO` yaradılır;
- write yalnız kataloqda təsdiqlənmiş expected value üçün mümkündür;
- GPO read-back, AD/SYSVOL metadata, scope, RSoP və endpoint ayrıca yoxlanır;
- verification tamamlanmayıbsa `PASS` verilmir;
- restart tələb edən control avtomatik təkrar restart sorğusu göndərmir.

## 9. Rollback

Rollback sadəcə “əvvəlki registry value”-nu geri yazmır; saxlanmış GPO backup bərpa edilir. Avtomatik rollback-dan əvvəl:

- cari GPO version post-write version ilə uyğun olmalıdır;
- scope/filter vəziyyəti gözlənilmədən dəyişibsə rollback dayanır;
- restore-dan əvvəl ayrıca rollback safety backup saxlanılır;
- restore-dan sonra GPO content və endpoint/effective vəziyyət yenidən yoxlanır.

Backup-dan sonra başqa administrator GPO-nu dəyişibsə avtomatik rollback onun dəyişikliklərini üstələməmək üçün bloklanmalıdır. Belə vəziyyətdə GPMC ilə manual recovery proseduru istifadə olunur.

## 10. Real rejimi başlatmaq

Normal operator əmri yalnız budur:

```text
GpoRemediator.cmd
```

Launcher source fingerprint-lərini yoxlayır. Backend build lazımdırsa portable .NET 8 SDK-nı project-local `.tools\dotnet` altında provision edir; static frontend `frontend\source`-dan dependency olmadan paketlənir. Node.js/npm/pnpm/Corepack və npm registry tələb olunmur. Windows mode üçün RSAT yoxdursa UAC-approved ayrıca prerequisite helper işə düşür; application prosesi sırf buna görə elevated saxlanmır.

Konfiqurasiya yoxdursa MOCK onboarding açılır. Konfiqurasiya varsa launcher Windows mode-u seçir. Windows mode certificate/config səbəbilə erkən start edə bilməsə safe MOCK UI-yə fallback edir ki, setup düzəldilə bilsin.

`Build-Portable.ps1`, `Test.ps1`, `Start-*` faylları development/compatibility utility-ləridir və gündəlik operator workflow-u deyil.

## 11. İlk real qəbul sınağı

İlk sınaqda yalnız bir test server və bir dedicated remediation GPO istifadə edin:

1. GPO-nu əvvəlcədən GPMC-də yaradın və test OU-ya link edin.
2. GPO GUID, test host FQDN və OU DN-ni allowlist-ə əlavə edin.
3. `EnableWrites=false` ilə UI readiness yoxlamasını və `Target scan`-ı işlədin; sonra finding-də `Auto prepare safe plan` ilə Analyze → Preview → Dry Run zəncirini hazırlayın.
4. UI-də yalnız endpoint RSoP-da faktiki applied olan GPO-ların gəldiyini yoxlayın.
5. Service identity-nin GPO read/edit, backup və WinRM hüquqlarını preflight ilə yoxlayın.
6. Change approval-dan sonra UI-də exact `ENABLE WRITES` confirmation verin; controlled restart write gate-i aktivləşdirəcək.
7. Bir control tətbiq edin; GPO verify, scope verify, gpupdate, RSoP və endpoint verify hamısını ayrıca təsdiqləyin.
8. Rollback edin və əvvəlki effective vəziyyətin qayıtdığını yoxlayın.
9. Audit history və backup artefaktlarını saxlayın.

## 12. Tipik xətalar

- `WINDOWS_CONFIG` — Domain/DC düzgün deyil və ya FQDN validation keçmir.
- `WINDOWS_ALLOWLIST_EMPTY` — host/OU/GPO allowlist boşdur.
- `TARGET_NOT_APPROVED` / `OU_NOT_APPROVED` — target server-side scope-dan kənardadır.
- `GPO_NOT_APPROVED` / `PROTECTED_GPO` — GPO write üçün təsdiqlənməyib və ya qorunan default GPO-dur.
- `SOURCE_AMBIGUOUS` — RSoP winning source-u etibarlı müəyyən etməyib.
- `BACKUP_REQUIRED` / `BACKUP_STALE` — write üçün uyğun rollback snapshot yoxdur.
- `GPO_CONCURRENT_CHANGE` tipli version/fingerprint konflikti — GPO başqa proses tərəfindən dəyişib; avtomatik işi dayandırın.
- `RSOP_REPLICATION_OR_PRECEDENCE_PENDING` — yeni effective policy hələ winning source kimi görünmür.
- `ENDPOINT_PENDING` — endpoint effective value gözlənilən deyil; PASS verilmir.

## 13. Production hardening qeydləri

MVP-ni production service kimi yerləşdirərkən əlavə olaraq service recovery, mərkəzi log forwarding, backup ACL/retention, reverse proxy və ya enterprise TLS standardı, endpoint firewall qaydaları, patching, certificate rotation, SQLite backup/retention və audit artefaktlarının xarici immutable saxlanması ayrıca planlanmalıdır.

Yeni GPO yaratma/link etmə browser workflow-na açılmır. Provisioning ayrı administrative proses kimi saxlanır; sonra yalnız təsdiqlənmiş GUID application allowlist-ə əlavə edilir.
