# GPO Remediator — password-policy pilot

SecHard-da uğursuz görünən **parol parametrini seçin → test istifadəçisini yazın → planı yoxlayın → APPLY → nəticə / rollback**.

Bu mərhələ yalnız seçilmiş **bir domen istifadəçisi** üçün fine-grained password policy (PSO) yaradır. Domenin default siyasətini, GPO-ları və əvvəlki PSO-ları dəyişmir. Bir neçə test istifadəçisi üçün əməliyyatı ayrıca təkrarlayın. Digər modullar növbəti mərhələlərdə əlavə ediləcək.

## Başlamaq

`GpoRemediator.cmd` faylını açın və **Başlat** düyməsini basın. Launcher portable .NET SDK/runtime və statik interfeysi hazırlayır. Node.js və npm tələb olunmur.

1. **Sazlamalar** bölməsini açın. Domen, writable DC/PDC, management HTTPS ünvanı və operator avtomatik aşkarlanır. Aşkarlama yalnız mühit metadatasını oxuyur; kompüter, istifadəçi və compliance siyahısını skan etmir. Nəticə xidmət işlədiyi müddətdə yaddaşda saxlanır.
2. Lazım olsa dəyərləri əl ilə düzəldin. Mövcud sazlamalar avtomatik əvəz edilmir. HTTPS üçün management host adına uyğun etibarlı sertifikat lazımdır. **GPO GUID / OU / kompüter allowlist-i bu pilot üçün tələb olunmur.**
3. **Saxla və yenidən başlat** seçin. Windows rejimində **Hazırlığı yoxla**, sonra `ENABLE WRITES` ilə yazmanı ayrıca aktivləşdirin. Saxlama hər dəfə yazmanı bağlayır.
4. **Parol siyasətləri** səhifəsində SecHard-da uğursuz olan elementi seçin. Test istifadəçisinin sAMAccountName, UPN və ya object GUID dəyərini və SecHard-ın tələb etdiyi dəyəri daxil edin. İstifadəçi parolu istənilmir.
5. Plan seçilən istifadəçinin effektiv siyasətini oxuyur, digər dəyərləri saxlayır və yalnız seçilən dəyəri dəyişir. `APPLY` təsdiqindən sonra backup, PSO yaradılması, birbaşa user assignment və resultant-policy yoxlaması edilir.
6. Tarixçədə `ROLLBACK` ilə həmin pilot assignment-i silib əvvəlki effektiv siyasətə qayıdın. Bir neçə dəyişiklik varsa ən yenidən başlayın.

## Altı parametr

| Parametr | Dəyər |
|---|---|
| Enforce password history | 0–1024 parol |
| Maximum password age | 0–999 gün; 0 = müddətsiz |
| Minimum password age | 0–998 gün; maksimumdan kiçik olmalıdır |
| Minimum password length | 0–255 simvol |
| Password must meet complexity requirements | 0 / 1 |
| Store passwords using reversible encryption | 0 / 1 |

İnterfeysdəki ilkin dəyərlər nümunədir. SecHard nəticənizdəki tələbə uyğunlaşdırın. Lockout dəyərləri mövcud siyasətdən olduğu kimi köçürülür; bu mərhələdə ayrıca dəyişdirilmir.

## Sərhədlər və ilkin şərtlər

- **Avtomatik scan yoxdur.** Köhnə scan endpoint-i və qeyri-parol write endpoint-ləri bu release-də bloklanır. SecHard üçün canlı connector yoxdur; failed item və tələb olunan dəyər operator tərəfindən seçilir.
- Domain functional level Windows Server 2008 və ya daha yüksək, writable DC, ActiveDirectory RSAT, HTTPS + Windows Integrated Authentication tələb olunur. Xidmət identity-si PSO yaratmaq və test istifadəçisinə təyin etmək səlahiyyətinə malik olmalıdır.
- Readiness bağlantını yoxlayır; AD-yə test yazısı etmir və write icazəsini sübut etmir. İcazə çatmırsa Apply nəticəni uğurlu göstərmir.
- Privileged/protected hesablar test üçün qəbul edilmir. Mövcud PSO precedence 1-dirsə və ya password age tam günlə ifadə edilmirsə, avtomatik dəyişiklik bloklanır.
- PSO testi domain-wide GPO tapıntısını düzəltmir. `VERIFIED` seçilən DC-də həmin istifadəçinin resultant policy nəticəsidir; AD replication və SecHard retest ayrıca aparılmalıdır. Mövcud parollar dəyişdirilmir və reset edilmir.
- `MOCK` yalnız lokal simulyasiyadır. Demo PASS real AD hazırlığı demək deyil. Real və demo məlumat bazaları ayrıdır.
- Plan 15 dəqiqə keçdikdə, operator/mühit və ya effektiv siyasət dəyişdikdə yenidən hazırlanmalıdır. Apply təkrarı ikinci PSO yaratmır.

## Backup və bərpa

Real Apply-dən əvvəl tam preview `${BackupPath}\PasswordPilot\<plan-id>.json` faylına yazılır. Qovluq service identity, SYSTEM və lokal administratorlara məhdudlaşdırılır. Lokal SQLite tarixçəsi və audit də saxlanır.

Rollback yalnız tətbiqin həmin əməliyyatda yaratdığı, dəyişdirilməmiş və başqa istifadəçilərə verilməmiş PSO-nu silir. Əvvəlki PSO-ya toxunmur. Crash/timeout zamanı əməliyyat avtomatik təkrarlanmır; tarixçəni və backup-ı yoxlayın. UI açılmırsa `scripts\Recover-PasswordPilot.ps1` backup ilə interaktiv bərpa üçündür. Ətraflı: [Password pilot](docs/PASSWORD-PILOT.md).

## Yoxlama

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\PasswordPilot.ps1
```

`Test.ps1` .NET invariant testləri və ayrı demo database üzərində HTTP smoke testləri işlədir. `PasswordPilot.ps1` real dispatcher-i saxta AD cmdlet-ləri ilə yoxlayır; domenə qoşulmur. Real AD test domenində acceptance addımları [docs/PASSWORD-PILOT.md](docs/PASSWORD-PILOT.md) faylındadır.

`backend/appsettings.Local.json`, runtime, SDK, database və iş faylları Git-ə göndərilmir. Tarixi GPO adapterləri kodda saxlanılıb, lakin cari UI və write API yalnız password pilot-u aktivləşdirir.
