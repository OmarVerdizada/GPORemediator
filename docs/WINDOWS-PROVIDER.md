# Windows / Active Directory execution

Production əməliyyatları üçün Windows / AD rejimi, domen bağlantısı, AD DNS və writable DC tələb olunur. Setup/Recovery yalnız konfiqurasiyanı idarə edir.

## İcra kimlikləri

Web UI operatoru Windows Integrated Authentication və konfiqurasiyadakı rollar ilə səlahiyyətləndirilir. Domen əməliyyatları ayrıca daxil edilmiş delegated execution hesabı ilə Kerberos/WinRM üzərindən seçilmiş DC-də icra edilir. Backend service hesabı GPO icrası üçün avtomatik istifadə olunmur.

Delegated parol yalnız yaddaşda saxlanılır və lokal PowerShell prosesinə private stdin ilə ötürülür. Browser storage, process arguments, log, konfiqurasiya, audit və evidence fayllarına yazılmır. Brauzer ixtiyari script və ya registry əmri seçə bilməz; mapping server tərəfindən müəyyən edilir.

## Tələblər və icazələr

Seçilmiş DC ActiveDirectory və GroupPolicy/GPMC modullarını, SYSVOL və yazıla bilən backup repository-ni təmin etməlidir. Delegated hesab seçilmiş GPO-nu, lazım olduqda SYSVOL məzmununu və hədəf gPLink-i dəyişmək hüququna malik olmalıdır. Operatorun Web UI rolu bu domen icazələrindən ayrıdır.

Write gate və konkret GPO/scope icazəsi olmadan Apply, Rollback və Refresh icra edilmir. Wildcard yalnız read-only discovery üçündür. Readiness nəticəsində tələb olunan yoxlamalar uğurlu olmalıdır.

## Əməliyyat və recovery

Yeni preview yaradın, bütün mövcud linkləri və təsiri nəzərdən keçirin, change reference və təsdiqləri daxil edin. Backup-GPO siyasət dəyişməzdən əvvəl yaradılır. Apply avtomatik gpupdate işə salmır.

Publication, link, replikasiya və endpoint nəticələrini ayrıca yoxlayın. Qeyri-müəyyən nəticədə Apply-ni təkrar icra etməyin. Rollback yalnız dəyişməyən post-write fingerprint və tamamlanmış backup ilə mümkündür. Ətraflı addımlar `PRODUCTION-OPERATIONS.md` sənədindədir.
