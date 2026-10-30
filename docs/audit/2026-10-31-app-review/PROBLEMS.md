# GPORemediator — tam tətbiq auditi

Tarix: 31 oktyabr 2026, Asia/Baku. Versiya: 3.17.4. Commit: `ea5dcf7e85c2adac26dae33c676b81157c20b40c`.

**3.17.4 auditində 18 tapıntı: 4 P1, 11 P2, 3 P3. Hamısı 3.17.5-də düzəldilib və yerli regressiya testləri keçib.** [Düzəlişlər və testlər](RESOLUTION.md). P1: məlumat bütövlüyü, səlahiyyət sərhədi və ya aktiv əməliyyat üçün yüksək təsir. P2: funksional/nəticə/istifadə problemi. P3: aşağı prioritetli metadata, sənəd və kod təmizliyi.

Aşağıdakı müşahidələr 3.17.4 baseline-a aiddir; əvvəlki sübutlar saxlanılıb. Cari status: RESOLVED_LOCAL (3.17.5). Real AD-yə yazı və ya real tətbiq prosesinin dayandırılması aparılmayıb. Canlı domain təsdiqi yerli testlərin əhatəsinə daxil deyil.

## Əhatə və sübut sərhədi

23 backend C# faylı, 5 backend PowerShell mənbəyi, 25 frontend JS mənbəyinin arxitekturası və əlaqəli HTML/CSS, konfiqurasiya, SQLite/evidence, launcher/installer, CI və test axınları nəzərdən keçirildi. Generated engine və runtime üçün mövcud source/hash yoxlaması əsas götürüldü. Bütün mənbə fayllarının hər mümkün runtime yolunun icra edildiyi iddia edilmir.

Eyni commit üçün əvvəlki 69-check audit, 405 control/413 scope tətbiq matrisi və 1,148 endpoint fixture yoxlamasının nəticələri saxlanır. Yeni audit bu sınaqlarda olmayan negative/race/report ssenarilərini yoxladı. Əvvəlki testlərin keçməsi aşağıdakı problemləri istisna etmir.

Yeni sübutlar: C#-da real service/store/rules + in-memory DB; real worker helper-ləri və private filesystem; launcher stop üçün təhlükəsiz mock; real Chromium ilə GPO/OU modalları və Reports. Discovery reproduksiyası async endpoint-i AD-yə işlətmək əvəzinə həmin private connection CAS əməliyyatını heartbeat ilə yarışı canlandıraraq yoxlayır. Domain scan reproduksiyası real ProcessScan və real target validator, AD-siz stub istifadə edir.

## Problemlər siyahısı

| ID | Prioritet | Sahə | Problem |
|---|---|---|---|
| A01 | P1 | Launcher / recovery | [Aktiv əməliyyatın Stop qoruması launcher tərəfindən keçilə bilir](#a01) |
| A02 | P1 | PowerShell / rollback integrity | [Hidden GPO faylları drift fingerprint-inə daxil edilmir](#a02) |
| A03 | P1 | PowerShell / backup trust | [Backup readiness təhlükəli child workspace ACL-ni nəzərdən qaçırır](#a03) |
| A04 | P1 | Frontend / reports / evidence classification | [Reports səhifəsi və ixraclar mismatch-i verified göstərə bilir](#a04) |
| A05 | P2 | Frontend / catalog / dashboard / stepper | [Dəqiq tövsiyə planları custom sayılır və xəta etiketi gizlənir](#a05) |
| A06 | P2 | Backend API / history / reports | [Tarixçə 200 qeyddə kəsilir, UI bütün tarixçəni axtara bilmir](#a06) |
| A07 | P2 | Backend / concurrency / inventory | [Discovery nəticəsi heartbeat ilə toqquşanda sessiyada itir](#a07) |
| A08 | P2 | Backend / evidence export | [Operation evidence JSON refresh və coverage sübutlarını buraxır](#a08) |
| A09 | P2 | PowerShell / verification / applicability | [Re-verify cari GPO policy-half disabled vəziyyətini yoxlamır](#a09) |
| A10 | P2 | CI / regression reliability | [GitHub Actions silinmiş test fayllarını çağırır](#a10) |
| A11 | P2 | Permissions / diagnostics | [Domain account access report AD property yazı hüququnu yoxlamır](#a11) |
| A12 | P2 | Backend / HTML report | [Workflow HTML hesabatı link nəticəsini sabit Enabled yazır](#a12) |
| A13 | P2 | Backend / retained scan API | [Domain scan sorğusu lokal account scan-ə çevrilir](#a13) |
| A14 | P2 | Frontend / accessibility / target selection | [GPO və OU modalında klaviatura fokusu arxa səhifəyə çıxır](#a14) |
| A15 | P2 | Frontend / asynchronous operations | [Accepted job-dan sonra reload xətası live polling-i dayandıra bilir](#a15) |
| A16 | P3 | Frontend / risk display | [Metadata fallback domain policy riskini Low göstərir](#a16) |
| A17 | P3 | Frontend / maintainability | [Silinmiş axınlardan qalan və kölgələnən frontend kodu var](#a17) |
| A18 | P3 | Documentation / operational contract | [Security və retention sənədləri cari davranışla uyğun deyil](#a18) |

<a id="a01"></a>
## A01 · P1 · Aktiv əməliyyatın Stop qoruması launcher tərəfindən keçilə bilir

**Status:** RESOLVED_LOCAL (3.17.5; [düzəliş matrisi](RESOLUTION.md)). **Sahə:** Launcher / recovery.

**Yer:** [GpoRemediator.ps1:445](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/GpoRemediator.ps1#L445), [GpoRemediator.ps1:460](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/GpoRemediator.ps1#L460).

**Sübut:** Stop-StaleProductInstance təkrar sınağında normal Stop aktiv əməliyyat səbəbilə rədd edildi. Buna baxmayaraq catch Stop-Process -Force çağırdı: forcedStopInvoked=true. Real proses dayandırılmadı; çağırış mock idi.

**Təsir:** Fərqli qovluqdakı yeni versiyanı açmaq davam edən Apply/backup/rollback prosesini kəsə bilər. DC-də iş davam edərkən yerli qeyd qeyri-müəyyən qala bilər.

**Düzəliş istiqaməti:** 403/423 kimi normal rədd cavablarını yuxarı qaytarmaq; zorla dayandırmanı yalnız ayrıca, açıq emergency əməliyyatına buraxmaq.

**Qəbul meyarı:** Aktiv iş üçün migration və ikinci launcher açılışı Force çağırmamalı, mövcud iş tamamlanmalıdır.

<a id="a02"></a>
## A02 · P1 · Hidden GPO faylları drift fingerprint-inə daxil edilmir

**Status:** RESOLVED_LOCAL (3.17.5; [düzəliş matrisi](RESOLUTION.md)). **Sahə:** PowerShell / rollback integrity.

**Yer:** [backend/PowerShell/SecurityTemplate.psm1:86](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/backend/PowerShell/SecurityTemplate.psm1#L86), [backend/PowerShell/SecurityTemplate.psm1:92](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/backend/PowerShell/SecurityTemplate.psm1#L92).

**Sübut:** Real müvəqqəti Registry.pol faylı Hidden atributu ilə yaradıldı. Məzmun before-dan after-a dəyişdi, atribut yenidən Hidden oldu. Get-NormalizedGpoContentFingerprint əvvəl və sonra eyni hash verdi.

**Təsir:** Hidden fayldakı kənar dəyişiklik tam GPO snapshot rollback-inin drift qorumasından yayınır. Bərpa həmin dəyişikliyi əzə bilər.

**Düzəliş istiqaməti:** Hidden/System daxil olmaqla bütün uyğun GPO fayllarını -Force ilə hash-ləmək; reparse və oxuma xətalarında fail closed saxlamaq.

**Qəbul meyarı:** Normal, Hidden və System policy fayllarının hər birində məzmun dəyişikliyi fingerprint-i dəyişməli və rollback-i bloklamalıdır.

<a id="a03"></a>
## A03 · P1 · Backup readiness təhlükəli child workspace ACL-ni nəzərdən qaçırır

**Status:** RESOLVED_LOCAL (3.17.5; [düzəliş matrisi](RESOLUTION.md)). **Sahə:** PowerShell / backup trust.

**Yer:** [backend/PowerShell/GpoWorkflow.Worker.ps1:335](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/backend/PowerShell/GpoWorkflow.Worker.ps1#L335), [backend/PowerShell/GpoWorkflow.Worker.ps1:363](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/backend/PowerShell/GpoWorkflow.Worker.ps1#L363).

**Sübut:** Real private temp qovluğunda backup root yalnız owner üçün təhlükəsiz edildi, mövcud GpoWorkflow child-na Everyone Modify verildi. Environment-Status ready=true və backup-acl=PASS qaytardı; childBroadModify=true, workspaceAclRead=false idi. AD və real backup repository dəyişdirilmədi.

**Təsir:** Mövcud child ACL inheritance-dan ayrılıbsa, backup və manifestlər geniş qrupa yazıla bilən halda readiness yaşıl qala bilər. Rollback etibarlı snapshot-a söykəndiyindən bu saxlanma bütövlüyü boşluğudur; real istismar bu auditdə edilməyib.

**Düzəliş istiqaməti:** Root ilə yanaşı faktiki GpoWorkflow/run/backup/manifest yollarının təhlükəsiz ACL və reparse vəziyyətini yoxlamaq; qeyri-müəyyən və təhlükəli vəziyyətdə Apply/rollback-i bloklamaq. Mövcud legitim delegation-u kor-koranə silməmək.

**Qəbul meyarı:** Safe root + Everyone/Authenticated Users Modify child halı required ACL check-də fail olmalı; yalnız konkret delegated identity-yə verilmiş legitim hüquqlar işləməlidir.

<a id="a04"></a>
## A04 · P1 · Reports səhifəsi və ixraclar mismatch-i verified göstərə bilir

**Status:** RESOLVED_LOCAL (3.17.5; [düzəliş matrisi](RESOLUTION.md)). **Sahə:** Frontend / reports / evidence classification.

**Yer:** [frontend/source/enterprise-center.js:15](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/frontend/source/enterprise-center.js#L15), [frontend/source/enterprise-center.js:18](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/frontend/source/enterprise-center.js#L18), [frontend/source/enterprise-center.js:20](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/frontend/source/enterprise-center.js#L20).

**Sübut:** Köhnə DOMAIN_VALUE_MATCHES_ON_SELECTED_DC qeydi üçün actual AD=30, requested=15 verildi. Control classifier effective=failed dedi; Reports EVIDENCE_VERIFIED qaytardı. Brauzerdə də 30 → 15 / observed 30 yaşıl göstərildi. Ayrı sınaqda failed refresh də report statusunu verified-dan çıxarmadı.

**Təsir:** Reports sayğacları, JSON/CSV/HTML/PDF nəticələri operator ekranındakı xəbərdarlıqla ziddiyyət yarada və yanlış audit sübutu verə bilər.

**Düzəliş istiqaməti:** Reports üçün ayrıca uğur məntiqi əvəzinə vahid assurance/classification istifadə etmək; DomainMismatch, refresh failures və endpoint states-i nəzərə almaq.

**Qəbul meyarı:** Eyni run Control, Reports, bütün ixrac formatları və sayğaclarda eyni nəticə verməlidir; 30/15 və failed refresh yaşıl olmamalıdır.

<a id="a05"></a>
## A05 · P2 · Dəqiq tövsiyə planları custom sayılır və xəta etiketi gizlənir

**Status:** RESOLVED_LOCAL (3.17.5; [düzəliş matrisi](RESOLUTION.md)). **Sahə:** Frontend / catalog / dashboard / stepper.

**Yer:** [frontend/source/ui-domain.js:19](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/frontend/source/ui-domain.js#L19), [frontend/source/product.js:36](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/frontend/source/product.js#L36), [frontend/source/control-view.js:27](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/frontend/source/control-view.js#L27), [frontend/source/workspace.js:203](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/frontend/source/workspace.js#L203).

**Sübut:** Yeni normal plan itemValues=[[15]] saxlayır. Dəyər dəqiq verified olsa da custom=true və compliant=false olur. Product.controlStatus attention-dan əvvəl custom-u yoxladığından mismatch üçün də Custom value · benchmark not verified göstərir.

**Təsir:** Tövsiyə ilə tətbiq olunan əksər yeni planlar Dashboard Verified results sayına və Verify tamamlanma işarəsinə düşmür; kataloq konkret Needs review siqnalını gizlədir.

**Düzəliş istiqaməti:** Exact intent ilə benchmark-dan fərqli custom seçimi ayırmaq; real xəta/attention etiketini custom qeydindən əvvəl göstərmək.

**Qəbul meyarı:** Tövsiyə ilə verified plan custom kimi səhv etiketlənməməli; mismatch və refresh failure həmişə Needs review görünməlidir.

<a id="a06"></a>
## A06 · P2 · Tarixçə 200 qeyddə kəsilir, UI bütün tarixçəni axtara bilmir

**Status:** RESOLVED_LOCAL (3.17.5; [düzəliş matrisi](RESOLUTION.md)). **Sahə:** Backend API / history / reports.

**Yer:** [backend/Infrastructure/Store.cs:140](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/backend/Infrastructure/Store.cs#L140), [backend/Infrastructure/Store.cs:144](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/backend/Infrastructure/Store.cs#L144).

**Sübut:** İn-memory bazaya 201 run yazıldı. Store.List 201 gördü, service.History yalnız 200 qaytardı. Endpoint-də cursor, total və əlavə səhifə parametri yoxdur.

**Təsir:** Köhnə əməliyyatlar Operations, report filterləri və rollback seçimindən yox olur. 405 control-un hamısına bir əməliyyat edildikdə belə bütün sübutlar UI-dan əlçatan olmur. DB qeydləri silinmir.

**Düzəliş istiqaməti:** Server-side pagination, axtarış/filter, total və birbaşa operation ID axtarışı əlavə etmək; report ixracının tam və ya səhifəlik olduğunu açıq göstərmək.

**Qəbul meyarı:** 201/405/1000 qeydin hamısı səhifələmə və axtarışla tapılmalı, köhnə rollback qeydi açılmalıdır.

<a id="a07"></a>
## A07 · P2 · Discovery nəticəsi heartbeat ilə toqquşanda sessiyada itir

**Status:** RESOLVED_LOCAL (3.17.5; [düzəliş matrisi](RESOLUTION.md)). **Sahə:** Backend / concurrency / inventory.

**Yer:** [backend/Services/GpoWorkflowService.cs:162](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/backend/Services/GpoWorkflowService.cs#L162), [backend/Services/GpoWorkflowService.cs:168](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/backend/Services/GpoWorkflowService.cs#L168).

**Sübut:** Discovery-nin saxladığı connection snapshot-dan sonra SessionStatus çağırıldı. Eyni TryUpdate əməliyyatı false qaytardı; yeni inventory 2 GPO olsa da sessiya 1 GPO saxladı. DiscoverAsync bu false nəticəni yoxlamır.

**Təsir:** UI yeni GPO/OU-nu görə bilər, sonrakı Preview isə serverdə köhnə inventory səbəbilə seçimi rədd edə bilər. Görünən konsolun heartbeat-i bu yarışa şərait yaradır.

**Düzəliş istiqaməti:** Yenilənmiş connection-u əsas götürən CAS retry/update tətbiq etmək; expiry və WriteTargets məlumatını itirmədən yalnız inventory-ni dəyişmək.

**Qəbul meyarı:** Discovery davam edərkən paralel SessionStatus/Inventory sorğuları yeni GPO və OU-ların saxlanmasına mane olmamalıdır.

<a id="a08"></a>
## A08 · P2 · Operation evidence JSON refresh və coverage sübutlarını buraxır

**Status:** RESOLVED_LOCAL (3.17.5; [düzəliş matrisi](RESOLUTION.md)). **Sahə:** Backend / evidence export.

**Yer:** [backend/Domain/GpoWorkflow.cs:73](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/backend/Domain/GpoWorkflow.cs#L73), [backend/Services/GpoWorkflowService.cs:389](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/backend/Services/GpoWorkflowService.cs#L389).

**Sübut:** Run-da bir failed RefreshResult, EndpointCoverage və RefreshCoverage vardı. service.Evidence JSON-unda refreshResults, endpointCoverage və refreshCoverage sahələrinin heç biri olmadı. Before AD snapshot da ayrıca export müqaviləsində yoxdur.

**Təsir:** Endirilən operation evidence-dən gpupdate nəticəsini və bütün hədəflərin yoxlanılıb-yoxlanmadığını müstəqil qiymətləndirmək olmur. Domain control-da GPO before ilə actual AD before fərqlənə bilər.

**Düzəliş istiqaməti:** Evidence schema-sına per-host refresh nəticələri, hər iki coverage, pinned target konteksti və beforeDomainPolicy əlavə etmək; integrity hash-ə daxil etmək.

**Qəbul meyarı:** UI-da görünən refresh failure, host sayları və AD əvvəlki dəyər export-da da saxlanmalıdır; hash bu sahələrin dəyişikliyini tutmalıdır.

<a id="a09"></a>
## A09 · P2 · Re-verify cari GPO policy-half disabled vəziyyətini yoxlamır

**Status:** RESOLVED_LOCAL (3.17.5; [düzəliş matrisi](RESOLUTION.md)). **Sahə:** PowerShell / verification / applicability.

**Yer:** [backend/PowerShell/GpoWorkflow.Worker.ps1:948](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/backend/PowerShell/GpoWorkflow.Worker.ps1#L948).

**Sübut:** ComputerSettingsDisabled GPO fixture-i ilə Verify-Published çağırıldı. Status oxuma sayı 0 idi, published=true, linked=true, effective=VERIFIED_ON_SAMPLE qayıtdı. Endpoint registry dəyəri əvvəlki kimi saxlanmışdı.

**Təsir:** Apply-dən sonra GPO-nun uyğun hissəsi söndürülsə də yoxlama bunu ayrıca bildirmir; Refresh preflight də bu helper-ə söykənir. Bu nəticə həmin GPO-nun tətbiq olunduğunun sübutu deyil.

**Düzəliş istiqaməti:** Verify və Refresh preflight-də seçilmiş GPO statusunu/uyğun policy half-ı yenidən oxumaq və disabled halını explicit applicability failure kimi göstərmək.

**Qəbul meyarı:** Computer/User/AllSettingsDisabled keçidləri ayrıca diaqnostika yaratmalı; aktiv publication/applicability kimi qəbul edilməməlidir.

<a id="a10"></a>
## A10 · P2 · GitHub Actions silinmiş test fayllarını çağırır

**Status:** RESOLVED_LOCAL (3.17.5; [düzəliş matrisi](RESOLUTION.md)). **Sahə:** CI / regression reliability.

**Yer:** [.github/workflows/security-checks.yml:75](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/.github/workflows/security-checks.yml#L75), [.github/workflows/security-checks.yml:87](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/.github/workflows/security-checks.yml#L87), [.github/workflows/security-checks.yml:104](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/.github/workflows/security-checks.yml#L104).

**Sübut:** Workflow-da 34 script istinadı yoxlandı. Test-Studio-UI.cjs, Test-RecipeWorkspace.cjs və Test-WorkflowUi.cjs repoda yoxdur. Yerli 69-check runner bu workflow ilə eyni giriş nöqtəsi deyil.

**Təsir:** Bu CI job həmin sətirlərə çatanda MODULE_NOT_FOUND ilə dayanır. Yerli auditin keçməsi GitHub Actions-ın keçdiyini təsdiqləmir. Remote Actions run nəticəsi bu auditdə təsdiqlənməyib.

**Düzəliş istiqaməti:** Retired UI testlərini workflow-dan çıxarmaq, cari suite ilə sinxronlaşdırmaq və mümkün qədər vahid audit entry point işlətmək.

**Qəbul meyarı:** CI-də istinad edilən bütün scriptlər mövcud olmalı; cari exact-value, domain mismatch, atomic text və live UI regresiyaları pipeline-a daxil edilməlidir.

<a id="a11"></a>
## A11 · P2 · Domain account access report AD property yazı hüququnu yoxlamır

**Status:** RESOLVED_LOCAL (3.17.5; [düzəliş matrisi](RESOLUTION.md)). **Sahə:** Permissions / diagnostics.

**Yer:** [backend/PowerShell/PolicyDiagnostics.ps1:2](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/backend/PowerShell/PolicyDiagnostics.ps1#L2), [backend/PowerShell/PolicyDiagnostics.ps1:25](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/backend/PowerShell/PolicyDiagnostics.ps1#L25).

**Sübut:** Domain property write hüququ olmayan fixture-də GPO/link/file hüquqları ALLOWED edildi. Access-Report ready=true verdi, Domain-PolicyAccess çağırış sayı 0 oldu. Əsl Preview sonradan həmin ayrıca yoxlamanı aparır.

**Təsir:** Access & evidence səhifəsində exact permissions ALLOWED görünsə də domain account Apply üçün zəruri AD atribut hüququ çatışmaya bilər. Sonrakı Preview bunu təhlükəsiz bloklayır.

**Düzəliş istiqaməti:** Domain-sensitive mapping üçün dəqiq domain atribut yazı hüququnu access report-a ayrıca required sətir kimi əlavə etmək.

**Qəbul meyarı:** GPO edit/link icazəsi olan, AD lockout/password atributunu yaza bilməyən hesab üçün report ready=false və konkret çatışmayan hüquq göstərməlidir.

<a id="a12"></a>
## A12 · P2 · Workflow HTML hesabatı link nəticəsini sabit Enabled yazır

**Status:** RESOLVED_LOCAL (3.17.5; [düzəliş matrisi](RESOLUTION.md)). **Sahə:** Backend / HTML report.

**Yer:** [backend/Infrastructure/WorkspaceEndpoints.cs:49](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/backend/Infrastructure/WorkspaceEndpoints.cs#L49).

**Sübut:** Real Report generatoruna ROLLED_BACK run və currentLink.enabled=false verildi. Link sətri yenə Absent / Enabled; preserve existing order, or append a new link çıxardı.

**Təsir:** Approved / recorded result sütununda niyyət və faktiki nəticə qarışır. Rollback/failure/missing-link halında oxucu linkin enabled olduğunu düşünə bilər.

**Düzəliş istiqaməti:** Link intent və observed currentLink-i ayrı sahələrdə göstərmək; ölçü yoxdursa unknown yazmaq, Enabled nəticəsini sabit mətnlə verməmək.

**Qəbul meyarı:** Created/enabled/disabled/absent/rolled-back hallarının hər biri düzgün link nəticəsini göstərməlidir.

<a id="a13"></a>
## A13 · P2 · Domain scan sorğusu lokal account scan-ə çevrilir

**Status:** RESOLVED_LOCAL (3.17.5; [düzəliş matrisi](RESOLUTION.md)). **Sahə:** Backend / retained scan API.

**Yer:** [backend/Services/WorkspaceWorkflows.cs:190](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/backend/Services/WorkspaceWorkflows.cs#L190).

**Sübut:** ProcessScan-a accountScope=Domain, domain-root target və 1.2.1 verildi. O, Preview-a LocalComputers göndərdi. Həqiqi ValidateTarget nəticəsi LOCAL_ACCOUNT_OU_REQUIRED oldu, scan row NOT_CHECKED saxlandı.

**Təsir:** Retained scan API domain account control-larını istənilən scope ilə yoxlamır. Cari UI-da scan səhifəsi yoxdur; bu backend/legacy API funksiyasının problemidir.

**Düzəliş istiqaməti:** Sorğunun account scope niyyətini qorumaq və ya endpoint-i açıq computer-OU-only etmək; dəstəklənməyən domain sorğusunu əvvəlcədən rədd etmək.

**Qəbul meyarı:** Domain root scan 1.1/1.2 account control-larını AD domain kontekstində yoxlamalı; OU scan lokal hesab kontekstində qalmalıdır.

<a id="a14"></a>
## A14 · P2 · GPO və OU modalında klaviatura fokusu arxa səhifəyə çıxır

**Status:** RESOLVED_LOCAL (3.17.5; [düzəliş matrisi](RESOLUTION.md)). **Sahə:** Frontend / accessibility / target selection.

**Yer:** [frontend/source/workspace.js:386](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/frontend/source/workspace.js#L386), [frontend/source/control-view.js:47](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/frontend/source/control-view.js#L47), [frontend/source/gpo-scope-picker.js:73](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/frontend/source/gpo-scope-picker.js#L73).

**Sübut:** Real headless Chromium-da hər modalın son düyməsinə fokus verilib Tab basıldı. GPO və OU üçün fokusun dialoqdan kənara çıxması true oldu. JavaScript page error yox idi.

**Təsir:** aria-modal pəncərə açıqkən klaviatura istifadəçisi arxa formaya və əməliyyat elementlərinə keçə bilir. Modalın öz Tab trap-i yoxdur; mövcud trap yalnız product-drawer və confirm-dialog üçündür.

**Düzəliş istiqaməti:** Bütün modal növləri üçün ümumi focus trap, background inert və açan düyməyə focus return tətbiq etmək.

**Qəbul meyarı:** Tab/Shift+Tab modal daxilində dövr etməli; Escape bağlamalı; background input/action-lar fokuslana bilməməlidir.

<a id="a15"></a>
## A15 · P2 · Accepted job-dan sonra reload xətası live polling-i dayandıra bilir

**Status:** RESOLVED_LOCAL (3.17.5; [düzəliş matrisi](RESOLUTION.md)). **Sahə:** Frontend / asynchronous operations.

**Yer:** [frontend/source/operation-monitor.js:17](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/frontend/source/operation-monitor.js#L17), [frontend/source/operation-monitor.js:24](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/frontend/source/operation-monitor.js#L24).

**Sübut:** Server apply job-unu QUEUED kimi qəbul etdi. Sonrakı reload üçün /workflows GET bir dəfə xəta verdi. Bağlantı bərpa ediləndən sonra #/control-da poll çağırıldı, amma yeni API çağırışı sayı 0 oldu: queued job singleOperation-da olsa da workflowJobs boş idi.

**Təsir:** Accepted əməliyyat növbədə qaldıqda control səhifəsi yenilənməyə bilər. Manual Refresh və ya Operations-a keçid tələb olunur; job serverdə yenə mövcuddur.

**Düzəliş istiqaməti:** Polling şərtinə aktiv singleOperation.job-u daxil etmək; acceptance-dan sonrakı reload xətasını submission failure-dan ayırmaq və təkrar read-only poll etmək.

**Qəbul meyarı:** Accepted → bir transient GET failure → recovery ssenarisində control səhifəsi istifadəçi müdaxiləsi olmadan terminal nəticəyə çatmalıdır.

<a id="a16"></a>
## A16 · P3 · Metadata fallback domain policy riskini Low göstərir

**Status:** RESOLVED_LOCAL (3.17.5; [düzəliş matrisi](RESOLUTION.md)). **Sahə:** Frontend / risk display.

**Yer:** [frontend/source/ui-domain.js:46](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/frontend/source/ui-domain.js#L46).

**Sübut:** automation=Automated və domainPolicySensitive=true olan, operationalImpact sahəsi olmayan mapping üçün impact() Low qaytardı. Normal connected settings API HIGH qaytarır; problem fallback/offline kontekstinə aiddir.

**Təsir:** Offline/manual hazırlıq görünüşündə domain-wide əməliyyatın risk etiketi aşağı görünə bilər.

**Düzəliş istiqaməti:** Fallback hesablamasında domainPolicySensitive və requiresRestart flag-lərini də nəzərə almaq.

**Qəbul meyarı:** Server annotation-u olmadıqda belə domain/restart-sensitive mapping High olmalıdır.

<a id="a17"></a>
## A17 · P3 · Silinmiş axınlardan qalan və kölgələnən frontend kodu var

**Status:** RESOLVED_LOCAL (3.17.5; [düzəliş matrisi](RESOLUTION.md)). **Sahə:** Frontend / maintainability.

**Yer:** [frontend/source/workspace.js:221](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/frontend/source/workspace.js#L221), [frontend/source/workspace.js:222](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/frontend/source/workspace.js#L222), [frontend/source/client.js:11](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/frontend/source/client.js#L11), [frontend/source/operator-sign-in.js:33](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/frontend/source/operator-sign-in.js#L33).

**Sübut:** notifications() eyni scope-da iki dəfə elan edilib; sonuncu birincini əvəz edir. ephemeralCredential.set üçün application source-da çağırış yoxdur; cari sign-in onu clear edir, credential replay infrastrukturu isə qalıb.

**Təsir:** Hazırkı normal sign-in axınında bu cache doldurulmur. Qalıq kod sessiya/restart davranışını anlamağı və dəyişməyi çətinləşdirir; bu ayrıca credential leak sübutu deyil.

**Düzəliş istiqaməti:** Kölgələnən funksiyanı və artıq işləməyən replay/cache axınını təmizləmək; cari no-browser-password-retention davranışını qorumaq.

**Qəbul meyarı:** Bir notifications implementasiyası və sənədlə uyğun, istifadə olunan sessiya bərpa axını qalmalıdır.

<a id="a18"></a>
## A18 · P3 · Security və retention sənədləri cari davranışla uyğun deyil

**Status:** RESOLVED_LOCAL (3.17.5; [düzəliş matrisi](RESOLUTION.md)). **Sahə:** Documentation / operational contract.

**Yer:** [DATA-RETENTION.md:5](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/DATA-RETENTION.md#L5), [USER-GUIDE.md:5](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/USER-GUIDE.md#L5), [SECURITY.md:27](https://github.com/OmarVerdizada/GPORemediator/blob/ea5dcf7e85c2adac26dae33c676b81157c20b40c/SECURITY.md#L27).

**Sübut:** DATA-RETENTION Config daxilində operator roles saxlandığını yazır. Cari user guide və OperatorSecurity isə application role allowlist olmadığını deyir. SECURITY.md isə yeni pinned/paged yoxlamalar əvəzinə hələ maksimum beş endpoint sample təsvir edir.

**Təsir:** Admin və auditor saxlanan məlumat və səlahiyyət modeli barədə ziddiyyətli məlumat alır.

**Düzəliş istiqaməti:** Retention/security/user guide mətnlərini cari Windows identity + delegated AD execution modeli ilə sinxronlaşdırmaq.

**Qəbul meyarı:** Sənədlərdə mövcud olmayan role konfiqurasiyası göstərilməməlidir.

## Təkrar yaratmaq

Repo root-dan, developer SDK/Node və Playwright mövcud olduqda:

```powershell
dotnet run --project docs/audit/2026-10-31-app-review/reproducers/Review.csproj -c Release
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File docs/audit/2026-10-31-app-review/reproducers/repro.ps1
node docs/audit/2026-10-31-app-review/reproducers/repro.cjs
node docs/audit/2026-10-31-app-review/reproducers/browser.cjs
```

C# və PowerShell sınaqları app konfiqurasiyasını və ya AD siyasətini dəyişmir. C# layihəsi adi ignored bin/obj build faylları yaradır. Browser öz loopback fixture serverini açır. PowerShell yalnız öz private temp qovluğunda fayl yaradır və təmizləyir; Stop-Process mock-dur. Reproducer-lər tarixi 3.17.4 baseline üçün saxlanılıb; cari release yoxlaması `scripts/Invoke-FullAuditTests.ps1` ilə aparılır.

## C01 · Əlavə yoxlama tələb edən DN matching riski

C# helper escaped vergüllü synthetic DN input-unu icazəli OU suffix-i kimi qəbul etdi. Lakin bu, real AD inventory-dən gələn canonical DN ilə end-to-end authorization bypass kimi təsdiqlənməyib. Microsoft DN qaydalarında reserved equals işarəsinin encoding-i də göstərilir; ona görə helper sınağını canlı bypass kimi təqdim etmək düzgün olmaz. Bu hal 18 təsdiqlənmiş tapıntının sayına daxil deyil. [Microsoft DN qaydaları](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/distinguished-names).

3.17.5: escaped RDN komponentləri ilə ancestry müqayisəsi əlavə edilib; synthetic və həqiqi child DN halları regressiya ilə yoxlanılıb. Canlı AD bypass iddiası yoxdur. Sintetik input və helper nəticəsi backend-repros.json-dadır.

## Əlavə canlı yoxlama tələb edən sahələr

Bunlar təsdiqlənmiş yeni bug kimi sayılmır; bu mühitdən təsdiqlənməyən yoxlama boşluqlarıdır:

- Real multi-DC AD/SYSVOL replication, KDC/WinRM/endpoint icazələri və şəbəkə kəsilməsi.
- Həqiqi Apply zamanı proses/host restart, disk dolması və real crash recovery; auditdə məcburi stop yalnız mock edildi.
- Windows server rolları/versiyaları, uğurlu native LSA oxunuşu, restart/logoff/tamper-protection və runtime enforcement.
- Winning GPO/RSoP atribusiyası və Sechard ilə eyni host/control/zaman üzrə müqayisə.
- Böyük real OU-larda yük, bütün brauzerlər və native installer ilə real in-place upgrade.
- GitHub Actions remote run statusu: connector-un classic status cavabı boş idi; faktiki Actions nəticəsi təsdiqlənmədi. CI fayl istinadlarının qırıq olması yerli mənbədən təsdiqləndi.

A01–A18 üzrə yekun düzəlişlər və yerli test sübutları [RESOLUTION.md](RESOLUTION.md) və [3.17.5 validation](../3.17.5/validation.md) fayllarındadır.
