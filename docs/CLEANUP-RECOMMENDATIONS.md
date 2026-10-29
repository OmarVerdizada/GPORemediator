# Sadələşdirmə üçün konkret namizədlər

Bu siyahı kod istinadlarına əsaslanır. İstifadə telemetriyası yoxdur; istifadə edilmədiyi ölçülməyən funksiyalar “ölü kod” sayılmır. İşlək funksional bölmələr bu dəyişiklikdə silinməyib.

| Hissə | Kodda müşahidə | Təklif və qorunmalı davranış |
| --- | --- | --- |
| Təkrarlanan remediation context paneli | `studio-ui.js` içindəki `remediation()` artıq heç bir məhsul ekranından çağırılmırdı. Control ekranında vahid stepper var. | **Bu versiyada silindi:** istifadə olunmayan renderer, export və ona aid `studio-design.css` qaydaları. |
| Reports ayrıca menyusu | `enterprise-center.js` içindəki `reports()` Operations ilə eyni `state.history` qeydlərini oxuyur; ayrıca domain skanı deyil. | Filtrləmə və JSON/CSV/HTML ixracını Operations daxilində Reports tabına yığmaq, sonra ayrıca menyu/route-u silmək olar. İxrac formatları saxlanmalıdır. |
| Diagnostics ayrıca menyusu | `enterprise-center.js` içindəki `diagnostics()` və Dashboard readiness eyni `/api/gpo/readiness` nəticəsinə əsaslanır. | Vahid Diagnostics ekranını Settings altında saxlamaq, Dashboard-da yalnız qısa status və keçid göstərmək olar. DNS/WinRM/SYSVOL izahatları və servis loglarına çıxış saxlanmalıdır. |
| Access & evidence ayrıca səhifəsi | `assurance.js` real access-report və endpoint explanation API-lərini çağırır. Target selection və Verification ilə kontekst təkrarlanır. | Access report-u target seçiminə, endpoint explanation-u Verification daxilinə köçürüb ayrıca menyunu azaltmaq olar. Permission yoxlamaları, winning-GPO/RSoP izahı və read-only API-lər silinməməlidir. |
| Operations Table / Cards | `operation-view.js` eyni qeydlər üçün iki layout saxlayır; `workspace.js` ayrıca `opsLayout` seçimini idarə edir. | Yalnız table + mövcud operation inspector saxlamaq daha az UI/CSS tələb edir. Cards istifadə olunmursa renderer, switch və storage preference birlikdə çıxarıla bilər. |
| CSS qatları | `index.html` səkkiz stylesheet yükləyir; `app.css` özü `styles/` daxilindəki doqquz komponentdən generasiya edilir. | Aktiv qaydaları bir dizayn qatında toplamaq, köhnə override-ları sonra çıxarmaq olar. `styles/` build mənbəyidir, `frontend/dist` paket mənbəyidir; bunları sadəcə dublikat görünür deyə silmək olmaz. |
| Köhnə audit çıxışları | `docs/audit/` əvvəlki versiyaların test sübutlarını saxlayır; tətbiq bunları runtime-da istifadə etmir. | Köhnə nəticələri ayrıca arxiv/release asset-ə köçürmək olar. Cari versiyanın sübutları və release tarixçəsi saxlanmalıdır. |

Password policies (FGPP), Workflow center, Audit və rollback snapshotları ayrıca real davranış saxlayır. FGPP domain/OU GPO-sunun əvəzi deyil; Workflow center serverdə batch/scan/recovery işlərini idarə edir. Onları istifadəsiz hesab edib avtomatik silmək üçün əsas yoxdur.

İlk sadələşdirmə üçün ən az funksional itki yaradan sıra: **Reports → Operations**, **Diagnostics → Settings**, **Operations Cards layout**. Sonra Access report və endpoint explanation-u müvafiq control ekranına köçürmək olar.
