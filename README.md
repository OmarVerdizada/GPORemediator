# GPO Remediator

GPO Remediator Windows Group Policy təhlükəsizlik parametrlərinin **benchmark seçimi → hədəf → plan → backup → apply → verification → rollback** axınını idarə edən ASP.NET Core 8 tətbiqidir. İlkin vəziyyət skanı tələb olunmur. Brauzerdən sərbəst PowerShell qəbul etmir; yalnız serverdə implementasiya edilmiş əməliyyatlar mövcuddur.

## Operator üçün yalnız 1 launcher

Adi istifadə zamanı ayrıca build, frontend package-manager və start script-ləri işlətməyin.

**Sadəcə `GpoRemediator.cmd` faylına iki dəfə klik edin.**

Vizual idarəetmə panelində **Başlat**, **Brauzerdə aç**, **Yenidən başlat**, **Dayandır** və **Log qovluğu** düymələri var. Konfiqurasiya olmayan ilk açılışda Demo seçilir. Paneli bağlamaq xidməti dayandırmır; bunun üçün **Dayandır** düyməsini istifadə edin.

Brauzerdə **Modullar** səhifəsində operatorun təqdim etdiyi CIS v4.0.0 mətnindən 397 parametr var. Modul, ad/kod və dəstək üzrə filtr edin, hədəfin DNS adını yazın və **Seç və planı aç** düyməsini basın. **Planı hazırla və yoxla**, sonra ayrıca **APPLY** təsdiqi ilə davam edin. Seçim `NOT_SCANNED` kimi qeyd olunur; PASS/FAIL nəticəsi uydurulmur.

Hazırda bu siyahıda 2.2.3, 2.3.1.3 və 2.3.17.6 mövcud adapterlərlə işləyir (Member Server). Qalan 394 parametr kataloq üçündür və tətbiqi bağlıdır. Mətnin `Automated` etiketi toolun adapter dəstəyi demək deyil. Mənbədə `18.10.8.1` iki fərqli parametr üçün yazılıb; hər ikisi ayrıca saxlanır və qeyd ilə göstərilir. Bu, tam/certified benchmark paketi deyil.

Aktiv remediation işi varsa dayandırma və restart API səviyyəsində bloklanır. Stop utiliti yalnız bu layihənin qeydə alınmış prosesini idarə edir; digər `.NET` proseslərini dayandırmır.

Windows başlanğıcında konfiqurasiya, sertifikat və ya prerequisite xətası olarsa launcher dayanmaq əvəzinə localhost-da **yerli sazlama rejimi** açır. Panel səbəbi göstərir, **Brauzerdə aç** sazlamalara aparır. Korlanmış konfiqurasiya faylı silinmir və bərpa ekranının açılmasına mane olmur. Bu rejim real AD-yə yazmır. RSAT quraşdırılması zamanı hər 15 saniyədə gözləmə mesajı göstərilir.

Launcher avtomatik olaraq:

1. source/runtime fingerprint-lərini yoxlayır;
2. backend rebuild lazımdırsa portable `.NET 8 SDK`-nı layihənin `.tools\dotnet` qovluğuna provision edir;
3. dependency-free static Web UI-ni `frontend\source`-dan `frontend\dist`-ə paketləyir;
4. ASP.NET backend-i Windows x64 self-contained runtime kimi publish edir;
5. konfiqurasiya varsa Windows mode, yoxdursa təhlükəsiz MOCK mode seçir;
6. Windows mode üçün `ActiveDirectory` və `GroupPolicy` RSAT komponentlərini yoxlayır və lazım olsa yalnız prerequisite mərhələsi üçün UAC istəyir;
7. backend-i başladır; paneldə **Brauzerdə aç** düyməsi Web UI-yə keçir;
8. UI-dan gələn validated setup/write-mode restart marker-lərini idarə edir.

**Node.js, npm, pnpm, Corepack və `registry.npmjs.org` production bootstrap üçün tələb olunmur.**

## Built-in Automation Center

Base operator UI-yə əlavə olaraq hər səhifədə **Automation Center** mövcuddur:

- **Readiness** – runtime/provider, RSAT, domain/DC, identity və backup hazırlığını yoxlayır.
- **Setup** – HTTPS URL, domain, writable DC, approved GPO GUID-lər, authorized OU-lar, allowed hosts/operators və backup path-i UI-dan saxlayır.
- **Benchmark seçimi** – scan etmədən seçilmiş parametr və hədəf üzrə remediation qeydi yaradır. Köhnə scan API-si uyğunluq üçün saxlanılıb, əsas UI axınında çağırılmır.
- **Safe plan** – source analysis → safe GPO selection → impact preview → preflight → zero-write dry run əməliyyatlarını bir düymə ilə hazırlayır.
- **Explicit Apply** – safe-plan nəticəsindən ayrıca `APPLY` typed confirmation, gpupdate/restart seçimləri və broad-impact acknowledgement ilə job yarada bilir; execution record base UI-də izlənir.
- **Controlled write mode** – yalnız Windows mode + readiness PASS + exact typed confirmation ilə açılır.

Apply ayrıca operator authorization tələb edir. Automation Center heç vaxt səssiz policy write başlamır.

## Təhlükəsizlik sərhədləri

- Default Domain Policy və Default Domain Controllers Policy GUID-ləri bloklanır.
- Host, OU, operator və remediation GPO-ları exact allowlist olmalıdır.
- Real mode HTTPS + Windows Integrated Authentication istifadə edir.
- Browser credential/password qəbul etmir.
- RSoP qeyri-müəyyəndirsə source `AMBIGUOUS`/`NOT_DEFINED` qalır; başqa GPO səssiz seçilmir.
- Target scan endpoint dəyərini oxuya bilmirsə `PASS` vermir.
- Apply-dən əvvəl stale-preview/fingerprint, permission, scope və backup yoxlamaları yenidən edilir.
- PASS yalnız layered verification-dan sonra verilir.
- Rollback explicit acknowledgement və post-write conflict/version yoxlaması tələb edir.

## Layihə strukturu

| Yol | Funksiya |
| --- | --- |
| `GpoRemediator.cmd` | Operator üçün əsas və yeganə normal giriş nöqtəsi |
| `Control-Panel.ps1` | Status, rejim seçimi, başlat/dayandır/restart və loglara vizual giriş |
| `scripts/ServiceControl.ps1` | Layihəyə aid proses yoxlaması və qorunan lifecycle API çağırışları |
| `GpoRemediator.ps1` | Bootstrap, .NET provision, build, RSAT, mode/restart orchestration |
| `backend/` | ASP.NET Core API, domain model, mock/Windows provider-lər |
| `frontend/source/` | Canonical static Web UI + Automation Center; package registry tələb etmir |
| `frontend/dist/` | Build zamanı `source/`-dan yaranan runtime UI |
| `runtime/` | Windows x64 self-contained backend output |
| `scripts/` | Build fingerprint/helper funksiyaları |
| `tests/` | .NET invariant tests və PowerShell HTTP smoke tests |
| `docs/` | Arxitektura və Windows provider detalları |

Detallı istifadə üçün [ISTIFADE.md](ISTIFADE.md), Windows provider üçün [docs/WINDOWS-PROVIDER.md](docs/WINDOWS-PROVIDER.md) faylına baxın.
