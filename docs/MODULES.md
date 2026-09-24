# Benchmark modullarının növbəti mərhələdə əlavə edilməsi

İlkin UX yenilənməsi yeni benchmark və ya PowerShell skriptləri daxil etmir. “Modullar” ekranı mövcud backend kataloqunu siyasət növünə görə qruplaşdırır. Kartdakı “Adapter mövcuddur” yalnız hazırkı parametrlərə aiddir; bütöv benchmark dəstəyi mənasına gəlmir.

Hər yeni modul üçün istifadəçidən gələn benchmark bölməsi və skript birlikdə nəzərdən keçiriləcək:

1. Benchmark adı/versiyası, control ID, server rolu, gözlənilən dəyər və istisnalar müəyyən edilir.
2. Read-only yoxlama, dəyişiklik, backup/rollback və nəticə yoxlaması ayrılır. Mövcud skript bu mərhələlərin hamısını təmin etmirsə çatışmayan hissə tamamlanır.
3. Parametr `backend/Domain/Catalog.cs` kataloquna daxil edilir. İcra tipi üçün adapter `AdapterRegistry`-də təsdiqlənir; hazır adapter olmayan parametr avtomatlaşdırılan kimi göstərilmir.
4. PowerShell əməliyyatı `backend/PowerShell/` altında yerləşdirilir və `WindowsPowerShellExecutor` / provider daxilində typed, allowlist edilmiş əməliyyata bağlanır. Brauzerdən sərbəst skript mətni icra edilmir.
5. Mock ssenari, uyğunluq/uyğunsuzluq/oxunmayan nəticə və rollback yoxlamaları əlavə edilir. Əvvəl Demo, sonra ayrılmış staging OU/server üzərində təsdiqlənir.

Kataloqa daxil edilən parametrlər UI-də uyğun modul kartında avtomatik görünəcək. Yeni siyasət növü tələb olunarsa model, adapter, provider və `frontend/source/workspace.js`-dəki modul adı birlikdə yenilənəcək.
