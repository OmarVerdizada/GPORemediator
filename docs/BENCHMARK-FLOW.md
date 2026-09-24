# Benchmark seçimi

1. `GpoRemediator.cmd` ilə tətbiqi başladın. Sazlamalar yalnız mühiti ilk dəfə qoşarkən lazımdır.
2. **Modullar** səhifəsini açın; ad/kod, modul və ya **Remediation hazırdır** filtri ilə parametr tapın.
3. Member Server hədəfinin DNS adını yazın və **Seç və planı aç** düyməsini basın.
4. **Planı hazırla və yoxla** seçin. Yalnız həmin parametrin GPO mənbəyi və dəyişiklik dairəsi yoxlanır; ümumi compliance scan aparılmır.
5. Planı nəzərdən keçirin, lazım olan seçimləri edin və `APPLY` təsdiqi ilə tətbiq edin. Backup, nəticənin yoxlanması və rollback əvvəlki qaydada qalır.

Siyahı operatorun göndərdiyi mətndən çıxarılmış 397 parametrdən ibarətdir; dashboard-dakı 405 sayına çatmaq üçün çatışmayan maddələr uydurulmayıb. Üç mövcud adapterə uyğun parametr aktivdir: 2.2.3, 2.3.1.3, 2.3.17.6. Digər 394 parametr üçün yoxlanmış mapping/adapter tələb olunur. `18.10.8.1` kodu mənbədə iki dəfə, fərqli adlarla verilib; hər iki maddənin tətbiqi bağlıdır.

`backend/Data/benchmark.json` build zamanı assembly-yə daxil edilir və launcher fingerprint-inə daxildir. Yeni siyahı maddəsi öz-özünə yazma icazəsi yaratmır. `POST /api/findings` sorğusunda `benchmarkSelection: true` seçimi `NOT_SCANNED` statusu yaradır; naməlum və dəstəklənməyən parametrlər rədd olunur. Heç bir real AD dəyişikliyi bu inkişaf/test işi zamanı aparılmayıb.
