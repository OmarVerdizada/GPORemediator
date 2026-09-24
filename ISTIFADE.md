# İstifadə — password-policy pilot

1. `GpoRemediator.cmd` → **Başlat** → **Brauzerdə aç**.
2. **Sazlamalar** bölməsində aşkarlanan domen, DC, HTTPS ünvanı və operatoru nəzərdən keçirin. İstəsəniz əl ilə dəyişdirin. GPO GUID tələb olunmur.
3. **Saxla və yenidən başlat**. Windows rejimi üçün düzgün HTTPS sertifikatı və AD bağlantısı olmalıdır. Xəta varsa launcher localhost-da sazlama rejimi açır; real AD-yə yazmır.
4. **Hazırlığı yoxla**, sonra `ENABLE WRITES` ilə yazma rejimini aktivləşdirin. Bu yalnız test user PSO əməliyyatları üçündür.
5. **Parol siyasətləri** səhifəsində SecHard-da uğursuz olan altı password item-dən birini seçin.
6. Ayrı, privileged olmayan test istifadəçisinin adını və SecHard-da tələb olunan dəyəri yazın. Account parolunu heç yerə daxil etməyin.
7. **Seçilmiş parametr üçün plan hazırla**. Plan yalnız bu istifadəçinin effektiv siyasətini oxuyur. Başqa parametrlər skan edilmir.
8. İstifadəçi, əvvəl/sonra dəyərləri və təsir dairəsini yoxlayın. `APPLY` yazıb **Backup et və tətbiq et** düyməsini basın.
9. Tarixçədə nəticəyə baxın. `VERIFIED` seçilən DC-də istifadəçinin resultant policy-si ilə təsdiqlənir. Sonra AD replication və SecHard nəticəsini test domenində yoxlayın.
10. Bərpa üçün həmin əməliyyatın altında `ROLLBACK` yazın. Bir neçə əməliyyat varsa ən yenidən başlayın.

**Demo** rejimində bu axını real AD olmadan məşq edə bilərsiniz. Demo nəticəsi real AD-də dəyişiklik edildiyini göstərmir.

Default Domain Policy GUID-ni daxil etmək lazım deyil: PSO konkret istifadəçiyə təyin edilir. Domain-wide GPO tapıntısı üçün ayrıca gələcək mərhələ lazımdır. Mövcud parollar dəyişmir/reset edilmir.

Sazlama zamanı aşkarlama mühit metadatasını oxuyur. Avtomatik inventar/compliance scan, istifadəçi siyahısı yığılması və fonda remediation yoxdur. Mövcud sazlamalar və əl ilə düzəlişlər qorunur.

Əlavə texniki məlumat, bərpa və test addımları: [Password pilot](docs/PASSWORD-PILOT.md).
