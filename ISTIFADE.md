# İstifadə qaydası

1. ZIP-i yeni qovluğa çıxarın və `GpoRemediator.cmd` açın.
2. İlk açılışda Setup gəlirsə, `AD domain`, writable DC, `Backup path` və `AllowedOperators` məlumatlarını yoxlayıb saxlayın. HTTPS sertifikatı tələb olunmur; UI yalnız `127.0.0.1`-də açılır.
3. Windows rejimində əsas səhifədə icra hesabı ilə qoşulun. Hazırkı mərhələdə DC/domain admin hesabı istifadə edilə bilər; parol diskə və loga yazılmır.
4. `Environment Health / Readiness` yoxlamasını işlədin. Required check `FAIL` olarsa Apply aktivləşdirilməməlidir.
5. Benchmark bölməsində domain → subsection → control seçin.
6. Control workspace-də GPO və domain/OU scope seçin. Account Policy qaydaları server tərəfindən domain root + Default Domain Policy ilə məhdudlaşdırılır.
7. `Preview` edin. Current/desired value, existing links, inheritance/conflict warnings, affected objects və refresh target-lərini yoxlayın. Preview heç nə yazmır.
8. Settings-də `ENABLE WRITES` ilə write mode-u aktivləşdirin. Readiness yenidən yoxlanır.
9. Apply üçün Change/Ticket ID, Approver, impact acknowledgment və `APPLY` təsdiqi daxil edin. Protected GPO üçün əlavə təsdiq tələb olunur.
10. Backend əvvəlcə tam `Backup-GPO` yaradır, sonra yalnız seçilmiş mapping-i dəyişir/link edir və read-back edir. İstəsəniz bounded `gpupdate` seçə bilərsiniz.
11. `Verify` ilə AD/SYSVOL version, replication və mümkün olduqda endpoint effective value yoxlanılır. `PENDING` nəticəni `PASS` kimi qəbul etməyin.
12. Geri qaytarmaq lazım olarsa Operation Center-dən `ROLLBACK` istifadə edin. GPO başqa administrator tərəfindən sonradan dəyişibsə avtomatik rollback təhlükəsizlik üçün bloklanır.

Real production-a keçməzdən əvvəl `PRODUCTION-TEST-CHECKLIST.md` tam icra olunmalıdır.
