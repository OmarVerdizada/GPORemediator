# Sadə istifadə qaydası

1. `GpoRemediator.cmd` faylını açın. İlk build lazım olsa avtomatik edilir.
2. Sazlamalarda **Domen**, **Domen kontrolleri** və aşkarlanan Windows hesabını yoxlayın. **Saxla və yenidən başlat** seçin.
3. Əsas ekranda **Qoşul** seçin. Cari Windows hesabı istifadə edilir. Başqa hesab üçün **Başqa hesab istifadə et** bölməsini açın. `DOMEN/istifadəçi` yazılışı avtomatik `DOMEN\istifadəçi` formasına çevrilir.
   Bağlantı aktiv istifadə zamanı yenilənir və 30 dəqiqə fəaliyyətsizlikdən sonra silinir. Tətbiq yenidən başladıqda təhlükəsizlik üçün yenidən qoşulmaq lazımdır.
4. **Bağlantını yoxla** nəticələrinə baxın. Domenə giriş alınması bütün hazırlıq yoxlamalarının keçməsi demək deyil. Problem varsa, uyğun yoxlamanın yanında göstərilir.
5. **Benchmark** bölməsində qaydanın nömrəsini və ya adını axtarın. **Dəyişiklik** bölməsində GPO və hədəf seçib **Plan hazırla** düyməsini basın. Bu mərhələdə siyasət dəyişmir.
6. Tətbiq etmək üçün **Sazlamalar** bölməsində dəyişiklik icazəsini açın. Tətbiq yenidən başladıqdan sonra yenidən qoşulub plan hazırlayın. Planı yoxlayın, dəyişiklik nömrəsini və təsdiqləyən şəxsi daxil edin, `APPLY` yazıb tətbiq edin.
7. **Əməliyyatlar** bölməsində nəticəni yoxlayın. Lazım olduqda **Yenidən yoxla** və ya ehtiyat nüsxəsi olan əməliyyatda `ROLLBACK` istifadə edin.

## Mövcud versiyanı yeniləmək

Git checkout-da `git pull --ff-only` işlədin və tətbiqi `GpoRemediator.cmd` ilə yenidən başladın. Köhnə runtime aşkarlanarsa avtomatik yenilənir. Build saxlanmış konfiqurasiyanı və əməliyyat məlumatlarını silmir. Brauzerdə köhnə ekran qalsa `Ctrl+F5` basın.

## Bağlantı alınmırsa

- Domen kontrollerinin tam DNS adını yazın: məsələn, `dc01.example.local`.
- Domen hesabını istifadə edin; tətbiqin Windows hesabı icazəli hesablar siyahısında qalmalıdır.
- Bağlantı xətası Kerberos/WinRM mərhələsindədirsə, kontrollerin DNS adını, WinRM xidmətini və hesabın uzaqdan giriş icazəsini yoxlayın.
- Hazırlıq yoxlaması uğursuzdursa, həmin yoxlamanın nəticəsinə baxın. Ehtiyat nüsxə qovluğu seçilmiş DC üzərində olmalıdır.
- Uzun sorğuda mərhələ və vaxt göstərilir. Yalnız oxuma sorğusunda gözləməni dayandırmaq olar. Tətbiq zamanı əlaqə itərsə, yenidən tətbiqdən əvvəl Əməliyyatlarda nəticəni yoxlayın.

Account Policy qaydaları domenin kökünə və Default Domain Policy-yə tətbiq edilir. Real domen sınağını `PRODUCTION-TEST-CHECKLIST.md` üzrə test mühitində aparın. Domen və kompüterlərdə faktiki tətbiq ayrıca yoxlanılır; gözləyən nəticə uğurlu nəticə deyil.
