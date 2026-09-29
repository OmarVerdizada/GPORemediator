/* Shared transport. Never retry mutations automatically: their outcome can be uncertain. */
(() => {
  'use strict';
  const active = new Set();
  const storage = {
    get(key, fallback) { try { return sessionStorage.getItem(key) ?? fallback; } catch { return fallback; } },
    set(key, value) { try { sessionStorage.setItem(key, value); } catch { /* Storage may be disabled. */ } },
    favorites() { try { const value = JSON.parse(this.get('gr-favorites', '[]')); return Array.isArray(value) ? value.filter(x => typeof x === 'string') : []; } catch { return []; } }
  };
  const words = {
    'Main navigation':'Əsas menyu','Security operations':'Təhlükəsizlik idarəetməsi',
    'Loading application data':'Məlumatlar yüklənir','Processing request':'Sorğu icra olunur','Please keep this window open.':'Pəncərəni açıq saxlayın.','Cancel request':'Gözləməni dayandır',
    'Overview':'Ümumi məlumat','Remediation':'Dəyişiklik','Impact':'Təsir','Verification':'Yoxlama','Audit':'Tarixçə',
    'Target & policy':'Siyasət və hədəf','Generate plan':'Planı göstər','Change approval':'Dəyişikliyin təsdiqi',
    'CIS BENCHMARK LIBRARY':'CIS QAYDALARI','Navigate by domain, use saved views, and favorite recurring controls without flattening the benchmark hierarchy.':'Qaydanın nömrəsi və ya adı ilə axtarın, sonra bölməni açın.',
    'All controls':'Bütün qaydalar','★ Favorites':'★ Seçilmişlər','Remediation ready':'Avtomatlaşdırılan','High impact':'Yüksək təsir',
    'High':'Yüksək','Medium':'Orta','Low':'Aşağı','Manual / read-only control':'Əl ilə yoxlanılan qayda','Mapping unavailable':'Hazırda əlçatan deyil',
    'CONTROL INTENT':'QAYDANIN MƏQSƏDİ','What this control changes':'Qayda nəyi dəyişir','RECOMMENDED STATE':'TÖVSİYƏ EDİLƏN DƏYƏR',
    'This value comes from the imported CIS Benchmark v4.0.0 recipe.':'Dəyər CIS Benchmark v4.0.0 sənədindən götürülüb.',
    'OPERATIONAL RISK':'DƏYİŞİKLİYİN TƏSİRİ','IMPLEMENTATION':'İCRA ÜSULU','Automated remediation ready':'Avtomatik tətbiq mümkündür',
    'This control has a server-authoritative production mapping and can generate a real GPO preview.':'Bu qayda üçün GPO seçib dəyişiklik planını hazırlaya bilərsiniz.',
    'The imported CIS catalog does not classify this control as safely automated. The product keeps it visible but blocks automatic writes.':'Bu qayda əl ilə yoxlanılmalıdır. Avtomatik tətbiq mümkün deyil.',
    'No server-authoritative mapping is available for this control.':'Qaydanın tətbiqi hazırda əlçatan deyil. Domen bağlantısını yoxlayın.',
    'CLASSIFICATION':'TƏSNİFAT','Level':'Səviyyə','Type':'Növ','Section':'Bölmə','CONTEXTUAL GUIDANCE':'İSTİFADƏ QAYDASI',
    'When to use':'Nə vaxt tətbiq etməli','Before change':'Dəyişiklikdən əvvəl','After change':'Dəyişiklikdən sonra',
    'Apply when this control belongs to the intended server/workstation baseline and the selected GPO scope is correct.':'Qaydanın seçdiyiniz serverlərə və GPO hədəfinə uyğun olduğunu yoxlayın.',
    'Review application dependencies, policy precedence and affected objects. Generate a read-only plan first.':'Əvvəlcə planı hazırlayın və təsir edəcək obyektləri yoxlayın.',
    'Verify GPO publication, link state, gpupdate and effective policy. Pending probes must remain pending.':'Tətbiqdən sonra siyasətin və hədəf kompüterlərdəki nəticənin yoxlanmasını izləyin.',
    'May affect authentication, access, remote administration, or production connectivity.':'Girişə, autentifikasiyaya və uzaqdan idarəetməyə təsir edə bilər.',
    'Validate scope and application dependencies before broad rollout.':'Tətbiqdən əvvəl hədəfi və proqram asılılıqlarını yoxlayın.',
    'Lower expected operational impact, but preview and verification are still required.':'Gözlənilən təsir azdır. Yenə də planı və nəticəni yoxlayın.',
    'Control':'Qayda','Target':'Hədəf','Preview':'Plan','Approval':'Təsdiq','Apply':'Tətbiq','Verify':'Yoxla',
    'Connect to Active Directory to select a real GPO and target scope.':'GPO və hədəf seçmək üçün domenə qoşulun.',
    'Selected GPO':'Seçilmiş GPO','Choose a Group Policy Object':'GPO seçin','Search GPO by name…':'GPO adı ilə axtarın…','No matching GPO':'Uyğun GPO tapılmadı',
    'Selectable':'Seçmək olar','Unavailable for this workflow':'Bu əməliyyat üçün əlçatan deyil','Protected':'Qorunan',
    'Policy target':'Siyasətin növü','Link target':'Tətbiq ediləcək hədəf','Desired value':'Yeni dəyər','Desired benchmark state':'Tövsiyə edilən vəziyyət',
    'Policy refresh':'Kompüterlərdə yenilənmə','Do not force update':'Növbəti avtomatik yenilənməni gözlə','PDC emulator only':'Yalnız əsas domen kontrolleri','Selected scope computers':'Seçilmiş hədəfdəki kompüterlər',
    'Highest link priority':'Ən yüksək tətbiq prioriteti','Move the selected link to first position. Existing Enforced and filtering settings are not changed.':'Seçilmiş GPO əlaqəsini ilk yerə keçir. Digər məcburilik və filtr sazlamaları saxlanılır.',
    'DRY RUN / WHAT-IF':'DƏYİŞİKLİK PLANI','No read-only plan generated yet.':'Plan hələ hazırlanmayıb.','Select a GPO and target, then generate a plan. The preview performs no domain write.':'GPO və hədəfi seçin, sonra planı hazırlayın. Bu mərhələdə siyasət dəyişmir.',
    'Before/after diff':'Əvvəlki və yeni dəyər','Link intent':'Tətbiq hədəfi','Warning aggregation':'Xəbərdarlıqlar','Rollback context':'Geri qaytarma',
    'DRY RUN · READ-ONLY PREVIEW':'YALNIZ BAXIŞ','Change plan ready':'Dəyişiklik planı hazırdır','NO WRITE YET':'HƏLƏ TƏTBİQ EDİLMƏYİB',
    'BEFORE / AFTER DIFF':'DƏYƏRİN DƏYİŞMƏSİ','CURRENT':'ƏVVƏLKİ','DESIRED':'YENİ','Not configured':'Təyin edilməyib',
    'Link':'Əlaqə','Execution':'İcra hesabı','Rollback':'Geri qaytarma','Backup before write':'Dəyişiklikdən əvvəl ehtiyat nüsxə','Not requested':'Seçilməyib',
    'GOVERNANCE':'TƏSDİQ','Change / Ticket ID':'Dəyişiklik nömrəsi','Reviewed / Approved by':'Təsdiqləyən şəxs','Name or operator':'Ad və ya istifadəçi hesabı',
    'Impact reviewed and approved':'Planı və təsiri yoxlayıb təsdiqlədim','I reviewed the target, GPO, scope and potential precedence impact.':'Seçilmiş GPO-nu, hədəfi və prioritetin təsirini yoxladım.',
    'Confirm production impact':'Dəyişikliyin təsirini təsdiqləyin','Backup will be created before the GPO write.':'GPO dəyişməzdən əvvəl ehtiyat nüsxə yaradılacaq.',
    'Protected GPO confirmation':'Qorunan GPO təsdiqi','I explicitly approve changing this protected/default policy.':'Qorunan və ya standart siyasətin dəyişdirilməsini təsdiqləyirəm.',
    'Type APPLY to continue':'Davam etmək üçün APPLY yazın','Backup → Apply → Link → Verify':'Ehtiyat nüsxə → Tətbiq → Yoxlama',
    'IMPACT ANALYSIS':'TƏSİRİN TƏHLİLİ','SELECTED GPO':'SEÇİLMİŞ GPO','TARGET SCOPE':'HƏDƏF','Not selected':'Seçilməyib','Yes':'Bəli','No':'Xeyr',
    'Choose a domain/OU target in Remediation.':'Dəyişiklik bölməsində domen və ya OU seçin.','POLICY CONFLICT GRAPH':'SİYASƏTLƏRİN TƏTBİQ ARDICILLIĞI',
    'Inheritance & precedence path':'İrsilik və prioritet','LIVE ANALYSIS':'YOXLANILIB','PREVIEW REQUIRED':'PLAN TƏLƏB OLUNUR','Domain root':'Domen','Target scope':'Hədəf',
    'Effective policy':'Faktiki siyasət','Verification after Apply':'Tətbiqdən sonra yoxlama','Preview required':'Plan tələb olunur','Not connected':'Qoşulmayıb',
    'No conflicting definition was detected in the analyzed inheritance path.':'Yoxlanılan siyasət ardıcıllığında ziddiyyət tapılmadı.',
    'Generate a read-only plan to run live inheritance, precedence, security filtering and WMI analysis.':'İrsilik, prioritet və filtrləri yoxlamaq üçün plan hazırlayın.',
    'AFFECTED OBJECTS EXPLORER':'TƏSİR EDİLƏN OBYEKTLƏR','Scope inventory':'Hədəfdəki obyektlər','LIVE INVENTORY':'YOXLANILIB','Computers':'Kompüterlər','Servers':'Serverlər','Workstations':'İş stansiyaları','Disabled':'Deaktiv',
    'Generate a plan to load the directory scope inventory.':'Hədəfdəki obyektləri görmək üçün plan hazırlayın.',
    'POST-CHANGE ASSURANCE':'TƏTBİQDƏN SONRA YOXLAMA','Verification pipeline':'Yoxlama nəticələri','Each stage must be independently confirmed. Pending probes are never displayed as passed.':'Hər mərhələnin nəticəsi ayrıca göstərilir. Gözləyən yoxlama uğurlu sayılmır.',
    'No verification run for this control yet':'Bu qayda hələ yoxlanılmayıb','After Apply, this workspace will show GPO write, link, gpupdate, replication and effective-policy status.':'Tətbiqdən sonra siyasətin, əlaqənin və kompüterlərdəki nəticənin vəziyyəti burada görünəcək.',
    'GPO write':'GPO dəyişikliyi','Link verification':'Hədəflə əlaqə','AD / SYSVOL replication':'Kontrollerlər arasında yayılma','Verified':'Yoxlanılıb','Not confirmed':'Təsdiqlənməyib','Pending':'Gözlənilir','Not checked':'Yoxlanılmayıb',
    'EVIDENCE PACK':'HESABAT','Change evidence & audit bundle':'Dəyişiklik və yoxlama hesabatı','Prepare JSON evidence':'Hesabatı endir','Before value':'Əvvəlki dəyər','After value':'Yeni dəyər','GPO & target':'GPO və hədəf','Operator':'İstifadəçi','Backup ID':'Ehtiyat nüsxə',
    'Evidence can be generated from the recorded operation currently loaded in the browser.':'Hesabat serverdə saxlanılan əməliyyat qeydindən hazırlanır.',
    'Apply and record an operation before generating evidence.':'Hesabat üçün əvvəlcə əməliyyat icra edilməlidir.','CONTROL AUDIT TRAIL':'QAYDANIN TARİXÇƏSİ',
    'Operator, target, backup and recovery context for this control.':'İcra hesabı, hədəf, ehtiyat nüsxə və geri qaytarma məlumatları.',
    'Operation':'Əməliyyat','State':'Vəziyyət','Backup':'Ehtiyat nüsxə','Action':'Əməliyyat','Re-verify':'Yenidən yoxla','No operation has been recorded for this control.':'Bu qayda üzrə əməliyyat yoxdur.',
    'CHANGE & RECOVERY CENTER':'ƏMƏLİYYATLAR','Review completed changes, verification state, backups and rollback availability.':'Dəyişiklikləri, yoxlama nəticələrini və geri qaytarma imkanlarını izləyin.',
    'All':'Hamısı','Successful':'Tətbiq edilib','Review':'Diqqət tələb edir','Rolled back':'Geri qaytarılıb','Replication':'Yayılma','Effective':'Faktiki nəticə',
    'Kerberos / WinRM session':'Domenə giriş','DNS resolution':'Domen adının tapılması','Active Directory / LDAP':'Domen məlumatları','Backup repository':'Ehtiyat nüsxə qovluğu','AD replication':'Domen sinxronizasiyası',
    'PUBLISHED':'GPO-ya tətbiq edilib','PUBLISHED_REFRESH_FAILED':'GPO dəyişib, kompüter yenilənməsi alınmayıb','NO_CHANGE':'Dəyişiklik tələb olunmur','VERIFY_MISMATCH':'Yoxlama nəticəsi uyğun deyil','REVIEW_REQUIRED':'Əl ilə yoxlama tələb olunur','FAILED_SAFE':'Tətbiq edilmədi','ROLLED_BACK':'Geri qaytarılıb','ROLLBACK_REVIEW_REQUIRED':'Geri qaytarma yoxlanılmalıdır','ROLLBACK_DRIFT_DETECTED':'Rollback-dan sonra dəyişiklik aşkarlanıb','REPLICATION_PENDING':'Kontrollerlər arasında yayılma gözlənilir','ENDPOINT_VERIFICATION_PENDING':'Kompüterdə yoxlama gözlənilir','VERIFIED_ON_SAMPLE':'Yoxlanılan kompüterlərdə təsdiqlənib',
    'DOMAIN_VALUE_MATCHES_ON_SELECTED_DC':'Seçilmiş kontrollerdə dəyər uyğundur','DOMAIN_VALUE_PENDING_OR_OVERRIDDEN':'Domen dəyəri hələ uyğun deyil','ROLLBACK_ENDPOINT_PENDING':'Geri qaytarılıb, kompüter yenilənməsi gözlənilir',
    '☆ Save':'☆ Seçilmişlərə əlavə et','★ Saved':'★ Seçilmişlərdədir','Light':'Açıq','Dark':'Tünd','Retry':'Yenidən cəhd et','Settings':'Sazlamalar','Loading benchmark catalog…':'Qaydalar yüklənir…',
    'Authenticated remote session':'Domen hesabı ilə giriş alınıb','Backup directory is writable':'Ehtiyat nüsxə qovluğuna yazmaq mümkündür'
  };
  function localize(root) {
    if (storage.get('gr-lang','az') !== 'az' || !root) return;
    const walker=document.createTreeWalker(root,NodeFilter.SHOW_TEXT);
    while(walker.nextNode()) {const node=walker.currentNode,key=node.nodeValue.trim();if(words[key])node.nodeValue=node.nodeValue.replace(key,words[key]);}
    for(const input of root.querySelectorAll('[placeholder]'))if(words[input.placeholder])input.placeholder=words[input.placeholder];
  }
  const errors = {
    INVALID_OPERATOR_ALLOWLIST:'Hesabı DOMEN\\istifadəçi formasında yazın və ya aşkarlanan Windows hesabını seçin.',
    OPERATOR_SELF_LOCKOUT:'Hazırda istifadə etdiyiniz Windows hesabı icazəli hesablar siyahısında qalmalıdır.',
    GPO_LOGIN_REQUIRED:'Domen bağlantısı bitib və ya tətbiq yenidən başlayıb. Əsas ekranda yenidən qoşulun.',
    GPO_AUTH_FAILED:'Hesab və ya şifrə qəbul edilmədi. Domen hesabını yoxlayın və ya cari Windows hesabı ilə qoşulun.',
    GPO_REMOTING_FAILED:'Domen kontrollerinə bağlantı alınmadı. Kontrollerin adını, WinRM xidmətini və hesabın uzaqdan giriş icazəsini yoxlayın.',
    GPO_READINESS_FAILED:'Domenə giriş alınıb, amma hazırlıq yoxlaması tamamlanmadı. Tətbiqi yeniləyin və bağlantını yenidən yoxlayın.',
    GPO_DISCOVERY_FAILED:'GPO siyahısı alınmadı. Kontrollerdə GroupPolicy və ActiveDirectory modullarını, hesabın oxuma icazəsini yoxlayın.',
    GPO_PREVIEW_FAILED:'Plan hazırlana bilmədi. GPO və hədəfi yenidən seçin, SYSVOL oxuma icazəsini yoxlayın.',
    WRITES_DISABLED:'Dəyişiklik icazəsi bağlıdır. Sazlamalarda aktivləşdirin, sonra yenidən qoşulun.',
    ENVIRONMENT_NOT_READY:'Əvvəlcə bağlantı yoxlamasında göstərilən problemləri aradan qaldırın.',
    WINDOWS_MODE_REQUIRED:'Əvvəlcə domen sazlamalarını saxlayıb tətbiqi yenidən başladın.',
    CSRF_INVALID:'Sessiya yenilənməlidir. Səhifəni yeniləyib təkrar cəhd edin.',
    INVALID_DOMAIN:'Domeni və həmin domenə aid kontrollerin tam adını daxil edin: məsələn, example.local və dc01.example.local.'
  };
  function policy(path) {
    if (/\/gpo\/[^/]+\/apply$/.test(path)) return { timeout: 1740000, label: 'Backup, policy change, optional gpupdate and verification', cancelable: false };
    if (/\/gpo\/[^/]+\/rollback$/.test(path)) return { timeout: 980000, label: 'Backup, policy change and verification', cancelable: false };
    if (/\/gpo\/[^/]+\/refresh$/.test(path)) return { timeout: 760000, label: 'Scheduling gpupdate and re-verifying policy', cancelable: false };
    if (/\/gpo\/(preview|[^/]+\/(verify|replan))$/.test(path)) return { timeout: 620000, label: 'Reading policy and verifying scope', cancelable: true };
    if (/\/gpo\/(connect|discover|readiness)$/.test(path)) return { timeout: 110000, label: path.endsWith('/readiness') ? 'Checking AD readiness' : 'Connecting to AD and loading GPOs', cancelable: true };
    if (/\/setup\/write-mode$/.test(path)) return { timeout: 120000, label: 'Checking readiness and updating write mode', cancelable: false };
    return { timeout: 20000, label: 'Loading application data', cancelable: true };
  }
  async function request(path, { body, csrfToken, ...options } = {}) {
    const settings = { ...policy(path), ...options };
    if (body !== undefined && !/^\/api\/gpo\/(connect|discover|preview|[^/]+\/(verify|replan))$/.test(path)) settings.cancelable = false;
    const controller = new AbortController();
    const pending = { controller, path, ...settings, started: Date.now() };
    active.add(pending);
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; controller.abort(); }, settings.timeout);
    try {
      const response = await fetch(path, {
        method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store', signal: controller.signal,
        headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken || '' }) },
        body: body === undefined ? undefined : JSON.stringify(body)
      });
      const text = await response.text();
      let data;
      try { data = JSON.parse(text); } catch {
        throw new Error(response.status === 401 ? 'Windows authentication is required. Reopen the app with an allowed Windows account.' : `The server returned an invalid response (HTTP ${response.status}). Check the service and reload.`);
      }
      if (!response.ok) {
        const error = new Error((storage.get('gr-lang','az')==='az'&&errors[data.code]) || data.message || `Request failed (HTTP ${response.status}).`);
        error.code = data.code; error.status = response.status; throw error;
      }
      return data;
    } catch (error) {
      if (controller.signal.aborted) throw new Error(timedOut
        ? `Request timed out after ${Math.round(settings.timeout / 1000)} seconds. ${settings.cancelable ? 'Check the service, DC and Kerberos/WinRM connection, then retry.' : 'The operation may still be running. Review Operations before submitting it again.'}`
        : 'Request canceled. No further step was submitted.');
      if (error instanceof TypeError) throw new Error('The service connection was lost. Check that GPO Remediator is running. Review Operations before retrying a change.');
      throw error;
    } finally { clearTimeout(timer); active.delete(pending); }
  }
  window.GpoClient = {
    request, storage, localize,
    progress() { return [...active].at(-1); },
    cancelReadOnly() { for (const p of active) if (p.cancelable) p.controller.abort(); }
  };
})();
