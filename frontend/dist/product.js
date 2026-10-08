/* Product surfaces use existing server-authoritative state; no policy writes here. */
(() => {
  'use strict';
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const text = (s, az, en) => s.lang === 'az' ? az : en;
  const date = (value, lang) => {
    const d = new Date(value);
    if(!Number.isFinite(d.getTime()))return '—';
    return lang==='az'
      ? d.toLocaleString('en-GB',{day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit',hour12:false}).replaceAll('/','.')
      : d.toLocaleString('en-GB',{dateStyle:'medium',timeStyle:'short'});
  };
  const active = run => /^(APPLYING|VERIFYING|REFRESHING|ROLLBACKING|ROLLING_BACK)$/.test(String(run?.result?.state || '').toUpperCase());
  function recentControls() {
    try { const ids = JSON.parse(window.GpoClient.storage.get('gr-recent-controls','[]')); return Array.isArray(ids) ? ids.filter(x => typeof x === 'string').slice(0,5) : []; }
    catch { return []; }
  }
  function remember(id) { window.GpoClient.storage.set('gr-recent-controls', JSON.stringify([id,...recentControls().filter(x=>x!==id)].slice(0,5))); }
  function sortedRuns(runs, order='newest') {
    return [...runs].sort((a,b) => {
      const aTime = Date.parse(a.updatedAt) || 0, bTime = Date.parse(b.updatedAt) || 0;
      if (order === 'attention') { const delta = Number(window.GpoUiDomain.classify(b).attention)-Number(window.GpoUiDomain.classify(a).attention); if(delta) return delta; }
      return order === 'oldest' ? aTime-bTime : bTime-aTime;
    });
  }
  function dashboard(s) {
    const steps = [
      {done:s.session?.mode==='WINDOWS',title:text(s,'Windows / AD-ni başlat','Start Windows / AD'),copy:text(s,'Domen və kontroller konfiqurasiyası','Domain and controller configuration'),action:'settings'},
      {done:!!s.gpoSession?.connected,title:text(s,'Domenə qoşul','Connect to your domain'),copy:text(s,'Əməliyyatları icra edəcək AD hesabı','AD identity used for execution'),action:'connect'},
      {done:!!s.readiness?.ready,title:text(s,'Bağlantını yoxla','Check readiness'),copy:text(s,'Kerberos, WinRM, SYSVOL və icazələr','Kerberos, WinRM, SYSVOL and permissions'),action:'readiness'},
      {done:!!s.plan,title:text(s,'İlk planını hazırla','Prepare your next plan'),copy:text(s,'Qayda → GPO → hədəf → preview','Control → GPO → scope → preview'),action:'benchmark'}
    ];
    const next = steps.findIndex(x=>!x.done);
    const attention = sortedRuns(s.history.filter(h=>window.GpoUiDomain.classify(h).attention)).slice(0,3);
    const recent = recentControls().map(id=>s.catalog?.rules.find(r=>r.id===id)).filter(Boolean);
    return `<section class="product-desk"><article class="product-checklist"><div class="product-section-head"><div><span class="product-eyebrow">${text(s,'İŞ MASASI','YOUR WORKSPACE')}</span><h2>${text(s,'Növbəti addım aydındır','A clear next step')}</h2></div><span class="product-counter">${steps.filter(x=>x.done).length} / 4</span></div><div class="product-step-list">${steps.map((x,i)=>`<button data-product-action="${x.action}" class="product-step ${x.done?'complete':i===next?'next':''}"><span class="product-step-number">${x.done?'✓':String(i+1).padStart(2,'0')}</span><span><strong>${x.title}</strong><small>${x.copy}</small></span><b>↗</b></button>`).join('')}</div></article><article class="product-focus"><div class="product-section-head"><div><span class="product-eyebrow">${text(s,'DİQQƏT MƏRKƏZİ','FOCUS CENTER')}</span><h2>${attention.length?text(s,'Yoxlama tələb edən nəticələr','Results needing review'):text(s,'İşə qaldığın yerdən davam et','Pick up where you left off')}</h2></div><span class="product-status ${attention.length?'warning':'good'}">${attention.length?text(s,'Yoxla','Review'):text(s,'Hazır','Ready')}</span></div>${attention.length?attention.map(h=>`<button class="product-recent" data-inspect="${esc(h.id)}"><span class="product-rule-id">${esc(h.plan?.selection?.setting||'GPO')}</span><span><strong>${esc(h.plan?.preview?.gpo?.name||h.id)}</strong><small>${esc(h.result?.message||h.result?.state)}</small></span><b>↗</b></button>`).join(''):recent.length?recent.map(r=>`<button class="product-recent" data-rule="${esc(r.id)}"><span class="product-rule-id">${esc(r.id)}</span><span><strong>${esc(r.title)}</strong><small>${esc(r.level)} · CIS v4.0.0</small></span><b>→</b></button>`).join(''):`<div class="product-welcome"><span>↗</span><h3>${text(s,'Bir qayda ilə başla','Start with one control')}</h3><p>${text(s,'Son baxdığın qaydalar burada saxlanacaq. Əvvəlcə məhdud hədəf üçün read-only plan hazırla.','Recently viewed controls appear here. Start with a read-only plan for a limited scope.')}</p><a href="#/benchmark">${text(s,'Kitabxananı aç','Explore the library')} →</a></div>`}</article></section>`;
  }
  function catalogTools(s, count) {
    const filtered = !!s.query || s.level!=='ALL' || s.automation!=='ALL' || s.savedView!=='ALL';
    return `<div class="product-catalog-tools"><span><strong>${count}</strong> ${text(s,'uyğun qayda','matching controls')} ${filtered?`<button data-product-action="clear-filters">${text(s,'Filtrləri təmizlə','Clear filters')} ×</button>`:''}</span><div><div class="product-view-switch" role="group" aria-label="${text(s,'Kataloq görünüşü','Catalog view')}"><button data-catalog-layout="tree" aria-pressed="${s.catalogLayout!=='list'}">${text(s,'Bölmələr','Hierarchy')}</button><button data-catalog-layout="list" aria-pressed="${s.catalogLayout==='list'}">${text(s,'Siyahı','List')}</button></div><button data-product-action="export-catalog">↓ ${text(s,'CSV ixrac','Export CSV')}</button></div></div>`;
  }
  function inspector(s) {
    const h=s.history.find(x=>x.id===s.inspectedOperation); if(!h)return '';
    const p=h.plan||{},r=h.result||{},quality=window.GpoUiDomain.classify(h);
    const checks=[
      [text(s,'GPO publication','GPO publication'),r.gpoPublished===true,text(s,'Dəyər GPO-da yazılıb','Value recorded in the GPO')],
      [text(s,'Hədəf əlaqəsi','Target link'),r.linkVerified===true,text(s,'Seçilmiş hədəfə link təsdiqlənib','Link to the selected scope verified')],
      [text(s,'AD / SYSVOL replikasiyası','AD / SYSVOL replication'),quality.replication==='converged',text(s,'Kontrollerlərin versiyaları uyğunlaşıb','Controller versions have converged')],
      [text(s,'Faktiki siyasət','Effective policy'),quality.effective==='verified',text(s,'Canlı yoxlamanın nəticəsi','Result of live verification')]
    ];
    return `<div class="product-drawer-backdrop" data-product-close></div><aside class="product-drawer" role="dialog" aria-modal="true" aria-labelledby="operation-detail-title" tabindex="-1"><header><div><span class="product-eyebrow">${text(s,'ƏMƏLİYYAT DETALLARI','OPERATION DETAILS')}</span><h2 id="operation-detail-title">${esc(p.selection?.setting||'GPO')} · ${esc(p.preview?.gpo?.name||'GPO')}</h2><p>${date(h.updatedAt,s.lang)}</p></div><button data-product-close aria-label="${text(s,'Bağla','Close')}">×</button></header><div class="product-drawer-body"><div class="product-result ${quality.attention?'warning':'neutral'}"><strong>${esc(r.state||'—')}</strong><p>${esc(r.message||text(s,'Nəticə gözlənilir','Awaiting result'))}</p></div><h3>${text(s,'Yoxlama qatları','Verification layers')}</h3><div class="product-verification">${checks.map(([title,ok,copy])=>`<div><span class="product-check ${ok?'good':'pending'}">${ok?'✓':'○'}</span><span><strong>${title}</strong><small>${ok?copy:text(s,'Hələ təsdiqlənməyib','Not confirmed yet')}</small></span></div>`).join('')}</div><div class="product-value-grid"><div><small>${text(s,'ƏVVƏL','BEFORE')}</small><strong>${esc(p.preview?.previousValue??text(s,'Təyin edilməyib','Not configured'))}</strong></div><div><small>${text(s,'GÖZLƏNİLƏN','EXPECTED')}</small><strong>${esc(p.preview?.desiredValue??'—')}</strong></div><div><small>${text(s,'CARİ','CURRENT')}</small><strong>${esc(r.currentValue??'—')}</strong></div></div><h3>${text(s,'Dəyişiklik konteksti','Change context')}</h3><dl class="product-facts">${[
      [text(s,'Domen','Domain'),p.domain],[text(s,'Kontroller','Controller'),p.domainController],[text(s,'Hədəf','Scope'),p.selection?.scopeDn],[text(s,'İcra hesabı','Execution identity'),p.executionUser],[text(s,'Dəyişiklik sorğusu','Change reference'),h.approval?.changeReference],[text(s,'Backup','Backup'),r.backupId],[text(s,'Əməliyyat ID-si','Operation ID'),h.id],[text(s,'Correlation ID','Correlation ID'),h.correlationId]
    ].map(([label,value])=>`<div><dt>${label}</dt><dd>${esc(value||'—')}</dd></div>`).join('')}</dl>${(r.endpointChecks||[]).length?`<h3>${text(s,'Endpoint nəticələri','Endpoint results')}</h3>${r.endpointChecks.map(e=>`<div class="product-endpoint"><strong>${esc(e.hostname)}</strong><span>${esc(e.state)}</span><small>${esc(e.message)}</small></div>`).join('')}`:''}${(p.preview?.warnings||[]).length?`<h3>${text(s,'Plan xəbərdarlıqları','Plan warnings')}</h3><ul class="product-warnings">${p.preview.warnings.map(w=>`<li>${esc(w)}</li>`).join('')}</ul>`:''}</div><footer><button data-op-evidence="${esc(h.id)}">↓ ${text(s,'Sübutu endir','Download evidence')}</button><button data-product-action="copy-operation">${text(s,'Xülasəni kopyala','Copy summary')}</button></footer></aside>`;
  }
  function help(s) {
    if(!s.helpOpen)return '';
    return `<div class="product-drawer-backdrop" data-product-close></div><aside class="product-drawer" role="dialog" aria-modal="true" aria-labelledby="product-help-title" tabindex="-1"><header><div><span class="product-eyebrow">${text(s,'BƏLƏDÇİ','FIELD GUIDE')}</span><h2 id="product-help-title">${text(s,'Siyasəti inamla idarə et','Operate with confidence')}</h2></div><button data-product-close aria-label="${text(s,'Bağla','Close')}">×</button></header><div class="product-drawer-body"><p class="product-help-intro">${text(s,'Hər dəyişiklik eyni aydın ardıcıllıqla irəliləyir.','Every change follows the same clear sequence.')}</p>${[
      [text(s,'01 · Qoşul və yoxla','01 · Connect and check'),text(s,'Domen hesabını bir dəfə daxil et. Readiness yoxlamalarında məcburi xətaları həll et.','Connect your domain account once. Resolve required readiness failures.')],
      [text(s,'02 · Hədəfi dəqiq seç','02 · Choose a precise target'),text(s,'Qaydanı, GPO-nu və OU/domen hədəfini seç. Preview siyasəti dəyişmir.','Choose the control, GPO and OU/domain scope. Preview does not change policy.')],
      [text(s,'03 · Planı nəzərdən keçir','03 · Review the plan'),text(s,'Əvvəlki/yeni dəyəri, təsirlənən obyektləri və xəbərdarlıqları yoxla. Təsdiq üçün change reference daxil et.','Review before/after values, affected objects and warnings. Supply the change reference for approval.')],
      [text(s,'04 · Tətbiq et və nəticəni yoxla','04 · Apply and verify'),text(s,'Backup Apply-dan əvvəl yaradılır. Publication, replikasiya və faktiki siyasət ayrı nəticələrdir; hər birini yoxla.','Backup is created before Apply. Publication, replication and effective policy are separate results; check each one.')]
    ].map(([title,copy])=>`<section class="product-help-step"><h3>${title}</h3><p>${copy}</p></section>`).join('')}<h3>${text(s,'Klaviatura ilə daha sürətli','Move faster with the keyboard')}</h3><dl class="product-shortcuts"><div><dt>${text(s,'Qayda və əmrləri axtar','Search controls and actions')}</dt><dd><kbd>Ctrl</kbd> <kbd>K</kbd></dd></div><div><dt>${text(s,'Kitabxanada axtar','Search the library')}</dt><dd><kbd>/</kbd></dd></div><div><dt>${text(s,'Paneli bağla','Close a panel')}</dt><dd><kbd>Esc</kbd></dd></div></dl><div class="product-help-note">${text(s,'Kataloq əhatəsi domen uyğunluğu demək deyil. Uyğunluq canlı yoxlamaların nəticələri ilə təsdiqlənir.','Catalog coverage is not domain compliance. Compliance is established by live verification results.')}</div></div></aside>`;
  }
  function csv(rules) {
    // Prevent spreadsheet formula execution from imported text fields.
    const cell=value=>'"'+String(value??'').replace(/^[=+@-]/,"'$&").replaceAll('"','""')+'"';
    return '\uFEFF'+[['Control','Title','Level','Automation','Implementation','Recommended'],...rules.map(r=>[r.id,r.title,r.level,r.automation,r.implementation,r.recommended])].map(row=>row.map(cell).join(',')).join('\r\n');
  }
  window.GpoProduct=Object.freeze({dashboard,catalogTools,inspector,help,remember,sortedRuns,active,csv,date});
})();
