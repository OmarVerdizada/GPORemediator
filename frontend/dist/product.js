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
  function controlStatus(s, rule) {
    const run=sortedRuns(s.history.filter(h=>h.plan?.selection?.setting===(rule.backendSetting||rule.id)))[0];
    if(!run)return {tone:'unknown',label:text(s,'Yoxlanmayıb','Not assessed'),run:null};
    const quality=window.GpoUiDomain.classify(run),state=String(run.result?.state||'').toUpperCase();
    if(state==='ROLLED_BACK')return {tone:'unknown',label:text(s,'Geri qaytarılıb','Rolled back'),run};
    if(active(run))return {tone:'unknown',label:text(s,'İcra olunur','In progress'),run};
    if(quality.compliant)return {tone:'good',label:text(s,'Tətbiq təsdiqlənib','Implementation verified'),run};
    if(quality.attention)return {tone:'warning',label:text(s,'Yoxlama tələb edir','Needs review'),run};
    return {tone:'unknown',label:text(s,'Təsdiq gözlənilir','Verification pending'),run};
  }
  function coverage(s) {
    const rules=s.catalog.rules,ready=rules.filter(r=>r.implementation==='live').length,manual=rules.filter(r=>r.implementation==='manual').length;
    const checked=rules.filter(r=>controlStatus(s,r).run).length;
    return `<section class="recipe-coverage"><div><span class="product-eyebrow">${text(s,'BENCHMARK ƏHATƏSİ','BENCHMARK COVERAGE')}</span><h2>${text(s,'Bütün qaydalar, bir baxışda','Every control at a glance')}</h2><p>${text(s,'Kataloq GPO bağlantısı olmadan da açıqdır. Tətbiq statusları son qeydə alınmış əməliyyata əsaslanır; domen üzrə audit balı deyil.','The catalog is available without a GPO connection. Implementation statuses reflect the last recorded operation, not a domain audit score.')}</p><a href="#/benchmark">${text(s,'Qaydaları nəzərdən keçir','Browse controls')} →</a></div><dl>${[[rules.length,text(s,'Ümumi qayda','Total controls')],[ready,text(s,'Avtomatlaşdırma hazır','Automation ready')],[manual,text(s,'Əl ilə yoxlama','Manual review')],[rules.length-checked,text(s,'Yoxlanmayıb','Not assessed')]].map(([n,label])=>`<div><dd>${n}</dd><dt>${label}</dt></div>`).join('')}</dl></section>`;
  }
  function recipeCards(s, rules) {
    let section='';
    return [...rules].sort((a,b)=>a.id.localeCompare(b.id,undefined,{numeric:true})).map(rule=>{
      const group=s.catalog.sections.find(x=>x.id===rule.sectionId),status=controlStatus(s,rule);
      const heading=section!==rule.sectionId?`<h2 class="recipe-section">${esc(rule.sectionId)} <span>${esc(group?.title||'')}</span></h2>`:'';section=rule.sectionId;
      const support=rule.implementation==='live'?text(s,'Avtomatlaşdırma hazır','Automation ready'):rule.implementation==='manual'?text(s,'Əl ilə yoxlama','Manual review'):text(s,'Mapping mövcud deyil','Mapping unavailable');
      return `${heading}<article class="recipe-card"><header><span class="recipe-number">${esc(rule.id)}</span><div><h3><button data-rule="${esc(rule.id)}">${esc(rule.title)}</button></h3><div class="recipe-tags"><span>${esc(rule.level)}</span><span class="${rule.implementation==='live'?'good':'unknown'}">${support}</span><span class="${status.tone}">${status.label}</span></div></div><button class="fav-mini ${s.favorites.has(rule.id)?'active':''}" data-favorite="${esc(rule.id)}" aria-label="${text(s,'Seçilmiş statusunu dəyiş','Toggle favorite')}">${s.favorites.has(rule.id)?'★':'☆'}</button></header><p class="recipe-description">${esc(rule.description||text(s,'İzah əlavə edilməyib.','No description available.'))}</p><details><summary>${text(s,'Tam izahı oxu','Read full description')}</summary><p>${esc(rule.description||'—')}</p></details><footer><div><small>${text(s,'TÖVSİYƏ OLUNAN VƏZİYYƏT','RECOMMENDED STATE')}</small><strong>${esc(rule.recommended||text(s,'Benchmark izahına baxın','See benchmark description'))}</strong>${status.run?`<small>${text(s,'Son qeyd','Last record')}: ${date(status.run.updatedAt,s.lang)} · ${esc(status.run.plan?.preview?.gpo?.name||'GPO')}</small>`:''}</div><button data-rule="${esc(rule.id)}">${text(s,'Qaydanı aç','Open control')} →</button></footer></article>`;
    }).join('');
  }
  const domainSymbols={'1':'⌾','2':'◇','3':'▤','4':'♧','5':'⚙','6':'⊞','7':'▱','8':'⇄','9':'◫','10':'◎','11':'⌁','12':'⚿','13':'⊘','14':'⊕','15':'◈','16':'⛨','17':'≋','18':'▦','19':'◉'};
  function domainHeader(s, domain, rules, open) {
    const ready=rules.filter(r=>r.implementation==='live').length;
    return `<button type="button" class="ent-domain-head" data-domain="${esc(domain.id)}" aria-expanded="${open}" aria-controls="catalog-domain-${esc(domain.id)}"><span class="domain-icon" aria-hidden="true">${window.GpoComponents.domainIcon(domain.id)}</span><span class="domain-title"><span class="domain-kicker">${text(s,'DOMEN','DOMAIN')} ${esc(domain.id)}</span><strong>${esc(domain.title)}</strong><small>${rules.length} ${text(s,'qayda','controls')} · ${ready} ${text(s,'avtomatlaşdırma hazır','automation ready')}</small></span><span class="domain-counter"><i>L1</i><b>${rules.filter(r=>r.level==='L1').length}</b></span><span class="domain-counter"><i>L2</i><b>${rules.filter(r=>r.level==='L2').length}</b></span><span class="domain-progress" aria-hidden="true"><i style="width:${Math.round(ready/Math.max(1,rules.length)*100)}%"></i></span><span class="domain-chevron" aria-hidden="true">${open?'−':'+'}</span></button>`;
  }
  function recipes(s, rules) {
    const filtered=!!s.query||s.level!=='ALL'||s.automation!=='ALL'||s.savedView!=='ALL';
    return s.catalog.sections.filter(d=>!d.parentId).sort((a,b)=>a.id.localeCompare(b.id,undefined,{numeric:true})).map(domain=>{
      const matching=rules.filter(r=>r.id.startsWith(domain.id+'.'));
      if(filtered&&!matching.length)return '';
      const open=!!s.expandedTop?.has(domain.id);
      return `<section class="ent-domain recipe-domain domain-tone-${(Number(domain.id)-1)%7} ${open?'open':''}">${domainHeader(s,domain,matching,open)}${open?`<div id="catalog-domain-${esc(domain.id)}" class="ent-domain-body">${matching.length?recipeCards(s,matching):`<p class="domain-empty">${text(s,'Bu domen üçün benchmark-da qayda yoxdur.','The benchmark contains no controls for this domain.')}</p>`}</div>`:''}</section>`;
    }).join('');
  }
  function disconnectedControl(s, rule) {
    return `<section class="recipe-offline"><span class="product-eyebrow">${text(s,'QAYDA HAZIRLIĞI','CONTROL PREPARATION')}</span><h2>${text(s,'GPO seçməzdən əvvəl qaydanı nəzərdən keçir','Review the control before choosing a GPO')}</h2><div class="recipe-tags"><span>${rule.implementation==='live'?text(s,'Avtomatlaşdırma hazır','Automation ready'):text(s,'Əl ilə yoxlama','Manual review')}</span><span>${controlStatus(s,rule).label}</span></div><h3>${text(s,'Tövsiyə olunan vəziyyət','Recommended state')}</h3><p>${esc(rule.recommended||'—')}</p><p>${esc(rule.description||'')}</p><ol><li>${text(s,'Qaydanın təsirini və tətbiq sahəsini nəzərdən keçirin.','Review the control impact and intended scope.')}</li><li>${text(s,'Domenə qoşulun və inventardan real GPO seçin.','Connect to the domain and choose a real GPO from inventory.')}</li><li>${text(s,'Dəyişiklikdən əvvəl yalnız oxuma planını hazırlayın.','Generate the read-only plan before making changes.')}</li></ol><button data-product-action="connect">${text(s,'Domenə qoşul','Connect to domain')} →</button></section>`;
  }
  function catalogTools(s, count) {
    const filtered = !!s.query || s.level!=='ALL' || s.automation!=='ALL' || s.savedView!=='ALL';
    return `<div class="product-catalog-tools"><span><strong>${count}</strong> ${text(s,'uyğun qayda','matching controls')} ${filtered?`<button data-product-action="clear-filters">${text(s,'Filtrləri təmizlə','Clear filters')} ×</button>`:''}</span><div><div class="product-view-switch" role="group" aria-label="${text(s,'Kataloq görünüşü','Catalog view')}"><button data-catalog-layout="recipes" aria-pressed="${s.catalogLayout==='recipes'}">${text(s,'Qaydalar','Recipes')}</button><button data-catalog-layout="tree" aria-pressed="${s.catalogLayout==='tree'}">${text(s,'Bölmələr','Hierarchy')}</button><button data-catalog-layout="list" aria-pressed="${s.catalogLayout==='list'}">${text(s,'Siyahı','List')}</button></div><button data-product-action="export-catalog">↓ ${text(s,'CSV ixrac','Export CSV')}</button></div></div>`;
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
    return `<div class="product-drawer-backdrop" data-product-close></div><aside class="product-drawer" role="dialog" aria-modal="true" aria-labelledby="operation-detail-title" tabindex="-1"><header><div><span class="product-eyebrow">${text(s,'ƏMƏLİYYAT DETALLARI','OPERATION DETAILS')}</span><h2 id="operation-detail-title">${esc(p.selection?.setting||'GPO')} · ${esc(p.preview?.gpo?.name||'GPO')}</h2><p>${date(h.updatedAt,s.lang)}</p></div><button data-product-close aria-label="${text(s,'Bağla','Close')}">${window.GpoComponents.icon('close')}</button></header><div class="product-drawer-body"><div class="product-result ${quality.attention?'warning':'neutral'}">${window.GpoComponents.status(s,r.state).html}<p>${esc(r.message||text(s,'Nəticə gözlənilir','Awaiting result'))}</p></div><h3>${text(s,'Mərhələlər','Stages')}</h3>${window.GpoComponents.timeline(s,h)}<h3>${text(s,'Yoxlama qatları','Verification layers')}</h3><div class="product-verification">${checks.map(([title,ok,copy])=>`<div><span class="product-check ${ok?'good':'pending'}">${ok?'✓':'○'}</span><span><strong>${title}</strong><small>${ok?copy:text(s,'Hələ təsdiqlənməyib','Not confirmed yet')}</small></span></div>`).join('')}</div><div class="product-value-grid"><div><small>${text(s,'ƏVVƏL','BEFORE')}</small><strong>${esc(p.preview?.previousValue??text(s,'Təyin edilməyib','Not configured'))}</strong></div><div><small>${text(s,'GÖZLƏNİLƏN','EXPECTED')}</small><strong>${esc(p.preview?.desiredValue??'—')}</strong></div><div><small>${text(s,'CARİ','CURRENT')}</small><strong>${esc(r.currentValue??'—')}</strong></div></div><h3>${text(s,'Dəyişiklik konteksti','Change context')}</h3><dl class="product-facts">${[
      [text(s,'Domen','Domain'),p.domain],[text(s,'Kontroller','Controller'),p.domainController],[text(s,'Hədəf','Scope'),p.selection?.scopeDn],[text(s,'İcra hesabı','Execution identity'),p.executionUser],[text(s,'Dəyişiklik sorğusu','Change reference'),h.approval?.changeReference],[text(s,'Backup','Backup'),r.backupId],[text(s,'Əməliyyat ID-si','Operation ID'),h.id],[text(s,'Correlation ID','Correlation ID'),h.correlationId]
    ].map(([label,value])=>`<div><dt>${label}</dt><dd>${esc(value||'—')}</dd></div>`).join('')}</dl>${(r.endpointChecks||[]).length?`<h3>${text(s,'Endpoint nəticələri','Endpoint results')}</h3>${r.endpointChecks.map(e=>`<div class="product-endpoint"><strong>${esc(e.hostname)}</strong><span>${esc(e.state)}</span><small>${esc(e.message)}</small></div>`).join('')}`:''}${(p.preview?.warnings||[]).length?`<h3>${text(s,'Plan xəbərdarlıqları','Plan warnings')}</h3><ul class="product-warnings">${p.preview.warnings.map(w=>`<li>${esc(w)}</li>`).join('')}</ul>`:''}</div><footer><button data-op-evidence="${esc(h.id)}">↓ ${text(s,'Sübutu endir','Download evidence')}</button><button data-product-action="copy-operation">${text(s,'Xülasəni kopyala','Copy summary')}</button></footer></aside>`;
  }
  function help(s) {
    if(!s.helpOpen)return '';
    return `<div class="product-drawer-backdrop" data-product-close></div><aside class="product-drawer" role="dialog" aria-modal="true" aria-labelledby="product-help-title" tabindex="-1"><header><div><span class="product-eyebrow">${text(s,'BƏLƏDÇİ','FIELD GUIDE')}</span><h2 id="product-help-title">${text(s,'Siyasəti inamla idarə et','Operate with confidence')}</h2></div><button data-product-close aria-label="${text(s,'Bağla','Close')}">${window.GpoComponents.icon('close')}</button></header><div class="product-drawer-body"><p class="product-help-intro">${text(s,'Hər dəyişiklik eyni aydın ardıcıllıqla irəliləyir.','Every change follows the same clear sequence.')}</p>${[
      [text(s,'01 · Qoşul və yoxla','01 · Connect and check'),text(s,'Domen hesabını bir dəfə daxil et. Readiness yoxlamalarında məcburi xətaları həll et.','Connect your domain account once. Resolve required readiness failures.')],
      [text(s,'02 · Hədəfi dəqiq seç','02 · Choose a precise target'),text(s,'Qaydanı, GPO-nu və OU/domen hədəfini seç. Preview siyasəti dəyişmir.','Choose the control, GPO and OU/domain scope. Preview does not change policy.')],
      [text(s,'03 · Planı nəzərdən keçir','03 · Review the plan'),text(s,'Əvvəlki/yeni dəyəri, təsirlənən obyektləri və xəbərdarlıqları yoxla. Təsdiq üçün change reference daxil et.','Review before/after values, affected objects and warnings. Supply the change reference for approval.')],
      [text(s,'04 · Tətbiq et və nəticəni yoxla','04 · Apply and verify'),text(s,'Backup Apply-dan əvvəl yaradılır. Publication, replikasiya və faktiki siyasət ayrı nəticələrdir; hər birini yoxla.','Backup is created before Apply. Publication, replication and effective policy are separate results; check each one.')]
    ].map(([title,copy])=>`<section class="product-help-step"><h3>${title}</h3><p>${copy}</p></section>`).join('')}<h3>${text(s,'Klaviatura ilə daha sürətli','Move faster with the keyboard')}</h3><dl class="product-shortcuts"><div><dt>${text(s,'Qayda və əmrləri axtar','Search controls and actions')}</dt><dd><kbd>Ctrl</kbd> <kbd>K</kbd></dd></div><div><dt>${text(s,'Kitabxanada axtar','Search the library')}</dt><dd><kbd>/</kbd></dd></div><div><dt>${text(s,'Əsas səhifələr','Main pages')}</dt><dd><kbd>Alt</kbd> <kbd>1 / 2 / 3</kbd></dd></div><div><dt>${text(s,'Paneli bağla','Close a panel')}</dt><dd><kbd>Esc</kbd></dd></div></dl><div class="product-help-note">${text(s,'Kataloq əhatəsi domen uyğunluğu demək deyil. Uyğunluq canlı yoxlamaların nəticələri ilə təsdiqlənir.','Catalog coverage is not domain compliance. Compliance is established by live verification results.')}</div></div></aside>`;
  }
  function csv(rules) {
    // Prevent spreadsheet formula execution from imported text fields.
    const cell=value=>'"'+String(value??'').replace(/^[=+@-]/,"'$&").replaceAll('"','""')+'"';
    return '\uFEFF'+[['Control','Title','Level','Automation','Implementation','Recommended'],...rules.map(r=>[r.id,r.title,r.level,r.automation,r.implementation,r.recommended])].map(row=>row.map(cell).join(',')).join('\r\n');
  }
  window.GpoProduct=Object.freeze({dashboard,coverage,recipes,domainHeader,controlStatus,disconnectedControl,catalogTools,inspector,help,remember,sortedRuns,active,csv,date});
})();
