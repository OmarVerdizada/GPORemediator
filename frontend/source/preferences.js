(() => {
  'use strict';
  const storage=window.GpoClient.storage,ui=window.GpoComponents;
  const preference=(key,fallback)=>storage.get(key,fallback);
  function apply(s){
    const root=document.documentElement,theme=s.theme==='system'?(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'):s.theme;
    root.dataset.grTheme=theme;root.dataset.density=preference('gr-density','comfortable');root.dataset.accent=preference('gr-accent','blue');root.dataset.sidebarCollapsed=preference('gr-sidebar-collapsed','false');root.dataset.largeText=preference('gr-large-text','false');root.dataset.contrast=preference('gr-high-contrast','false');storage.set('gr-theme',s.theme);
  }
  function menu(s){const text=(_fallback,en)=>ui.text(s,_fallback,en);return `<details class="ds-preferences"><summary aria-label="${'Appearance and help'}">${ui.icon('settings')}<span>${'Appearance'}</span></summary><div class="ds-preferences-panel"><label>${'Theme'}<select data-preference="theme" aria-label="${'Theme selection'}">${[['system','System'],['light','Light'],['dark','Dark']].map(([v,l])=>`<option value="${v}" ${s.theme===v?'selected':''}>${l}</option>`).join('')}</select></label><label>${'Accent color'}<select data-preference="accent" aria-label="${'Accent color'}">${[['blue','Cool blue'],['cyan','Cyan'],['violet','Violet']].map(([v,l])=>`<option value="${v}" ${preference('gr-accent','blue')===v?'selected':''}>${l}</option>`).join('')}</select></label><label>${'Display density'}<select data-preference="density" aria-label="${'Display density'}">${[['comfortable','Comfortable'],['compact','Compact']].map(([v,l])=>`<option value="${v}" ${preference('gr-density','comfortable')===v?'selected':''}>${l}</option>`).join('')}</select></label><label class="ds-checkbox"><input type="checkbox" data-preference="large-text" ${preference('gr-large-text','false')==='true'?'checked':''}>${'Large text'}</label><label class="ds-checkbox"><input type="checkbox" data-preference="high-contrast" ${preference('gr-high-contrast','false')==='true'?'checked':''}>${'High contrast'}</label><button data-product-action="help">${ui.icon('help')}${'Guide and shortcuts'}</button></div></details>`;}
  function validate(input,s){
    if(!input?.willValidate)return;const id=input.dataset.errorId||(input.dataset.errorId='field-error-'+(++validate.sequence)),existing=document.getElementById(id);
    if(input.validity.valid){input.removeAttribute('aria-invalid');existing?.remove();input.setAttribute('aria-describedby',(input.getAttribute('aria-describedby')||'').split(' ').filter(x=>x&&x!==id).join(' '));return;}
    input.setAttribute('aria-invalid','true');let error=existing;if(!error){error=document.createElement('span');error.id=id;error.className='ds-field-error';error.setAttribute('role','status');input.insertAdjacentElement('afterend',error);input.setAttribute('aria-describedby',[(input.getAttribute('aria-describedby')||''),id].filter(Boolean).join(' '));}
    const text=(_fallback,en)=>ui.text(s,_fallback,en);error.textContent=input.validity.valueMissing?'Complete this field.':input.validity.patternMismatch?'Enter the confirmation text exactly as shown.':input.validity.rangeOverflow?text('Maximum value is '+input.max+'.','Maximum value is '+input.max+'.'):input.validity.rangeUnderflow?text('Minimum value is '+input.min+'.','Minimum value is '+input.min+'.'):'Enter a valid value.';
  }
  validate.sequence=0;
  function decorate(root){
    for(const b of root.querySelectorAll('button:not(.ent-domain-head,.ent-sub-head,.ent-rule,.nav-link,.product-step,.product-recent,.graph-node,.pr-cell,.pr-map-heading,.pr-copy,.gpo-option,.gpo-picker-trigger,.ds-activity-row)')){
      b.classList.add('ds-button');b.classList.toggle('ds-danger',b.matches('.ds-danger,.danger-action,.danger,[data-confirm-run]'));b.classList.toggle('ds-primary',b.matches('.primary,.primary-inline,.primary-action,.gr-auto-btn.primary,[data-preview-submit]'));if(!b.classList.contains('ds-primary')&&!b.classList.contains('ds-danger'))b.classList.add('ds-secondary');
    }
  }
  function install(s,render,installNav){
    if(document.querySelector('.ds-sidebar-toggle'))return;
    const toggle=document.createElement('button');toggle.className='ds-sidebar-toggle';toggle.innerHTML=ui.icon('panel');toggle.addEventListener('click',()=>{storage.set('gr-sidebar-collapsed',preference('gr-sidebar-collapsed','false')==='true'?'false':'true');apply(s);update();});document.querySelector('.brand-lockup').insertAdjacentElement('afterend',toggle);
    const update=()=>{toggle.setAttribute('aria-label','Collapse / expand sidebar');toggle.setAttribute('aria-expanded',preference('gr-sidebar-collapsed','false')!=='true');};update();
    document.addEventListener('change',e=>{const key=e.target.dataset.preference;if(!key)return;if(key==='theme')s.theme=e.target.value;if(key==='language'){s.lang='en';window.GpoI18n.setLanguage('en');storage.set('gr-lang','en');}if(key==='accent'||key==='density')storage.set('gr-'+key,e.target.value);if(key==='large-text'||key==='high-contrast')storage.set('gr-'+key,String(e.target.checked));apply(s);render();update();});
    document.addEventListener('invalid',e=>validate(e.target,s),true);document.addEventListener('input',e=>{if(e.target.hasAttribute('aria-invalid'))validate(e.target,s);});
    matchMedia('(prefers-color-scheme: dark)').addEventListener('change',()=>{if(s.theme==='system')apply(s);});
  }
  window.GpoPreferences=Object.freeze({apply,menu,decorate,install,validate});
})();
