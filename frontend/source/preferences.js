(() => {
  'use strict';
  const storage=window.GpoClient.storage,ui=window.GpoComponents;
  const preference=(key,fallback)=>{
    const value=storage.get(key,fallback);
    const values=['true','false'];
    return values.includes(value)?value:fallback;
  };
  function apply(s){
    if(!['system','light','dark'].includes(s.theme))s.theme='system';
    const root=document.documentElement,theme=s.theme==='system'?(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'):s.theme;
    root.dataset.grTheme=theme;root.dataset.sidebarCollapsed=preference('gr-sidebar-collapsed','false');root.dataset.largeText=preference('gr-large-text','false');root.dataset.contrast=preference('gr-high-contrast','false');storage.set('gr-theme',s.theme);
  }
  function menu(s){const text=(_fallback,en)=>ui.text(s,_fallback,en);return `<details class="ds-preferences"><summary id="appearance-trigger" aria-controls="appearance-options" aria-label="${'Appearance and help'}">${ui.icon('settings')}<span>${'Appearance'}</span></summary><div class="ds-preferences-panel" id="appearance-options" role="region" aria-label="Appearance options"><label>${'Theme'}<select id="preference-theme" data-preference="theme" aria-label="${'Theme selection'}">${[['system','System'],['light','Light'],['dark','Dark']].map(([v,l])=>`<option value="${v}" ${s.theme===v?'selected':''}>${l}</option>`).join('')}</select></label><label class="ds-checkbox"><input type="checkbox" id="preference-large-text" data-preference="large-text" ${preference('gr-large-text','false')==='true'?'checked':''}>${'Large text'}</label><label class="ds-checkbox"><input type="checkbox" id="preference-high-contrast" data-preference="high-contrast" ${preference('gr-high-contrast','false')==='true'?'checked':''}>${'High contrast'}</label><button data-product-action="help">${ui.icon('help')}${'Guide and shortcuts'}</button></div></details>`;}
  function validate(input,s){
    if(!input?.willValidate)return;const id=input.dataset.errorId||(input.dataset.errorId='field-error-'+(++validate.sequence)),existing=document.getElementById(id);
    if(input.validity.valid){input.removeAttribute('aria-invalid');existing?.remove();input.setAttribute('aria-describedby',(input.getAttribute('aria-describedby')||'').split(' ').filter(x=>x&&x!==id).join(' '));return;}
    input.setAttribute('aria-invalid','true');let error=existing;if(!error){error=document.createElement('span');error.id=id;error.className='ds-field-error';error.setAttribute('role','status');input.insertAdjacentElement('afterend',error);input.setAttribute('aria-describedby',[(input.getAttribute('aria-describedby')||''),id].filter(Boolean).join(' '));}
    error.textContent=input.validity.customError?input.validationMessage:input.validity.valueMissing?'Complete this field.':input.validity.patternMismatch?(input.name==='confirmation'?'Enter the confirmation text exactly as shown.':'Use the format shown for this field.'):input.validity.tooShort?'Enter at least '+input.minLength+' characters.':input.validity.rangeOverflow?'Maximum value is '+input.max+'.':input.validity.rangeUnderflow?'Minimum value is '+input.min+'.':input.validity.badInput?'Enter a valid number.':'Enter a valid value.';
  }
  validate.sequence=0;
  function decorate(root){
    for(const [groupIndex,group] of [...root.querySelectorAll('[role=tablist]')].entries()){
      const tabs=[...group.querySelectorAll('[role=tab]')],active=tabs.find(x=>x.getAttribute('aria-selected')==='true')||tabs[0];
      tabs.forEach((tab,index)=>{tab.tabIndex=tab===active?0:-1;if(!tab.id)tab.id='tab-'+root.id+'-'+groupIndex+'-'+index;});
    }
    for(const input of root.querySelectorAll('input:not([id]),select:not([id]),textarea:not([id])')){
      const name=input.name||input.dataset.entFilter;
      if(name)input.id=('field-'+(input.form?.id||root.id||'workspace')+'-'+name).replace(/[^A-Za-z0-9_-]/g,'-');
    }
    for(const table of root.querySelectorAll('.ent-table-wrap,.wf-table-wrap')){
      table.tabIndex=0;table.setAttribute('role','region');
      if(!table.hasAttribute('aria-label'))table.setAttribute('aria-label',(table.closest('section')?.querySelector('h2')?.textContent||'Results')+' — scrollable table');
    }
    for(const b of root.querySelectorAll('button:not(.ent-domain-head,.ent-sub-head,.ent-rule,.nav-link,.product-step,.product-recent,.graph-node,.pr-cell,.pr-map-heading,.pr-copy,.gpo-option,.gpo-picker-trigger,.ds-activity-row)')){
      b.classList.add('ds-button');b.classList.toggle('ds-danger',b.matches('.ds-danger,.danger-action,.danger,[data-confirm-run]'));b.classList.toggle('ds-primary',b.matches('.primary,.primary-inline,.primary-action,.gr-auto-btn.primary,[data-preview-submit]'));if(!b.classList.contains('ds-primary')&&!b.classList.contains('ds-danger'))b.classList.add('ds-secondary');
    }
  }
  function install(s,render,installNav){
    if(document.querySelector('.ds-sidebar-toggle'))return;
    const toggle=document.createElement('button');toggle.className='ds-sidebar-toggle';toggle.innerHTML=ui.icon('panel');toggle.addEventListener('click',()=>{storage.set('gr-sidebar-collapsed',preference('gr-sidebar-collapsed','false')==='true'?'false':'true');apply(s);update();});document.querySelector('.brand-lockup').append(toggle);
    const update=()=>{const expanded=preference('gr-sidebar-collapsed','false')!=='true';toggle.setAttribute('aria-label',expanded?'Collapse navigation':'Expand navigation');toggle.title=expanded?'Collapse navigation':'Expand navigation';toggle.setAttribute('aria-expanded',expanded);};update();
    document.addEventListener('change',e=>{const key=e.target.dataset.preference;if(!key)return;if(key==='theme')s.theme=e.target.value;if(key==='language'){s.lang='en';window.GpoI18n.setLanguage('en');storage.set('gr-lang','en');}if(key==='large-text'||key==='high-contrast')storage.set('gr-'+key,String(e.target.checked));apply(s);render();update();});
    document.addEventListener('invalid',e=>validate(e.target,s),true);document.addEventListener('input',e=>{if(e.target.hasAttribute('aria-invalid'))validate(e.target,s);});
    document.addEventListener('pointerdown',e=>{const menu=document.querySelector('.ds-preferences[open]');if(menu&&!menu.contains(e.target))menu.open=false;});
    document.addEventListener('keydown',e=>{
      const menu=document.querySelector('.ds-preferences[open]');
      if(e.key==='Escape'&&menu){e.preventDefault();e.stopPropagation();menu.open=false;menu.querySelector('summary')?.focus();}
      const tab=e.target.closest?.('[role=tab]'),group=tab?.closest('[role=tablist]');
      if(group&&!e.altKey&&!e.ctrlKey&&!e.metaKey&&['ArrowLeft','ArrowRight','Home','End'].includes(e.key)){
        const tabs=[...group.querySelectorAll('[role=tab]')].filter(x=>!x.disabled),current=tabs.indexOf(tab);
        const next=e.key==='Home'?0:e.key==='End'?tabs.length-1:(current+(e.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;
        const groupIndex=[...document.querySelectorAll('[role=tablist]')].indexOf(group);
        e.preventDefault();tabs[next]?.click();document.querySelectorAll('[role=tablist]')[groupIndex]?.querySelectorAll('[role=tab]')[next]?.focus({preventScroll:true});
      }
    });
    document.addEventListener('focusin',e=>{const menu=document.querySelector('.ds-preferences[open]');if(menu&&!menu.contains(e.target))menu.open=false;});
    matchMedia('(prefers-color-scheme: dark)').addEventListener('change',()=>{if(s.theme==='system')apply(s);});
  }
  window.GpoPreferences=Object.freeze({apply,menu,decorate,install,validate});
})();
