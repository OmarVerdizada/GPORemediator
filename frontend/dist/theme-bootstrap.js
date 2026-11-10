/* Apply saved appearance before CSS paints; storage may be blocked. */
(() => {
  'use strict';
  const root=document.documentElement,key='gr-theme';
  const choices=[['system','System'],['light','Light'],['dark','Dark']];
  const system=matchMedia('(prefers-color-scheme: dark)');
  const read=(storage,name)=>{try{return globalThis[storage]?.getItem(name);}catch{return null;}};
  const normalize=value=>choices.some(([id])=>id===value)?value:'system';
  let selected=normalize(read('localStorage',key)??read('sessionStorage',key));
  let paint;
  function apply(){
    const theme=selected==='system'?(system.matches?'dark':'light'):selected;
    if(root.dataset.grTheme&&root.dataset.grTheme!==theme){
      // Switch foregrounds and surfaces in one paint instead of fading them independently.
      root.dataset.themeChanging='true';
      cancelAnimationFrame(paint);
      paint=requestAnimationFrame(()=>{paint=requestAnimationFrame(()=>delete root.dataset.themeChanging);});
    }
    root.dataset.grTheme=theme;
    const meta=document.querySelector?.('meta[name=theme-color]');
    if(meta)meta.content=meta.dataset[theme];
    for(const select of document.querySelectorAll?.('[data-preference=theme], [data-sign-in-theme]')??[])select.value=selected;
  }
  function set(value){
    selected=normalize(value);
    try{localStorage.setItem(key,selected);}
    catch{try{sessionStorage.setItem(key,selected);}catch{/* Keep the selection for this page. */}}
    apply();
  }
  globalThis.GpoTheme=Object.freeze({set,options:()=>choices.map(([id,label])=>`<option value="${id}"${id===selected?' selected':''}>${label}</option>`).join('')});
  system.addEventListener?.('change',()=>{if(selected==='system')apply();});
  globalThis.addEventListener?.('storage',event=>{if(event.key===key){selected=normalize(event.newValue);apply();}});
  apply();
  for(const [attribute,key] of [['largeText','gr-large-text'],['contrast','gr-high-contrast'],['sidebarCollapsed','gr-sidebar-collapsed']])
    root.dataset[attribute]=String(read('sessionStorage',key)==='true');
})();
