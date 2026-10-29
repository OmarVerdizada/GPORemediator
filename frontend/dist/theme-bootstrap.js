/* Apply saved appearance before CSS paints; storage may be blocked. */
(() => {
  'use strict';
  const root=document.documentElement;
  const read=(key,fallback)=>{try{return sessionStorage.getItem(key)??fallback;}catch{return fallback;}};
  const choice=(key,values,fallback)=>{const value=read(key,fallback);return values.includes(value)?value:fallback;};
  const theme=choice('gr-theme',['system','light','dark'],'system');
  root.dataset.grTheme=theme==='system'?(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'):theme;
  for(const [attribute,key] of [['largeText','gr-large-text'],['contrast','gr-high-contrast'],['sidebarCollapsed','gr-sidebar-collapsed']])
    root.dataset[attribute]=String(read(key,'false')==='true');
})();
