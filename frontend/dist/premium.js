/* Premium presentation: recorded evidence only, with no policy mutations. */
(() => {
  'use strict';
  const ui=window.GpoComponents,esc=ui.esc;
  function copyValue(s,value,label){
    if(value==null||value==='')return '<span class="pr-missing">—</span>';
    const hint='Copy: '+label;
    return `<span class="pr-identity"><code title="${esc(value)}">${esc(value)}</code><button type="button" class="pr-copy" data-copy-value="${esc(value)}" aria-label="${esc(hint)}" title="${esc(hint)}"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V3H3v13h5"/></svg></button></span>`;
  }
  function emptyIcon(){return `<svg class="pr-empty-art" viewBox="0 0 120 80" width="120" height="80" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="20" y="14" width="80" height="52" rx="8"/><path d="M20 30h80M32 43h24m-24 10h16M75 40l12 5v8c0 6-12 12-12 12S63 59 63 53v-8z"/><path d="m70 51 4 4 7-8"/></svg>`;}
  window.GpoPremium=Object.freeze({copyValue,emptyIcon});
})();
