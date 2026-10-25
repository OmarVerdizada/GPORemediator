/* Bounded DOM rendering; filtering and exports retain the complete collection. */
(() => {
  'use strict';
  function page(items, requested = 0, size = 100) {
    size = Math.max(1, Math.min(500, Math.trunc(size) || 100));
    const total = items.length, pages = Math.max(1, Math.ceil(total / size));
    const index = Math.max(0, Math.min(pages - 1, Math.trunc(requested) || 0));
    return {items: items.slice(index * size, (index + 1) * size), page:index, total, pages, from:total ? index * size + 1 : 0, to:Math.min(total, (index + 1) * size)};
  }
  function render(key, result) {
    if (!/^[a-z-]+$/.test(key)) throw Error('Invalid pagination key');
    return `<nav class="list-pagination" aria-label="${key} pages"><span>${result.from}–${result.to} of ${result.total}</span><button type="button" data-list-page="${key}" data-page="${result.page-1}" ${result.page===0?'disabled':''}>Previous</button><span>Page ${result.page+1} / ${result.pages}</span><button type="button" data-list-page="${key}" data-page="${result.page+1}" ${result.page+1===result.pages?'disabled':''}>Next</button></nav>`;
  }
  window.GpoListPager=Object.freeze({page,render});
})();
