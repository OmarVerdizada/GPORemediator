(() => {
  'use strict';
  const routes=new Set(['#/assurance','#/dashboard','#/benchmark','#/control','#/operations','#/audit','#/settings','#/reports','#/diagnostics']);
  function current(){return routes.has(location.hash)?location.hash:'#/dashboard';}
  function ensure(){if(location.hash==='#/workspace')location.replace('#/operations');else if(!routes.has(location.hash))location.replace('#/dashboard');return current();}
  function navigate(route){location.hash=routes.has(route)?route:'#/dashboard';}
  window.GpoRouter={routes,current,ensure,navigate};
})();
