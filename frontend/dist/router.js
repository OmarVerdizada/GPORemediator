(() => {
  'use strict';
  const routes=new Set(['#/dashboard','#/benchmark','#/control','#/operations','#/audit','#/settings']);
  function current(){return routes.has(location.hash)?location.hash:'#/dashboard';}
  function ensure(){if(!routes.has(location.hash))location.replace('#/dashboard');return current();}
  function navigate(route){location.hash=routes.has(route)?route:'#/dashboard';}
  window.GpoRouter={routes,current,ensure,navigate};
})();
