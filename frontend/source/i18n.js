(() => {
  'use strict';
  const messages={
    en:{dashboard:'Dashboard',benchmark:'Benchmark',operations:'Operations',settings:'Settings',connected:'Connected',setup:'Setup required',refresh:'Refresh',theme:'Theme',language:'Language',domains:'Benchmark domains',controls:'Controls',ready:'Remediation ready',planned:'Mapping pending',manual:'Manual control',search:'Search control ID, policy name or keyword…',allLevels:'All levels',allTypes:'All types',overview:'Overview',remediation:'Remediation',impact:'Impact',verification:'Verification',audit:'Audit',back:'Back to benchmark',target:'Target & policy',preview:'Generate plan',approval:'Change approval',apply:'Apply change',history:'Recent operations',noHistory:'No operations yet.',noSelection:'No control selected',open:'Open',logout:'Disconnect',connect:'Connect to AD',risk:'Operational risk'}
  };
  let language='en';
  const normalize=()=> 'en';
  function setLanguage(value){language=normalize(value);document.documentElement.lang=language;document.documentElement.dir='ltr';return language;}
  function t(key){return messages[language]?.[key]??messages.en[key]??key;}
  function pair(_fallback,en){return en;}
  window.GpoI18n={get language(){return language;},setLanguage,t,pair,messages};
})();
