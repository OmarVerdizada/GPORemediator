(() => {
  'use strict';
  const messages={
    az:{dashboard:'İdarə paneli',benchmark:'Benchmark',operations:'Əməliyyatlar',settings:'Sazlamalar',connected:'Qoşulub',setup:'Setup tələb olunur',refresh:'Yenilə',theme:'Tema',language:'Dil',domains:'Benchmark domain-ləri',controls:'Nəzarətlər',ready:'Remediation hazır',planned:'Mapping gözləyir',manual:'Manual nəzarət',search:'Nəzarət ID-si, ad və ya açar söz axtarın…',allLevels:'Bütün səviyyələr',allTypes:'Bütün növlər',overview:'İcmal',remediation:'Remediation',impact:'Təsir',verification:'Yoxlama',audit:'Audit',back:'Benchmark-a qayıt',target:'Hədəf və siyasət',preview:'Plan hazırla',approval:'Dəyişiklik təsdiqi',apply:'Tətbiq et',history:'Son əməliyyatlar',noHistory:'Hələ əməliyyat yoxdur.',noSelection:'Nəzarət seçilməyib',open:'Aç',logout:'Ayrıl',connect:'AD-yə qoşul',risk:'Əməliyyat riski'},
    en:{dashboard:'Dashboard',benchmark:'Benchmark',operations:'Operations',settings:'Settings',connected:'Connected',setup:'Setup required',refresh:'Refresh',theme:'Theme',language:'Language',domains:'Benchmark domains',controls:'Controls',ready:'Remediation ready',planned:'Mapping pending',manual:'Manual control',search:'Search control ID, policy name or keyword…',allLevels:'All levels',allTypes:'All types',overview:'Overview',remediation:'Remediation',impact:'Impact',verification:'Verification',audit:'Audit',back:'Back to benchmark',target:'Target & policy',preview:'Generate plan',approval:'Change approval',apply:'Apply change',history:'Recent operations',noHistory:'No operations yet.',noSelection:'No control selected',open:'Open',logout:'Disconnect',connect:'Connect to AD',risk:'Operational risk'}
  };
  let language='az';
  const normalize=value=>value==='en'?'en':'az';
  function setLanguage(value){language=normalize(value);document.documentElement.lang=language;document.documentElement.dir='ltr';return language;}
  function t(key){return messages[language]?.[key]??messages.en[key]??key;}
  function pair(az,en){return language==='az'?az:en;}
  window.GpoI18n={get language(){return language;},setLanguage,t,pair,messages};
})();
