(() => {
  'use strict';
  const upper = value => String(value || '').toUpperCase();
  const bad = value => /FAIL|MISMATCH|REVIEW|PARTIAL|DRIFT|ERROR/.test(upper(value));
  const effectiveVerified = value => /^(VERIFIED_ON_SAMPLE|VERIFIED_ON_ALL_TARGETS|DOMAIN_VALUE_MATCHES_ON_SELECTED_DC)$/.test(upper(value));
  function coverageVerified(result){
    if(upper(result.effectiveStatus)!=='VERIFIED_ON_ALL_TARGETS')return true;
    const c=result.endpointCoverage,checks=result.endpointChecks;
    return !!(c?.complete===true&&Number.isSafeInteger(c.total)&&c.total>0&&c.checked===c.total&&Array.isArray(checks)&&checks.length===c.total&&
      new Set(checks.map(x=>String(x.hostname||'').toLowerCase())).size===c.total&&checks.every(x=>x.hostname&&x.state==='VERIFIED'));
  }
  function classify(run) {
    const result = run?.result || {};
    const publication = result.gpoPublished === true ? 'published' : bad(result.state) ? 'failed' : 'pending';
    const replication = result.verification?.replicationConverged ? 'converged' : (result.verification ? 'pending' : 'not_checked');
    const effective = effectiveVerified(result.effectiveStatus)&&coverageVerified(result) ? 'verified' : bad(result.effectiveStatus) ? 'failed' : 'pending';
    const attention = bad(result.state) || publication === 'failed' || effective === 'failed' || (result.refreshResults||[]).some(x=>upper(x.state)==='FAILED');
    const custom=!!run?.plan?.selection?.itemValues;
    const compliant = !upper(result.state).startsWith('ROLLED_BACK') && !custom && !attention && publication === 'published' && result.linkVerified === true && replication === 'converged' && effective === 'verified';
    return { publication, replication, effective, attention, compliant, custom };
  }
  function isUserPolicy(run,settings=[]) {
    return run?.plan?.selection?.accountScope==='Users'||String(settings.find(x=>x.id===run?.plan?.selection?.setting)?.scope||'').toLowerCase()==='user';
  }
  function refreshChoices(run,settings=[]) {
    const selection=run?.plan?.selection||{},mapping=settings.find(x=>x.id===selection.setting);
    if(isUserPolicy(run,settings))return selection.endpointScopeDn?[{value:'Scope',label:'User sessions on endpoint OU computers'}]:[];
    const domain=!/^OU=/i.test(selection.scopeDn||'')&&(selection.accountScope==='Domain'||(!selection.accountScope&&mapping?.domainPolicySensitive));
    return domain?[{value:'Pdc',label:'PDC emulator'}]:[{value:'Scope',label:'Scope computers'}];
  }
  function workflowStep({ plan, approvalReviewed, run }) {
    if (run) {
      const state = upper(run.result?.state);
      if (/ROLLED_BACK/.test(state)) return 5;
      if (/FAIL|REVIEW|DRIFT|MISMATCH/.test(state)) return run.result?.gpoPublished ? 6 : 5;
      if (classify(run).compliant) return 6;
      return run.result?.gpoPublished ? 6 : 5;
    }
    if (plan && approvalReviewed) return 4;
    if (plan) return 3;
    return 1;
  }
  function impact(mapping) {
    const level = mapping?.operationalImpact || 'LOW';
    const normalized = upper(level);
    return normalized === 'HIGH'
      ? { name: 'High', cls: 'high', copy: mapping?.impactReason || 'Requires a constrained rollout and explicit dependency review.' }
      : normalized === 'MEDIUM'
        ? { name: 'Medium', cls: 'medium', copy: mapping?.impactReason || 'Validate scope and application dependencies before broad rollout.' }
        : { name: 'Low', cls: 'low', copy: mapping?.impactReason || 'Preview and post-change verification are still required.' };
  }
  window.GpoUiDomain = Object.freeze({ classify, workflowStep, impact, bad, effectiveVerified, coverageVerified, isUserPolicy, refreshChoices });
})();
