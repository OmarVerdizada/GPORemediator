(() => {
  'use strict';
  const upper = value => String(value || '').toUpperCase();
  const bad = value => /FAIL|MISMATCH|REVIEW|PARTIAL|DRIFT|ERROR|OVERRIDDEN/.test(upper(value));
  const effectiveVerified = value => /^(VERIFIED_ON_SAMPLE|VERIFIED_ON_ALL_TARGETS|DOMAIN_VALUE_MATCHES_ON_SELECTED_DC)$/.test(upper(value));
  function domainMismatch(result){const d=result?.domainPolicy;if(!d||/^(?:BATCH_)?ROLLED_BACK$/.test(upper(result.state)))return false;const a=String(d.value??'').trim(),b=String(d.desiredValue??'').trim();return !a||!b||!Number.isFinite(Number(a))||!Number.isFinite(Number(b))||Number(a)!==Number(b);}
  function coverageVerified(result){
    if(upper(result.effectiveStatus)==='DOMAIN_VALUE_MATCHES_ON_SELECTED_DC')
      return !!result.domainPolicy?.domainController?.trim()&&!(result.endpointChecks||[]).some(x=>x.state==='MISMATCH');
    if(!Array.isArray(result.endpointChecks)||!result.endpointChecks.length||result.endpointChecks.some(x=>x.state!=='VERIFIED'||!String(x.hostname||'').trim()))return false;
    if(upper(result.effectiveStatus)==='VERIFIED_ON_SAMPLE'&&!result.endpointCoverage)return true;
    const c=result.endpointCoverage,checks=result.endpointChecks;
    return !!(c?.complete===true&&Number.isSafeInteger(c.total)&&c.total>0&&c.checked===c.total&&Array.isArray(checks)&&checks.length===c.total&&
      new Set(checks.map(x=>String(x.hostname||'').toLowerCase())).size===c.total&&checks.every(x=>x.hostname&&x.state==='VERIFIED'));
  }
  function outcome(run){
    const r=run?.result||{},checks=r.endpointChecks||[],q=classify(run);
    const restored=['ROLLED_BACK','BATCH_ROLLED_BACK'].includes(r.state),busy=/^(APPLYING|VERIFYING|REFRESHING|ROLLBACKING|ROLLING_BACK)$/.test(r.state||'');
    const applied=!busy&&r.gpoPublished===true&&r.linkVerified===true&&/^(PUBLISHED|NO_CHANGE|REFRESH_COMPLETED|REFRESH_SCHEDULED|REFRESH_PARTIAL|PUBLISHED_REFRESH_FAILED)$/.test(r.state||'');
    const mismatch=!restored&&(domainMismatch(r)||r.effectiveStatus==='ENDPOINT_MISMATCH'||r.effectiveStatus==='DOMAIN_VALUE_PENDING_OR_OVERRIDDEN'||checks.some(x=>x.state==='MISMATCH'));
    const verified=q.publication==='published'&&r.linkVerified===true&&q.replication==='converged'&&q.effective==='verified'&&!q.attention;
    const count=state=>checks.filter(x=>x.state===state).length,total=r.endpointCoverage?.total??checks.length;
    const endpoints={total,verified:count('VERIFIED'),mismatch:count('MISMATCH'),unavailable:count('UNAVAILABLE')+count('OUTSIDE_SCOPE'),observed:count('OBSERVED'),remaining:Math.max(0,total-checks.length)};
    const refresh=r.refreshResults||[],refreshFailed=refresh.filter(x=>x.state==='FAILED').length;
    const title=restored?(r.state==='BATCH_ROLLED_BACK'?'Restored with batch snapshot':'Rollback completed successfully'):
      busy?'Checking policy':mismatch?(applied?'GPO saved · endpoint mismatch':'Policy is not effective'):
      applied?(verified?'Endpoint values verified':'GPO saved · endpoint verification incomplete'):
      q.attention?'Operation needs review':'Application not verified';
    return {restored,applied,busy,mismatch,verified,endpoints,refreshFailed,refreshTotal:refresh.length,
      success:!busy&&!mismatch&&(restored||verified),title};
  }
  function classify(run) {
    const result = run?.result || {};
    const publication = result.gpoPublished === true ? 'published' : bad(result.state) ? 'failed' : 'pending';
    const replication = result.verification?.replicationConverged ? 'converged' : (result.verification ? 'pending' : 'not_checked');
    const effective = domainMismatch(result)?'failed':effectiveVerified(result.effectiveStatus)&&coverageVerified(result) ? 'verified' : bad(result.effectiveStatus) ? 'failed' : 'pending';
    const attention = bad(result.state) || publication === 'failed' || effective === 'failed' || (result.refreshResults||[]).some(x=>upper(x.state)==='FAILED');
    const custom=run?.plan?.preview?.customValues??!!run?.plan?.selection?.itemValues;
    const compliant = !/^(?:BATCH_)?ROLLED_BACK$/.test(upper(result.state)) && !custom && !attention && publication === 'published' && result.linkVerified === true && replication === 'converged' && effective === 'verified';
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
    const reviewed=mapping&&mapping.automation!=='Automated';
    const level = mapping?.operationalImpact || (reviewed||mapping?.domainPolicySensitive||mapping?.requiresRestart?'HIGH':mapping?.requiresGpUpdate||['SecurityTemplate','AdvancedAudit'].includes(mapping?.handler)?'MEDIUM':'LOW');
    const normalized = upper(level);
    return normalized === 'HIGH'
      ? { name: 'High', cls: 'high', copy: mapping?.impactReason || (reviewed?'Environment-specific OS, server-role or account exceptions require explicit review before execution.':'Requires a constrained rollout and explicit dependency review.') }
      : normalized === 'MEDIUM'
        ? { name: 'Medium', cls: 'medium', copy: mapping?.impactReason || 'Validate scope and application dependencies before broad rollout.' }
        : { name: 'Low', cls: 'low', copy: mapping?.impactReason || 'Preview and post-change verification are still required.' };
  }
  function resultState(run){
    const r=run?.result||{};
    if(/^(ROLLED_BACK|BATCH_ROLLED_BACK|APPLYING|VERIFYING|REFRESHING|ROLLBACKING|ROLLING_BACK)$/.test(r.state||''))return r.state;
    return domainMismatch(r)||r.effectiveStatus==='ENDPOINT_MISMATCH'||r.effectiveStatus==='DOMAIN_VALUE_PENDING_OR_OVERRIDDEN'||(r.endpointChecks||[]).some(x=>x.state==='MISMATCH')?'ENDPOINT_MISMATCH':r.state;
  }
  window.GpoUiDomain = Object.freeze({ classify, outcome, workflowStep, impact, bad, effectiveVerified, coverageVerified, isUserPolicy, refreshChoices, resultState, domainMismatch });
})();
