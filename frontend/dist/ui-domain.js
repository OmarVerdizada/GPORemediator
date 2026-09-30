(() => {
  'use strict';
  const upper = value => String(value || '').toUpperCase();
  const bad = value => /FAIL|MISMATCH|REVIEW|PARTIAL|DRIFT|ERROR/.test(upper(value));
  const effectiveVerified = value => /^(VERIFIED_ON_SAMPLE|DOMAIN_VALUE_MATCHES_ON_SELECTED_DC)$/.test(upper(value));
  function classify(run) {
    const result = run?.result || {};
    const publication = result.gpoPublished || upper(result.state) === 'NO_CHANGE' ? 'published' : bad(result.state) ? 'failed' : 'pending';
    const replication = result.verification?.replicationConverged ? 'converged' : (result.verification ? 'pending' : 'not_checked');
    const effective = effectiveVerified(result.effectiveStatus) ? 'verified' : bad(result.effectiveStatus) ? 'failed' : 'pending';
    const attention = bad(result.state) || publication === 'failed' || effective === 'failed';
    const compliant = !attention && publication === 'published' && result.linkVerified === true && replication === 'converged' && effective === 'verified';
    return { publication, replication, effective, attention, compliant };
  }
  function workflowStep({ plan, approvalReviewed, run }) {
    if (run) {
      const state = upper(run.result?.state);
      if (/ROLLED_BACK/.test(state)) return 5;
      if (/FAIL|REVIEW|DRIFT|MISMATCH/.test(state)) return 5;
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
  window.GpoUiDomain = Object.freeze({ classify, workflowStep, impact, bad, effectiveVerified });
})();
