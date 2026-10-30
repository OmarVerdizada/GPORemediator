/* Single-control jobs remain server-owned. This module only submits approved
   actions and reads their progress; it has no batch/workflow-center interface. */
(() => {'use strict';
window.GpoOperationMonitor={create({state,api,render}){
 let polling=false,loaded=false,error='',renderPending=false;
 const active=j=>['QUEUED','RUNNING','VERIFY_SCHEDULED'].includes(j.state);
 async function reload(){
  const [jobs,history]=await Promise.all([api('/workflows'),api('/gpo/history')]);
  const next=Array.isArray(jobs)?jobs:[];
  const changed=!loaded||!!error||JSON.stringify([state.workflowJobs,state.history])!==JSON.stringify([next,history]);
  state.workflowJobs=next;state.history=history;state.operationMonitorError='';loaded=true;error='';
  if(state.singleOperation){const op=state.singleOperation,job=next.find(j=>j.id===op.jobId);if(job){op.job=job;op.pollError='';if(['NEEDS_REVIEW','FAILED','CHECKS_INCOMPLETE','CANCELLED','REVIEW_REQUIRED'].includes(job.state)&&op.noticeState!==job.state){state.notice=job.message;op.noticeState=job.state;}}}
  return changed;
 }
 async function poll(){
  if(polling||state.busy||document.hidden||state.session?.mode!=='WINDOWS')return;
  if(!['#/dashboard','#/operations'].includes(location.hash)&&!active(state.singleOperation?.job||{})&&!(state.workflowJobs||[]).some(active)&&!state.history.some(window.GpoProduct.active)&&!renderPending)return;
  polling=true;
  try{if(await reload())renderPending=true;}
  catch(e){if(state.singleOperation)state.singleOperation.pollError=e.message;state.operationMonitorError=e.message;if(error!==e.message){error=e.message;renderPending=true;}}
  finally{polling=false;}
  if(renderPending&&!state.busy&&!state.confirmAction&&!state.scopeModal&&!state.notificationOpen&&!state.inspectedOperation&&!state.helpOpen&&(!document.activeElement?.closest('form')||location.hash==='#/control'&&state.tab==='verification')){renderPending=false;render();}
 }
 async function submitSingle(action,id,consent,refresh='None'){
  const job=await api('/workflows/'+action,{requestId:crypto.randomUUID(),planIds:[id],consent,refresh,verificationDelays:[]});
  const selection=(state.history.find(h=>h.id===id)?.plan||state.plan)?.selection;
  state.singleOperation={id,selection:selection?{...selection}:null,setting:selection?.setting||state.selectedRule?.backendSetting,jobId:job.id,action,startedAt:new Date().toISOString(),job,pollError:''};
  try{await reload();}catch(e){state.singleOperation.pollError=e.message;state.operationMonitorError=e.message;error=e.message;renderPending=true;}
  return job;
 }
 return {poll,submitSingle};
}};
})();
