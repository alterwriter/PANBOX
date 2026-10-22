import {ArrowUpRight, Check, ClipboardCopy, GitBranch, MapPin, ShieldCheck} from 'lucide-react';
import './finding_detail.css';

type FindingSummary={RuleID:string;Repository:string;Module:string;Raw:string;Effective:string;Line:number};
type FindingHistory={scan_id:string;commit_sha:string;created_at:string;detected:boolean};
type AIReview={state:string;run_id?:string;run_status?:string;provider?:string;error_code?:string;verdict?:string;confidence?:string;explanation?:string;remediation?:string;evidence?:string;at?:string};
type FindingDetail={rule_id:string;message:string;status:string;branch:string;path:string;first_seen:string;last_seen:string;source_url?:string;reference_url?:string;remediation:string;history?:FindingHistory[];ai_review?:AIReview};

const aiStateText:Record<string,string>={reviewed:'Reviewed',queued:'Queued',running:'Reviewing',failed:'Review failed',not_reviewed:'Not reviewed',not_requested:'Not requested',not_eligible:'Not eligible',resolved:'Not in latest scan',historical:'Historical scan'};

export function FindingDetailPanel({finding,detail,fmtDate,copy,onRecast,canTriage,disposition,setDisposition,reason,setReason,onSave}:{
 finding:FindingSummary;detail:FindingDetail;fmtDate:(v?:string|null)=>string;copy:(v:string)=>void;onRecast:()=>void;canTriage:boolean;
 disposition:string;setDisposition:(v:string)=>void;reason:string;setReason:(v:string)=>void;onSave:()=>void;
}){
 const prompt=`Review PANBOX finding ${detail.rule_id} at ${detail.path}:${finding.Line} on branch ${detail.branch}. ${detail.message} Suggested remediation: ${detail.remediation} Check the actual data flow, propose a minimal fix, and add a regression test.`;
 const ai=detail.ai_review;
 const aiMessage=ai?.state==='not_eligible'?'Only open Critical/High/Medium VACCIN findings with a source line are eligible.':
  ai?.state==='resolved'?'This finding was absent from the latest complete scan. Historical AI results remain in their run records.':
  ai?.state==='not_reviewed'?'A review run finished without an assessment for this finding. It may have reached the per-scan cap or failed at this finding; check the Admin run log.':
  ai?.state==='failed'?`The review run failed${ai.error_code?` (${ai.error_code})`:''}. Check the Admin process log and retry.`:
  ai?.state==='queued'?'Waiting for the selected AI worker.':
  ai?.state==='running'?'The server is evaluating this scan now. Reopen this finding to refresh.':
  'No AI review has been requested for this scan. Enable it in Admin or queue one from the scan detail.';
 return <div className="finding-detail">
  <header className="finding-detail-header">
   <div className="finding-detail-kicker"><span className="module-pill">{finding.Module.toUpperCase()}</span><span className={`status-badge ${detail.status==='open'?'fail':''}`}>{detail.status.replaceAll('_',' ')}</span><span className={`severity-pill ${finding.Effective}`}>{finding.Effective.toUpperCase()}</span></div>
   <p className="eyebrow">FINDING DETAIL</p><h2>{detail.rule_id}</h2><p className="finding-detail-summary">{detail.message}</p>
  </header>
  <div className="finding-detail-meta">
   <div><span><GitBranch size={14}/> Repository / branch</span><b>{finding.Repository}</b><small>{detail.branch}</small></div>
   <div><span><MapPin size={14}/> Source location</span><b className="mono">{detail.path||'Dependency'}{finding.Line?`:${finding.Line}`:''}</b></div>
   <div><span>First seen</span><b>{fmtDate(detail.first_seen)}</b><small>Last seen {fmtDate(detail.last_seen)}</small></div>
  </div>
  {detail.source_url&&<div className="finding-detail-links"><a href={detail.source_url} target="_blank" rel="noopener noreferrer">Open {detail.path}:{finding.Line} at scanned commit <ArrowUpRight size={15}/></a></div>}
  <section className="finding-detail-section remediation-panel"><div className="finding-section-heading"><span className="finding-section-icon"><ShieldCheck size={19}/></span><div><h3>Suggested remediation</h3><p>Validate the rule match against the actual data flow before changing code.</p></div></div><p>{detail.remediation}</p>{detail.reference_url&&<div className="finding-detail-links"><a href={detail.reference_url} target="_blank" rel="noopener noreferrer">{finding.Module==='enetron'?'Open public vulnerability advisory':'Read public remediation guidance'} <ArrowUpRight size={15}/></a><small>{finding.Module==='enetron'?'OSV vulnerability record':'OWASP or framework documentation'} · guidance, not proof of exploitability</small></div>}<div className="remediation-steps"><span><Check size={14}/> Inspect the source</span><span><Check size={14}/> Apply the safe change</span><span><Check size={14}/> Test and rescan</span></div><button className="secondary" onClick={()=>copy(prompt)}><ClipboardCopy size={16}/> Copy fix prompt</button></section>
  <section className="finding-detail-section ai-review-card">
   <div className="finding-section-heading">
    <div><h3>AI evaluation</h3><p>Advisory review of the latest complete scan on this branch. It never changes scanner severity or gate.</p></div>
    <span className={`status-badge ${ai?.state==='reviewed'?'pass':ai?.state==='failed'?'fail':'partial'}`}>{aiStateText[ai?.state||'not_requested']||'Unknown'}</span>
   </div>
   {ai?.state==='reviewed' ? <>
    <div className="ai-review-meta"><b>{ai.verdict?.replaceAll('_',' ')}</b><span>{ai.confidence} confidence · {ai.provider} · {fmtDate(ai.at)}</span></div>
    <p>{ai.explanation}</p><p><strong>AI suggested fix:</strong> {ai.remediation}</p>
    {ai.evidence&&<p><strong>Evidence:</strong> {ai.evidence}</p>}
   </> : <p className="muted">{aiMessage}</p>}
   {ai?.run_id&&<small className="mono muted">Run {ai.run_id.slice(0,12)} · {ai.run_status}</small>}
  </section>  <section className="finding-detail-section"><div className="finding-section-heading"><div><h3>Scan history</h3><p>Recent completed scans on this branch.</p></div></div><div className="finding-timeline">{detail.history?.map(h=><div key={h.scan_id}><span className={`timeline-dot ${h.detected?'detected':'resolved'}`}/><b>{h.detected?'Detected':'Resolved'}</b><span className="mono">{h.commit_sha.slice(0,12)}</span><time>{fmtDate(h.created_at)}</time></div>)}</div></section>
  {canTriage&&<section className="finding-detail-section triage-panel"><div className="finding-section-heading"><div><h3>Triage this finding</h3><p>Changes are audited and update the affected gate.</p></div><button className="secondary" onClick={onRecast}>Recast severity</button></div><div className="triage-fields"><label>Disposition<select value={disposition} onChange={e=>setDisposition(e.target.value)}><option value="">Choose an action</option><option value="false_positive">Mark false positive</option><option value="accepted_risk">Accept risk</option><option value="closed">Close manually</option><option value="open">Reopen</option></select></label><label>Reason <small>10–500 characters</small><textarea value={reason} onChange={e=>setReason(e.target.value)} maxLength={500} rows={3} placeholder="Explain the evidence and decision for the audit trail"/></label></div><div className="triage-footer"><span>{reason.trim().length}/500 characters</span><button className="primary" disabled={!disposition||reason.trim().length<10} onClick={onSave}>Save triage</button></div></section>}
 </div>
}
