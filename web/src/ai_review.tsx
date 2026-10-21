import React, {useEffect, useState} from 'react';

type Settings={enabled:boolean;provider:'openai'|'anthropic';model:string;max_findings:number};
type Run={id:string;scan_id:string;repository_id:string;provider:string;model:string;status:string;error_code:string;created_at:string};
type Detail=Run & {events:{stage:string;message:string;created_at:string}[];assessments:{finding_id:string;rule_id:string;path:string;verdict:string;confidence:string;explanation:string;remediation:string;evidence:string}[]};
type API=<T,>(path:string,options?:RequestInit)=>Promise<T>;

export function AIReviewConsole({api}:{api:API}){
 const [cfg,setCfg]=useState<Settings>({enabled:false,provider:'openai',model:'',max_findings:3});
 const [keys,setKeys]=useState({openai:false,anthropic:false});
 const [runs,setRuns]=useState<Run[]>([]);
 const [selected,setSelected]=useState('');
 const [detail,setDetail]=useState<Detail|null>(null);
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState('');
 const [notice,setNotice]=useState('');
 async function refresh(){try{const [settings,items]=await Promise.all([api<{settings:Settings;openai_key_configured:boolean;anthropic_key_configured:boolean}>('/v1/ai-review/settings'),api<Run[]>('/v1/ai-review/runs')]);setCfg(settings.settings);setKeys({openai:settings.openai_key_configured,anthropic:settings.anthropic_key_configured});setRuns(items);if(selected)setDetail(await api<Detail>('/v1/ai-review/runs/'+selected));setError('')}catch(e){setError((e as Error).message)}}
 useEffect(()=>{refresh()},[]);
 useEffect(()=>{const timer=setInterval(()=>{api<Run[]>('/v1/ai-review/runs').then(setRuns).catch(()=>{});if(selected)api<Detail>('/v1/ai-review/runs/'+selected).then(setDetail).catch(()=>{})},4000);return ()=>clearInterval(timer)},[selected]);
 async function save(e:React.FormEvent){e.preventDefault();setBusy(true);try{await api('/v1/ai-review/settings',{method:'PUT',body:JSON.stringify(cfg)});setNotice('Settings saved. Future uploads will use this configuration.');setError('');await refresh()}catch(e){setError((e as Error).message)}finally{setBusy(false)}}
 async function openRun(id:string){setSelected(id);try{setDetail(await api<Detail>('/v1/ai-review/runs/'+id))}catch(e){setError((e as Error).message)}}
 return <><p className="eyebrow">SERVER-SIDE AI REVIEW · BETA</p><h2>AI review & process log</h2><p className="muted">CI uploads the native scan and exits. The PANBOX server fetches bounded source snippets at the exact commit through your connected SCM account, then asks the selected provider to review eligible VACCIN findings. Suggestions never change raw findings or gates.</p>
 <form onSubmit={save} className="scm-form"><label><input type="checkbox" checked={cfg.enabled} onChange={e=>setCfg({...cfg,enabled:e.target.checked})}/> Enable review for future scans</label><label>Provider<select value={cfg.provider} onChange={e=>setCfg({...cfg,provider:e.target.value as Settings['provider']})}><option value="openai">OpenAI coding model</option><option value="anthropic">Claude model</option></select></label><label>Model ID<input required={cfg.enabled} value={cfg.model} onChange={e=>setCfg({...cfg,model:e.target.value})} placeholder={cfg.provider==='openai'?'Configured OpenAI model ID':'Configured Claude model ID'}/></label><label>Maximum findings per scan<input type="number" min="1" max="10" value={cfg.max_findings} onChange={e=>setCfg({...cfg,max_findings:Number(e.target.value)})}/></label><p className="muted small">Provider API key on server: {cfg.provider==='openai'?(keys.openai?'configured':'missing PANBOX_OPENAI_API_KEY'):(keys.anthropic?'configured':'missing PANBOX_ANTHROPIC_API_KEY')}. GitHub App needs Contents: read; GitLab read_api already permits repository file reads. Private source snippets leave your server for the selected AI provider when enabled.</p><button className="primary" disabled={busy}>{busy?'Saving…':'Save AI review settings'}</button></form>
 {notice&&<p className="muted">{notice}</p>}{error&&<p role="alert" className="error">{error}</p>}
 <h3>Recent server runs</h3><div className="ai-run-list">{runs.map(run=><button className="ai-run" key={run.id} onClick={()=>openRun(run.id)}><b>{run.status.toUpperCase()}</b><span>{run.provider} · {run.model}</span><small>Scan {run.scan_id.slice(0,12)} · {new Date(run.created_at).toLocaleString()}</small></button>)}{!runs.length&&<p className="muted">No AI runs yet. Enable review and upload a new scan, or rerun an existing scan from its detail panel.</p>}</div>
 {detail&&<section className="ai-run-detail"><h3>Run {detail.id.slice(0,12)} · {detail.status}</h3>{detail.error_code&&<p className="muted">Error code: {detail.error_code}</p>}<div className="ai-console" aria-label="AI server process events">{detail.events.map((event,i)=><div key={i}><time>{new Date(event.created_at).toLocaleTimeString()}</time><b>{event.stage}</b><span>{event.message}</span></div>)}</div><h3>AI suggestions ({detail.assessments.length})</h3>{detail.assessments.map(a=><article className="ai-assessment" key={a.finding_id}><b>{a.rule_id}</b><small>{a.path} · {a.verdict.replaceAll('_',' ')} · {a.confidence} confidence</small><p>{a.explanation}</p><p><strong>Suggested fix:</strong> {a.remediation}</p>{a.evidence&&<p><strong>Evidence:</strong> {a.evidence}</p>}</article>)}</section>}
 </>
}
