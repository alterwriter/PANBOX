import {useEffect, useState} from 'react';

type Config={repository_id:string;enabled:boolean;vaccin:boolean;enetron:boolean;gate_severity:string;version:number};
type Finding={ID:string;RuleID:string;Repository:string;Raw:string;Effective:string;Path:string};

export function ScanConfigForm({repo,load,save}:{repo:{id:string;name:string};load:()=>Promise<Config>;save:(v:Config)=>Promise<void>}){
 const [cfg,setCfg]=useState<Config|null>(null),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 useEffect(()=>{load().then(setCfg).catch(e=>setError(e.message))},[repo.id]);
 if(!cfg)return <div><p className="eyebrow">SCAN CONTROL</p><h2>{repo.name}</h2><p className="muted">{error||'Loading configuration...'}</p></div>;
 return <form onSubmit={async e=>{e.preventDefault();setBusy(true);setError('');try{await save(cfg)}catch(e){setError((e as Error).message)}finally{setBusy(false)}}}>
  <p className="eyebrow">SCAN CONTROL · {repo.name}</p><h2>Repository scan policy</h2>
  <p className="muted">The agent fetches this policy before its next online CI scan. The dashboard does not start a provider pipeline.</p>
  <label className="check-label"><input type="checkbox" checked={cfg.enabled} onChange={e=>setCfg({...cfg,enabled:e.target.checked})}/> Allow new scans</label>
  <div className="scope-grid"><label className="check-label"><input type="checkbox" checked={cfg.vaccin} onChange={e=>setCfg({...cfg,vaccin:e.target.checked})}/> VACCIN · source rules</label><label className="check-label"><input type="checkbox" checked={cfg.enetron} onChange={e=>setCfg({...cfg,enetron:e.target.checked})}/> ENETRON · dependencies</label></div>
  <label>Fail gate at or above<select value={cfg.gate_severity} onChange={e=>setCfg({...cfg,gate_severity:e.target.value})}>{['critical','high','medium','low','info'].map(v=><option value={v} key={v}>{v}</option>)}</select></label>
  <p className="muted small">Policy v{cfg.version}. Changes apply to new uploads. Recasting a finding recalculates affected historic gate revisions.</p>
  {error&&<p className="form-error">{error}</p>}<button className="primary wide" disabled={busy||(!cfg.vaccin&&!cfg.enetron)}>Save scan policy</button>
 </form>
}

export function RecastForm({finding,save}:{finding:Finding;save:(severity:string,reason:string)=>Promise<void>}){
 const [severity,setSeverity]=useState(finding.Effective),[reason,setReason]=useState(''),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 return <form onSubmit={async e=>{e.preventDefault();setBusy(true);setError('');try{await save(severity,reason)}catch(e){setError((e as Error).message)}finally{setBusy(false)}}}>
  <p className="eyebrow">FINDING TRIAGE</p><h2>Recast {finding.RuleID}</h2><p className="muted">{finding.Repository} · {finding.Path} · scanner severity {finding.Raw}</p>
  <label>Effective severity<select value={severity} onChange={e=>setSeverity(e.target.value)}><option value="raw">Restore scanner severity ({finding.Raw})</option>{['critical','high','medium','low','info'].map(v=><option value={v} key={v}>{v}</option>)}</select></label>
  <label>Reason (audited)<textarea required minLength={10} maxLength={500} value={reason} onChange={e=>setReason(e.target.value)} placeholder="Explain the evidence and why this severity should change"/></label>
  <p className="muted small">Raw severity remains unchanged. Effective severity and affected gate revisions update across this finding's scans.</p>
  {error&&<p className="form-error">{error}</p>}<button className="primary wide" disabled={busy||reason.trim().length<10}>Save recast</button>
 </form>
}

const mcpExample=['{','  "mcpServers": {','    "panbox": {','      "command": "/path/to/panbox",','      "args": ["mcp"],','      "env": {','        "PANBOX_SERVER": "https://your-panbox-server",','        "PANBOX_TOKEN": "<read-only-access-key>"','      }','    }','  }','}'].join('\n');
export function McpSetup(){return <><p className="eyebrow">READ-ONLY INTEGRATION</p><h2>MCP setup</h2><p className="muted">Generate an Access key with repos:read, scans:read and findings:read. Set it in your MCP host's secret environment, then launch the PANBOX agent as a local stdio server.</p><pre className="secret-box"><code>{mcpExample}</code></pre><p className="muted small">Available tools: repositories, findings, scans, and scan detail. The bridge uses the same RBAC and repository access checks as the API.</p></>}
