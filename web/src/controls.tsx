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
export function McpSetup(){return <><p className="eyebrow">READ-ONLY INTEGRATION</p><h2>Connect Codex with MCP</h2><p className="muted">This connects an interactive Codex session to PANBOX scan data. It does not start automatic server-side AI review.</p><ol><li>Install the PANBOX agent binary on the same workstation or trusted host where Codex runs.</li><li>In this dashboard, create an <b>Access key</b> with <code>repos:read</code>, <code>scans:read</code>, and <code>findings:read</code>. Copy its one-time secret into the Codex host's secret environment.</li><li>On that Codex host, run <code>codex login</code> and select ChatGPT sign-in. Verify with <code>codex login status</code>. There is no Codex login button in PANBOX.</li><li>Configure the local stdio MCP server with the executable path, runner-reachable <code>PANBOX_SERVER</code>, and <code>PANBOX_TOKEN</code>.</li><li>Restart Codex, check the MCP server is listed, and ask it to list PANBOX repositories. If access fails, test network reachability and the key's scopes.</li></ol><pre className="secret-box"><code>{mcpExample}</code></pre><p className="muted small">Available tools: repositories, findings, scans, and scan detail. RBAC and repository membership still apply. For automatic reviews on new scans, use <b>Server-side AI review</b> and run <code>panbox-ai-worker</code> on the PANBOX host with a separate ChatGPT login.</p><p><a href="https://boxsploit.com/products/panbox/#mcp-codex" target="_blank" rel="noopener noreferrer">Full Codex MCP setup guide ↗</a></p></>}
