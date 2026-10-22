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

const mcpExample=['[mcp_servers.panbox]','command = "/absolute/path/to/panbox"','args = ["mcp"]','[mcp_servers.panbox.env]','PANBOX_SERVER = "https://your-panbox-server"','PANBOX_TOKEN = "<read-only-access-key>"'].join('\n');
export function McpSetup(){return <><p className="eyebrow">READ-ONLY INTEGRATION</p><h2>Connect Codex with PANBOX MCP</h2><p className="muted">Interactive MCP lets your Codex session read PANBOX scan data. Server-side AI review is a separate worker setup.</p><ol><li>Install the PANBOX agent binary on the machine running Codex, and make <code>panbox</code> available on its PATH.</li><li>Create an <b>Access key</b> here with <code>repos:read</code>, <code>scans:read</code>, and <code>findings:read</code>. Give its owner access to the intended repositories. Store the one-time key as <code>PANBOX_TOKEN</code> on the Codex machine; set <code>PANBOX_SERVER</code> to a URL that machine can reach.</li><li>Sign in to Codex on that machine with <code>codex login</code> and check <code>codex login status</code>. PANBOX does not receive your ChatGPT credentials.</li></ol><details><summary>Install the PANBOX Codex plugin</summary><p>Run <code>codex plugin marketplace add alterwriter/PANBOX --ref v0.1.0-alpha.12</code>. Start <code>codex</code>, enter <code>/plugins</code>, choose the PANBOX Local marketplace, inspect PANBOX, and select Install. Start a new Codex session and enter <code>/mcp</code> to verify the four read-only tools. The plugin starts <code>panbox mcp</code> locally and needs the environment variables above.</p></details><details><summary>Use ChatGPT desktop without the plugin</summary><p>In ChatGPT desktop, open <b>Settings → MCP servers → Add server</b>. Select STDIO, name it PANBOX, set the command to the absolute <code>panbox</code> binary path, arguments to <code>mcp</code>, and provide <code>PANBOX_SERVER</code> and <code>PANBOX_TOKEN</code> as protected environment values. Save and restart, then use <code>/mcp</code>. ChatGPT web does not read your local Codex configuration.</p></details><details><summary>Configure Codex manually</summary><p>Place this in the Codex user's <code>~/.codex/config.toml</code> with owner-only permissions, replacing placeholders. Restart Codex, then run <code>codex mcp list</code>.</p><pre className="secret-box"><code>{mcpExample}</code></pre></details><p className="muted small">Available tools: repositories, findings, scans, and scan detail. RBAC and repository membership still apply. Installing the plugin does not start automatic finding review.</p><p><a href="https://boxsploit.com/products/panbox/#mcp-codex" target="_blank" rel="noopener noreferrer">Full MCP walkthrough ↗</a></p></>}
