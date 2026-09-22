import './style.css';

type User = { id:string; name:string; email?:string; createdAt:number };

const app = document.querySelector<HTMLDivElement>('#app')!;
let user: User | null = null;

async function api(path:string, init:RequestInit={}) {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has('content-type')) headers.set('content-type','application/json');
  const response = await fetch(path, {...init, headers, credentials:'same-origin'});
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error ?? 'Request failed');
  return data;
}

function escapeHtml(s:string) {
  return s.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'","&#39;");
}

function shell(title:string, body:string) {
  app.innerHTML = '<main><header><strong>farcmd</strong>' +
    (user ? '<nav><a href="#" data-page="dashboard">Dashboard</a><a href="#" data-page="ssh">SSH</a><a href="#" data-page="commands">Commands</a><a href="#" data-page="oauth">OAuth Sources</a><a href="#" data-page="settings">Settings</a><button id="logout">Log out</button></nav>' : '') +
    '</header><section><h1>'+title+'</h1>'+body+'</section></main>';
  document.querySelectorAll<HTMLElement>('[data-page]').forEach(a => a.onclick = e => { e.preventDefault(); render(a.dataset.page!); });
  document.querySelector('#logout')?.addEventListener('click', async () => { await api('/api/auth/logout',{method:'POST'}); user=null; render('login'); });
}

function render(page='dashboard') {
  if (!user) {
    shell('Sign in', '<form id="login"><label>Email<input name="email" type="email" required autocomplete="username"></label><label>Password<input name="password" type="password" required autocomplete="current-password"></label><button>Sign in</button></form><p id="error"></p><p><a href="#" id="register">Create an account</a></p>');
    document.querySelector<HTMLFormElement>('#login')!.onsubmit = async e => {
      e.preventDefault();
      try { const f=new FormData(e.currentTarget); const r=await api('/api/auth/login',{method:'POST',body:JSON.stringify({email:f.get('email'),password:f.get('password')})}); user=r.user; const params=new URLSearchParams(location.search); if(params.get('page')==='confirm'&&params.get('token')){(window as any).__confirmToken=params.get('token');render('confirm');} else if(params.get('page')==='unlock'&&params.get('key')){(window as any).__unlockKeyId=params.get('key');render('unlock');} else render(); }
      catch (err) { document.querySelector('#error')!.textContent=(err as Error).message; }
    };
    document.querySelector('#register')!.addEventListener('click', e => { e.preventDefault(); register(); });
    return;
  }
  if (page==='settings') settings();
  else if (page==='oauth') oauthPage();
  else if (page==='ssh') sshPage();
  else if (page==='commands') commandsPage();
  else if (page==='unlock') unlockPage((window as any).__unlockKeyId); else if (page==='confirm') confirmPage((window as any).__confirmToken);
  else dashboard();
}

function register() {
  shell('Create account', '<form id="register-form"><label>Name<input name="name" required autocomplete="name"></label><label>Email<input name="email" type="email" required autocomplete="email"></label><label>Password<input name="password" type="password" minlength="12" required autocomplete="new-password"></label><button>Create account</button></form><p id="error"></p><p><a href="#" id="back">Back to sign in</a></p>');
  document.querySelector<HTMLFormElement>('#register-form')!.onsubmit = async e => {
    e.preventDefault();
    try { const f=new FormData(e.currentTarget); const r=await api('/api/auth/register',{method:'POST',body:JSON.stringify({name:f.get('name'),email:f.get('email'),password:f.get('password')})}); user=r.user; render(); }
    catch (err) { document.querySelector('#error')!.textContent=(err as Error).message; }
  };
  document.querySelector('#back')!.addEventListener('click', e => { e.preventDefault(); render('login'); });
}

function dashboard() {
  shell('Dashboard', '<p>Signed in as <strong>'+escapeHtml(user!.email ?? '')+'</strong>.</p><div class="cards"><article><h2>SSH Targets</h2><p>Configure later in Phase 3.</p></article><article><h2>Commands</h2><p>Configure later in Phase 4.</p></article><article><h2>OAuth Sources</h2><p>Authorization is available through MCP clients.</p></article><article><h2>History</h2><p>Execution and shell history arrive in Phase 7.</p></article></div>');
}

async function sshPage() {
  const [keysResult, targetsResult] = await Promise.all([api('/api/ssh/keys'),api('/api/ssh/targets')]);
  const keys=keysResult.keys as any[]; const targets=targetsResult.targets as any[];
  shell('SSH configuration','<div class="ssh-columns"><article><h2>SSH keys</h2><form id="key-form"><label>Name<input name="name" required></label><label>Private key<textarea name="privateKey" rows="10" required autocomplete="off"></textarea></label><button>Add key</button></form><p id="key-error"></p><div id="keys">'+keys.map(k=>'<div class="item"><strong>'+escapeHtml(k.name)+'</strong><small>'+escapeHtml(k.fingerprint??'fingerprint pending')+'</small><span>'+(k.locked?'Locked':'Unlocked')+'</span><button data-unlock="'+k.id+'">Unlock</button><button data-lock="'+k.id+'">Lock</button><button data-delete-key="'+k.id+'">Delete</button></div>').join('')+'</div></article><article><h2>SSH targets</h2><form id="target-form"><label>Name<input name="name" required></label><label>Hostname<input name="hostname" required></label><label>Port<input name="port" type="number" min="1" max="65535" value="22" required></label><label>Username<input name="username" required></label><label>SSH key<select name="sshKeyId" required>'+keys.map(k=>'<option value="'+k.id+'">'+escapeHtml(k.name)+'</option>').join('')+'</select></label><button>Add target</button></form><p id="target-error"></p><div id="targets">'+targets.map(t=>'<div class="item"><strong>'+escapeHtml(t.name)+'</strong><small>'+escapeHtml(t.username+'@'+t.hostname+':'+t.port)+'</small><small>'+escapeHtml(t.hostFingerprint??'host fingerprint not verified')+'</small><button data-test="'+t.id+'">Test</button><button data-delete-target="'+t.id+'">Delete</button></div>').join('')+'</div></article></div>');
  document.querySelector<HTMLFormElement>('#key-form')!.onsubmit=async e=>{e.preventDefault();try{const f=new FormData(e.currentTarget);await api('/api/ssh/keys',{method:'POST',body:JSON.stringify({name:f.get('name'),privateKey:f.get('privateKey')})});sshPage();}catch(err){document.querySelector('#key-error')!.textContent=(err as Error).message;}};
  document.querySelector<HTMLFormElement>('#target-form')!.onsubmit=async e=>{e.preventDefault();try{const f=new FormData(e.currentTarget);await api('/api/ssh/targets',{method:'POST',body:JSON.stringify({name:f.get('name'),hostname:f.get('hostname'),port:Number(f.get('port')),username:f.get('username'),sshKeyId:f.get('sshKeyId')})});sshPage();}catch(err){document.querySelector('#target-error')!.textContent=(err as Error).message;}};
  document.querySelectorAll<HTMLElement>('[data-unlock]').forEach(b=>b.onclick=()=>{(window as any).__unlockKeyId=b.dataset.unlock;render('unlock');});
  document.querySelectorAll<HTMLElement>('[data-lock]').forEach(b=>b.onclick=async()=>{await api('/api/ssh/keys/'+b.dataset.lock+'/lock',{method:'POST'});sshPage();});
  document.querySelectorAll<HTMLElement>('[data-edit-key]').forEach(b=>b.onclick=async()=>{const k=keys.find(x=>x.id===b.dataset.editKey);if(!k)return;const name=prompt('Key name',k.name);if(name===null)return;await api('/api/ssh/keys/'+k.id,{method:'PATCH',body:JSON.stringify({name})});sshPage();});
  document.querySelectorAll<HTMLElement>('[data-edit-target]').forEach(b=>b.onclick=async()=>{const t=targets.find(x=>x.id===b.dataset.editTarget);if(!t)return;const name=prompt('Target name',t.name);if(name===null)return;const hostname=prompt('Hostname',t.hostname);if(hostname===null)return;const port=prompt('Port',String(t.port));if(port===null)return;const username=prompt('Username',t.username);if(username===null)return;await api('/api/ssh/targets/'+t.id,{method:'PATCH',body:JSON.stringify({name,hostname,port:Number(port),username})});sshPage();});
  document.querySelectorAll<HTMLElement>('[data-delete-key]').forEach(b=>b.onclick=async()=>{if(confirm('Delete this SSH key?')){await api('/api/ssh/keys/'+b.dataset.deleteKey,{method:'DELETE'});sshPage();}});
  document.querySelectorAll<HTMLElement>('[data-test]').forEach(b=>b.onclick=async()=>{const el=b as HTMLButtonElement;el.disabled=true;try{const result=await api('/api/ssh/targets/'+b.dataset.test+'/test',{method:'POST'});if(result.ok){alert('Connection successful. Host fingerprint: '+(result.fingerprint??'unknown'));}else if(result.fingerprint&&confirm((result.error??'Host key is not yet trusted.')+'\\n\\nFingerprint: '+result.fingerprint+'\\n\\nTrust this fingerprint for this target?')){await api('/api/ssh/targets/'+b.dataset.test,{method:'PATCH',body:JSON.stringify({hostFingerprint:result.fingerprint})});alert('Fingerprint saved. Run Test again to verify the connection.');}else{alert(result.error??'Connection failed');}}catch(err){alert((err as Error).message);}finally{el.disabled=false;}});
}
function unlockPage(keyId:string) {
  shell('Unlock SSH key','<p>The passphrase is used only in memory and is not stored in the database.</p><form id="unlock-form"><label>Passphrase<input name="passphrase" type="password" autocomplete="current-password" required></label><button>Unlock for 15 minutes</button></form><p id="unlock-error"></p>');
  document.querySelector<HTMLFormElement>('#unlock-form')!.onsubmit=async e=>{e.preventDefault();try{const f=new FormData(e.currentTarget);await api('/api/ssh/keys/'+keyId+'/unlock',{method:'POST',body:JSON.stringify({passphrase:f.get('passphrase')})});delete (window as any).__unlockKeyId;render('ssh');}catch(err){document.querySelector('#unlock-error')!.textContent=(err as Error).message;}};
}
async function commandsPage(){const [cr,tr]=await Promise.all([api('/api/commands'),api('/api/ssh/targets')]);const cs=cr.commands as any[],ts=tr.targets as any[];shell('Commands','<div class="ssh-columns"><article><h2>Command registry</h2><form id="command-form"><label>Name<input name="name" required></label><label>Description<textarea name="description" rows="3" required></textarea></label><label>Exact SSH command<textarea name="shellCommand" rows="4" required></textarea></label><label>Target<select name="targetId" required>'+ts.map(t=>'<option value="'+t.id+'">'+escapeHtml(t.name)+'</option>').join('')+'</select></label><label>Level<select name="level"><option value="1">1 — Safe/read-only</option><option value="2">2 — Low-impact</option><option value="3">3 — Normal mutating</option><option value="4">4 — High-impact</option><option value="5">5 — Dangerous/destructive</option></select></label><button>Create command</button></form><p id="command-error"></p></article><article><h2>Registered commands</h2>'+cs.map(c=>'<div class="item"><strong>'+escapeHtml(c.name)+'</strong><small>'+escapeHtml(c.description)+'</small><small>Level '+c.level+' · '+escapeHtml(ts.find(t=>t.id===c.targetId)?.name??'unknown target')+' · '+(c.enabled?'Enabled':'Disabled')+'</small><details><summary>Exact command</summary><pre>'+escapeHtml(c.shellCommand)+'</pre></details><button data-toggle-command="'+c.id+'">'+(c.enabled?'Disable':'Enable')+'</button><button data-delete-command="'+c.id+'">Delete</button></div>').join('')+'</article></div>');document.querySelector<HTMLFormElement>('#command-form')!.onsubmit=async e=>{e.preventDefault();try{const f=new FormData(e.currentTarget);await api('/api/commands',{method:'POST',body:JSON.stringify({name:f.get('name'),description:f.get('description'),shellCommand:f.get('shellCommand'),targetId:f.get('targetId'),level:Number(f.get('level'))})});commandsPage();}catch(err){document.querySelector('#command-error')!.textContent=(err as Error).message;}};document.querySelectorAll<HTMLElement>('[data-toggle-command]').forEach(b=>b.onclick=async()=>{const c=cs.find(x=>x.id===b.dataset.toggleCommand);if(c)await api('/api/commands/'+c.id,{method:'PATCH',body:JSON.stringify({enabled:!c.enabled})});commandsPage();});document.querySelectorAll<HTMLElement>('[data-delete-command]').forEach(b=>b.onclick=async()=>{if(confirm('Delete this command?')){await api('/api/commands/'+b.dataset.deleteCommand,{method:'DELETE'});commandsPage();}});}
async function oauthPage(){const r=await api('/api/oauth/grants');const grants=r.grants as any[];shell('OAuth Sources','<p>Each OAuth source controls which command levels are shown to the MCP client. Tool allow/ask/deny remains the MCP client's decision; levels 4 and 5 add farcmd human confirmation.</p>'+grants.map(g=>'<article class="item"><strong>'+escapeHtml(g.clientName||g.clientId)+'</strong><small>'+escapeHtml(g.clientId)+'</small><small>'+ (g.revoked?'Revoked':'Active') + (g.lastUsedAt?' · Last used '+new Date(g.lastUsedAt).toLocaleString():'') +'</small>'+(g.revoked?'':'<form data-oauth-form="'+escapeHtml(g.clientId)+'"><label><input type="checkbox" name="level" value="1" '+(g.visibleLevels.includes(1)?'checked':'')+'> Level 1 — Safe/read-only</label><label><input type="checkbox" name="level" value="2" '+(g.visibleLevels.includes(2)?'checked':'')+'> Level 2 — Low-impact</label><label><input type="checkbox" name="level" value="3" '+(g.visibleLevels.includes(3)?'checked':'')+'> Level 3 — Normal mutating</label><label><input type="checkbox" name="level" value="4" '+(g.visibleLevels.includes(4)?'checked':'')+'> Level 4 — High-impact</label><label><input type="checkbox" name="level" value="5" '+(g.visibleLevels.includes(5)?'checked':'')+(g.level5PermanentlyHidden?' disabled':'')+'> Level 5 — Dangerous/destructive</label><label><input type="checkbox" name="permanentLevel5" '+(g.level5PermanentlyHidden?'checked disabled':'')+'> Permanently hide level 5</label><button>Save permissions</button></form><button data-revoke-oauth="'+escapeHtml(g.clientId)+'">Revoke</button>')+'</article>').join(''));document.querySelectorAll<HTMLFormElement>('[data-oauth-form]').forEach(f=>f.onsubmit=async e=>{e.preventDefault();const levels=[...f.querySelectorAll<HTMLInputElement>('input[name="level"]:checked')].map(x=>Number(x.value));try{await api('/api/oauth/grants/'+encodeURIComponent(f.dataset.oauthForm!),{method:'PATCH',body:JSON.stringify({visibleLevels:levels,level5PermanentlyHidden:(f.querySelector<HTMLInputElement>('input[name="permanentLevel5"]')?.checked??false)})});oauthPage();}catch(err){alert((err as Error).message);}});document.querySelectorAll<HTMLElement>('[data-revoke-oauth]').forEach(b=>b.onclick=async()=>{if(confirm('Revoke this OAuth source?')){await api('/api/oauth/grants/'+encodeURIComponent(b.dataset.revokeOauth!)+'/revoke',{method:'POST'});oauthPage();}});}
async function confirmPage(token:string) { const info=await api('/api/confirm/'+encodeURIComponent(token)); const needsPassword=info.command.confirmation==='password'; shell('Confirm execution','<article><h2>'+escapeHtml(info.command.name)+'</h2><p>'+escapeHtml(info.command.description)+'</p><p>Level '+info.command.level+' · '+escapeHtml(info.clientName)+'</p>'+(needsPassword?'<form id="confirm-form"><label>Execution password<input name="password" type="password" autocomplete="current-password" required></label><button>Execute command</button></form>':'<button id="confirm-button">Approve & execute</button>')+'<p id="confirm-error"></p></article>'); const submit=async(password?:string)=>{try{const result=await api('/api/confirm/'+encodeURIComponent(token),{method:'POST',body:JSON.stringify(password===undefined?{}:{password})}); alert('Command executed. Exit code: '+result.exitCode); render();}catch(err){document.querySelector('#confirm-error')!.textContent=(err as Error).message;}}; if(needsPassword)document.querySelector<HTMLFormElement>('#confirm-form')!.onsubmit=async e=>{e.preventDefault();const f=new FormData(e.currentTarget);await submit(String(f.get('password')??''));}; else document.querySelector('#confirm-button')!.addEventListener('click',()=>submit()); }
function settings() {
  shell('Account settings', '<form id="settings-form"><label>Name<input name="name" required value="'+escapeHtml(user!.name)+'"></label><label>Email<input name="email" type="email" required value="'+escapeHtml(user!.email ?? '')+'"></label><button>Save</button></form><hr><h2>Execution password</h2><p>Level 5 commands require this password. It is separate from your SSH key passphrase.</p><form id="execution-password-form"><label>New execution password<input name="password" type="password" minlength="12" required autocomplete="new-password"></label><button>Set execution password</button></form><p id="message"></p>');
  document.querySelector<HTMLFormElement>('#execution-password-form')!.onsubmit=async e=>{e.preventDefault();try{const f=new FormData(e.currentTarget);await api('/api/account/execution-password',{method:'POST',body:JSON.stringify({password:f.get('password')})});document.querySelector('#message')!.textContent='Execution password saved.';}catch(err){document.querySelector('#message')!.textContent=(err as Error).message;}};
  document.querySelector<HTMLFormElement>('#settings-form')!.onsubmit = async e => {
    e.preventDefault();
    try { const f=new FormData(e.currentTarget); const r=await api('/api/account',{method:'PATCH',body:JSON.stringify({name:f.get('name'),email:f.get('email')})}); user=r.user; document.querySelector('#message')!.textContent='Saved.'; }
    catch (err) { document.querySelector('#message')!.textContent=(err as Error).message; }
  };
}

async function boot() {
  const params=new URLSearchParams(location.search); const page=params.get('page'); const token=params.get('token'); if(page==='confirm'&&token)(window as any).__confirmToken=token; if(page==='unlock'&&params.get('key'))(window as any).__unlockKeyId=params.get('key');
  try { const r=await api('/api/auth/session'); user=r.user; render(page==='confirm'?'confirm':page==='unlock'?'unlock':'dashboard'); }
  catch { user=null; render('login'); }
}
boot();
