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
    (user ? '<nav><a href="#" data-page="dashboard">Dashboard</a><a href="#" data-page="ssh">SSH</a><a href="#" data-page="settings">Settings</a><button id="logout">Log out</button></nav>' : '') +
    '</header><section><h1>'+title+'</h1>'+body+'</section></main>';
  document.querySelectorAll<HTMLElement>('[data-page]').forEach(a => a.onclick = e => { e.preventDefault(); render(a.dataset.page!); });
  document.querySelector('#logout')?.addEventListener('click', async () => { await api('/api/auth/logout',{method:'POST'}); user=null; render('login'); });
}

function render(page='dashboard') {
  if (!user) {
    shell('Sign in', '<form id="login"><label>Email<input name="email" type="email" required autocomplete="username"></label><label>Password<input name="password" type="password" required autocomplete="current-password"></label><button>Sign in</button></form><p id="error"></p><p><a href="#" id="register">Create an account</a></p>');
    document.querySelector<HTMLFormElement>('#login')!.onsubmit = async e => {
      e.preventDefault();
      try { const f=new FormData(e.currentTarget); const r=await api('/api/auth/login',{method:'POST',body:JSON.stringify({email:f.get('email'),password:f.get('password')})}); user=r.user; render(); }
      catch (err) { document.querySelector('#error')!.textContent=(err as Error).message; }
    };
    document.querySelector('#register')!.addEventListener('click', e => { e.preventDefault(); register(); });
    return;
  }
  if (page==='settings') settings();
  else if (page==='ssh') sshPage();
  else if (page==='unlock') unlockPage((window as any).__unlockKeyId);
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
  document.querySelectorAll<HTMLElement>('[data-delete-key]').forEach(b=>b.onclick=async()=>{if(confirm('Delete this SSH key?')){await api('/api/ssh/keys/'+b.dataset.deleteKey,{method:'DELETE'});sshPage();}});
  document.querySelectorAll<HTMLElement>('[data-test]').forEach(b=>b.onclick=async()=>{const el=b as HTMLButtonElement;el.disabled=true;try{const result=await api('/api/ssh/targets/'+b.dataset.test+'/test',{method:'POST'});alert(result.ok?'Connection successful. Host fingerprint: '+(result.fingerprint??'unknown'):(result.error??'Connection failed'));}catch(err){alert((err as Error).message);}finally{el.disabled=false;}});
}
function unlockPage(keyId:string) {
  shell('Unlock SSH key','<p>The passphrase is used only in memory and is not stored in the database.</p><form id="unlock-form"><label>Passphrase<input name="passphrase" type="password" autocomplete="current-password" required></label><button>Unlock for 15 minutes</button></form><p id="unlock-error"></p>');
  document.querySelector<HTMLFormElement>('#unlock-form')!.onsubmit=async e=>{e.preventDefault();try{const f=new FormData(e.currentTarget);await api('/api/ssh/keys/'+keyId+'/unlock',{method:'POST',body:JSON.stringify({passphrase:f.get('passphrase')})});delete (window as any).__unlockKeyId;render('ssh');}catch(err){document.querySelector('#unlock-error')!.textContent=(err as Error).message;}};
}
function settings() {
  shell('Account settings', '<form id="settings-form"><label>Name<input name="name" required value="'+escapeHtml(user!.name)+'"></label><label>Email<input name="email" type="email" required value="'+escapeHtml(user!.email ?? '')+'"></label><button>Save</button></form><p id="message"></p>');
  document.querySelector<HTMLFormElement>('#settings-form')!.onsubmit = async e => {
    e.preventDefault();
    try { const f=new FormData(e.currentTarget); const r=await api('/api/account',{method:'PATCH',body:JSON.stringify({name:f.get('name'),email:f.get('email')})}); user=r.user; document.querySelector('#message')!.textContent='Saved.'; }
    catch (err) { document.querySelector('#message')!.textContent=(err as Error).message; }
  };
}

async function boot() {
  try { const r=await api('/api/auth/session'); user=r.user; render(); }
  catch { user=null; render('login'); }
}
boot();
