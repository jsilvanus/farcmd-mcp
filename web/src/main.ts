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
    (user ? '<nav><a href="#" data-page="dashboard">Dashboard</a><a href="#" data-page="settings">Settings</a><button id="logout">Log out</button></nav>' : '') +
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
