import './style.css';

type User = { id:string; name:string; email?:string; createdAt:number };

const app = document.querySelector<HTMLDivElement>('#app')!;
let user: User | null = null;

async function api(path:string, init:RequestInit={}) {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has('content-type')) headers.set('content-type','application/json');
  headers.set('x-farcmd-request','1'); // required by the server on state-changing calls (CSRF defence)
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
    (user ? '<nav><a href="#" data-page="commands">Commands</a><a href="#" data-page="ssh">SSH</a><a href="#" data-page="oauth">OAuth Sources</a><a href="#" data-page="history">History</a><a href="#" data-page="audit">Audit</a><a href="#" data-page="settings">Settings</a><span class="signed-in" title="Signed in">'+escapeHtml(user.email??'')+'</span><button id="logout">Log out</button></nav>' : '') +
    '</header><section><h1>'+title+'</h1>'+body+'</section></main>';
  document.querySelectorAll<HTMLElement>('[data-page]').forEach(a => a.onclick = e => { e.preventDefault(); render(a.dataset.page!); });
  document.querySelector('#logout')?.addEventListener('click', async () => { await api('/api/auth/logout',{method:'POST'}); user=null; render('login'); });
}

/** The page a ?page=confirm&token= or ?page=unlock&key= link asks for, else Commands. */
function landing():[string,string?] {
  const params=new URLSearchParams(location.search); const token=params.get('token'); const key=params.get('key');
  return params.get('page')==='confirm'&&token?['confirm',token]:params.get('page')==='unlock'&&key?['unlock',key]:['commands'];
}

function render(page='commands', arg?:string) {
  if (!user) {
    shell('Sign in', '<form id="login"><label>Email<input name="email" type="email" required autocomplete="username"></label><label>Password<input name="password" type="password" required autocomplete="current-password"></label><button>Sign in</button></form><p id="error"></p><p id="register-row" hidden><a href="#" id="register">Create an account</a></p><p id="register-closed" hidden><small>New accounts are created by the administrator.</small></p>');
    // Self-service registration is shown only when the operator enabled it (farcmd-admin registration enable).
    api('/api/auth/config').then(c=>{document.querySelector<HTMLElement>(c.registrationEnabled?'#register-row':'#register-closed')?.removeAttribute('hidden');}).catch(()=>undefined);
    document.querySelector<HTMLFormElement>('#login')!.onsubmit = async e => {
      e.preventDefault();
      try { const f=new FormData(e.currentTarget as HTMLFormElement); const r=await api('/api/auth/login',{method:'POST',body:JSON.stringify({email:f.get('email'),password:f.get('password')})}); user=r.user; render(...landing()); }
      catch (err) { document.querySelector('#error')!.textContent=(err as Error).message; }
    };
    document.querySelector('#register')!.addEventListener('click', e => { e.preventDefault(); register(); });
    return;
  }
  if (page==='settings') settings();
  else if (page==='oauth') oauthPage();
  else if (page==='history') historyPage();
  else if (page==='audit') auditPage();
  else if (page==='ssh') sshPage();
  else if (page==='commands') commandsPage();
  else if (page==='unlock') unlockPage(arg!); else if (page==='confirm') confirmPage(arg!);
  else commandsPage();
}

function register() {
  shell('Create account', '<form id="register-form"><label>Name<input name="name" required autocomplete="name"></label><label>Email<input name="email" type="email" required autocomplete="email"></label><label>Password<input name="password" type="password" minlength="12" required autocomplete="new-password"></label><button>Create account</button></form><p id="error"></p><p><a href="#" id="back">Back to sign in</a></p>');
  document.querySelector<HTMLFormElement>('#register-form')!.onsubmit = async e => {
    e.preventDefault();
    try { const f=new FormData(e.currentTarget as HTMLFormElement); const r=await api('/api/auth/register',{method:'POST',body:JSON.stringify({name:f.get('name'),email:f.get('email'),password:f.get('password')})}); user=r.user; render(); }
    catch (err) { document.querySelector('#error')!.textContent=(err as Error).message; }
  };
  document.querySelector('#back')!.addEventListener('click', e => { e.preventDefault(); render('login'); });
}

// User-scoped MCP kill switch. Turning it off refuses every MCP tool call from this account's clients
// (including pending level 4/5 confirmations); the farcmd server, the web UI and OAuth grants stay as they are.
async function mcpAccessPanel(){
  const el=document.querySelector<HTMLElement>('#mcp-access'); if(!el)return;
  let s:any; try{s=await api('/api/mcp-access');}catch(err){el.textContent=(err as Error).message;return;}
  const blocked=!s.globalEnabled?'MCP access is disabled on this server by the administrator.':s.adminBlocked?'MCP access is disabled for your account by the administrator.':'';
  el.className='mcp-bar '+(s.effective?'on':'off');
  el.innerHTML='<div><strong>MCP access '+(s.effective?'on':'off')+'</strong><span>'+(s.effective?'MCP clients you authorized can use farcmd.':blocked||'All MCP tool calls from your clients are refused. Nothing else is affected.')+(blocked&&!s.userEnabled?' Your own switch is also off.':'')+'</span></div>'+
    '<button id="mcp-toggle" class="small'+(s.userEnabled?'':' primary')+'" data-enabled="'+(s.userEnabled?'1':'0')+'">'+(s.userEnabled?'Turn off MCP access':'Turn on MCP access')+'</button>';
  el.querySelector<HTMLButtonElement>('#mcp-toggle')!.onclick=async e=>{const on=(e.currentTarget as HTMLElement).dataset.enabled==='1';
    if(on&&!confirm('Turn off MCP access? Your MCP clients stay connected but every farcmd tool call is refused until you turn it on again.'))return;
    try{await api('/api/mcp-access',{method:'PUT',body:JSON.stringify({enabled:!on})});}catch(err){alert((err as Error).message);} mcpAccessPanel();};
}

const LEVELS=['','Safe/read-only','Low-impact','Normal mutating','High-impact','Dangerous/destructive'];

/** Modal <dialog>. Closing it (Cancel, Esc) removes it from the page. */
function openDialog(title:string, body:string):HTMLDialogElement{
  document.querySelector('dialog.modal')?.remove();
  const d=document.createElement('dialog'); d.className='modal';
  d.innerHTML='<h2>'+escapeHtml(title)+'</h2>'+body;
  document.body.appendChild(d);
  d.addEventListener('close',()=>d.remove());
  d.querySelectorAll('[data-dialog-close]').forEach(b=>b.addEventListener('click',()=>d.close()));
  d.showModal();
  return d;
}
/** Dialog with a form. onSubmit throws to keep the dialog open and show the error inside it. */
function formDialog(title:string, fields:string, submitLabel:string, onSubmit:(form:HTMLFormElement)=>Promise<void>):HTMLDialogElement{
  const d=openDialog(title,'<form>'+fields+'<p class="dialog-error" role="alert"></p><div class="dialog-actions"><button type="button" data-dialog-close>Cancel</button><button type="submit" class="primary">'+escapeHtml(submitLabel)+'</button></div></form>');
  const form=d.querySelector('form')!;
  form.onsubmit=async e=>{
    e.preventDefault(); const submit=form.querySelector<HTMLButtonElement>('button[type=submit]')!; submit.disabled=true;
    try{await onSubmit(form); d.close();}
    catch(err){form.querySelector('.dialog-error')!.textContent=(err as Error).message; submit.disabled=false;}
  };
  form.querySelector<HTMLElement>('input:not([disabled]),textarea:not([disabled]),select:not([disabled])')?.focus();
  return d;
}
function pill(text:string, tone:'ok'|'warn'|'bad'|'muted'='muted'){return '<span class="pill '+tone+'">'+escapeHtml(text)+'</span>';}
function row(main:string, actions:string){return '<li class="row"><div class="row-main">'+main+'</div><div class="row-actions">'+actions+'</div></li>';}
function rows(items:string[], empty:string){return items.length?'<ul class="rows">'+items.join('')+'</ul>':'<p class="empty">'+escapeHtml(empty)+'</p>';}
function sectionHead(title:string, buttons:string){return '<div class="section-head"><h2>'+escapeHtml(title)+'</h2><div class="row-actions">'+buttons+'</div></div>';}
function on(selector:string, handler:(el:HTMLElement)=>void){document.querySelectorAll<HTMLElement>(selector).forEach(el=>el.onclick=()=>handler(el));}
function sshKeyOptions(keys:any[], selected?:string){return keys.map(k=>'<option value="'+escapeHtml(k.id)+'"'+(k.id===selected?' selected':'')+'>'+escapeHtml(k.name)+'</option>').join('');}

type CheckState='done'|'todo'|'info';
/** Setup steps from a first master key to a connected MCP client, computed from the current state. Collapsed once everything is done. */
/** Levels 3–5 always need the verifier; levels 1–2 only when the command opts in. */
const needsVerifier=(c:any)=>c.level>=3||!!c.verifyIntegrity;
function setupChecklist(keys:any[],targets:any[],commands:any[],grants:any[]):string{
  const names=(list:any[])=>list.map(t=>escapeHtml(t.name)).join(', ');
  const installed=commands.filter(c=>c.commandKey); const needVerifier=targets.filter(t=>commands.some(c=>c.targetId===t.id&&needsVerifier(c))&&t.verifier?.status!=='active');
  const unpinned=targets.filter(t=>!t.hostFingerprint); const locked=keys.filter(k=>k.passphraseRequired&&k.locked);
  const steps:[CheckState,string,string][]=[
    keys.length?[locked.length?'todo':'done','Master key available',locked.length?'Unlock '+names(locked)+' before provisioning.':'Its public key must be in the target account\'s authorized_keys.']
      :installed.length?['info','Master key available','None right now, which is the recommended state between changes. Upload your master key again when you need to change something.']
      :['todo','Add a master key','Generate or upload one below, then add its public key to the target account\'s authorized_keys.'],
    targets.length?['done','Add an SSH target',targets.length+' target'+(targets.length===1?'':'s')+'.']:['todo','Add an SSH target','Host, port and the account commands run as.'],
    !targets.length?['todo','Pin the host fingerprint','Run Test on the target and trust the fingerprint it shows.']
      :unpinned.length?['todo','Pin the host fingerprint','Run Test on: '+names(unpinned)+'.']:['done','Pin the host fingerprint','All targets are pinned.'],
    needVerifier.length?['todo','Install the integrity verifier','Needed for level 3–5 commands (and verified level 1–2 commands) on: '+names(needVerifier)+'. The account that runs sudo can be a separate admin account.']
      :['done','Install the integrity verifier',commands.some(needsVerifier)?'Active wherever commands need it.':'Only needed for level 3–5 commands, or level 1–2 commands with verification on.'],
    installed.length?['done','Create and install commands',installed.length+' of '+commands.length+' installed. Manage them on the <a href="#" data-page="commands">Commands page</a>.']
      :['todo','Create and install commands','On the <a href="#" data-page="commands">Commands page</a>: New command, then Install.'],
    grants.length?['done','Connect an MCP client',grants.length+' client'+(grants.length===1?'':'s')+' authorized (see <a href="#" data-page="oauth">OAuth Sources page</a>).']
      :['todo','Connect an MCP client','Add '+escapeHtml(location.origin+'/mcp')+' as a remote MCP server in your client and approve it here.'],
    keys.length&&installed.length?['info','Delete the master key when you are done','Recommended: installed commands keep running without it.']
      :keys.length?['info','Delete the master key when you are done','Recommended once your commands are installed.']:['done','Delete the master key when you are done','No master key is stored.'],
  ];
  const open=steps.some(([state])=>state==='todo');
  const mark={done:'✓',todo:'○',info:'i'};
  return '<details class="checklist"'+(open?' open':'')+'><summary><strong>Setup checklist</strong> <small>'+steps.filter(([st])=>st==='done').length+' of '+steps.length+' done</small></summary><ol>'+
    steps.map(([state,title,detail])=>'<li class="'+state+'"><span class="mark" aria-hidden="true">'+mark[state]+'</span><div><strong>'+escapeHtml(title)+'</strong><small>'+detail+'</small></div></li>').join('')+'</ol></details>';
}
async function sshPage() {
  const [keysResult, targetsResult, commandsResult, grantsResult] = await Promise.all([api('/api/ssh/keys'),api('/api/ssh/targets'),api('/api/commands'),api('/api/oauth/grants')]);
  const keys=keysResult.keys as any[]; const targets=targetsResult.targets as any[];
  const commands=commandsResult.commands as any[]; const grants=(grantsResult.grants as any[]).filter(g=>!g.revoked);
  const ledger=(await Promise.all(targets.map(t=>api('/api/ssh/targets/'+t.id+'/capability-ledger')))).flatMap((r:any)=>r.entries as any[]);
  const ledgerTargets=targets.filter(t=>ledger.some(x=>x.targetId===t.id));
  const targetName=(id:string)=>targets.find(t=>t.id===id)?.name??id;
  const keyRows=keys.map(k=>row(
    '<strong>'+escapeHtml(k.name)+'</strong><small class="mono">'+escapeHtml(k.fingerprint??'fingerprint pending')+'</small><div class="pills">'+(k.passphraseRequired?pill(k.locked?'Locked':'Unlocked',k.locked?'warn':'ok')+pill('Passphrase protected'):pill('No passphrase'))+'</div>',
    (k.publicKey?'<button class="small" data-copy-public="'+k.id+'">Copy public key</button>':'')+
    (k.passphraseRequired?(k.locked?'<button class="small" data-unlock="'+k.id+'">Unlock</button>':'<button class="small" data-lock="'+k.id+'">Lock</button>'):'')+
    '<button class="small" data-edit-key="'+k.id+'">Rename</button><button class="small danger" data-delete-key="'+k.id+'">Delete</button>'));
  const targetRows=targets.map(t=>{const v=t.verifier?.status??'unavailable'; const key=keys.find(k=>k.id===t.sshKeyId);
    return row(
      '<strong>'+escapeHtml(t.name)+'</strong><small>'+escapeHtml(t.username+'@'+t.hostname+':'+t.port)+(key?' · key '+escapeHtml(key.name):'')+'</small><small class="mono">'+escapeHtml(t.hostFingerprint??'Host fingerprint not pinned — run Test')+'</small>'+
      '<div class="pills">'+(v==='active'?pill('Verifier active','ok'):v==='pending'?pill('Verifier not activated','warn'):pill('No verifier: levels 3–5 blocked','bad'))+(t.verifier?.lastError?pill('Last verification failed','bad'):'')+(key?'':pill('No master key: provisioning off','warn'))+(t.enabled?'':pill('Disabled'))+'</div>',
      '<button class="small" data-test="'+t.id+'">Test</button><button class="small" data-verifier="'+t.id+'">Verifier</button><button class="small" data-edit-target="'+t.id+'">Edit</button><button class="small danger" data-delete-target="'+t.id+'">Delete</button>');});
  shell('SSH configuration',setupChecklist(keys,targets,commands,grants)+
    '<article>'+sectionHead('Master keys','<button class="small" id="upload-key">Upload key</button><button class="small primary" id="generate-key">Generate key</button>')+
    '<p class="hint">A master key is provisioning authority only: it installs, replaces and removes capabilities and installs verifiers. Passphrases are never stored. Deleting a master key keeps existing capabilities executable; level 3–5 commands keep running as long as the target\'s integrity verifier confirms them.</p>'+
    '<p class="hint"><strong>Recommended:</strong> delete the master key when you have finished provisioning, and add it again for the next change. Upload your own passphrase-protected key (kept safely outside farcmd) so the same key can be uploaded again later. A key generated here is gone for good once deleted, and a new key\'s public key would have to be added to the target\'s authorized_keys again. After adding a key again, select it on the target with Edit.</p>'+
    rows(keyRows,'No master keys yet. Generate one, or upload an existing private key.')+'</article>'+
    '<article>'+sectionHead('Targets','<button class="small primary" id="add-target"'+(keys.length?'':' disabled title="Add a master key first"')+'>Add target</button>')+
    rows(targetRows,keys.length?'No targets yet.':'Add a master key before adding targets.')+'</article>'+
    '<article>'+sectionHead('Remote cleanup ledger',ledgerTargets.map(t=>'<button class="small" data-cleanup-target="'+t.id+'">Retry '+escapeHtml(t.name)+'</button>').join(''))+
    '<p class="hint">Command capabilities that remain on targets because farcmd had no provisioning authority when they were removed. Retry removes them with the target\'s master key.</p>'+
    rows(ledger.map(x=>row('<strong class="mono">'+escapeHtml(x.remoteScriptPath)+'</strong><small>'+escapeHtml(targetName(x.targetId))+' · '+escapeHtml(x.status)+' · attempts '+x.attemptCount+(x.lastError?' · '+escapeHtml(x.lastError):'')+'</small>','')),'No pending remote cleanup.')+'</article>');

  on('#generate-key',()=>formDialog('Generate master key','<label>Name<input name="name" required maxlength="120"></label><label>Passphrase (optional)<input name="passphrase" type="password" autocomplete="new-password"></label><p class="hint">farcmd generates an Ed25519 key. Add its public key to the targets\' authorized_keys. The private key never leaves farcmd, so once this key is deleted it is gone. If you plan to delete the master key after each round of provisioning, upload your own key instead.</p>','Generate',async form=>{
    const f=new FormData(form); await api('/api/ssh/keys/generate',{method:'POST',body:JSON.stringify({name:f.get('name'),passphrase:f.get('passphrase')})}); sshPage();}));
  on('#upload-key',()=>formDialog('Upload master key','<label>Name<input name="name" required maxlength="120"></label><label>Private key<textarea name="privateKey" rows="10" required autocomplete="off" spellcheck="false" class="mono"></textarea></label>','Upload',async form=>{
    const f=new FormData(form); await api('/api/ssh/keys',{method:'POST',body:JSON.stringify({name:f.get('name'),privateKey:f.get('privateKey')})}); sshPage();}));
  on('[data-edit-key]',b=>{const k=keys.find(x=>x.id===b.dataset.editKey); if(!k)return;
    formDialog('Rename master key','<label>Name<input name="name" required maxlength="120" value="'+escapeHtml(k.name)+'"></label>','Save',async form=>{
      await api('/api/ssh/keys/'+k.id,{method:'PATCH',body:JSON.stringify({name:new FormData(form).get('name')})}); sshPage();});});
  on('[data-copy-public]',async b=>{const k=keys.find(x=>x.id===b.dataset.copyPublic); if(!k?.publicKey)return;
    try{await navigator.clipboard.writeText(k.publicKey); b.textContent='Copied';}catch{openDialog('Public key','<pre class="mono">'+escapeHtml(k.publicKey)+'</pre><div class="dialog-actions"><button data-dialog-close>Close</button></div>');}});
  on('[data-unlock]',b=>render('unlock',b.dataset.unlock));
  on('[data-lock]',async b=>{await api('/api/ssh/keys/'+b.dataset.lock+'/lock',{method:'POST'}); sshPage();});
  on('[data-delete-key]',async b=>{if(confirm('Delete this master key?\n\nInstalled commands keep running, and level 3–5 commands keep being verified. Until you add a master key again and select it on the target (Edit), farcmd cannot install, change or remove capabilities, install verifiers automatically, clean up the ledger or read shell history on its targets. Removed capabilities wait in the cleanup ledger.\n\nIf farcmd generated this key, it cannot be restored: remove its line from the targets\' authorized_keys.')){try{await api('/api/ssh/keys/'+b.dataset.deleteKey,{method:'DELETE'});}catch(err){alert((err as Error).message);} sshPage();}});

  const targetFields=(t?:any)=>'<label>Name<input name="name" required maxlength="120" value="'+escapeHtml(t?.name??'')+'"></label><div class="field-row"><label>Hostname<input name="hostname" required value="'+escapeHtml(t?.hostname??'')+'"></label><label class="narrow">Port<input name="port" type="number" min="1" max="65535" required value="'+(t?.port??22)+'"></label></div><label>Username<input name="username" required autocomplete="off" value="'+escapeHtml(t?.username??'')+'"></label><label>Master key<select name="sshKeyId" required>'+sshKeyOptions(keys,t?.sshKeyId)+'</select></label>';
  const targetBody=(f:FormData)=>({name:f.get('name'),hostname:f.get('hostname'),port:Number(f.get('port')),username:f.get('username'),sshKeyId:f.get('sshKeyId')});
  on('#add-target',()=>formDialog('Add target',targetFields()+'<p class="hint">After adding, run Test to pin the host fingerprint.</p>','Add target',async form=>{
    await api('/api/ssh/targets',{method:'POST',body:JSON.stringify(targetBody(new FormData(form)))}); sshPage();}));
  on('[data-edit-target]',b=>{const t=targets.find(x=>x.id===b.dataset.editTarget); if(!t)return;
    formDialog('Edit target',targetFields(t)+'<p class="hint">Changing the hostname or port clears the pinned host fingerprint. Run Test afterwards to pin the new one.</p>','Save',async form=>{
      const body:Record<string,unknown>=targetBody(new FormData(form));
      if(body.hostname!==t.hostname||body.port!==t.port)body.hostFingerprint=null; // a different host must be pinned again
      await api('/api/ssh/targets/'+t.id,{method:'PATCH',body:JSON.stringify(body)}); sshPage();});});
  on('[data-delete-target]',async b=>{if(confirm('Delete this target?')){try{await api('/api/ssh/targets/'+b.dataset.deleteTarget,{method:'DELETE'});}catch(err){alert((err as Error).message);} sshPage();}});
  on('[data-test]',async b=>{const el=b as HTMLButtonElement;el.disabled=true;try{const result=await api('/api/ssh/targets/'+b.dataset.test+'/test',{method:'POST'});if(result.ok){alert('Connection successful. Host fingerprint: '+(result.fingerprint??'unknown'));}else if(result.fingerprint&&confirm((result.error??'Host key is not yet trusted.')+'\n\nFingerprint: '+result.fingerprint+'\n\nTrust this fingerprint for this target?')){await api('/api/ssh/targets/'+b.dataset.test,{method:'PATCH',body:JSON.stringify({hostFingerprint:result.fingerprint})});alert('Fingerprint saved. Run Test again to verify the connection.');sshPage();}else{alert(result.error??'Connection failed');}}catch(err){alert((err as Error).message);}finally{el.disabled=false;}});
  on('[data-verifier]',b=>{const t=targets.find(x=>x.id===b.dataset.verifier); if(t)verifierDialog(t,keys);});
  on('[data-cleanup-target]',async b=>{try{const r=await api('/api/ssh/targets/'+b.dataset.cleanupTarget+'/capability-ledger/cleanup',{method:'POST',body:'{}'});alert('Removed '+r.removed+' remote capabilities; '+r.remaining+' remain.');sshPage();}catch(err){alert((err as Error).message);}});
}
/** Integrity verifier status and actions for one target. */
function verifierDialog(t:any, keys:any[]){
  const v=t.verifier??{status:'unavailable'};
  const state=v.status==='active'?'<p>'+pill('Active','ok')+(v.lastVerifiedAt?' Last verified '+escapeHtml(new Date(v.lastVerifiedAt).toLocaleString())+'.':'')+'</p>':v.status==='pending'?'<p class="warning">Installed but not activated. Level 3–5 commands are blocked until “Verify now” succeeds.</p>':'<p class="warning">No integrity verifier. Level 3–5 commands (and level 1–2 commands with verification on) on this target are blocked.</p>';
  const d=openDialog('Integrity verifier — '+t.name,state+(v.lastError?'<p class="warning">Last verification problem: '+escapeHtml(v.lastError)+'</p>':'')+
    '<div class="action-list"><button data-verifier-install>'+(v.status==='unavailable'?'Install verifier':'Repair verifier')+' (automatic)</button><button data-verifier-manual>Manual root install script</button>'+(v.status!=='unavailable'?'<button data-verifier-verify>Verify now</button><button class="danger" data-verifier-remove>Remove verifier</button>':'')+'</div>'+
    '<div class="dialog-actions"><button data-dialog-close>Close</button></div>');
  const act=(sel:string,fn:(b:HTMLButtonElement)=>void)=>d.querySelector<HTMLButtonElement>(sel)?.addEventListener('click',e=>fn(e.currentTarget as HTMLButtonElement));
  act('[data-verifier-install]',()=>{d.close();verifierRootPage(t.id,t,keys,'install');});
  act('[data-verifier-remove]',()=>{d.close();verifierRootPage(t.id,t,keys,'remove');});
  act('[data-verifier-manual]',async()=>{if(!confirm('Generate a manual root install script? It replaces the stored verification key and secret immediately: level 3–5 commands on this target stay blocked until an administrator runs the script as root and you click "Verify now".'))return;try{const r=await api('/api/ssh/targets/'+t.id+'/verifier/manual',{method:'POST',body:'{}'});d.close();showScript('Run this as root on the target (for example: sudo sh -s < farcmd-verifier.sh), then delete it. It contains the verification secret and is shown only once.',r.installScript);}catch(err){alert((err as Error).message);}});
  act('[data-verifier-verify]',async b=>{b.disabled=true;try{const r=await api('/api/ssh/targets/'+t.id+'/verifier/verify',{method:'POST',body:'{}'});alert(verificationText(r));}catch(err){alert((err as Error).message);}d.close();sshPage();});
}
function verificationText(r:any):string{
  const v=r.verification; if(!v)return 'Done.';
  if(v.ok)return 'Integrity verification succeeded: every installed capability matches what farcmd provisioned.';
  return 'Integrity verification FAILED'+(v.error?': '+v.error:'')+(v.problems?.length?'\n\n'+v.problems.map((p:any)=>'• '+(p.commandName?p.commandName+': ':'')+p.message).join('\n'):'');
}
function showScript(message:string,script:string){
  shell('Verifier script','<p>'+escapeHtml(message)+'</p><pre id="verifier-script">'+escapeHtml(script)+'</pre><button id="copy-script">Copy</button> <button id="back-ssh">Back to SSH</button>');
  document.querySelector('#copy-script')!.addEventListener('click',()=>navigator.clipboard.writeText(script));
  document.querySelector('#back-ssh')!.addEventListener('click',()=>{document.querySelector('#verifier-script')!.textContent='';render('ssh');});
}
/** Install/repair or remove the verifier through the master key. Root comes from the target account's sudo password (sent once, never stored), passwordless sudo, or the root account. */
function verifierRootPage(targetId:string,t:any,keys:any[],action:'install'|'remove'){
  const account=escapeHtml(t?.username??'');
  const intro=action==='install'
    ?'<p>farcmd connects with the unlocked master key and installs (or repairs) the root-owned integrity verifier. A new verification key and secret replace the old ones.</p>'
    :'<p class="warning">Removing the verifier BLOCKS level 3–5 commands (and level 1–2 commands with verification on) on this target until a verifier is installed again.</p>';
  shell(action==='install'?'Install integrity verifier':'Remove integrity verifier',intro+'<form id="verifier-root-form"><div class="callout"><strong>The sudo account doesn\'t have to be the command account.</strong><p>The verifier is always installed for the command account <strong>'+account+'</strong>. Enter any account on the same host that can become root, for example an admin account with sudo, or root itself. The master key you choose must be authorized for that account.</p><p><strong>Recommended:</strong> keep the command account without sudo rights. Unrestricted sudo on the command account would defeat the verifier.</p></div><label>Connect as SSH account (the account that runs sudo) <input name="installUsername" required value="'+account+'" autocomplete="off"></label><label>Using master key <select name="installKeyId">'+keys.map(k=>'<option value="'+escapeHtml(k.id)+'"'+(k.id===t?.sshKeyId?' selected':'')+'>'+escapeHtml(k.name)+(k.locked?' (locked)':'')+'</option>').join('')+'</select></label><label>sudo password of that account <input name="sudoPassword" type="password" autocomplete="off"></label><p><small>Used once to run the installer with sudo on the target and then discarded: farcmd never stores or logs it, and it is passed on the SSH session\'s standard input, never on a command line. Leave the password empty if that account is root or has passwordless sudo. Only use this if you trust the target account right now — its shell start-up files run before sudo. Otherwise use the manual root install script.</small></p><button>'+(action==='install'?'Install verifier':'Remove verifier')+'</button> <button type="button" id="verifier-cancel">Cancel</button></form><p id="verifier-error"></p>');
  document.querySelector('#verifier-cancel')!.addEventListener('click',()=>render('ssh'));
  document.querySelector<HTMLFormElement>('#verifier-root-form')!.onsubmit=async e=>{
    e.preventDefault(); const form=e.currentTarget as HTMLFormElement; const button=form.querySelector('button')!; button.disabled=true;
    const input=form.querySelector<HTMLInputElement>('input[name=sudoPassword]')!; const sudoPassword=input.value; input.value='';
    try{
      const installUsername=form.querySelector<HTMLInputElement>('input[name=installUsername]')!.value.trim(); const installKeyId=form.querySelector<HTMLSelectElement>('select[name=installKeyId]')!.value;
      const r=await api('/api/ssh/targets/'+targetId+'/verifier',{method:action==='install'?'POST':'DELETE',body:JSON.stringify({installUsername,...(installKeyId?{installKeyId}:{}),...(sudoPassword?{sudoPassword}:{})})});
      if(action==='install'){alert(verificationText(r));render('ssh');}
      else if(r.uninstallScript)showScript('Removed locally. Remote removal was not possible ('+(r.error??'no provisioning authority')+'). Run this as root on the target to remove the verifier files:',r.uninstallScript);
      else render('ssh');
    }catch(err){document.querySelector('#verifier-error')!.textContent=(err as Error).message;button.disabled=false;}
  };
}
function unlockPage(keyId:string) {
  shell('Unlock SSH key','<p>The passphrase is used only in memory and is not stored in the database.</p><form id="unlock-form"><label>Passphrase<input name="passphrase" type="password" autocomplete="current-password" required></label><button>Unlock for 15 minutes</button></form><p id="unlock-error"></p>');
  document.querySelector<HTMLFormElement>('#unlock-form')!.onsubmit=async e=>{e.preventDefault();try{const f=new FormData(e.currentTarget as HTMLFormElement);await api('/api/ssh/keys/'+keyId+'/unlock',{method:'POST',body:JSON.stringify({passphrase:f.get('passphrase')})});render('ssh');}catch(err){document.querySelector('#unlock-error')!.textContent=(err as Error).message;}};
}
async function commandsPage(){
  const [cr,tr]=await Promise.all([api('/api/commands'),api('/api/ssh/targets')]);
  const cs=cr.commands as any[],ts=tr.targets as any[];
  const targetName=(id:string)=>ts.find(t=>t.id===id)?.name??'unknown target';
  const commandRows=cs.map(c=>row(
    '<strong>'+escapeHtml(c.name)+'</strong>'+(c.description?'<small>'+escapeHtml(c.description)+'</small>':'')+
    '<div class="pills">'+pill('Level '+c.level+' · '+LEVELS[c.level],c.level>=5?'bad':c.level>=4?'warn':'muted')+pill(targetName(c.targetId))+pill(c.type==='bash_script'?'Bash script':'Shell')+
      (c.enabled?'':pill('Disabled','warn'))+(c.commandKey?pill('Capability installed','ok'):pill('No capability'))+
      (c.level===5?pill(c.hasExecutionPassword?'Password set':'Password not set',c.hasExecutionPassword?'ok':'bad'):'')+
      (c.level<3&&c.verifyIntegrity?pill('Verified','ok'):'')+(needsVerifier(c)&&c.integrityVerification!=='active'?pill('Blocked: no active verifier','bad'):'')+'</div>',
    // Workflow left to right: Edit -> Install -> Run. Editing is locked (target, type, content) while installed.
    '<div class="command-actions"><div class="flow">'+
      '<button class="small" data-edit-command="'+c.id+'"'+(c.commandKey?' title="Installed: target, type and content are locked. Uninstall to change them."':'')+'>'+(c.commandKey?'<span aria-hidden="true">🔒 </span>':'')+'Edit</button><span class="flow-arrow" aria-hidden="true">→</span>'+
      (c.commandKey?'<button class="small" data-delete-command-key="'+c.id+'">Uninstall</button>':'<button class="small'+(c.enabled?' next':'')+'" data-create-command-key="'+c.id+'">Install</button>')+'<span class="flow-arrow" aria-hidden="true">→</span>'+
      '<button class="primary run" data-run-command="'+c.id+'"'+(!c.enabled?' disabled title="The command is disabled"':!c.commandKey?' disabled title="Install the SSH capability first"':'')+'>Run</button>'+
    '</div><div class="secondary-actions">'+
      (c.level===5?'<button class="small" data-set-level5="'+c.id+'">Password</button>':'')+
      '<button class="small" data-toggle-command="'+c.id+'">'+(c.enabled?'Disable':'Enable')+'</button><button class="small danger" data-delete-command="'+c.id+'">Delete</button>'+
    '</div></div>'));
  shell('Commands','<div id="mcp-access"></div>'+
    '<article>'+sectionHead('Command registry','<button class="small primary" id="new-command"'+(ts.length?'':' disabled title="Add an SSH target first"')+'>New command</button>')+
    '<p class="hint">A command is an MCP capability. Install creates a dedicated SSH key on the target that can only run this command’s farcmd-managed script.</p>'+
    rows(commandRows,ts.length?'No commands yet.':'Add an SSH target before creating commands.')+'</article>');

  // Content, type and target cannot change while a capability is installed (the server refuses with 409).
  const verifyHint=(level:number)=>level>=3?'Always on for levels 3–5.':'Optional for levels 1–2: the target\'s integrity verifier must confirm the installed script and authorized_keys before each run, otherwise the run is blocked.';
  /** Levels 3–5 are always verified: show the box checked and locked; levels 1–2 restore the command's own choice. */
  const wireVerify=(d:HTMLDialogElement,c?:any)=>{const level=d.querySelector<HTMLSelectElement>('select[name=level]')!,box=d.querySelector<HTMLInputElement>('input[name=verifyIntegrity]')!,hint=d.querySelector('[data-verify-hint]')!;
    let own=!!c?.verifyIntegrity; box.onchange=()=>{if(!box.disabled)own=box.checked;};
    level.onchange=()=>{const always=Number(level.value)>=3; box.disabled=always; box.checked=always||own; hint.textContent=verifyHint(Number(level.value));};};
  const commandFields=(c?:any)=>{const locked=!!c?.commandKey; const dis=locked?' disabled':'';
    return (locked?'<p class="locked-note"><span aria-hidden="true">🔒 </span>The SSH capability is installed, so target, type and content are locked (shown as installed). Name, description, level, verification and output setting can still be changed. Uninstall to change the rest.</p>':'')+
      '<label>Name<input name="name" required maxlength="120" value="'+escapeHtml(c?.name??'')+'"></label>'+
      '<label>Description<textarea name="description" rows="2" maxlength="2000">'+escapeHtml(c?.description??'')+'</textarea></label>'+
      '<div class="field-row"><label>Target<select name="targetId" required'+dis+'>'+ts.map(t=>'<option value="'+escapeHtml(t.id)+'"'+(t.id===c?.targetId?' selected':'')+'>'+escapeHtml(t.name)+'</option>').join('')+'</select></label>'+
      '<label>Type<select name="type"'+dis+'><option value="shell">Shell command</option><option value="bash_script"'+(c?.type==='bash_script'?' selected':'')+'>Bash script</option></select></label></div>'+
      '<label>Content<textarea name="content" rows="8" required spellcheck="false" class="mono" placeholder="Shell command or Bash script"'+dis+'>'+escapeHtml(c?.content??'')+'</textarea></label>'+
      '<label>Level<select name="level">'+[1,2,3,4,5].map(l=>'<option value="'+l+'"'+(l===(c?.level??1)?' selected':'')+'>'+l+' — '+LEVELS[l]+'</option>').join('')+'</select></label>'+
      (c?.level===5?'<p class="hint">Moving this command off level 5 clears its execution password.</p>':'')+
      '<label class="check"><input type="checkbox" name="verifyIntegrity"'+(c?.verifyIntegrity||(c?.level??1)>=3?' checked':'')+((c?.level??1)>=3?' disabled':'')+'> Verify integrity before each run</label><p class="hint" data-verify-hint>'+verifyHint(c?.level??1)+'</p>'+
      '<label class="check"><input type="checkbox" name="showOutputOnApproval"'+(c?.showOutputOnApproval?' checked':'')+'> Show output after approval (levels 4–5)</label><p class="hint">Levels 1–3 always show their output when run from here. For levels 4–5, the approval page and Run show only the exit code unless this is on. The MCP client always gets the full result.</p>';};
  const commandBody=(form:HTMLFormElement)=>{const f=new FormData(form); const body:Record<string,unknown>={name:f.get('name'),description:f.get('description'),level:Number(f.get('level')),showOutputOnApproval:f.get('showOutputOnApproval')==='on'};
    const verify=form.querySelector<HTMLInputElement>('input[name=verifyIntegrity]')!; if(!verify.disabled)body.verifyIntegrity=verify.checked; // levels 3–5: always on, keep the stored choice
    for(const k of ['targetId','type','content'])if(f.has(k))body[k]=f.get(k); // disabled fields are absent
    return body;};
  mcpAccessPanel();
  on('#new-command',()=>wireVerify(formDialog('New command',commandFields(),'Create command',async form=>{
    await api('/api/commands',{method:'POST',body:JSON.stringify(commandBody(form))}); commandsPage();})));
  on('[data-edit-command]',b=>{const c=cs.find(x=>x.id===b.dataset.editCommand); if(!c)return;
    wireVerify(formDialog(c.commandKey?'Edit command (installed)':'Edit command',commandFields(c),'Save',async form=>{await api('/api/commands/'+c.id,{method:'PATCH',body:JSON.stringify(commandBody(form))}); commandsPage();}),c);});
  on('[data-run-command]',b=>{const c=cs.find(x=>x.id===b.dataset.runCommand); if(c)runCommand({...c,targetName:targetName(c.targetId)});});
  on('[data-set-level5]',b=>{const c=cs.find(x=>x.id===b.dataset.setLevel5); if(!c)return;
    formDialog((c.hasExecutionPassword?'Change':'Set')+' execution password','<p class="hint">Level 5 commands run only after this password is entered on the confirmation page.</p><label>Password<input name="password" type="password" minlength="12" maxlength="1024" required autocomplete="new-password"></label><label>Repeat password<input name="repeat" type="password" required autocomplete="new-password"></label>','Save',async form=>{
      const f=new FormData(form); if(f.get('password')!==f.get('repeat'))throw new Error('The passwords do not match.');
      await api('/api/commands/'+c.id+'/execution-password',{method:'POST',body:JSON.stringify({password:f.get('password')})}); commandsPage();});});
  on('[data-create-command-key]',async b=>{if(!confirm('Generate an Ed25519 capability key and install a forced farcmd script on the target?'))return;try{await api('/api/commands/'+b.dataset.createCommandKey+'/key',{method:'POST',body:'{}'});commandsPage();}catch(err){alert((err as Error).message);}});
  on('[data-delete-command-key]',async b=>{if(!confirm('Remove this SSH capability remotely? If no master key is available, farcmd will record it for later cleanup.'))return;try{const r=await api('/api/commands/'+b.dataset.deleteCommandKey+'/key',{method:'DELETE'});if(r.remoteCleanupPending)alert('Capability removed locally and recorded for remote cleanup when a master key is available.');commandsPage();}catch(err){alert((err as Error).message);}});
  on('[data-toggle-command]',async b=>{const x=cs.find(v=>v.id===b.dataset.toggleCommand);if(x)await api('/api/commands/'+x.id,{method:'PATCH',body:JSON.stringify({enabled:!x.enabled})});commandsPage();});
  on('[data-delete-command]',async b=>{const c=cs.find(x=>x.id===b.dataset.deleteCommand);
    if(!confirm(c?.commandKey?'Delete this command?\n\nIt has an installed SSH capability, so this first removes the capability from the target (or records it for later cleanup if the target cannot be reached now). The command itself stays in the list: press Delete again to remove it.':'Delete this command?'))return;
    const r=await api('/api/commands/'+b.dataset.deleteCommand,{method:'DELETE'});
    if(!r.commandDeleted)alert((r.remoteCleanupPending?'The SSH capability could not be removed now and was recorded for later cleanup.':'The SSH capability was removed from the target.')+' The command is still in the list: press Delete again to delete it.');
    commandsPage();});
}
async function oauthPage(){
  const r=await api('/api/oauth/grants'); const grants=r.grants as any[];
  const levelBoxes=(g:any)=>[1,2,3,4,5].map(l=>'<label class="check"><input type="checkbox" name="level" value="'+l+'"'+(g.visibleLevels.includes(l)?' checked':'')+(l===5&&g.level5PermanentlyHidden?' disabled':'')+'><span>Level '+l+' · '+escapeHtml(LEVELS[l]!)+'</span></label>').join('');
  const grantRow=(g:any)=>'<li class="grant">'+
    '<div class="row-main"><strong>'+escapeHtml(g.clientName||g.clientId)+'</strong><small class="mono">'+escapeHtml(g.clientId)+'</small><div class="pills">'+
      (g.revoked?pill('Revoked','bad'):pill('Active','ok'))+pill(g.lastUsedAt?'Last used '+new Date(g.lastUsedAt).toLocaleString():'Not used yet')+(g.level5PermanentlyHidden?pill('Level 5 permanently hidden','warn'):'')+'</div></div>'+
    (g.revoked?'<p class="hint">This client was revoked. It has to be authorized again before it can use farcmd.</p>'
      :'<form data-oauth-form="'+escapeHtml(g.clientId)+'"><fieldset class="level-grid"><legend>Levels this client can see</legend>'+levelBoxes(g)+'</fieldset>'+
        '<label class="check"><input type="checkbox" name="permanentLevel5"'+(g.level5PermanentlyHidden?' checked disabled':'')+'><span>Permanently hide level 5 from this client (cannot be undone)</span></label>'+
        '<div class="grant-actions"><button class="small primary" type="submit">Save levels</button><button class="small danger" type="button" data-revoke-oauth="'+escapeHtml(g.clientId)+'">Revoke</button><span class="form-message" role="status"></span></div></form>')+
    '</li>';
  shell('OAuth Sources','<div id="mcp-access"></div><article>'+sectionHead('Authorized MCP clients','')+
    '<p class="hint">Each client sees only the command levels ticked here. Whether it asks before a call is the client\'s own setting; levels 4 and 5 always need your approval in farcmd as well.</p>'+
    (grants.length?'<ul class="rows grants">'+grants.map(grantRow).join('')+'</ul>':'<p class="empty">No MCP clients yet. Add '+escapeHtml(location.origin+'/mcp')+' as a remote MCP server in your client, then approve it when it opens the sign-in page.</p>')+'</article>');
  document.querySelectorAll<HTMLFormElement>('[data-oauth-form]').forEach(f=>{
    const permanent=f.querySelector<HTMLInputElement>('input[name="permanentLevel5"]')!; const level5=f.querySelector<HTMLInputElement>('input[name="level"][value="5"]')!;
    permanent.addEventListener('change',()=>{if(permanent.checked){level5.checked=false;}level5.disabled=permanent.checked;});
    f.onsubmit=async e=>{e.preventDefault();const message=f.querySelector('.form-message')!;const levels=[...f.querySelectorAll<HTMLInputElement>('input[name="level"]:checked')].map(x=>Number(x.value));
      if(permanent.checked&&!permanent.disabled&&!confirm('Permanently hide level 5 from this client? This cannot be undone.'))return;
      try{await api('/api/oauth/grants/'+encodeURIComponent(f.dataset.oauthForm!),{method:'PATCH',body:JSON.stringify({visibleLevels:levels,level5PermanentlyHidden:permanent.checked})});oauthPage();}catch(err){message.textContent=(err as Error).message;}};
  });
  document.querySelectorAll<HTMLElement>('[data-revoke-oauth]').forEach(b=>b.onclick=async()=>{if(confirm('Revoke this client? It loses access at once and has to be authorized again.')){await api('/api/oauth/grants/'+encodeURIComponent(b.dataset.revokeOauth!)+'/revoke',{method:'POST'});oauthPage();}});
  mcpAccessPanel();
}
const AUDIT_PAGE_SIZE=50;
async function auditPage(filters:{event?:string;outcome?:string;search?:string}={},offset=0){
  const params=new URLSearchParams({...Object.fromEntries(Object.entries(filters).filter((e):e is [string,string]=>!!e[1])),limit:String(AUDIT_PAGE_SIZE),offset:String(offset)});
  const r=await api('/api/audit?'+params.toString()); const entries=r.entries as any[]; const total=r.total as number;
  // Long details (e.g. every field of a created command) fold behind a toggle so rows stay one or two lines high.
  const detail=(d:any)=>{if(!d)return '';const text=Object.entries(d).map(([k,v])=>k+'='+(typeof v==='string'?v:JSON.stringify(v))).join(' · ');
    return text.length<=90?escapeHtml(text):'<details class="audit-details"><summary>'+escapeHtml(text.slice(0,70))+'…</summary>'+escapeHtml(text)+'</details>';};
  const shortId=(id:string)=>/^[0-9a-f]{8}-[0-9a-f-]{27}$/i.test(id)?'<span class="mono" title="'+escapeHtml(id)+'">'+escapeHtml(id.slice(0,8))+'…</span>':escapeHtml(id);
  const day=(t:number)=>new Date(t).toLocaleDateString(undefined,{weekday:'long',year:'numeric',month:'long',day:'numeric'});
  let lastDay=''; const body=entries.map(e=>{const d=day(e.createdAt);const head=d!==lastDay?'<tr class="day"><th colspan="7">'+escapeHtml(d)+'</th></tr>':'';lastDay=d;
    return head+'<tr class="'+(e.outcome==='failure'?'failure':'')+'"><td class="num">'+e.seq+'</td><td class="num">'+escapeHtml(new Date(e.createdAt).toLocaleTimeString())+'</td><td><span class="mono">'+escapeHtml(e.event)+'</span>'+(e.outcome==='failure'?' '+pill('failure','bad'):'')+'</td><td>'+escapeHtml(e.actor)+'</td><td>'+escapeHtml(e.targetType??'')+(e.targetId?' '+shortId(e.targetId):'')+'</td><td>'+escapeHtml([e.clientId,e.ip].filter(Boolean).join(' · '))+'</td><td>'+detail(e.details)+'</td></tr>';}).join('');
  const first=total?offset+1:0, last=offset+entries.length;
  const pager='<div class="pager"><button type="button" class="small" data-audit-page="'+Math.max(offset-AUDIT_PAGE_SIZE,0)+'"'+(offset>0?'':' disabled')+'>← Newer</button><span>'+(total?first+'–'+last+' of '+total:'No entries')+'</span><button type="button" class="small" data-audit-page="'+(offset+AUDIT_PAGE_SIZE)+'"'+(last<total?'':' disabled')+'>Older →</button></div>';
  shell('Audit log','<article>'+sectionHead('Security events','<button type="button" class="small" id="audit-verify">Verify integrity</button>')+
    '<p class="hint">Sign-ins, credential and target changes, commands, verifier operations, OAuth grants and MCP executions on your account. Secrets and passwords are never recorded. Entries are hash-chained, so a changed or deleted earlier entry is detected by Verify integrity.</p><p id="audit-verify-result" role="status"></p>'+
    '<form id="audit-filter" class="filter-bar"><input name="event" aria-label="Event" placeholder="Event, e.g. command or ssh_key.delete" value="'+escapeHtml(filters.event??'')+'"><select name="outcome" aria-label="Outcome"><option value="">Any outcome</option><option value="success"'+(filters.outcome==='success'?' selected':'')+'>Success</option><option value="failure"'+(filters.outcome==='failure'?' selected':'')+'>Failure</option></select><input name="search" type="search" aria-label="Search" placeholder="Search target, client or details" value="'+escapeHtml(filters.search??'')+'"><button class="small primary">Filter</button></form>'+
    pager+(entries.length?'<div class="table-scroll"><table class="audit"><thead><tr><th>#</th><th>Time</th><th>Event</th><th>Actor</th><th>Target</th><th>Client / IP</th><th>Details</th></tr></thead><tbody>'+body+'</tbody></table></div>'+pager:'<p class="empty">No entries match these filters.</p>')+'</article>');
  document.querySelector<HTMLFormElement>('#audit-filter')!.onsubmit=e=>{e.preventDefault();const f=new FormData(e.currentTarget as HTMLFormElement);auditPage({event:String(f.get('event')??''),outcome:String(f.get('outcome')??''),search:String(f.get('search')??'')});};
  document.querySelectorAll<HTMLButtonElement>('[data-audit-page]').forEach(b=>b.onclick=()=>auditPage(filters,Number(b.dataset.auditPage)));
  document.querySelector('#audit-verify')!.addEventListener('click',async()=>{const out=document.querySelector('#audit-verify-result')!;try{const v=await api('/api/audit/verify');out.innerHTML=v.ok?pill('Chain intact','ok')+' '+escapeHtml(v.checked+' entries verified'+(v.legacy?' ('+v.legacy+' older unchained entries)':'')+(v.headHash?'. Head #'+v.headSeq+' '+v.headHash+'. Note it somewhere else to detect later truncation.':'.')):pill('Integrity failure','bad')+' '+escapeHtml('at entry #'+v.brokenAtSeq+': '+v.reason);}catch(err){out.textContent=(err as Error).message;}});
}
const HISTORY_PAGE_SIZE=25;
async function historyPage(){
  const [cr,tr,gr]=await Promise.all([api('/api/history/command-counts'),api('/api/ssh/targets'),api('/api/oauth/grants')]);
  const counts=cr.counts as any[],targets=tr.targets as any[],grants=gr.grants as any[];
  const source=(clientId:string)=>clientId==='web'?'Web UI':(grants.find(g=>g.clientId===clientId)?.clientName??clientId);
  const statusPill=(x:any)=>x.status==='success'?pill('Exit 0','ok'):x.status==='blocked'?pill('Blocked before running','bad'):x.status==='timeout'?pill('Timed out','bad'):pill('Exit '+(x.exitCode??'none'),'bad');
  const runRow=(x:any)=>row('<strong>'+escapeHtml(x.commandName)+'</strong><small>'+escapeHtml(new Date(x.startedAt).toLocaleString())+' · '+escapeHtml(source(x.clientId))+'</small><div class="pills">'+pill('Level '+x.level+' · '+LEVELS[x.level],x.level>=5?'bad':x.level>=4?'warn':'muted')+statusPill(x)+pill((x.durationMs/1000).toFixed(x.durationMs<10_000?2:1)+' s')+'</div>',
    '<button type="button" class="small" data-run-output="'+escapeHtml(x.id)+'">Output</button>');
  shell('History','<article>'+sectionHead('Runs','')+
    '<p class="hint">Every run of a farcmd command, from MCP clients and from Run in this web UI (source “Web UI”). Runs are kept for the retention period the operator sets (365 days by default). The command content is not stored here.</p>'+
    '<form id="history-filter" class="filter-bar"><input id="history-search" type="search" aria-label="Search" placeholder="Search output, command or client"><select id="history-level" aria-label="Level"><option value="">All levels</option>'+[1,2,3,4,5].map(l=>'<option value="'+l+'">Level '+l+'</option>').join('')+'</select>'+
      '<select id="history-source" aria-label="Source"><option value="">All sources</option><option value="web">Web UI</option>'+grants.map(g=>'<option value="'+escapeHtml(g.clientId)+'">'+escapeHtml(g.clientName||g.clientId)+'</option>').join('')+'</select><button class="small primary">Search</button></form>'+
    '<div id="execution-history"></div><div class="load-more"><button type="button" class="small" id="history-more" hidden>Load more</button></div></article>'+
    '<article>'+sectionHead('Successful runs per command','')+'<p class="hint">Runs that finished with exit code 0, within the retention period.</p>'+
      rows(counts.map(x=>row('<strong>'+escapeHtml(x.commandName)+'</strong><div class="pills">'+pill('Level '+x.level+' · '+LEVELS[x.level],x.level>=5?'bad':x.level>=4?'warn':'muted')+'</div>','<span class="count">'+x.count+' run'+(x.count===1?'':'s')+'</span>')),'No successful runs yet.')+'</article>'+
    '<article>'+sectionHead('Remote shell history','')+'<p class="hint">Human-only view of the target account\'s shell history, read with the master key. It is separate from farcmd runs and may contain sensitive or unrelated commands.</p>'+
      (targets.length?'<div class="filter-bar"><select id="shell-target" aria-label="SSH target">'+targets.map(t=>'<option value="'+t.id+'">'+escapeHtml(t.name)+'</option>').join('')+'</select><button type="button" class="small primary" id="shell-load">Load recent history</button></div><p id="shell-error" class="dialog-error"></p><pre id="shell-output" class="output" hidden></pre>':'<p class="empty">No SSH targets yet.</p>')+'</article>');
  const box=document.querySelector<HTMLElement>('#execution-history')!; const more=document.querySelector<HTMLButtonElement>('#history-more')!;
  let loaded:any[]=[]; let query:Record<string,string>={};
  const load=async(append:boolean)=>{
    const r=await api('/api/history/executions?'+new URLSearchParams({...query,limit:String(HISTORY_PAGE_SIZE),offset:String(append?loaded.length:0)}).toString());
    const page=r.executions as any[]; loaded=append?loaded.concat(page):page;
    box.innerHTML=rows(loaded.map(runRow),Object.keys(query).length?'No runs match these filters.':'No runs yet.');
    more.hidden=page.length<HISTORY_PAGE_SIZE;
    box.querySelectorAll<HTMLButtonElement>('[data-run-output]').forEach(b=>b.onclick=()=>{const x=loaded.find(v=>v.id===b.dataset.runOutput);if(!x)return;
      const d=openDialog(x.commandName,'<p class="hint">'+escapeHtml(new Date(x.startedAt).toLocaleString()+' · '+source(x.clientId))+'</p>'+(x.error?'<p class="dialog-error">'+escapeHtml(x.error)+'</p>':'')+resultView({...x,...(x.status==='timeout'?{signal:'TIMEOUT'}:{})})+'<div class="dialog-actions"><button data-dialog-close>Close</button></div>');d.classList.add('wide');bindCopyButtons(d);});
  };
  document.querySelector<HTMLFormElement>('#history-filter')!.onsubmit=e=>{e.preventDefault();
    const search=document.querySelector<HTMLInputElement>('#history-search')!.value.trim(),level=document.querySelector<HTMLSelectElement>('#history-level')!.value,clientId=document.querySelector<HTMLSelectElement>('#history-source')!.value;
    query={...(search?{search}:{}),...(level?{level}:{}),...(clientId?{clientId}:{})}; load(false);};
  more.onclick=()=>load(true);
  await load(false);
  document.querySelector('#shell-load')?.addEventListener('click',async()=>{const target=document.querySelector<HTMLSelectElement>('#shell-target')!.value;const out=document.querySelector<HTMLElement>('#shell-output')!;const error=document.querySelector('#shell-error')!;error.textContent='';
    try{const r=await api('/api/history/shell?targetId='+encodeURIComponent(target));out.textContent=r.stdout+(r.stderr?'\n[stderr]\n'+r.stderr:'');out.hidden=false;}catch(err){error.textContent=(err as Error).message;}});
}
/** Exit status, duration and (unless hidden) stdout/stderr of one execution. */
function resultView(r:any):string{
  const status=r.signal==='TIMEOUT'?pill('Timed out','bad'):r.exitCode===0?pill('Exit 0','ok'):pill('Exit '+(r.exitCode??'none')+(r.signal?' · '+r.signal:''),'bad');
  const block=(label:string,text:string,cls:string)=>'<div class="output-block"><div class="output-head"><span>'+label+'</span>'+(text?'<button type="button" class="small" data-copy-output>Copy</button>':'')+'</div><pre class="output '+cls+'">'+(text?escapeHtml(text):'<span class="empty-output">(no output)</span>')+'</pre></div>';
  return '<div class="pills">'+status+pill((r.durationMs/1000).toFixed(r.durationMs<10_000?2:1)+' s')+(r.truncated?pill('Output truncated','warn'):'')+'</div>'+
    (r.outputHidden?'<p class="hint">Output is not shown after approval for this command (see “Show output after approval” in its settings). It is still recorded in History.</p>'
      :block('stdout',r.stdout??'','stdout')+(r.stderr?block('stderr',r.stderr,'stderr'):''));
}
function bindCopyButtons(root:ParentNode){root.querySelectorAll<HTMLButtonElement>('[data-copy-output]').forEach(b=>b.onclick=async()=>{const text=b.closest('.output-block')?.querySelector('pre')?.textContent??'';try{await navigator.clipboard.writeText(text);b.textContent='Copied';}catch{b.textContent='Copy failed';}});}
function resultDialog(c:any,r:any){const d=openDialog(c.name,resultView(r)+'<div class="dialog-actions"><button data-dialog-close>Close</button></div>');d.classList.add('wide');bindCopyButtons(d);}
/** Web Run: levels 1-3 run at once; level 4 asks for confirmation and level 5 for the execution password first. */
function runCommand(c:any){
  const run=async(body:Record<string,unknown>)=>api('/api/commands/'+c.id+'/run',{method:'POST',body:JSON.stringify(body)});
  if(c.level<=3){
    const d=openDialog(c.name,'<p class="running">Running on '+escapeHtml(c.targetName??'the target')+'…</p><div class="dialog-actions"><button data-dialog-close>Close</button></div>'); d.classList.add('wide');
    run({}).then(r=>{if(d.open){d.querySelector('.running')!.outerHTML=resultView(r);bindCopyButtons(d);}},err=>{if(d.open)d.querySelector('.running')!.outerHTML='<p class="dialog-error">'+escapeHtml((err as Error).message)+'</p>';});
    return;
  }
  const output=c.showOutputOnApproval?'The output is shown when it finishes.':'Only the exit code is shown when it finishes (output after approval is off for this command).';
  formDialog('Run '+c.name,'<p class="warning">Level '+c.level+' · '+escapeHtml(LEVELS[c.level]!)+'. This runs the command on the target now.</p><p class="hint">'+output+'</p>'+
    (c.level===5?'<label>Execution password<input name="password" type="password" required autocomplete="current-password"></label>':''),'Run',async form=>{
      const r=await run(c.level===5?{password:new FormData(form).get('password')}:{confirmed:true}); setTimeout(()=>resultDialog(c,r));});
}
/** Leaves the approval page: closes the tab when the browser allows it (it was opened from a link), otherwise shows Commands. */
function closeApproval(){
  window.close();
  setTimeout(()=>{history.replaceState(null,'',location.pathname); render('commands');},150);
}
const CLOSE_APPROVAL='<button type="button" data-close-approval>Close</button>';
async function confirmPage(token:string) {
  let info:any; try{info=await api('/api/confirm/'+encodeURIComponent(token));}catch(err){shell('Confirm execution','<article><p class="warning">'+escapeHtml((err as Error).message)+'</p><div class="form-actions">'+CLOSE_APPROVAL+'</div></article>');on('[data-close-approval]',closeApproval);return;}
  const needsPassword=info.command.confirmation==='password';
  shell('Confirm execution','<article><h2>'+escapeHtml(info.command.name)+'</h2><p>'+escapeHtml(info.command.description)+'</p><div class="pills">'+pill('Level '+info.command.level+' · '+LEVELS[info.command.level],info.command.level>=5?'bad':'warn')+pill('Requested by '+info.clientName)+'</div>'+
    '<p class="hint">'+(info.command.showOutputOnApproval?'The output is shown here when the command finishes.':'Only the exit code is shown here; the MCP client receives the full result.')+'</p>'+
    '<form id="confirm-form">'+(needsPassword?'<label>Execution password<input name="password" type="password" autocomplete="current-password" required></label>':'')+'<div class="form-actions"><button class="primary">'+(needsPassword?'Execute command':'Approve & execute')+'</button>'+CLOSE_APPROVAL+'</div><p class="hint">Close leaves the request unanswered; it expires 5 minutes after it was made.</p></form><p id="confirm-error" class="dialog-error"></p><div id="confirm-result"></div></article>');
  const form=document.querySelector<HTMLFormElement>('#confirm-form')!; on('[data-close-approval]',closeApproval);
  form.onsubmit=async e=>{
    e.preventDefault(); const button=form.querySelector<HTMLButtonElement>('button.primary')!; button.disabled=true; button.textContent='Running…';
    const password=needsPassword?String(new FormData(form).get('password')??''):undefined;
    try{
      const r=await api('/api/confirm/'+encodeURIComponent(token),{method:'POST',body:JSON.stringify(password===undefined?{}:{password})});
      form.remove(); document.querySelector('#confirm-error')!.textContent='';
      const out=document.querySelector<HTMLElement>('#confirm-result')!; out.innerHTML='<h3>Executed</h3>'+resultView(r)+'<p class="hint">The result was also sent to '+escapeHtml(info.clientName)+'.</p><div class="form-actions">'+CLOSE_APPROVAL+'</div>'; bindCopyButtons(out); on('[data-close-approval]',closeApproval);
    }catch(err){document.querySelector('#confirm-error')!.textContent=(err as Error).message; button.disabled=false; button.textContent=needsPassword?'Execute command':'Approve & execute';}
  };
}
function settings() {
  shell('Settings','<article>'+sectionHead('Account','')+'<form id="settings-form"><label>Name<input id="settings-name" name="name" required maxlength="120" value="'+escapeHtml(user!.name)+'"></label><label>Email<input id="settings-email" name="email" type="email" required value="'+escapeHtml(user!.email ?? '')+'"></label><p class="hint">Your email is your sign-in name. farcmd never sends email.</p><div class="form-actions"><button class="small primary">Save</button><span id="message" class="form-message" role="status"></span></div></form></article>'+
    '<article>'+sectionHead('Password','')+'<form id="password-form"><label>Current password<input id="current-password" name="currentPassword" type="password" required autocomplete="current-password"></label><label>New password<input id="new-password" name="newPassword" type="password" required minlength="12" maxlength="1024" autocomplete="new-password"></label><label>Repeat new password<input id="repeat-password" name="repeat" type="password" required autocomplete="new-password"></label>'+
    '<p class="hint">At least 12 characters. Changing it signs out your other browser sessions and ends the sign-in of your MCP clients: they keep working for up to an hour and then need to be authorized again.</p><div class="form-actions"><button class="small primary">Change password</button><span id="password-message" class="form-message" role="status"></span></div></form></article>');
  document.querySelector<HTMLFormElement>('#settings-form')!.onsubmit = async e => {
    e.preventDefault(); const message=document.querySelector('#message')!;
    try { const f=new FormData(e.currentTarget as HTMLFormElement); const r=await api('/api/account',{method:'PATCH',body:JSON.stringify({name:f.get('name'),email:f.get('email')})}); user=r.user; message.textContent='Saved.'; }
    catch (err) { message.textContent=(err as Error).message; }
  };
  document.querySelector<HTMLFormElement>('#password-form')!.onsubmit = async e => {
    e.preventDefault(); const form=e.currentTarget as HTMLFormElement; const f=new FormData(form); const message=document.querySelector('#password-message')!;
    if(f.get('newPassword')!==f.get('repeat')){message.textContent='The new passwords do not match.';return;}
    try{
      const r=await api('/api/account/password',{method:'POST',body:JSON.stringify({currentPassword:f.get('currentPassword'),newPassword:f.get('newPassword')})});
      form.reset(); message.textContent='Password changed. '+r.sessionsEnded+' other session'+(r.sessionsEnded===1?'':'s')+' signed out'+(r.refreshTokensRevoked?'; MCP clients need to be authorized again within the hour.':'.');
    }catch(err){message.textContent=(err as Error).message;}
  };
}

async function boot() {
  try { const r=await api('/api/auth/session'); user=r.user; render(...landing()); }
  catch { user=null; render('login'); }
}
boot();
