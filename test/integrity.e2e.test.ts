/**
 * End-to-end capability integrity tests against a real OpenSSH server, a real unprivileged target
 * account, the real root-owned verifier and sudo. The attacker in these tests is the target account
 * itself (it holds an unrestricted key = full shell as that account), which is exactly the threat
 * the verification authority must withstand.
 *
 * Requires root, /usr/sbin/sshd, sudo and python3. Run with: sudo -E npm run test:e2e
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, createHmac } from 'node:crypto';
import { createServer } from 'node:net';
import ssh2 from 'ssh2';
const { Client, utils }=ssh2;

const skipReason=process.getuid?.()!==0?'requires root (run: sudo -E npm run test:e2e)'
  :!existsSync('/usr/sbin/sshd')?'requires the OpenSSH server (/usr/sbin/sshd)'
  :!existsSync('/usr/bin/sudo')?'requires sudo'
  :spawnSync('python3',['--version']).status!==0?'requires python3'
  :false;

process.env.FARCMD_ENCRYPTION_KEY??=randomBytes(32).toString('base64');
process.env.MCP_PUBLIC_URL='https://mcp.e2e.test';

function sh(command:string,input?:string):{status:number|null;stdout:string;stderr:string}{
  const r=spawnSync('/bin/sh',['-c',command],{input,encoding:'utf8'});
  return {status:r.status,stdout:r.stdout,stderr:r.stderr};
}
function must(command:string,input?:string):string{const r=sh(command,input);if(r.status!==0)throw new Error(command+' failed: '+r.stderr);return r.stdout;}
async function freePort():Promise<number>{return new Promise(resolve=>{const s=createServer();s.listen(0,'127.0.0.1',()=>{const p=(s.address() as any).port;s.close(()=>resolve(p));});});}

test('capability integrity verification end to end',{skip:skipReason,timeout:300_000},async t=>{
  const { default: Fastify }=await import('fastify');
  const { default: cookie }=await import('@fastify/cookie');
  const { default: formbody }=await import('@fastify/formbody');
  const { SqliteAuthStore, SqliteUserStore }=await import('../src/storage/sqlite.js');
  const { mountWebApi }=await import('../src/web-api.js');
  const { FarcmdConnectorImpl }=await import('../src/connector.js');
  const { SqliteOAuthGrantStore }=await import('../src/oauth/grants.js');
  const { SqliteVerificationAuthorityStore, verificationKeyAad, verificationSecretAad }=await import('../src/storage/verification-authorities.js');
  const { SqliteCommandInstallationStore }=await import('../src/storage/command-installations.js');
  const { decryptSecret }=await import('../src/crypto-at-rest.js');
  const { executeSshCommand, openSshSession }=await import('../src/ssh.js');
  const { buildVerificationRequest, parseVerificationResponse, newVerificationNonce, verifierPaths }=await import('../src/verification.js');

  const dir=mkdtempSync(join(tmpdir(),'farcmd-e2e-'));
  chmodSync(dir,0o755);
  const account='fce2e'+randomBytes(3).toString('hex');
  const admin='fce2a'+randomBytes(3).toString('hex');
  const port=await freePort();
  let sshd:ChildProcess|undefined; let verifierId:string|undefined;
  const tempSudoers='/etc/sudoers.d/zz-farcmd-e2e-'+admin;
  try{
    // ---------------------------------------------------------------- target host setup
    must('useradd -m -s /bin/bash '+account+' && usermod -p "*" '+account);
    must('mkdir -p /run/sshd && ssh-keygen -q -t ed25519 -N "" -f '+dir+'/host');
    writeFileSync(dir+'/sshd_config',['Port '+port,'ListenAddress 127.0.0.1','HostKey '+dir+'/host','PidFile '+dir+'/sshd.pid','UsePAM no','PasswordAuthentication no','KbdInteractiveAuthentication no','PubkeyAuthentication yes','AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2','AllowUsers '+account+' '+admin,'StrictModes yes','AllowTcpForwarding yes','AllowAgentForwarding yes','PermitTTY yes','LogLevel ERROR',''].join('\n'));
    sshd=spawn('/usr/sbin/sshd',['-D','-e','-f',dir+'/sshd_config'],{stdio:['ignore','ignore','pipe']});
    // The master key is an ordinary unrestricted key of the target account. The same key is the
    // attacker's channel: "full shell as the target account".
    const master=utils.generateKeyPairSync('ed25519',{comment:'farcmd-e2e-master'});
    must('install -d -m 700 -o '+account+' -g '+account+' /home/'+account+'/.ssh && cat > /home/'+account+'/.ssh/authorized_keys && chown '+account+': /home/'+account+'/.ssh/authorized_keys && chmod 600 /home/'+account+'/.ssh/authorized_keys',String(master.public).trim()+'\n');
    const attacker=async(script:string)=>executeSshCommand({hostname:'127.0.0.1',port,username:account,hostFingerprint:fingerprint},{privateKey:String(master.private)},script);
    let fingerprint='';

    // ---------------------------------------------------------------- farcmd setup through the web API
    const store=new SqliteAuthStore(join(dir,'app.sqlite')); const db=store.getDatabase();
    const users=new SqliteUserStore(db);
    const app=Fastify(); await app.register(formbody); await app.register(cookie); await mountWebApi(app,users,store);
    const reg=await app.inject({method:'POST',url:'/api/auth/register',payload:{name:'E2E',email:account+'@example.test',password:'correct horse battery staple'}});
    assert.equal(reg.statusCode,201,reg.body);
    const cookieHeader='farcmd_session='+reg.cookies.find(c=>c.name==='farcmd_session')!.value;
    const userId=reg.json().user.id as string;
    const api=async(method:'GET'|'POST'|'PATCH'|'DELETE',url:string,payload?:unknown)=>{const r=await app.inject({method,url,headers:{cookie:cookieHeader},...(payload!==undefined?{payload:payload as any}:{})});return {status:r.statusCode,body:r.body?JSON.parse(r.body):undefined};};

    for(let i=0;i<50;i++){const r=await executeSshCommand({hostname:'127.0.0.1',port,username:account},{privateKey:String(master.private)},'true',2000);if(!/ECONNREFUSED/.test(r.stderr))break;await new Promise(r=>setTimeout(r,100));}
    const masterKey=await api('POST','/api/ssh/keys',{name:'master',privateKey:String(master.private)}); assert.equal(masterKey.status,201,JSON.stringify(masterKey.body));
    const target=await api('POST','/api/ssh/targets',{name:'e2e',hostname:'127.0.0.1',port,username:account,sshKeyId:masterKey.body.key.id}); assert.equal(target.status,201);
    const targetId=target.body.target.id as string;
    const probe=await api('POST','/api/ssh/targets/'+targetId+'/test'); assert.match(probe.body.fingerprint,/^sha256:/);
    fingerprint=probe.body.fingerprint;
    await api('PATCH','/api/ssh/targets/'+targetId,{hostFingerprint:fingerprint});
    const pinned=await api('POST','/api/ssh/targets/'+targetId+'/test'); assert.equal(pinned.body.ok,true,JSON.stringify(pinned.body)+JSON.stringify(probe.body));

    const mk=async(name:string,level:number,type:'shell'|'bash_script',content:string)=>{const r=await api('POST','/api/commands',{name,description:name,type,content,targetId,level});assert.equal(r.status,201,JSON.stringify(r.body));const id=r.body.command.id as string;const k=await api('POST','/api/commands/'+id+'/key',{});assert.equal(k.status,201,JSON.stringify(k.body));return id;};
    const cmdA=await mk('A',3,'bash_script','echo "A:$(id -un)"\n\n');
    const cmdB=await mk('B',3,'shell','echo B-ok');
    const cmdL1=await mk('L1',1,'shell','echo level-one');
    const cmdL2=await mk('L2',2,'shell','echo level-two');
    const cmdL4=await mk('L4',4,'shell','echo level-four');
    const cmdL5=await mk('L5',5,'shell','echo level-five');
    assert.equal((await api('POST','/api/commands/'+cmdL5+'/execution-password',{password:'level five password'})).status,200);

    new SqliteOAuthGrantStore(db).upsert(userId,'e2e-client','E2E client',[1,2,3,4,5],false);
    const connector=new FarcmdConnectorImpl(db,process.env.MCP_PUBLIC_URL!);
    const ctx={userId,clientId:'e2e-client',accessToken:'unused'};
    const run=(commandId:string,level:1|2|3|4|5)=>connector.executeCommand(ctx,commandId,level);
    const installations=new SqliteCommandInstallationStore(db);
    const scriptFile=(commandId:string)=>'.ssh/farcmd/'+installations.get(userId,commandId)!.remoteScriptPath.split('/').pop();
    const lastHistory=()=>db.prepare('SELECT status,error FROM execution_history WHERE user_id=? ORDER BY started_at DESC, rowid DESC LIMIT 1').get(userId) as any;

    await t.test('capability install writes the exact provisioned script bytes',{timeout:60_000},async()=>{
      const r=await attacker('sha256sum '+scriptFile(cmdA));
      assert.equal(r.stdout.split(' ')[0],installations.get(userId,cmdA)!.scriptSha256);
    });

    await t.test('without a verification authority L3 is blocked and L1/L2 keep their behaviour',{timeout:60_000},async()=>{
      await assert.rejects(()=>run(cmdA,3),/Integrity verification is unavailable/);
      assert.equal(lastHistory().status,'blocked');
      const one=await run(cmdL1,1); assert.ok('stdout' in one); assert.equal((one as any).stdout,'level-one\n');
      const two=await run(cmdL2,2); assert.equal((two as any).stdout,'level-two\n');
    });

    await t.test('automatic verifier install through a separate admin account with its sudo password',{timeout:60_000},async()=>{
      // The command account has no sudo at all; root comes from a different admin account whose sudo needs a password.
      const adminKey=utils.generateKeyPairSync('ed25519',{comment:'farcmd-e2e-admin'});
      must('useradd -m -s /bin/bash '+admin+' && install -d -m 700 -o '+admin+' -g '+admin+' /home/'+admin+'/.ssh && cat > /home/'+admin+'/.ssh/authorized_keys && chown '+admin+': /home/'+admin+'/.ssh/authorized_keys && chmod 600 /home/'+admin+'/.ssh/authorized_keys',String(adminKey.public).trim()+'\n');
      must('chpasswd',admin+':Sudo-Pa55word\n');
      writeFileSync(tempSudoers,admin+' ALL=(root) ALL\n',{mode:0o440});
      const adminMaster=await api('POST','/api/ssh/keys',{name:'admin',privateKey:String(adminKey.private)}); assert.equal(adminMaster.status,201);
      const via=(extra:Record<string,unknown>)=>api('POST','/api/ssh/targets/'+targetId+'/verifier',{installUsername:admin,installKeyId:adminMaster.body.key.id,...extra});
      assert.notEqual((await attacker('sudo -n true')).exitCode,0,'the command account has no root');
      const own=await api('POST','/api/ssh/targets/'+targetId+'/verifier',{});
      assert.equal(own.status,502,'the command account itself cannot install the verifier');
      const none=await via({}); assert.equal(none.status,502); assert.match(none.body.error,/password is required/);
      const wrong=await via({sudoPassword:'wrong password'}); assert.equal(wrong.status,502); assert.match(wrong.body.error,/sudo rejected the password/);
      assert.equal((await api('GET','/api/ssh/targets/'+targetId+'/verifier')).body.verifier.status,'unavailable');
      assert.equal(sh('ls /etc/farcmd/*.key 2>/dev/null').stdout,'','nothing was installed with a rejected password');
      assert.equal((await via({sudoPassword:'bad\nline'})).status,400);
      assert.equal((await via({installUsername:'bad user'})).status,400);
      const r=await via({sudoPassword:'Sudo-Pa55word'});
      assert.equal(r.status,201,JSON.stringify(r.body));
      verifierId=r.body.verifier.id;
      assert.equal(r.body.verifier.status,'active',JSON.stringify(r.body));
      assert.equal(r.body.verification.ok,true,JSON.stringify(r.body.verification));
      // Installed for the command account, not for the admin account.
      assert.match(must('cat '+verifierPaths(verifierId!).sudoers),new RegExp('^'+account+' ALL=\\(root\\) NOPASSWD: ','m'));
      assert.equal(Number((await attacker('grep -c farcmd-verify: .ssh/authorized_keys')).stdout.trim()),1);
      assert.equal(sh('grep -c farcmd-verify: /home/'+admin+'/.ssh/authorized_keys').stdout.trim(),'0');
      const stored=JSON.stringify(db.prepare('SELECT * FROM verification_authorities').all())+JSON.stringify(db.prepare('SELECT * FROM security_events').all());
      assert.ok(!stored.includes('Sudo-Pa55word'),'the sudo password is never stored');
      assert.notEqual(sh("runuser -u "+admin+" -- sudo -n true").status,0,'no sudo timestamp is left behind');
    });
    const paths=verifierPaths(verifierId!);

    await t.test('the target account cannot read the secret, modify the verifier or abuse the sudo rule',{timeout:60_000},async()=>{
      assert.notEqual((await attacker('cat '+paths.secret)).exitCode,0);
      assert.notEqual((await attacker('sudo -n cat '+paths.secret)).exitCode,0);
      assert.notEqual((await attacker('echo "print(1)" >> '+paths.program)).exitCode,0);
      assert.notEqual((await attacker('mv '+paths.program+' /tmp/x')).exitCode,0);
      assert.notEqual((await attacker('sudo -n '+paths.program+' --anything')).exitCode,0);
      // Invoking the real verifier directly only yields an authenticated measurement it cannot forge.
      const direct=await attacker('printf "FARCMD-VERIFY 1 %064d\\n" 0 | sudo -n '+paths.program);
      assert.equal(direct.exitCode,0,direct.stderr); assert.match(direct.stdout,/\nmac [0-9a-f]{64}\n$/);
      assert.equal(must('stat -c %U:%a '+paths.secret).trim(),'root:600');
    });

    await t.test('normal verification then execution succeeds (L3)',{timeout:60_000},async()=>{
      const a=await run(cmdA,3) as any; assert.equal(a.exitCode,0,a.stderr); assert.equal(a.stdout,'A:'+account+'\n');
      const b=await run(cmdB,3) as any; assert.equal(b.stdout,'B-ok\n');
    });

    await t.test('script tampering blocks that command',{timeout:60_000},async()=>{
      await attacker('chmod u+w '+scriptFile(cmdA)+' && echo "echo PWNED" >> '+scriptFile(cmdA));
      await assert.rejects(()=>run(cmdA,3),/Remote script content changed/);
      assert.equal(lastHistory().status,'blocked');
      assert.equal(((await run(cmdB,3)) as any).stdout,'B-ok\n','an untouched capability is still verified independently');
      const original=installations.get(userId,cmdA)!.scriptContent!;
      await attacker('cat > '+scriptFile(cmdA)+' <<"EOF_ORIGINAL"\n'+original+'EOF_ORIGINAL\nchmod 500 '+scriptFile(cmdA));
      assert.equal(((await run(cmdA,3)) as any).stdout,'A:'+account+'\n');
    });

    await t.test('authorized_keys tampering blocks: modified entry and unrestricted duplicate',{timeout:60_000},async()=>{
      const line=installations.get(userId,cmdA)!.authorizedKeyLine;
      const pub=installations.get(userId,cmdA)!.publicKey;
      const blob=pub.split(' ')[1]!;
      await attacker('cp .ssh/authorized_keys /tmp/ak.'+account+' && sed -i "/'+blob.replaceAll('/','\\/')+'/s/^restrict,command=/no-pty,command=/" .ssh/authorized_keys');
      await assert.rejects(()=>run(cmdA,3),/Command authorized_keys entry was modified/);
      assert.equal(((await run(cmdB,3)) as any).exitCode,0,'only the modified capability is blocked');
      await attacker('cp /tmp/ak.'+account+' .ssh/authorized_keys');
      assert.equal(((await run(cmdA,3)) as any).exitCode,0);
      await attacker("printf '%s\\n' '"+pub+"' >> .ssh/authorized_keys");
      await assert.rejects(()=>run(cmdA,3),/appears in 2 authorized_keys entries/);
      await attacker("printf '%s\\n' '"+pub+"' > .ssh/authorized_keys2");
      await attacker('cp /tmp/ak.'+account+' .ssh/authorized_keys');
      await assert.rejects(()=>run(cmdA,3),/appears in 2/,'authorized_keys2 is measured too');
      await attacker('rm -f .ssh/authorized_keys2');
      assert.ok(line.startsWith('restrict,command="'));
      assert.equal(((await run(cmdA,3)) as any).exitCode,0);
    });

    await t.test('unexpected file in the capability namespace blocks every L3 command',{timeout:60_000},async()=>{
      await attacker('echo "echo hi" > .ssh/farcmd/mcp.e2e.test-00000000-0000-4000-8000-000000000000.sh');
      await assert.rejects(()=>run(cmdB,3),/Unexpected file/);
      await attacker('rm .ssh/farcmd/mcp.e2e.test-00000000-0000-4000-8000-000000000000.sh');
      await attacker('ln -s /etc/shadow .ssh/farcmd/zz-link');
      assert.equal(((await run(cmdB,3)) as any).exitCode,0,'symlinks outside the namespace are measured but never followed');
      await attacker('rm .ssh/farcmd/zz-link');
    });

    // Capture one genuine response for the replay/forgery scenarios.
    const authority=new SqliteVerificationAuthorityStore(db).getForTarget(userId,targetId)!;
    const verificationKey=decryptSecret(authority.encryptedPrivateKey,verificationKeyAad(userId,authority.id));
    const secret=Buffer.from(decryptSecret(authority.encryptedSecret,verificationSecretAad(userId,authority.id)),'hex');
    const capturedNonce=newVerificationNonce();
    const captured=await (await openSshSession({hostname:'127.0.0.1',port,username:account,hostFingerprint:fingerprint},{privateKey:verificationKey})).exec('ignored',{stdin:buildVerificationRequest(capturedNonce)});
    assert.equal(captured.exitCode,0,captured.stderr);
    const capturedReport=parseVerificationResponse(captured.stdout,secret,capturedNonce);
    assert.equal(capturedReport.nonce,capturedNonce);
    assert.equal(capturedReport.self.trust,'ok'); assert.equal(capturedReport.python.trust,'ok'); assert.equal(capturedReport.sshd.state,'ok');
    if(process.env.FARCMD_E2E_PRINT)console.log(captured.stdout);

    await t.test('replay: a genuine response is rejected for any other challenge',{timeout:60_000},async()=>{
      assert.throws(()=>parseVerificationResponse(captured.stdout,secret,newVerificationNonce()),/stale or replayed/);
    });

    await t.test('fake verifier returning the old expected state is rejected (MAC)',{timeout:60_000},async()=>{
      const verificationLine=authority.authorizedKeyLine;
      writeFileSync(dir+'/captured',captured.stdout);
      must('install -o '+account+' -m 600 '+dir+'/captured /home/'+account+'/captured');
      // The fake reads the live nonce and replays the captured measurement (all hashes "as expected")
      // under that nonce, with a MAC computed under a key it made up.
      const fake=String.raw`import sys, hmac, hashlib, os
req = sys.stdin.readline().split()
body, _ = open(os.path.expanduser("~/captured")).read().rsplit("mac ", 1)
lines = body.split("\n")
lines[1] = "nonce " + req[2]
body = "\n".join(lines)
sys.stdout.write(body + "mac " + hmac.new(os.urandom(32), body.encode(), hashlib.sha256).hexdigest() + "\n")
`;
      await attacker("cat > fake-verify.py <<'EOF_FAKE'\n"+fake+"EOF_FAKE");
      const forced=verificationLine.replace(/command="[^"]*"/,'command="python3 ~/fake-verify.py"');
      await attacker('cp .ssh/authorized_keys /tmp/ak2.'+account+' && grep -v "farcmd-verify:" /tmp/ak2.'+account+" > .ssh/authorized_keys && printf '%s\\n' '"+forced+"' >> .ssh/authorized_keys");
      await assert.rejects(()=>run(cmdA,3),/invalid MAC/);
      assert.equal(lastHistory().status,'blocked');
      // Pure replay of the captured genuine response (valid MAC, old nonce).
      await attacker("printf '%s\\n' 'cat ~/captured' > fake-replay.sh && chmod +x fake-replay.sh && grep -v 'farcmd-verify:' /tmp/ak2."+account+" > .ssh/authorized_keys && printf '%s\\n' '"+verificationLine.replace(/command="[^"]*"/,'command="sh ~/fake-replay.sh"')+"' >> .ssh/authorized_keys");
      await assert.rejects(()=>run(cmdA,3),/stale or replayed/);
      // A MAC computed with the real secret would be needed; the account cannot read it.
      const forgedWithRealKey=createHmac('sha256',secret).update('x').digest('hex');
      assert.equal(forgedWithRealKey.length,64);
      await attacker('cp /tmp/ak2.'+account+' .ssh/authorized_keys && rm -f fake-verify.py fake-replay.sh');
      assert.equal(((await run(cmdA,3)) as any).exitCode,0);
    });

    await t.test('damaged verification infrastructure blocks L3–L5 (no fallback)',{timeout:60_000},async()=>{
      must('mv '+paths.program+' '+paths.program+'.moved');
      await assert.rejects(()=>run(cmdA,3),/Verifier failed/);
      must('mv '+paths.program+'.moved '+paths.program);
      must('cp '+paths.secret+' '+dir+'/secret.bak && printf "%s\\n" '+randomBytes(32).toString('hex')+' > '+paths.secret);
      await assert.rejects(()=>run(cmdA,3),/invalid MAC/);
      must('cp '+dir+'/secret.bak '+paths.secret);
      must('chmod 644 '+paths.secret);
      await assert.rejects(()=>run(cmdA,3),/secret is not root-only/);
      must('chmod 600 '+paths.secret);
      assert.equal(((await run(cmdA,3)) as any).exitCode,0);
    });

    await t.test('verification and forced-command capabilities cannot be turned into a shell or tunnel',{timeout:60_000},async()=>{
      const connect=(privateKey:string,extra:Record<string,unknown>={})=>new Promise<InstanceType<typeof Client>>((resolve,reject)=>{const c=new Client();c.once('ready',()=>resolve(c));c.once('error',reject);c.connect({host:'127.0.0.1',port,username:account,privateKey,hostHash:'sha256',hostVerifier:(f:string)=>'sha256:'+f===fingerprint,...extra});});
      const probe=async(c:InstanceType<typeof Client>)=>({
        pty:await new Promise<string>(resolve=>c.exec('tty',{pty:true},(err,stream)=>{if(err)return resolve('refused');let out='';stream.on('data',(d:Buffer)=>out+=d);stream.on('close',()=>resolve(/\/dev\/pts/.test(out)?'opened':'no-pty'));})),
        forwardOut:await new Promise<string>(resolve=>c.forwardOut('127.0.0.1',0,'127.0.0.1',port,(err,stream)=>{if(err)return resolve('refused');stream.destroy();resolve('opened');})),
        forwardIn:await new Promise<string>(resolve=>c.forwardIn('127.0.0.1',0,err=>resolve(err?'refused':'opened'))),
        agent:await new Promise<string>(resolve=>{try{c.exec('true',{agentForward:true},(err,stream)=>{if(err)return resolve('refused');stream.on('close',()=>resolve('opened'));stream.resume();stream.end();});}catch{resolve('refused');}}),
      });
      // Positive control: the same probes succeed with an unrestricted key on this sshd, so "refused" below is meaningful.
      const control=await connect(String(master.private),{agent:join(dir,'no-agent.sock')});
      try{assert.deepEqual(await probe(control),{pty:'opened',forwardOut:'opened',forwardIn:'opened',agent:'opened'});}finally{control.end();}
      for(const [label,key] of [['verification',verificationKey],['command',decryptSecret(installations.get(userId,cmdB)!.encryptedPrivateKey,'command-installation:'+userId+':'+installations.get(userId,cmdB)!.id)]] as const){
        const exec=await executeSshCommand({hostname:'127.0.0.1',port,username:account,hostFingerprint:fingerprint},{privateKey:key},'id; cat /etc/passwd');
        assert.doesNotMatch(exec.stdout,/uid=|root:x:0/,label+': client command must be ignored');
        const c=await connect(key,{agent:join(dir,'no-agent.sock')});
        try{
          const result=await probe(c);
          assert.notEqual(result.pty,'opened',label+': no PTY');
          assert.equal(result.forwardOut,'refused',label+': no local port forwarding');
          assert.equal(result.forwardIn,'refused',label+': no remote port forwarding');
          assert.equal(result.agent,'refused',label+': no agent forwarding');
        }finally{c.end();}
      }
    });

    await t.test('L4 (human approval) and L5 (password) verify after confirmation',{timeout:60_000},async()=>{
      const p4=await run(cmdL4,4) as any; assert.equal(p4.pending,true);
      const a4=await api('POST','/api/confirm/'+encodeURIComponent(p4.confirmationToken),{}); assert.equal(a4.status,200,JSON.stringify(a4.body)); assert.equal(a4.body.stdout,'level-four\n');
      const p5=await run(cmdL5,5) as any; assert.equal(p5.pending,true);
      const a5=await api('POST','/api/confirm/'+encodeURIComponent(p5.confirmationToken),{password:'level five password'}); assert.equal(a5.status,200,JSON.stringify(a5.body)); assert.equal(a5.body.stdout,'level-five\n');
    });

    await t.test('master deletion: verification and execution continue, provisioning is unavailable',{timeout:60_000},async()=>{
      assert.equal((await api('DELETE','/api/ssh/keys/'+masterKey.body.key.id)).status,200);
      assert.equal(((await run(cmdA,3)) as any).stdout,'A:'+account+'\n');
      assert.equal(((await run(cmdB,3)) as any).stdout,'B-ok\n');
      const p4=await run(cmdL4,4) as any;
      assert.equal((await api('POST','/api/confirm/'+encodeURIComponent(p4.confirmationToken),{})).body.stdout,'level-four\n');
      const p5=await run(cmdL5,5) as any;
      assert.equal((await api('POST','/api/confirm/'+encodeURIComponent(p5.confirmationToken),{password:'level five password'})).body.stdout,'level-five\n');
      assert.equal((await api('POST','/api/ssh/targets/'+targetId+'/verifier/verify',{})).body.verification.ok,true);
      // Provisioning authority is gone.
      const created=await api('POST','/api/commands',{name:'new',description:'new',type:'shell',content:'echo new',targetId,level:3});
      const provision=await api('POST','/api/commands/'+created.body.command.id+'/key',{});
      assert.equal(provision.status,400); assert.match(provision.body.error,/master key is missing/);
      const repair=await api('POST','/api/ssh/targets/'+targetId+'/verifier',{});
      assert.equal(repair.status,400); assert.match(repair.body.error,/master key is missing/);
      // Removal cannot happen remotely; it is recorded in the ledger and the stale script is tolerated.
      const removed=await api('DELETE','/api/commands/'+cmdB+'/key'); assert.equal(removed.body.remoteCleanupPending,true);
      assert.equal(((await run(cmdA,3)) as any).exitCode,0);
    });

    await t.test('repair without a master: manual root install script',{timeout:60_000},async()=>{
      const manual=await api('POST','/api/ssh/targets/'+targetId+'/verifier/manual',{});
      assert.equal(manual.status,201); assert.equal(manual.body.verifier.status,'pending');
      await assert.rejects(()=>run(cmdA,3),/not been activated/);
      must('sh -s',manual.body.installScript); // the administrator runs it as root
      const verified=await api('POST','/api/ssh/targets/'+targetId+'/verifier/verify',{});
      assert.equal(verified.body.verifier.status,'active',JSON.stringify(verified.body)); assert.equal(verified.body.verification.ok,true);
      assert.equal(((await run(cmdA,3)) as any).exitCode,0);
      // The old verification key was replaced, not duplicated.
      assert.equal(Number((await attacker('grep -c farcmd-verify: .ssh/authorized_keys')).stdout.trim()),1);
    });

    await t.test('deleting the verification authority blocks L3 but not L1',{timeout:60_000},async()=>{
      const removed=await api('DELETE','/api/ssh/targets/'+targetId+'/verifier');
      assert.equal(removed.body.removed,false); assert.match(removed.body.uninstallScript,/rm -f/);
      await assert.rejects(()=>run(cmdA,3),/Integrity verification is unavailable/);
      assert.equal(((await run(cmdL1,1)) as any).stdout,'level-one\n');
      must('sh -s',removed.body.uninstallScript);
      assert.equal(existsSync(paths.program)||existsSync(paths.secret)||existsSync(paths.sudoers),false);
    });
  }finally{
    if(sshd&&sshd.exitCode===null){const exited=new Promise(r=>sshd!.once('exit',r));sshd.kill();await exited;}
    sh('pkill -KILL -u '+account+' 2>/dev/null; pkill -KILL -u '+admin+' 2>/dev/null; sleep 0.2'); sh('userdel -r '+admin+' 2>/dev/null');
    const removedAccount=sh('userdel -r '+account);
    if(removedAccount.status!==0&&sh('getent passwd '+account).status===0)console.error('farcmd e2e: could not remove test account '+account+': '+removedAccount.stderr);
    rmSync(tempSudoers,{force:true});
    if(verifierId){const p=verifierPaths(verifierId);for(const f of [p.program,p.secret,p.sudoers,p.program+'.moved'])rmSync(f,{force:true});}
    rmSync(dir,{recursive:true,force:true});
  }
});
