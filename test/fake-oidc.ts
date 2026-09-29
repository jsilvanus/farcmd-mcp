import { createServer, type Server } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

export interface FakeOidcUser { sub:string; email?:string; email_verified?:boolean; name?:string; }

/**
 * A minimal OpenID provider for tests: discovery, JWKS, authorize (redirects straight back with a code for
 * `nextUser`), token (checks client secret and PKCE, returns an RS256 ID token) and userinfo.
 */
export async function startFakeOidc(options:{clientId:string;clientSecret:string}){
  const {publicKey,privateKey}=await generateKeyPair('RS256');
  const jwk={...(await exportJWK(publicKey)),kid:'k1',alg:'RS256',use:'sig'};
  const codes=new Map<string,{user:FakeOidcUser;nonce:string;challenge:string;redirectUri:string}>();
  const accessTokens=new Map<string,FakeOidcUser>();
  const state={nextUser:{sub:'user-1',email:'person@example.test',email_verified:true,name:'Person'} as FakeOidcUser,idTokenOmitsEmail:false,nonceOverride:undefined as string|undefined};
  let issuer='';
  const server:Server=createServer(async(req,res)=>{
    const url=new URL(req.url??'/',issuer);
    const json=(status:number,body:unknown)=>{res.writeHead(status,{'content-type':'application/json'});res.end(JSON.stringify(body));};
    if(url.pathname==='/.well-known/openid-configuration')return json(200,{issuer,authorization_endpoint:issuer+'/authorize',token_endpoint:issuer+'/token',userinfo_endpoint:issuer+'/userinfo',jwks_uri:issuer+'/jwks',response_types_supported:['code'],subject_types_supported:['public'],id_token_signing_alg_values_supported:['RS256'],code_challenge_methods_supported:['S256'],token_endpoint_auth_methods_supported:['client_secret_basic']});
    if(url.pathname==='/jwks')return json(200,{keys:[jwk]});
    if(url.pathname==='/authorize'){
      const p=url.searchParams;
      if(p.get('client_id')!==options.clientId||p.get('response_type')!=='code'||p.get('code_challenge_method')!=='S256'||!p.get('scope')?.split(' ').includes('openid'))return json(400,{error:'invalid_request'});
      const code=randomBytes(16).toString('hex');
      codes.set(code,{user:state.nextUser,nonce:p.get('nonce')??'',challenge:p.get('code_challenge')??'',redirectUri:p.get('redirect_uri')??''});
      const back=new URL(p.get('redirect_uri')!); back.searchParams.set('code',code); back.searchParams.set('state',p.get('state')??'');
      res.writeHead(302,{location:back.toString()}); return res.end();
    }
    if(url.pathname==='/token'&&req.method==='POST'){
      let raw=''; for await(const chunk of req)raw+=chunk;
      const body=new URLSearchParams(raw);
      const [id,secret]=Buffer.from(String(req.headers.authorization??'').replace(/^Basic /,''),'base64').toString().split(':').map(decodeURIComponent);
      if(id!==options.clientId||secret!==options.clientSecret)return json(401,{error:'invalid_client'});
      const grant=codes.get(body.get('code')??''); codes.delete(body.get('code')??'');
      if(!grant||body.get('redirect_uri')!==grant.redirectUri||createHash('sha256').update(body.get('code_verifier')??'').digest('base64url')!==grant.challenge)return json(400,{error:'invalid_grant'});
      const {sub,...profile}=grant.user;
      const idToken=await new SignJWT({nonce:state.nonceOverride??grant.nonce,...(state.idTokenOmitsEmail?{}:profile)}).setProtectedHeader({alg:'RS256',kid:'k1'}).setIssuer(issuer).setAudience(options.clientId).setSubject(sub).setIssuedAt().setExpirationTime('5m').sign(privateKey);
      const accessToken=randomBytes(16).toString('hex'); accessTokens.set(accessToken,grant.user);
      return json(200,{access_token:accessToken,token_type:'Bearer',expires_in:300,id_token:idToken});
    }
    if(url.pathname==='/userinfo'){
      const user=accessTokens.get(String(req.headers.authorization??'').replace(/^Bearer /,''));
      return user?json(200,user):json(401,{error:'invalid_token'});
    }
    json(404,{error:'not_found'});
  });
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  issuer='http://127.0.0.1:'+(server.address() as AddressInfo).port;
  return {issuer,state,close:()=>new Promise<void>(resolve=>server.close(()=>resolve()))};
}
