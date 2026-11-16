export interface Env { DB: D1Database; APP_ORIGIN?: string; BOOTSTRAP_SECRET?: string }
const enc=new TextEncoder(), TTL=604800, ITER=310000;
const b64=(b:Uint8Array)=>btoa(String.fromCharCode(...b)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
const un64=(s:string)=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")+"===".slice((s.length+3)%4)),c=>c.charCodeAt(0));
const random=(n=32)=>{const b=new Uint8Array(n);crypto.getRandomValues(b);return b64(b)};
const sha=async(s:string)=>b64(new Uint8Array(await crypto.subtle.digest("SHA-256",enc.encode(s))));
async function hashPassword(p:string,s=random(16)){const k=await crypto.subtle.importKey("raw",enc.encode(p),"PBKDF2",false,["deriveBits"]);const bits=await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:un64(s),iterations:ITER},k,256);return s+":"+b64(new Uint8Array(bits))}
async function verify(p:string,h:string){const [s]=h.split(":");return !!s&&(await hashPassword(p,s))===h}
const json=(v:unknown,status=200,h:HeadersInit={})=>new Response(JSON.stringify(v),{status,headers:{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store",...h}});
function cookie(t:string,age:number){return `fluxo_session=${t}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=${age}`}
function getCookie(r:Request){return r.headers.get("Cookie")?.split(";").map(x=>x.trim()).find(x=>x.startsWith("fluxo_session="))?.slice(14)??null}
function cors(r:Request,e:Env){const h=new Headers({"Vary":"Origin"}),o=r.headers.get("Origin");if(o&&e.APP_ORIGIN&&o===e.APP_ORIGIN){h.set("Access-Control-Allow-Origin",o);h.set("Access-Control-Allow-Credentials","true");h.set("Access-Control-Allow-Methods","GET,POST,OPTIONS");h.set("Access-Control-Allow-Headers","Content-Type, Authorization")}return h}
async function audit(e:Env,u:string|null,a:string,d:string){await e.DB.prepare("INSERT INTO auditoria(id,usuario_id,acao,entidade) VALUES(?,?,?,?)").bind(crypto.randomUUID(),u,a,d).run()}
async function userFrom(r:Request,e:Env){const t=getCookie(r);if(!t)return null;return e.DB.prepare("SELECT u.id,u.nome,u.email,u.papel FROM sessoes s JOIN usuarios u ON u.id=s.usuario_id WHERE s.token_hash=? AND s.revogada_em IS NULL AND s.expira_em>datetime('now') AND u.status='ativo'").bind(await sha(t)).first()}
async function body(r:Request){if(!r.headers.get("Content-Type")?.includes("application/json"))throw Error("content-type");return await r.json() as any}
export default {async fetch(r:Request,e:Env):Promise<Response>{
 const u=new URL(r.url),h=cors(r,e),origin=r.headers.get("Origin");
 if(r.method==="OPTIONS")return new Response(null,{status:204,headers:h});
 if(u.pathname.startsWith("/api/")&&origin&&(!e.APP_ORIGIN||origin!==e.APP_ORIGIN))return json({error:"Origem não autorizada"},403,h);
 if(r.method==="GET"&&u.pathname==="/api/health"){try{const x=await e.DB.prepare("SELECT COUNT(*) total FROM sqlite_master WHERE type='table' AND name NOT LIKE '_cf_%'").first<any>();return json({status:"ok",database:"connected",applicationTables:x?.total??0},200,h)}catch{return json({status:"error",database:"unavailable"},503,h)}}
 if(r.method==="POST"&&u.pathname==="/api/auth/setup-owners"){
  if(!e.BOOTSTRAP_SECRET)return json({error:"Configuração inicial indisponível"},503,h);
  const key=r.headers.get("Authorization")?.replace(/^Bearer\s+/i,"")??"";
  if(!key||key.length!==e.BOOTSTRAP_SECRET.length||await sha(key)!==await sha(e.BOOTSTRAP_SECRET))return json({error:"Não autorizado"},401,h);
  try{const b=await body(r),owners=b.owners;if(!Array.isArray(owners)||owners.length<1||owners.length>2)return json({error:"Informe um ou dois sócios"},400,h);
   const count=await e.DB.prepare("SELECT COUNT(*) total FROM usuarios").first<any>();if(count.total!==0)return json({error:"Configuração inicial já concluída"},409,h);
   const data=owners.map((x:any)=>({nome:String(x.nome??"").trim(),email:String(x.email??"").trim().toLowerCase(),senha:String(x.senha??"")}));
   if(data.some(x=>x.nome.length<2||x.nome.length>100||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x.email)||x.senha.length<12||x.senha.length>128)||(data.length===2&&data[0].email===data[1].email))return json({error:"Confira nomes, e-mails diferentes e senhas de 12 a 128 caracteres"},400,h);
   await e.DB.batch(await Promise.all(data.map(async x=>e.DB.prepare("INSERT INTO usuarios(id,nome,email,senha_hash,papel,status) VALUES(?,?,?,?,'socio','ativo')").bind(crypto.randomUUID(),x.nome,x.email,await hashPassword(x.senha)))));
   await audit(e,null,"configuracao_inicial","usuarios");return json({status:"configured",ownersCreated:data.length},201,h)
  }catch{return json({error:"Não foi possível concluir a configuração inicial"},400,h)}
 }
 if(r.method==="POST"&&u.pathname==="/api/auth/login"){
  try{const b=await body(r),email=String(b.email??"").trim().toLowerCase(),password=String(b.senha??""),ip=r.headers.get("CF-Connecting-IP")??"unknown",key=await sha(email+"|"+ip),now=Math.floor(Date.now()/1000);
   await e.DB.prepare("DELETE FROM tentativas_login WHERE ocorreu_em<?").bind(now-900).run();
   const attempts=await e.DB.prepare("SELECT COUNT(*) total FROM tentativas_login WHERE chave=? AND ocorreu_em>?").bind(key,now-900).first<any>();
   if(attempts.total>=8)return json({error:"Muitas tentativas. Aguarde 15 minutos."},429,h);
   const account=await e.DB.prepare("SELECT id,nome,email,papel,senha_hash FROM usuarios WHERE email=? AND status='ativo'").bind(email).first<any>();
   if(!account?.senha_hash||!await verify(password,account.senha_hash)){await e.DB.prepare("INSERT INTO tentativas_login(id,chave,ocorreu_em) VALUES(?,?,?)").bind(crypto.randomUUID(),key,now).run();return json({error:"E-mail ou senha inválidos"},401,h)}
   await e.DB.prepare("DELETE FROM tentativas_login WHERE chave=?").bind(key).run();
   const token=random(),expires=new Date(Date.now()+TTL*1000).toISOString();
   await e.DB.prepare("INSERT INTO sessoes(id,usuario_id,token_hash,expira_em) VALUES(?,?,?,?)").bind(crypto.randomUUID(),account.id,await sha(token),expires).run();
   await audit(e,account.id,"login","sessao");return json({user:{id:account.id,nome:account.nome,email:account.email,papel:account.papel}},200,{...Object.fromEntries(h),"Set-Cookie":cookie(token,TTL)})
  }catch{return json({error:"Não foi possível realizar o login"},400,h)}
 }
 if(r.method==="GET"&&u.pathname==="/api/auth/me"){const x=await userFrom(r,e);return x?json({user:x},200,h):json({user:null},401,h)}
 if(r.method==="POST"&&u.pathname==="/api/auth/logout"){const t=getCookie(r);if(t)await e.DB.prepare("UPDATE sessoes SET revogada_em=datetime('now') WHERE token_hash=? AND revogada_em IS NULL").bind(await sha(t)).run();return json({status:"logged_out"},200,{...Object.fromEntries(h),"Set-Cookie":cookie("",0)})}
 return json({error:"Not found"},404,h)
}};