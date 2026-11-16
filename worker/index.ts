export interface Env { DB: D1Database; APP_ORIGIN?: string; BOOTSTRAP_SECRET?: string }
const enc=new TextEncoder(), TTL=604800, ITER=100000;
const b64=(b:Uint8Array)=>btoa(String.fromCharCode(...b)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
const un64=(s:string)=>Uint8Array.from(atob(s.replace(/-/g,"+").replace(/_/g,"/")+"===".slice((s.length+3)%4)),c=>c.charCodeAt(0));
const random=(n=32)=>{const b=new Uint8Array(n);crypto.getRandomValues(b);return b64(b)};
const sha=async(s:string)=>b64(new Uint8Array(await crypto.subtle.digest("SHA-256",enc.encode(s))));
async function hashPassword(p:string,s=random(16)){const k=await crypto.subtle.importKey("raw",enc.encode(p),"PBKDF2",false,["deriveBits"]);const bits=await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:un64(s),iterations:ITER},k,256);return "v2$"+ITER+"$"+s+"$"+b64(new Uint8Array(bits))}
function passwordParams(h:string){if(h.startsWith("v2$")){const [,iterations,salt]=h.split("$");return {salt,iterations:Number(iterations)}}const [salt]=h.split(":");return {salt,iterations:310000}}
function passwordDigest(h:string){return h.startsWith("v2$")?h.split("$")[3]:h.split(":")[1]}
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
   const data=owners.map((x:any)=>({nome:String(x.nome??"").trim(),email:String(x.email??"").trim().toLowerCase(),senha_hash:String(x.senha_hash??""),salt:String(x.salt??"")}));
   if(data.some(x=>x.nome.length<2||x.nome.length>100||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x.email)||x.senha_hash.length!==43||x.salt.length<20||x.salt.length>24)||(data.length===2&&data[0].email===data[1].email))return json({error:"Confira nomes, e-mails diferentes e senhas de 8 a 128 caracteres"},400,h);
   await e.DB.batch(await Promise.all(data.map(async x=>e.DB.prepare("INSERT INTO usuarios(id,nome,email,senha_hash,papel,status) VALUES(?,?,?,?,'socio','ativo')").bind(crypto.randomUUID(),x.nome,x.email,"v2$"+ITER+"$"+x.salt+"$"+x.senha_hash))));
   await audit(e,null,"configuracao_inicial","usuarios");return json({status:"configured",ownersCreated:data.length},201,h)
  }catch(error){console.error("auth_setup_error",{name:error instanceof Error?error.name:"UnknownError",message:error instanceof Error?error.message:"Unknown error"});return json({error:"Não foi possível concluir a configuração inicial",reference:"auth_setup_error"},500,h)}
 }
 if(r.method==="GET"&&u.pathname==="/api/auth/login-info"){const email=(u.searchParams.get("email")??"").trim().toLowerCase();if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return json({error:"E-mail inválido"},400,h);const account=await e.DB.prepare("SELECT senha_hash FROM usuarios WHERE email=? AND status='ativo'").bind(email).first<any>();if(!account?.senha_hash)return json({error:"Conta não encontrada"},404,h);const nonce=random(32),expires=Math.floor(Date.now()/1000)+120;await e.DB.prepare("DELETE FROM login_challenges WHERE expires_at<?").bind(Math.floor(Date.now()/1000)).run();await e.DB.prepare("INSERT INTO login_challenges(id,email,nonce_hash,expires_at) VALUES(?,?,?,?)").bind(crypto.randomUUID(),email,await sha(nonce),expires).run();return json({...passwordParams(account.senha_hash),nonce},200,h)}
 if(r.method==="POST"&&u.pathname==="/api/auth/login"){
  try{const b=await body(r),email=String(b.email??"").trim().toLowerCase(),proof=String(b.proof??""),nonce=String(b.nonce??""),ip=r.headers.get("CF-Connecting-IP")??"unknown",key=await sha(email+"|"+ip),now=Math.floor(Date.now()/1000);
   await e.DB.prepare("DELETE FROM tentativas_login WHERE ocorreu_em<?").bind(now-900).run();
   const attempts=await e.DB.prepare("SELECT COUNT(*) total FROM tentativas_login WHERE chave=? AND ocorreu_em>?").bind(key,now-900).first<any>();
   if(attempts.total>=8)return json({error:"Muitas tentativas. Aguarde 15 minutos."},429,h);
   const account=await e.DB.prepare("SELECT id,nome,email,papel,senha_hash FROM usuarios WHERE email=? AND status='ativo'").bind(email).first<any>();
   const challenge=nonce?await e.DB.prepare("SELECT id FROM login_challenges WHERE email=? AND nonce_hash=? AND expires_at>?").bind(email,await sha(nonce),now).first<any>():null;if(challenge)await e.DB.prepare("DELETE FROM login_challenges WHERE id=?").bind(challenge.id).run();let valid=false;if(account?.senha_hash&&challenge&&proof){const key=await crypto.subtle.importKey("raw",un64(passwordDigest(account.senha_hash)),{name:"HMAC",hash:"SHA-256"},false,["verify"]);valid=await crypto.subtle.verify("HMAC",key,un64(proof),enc.encode(nonce))}if(!account?.senha_hash||!valid){await e.DB.prepare("INSERT INTO tentativas_login(id,chave,ocorreu_em) VALUES(?,?,?)").bind(crypto.randomUUID(),key,now).run();return json({error:"E-mail ou senha inválidos"},401,h)}
   await e.DB.prepare("DELETE FROM tentativas_login WHERE chave=?").bind(key).run();
   const token=random(),expires=new Date(Date.now()+TTL*1000).toISOString().slice(0,19).replace("T"," ");
   await e.DB.prepare("INSERT INTO sessoes(id,usuario_id,token_hash,expira_em) VALUES(?,?,?,?)").bind(crypto.randomUUID(),account.id,await sha(token),expires).run();
   await audit(e,account.id,"login","sessao");return json({user:{id:account.id,nome:account.nome,email:account.email,papel:account.papel}},200,{...Object.fromEntries(h),"Set-Cookie":cookie(token,TTL)})
  }catch(error){console.error("auth_login_error",{name:error instanceof Error?error.name:"UnknownError",message:error instanceof Error?error.message:"Unknown error"});return json({error:"Não foi possível realizar o login",reference:"auth_login_error"},500,h)}
 }

 const current=await userFrom(r,e);
 if(u.pathname.startsWith("/api/")&&u.pathname!=="/api/health"&&u.pathname!=="/api/auth/me"&&u.pathname!=="/api/auth/login-info"&&u.pathname.startsWith("/api/")&&!u.pathname.startsWith("/api/auth/")&&!current)return json({error:"Sessão expirada. Entre novamente."},401,h);
 if(r.method==="GET"&&u.pathname==="/api/dashboard"){
  const [clients,appointments,today,revenue,openAppointments,services]=await Promise.all([
   e.DB.prepare("SELECT COUNT(*) total FROM clientes").first<any>(),
   e.DB.prepare("SELECT COUNT(*) total FROM atendimentos").first<any>(),
   e.DB.prepare("SELECT COUNT(*) total FROM atendimentos WHERE substr(data_hora,1,10)=date('now','-3 hours') AND status<>'cancelado'").first<any>(),
   e.DB.prepare("SELECT COALESCE(SUM(valor_centavos),0) total FROM pagamentos WHERE status='recebido' AND substr(COALESCE(recebido_em,criado_em),1,7)=strftime('%Y-%m','now','-3 hours')").first<any>(),
   e.DB.prepare("SELECT a.id,a.data_hora,a.status,a.valor_centavos,c.nome cliente,COALESCE(v.modelo,'') veiculo,COALESCE(v.placa,'') placa FROM atendimentos a JOIN clientes c ON c.id=a.cliente_id LEFT JOIN veiculos v ON v.id=a.veiculo_id WHERE a.status IN('agendado','em_andamento') ORDER BY a.data_hora LIMIT 6").all<any>(),
   e.DB.prepare("SELECT COUNT(*) total FROM catalogo_servicos WHERE ativo=1").first<any>()
  ]);
  return json({clientes:clients?.total??0,atendimentos:appointments?.total??0,hoje:today?.total??0,faturamento_centavos:revenue?.total??0,servicos:services?.total??0,proximos:openAppointments.results??[]},200,h)
 }
 if(r.method==="GET"&&u.pathname==="/api/clientes"){
  const q=(u.searchParams.get("q")??"").trim();
  const rows=await e.DB.prepare("SELECT c.id,c.nome,c.telefone,c.email,c.observacoes,c.criado_em,(SELECT COUNT(*) FROM veiculos v WHERE v.cliente_id=c.id) veiculos FROM clientes c WHERE (?='' OR c.nome LIKE '%'||?||'%' OR COALESCE(c.telefone,'') LIKE '%'||?||'%') ORDER BY c.nome LIMIT 200").bind(q,q,q).all<any>();
  return json({clientes:rows.results??[]},200,h)
 }
 if(r.method==="POST"&&u.pathname==="/api/clientes"){
  try{const b=await body(r),nome=String(b.nome??"").trim(),telefone=String(b.telefone??"").trim(),email=String(b.email??"").trim(),observacoes=String(b.observacoes??"").trim();
   if(nome.length<2||nome.length>120||telefone.length<8||telefone.length>30||email.length>160||observacoes.length>1000)return json({error:"Informe o nome e um celular válido para cadastrar o cliente."},400,h);
   const id=crypto.randomUUID();await e.DB.prepare("INSERT INTO clientes(id,nome,telefone,email,observacoes) VALUES(?,?,?,?,?)").bind(id,nome,telefone||null,email||null,observacoes||null).run();
   await audit(e,(current as any).id,"cliente_criado","clientes");return json({id,nome,telefone,email,observacoes},201,h)
  }catch(error){console.error("cliente_create_error",{message:error instanceof Error?error.message:"unknown"});return json({error:"Não foi possível cadastrar o cliente."},500,h)}
 }
 if(r.method==="GET"&&u.pathname==="/api/veiculos"){
  const clienteId=(u.searchParams.get("cliente_id")??"").trim();
  const rows=await e.DB.prepare("SELECT v.id,v.cliente_id,v.marca,v.modelo,v.ano,v.placa,v.cor,v.observacoes,c.nome cliente FROM veiculos v JOIN clientes c ON c.id=v.cliente_id WHERE (?='' OR v.cliente_id=?) ORDER BY c.nome,v.modelo").bind(clienteId,clienteId).all<any>();
  return json({veiculos:rows.results??[]},200,h)
 }
 if(r.method==="POST"&&u.pathname==="/api/veiculos"){
  try{const b=await body(r),clienteId=String(b.cliente_id??""),modelo=String(b.modelo??"").trim(),placa=String(b.placa??"").trim().toUpperCase(),cor=String(b.cor??"").trim(),ano=b.ano==null||b.ano===""?null:Number(b.ano);
   if(!clienteId||modelo.length<2||modelo.length>100||placa.length>12||cor.length>40||(ano!==null&&(!Number.isInteger(ano)||ano<1950||ano>2100)))return json({error:"Informe cliente e modelo; placa, ano e cor são opcionais."},400,h);
   const client=await e.DB.prepare("SELECT id FROM clientes WHERE id=?").bind(clienteId).first<any>();if(!client)return json({error:"Cliente não encontrado."},404,h);
   const id=crypto.randomUUID();await e.DB.prepare("INSERT INTO veiculos(id,cliente_id,modelo,placa,ano,cor) VALUES(?,?,?,?,?,?)").bind(id,clienteId,modelo,placa||null,ano,cor||null).run();
   await audit(e,(current as any).id,"veiculo_criado","veiculos");return json({id,cliente_id:clienteId,modelo,placa,ano,cor},201,h)
  }catch(error){console.error("veiculo_create_error",{message:error instanceof Error?error.message:"unknown"});return json({error:"Não foi possível cadastrar o veículo."},500,h)}
 }
 if(r.method==="GET"&&u.pathname==="/api/servicos"){
  const rows=await e.DB.prepare("SELECT id,nome,descricao,preco_sugerido_centavos FROM catalogo_servicos WHERE ativo=1 ORDER BY nome").all<any>();
  return json({servicos:rows.results??[]},200,h)
 }
 if(r.method==="POST"&&u.pathname==="/api/servicos"){
  try{const b=await body(r),nome=String(b.nome??"").trim(),descricao=String(b.descricao??"").trim(),preco=Math.round(Number(b.preco??0)*100);
   if(nome.length<2||nome.length>100||descricao.length>500||!Number.isSafeInteger(preco)||preco<0||preco>100000000)return json({error:"Confira nome, descrição e preço do serviço."},400,h);
   const id=crypto.randomUUID();await e.DB.prepare("INSERT INTO catalogo_servicos(id,nome,descricao,preco_sugerido_centavos) VALUES(?,?,?,?)").bind(id,nome,descricao||null,preco).run();
   await audit(e,(current as any).id,"servico_criado","catalogo_servicos");return json({id,nome,descricao,preco_sugerido_centavos:preco},201,h)
  }catch(error){console.error("servico_create_error",{message:error instanceof Error?error.message:"unknown"});return json({error:"Não foi possível cadastrar o serviço."},500,h)}
 }
 if(r.method==="GET"&&u.pathname==="/api/atendimentos"){
  const rows=await e.DB.prepare("SELECT a.id,a.veiculo_id,a.data_hora,a.status,a.valor_centavos,a.observacoes,c.nome cliente,c.telefone,COALESCE(v.modelo,'') veiculo,COALESCE(v.placa,'') placa,COALESCE((SELECT group_concat(s.descricao,', ') FROM atendimento_servicos s WHERE s.atendimento_id=a.id),'') servicos FROM atendimentos a JOIN clientes c ON c.id=a.cliente_id LEFT JOIN veiculos v ON v.id=a.veiculo_id ORDER BY a.data_hora DESC LIMIT 200").all<any>();
  return json({atendimentos:rows.results??[]},200,h)
 }
 if(r.method==="POST"&&u.pathname==="/api/atendimentos"){
  try{const b=await body(r),clienteId=String(b.cliente_id??""),servicoId=String(b.servico_id??""),dataHora=String(b.data_hora??""),observacoes=String(b.observacoes??"").trim(),modelo=String(b.modelo??"").trim(),placa=String(b.placa??"").trim(),requestedVehicleId=String(b.veiculo_id??"");
   if(!clienteId||!servicoId||!/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}$/.test(dataHora)||observacoes.length>1000||modelo.length>80||placa.length>12)return json({error:"Preencha cliente, serviço e data/hora corretamente."},400,h);
   const [client,service]=await Promise.all([e.DB.prepare("SELECT id FROM clientes WHERE id=?").bind(clienteId).first<any>(),e.DB.prepare("SELECT id,nome,preco_sugerido_centavos FROM catalogo_servicos WHERE id=? AND ativo=1").bind(servicoId).first<any>()]);
   if(!client||!service)return json({error:"Cliente ou serviço não encontrado."},404,h);
   let vehicleId:string|null=null;
   if(requestedVehicleId){const vehicle=await e.DB.prepare("SELECT id FROM veiculos WHERE id=? AND cliente_id=?").bind(requestedVehicleId,clienteId).first<any>();if(!vehicle)return json({error:"O veículo selecionado não pertence a este cliente."},400,h);vehicleId=requestedVehicleId}
   else if(modelo||placa){vehicleId=crypto.randomUUID();await e.DB.prepare("INSERT INTO veiculos(id,cliente_id,modelo,placa) VALUES(?,?,?,?)").bind(vehicleId,clienteId,modelo||null,placa||null).run()}
   const id=crypto.randomUUID(),price=Number(service.preco_sugerido_centavos)||0;
   await e.DB.batch([
    e.DB.prepare("INSERT INTO atendimentos(id,cliente_id,veiculo_id,data_hora,status,valor_centavos,criado_por,observacoes) VALUES(?,?,?,?,'agendado',?,?,?)").bind(id,clienteId,vehicleId,dataHora,price,(current as any).id,observacoes||null),
    e.DB.prepare("INSERT INTO atendimento_servicos(atendimento_id,servico_id,descricao,valor_centavos) VALUES(?,?,?,?)").bind(id,servicoId,service.nome,price)
   ]);
   await audit(e,(current as any).id,"atendimento_criado","atendimentos");return json({id},201,h)
  }catch(error){console.error("atendimento_create_error",{message:error instanceof Error?error.message:"unknown"});return json({error:"Não foi possível criar o atendimento."},500,h)}
 }
 if(r.method==="PATCH"&&u.pathname.startsWith("/api/atendimentos/")){
  try{const id=u.pathname.split("/").pop()??"",b=await body(r),status=String(b.status??"");if(!["agendado","em_andamento","concluido","cancelado"].includes(status))return json({error:"Status inválido."},400,h);
   const result=await e.DB.prepare("UPDATE atendimentos SET status=? WHERE id=?").bind(status,id).run();if(!result.meta.changes)return json({error:"Atendimento não encontrado."},404,h);
   await audit(e,(current as any).id,"atendimento_status_alterado","atendimentos");return json({status},200,h)
  }catch(error){console.error("atendimento_update_error",{message:error instanceof Error?error.message:"unknown"});return json({error:"Não foi possível atualizar o atendimento."},500,h)}
 }
 if(r.method==="GET"&&u.pathname==="/api/auth/me"){const x=await userFrom(r,e);return x?json({user:x},200,h):json({user:null},401,h)}
 if(r.method==="POST"&&u.pathname==="/api/auth/logout"){const t=getCookie(r);if(t)await e.DB.prepare("UPDATE sessoes SET revogada_em=datetime('now') WHERE token_hash=? AND revogada_em IS NULL").bind(await sha(t)).run();return json({status:"logged_out"},200,{...Object.fromEntries(h),"Set-Cookie":cookie("",0)})}
 return json({error:"Not found"},404,h)
}};