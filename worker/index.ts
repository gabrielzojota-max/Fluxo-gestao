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
function allowedOrigin(o:string|null,e:Env){return !!o&&((!!e.APP_ORIGIN&&o===e.APP_ORIGIN)||/^https:\/\/[a-z0-9-]+\.fluxo-gestao-b7w\.pages\.dev$/.test(o))}
function cors(r:Request,e:Env){const h=new Headers({"Vary":"Origin"}),o=r.headers.get("Origin");if(allowedOrigin(o,e)){h.set("Access-Control-Allow-Origin",o!);h.set("Access-Control-Allow-Credentials","true");h.set("Access-Control-Allow-Methods","GET,POST,PATCH,OPTIONS");h.set("Access-Control-Allow-Headers","Content-Type, Authorization")}return h}
async function audit(e:Env,u:string|null,a:string,d:string){await e.DB.prepare("INSERT INTO auditoria(id,usuario_id,acao,entidade) VALUES(?,?,?,?)").bind(crypto.randomUUID(),u,a,d).run()}
async function userFrom(r:Request,e:Env){const t=getCookie(r);if(!t)return null;return e.DB.prepare("SELECT u.id,u.nome,u.email,u.papel FROM sessoes s JOIN usuarios u ON u.id=s.usuario_id WHERE s.token_hash=? AND s.revogada_em IS NULL AND s.expira_em>datetime('now') AND u.status='ativo'").bind(await sha(t)).first()}
async function body(r:Request){if(!r.headers.get("Content-Type")?.includes("application/json"))throw Error("content-type");return await r.json() as any}
export default {async fetch(r:Request,e:Env):Promise<Response>{
 const u=new URL(r.url),h=cors(r,e),origin=r.headers.get("Origin");
 if(r.method==="OPTIONS")return new Response(null,{status:204,headers:h});
 if(u.pathname.startsWith("/api/")&&origin&&!allowedOrigin(origin,e))return json({error:"Origem não autorizada"},403,h);
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
 if(r.method==="POST"&&u.pathname==="/api/usuarios"){
  try{
   if((current as any)?.papel!=="socio")return json({error:"Apenas sócios podem cadastrar outros sócios."},403,h);
   const b=await body(r),nome=String(b.nome??"").trim(),email=String(b.email??"").trim().toLowerCase(),senha=String(b.senha??"");
   if(nome.length<2||nome.length>100||!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(email)||senha.length<8||senha.length>128)return json({error:"Confira nome, e-mail e senha (8 a 128 caracteres)."},400,h);
   const exists=await e.DB.prepare("SELECT id FROM usuarios WHERE email=?").bind(email).first<any>();
   if(exists)return json({error:"Já existe uma conta com este e-mail."},409,h);
   const senhaHash=await hashPassword(senha),id=crypto.randomUUID();
   await e.DB.prepare("INSERT INTO usuarios(id,nome,email,senha_hash,papel,status) VALUES(?,?,?,?,'socio','ativo')").bind(id,nome,email,senhaHash).run();
   await audit(e,(current as any).id,"socio_criado","usuarios");
   return json({usuario:{id,nome,email,papel:"socio",status:"ativo"}},201,h);
  }catch(error){console.error("user_create_error",{message:error instanceof Error?error.message:"unknown"});return json({error:"Não foi possível criar o acesso do sócio."},500,h)}
 }
 if(r.method==="GET"&&u.pathname==="/api/dashboard"){
   const [clients,appointments,today,revenue,monthExpenses,weekRevenue,weekExpenses,prevWeekRevenue,prevWeekExpenses,openAppointments,services]=await Promise.all([
    e.DB.prepare("SELECT COUNT(*) total FROM clientes").first<any>(),
    e.DB.prepare("SELECT COUNT(*) total FROM atendimentos").first<any>(),
    e.DB.prepare("SELECT COUNT(*) total,COUNT(CASE WHEN status='agendado' THEN 1 END) agendados,COUNT(CASE WHEN status='em_andamento' THEN 1 END) em_andamento,COUNT(CASE WHEN status='concluido' THEN 1 END) concluidos,COUNT(CASE WHEN status='cancelado' THEN 1 END) cancelados FROM atendimentos WHERE substr(data_hora,1,10)=date('now','-3 hours')").first<any>(),
    e.DB.prepare("SELECT COALESCE(SUM(valor_centavos),0) bruto,COALESCE(SUM(taxa_centavos),0) taxas,COALESCE(SUM(COALESCE(liquido_centavos,valor_centavos)),0) liquido FROM pagamentos WHERE status='recebido' AND substr(COALESCE(recebido_em,criado_em),1,7)=strftime('%Y-%m','now','-3 hours')").first<any>(),
    e.DB.prepare("SELECT COALESCE(SUM(valor_centavos),0) total FROM despesas WHERE status='paga' AND substr(COALESCE(pago_em,criado_em),1,7)=strftime('%Y-%m','now','-3 hours')").first<any>(),
    e.DB.prepare("SELECT COALESCE(SUM(COALESCE(liquido_centavos,valor_centavos)),0) total FROM pagamentos WHERE status='recebido' AND date(COALESCE(recebido_em,criado_em)) BETWEEN date('now','-3 hours','weekday 0','-6 days') AND date('now','-3 hours')").first<any>(),
    e.DB.prepare("SELECT COALESCE(SUM(valor_centavos),0) total FROM despesas WHERE status='paga' AND date(COALESCE(pago_em,criado_em)) BETWEEN date('now','-3 hours','weekday 0','-6 days') AND date('now','-3 hours')").first<any>(),
    e.DB.prepare("SELECT COALESCE(SUM(COALESCE(liquido_centavos,valor_centavos)),0) total FROM pagamentos WHERE status='recebido' AND date(COALESCE(recebido_em,criado_em)) BETWEEN date('now','-3 hours','weekday 0','-13 days') AND date('now','-3 hours','-7 days')").first<any>(),
    e.DB.prepare("SELECT COALESCE(SUM(valor_centavos),0) total FROM despesas WHERE status='paga' AND date(COALESCE(pago_em,criado_em)) BETWEEN date('now','-3 hours','weekday 0','-13 days') AND date('now','-3 hours','-7 days')").first<any>(),
    e.DB.prepare("SELECT a.id,a.data_hora,a.status,a.valor_centavos,c.nome cliente,COALESCE(v.modelo,'') veiculo,COALESCE(v.placa,'') placa FROM atendimentos a JOIN clientes c ON c.id=a.cliente_id LEFT JOIN veiculos v ON v.id=a.veiculo_id WHERE a.status IN('agendado','em_andamento') ORDER BY a.data_hora LIMIT 6").all<any>(),
    e.DB.prepare("SELECT COUNT(*) total FROM catalogo_servicos WHERE ativo=1").first<any>()
   ]);
   const monthNet=Number(revenue?.liquido??0),monthCost=Number(monthExpenses?.total??0),weekNet=Number(weekRevenue?.total??0),weekCost=Number(weekExpenses?.total??0),prevNet=Number(prevWeekRevenue?.total??0),prevCost=Number(prevWeekExpenses?.total??0),pct=(x:number,y:number)=>y===0?(x===0?0:null):Math.round((x-y)/y*1000)/10;
   return json({clientes:clients?.total??0,atendimentos:appointments?.total??0,hoje:today?.total??0,hoje_status:{agendados:today?.agendados??0,em_andamento:today?.em_andamento??0,concluidos:today?.concluidos??0,cancelados:today?.cancelados??0},faturamento_bruto_centavos:revenue?.bruto??0,taxas_cartao_centavos:revenue?.taxas??0,faturamento_centavos:monthNet,despesas_mes_centavos:monthCost,resultado_mes_centavos:monthNet-monthCost,semana:{receita_liquida_centavos:weekNet,despesas_centavos:weekCost,resultado_centavos:weekNet-weekCost,receita_anterior_centavos:prevNet,resultado_anterior_centavos:prevNet-prevCost,receita_delta_pct:pct(weekNet,prevNet),resultado_delta_pct:pct(weekNet-weekCost,prevNet-prevCost)},servicos:services?.total??0,proximos:openAppointments.results??[]},200,h)
  }
  if(r.method==="GET"&&u.pathname==="/api/clientes"){
  const q=(u.searchParams.get("q")??"").trim();
  const rows=await e.DB.prepare("SELECT c.id,c.nome,c.telefone,c.email,c.observacoes,c.criado_em,(SELECT COUNT(*) FROM veiculos v WHERE v.cliente_id=c.id) veiculos,(SELECT COUNT(*) FROM atendimentos a WHERE a.cliente_id=c.id AND a.status<>'cancelado') atendimentos,(SELECT COALESCE(SUM(p.valor_centavos),0) FROM pagamentos p JOIN atendimentos a ON a.id=p.atendimento_id WHERE a.cliente_id=c.id AND p.status='recebido') gasto_centavos FROM clientes c WHERE (?='' OR c.nome LIKE '%'||?||'%' OR COALESCE(c.telefone,'') LIKE '%'||?||'%') ORDER BY c.nome LIMIT 200").bind(q,q,q).all<any>();
  return json({clientes:rows.results??[]},200,h)
 }
 if(r.method==="POST"&&u.pathname==="/api/clientes"){
  try{const b=await body(r),nome=String(b.nome??"").trim(),telefone=String(b.telefone??"").trim(),email=String(b.email??"").trim(),observacoes=String(b.observacoes??"").trim();
   if(nome.length<2||nome.length>120||telefone.length<8||telefone.length>30||email.length>160||observacoes.length>1000)return json({error:"Informe o nome e um celular válido para cadastrar o cliente."},400,h);
   const id=crypto.randomUUID();await e.DB.prepare("INSERT INTO clientes(id,nome,telefone,email,observacoes) VALUES(?,?,?,?,?)").bind(id,nome,telefone||null,email||null,observacoes||null).run();
   await audit(e,(current as any).id,"cliente_criado","clientes");return json({id,nome,telefone,email,observacoes},201,h)
  }catch(error){console.error("cliente_create_error",{message:error instanceof Error?error.message:"unknown"});return json({error:"Não foi possível cadastrar o cliente."},500,h)}
 }
 if(r.method==="GET"&&/^\/api\/clientes\/[^/]+$/.test(u.pathname)){
  const id=u.pathname.split("/").pop()??"";
  const client=await e.DB.prepare("SELECT c.id,c.nome,c.telefone,c.email,c.observacoes,c.criado_em,(SELECT COUNT(*) FROM veiculos v WHERE v.cliente_id=c.id) veiculos,(SELECT COUNT(*) FROM atendimentos a WHERE a.cliente_id=c.id AND a.status<>'cancelado') atendimentos,(SELECT COALESCE(SUM(p.valor_centavos),0) FROM pagamentos p JOIN atendimentos a ON a.id=p.atendimento_id WHERE a.cliente_id=c.id AND p.status='recebido') gasto_centavos,(SELECT MAX(a.data_hora) FROM atendimentos a WHERE a.cliente_id=c.id AND a.status<>'cancelado') ultima_visita FROM clientes c WHERE c.id=?").bind(id).first<any>();
  if(!client)return json({error:"Cliente não encontrado."},404,h);
  const [vehicles,history]=await Promise.all([
   e.DB.prepare("SELECT id,marca,modelo,ano,placa,cor,observacoes,foto_data FROM veiculos WHERE cliente_id=? ORDER BY criado_em DESC").bind(id).all<any>(),
   e.DB.prepare("SELECT a.id,a.data_hora,a.status,a.valor_centavos,a.desconto_centavos,a.acrescimo_centavos,COALESCE(v.modelo,'') veiculo,COALESCE(v.placa,'') placa,COALESCE((SELECT group_concat(s.descricao,', ') FROM atendimento_servicos s WHERE s.atendimento_id=a.id),'') servicos,COALESCE((SELECT SUM(p.valor_centavos) FROM pagamentos p WHERE p.atendimento_id=a.id AND p.status='recebido'),0) recebido_centavos,COALESCE((SELECT SUM(p.valor_centavos) FROM pagamentos p WHERE p.atendimento_id=a.id AND p.status='pendente'),0) pendente_centavos FROM atendimentos a LEFT JOIN veiculos v ON v.id=a.veiculo_id WHERE a.cliente_id=? ORDER BY a.data_hora DESC LIMIT 100").bind(id).all<any>()
  ]);
  return json({cliente:client,veiculos:vehicles.results??[],historico:history.results??[]},200,h)
 }
  if(r.method==="GET"&&u.pathname==="/api/estoque"){
  const [products,movements]=await Promise.all([
   e.DB.prepare("SELECT id,nome,unidade,quantidade,estoque_minimo,custo_unitario_centavos,ativo,CASE WHEN quantidade<=0 THEN 'zerado' WHEN quantidade<=estoque_minimo THEN 'baixo' ELSE 'ok' END status FROM produtos WHERE ativo=1 ORDER BY nome").all<any>(),
   e.DB.prepare("SELECT m.id,m.produto_id,m.tipo,m.quantidade,m.custo_unitario_centavos,m.motivo,m.criado_em,p.nome produto,p.unidade FROM movimentacoes_estoque m JOIN produtos p ON p.id=m.produto_id ORDER BY m.criado_em DESC LIMIT 100").all<any>()
  ]);
  const rows=products.results??[];
  return json({produtos:rows,movimentacoes:movements.results??[],resumo:{produtos:rows.length,baixo:rows.filter((p:any)=>p.status==='baixo').length,zerado:rows.filter((p:any)=>p.status==='zerado').length,unidades:rows.reduce((n:number,p:any)=>n+Number(p.quantidade||0),0)}},200,h)
 }
 if(r.method==="POST"&&u.pathname==="/api/estoque/produtos"){
  try{const b=await body(r),nome=String(b.nome??"").trim(),unidade=String(b.unidade??"un"),minimo=Number(b.estoque_minimo??0),custo=Math.round(Number(b.custo_unitario_reais??0)*100);
   if(nome.length<2||nome.length>120||!["un","ml","L","g","kg","pacote","frasco"].includes(unidade)||!Number.isFinite(minimo)||minimo<0||minimo>1000000||!Number.isSafeInteger(custo)||custo<0||custo>100000000)return json({error:"Confira nome, unidade, estoque mínimo e custo do produto."},400,h);
   const id=crypto.randomUUID();await e.DB.prepare("INSERT INTO produtos(id,nome,unidade,quantidade,estoque_minimo,custo_unitario_centavos,ativo) VALUES(?,?,?,0,?,?,1)").bind(id,nome,unidade,minimo,custo).run();
   await audit(e,(current as any).id,"produto_estoque_criado","produtos");return json({id,nome},201,h)
  }catch(error){console.error("stock_product_create_error",{message:error instanceof Error?error.message:"unknown"});return json({error:"Não foi possível cadastrar o produto."},500,h)}
 }
 if(r.method==="POST"&&u.pathname==="/api/estoque/movimentacoes"){
  try{const b=await body(r),produtoId=String(b.produto_id??""),tipo=String(b.tipo??""),quantidade=Number(b.quantidade),motivo=String(b.motivo??"").trim(),custo=b.custo_unitario_reais===""||b.custo_unitario_reais==null?null:Math.round(Number(b.custo_unitario_reais)*100);
   if(!produtoId||!["compra","consumo","perda"].includes(tipo)||!Number.isFinite(quantidade)||quantidade<=0||quantidade>1000000||motivo.length<2||motivo.length>240||(custo!==null&&(!Number.isSafeInteger(custo)||custo<0||custo>100000000)))return json({error:"Confira produto, tipo, quantidade e motivo da movimentação."},400,h);
   const product=await e.DB.prepare("SELECT id,quantidade FROM produtos WHERE id=? AND ativo=1").bind(produtoId).first<any>();if(!product)return json({error:"Produto não encontrado."},404,h);
   if(tipo!=="compra"&&Number(product.quantidade)<quantidade)return json({error:"Estoque insuficiente para essa saída."},409,h);
   const update=tipo==="compra"
    ?e.DB.prepare("UPDATE produtos SET quantidade=quantidade+?,custo_unitario_centavos=COALESCE(?,custo_unitario_centavos) WHERE id=? AND ativo=1").bind(quantidade,custo,produtoId)
    :e.DB.prepare("UPDATE produtos SET quantidade=quantidade-? WHERE id=? AND ativo=1 AND quantidade>=?").bind(quantidade,produtoId,quantidade);
   const id=crypto.randomUUID();const batch=await e.DB.batch([
    update,
    e.DB.prepare("INSERT INTO movimentacoes_estoque(id,produto_id,tipo,quantidade,custo_unitario_centavos,motivo,criado_por) SELECT ?,?,?,?,?,?,? WHERE changes()=1").bind(id,produtoId,tipo,quantidade,custo,motivo,(current as any).id)
   ]);
   if(!batch[0].meta.changes)return json({error:"O estoque mudou. Atualize a tela e tente novamente."},409,h);
   if(!batch[1].meta.changes)return json({error:"Não foi possível registrar a movimentação. Nenhuma alteração foi mantida."},500,h);
   await audit(e,(current as any).id,"movimentacao_estoque_"+tipo,"movimentacoes_estoque");return json({id,status:"registrado"},201,h)
  }catch(error){console.error("stock_movement_error",{message:error instanceof Error?error.message:"unknown"});return json({error:"Não foi possível registrar a movimentação."},500,h)}
 }
  if(r.method==="GET"&&u.pathname==="/api/despesas"){
 const rows=await e.DB.prepare("SELECT id,categoria,descricao,valor_centavos,vencimento,status,metodo,pago_em,criado_em FROM despesas WHERE status<>'cancelada' ORDER BY CASE status WHEN 'pendente' THEN 0 ELSE 1 END,COALESCE(vencimento,criado_em) DESC LIMIT 300").all();
 const totals=await e.DB.prepare("SELECT COALESCE(SUM(CASE WHEN status='paga' THEN valor_centavos ELSE 0 END),0) pagas_centavos,COALESCE(SUM(CASE WHEN status='pendente' THEN valor_centavos ELSE 0 END),0) pendentes_centavos FROM despesas").first();
 return json({despesas:rows.results??[],totais:totals},200,h)
 }
 if(r.method==="POST"&&u.pathname==="/api/despesas"){
 try{const b=await body(r),categoria=String(b.categoria??"outros"),descricao=String(b.descricao??"").trim(),valor=Math.round(Number(b.valor_reais??0)*100),vencimento=b.vencimento?String(b.vencimento):null;
 if(!["produtos","aluguel","agua","energia","internet","manutencao","outros"].includes(categoria)||descricao.length<2||descricao.length>160||!Number.isSafeInteger(valor)||valor<=0||valor>100000000||(vencimento&&!/^\d{4}-\d{2}-\d{2}$/.test(vencimento)))return json({error:"Confira categoria, descrição, valor e vencimento."},400,h);
 const id=crypto.randomUUID();await e.DB.prepare("INSERT INTO despesas(id,descricao,valor_centavos,vencimento,status,categoria,criado_por) VALUES(?,?,?,?,'pendente',?,?)").bind(id,descricao,valor,vencimento,categoria,current.id).run();
 await audit(e,current.id,"despesa_criada","despesas");return json({id,status:"pendente"},201,h)
 }catch(error){console.error("expense_create_error",{message:error instanceof Error?error.message:"unknown"});return json({error:"Não foi possível cadastrar a despesa."},500,h)}
 }
 if(r.method==="PATCH"&&u.pathname.startsWith("/api/despesas/")){
 try{const id=u.pathname.split("/").pop()??"",b=await body(r),metodo=String(b.metodo??"pix");if(b.status!=="paga"||!["pix","dinheiro","cartao","outro"].includes(metodo))return json({error:"Informe uma forma válida para dar baixa na despesa."},400,h);
 const expense=await e.DB.prepare("SELECT id,descricao,valor_centavos,status FROM despesas WHERE id=?").bind(id).first();if(!expense)return json({error:"Despesa não encontrada."},404,h);if(expense.status!=="pendente")return json({error:"Esta despesa não está pendente."},409,h);
 const movementId=crypto.randomUUID();await e.DB.batch([
 e.DB.prepare("INSERT INTO movimentacoes(id,tipo,origem,origem_id,descricao,valor_centavos,metodo,criado_por) SELECT ?,'saida','despesa',?,?,?, ?,? WHERE EXISTS(SELECT 1 FROM despesas WHERE id=? AND status='pendente')").bind(movementId,id,expense.descricao,Number(expense.valor_centavos),metodo,current.id,id),
 e.DB.prepare("UPDATE despesas SET status='paga',metodo=?,pago_em=datetime('now','-3 hours') WHERE id=? AND status='pendente' AND EXISTS(SELECT 1 FROM movimentacoes WHERE id=?)").bind(metodo,id,movementId)
 ]);
 const updated=await e.DB.prepare("SELECT status FROM despesas WHERE id=?").bind(id).first();if(updated?.status!=="paga")return json({error:"Não foi possível confirmar a baixa desta despesa."},409,h);
 await audit(e,current.id,"despesa_paga","despesas");return json({status:"paga"},200,h)
 }catch(error){console.error("expense_pay_error",{message:error instanceof Error?error.message:"unknown"});return json({error:"Não foi possível dar baixa na despesa."},500,h)}
 }
 if(u.pathname==="/api/reserva"&&(r.method==="GET"||r.method==="POST")){
  try{
   await e.DB.prepare("CREATE TABLE IF NOT EXISTS reserva_movimentacoes(id TEXT PRIMARY KEY,tipo TEXT NOT NULL CHECK(tipo IN('aporte','uso')),descricao TEXT NOT NULL,valor_centavos INTEGER NOT NULL CHECK(valor_centavos>0),criado_por TEXT REFERENCES usuarios(id),criado_em TEXT NOT NULL DEFAULT(datetime('now','-3 hours')))").run();
   if(r.method==="POST"){
    const b=await body(r),tipo=String(b.tipo??""),descricao=String(b.descricao??"").trim(),valor=Math.round(Number(b.valor_reais??0)*100);
    if(!["aporte","uso"].includes(tipo)||descricao.length<2||descricao.length>160||!Number.isSafeInteger(valor)||valor<=0||valor>100000000)return json({error:"Informe o tipo, uma descrição e um valor válido para a reserva."},400,h);
    const id=crypto.randomUUID(),movementId=crypto.randomUUID(),expenseId=crypto.randomUUID(),label="Depósito na reserva · "+descricao;
    const batch=await e.DB.batch([
     e.DB.prepare("INSERT INTO reserva_movimentacoes(id,tipo,descricao,valor_centavos,criado_por) SELECT ?,?,?,?,? WHERE ?='aporte' OR ?<=COALESCE((SELECT SUM(CASE WHEN tipo='aporte' THEN valor_centavos ELSE -valor_centavos END) FROM reserva_movimentacoes),0)").bind(id,tipo,descricao,valor,(current as any).id,tipo,valor),
     e.DB.prepare("INSERT INTO movimentacoes(id,tipo,origem,origem_id,descricao,valor_centavos,metodo,criado_por) SELECT ?,'saida','reserva',?,?,?,'outro',? WHERE ?='aporte' AND EXISTS(SELECT 1 FROM reserva_movimentacoes WHERE id=?)").bind(movementId,id,label,valor,(current as any).id,tipo,id),
     e.DB.prepare("INSERT INTO despesas(id,descricao,valor_centavos,categoria,status,metodo,pago_em,criado_por) SELECT ?,?,?, 'melhorias','paga','outro',datetime('now','-3 hours'),? WHERE ?='uso' AND EXISTS(SELECT 1 FROM reserva_movimentacoes WHERE id=?)").bind(expenseId,descricao,valor,(current as any).id,tipo,id)
    ]);
    if(!batch[0].meta.changes)return json({error:"O valor informado é maior que o saldo guardado na reserva."},400,h);
    await audit(e,(current as any).id,tipo==="aporte"?"reserva_aporte":"reserva_uso","reserva_movimentacoes");
   }
   const [totals,rows]=await Promise.all([
    e.DB.prepare("SELECT COALESCE(SUM(CASE WHEN tipo='aporte' THEN valor_centavos ELSE -valor_centavos END),0) saldo_centavos,COALESCE(SUM(CASE WHEN tipo='aporte' THEN valor_centavos ELSE 0 END),0) total_guardado_centavos,COALESCE(SUM(CASE WHEN tipo='uso' THEN valor_centavos ELSE 0 END),0) total_utilizado_centavos FROM reserva_movimentacoes").first<any>(),
    e.DB.prepare("SELECT id,tipo,descricao,valor_centavos,criado_em FROM reserva_movimentacoes ORDER BY criado_em DESC LIMIT 100").all<any>()
   ]);
   return json({...totals,movimentacoes:rows.results??[]},r.method==="POST"?201:200,h)
  }catch(error){console.error("reserve_error",{message:error instanceof Error?error.message:"unknown"});return json({error:"Não foi possível carregar ou atualizar a reserva."},500,h)}
 }
 if(r.method==="GET"&&u.pathname==="/api/relatorios"){
 const inicio=u.searchParams.get("inicio")??"",fim=u.searchParams.get("fim")??"",valid=(v:string)=>/^\d{4}-\d{2}-\d{2}$/.test(v)&&!Number.isNaN(Date.parse(v+"T00:00:00Z"));
 if(!valid(inicio)||!valid(fim)||inicio>fim)return json({error:"Informe um período válido."},400,h);
 const a=Date.parse(inicio+"T00:00:00Z"),b=Date.parse(fim+"T00:00:00Z"),days=Math.round((b-a)/86400000)+1;
 if(days>366)return json({error:"O período máximo é de 366 dias."},400,h);
 const prevEnd=new Date(a-86400000).toISOString().slice(0,10),prevStart=new Date(a-days*86400000).toISOString().slice(0,10);
 const [rev,cost,ats,svc,revDays,costDays,costCats,prevRev,prevCost,prevAts]=await Promise.all([
 e.DB.prepare("SELECT COALESCE(SUM(valor_centavos),0) total,COALESCE(SUM(taxa_centavos),0) taxas,COALESCE(SUM(COALESCE(liquido_centavos,valor_centavos)),0) liquido,COUNT(*) quantidade FROM pagamentos WHERE status='recebido' AND substr(COALESCE(recebido_em,criado_em),1,10) BETWEEN ? AND ?").bind(inicio,fim).first<any>(),
 e.DB.prepare("SELECT COALESCE(SUM(valor_centavos),0) total,COUNT(*) quantidade FROM despesas WHERE status='paga' AND substr(COALESCE(pago_em,criado_em),1,10) BETWEEN ? AND ?").bind(inicio,fim).first<any>(),
 e.DB.prepare("SELECT COUNT(CASE WHEN status='concluido' THEN 1 END) concluidos,COALESCE(SUM(CASE WHEN status='concluido' THEN valor_centavos ELSE 0 END),0) valor_servicos,COUNT(CASE WHEN status='cancelado' THEN 1 END) cancelados,COUNT(*) total FROM atendimentos WHERE substr(data_hora,1,10) BETWEEN ? AND ?").bind(inicio,fim).first<any>(),
 e.DB.prepare("SELECT s.descricao nome,COUNT(*) quantidade,COALESCE(SUM(s.valor_centavos),0) total_centavos FROM atendimento_servicos s JOIN atendimentos a ON a.id=s.atendimento_id WHERE a.status='concluido' AND substr(a.data_hora,1,10) BETWEEN ? AND ? GROUP BY s.descricao ORDER BY total_centavos DESC LIMIT 12").bind(inicio,fim).all<any>(),
 e.DB.prepare("SELECT substr(COALESCE(recebido_em,criado_em),1,10) dia,SUM(valor_centavos) bruto,SUM(taxa_centavos) taxas,SUM(COALESCE(liquido_centavos,valor_centavos)) total FROM pagamentos WHERE status='recebido' AND substr(COALESCE(recebido_em,criado_em),1,10) BETWEEN ? AND ? GROUP BY dia ORDER BY dia").bind(inicio,fim).all<any>(),
 e.DB.prepare("SELECT substr(COALESCE(pago_em,criado_em),1,10) dia,SUM(valor_centavos) total FROM despesas WHERE status='paga' AND substr(COALESCE(pago_em,criado_em),1,10) BETWEEN ? AND ? GROUP BY dia ORDER BY dia").bind(inicio,fim).all<any>(),
 e.DB.prepare("SELECT categoria,COUNT(*) quantidade,SUM(valor_centavos) total_centavos FROM despesas WHERE status='paga' AND substr(COALESCE(pago_em,criado_em),1,10) BETWEEN ? AND ? GROUP BY categoria ORDER BY total_centavos DESC").bind(inicio,fim).all<any>(),
 e.DB.prepare("SELECT COALESCE(SUM(COALESCE(liquido_centavos,valor_centavos)),0) total FROM pagamentos WHERE status='recebido' AND substr(COALESCE(recebido_em,criado_em),1,10) BETWEEN ? AND ?").bind(prevStart,prevEnd).first<any>(),
 e.DB.prepare("SELECT COALESCE(SUM(valor_centavos),0) total FROM despesas WHERE status='paga' AND substr(COALESCE(pago_em,criado_em),1,10) BETWEEN ? AND ?").bind(prevStart,prevEnd).first<any>(),
 e.DB.prepare("SELECT COUNT(*) concluidos FROM atendimentos WHERE status='concluido' AND substr(data_hora,1,10) BETWEEN ? AND ?").bind(prevStart,prevEnd).first<any>()
 ]);
 const G=Number(rev?.total??0),F=Number(rev?.taxas??0),R=Number(rev?.liquido??0),C=Number(cost?.total??0),PR=Number(prevRev?.total??0),PC=Number(prevCost?.total??0),N=Number(ats?.concluidos??0),PN=Number(prevAts?.concluidos??0),pct=(x:number,y:number)=>y===0?(x===0?0:null):Math.round((x-y)/y*1000)/10;
 return json({periodo:{inicio,fim,dias:days,comparacao_inicio:prevStart,comparacao_fim:prevEnd},totais:{receita_bruta_centavos:G,taxas_cartao_centavos:F,receita_centavos:R,despesas_centavos:C,resultado_centavos:R-C,atendimentos_concluidos:N,ticket_medio_centavos:N?Math.round(Number(ats?.valor_servicos??0)/N):0,pagamentos:rev?.quantidade??0,despesas_pagas:cost?.quantidade??0,total_atendimentos:ats?.total??0,cancelados:ats?.cancelados??0},comparacao:{receita_centavos:PR,despesas_centavos:PC,resultado_centavos:PR-PC,atendimentos_concluidos:PN,receita_delta_pct:pct(R,PR),despesas_delta_pct:pct(C,PC),resultado_delta_pct:pct(R-C,PR-PC),atendimentos_delta_pct:pct(N,PN)},servicos:svc.results??[],receita_por_dia:revDays.results??[],despesas_por_dia:costDays.results??[],despesas_por_categoria:costCats.results??[]},200,h)
 }
if(r.method==="GET"&&u.pathname==="/api/taxas-pagamento"){
  const rows=await e.DB.prepare("SELECT metodo,taxa_percentual,atualizado_em FROM taxas_pagamento ORDER BY metodo").all<any>();
  const taxas={credito:0,debito:0};for(const row of rows.results??[])taxas[row.metodo]=Number(row.taxa_percentual??0);
  return json({taxas},200,h)
 }
 if(r.method==="PATCH"&&u.pathname==="/api/taxas-pagamento"){
  if((current as any)?.papel!=="socio")return json({error:"Somente um sócio pode alterar as taxas."},403,h);
  try{const b=await body(r),credito=Number(b.credito),debito=Number(b.debito);
   if(!Number.isFinite(credito)||!Number.isFinite(debito)||credito<0||debito<0||credito>100||debito>100)return json({error:"Informe taxas entre 0% e 100%."},400,h);
   await e.DB.batch([
    e.DB.prepare("INSERT INTO taxas_pagamento(metodo,taxa_percentual,atualizado_em) VALUES('credito',?,datetime('now','-3 hours')) ON CONFLICT(metodo) DO UPDATE SET taxa_percentual=excluded.taxa_percentual,atualizado_em=excluded.atualizado_em").bind(credito),
    e.DB.prepare("INSERT INTO taxas_pagamento(metodo,taxa_percentual,atualizado_em) VALUES('debito',?,datetime('now','-3 hours')) ON CONFLICT(metodo) DO UPDATE SET taxa_percentual=excluded.taxa_percentual,atualizado_em=excluded.atualizado_em").bind(debito)
   ]);
   await audit(e,(current as any).id,"taxas_cartao_atualizadas","taxas_pagamento");return json({taxas:{credito,debito}},200,h)
  }catch(error){console.error("payment_fees_update_error",{message:error instanceof Error?error.message:"unknown"});return json({error:"Não foi possível atualizar as taxas."},500,h)}
 }
// Fechamento diário imutável: uma única confirmação por data.
if(u.pathname==="/api/caixa/fechamento"&&(r.method==="GET"||r.method==="POST")){
  try{
   await e.DB.prepare("CREATE TABLE IF NOT EXISTS fechamentos_caixa(dia TEXT PRIMARY KEY,total_entradas_centavos INTEGER NOT NULL,total_saidas_centavos INTEGER NOT NULL,saldo_centavos INTEGER NOT NULL,resumo_json TEXT NOT NULL,observacoes TEXT,fechado_por TEXT NOT NULL,fechado_em TEXT NOT NULL DEFAULT(datetime('now','-3 hours')))").run();
   const payload=r.method==="POST"?await body(r):{};const dia=r.method==="GET"?(u.searchParams.get("dia")??""):String(payload.dia??"");
   if(!/^\d{4}-\d{2}-\d{2}$/.test(dia)||Number.isNaN(Date.parse(dia+"T00:00:00Z")))return json({error:"Informe uma data válida."},400,h);
   const [mov,byMethod,closed]=await Promise.all([
    e.DB.prepare("SELECT COALESCE(SUM(CASE WHEN tipo='entrada' THEN valor_centavos ELSE 0 END),0) entradas_centavos,COALESCE(SUM(CASE WHEN tipo='saida' THEN valor_centavos ELSE 0 END),0) saidas_centavos,COUNT(*) quantidade FROM movimentacoes WHERE substr(ocorrido_em,1,10)=?").bind(dia).first<any>(),
    e.DB.prepare("SELECT tipo,COALESCE(metodo,'outro') metodo,SUM(valor_centavos) valor_centavos,COUNT(*) quantidade FROM movimentacoes WHERE substr(ocorrido_em,1,10)=? GROUP BY tipo,COALESCE(metodo,'outro') ORDER BY tipo,metodo").bind(dia).all<any>(),
    e.DB.prepare("SELECT f.*,u.nome fechado_por_nome FROM fechamentos_caixa f LEFT JOIN usuarios u ON u.id=f.fechado_por WHERE f.dia=?").bind(dia).first<any>()
   ]);
   const entradas=Number(mov?.entradas_centavos??0),saidas=Number(mov?.saidas_centavos??0),methods=byMethod.results??[],dinheiroEsperado=methods.reduce((sum:number,m:any)=>sum+(m.metodo==="dinheiro"?(m.tipo==="entrada"?1:-1)*Number(m.valor_centavos||0):0),0),resumo={dia,entradas_centavos:entradas,saidas_centavos:saidas,saldo_centavos:entradas-saidas,dinheiro_esperado_centavos:dinheiroEsperado,quantidade:Number(mov?.quantidade??0),por_metodo:methods};
   if(r.method==="POST"){
    if(closed)return json({error:"Este dia já foi fechado. O fechamento existente foi preservado.",fechamento:closed,resumo:JSON.parse(String(closed.resumo_json||"{}"))},409,h);
    const observacoes=String(payload.observacoes??"").trim().slice(0,500),rawCount=payload.dinheiro_contado_reais,dinheiroContado=rawCount===null||rawCount===undefined||rawCount===""?null:Math.round(Number(rawCount)*100);
    if(dinheiroContado===null)return json({error:"Informe quanto dinheiro físico foi contado. Se não houver dinheiro em caixa, informe 0."},400,h);
    if(!Number.isSafeInteger(dinheiroContado)||dinheiroContado<0||dinheiroContado>100000000000)return json({error:"Informe um valor contado válido."},400,h);
    const diferencaDinheiro=dinheiroContado===null?null:dinheiroContado-dinheiroEsperado;
    if(dia>new Date(Date.now()-3*60*60*1000).toISOString().slice(0,10))return json({error:"Não é possível fechar uma data futura."},400,h);
    const ins=await e.DB.prepare("INSERT OR IGNORE INTO fechamentos_caixa(dia,total_entradas_centavos,total_saidas_centavos,saldo_centavos,resumo_json,observacoes,fechado_por,dinheiro_contado_centavos,diferenca_dinheiro_centavos) VALUES(?,?,?,?,?,?,?,?,?)").bind(dia,entradas,saidas,entradas-saidas,JSON.stringify(resumo),observacoes,(current as any).id,dinheiroContado,diferencaDinheiro).run();
    if(!ins.meta.changes)return json({error:"Este dia já foi fechado por outro usuário."},409,h);
    await audit(e,(current as any).id,"caixa_fechado_"+dia,"fechamentos_caixa");
    const saved=await e.DB.prepare("SELECT f.*,u.nome fechado_por_nome FROM fechamentos_caixa f LEFT JOIN usuarios u ON u.id=f.fechado_por WHERE f.dia=?").bind(dia).first<any>();
    return json({resumo,fechamento:saved,fechado:true},201,h)
   }
   return json({resumo,fechamento:closed??null},200,h)
  }catch(error){console.error("cash_closing_error",{message:error instanceof Error?error.message:"unknown"});return json({error:"Não foi possível carregar ou fechar o caixa."},500,h)}
 }
 if(r.method==="GET"&&u.pathname==="/api/financeiro"){
  const [payments,open]=await Promise.all([
   e.DB.prepare("SELECT p.id,p.atendimento_id,p.valor_centavos,p.taxa_centavos,p.liquido_centavos,p.metodo,p.modalidade,p.status,p.recebido_em,p.criado_em,c.nome cliente,COALESCE(v.modelo,'') veiculo,a.data_hora FROM pagamentos p JOIN atendimentos a ON a.id=p.atendimento_id JOIN clientes c ON c.id=a.cliente_id LEFT JOIN veiculos v ON v.id=a.veiculo_id ORDER BY CASE p.status WHEN 'pendente' THEN 0 ELSE 1 END,p.criado_em DESC LIMIT 150").all<any>(),
   e.DB.prepare("SELECT a.id,a.data_hora,a.valor_centavos,c.nome cliente,COALESCE(v.modelo,'') veiculo,COALESCE((SELECT json_group_array(json_object('descricao',s.descricao,'valor_centavos',s.valor_centavos)) FROM atendimento_servicos s WHERE s.atendimento_id=a.id),'[]') servicos_detalhados,COALESCE((SELECT SUM(p.valor_centavos) FROM pagamentos p WHERE p.atendimento_id=a.id AND p.status='recebido'),0) recebido_centavos,COALESCE((SELECT SUM(p.valor_centavos) FROM pagamentos p WHERE p.atendimento_id=a.id AND p.status='pendente'),0) pendente_centavos,MAX(0,a.valor_centavos-COALESCE((SELECT SUM(p.valor_centavos) FROM pagamentos p WHERE p.atendimento_id=a.id AND p.status='recebido'),0)) saldo_centavos,MAX(0,a.valor_centavos-COALESCE((SELECT SUM(p.valor_centavos) FROM pagamentos p WHERE p.atendimento_id=a.id AND p.status IN('pendente','recebido')),0)) disponivel_centavos,COALESCE((SELECT json_group_array(json_object('id',p.id,'valor_centavos',p.valor_centavos,'status',p.status,'metodo',p.metodo,'modalidade',p.modalidade,'criado_em',p.criado_em,'recebido_em',p.recebido_em)) FROM pagamentos p WHERE p.atendimento_id=a.id),'[]') pagamentos_detalhados FROM atendimentos a JOIN clientes c ON c.id=a.cliente_id LEFT JOIN veiculos v ON v.id=a.veiculo_id WHERE a.status<>'cancelado' AND a.valor_centavos>COALESCE((SELECT SUM(p.valor_centavos) FROM pagamentos p WHERE p.atendimento_id=a.id AND p.status='recebido'),0) ORDER BY a.data_hora DESC LIMIT 100").all<any>()
  ]);
  const totals=await e.DB.prepare("SELECT COALESCE(SUM(CASE WHEN status='recebido' THEN valor_centavos ELSE 0 END),0) recebido_centavos,COALESCE(SUM(CASE WHEN status='pendente' THEN valor_centavos ELSE 0 END),0) pendente_centavos,COUNT(CASE WHEN status='recebido' THEN 1 END) recebidos,COUNT(CASE WHEN status='pendente' THEN 1 END) pendentes,COALESCE(SUM(CASE WHEN status='recebido' THEN taxa_centavos ELSE 0 END),0) taxas_centavos,COALESCE(SUM(CASE WHEN status='recebido' THEN COALESCE(liquido_centavos,valor_centavos) ELSE 0 END),0) liquido_centavos FROM pagamentos").first<any>();
  return json({pagamentos:payments.results??[],em_aberto:open.results??[],totais:totals},200,h)
 }
 if(r.method==="POST"&&u.pathname==="/api/pagamentos"){
  try{const b=await body(r),atendimentoId=String(b.atendimento_id??""),valor=Math.round(Number(b.valor_reais??0)*100),metodo=String(b.metodo??"");
   if(!atendimentoId||!Number.isSafeInteger(valor)||valor<=0||valor>100000000||!["dinheiro","pix","cartao","outro"].includes(metodo)||((metodo==="cartao")&&!["credito","debito"].includes(String(b.modalidade??""))))return json({error:"Informe atendimento, valor válido e forma de pagamento."},400,h);
   const at=await e.DB.prepare("SELECT a.id,a.valor_centavos,a.status,COALESCE((SELECT SUM(p.valor_centavos) FROM pagamentos p WHERE p.atendimento_id=a.id AND p.status IN('pendente','recebido')),0) comprometido FROM atendimentos a WHERE a.id=?").bind(atendimentoId).first<any>();
   if(!at||at.status==="cancelado")return json({error:"Atendimento não encontrado ou cancelado."},404,h);
   const saldo=Math.max(0,Number(at.valor_centavos)-Number(at.comprometido));if(valor>saldo)return json({error:"O valor informado é maior que o saldo em aberto."},400,h);
   const rate=metodo==="cartao"?Number((await e.DB.prepare("SELECT taxa_percentual FROM taxas_pagamento WHERE metodo=?").bind(String(b.modalidade)).first<any>())?.taxa_percentual??0):0;const fee=Math.min(valor,Math.round(valor*rate/100)),net=valor-fee;const id=crypto.randomUUID();const inserted=await e.DB.prepare("INSERT INTO pagamentos(id,atendimento_id,valor_centavos,taxa_centavos,liquido_centavos,metodo,modalidade,status,criado_por) SELECT ?,a.id,?,?,?,?,?,'pendente',? FROM atendimentos a WHERE a.id=? AND a.status<>'cancelado' AND ?<=a.valor_centavos-COALESCE((SELECT SUM(p.valor_centavos) FROM pagamentos p WHERE p.atendimento_id=a.id AND p.status IN('pendente','recebido')),0)").bind(id,valor,fee,net,metodo,metodo==="cartao"?String(b.modalidade):"nao_aplicavel",(current as any).id,atendimentoId,valor).run();if(!inserted.meta.changes)return json({error:"O saldo mudou ou já foi reservado. Atualize a tela."},409,h);
   await audit(e,(current as any).id,"pagamento_pendente_criado","pagamentos");return json({id,status:"pendente"},201,h)
  }catch(error){console.error("payment_create_error",{message:error instanceof Error?error.message:"unknown"});return json({error:"Não foi possível registrar o pagamento."},500,h)}
 }
 if(r.method==="PATCH"&&/^\/api\/pagamentos\/[^/]+$/.test(u.pathname)){
  try{const id=u.pathname.split("/").pop()??"",payment=await e.DB.prepare("SELECT p.id,p.atendimento_id,p.valor_centavos,p.taxa_centavos,p.liquido_centavos,p.metodo,p.status,c.nome cliente FROM pagamentos p JOIN atendimentos a ON a.id=p.atendimento_id JOIN clientes c ON c.id=a.cliente_id WHERE p.id=?").bind(id).first<any>();
   if(!payment)return json({error:"Pagamento não encontrado."},404,h);if(payment.status!=="pendente")return json({error:"Este pagamento não está pendente."},409,h);
   const movementId=crypto.randomUUID();
   await e.DB.batch([
    e.DB.prepare("INSERT INTO movimentacoes(id,tipo,origem,origem_id,descricao,valor_centavos,metodo,criado_por) SELECT ?, 'entrada','pagamento',?,?,?, ?,? WHERE EXISTS(SELECT 1 FROM pagamentos WHERE id=? AND status='pendente')").bind(movementId,id,"Recebimento líquido · "+payment.cliente,Number(payment.liquido_centavos??payment.valor_centavos),payment.metodo,(current as any).id,id),
    e.DB.prepare("INSERT INTO movimentacoes(id,tipo,origem,origem_id,descricao,valor_centavos,metodo,criado_por) SELECT ?,'saida','taxa_cartao',?,?,?,'cartao',? WHERE EXISTS(SELECT 1 FROM pagamentos WHERE id=? AND status='pendente' AND taxa_centavos>0)").bind(crypto.randomUUID(),id,"Taxa do cartão · "+payment.cliente,Number(payment.taxa_centavos??0),(current as any).id,id),
    e.DB.prepare("UPDATE pagamentos SET status='recebido',recebido_em=datetime('now','-3 hours'),movimento_id=? WHERE id=? AND status='pendente' AND EXISTS(SELECT 1 FROM movimentacoes WHERE id=?)").bind(movementId,id,movementId)
   ]);
   const confirmed=await e.DB.prepare("SELECT status,recebido_em,movimento_id FROM pagamentos WHERE id=?").bind(id).first<any>();
   if(confirmed?.status!=="recebido")return json({error:"Não foi possível confirmar este pagamento."},409,h);
   await audit(e,(current as any).id,"pagamento_confirmado","pagamentos");return json({status:confirmed.status,recebido_em:confirmed.recebido_em},200,h)
  }catch(error){console.error("payment_confirm_error",{message:error instanceof Error?error.message:"unknown"});return json({error:"Não foi possível confirmar o pagamento. Verifique se ele já foi confirmado."},409,h)}
 }
  if(r.method==="GET"&&u.pathname==="/api/veiculos"){
  const clienteId=(u.searchParams.get("cliente_id")??"").trim();
  const rows=await e.DB.prepare("SELECT v.id,v.cliente_id,v.marca,v.modelo,v.ano,v.placa,v.cor,v.observacoes,v.foto_data,c.nome cliente FROM veiculos v JOIN clientes c ON c.id=v.cliente_id WHERE (?='' OR v.cliente_id=?) ORDER BY c.nome,v.modelo").bind(clienteId,clienteId).all<any>();
  return json({veiculos:rows.results??[]},200,h)
 }
 if(r.method==="PATCH"&&/^\/api\/veiculos\/[^/]+$/.test(u.pathname)){
  try{const id=u.pathname.split("/").pop()??"",b=await body(r),fotoData=String(b.foto_data??"");if(!fotoData||fotoData.length>480000||!/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(fotoData))return json({error:"Envie uma foto JPG, PNG ou WebP com tamanho reduzido."},400,h);const result=await e.DB.prepare("UPDATE veiculos SET foto_data=? WHERE id=?").bind(fotoData,id).run();if(!result.meta.changes)return json({error:"Veículo não encontrado."},404,h);await audit(e,(current as any).id,"foto_veiculo_atualizada","veiculos");return json({status:"updated"},200,h)}catch(error){console.error("vehicle_photo_error",{message:error instanceof Error?error.message:"unknown"});return json({error:"Não foi possível salvar a foto do veículo."},500,h)}
 }
 if(r.method==="POST"&&u.pathname==="/api/veiculos"){
  try{const b=await body(r),clienteId=String(b.cliente_id??""),modelo=String(b.modelo??"").trim(),placa=String(b.placa??"").trim().toUpperCase(),cor=String(b.cor??"").trim(),ano=b.ano==null||b.ano===""?null:Number(b.ano);
   if(!clienteId||modelo.length<2||modelo.length>100||placa.length>12||cor.length>40||(ano!==null&&(!Number.isInteger(ano)||ano<1950||ano>2100)))return json({error:"Informe cliente e modelo; placa, ano e cor são opcionais."},400,h);
   const client=await e.DB.prepare("SELECT id FROM clientes WHERE id=?").bind(clienteId).first<any>();if(!client)return json({error:"Cliente não encontrado."},404,h);
   const fotoData=String(b.foto_data??"");if(fotoData&&(fotoData.length>480000||!/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(fotoData)))return json({error:"A foto precisa ser JPG, PNG ou WebP e ter tamanho reduzido."},400,h);
   const id=crypto.randomUUID();await e.DB.prepare("INSERT INTO veiculos(id,cliente_id,modelo,placa,ano,cor,foto_data) VALUES(?,?,?,?,?,?,?)").bind(id,clienteId,modelo,placa||null,ano,cor||null,fotoData||null).run();
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
  const rows=await e.DB.prepare("SELECT a.id,a.veiculo_id,a.data_hora,a.status,a.valor_centavos,a.observacoes,c.nome cliente,c.telefone,COALESCE(v.modelo,'') veiculo,COALESCE(v.placa,'') placa,COALESCE((SELECT group_concat(s.descricao,', ') FROM atendimento_servicos s WHERE s.atendimento_id=a.id),'') servicos,COALESCE((SELECT json_group_array(json_object('descricao',s.descricao,'valor_centavos',s.valor_centavos)) FROM atendimento_servicos s WHERE s.atendimento_id=a.id),'[]') servicos_detalhados FROM atendimentos a JOIN clientes c ON c.id=a.cliente_id LEFT JOIN veiculos v ON v.id=a.veiculo_id ORDER BY a.data_hora DESC LIMIT 200").all<any>();
  return json({atendimentos:rows.results??[]},200,h)
 }
 if(r.method==="POST"&&u.pathname==="/api/atendimentos"){
  try{const b=await body(r),clienteId=String(b.cliente_id??""),dataHora=String(b.data_hora??""),observacoes=String(b.observacoes??"").trim(),requestedVehicleId=String(b.veiculo_id??"");
   const client=await e.DB.prepare("SELECT id FROM clientes WHERE id=?").bind(clienteId).first<any>();
   const rawItems=Array.isArray(b.servicos)?b.servicos:[{servico_id:b.servico_id,descricao:b.servico_nome,valor_reais:b.valor_reais}];
   if(rawItems.length<1||rawItems.length>20)return json({error:"Adicione entre 1 e 20 serviços ao atendimento."},400,h);
   const items:any[]=[];
   for(const raw of rawItems){const serviceId=String(raw?.servico_id??""),description=String(raw?.descricao??"").trim(),rawPrice=Number(raw?.valor_reais),price=Number.isFinite(rawPrice)?Math.round(rawPrice*100):NaN;let service:any=null;if(serviceId)service=await e.DB.prepare("SELECT id FROM catalogo_servicos WHERE id=? AND ativo=1").bind(serviceId).first<any>();if((serviceId&&!service)||!description||description.length>120||!Number.isSafeInteger(price)||price<0||price>1000000000)return json({error:"Confira o nome e o valor de cada serviço."},400,h);items.push({serviceId:service?.id??null,description,price})}
   const total=items.reduce((sum,item)=>sum+item.price,0),uniqueNames=new Set(items.map(item=>item.description.toLocaleLowerCase("pt-BR")));if(uniqueNames.size!==items.length)return json({error:"Não repita o mesmo nome de serviço no atendimento."},400,h);
   if(!clienteId||!client||total>1000000000||!/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}$/.test(dataHora)||observacoes.length>1000)return json({error:"Preencha cliente, serviços, valores e data/hora corretamente."},400,h);
   let vehicleId:string|null=null;if(requestedVehicleId){const vehicle=await e.DB.prepare("SELECT id FROM veiculos WHERE id=? AND cliente_id=?").bind(requestedVehicleId,clienteId).first<any>();if(!vehicle)return json({error:"O veículo selecionado não pertence a este cliente."},400,h);vehicleId=requestedVehicleId}
   const id=crypto.randomUUID(),statements=[e.DB.prepare("INSERT INTO atendimentos(id,cliente_id,veiculo_id,data_hora,status,valor_centavos,criado_por,observacoes) VALUES(?,?,?,?,'agendado',?,?,?)").bind(id,clienteId,vehicleId,dataHora,total,(current as any).id,observacoes||null),...items.map(item=>e.DB.prepare("INSERT INTO atendimento_servicos(atendimento_id,servico_id,descricao,valor_centavos) VALUES(?,?,?,?)").bind(id,item.serviceId,item.description,item.price))];
   await e.DB.batch(statements);await audit(e,(current as any).id,"atendimento_criado","atendimentos");return json({id,servicos:items.length,valor_centavos:total},201,h)
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