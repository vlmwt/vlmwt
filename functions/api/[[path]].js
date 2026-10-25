const J=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{"Content-Type":"application/json"}});
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("");
const rnd=n=>hex(crypto.getRandomValues(new Uint8Array(n)));
const gen=()=>[0,1,2,3,4].map(()=>rnd(2)).join("-");
const enc=s=>new TextEncoder().encode(s);
const sha=async s=>hex(await crypto.subtle.digest("SHA-256",enc(s)));
async function pw(p,salt){const k=await crypto.subtle.importKey("raw",enc(p),"PBKDF2",false,["deriveBits"]);return hex(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt:enc(salt),iterations:100000},k,256))}
export async function onRequest({request,env}){
  const DB=env.DB;if(!DB)return J({e:"Database non collegato"},500);
  const m=request.method,r=new URL(request.url).pathname.replace(/^\/api\//,"").split("/"),ep=r[0];
  let b={};if(m==="POST"){try{b=await request.json()}catch(e){return J({e:"Richiesta non valida"},400)}}
  const tk=(request.headers.get("Authorization")||"").slice(7);
  const me=tk?(await DB.prepare("SELECT u FROM sessions WHERE h=?").bind(await sha(tk)).first())?.u:null;
  const mk=async(u,code)=>{const t=rnd(32);await DB.prepare("INSERT INTO sessions(h,u) VALUES(?,?)").bind(await sha(t),u).run();return J({token:t,u,code})};
  if(ep==="register"){
    const u=String(b.u||"").toLowerCase(),p=String(b.p||"");
    if(!/^[a-z0-9_]{3,20}$/.test(u))return J({e:"Nome utente: 3-20 caratteri, solo lettere, numeri e _"},400);
    if(p.length<8)return J({e:"La password deve avere almeno 8 caratteri"},400);
    if(await DB.prepare("SELECT 1 FROM users WHERE u=?").bind(u).first())return J({e:"Nome utente già preso"},409);
    const s=rnd(16),code=gen();
    await DB.prepare("INSERT INTO users(u,salt,hash,name,rec,t) VALUES(?,?,?,?,?,?)").bind(u,s,await pw(p,s),u,await sha(code),Date.now()).run();
    return mk(u,code);
  }
  if(ep==="login"){
    const u=String(b.u||"").toLowerCase(),x=await DB.prepare("SELECT salt,hash FROM users WHERE u=?").bind(u).first();
    if(!x||await pw(String(b.p||""),x.salt)!==x.hash)return J({e:"Nome utente o password sbagliati"},401);
    return mk(u);
  }
  if(ep==="reset"){
    const u=String(b.u||"").toLowerCase(),p=String(b.p||""),x=await DB.prepare("SELECT rec FROM users WHERE u=?").bind(u).first();
    if(p.length<8)return J({e:"La password deve avere almeno 8 caratteri"},400);
    if(!x||!x.rec||await sha(String(b.code||"").trim().toLowerCase())!==x.rec)return J({e:"Nome utente o codice di recupero sbagliati"},401);
    const s=rnd(16),code=gen();
    await DB.prepare("UPDATE users SET salt=?,hash=?,rec=? WHERE u=?").bind(s,await pw(p,s),await sha(code),u).run();
    await DB.prepare("DELETE FROM sessions WHERE u=?").bind(u).run();
    return mk(u,code);
  }
  if(ep==="users")return J((await DB.prepare("SELECT u,name,photo FROM users ORDER BY t DESC LIMIT 60").all()).results);
  if(ep==="user"&&r[1]){
    const x=await DB.prepare("SELECT u,name,photo,banner,anime FROM users WHERE u=?").bind(r[1].toLowerCase()).first();
    if(!x)return J({e:"Non trovato"},404);
    x.comments=(await DB.prepare("SELECT id,f,x,t FROM comments WHERE a=? ORDER BY id DESC LIMIT 50").bind(x.u).all()).results;
    return J(x);
  }
  if(!me)return J({e:"Devi accedere"},401);
  if(ep==="me")return J(await DB.prepare("SELECT u,name,banner FROM users WHERE u=?").bind(me).first());
  if(m!=="POST")return J({e:"Metodo non valido"},405);
  if(ep==="profile"){
    const ok=(v,n)=>v==null||(typeof v==="string"&&v.startsWith("data:image/")&&v.length<n);
    if(!ok(b.photo,60000)||!ok(b.banner,150000))return J({e:"Immagine troppo grande"},400);
    await DB.prepare("UPDATE users SET name=?,photo=COALESCE(?,photo),banner=COALESCE(?,banner) WHERE u=?").bind(String(b.name||me).slice(0,30),b.photo||null,b.banner||null,me).run();
    return J({ok:1});
  }
  if(ep==="sync"){
    const s=JSON.stringify(Array.isArray(b.anime)?b.anime.slice(0,2000):[]);
    if(s.length>1500000)return J({e:"Lista troppo grande"},400);
    await DB.prepare("UPDATE users SET anime=? WHERE u=?").bind(s,me).run();
    return J({ok:1});
  }
  if(ep==="comment"){
    const to=String(b.to||"").toLowerCase(),text=String(b.text||"").trim().slice(0,300);
    if(!text)return J({e:"Commento vuoto"},400);
    if(!await DB.prepare("SELECT 1 FROM users WHERE u=?").bind(to).first())return J({e:"Profilo non trovato"},404);
    await DB.prepare("INSERT INTO comments(a,f,x,t) VALUES(?,?,?,?)").bind(to,me,text,Date.now()).run();
    return J({ok:1});
  }
  if(ep==="delcomment"){
    const c=await DB.prepare("SELECT a,f FROM comments WHERE id=?").bind(+b.id).first();
    if(c&&(c.a===me||c.f===me))await DB.prepare("DELETE FROM comments WHERE id=?").bind(+b.id).run();
    return J({ok:1});
  }
  return J({e:"Non trovato"},404);
}
