import crypto from 'node:crypto';
const BASE=process.argv[2]||'https://bxbot-ruw1.onrender.com';
const SALT=process.argv[3]||'bx8-session-salt-do-not-publish';
const b64=b=>Buffer.from(b).toString('base64');
const hkdf=(salt,secret,info)=>{const prk=crypto.createHmac('sha256',Buffer.from(salt)).update(secret).digest();return crypto.createHmac('sha256',prk).update(Buffer.concat([Buffer.from(info),Buffer.from([1])])).digest();};
const enc=(k,p)=>{const iv=crypto.randomBytes(12);const c=crypto.createCipheriv('aes-256-gcm',k,iv);const ct=Buffer.concat([c.update(Buffer.from(p,'utf8')),c.final()]);return b64(Buffer.concat([iv,ct,c.getAuthTag()]));};
const mac=(k,m)=>crypto.createHmac('sha256',k).update(m).digest('base64');
const DEV='bx10'+Date.now().toString(36);
const e=crypto.createECDH('prime256v1'); e.generateKeys();
const hr=await fetch(BASE+'/api/hello',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({dev:DEV,name:'Samsung SM-A127F',pkg:'com.alamin.ludu',st:'ingame',pk:b64(e.getPublicKey()),v:8})});
const hj=await hr.json();
console.log('hello   ',hr.status,'node',hj.node,'cfg',JSON.stringify(hj.cfg));
const secret=e.computeSecret(Buffer.from(hj.spk,'base64'));
const AES=hkdf(SALT,secret,'enc'), MAC=hkdf(SALT,secret,'sig');
for(let i=1;i<=3;i++){
  const wire=enc(AES,JSON.stringify({st:'ingame',name:'Samsung SM-A127F',pkg:'com.alamin.ludu',polls:i,ig:1,up:-1,fail:0}));
  const r=await fetch(BASE+'/api/poll',{method:'POST',headers:{'content-type':'text/plain','x-sid':hj.sid,'x-sig':mac(MAC,hj.sid+'|'+wire)},body:wire});
  const body=await r.text();
  const sigOk=r.headers.get('x-sig')===mac(MAC,hj.sid+'|'+body);
  let dec=null; if(r.status===200){const all=Buffer.from(body,'base64');const d=crypto.createDecipheriv('aes-256-gcm',AES,all.subarray(0,12));d.setAuthTag(all.subarray(all.length-16));dec=JSON.parse(Buffer.concat([d.update(all.subarray(12,all.length-16)),d.final()]).toString());}
  console.log(`poll#${i}  ${r.status} sigOk=${sigOk} cfg.i=${dec?dec.cfg.i:'-'} reg=${dec?dec.reg:'-'} cmds=${dec?dec.cmds.length:'-'}`);
}
const dbg=await (await fetch(BASE+'/api/debug?token=bx8debug')).json();
const mine=dbg.devices.find(d=>d.id===DEV);
console.log('VISIBLE :', mine?('YES '+JSON.stringify(mine)):'NO');
console.log('drops   :', JSON.stringify(dbg.counters.drops));
process.exit(mine?0:1);
