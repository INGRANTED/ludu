import crypto from 'node:crypto';
const BASE=process.argv[2]||'http://127.0.0.1:10099';
const b64=b=>Buffer.from(b).toString('base64');
const hkdf=(salt,secret,info)=>{const prk=crypto.createHmac('sha256',Buffer.from(salt)).update(secret).digest();return crypto.createHmac('sha256',prk).update(Buffer.concat([Buffer.from(info),Buffer.from([1])])).digest();};
const enc=(k,p)=>{const iv=crypto.randomBytes(12);const c=crypto.createCipheriv('aes-256-gcm',k,iv);const ct=Buffer.concat([c.update(Buffer.from(p,'utf8')),c.final()]);return b64(Buffer.concat([iv,ct,c.getAuthTag()]));};
const mac=(k,m)=>crypto.createHmac('sha256',k).update(m).digest('base64');
async function hello(dev,extra={}){
  const e=crypto.createECDH('prime256v1'); e.generateKeys();
  const r=await fetch(BASE+'/api/hello',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({dev,name:'Samsung SM-A127F',pkg:'com.alamin.ludu',st:'ingame',pk:b64(e.getPublicKey()),v:8,...extra})});
  const j=await r.json();
  const secret=e.computeSecret(Buffer.from(j.spk,'base64'));
  return {status:r.status,j,secret};
}
async function poll(secret,sid,salt){
  const AES=hkdf(salt,secret,'enc'), MAC=hkdf(salt,secret,'sig');
  const wire=enc(AES,JSON.stringify({st:'ingame',name:'Samsung SM-A127F',pkg:'com.alamin.ludu',polls:1,ig:1}));
  const r=await fetch(BASE+'/api/poll',{method:'POST',headers:{'content-type':'text/plain','x-sid':sid,'x-sig':mac(MAC,sid+'|'+wire)},body:wire});
  return r.status;
}
const NEW='bx10-session-salt-do-not-publish';
const OLD='bx8-session-salt-do-not-publish';

// 1: current salt
let a=await hello('devCurrent');
console.log('hello(current)   ',a.status,'sid?',!!a.j.sid);
console.log('poll(current)    ',await poll(a.secret,a.j.sid,NEW));

// 2: APK built with the OLD salt (exactly the field failure)
let b=await hello('devOldSalt');
console.log('hello(oldsalt)   ',b.status,'sid?',!!b.j.sid);
console.log('poll(oldsalt)    ',await poll(b.secret,b.j.sid,OLD),'<- must be 200');

// 3: wrong salt entirely -> 401
let c=await hello('devWrong');
console.log('poll(wrongsalt)  ',await poll(c.secret,c.j.sid,'totally-made-up'),'<- must be 401');

// 4: legacy field names
const e2=crypto.createECDH('prime256v1'); e2.generateKeys();
const lr=await fetch(BASE+'/api/hello',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({deviceId:'devLegacyFields',pub:b64(e2.getPublicKey()),dn:'Pixel 7',state:'idle',v:7})});
console.log('hello(legacyfld) ',lr.status,(await lr.json()).sid?'sid ✅':'no sid ❌');

// 5: legacy /api/register
const rr=await fetch(BASE+'/api/register',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({dev:'devLegacyReg',name:'Old Phone'})});
console.log('legacy register  ',rr.status);

// 6: uplink
const ur=await fetch(BASE+'/api/uplink',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({dev:'devUp'})});
console.log('uplink           ',ur.status);

// 7: visibility
const dbg=await (await fetch(BASE+'/api/debug?token=bx8debug')).json();
console.log('devices          ',dbg.devices.map(d=>d.id).join(','));
console.log('counters         ',JSON.stringify({reg:dbg.counters.reg,regOk:dbg.counters.regOk,drop:dbg.counters.drop,drops:dbg.counters.drops,legacyReg:dbg.counters.legacyReg,uplink:dbg.counters.uplink}));
