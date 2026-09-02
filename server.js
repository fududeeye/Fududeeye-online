const express=require('express');
const path=require('path');
const fs=require('fs');
const Database=require('better-sqlite3');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');

const app=express();
app.use(express.json({limit:'1mb'}));
const PORT=process.env.PORT||3000;
const JWT_SECRET=process.env.JWT_SECRET||'CHANGE_ME_IN_PRODUCTION';
const ADMIN_USER=process.env.ADMIN_USER||'admin';
const ADMIN_PASSWORD=process.env.ADMIN_PASSWORD||'CHANGE_ME';
const dataDir=path.join(__dirname,'data');
fs.mkdirSync(dataDir,{recursive:true});
const db=new Database(path.join(dataDir,'fududeeye.db'));
db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS customers (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 phone TEXT NOT NULL UNIQUE,
 dob TEXT NOT NULL,
 gender TEXT NOT NULL,
 city TEXT NOT NULL,
 password_hash TEXT NOT NULL,
 phone_verified INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);`);
db.exec(`CREATE TABLE IF NOT EXISTS otp_verifications (
 id TEXT PRIMARY KEY,
 phone TEXT NOT NULL,
 purpose TEXT NOT NULL,
 payload TEXT,
 code_hash TEXT NOT NULL,
 expires_at INTEGER NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,
 used INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);`);

function normalizePhone(v='') { return String(v).replace(/\D/g,'').replace(/^252/,'').replace(/^0/,''); }
function sign(user){return jwt.sign({id:user.id,phone:user.phone},JWT_SECRET,{expiresIn:'30d'});}
function auth(req,res,next){
 const h=req.headers.authorization||''; if(!h.startsWith('Bearer ')) return res.status(401).json({error:'Login required.'});
 try{req.user=jwt.verify(h.slice(7),JWT_SECRET);next();}catch(e){return res.status(401).json({error:'Session expired. Please login again.'});}
}
function makeOtp(){return String(Math.floor(100000+Math.random()*900000));}
function createOtp(phone,purpose,payload){
 const crypto=require('crypto'); const id=crypto.randomUUID(); const code=makeOtp();
 const hash=bcrypt.hashSync(code,10); const expires=Date.now()+10*60*1000;
 db.prepare('INSERT INTO otp_verifications(id,phone,purpose,payload,code_hash,expires_at) VALUES(?,?,?,?,?,?)').run(id,phone,purpose,JSON.stringify(payload||{}),hash,expires);
 return {id,code};
}
// Demo sender: logs OTP on the server. Replace this function with your SMS provider API later.
async function sendSms(phone,code,purpose){
 console.log(`[SMS DEMO] +252${phone} | ${purpose} | OTP: ${code}`);
 return {sent:true,demo:true};
}

app.post('/api/register/start',async(req,res)=>{
 try{
  const {name,phone,dob,gender,city,password}=req.body||{}; const p=normalizePhone(phone);
  if(!name||name.trim().length<2) return res.status(400).json({error:'Please enter your name.'});
  if(p.length!==9) return res.status(400).json({error:'Please enter a valid +252 number.'});
  if(!dob||!gender||!city||!password||password.length<6) return res.status(400).json({error:'Please complete all registration fields.'});
  if(db.prepare('SELECT id FROM customers WHERE phone=?').get(p)) return res.status(409).json({error:'This phone number is already registered.'});
  const passwordHash=await bcrypt.hash(password,12);
  const payload={name:name.trim(),phone:p,dob,gender,city,passwordHash};
  const o=createOtp(p,'register',payload); await sendSms(p,o.code,'registration');
  res.json({verificationId:o.id});
 }catch(e){console.error(e);res.status(500).json({error:'Server error.'});}
});
app.post('/api/register/resend',async(req,res)=>{
 const old=db.prepare('SELECT * FROM otp_verifications WHERE id=? AND purpose=? AND used=0').get(req.body?.verificationId,'register');
 if(!old)return res.status(404).json({error:'Verification expired.'});
 const payload=JSON.parse(old.payload||'{}'); const o=createOtp(old.phone,'register',payload); await sendSms(old.phone,o.code,'registration'); res.json({verificationId:o.id});
});
app.post('/api/register/check',(req,res)=>{
 try{
  const {verificationId,code}=req.body||{}; const o=db.prepare('SELECT * FROM otp_verifications WHERE id=? AND purpose=? AND used=0').get(verificationId,'register');
  if(!o)return res.status(400).json({error:'Invalid or expired code.'});
  if(Date.now()>o.expires_at)return res.status(400).json({error:'Code expired. Please request a new code.'});
  if(o.attempts>=5)return res.status(429).json({error:'Too many attempts.'});
  db.prepare('UPDATE otp_verifications SET attempts=attempts+1 WHERE id=?').run(o.id);
  if(!bcrypt.compareSync(String(code||''),o.code_hash))return res.status(400).json({error:'Incorrect verification code.'});
  const p=JSON.parse(o.payload||'{}');
  const info=db.prepare('INSERT INTO customers(name,phone,dob,gender,city,password_hash,phone_verified) VALUES(?,?,?,?,?,?,1)').run(p.name,p.phone,p.dob,p.gender,p.city,p.passwordHash);
  db.prepare('UPDATE otp_verifications SET used=1 WHERE id=?').run(o.id);
  const user=db.prepare('SELECT id,name,phone,dob,gender,city,created_at FROM customers WHERE id=?').get(info.lastInsertRowid);
  res.json({token:sign(user),user});
 }catch(e){console.error(e);res.status(500).json({error:e.code==='SQLITE_CONSTRAINT_UNIQUE'?'This phone number is already registered.':'Server error.'});}
});
app.post('/api/login',(req,res)=>{
 const p=normalizePhone(req.body?.phone), password=String(req.body?.password||''); const u=db.prepare('SELECT * FROM customers WHERE phone=?').get(p);
 if(!u||!bcrypt.compareSync(password,u.password_hash))return res.status(401).json({error:'Phone number or password is incorrect.'});
 res.json({token:sign(u),user:{id:u.id,name:u.name,phone:u.phone,dob:u.dob,gender:u.gender,city:u.city}});
});
app.get('/api/me',auth,(req,res)=>{const u=db.prepare('SELECT id,name,phone,dob,gender,city,created_at FROM customers WHERE id=?').get(req.user.id);if(!u)return res.status(404).json({error:'Customer not found.'});res.json({user:u});});
app.post('/api/forgot/start',async(req,res)=>{
 const p=normalizePhone(req.body?.phone); const u=db.prepare('SELECT id,phone FROM customers WHERE phone=?').get(p);
 if(!u)return res.status(404).json({error:'No account found for this phone number.'}); const o=createOtp(p,'forgot',{customerId:u.id}); await sendSms(p,o.code,'password reset'); res.json({verificationId:o.id});
});
app.post('/api/forgot/check',(req,res)=>{
 const {verificationId,code,newPassword}=req.body||{}; if(!newPassword||newPassword.length<6)return res.status(400).json({error:'Password must be at least 6 characters.'});
 const o=db.prepare('SELECT * FROM otp_verifications WHERE id=? AND purpose=? AND used=0').get(verificationId,'forgot'); if(!o||Date.now()>o.expires_at)return res.status(400).json({error:'Invalid or expired code.'});
 if(o.attempts>=5)return res.status(429).json({error:'Too many attempts.'}); db.prepare('UPDATE otp_verifications SET attempts=attempts+1 WHERE id=?').run(o.id);
 if(!bcrypt.compareSync(String(code||''),o.code_hash))return res.status(400).json({error:'Incorrect verification code.'});
 const p=JSON.parse(o.payload||'{}'); const hash=bcrypt.hashSync(newPassword,12); db.prepare('UPDATE customers SET password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(hash,p.customerId); db.prepare('UPDATE otp_verifications SET used=1 WHERE id=?').run(o.id); res.json({ok:true});
});

// Simple admin API. Protect it with HTTP Basic Auth using ADMIN_USER/ADMIN_PASSWORD.
function admin(req,res,next){const h=req.headers.authorization||'';if(!h.startsWith('Basic '))return res.status(401).set('WWW-Authenticate','Basic realm="Fududeeye Admin"').json({error:'Admin login required.'});try{const [u,p]=Buffer.from(h.slice(6),'base64').toString().split(':');if(u!==ADMIN_USER||p!==ADMIN_PASSWORD)throw 0;next();}catch(e){return res.status(401).set('WWW-Authenticate','Basic realm="Fududeeye Admin"').json({error:'Invalid admin credentials.'});}}
app.get('/api/admin/customers',admin,(req,res)=>{const rows=db.prepare('SELECT id,name,phone,dob,gender,city,phone_verified,created_at,updated_at FROM customers ORDER BY id DESC').all();res.json({customers:rows});});
app.get('/api/admin/stats',admin,(req,res)=>{const total=db.prepare('SELECT COUNT(*) c FROM customers').get().c;const verified=db.prepare('SELECT COUNT(*) c FROM customers WHERE phone_verified=1').get().c;res.json({total,verified});});
app.get('/admin',admin,(req,res)=>res.sendFile(path.join(__dirname,'admin.html')));
app.use(express.static(__dirname));
app.listen(PORT,()=>console.log(`Fududeeye server running on http://localhost:${PORT}`));
