const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const app = express();
// Allow the mobile app opened from a local content:// or file:// page to call the Render API.
app.use((req,res,next)=>{
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization, X-Payment-Webhook-Secret');
  if(req.method==='OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json({ limit: '2mb' }));
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME_IN_PRODUCTION';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'CHANGE_ME';
const PAYMENT_WEBHOOK_SECRET = process.env.PAYMENT_WEBHOOK_SECRET || 'CHANGE_ME_PAYMENT_WEBHOOK';

const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'fududeeye.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

try { db.exec("ALTER TABLE stores ADD COLUMN approval_status TEXT NOT NULL DEFAULT 'approved'"); } catch (_) {}

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('customer','seller','admin')),
  city TEXT,
  neighborhood TEXT,
  dob TEXT,
  gender TEXT,
  lat REAL,
  lng REAL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS stores (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  seller_id INTEGER NOT NULL UNIQUE,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  city TEXT NOT NULL,
  neighborhood TEXT NOT NULL,
  address TEXT,
  lat REAL,
  lng REAL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  approval_status TEXT NOT NULL DEFAULT 'approved',
  FOREIGN KEY(seller_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  seller_id INTEGER NOT NULL,
  store_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  price REAL NOT NULL CHECK(price >= 0),
  stock INTEGER NOT NULL DEFAULT 0,
  unit TEXT,
  image TEXT,
  category TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(seller_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(store_id) REFERENCES stores(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_no TEXT NOT NULL UNIQUE,
  customer_id INTEGER NOT NULL,
  seller_id INTEGER NOT NULL,
  store_id INTEGER NOT NULL,
  subtotal REAL NOT NULL,
  delivery_fee REAL NOT NULL DEFAULT 0,
  total REAL NOT NULL,
  payment_method TEXT NOT NULL,
  payment_reference TEXT,
  payment_status TEXT NOT NULL DEFAULT 'processing',
  status TEXT NOT NULL DEFAULT 'processing',
  customer_name TEXT NOT NULL,
  customer_phone TEXT NOT NULL,
  city TEXT NOT NULL,
  neighborhood TEXT NOT NULL,
  address TEXT,
  lat REAL,
  lng REAL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(customer_id) REFERENCES users(id),
  FOREIGN KEY(seller_id) REFERENCES users(id),
  FOREIGN KEY(store_id) REFERENCES stores(id)
);
CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  price REAL NOT NULL,
  quantity INTEGER NOT NULL,
  line_total REAL NOT NULL,
  FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,
  FOREIGN KEY(product_id) REFERENCES products(id)
);
CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL,
  amount REAL NOT NULL,
  method TEXT NOT NULL,
  reference TEXT,
  status TEXT NOT NULL DEFAULT 'processing',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_user_id INTEGER,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id INTEGER,
  details TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_products_seller ON products(seller_id);
CREATE INDEX IF NOT EXISTS idx_orders_customer ON orders(customer_id);
CREATE INDEX IF NOT EXISTS idx_orders_seller ON orders(seller_id);
`);

const defaultCategories = ['Bariis','Baasto','Saliid','Bur','Sonkor','Caano','Cabitaan','Khudaar','Hilib','Qalab kale'];
for (const c of defaultCategories) db.prepare('INSERT OR IGNORE INTO categories(name) VALUES(?)').run(c);

const adminExists = db.prepare('SELECT id FROM users WHERE phone=?').get(ADMIN_USER);
if (!adminExists) {
  const hash = bcrypt.hashSync(ADMIN_PASSWORD, 12);
  db.prepare('INSERT INTO users(name,phone,password_hash,role,active) VALUES(?,?,?,?,1)').run('Maamule', ADMIN_USER, hash, 'admin');
}

function normalizePhone(v='') {
  const s = String(v).replace(/\D/g, '');
  return s.replace(/^252/, '').replace(/^0/, '');
}
function sign(user) { return jwt.sign({ id: user.id, role: user.role, phone: user.phone }, JWT_SECRET, { expiresIn: '30d' }); }
function auth(req,res,next){
  const h=req.headers.authorization||'';
  if(!h.startsWith('Bearer ')) return res.status(401).json({error:'Fadlan marka hore soo gal.'});
  try { req.user=jwt.verify(h.slice(7),JWT_SECRET); next(); }
  catch { return res.status(401).json({error:'Gelitaankaagu wuu dhacay. Fadlan mar kale soo gal.'}); }
}
function requireRole(...roles){ return (req,res,next)=>roles.includes(req.user.role) ? next() : res.status(403).json({error:'Uma lihid oggolaanshahan.'}); }
function audit(actor,action,type,id,details){ db.prepare('INSERT INTO audit_logs(actor_user_id,action,target_type,target_id,details) VALUES(?,?,?,?,?)').run(actor||null,action,type||null,id||null,details?JSON.stringify(details):null); }
function orderNo(){ return 'FO-' + new Date().toISOString().slice(0,10).replace(/-/g,'') + '-' + crypto.randomBytes(3).toString('hex').toUpperCase(); }

app.post('/api/login',(req,res)=>{
  const p=normalizePhone(req.body?.phone); const password=String(req.body?.password||'');
  const u=db.prepare('SELECT * FROM users WHERE phone=?').get(p || req.body?.phone);
  if(!u || !bcrypt.compareSync(password,u.password_hash)) return res.status(401).json({error:'Lambarka ama furaha sirta ah waa khalad.'});
  const store=u.role==='seller' ? db.prepare('SELECT * FROM stores WHERE seller_id=?').get(u.id) : null;
  if(u.role==='seller' && store?.approval_status==='pending') return res.status(403).json({error:'Codsiga bakhaarkaaga wali waa la sugayaa. Fadlan sug inta Admin-ku ansixinayo.'});
  if(u.role==='seller' && store?.approval_status==='rejected') return res.status(403).json({error:'Codsiga bakhaarkaaga waa la diiday. Fadlan la xiriir Maamulka.'});
  if(!u.active) return res.status(401).json({error:'Account-kan hadda ma shaqaynayo.'});
  const safe={id:u.id,name:u.name,phone:u.phone,role:u.role,city:u.city||'',neighborhood:u.neighborhood||'',dob:u.dob||'',gender:u.gender||'',lat:u.lat,lng:u.lng,store};
  res.json({token:sign(u),user:safe});
});

app.post('/api/register/customer',(req,res)=>{
  const {name,phone,password,dob,gender,city,neighborhood,lat,lng}=req.body||{}; const p=normalizePhone(phone);
  if(!name||name.trim().length<2 || p.length!==9 || !password || password.length<6 || !city || !neighborhood) return res.status(400).json({error:'Fadlan buuxi magaca, lambarka, password-ka, magaalada iyo xaafadda.'});
  if(db.prepare('SELECT id FROM users WHERE phone=?').get(p)) return res.status(409).json({error:'Lambarkan hore ayaa account loogu sameeyay.'});
  const hash=bcrypt.hashSync(password,12);
  const info=db.prepare('INSERT INTO users(name,phone,password_hash,role,city,neighborhood,dob,gender,lat,lng) VALUES(?,?,?,?,?,?,?,?,?,?)').run(name.trim(),p,hash,'customer',city,neighborhood,dob||null,gender||null,lat||null,lng||null);
  const u=db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid);
  res.json({token:sign(u),user:{id:u.id,name:u.name,phone:u.phone,role:u.role,city:u.city,neighborhood:u.neighborhood,lat:u.lat,lng:u.lng}});
});

app.post('/api/me/location',auth,(req,res)=>{
  const {lat,lng,city,neighborhood,address}=req.body||{};
  if(typeof lat!=='number'||typeof lng!=='number') return res.status(400).json({error:'Location-ka lama helin.'});
  db.prepare('UPDATE users SET lat=?,lng=?,city=COALESCE(?,city),neighborhood=COALESCE(?,neighborhood),updated_at=CURRENT_TIMESTAMP WHERE id=?').run(lat,lng,city||null,neighborhood||null,req.user.id);
  if(req.user.role==='seller') db.prepare('UPDATE stores SET lat=?,lng=?,city=COALESCE(?,city),neighborhood=COALESCE(?,neighborhood),address=COALESCE(?,address) WHERE seller_id=?').run(lat,lng,city||null,neighborhood||null,address||null,req.user.id);
  res.json({ok:true});
});

app.get('/api/me',auth,(req,res)=>{
  const u=db.prepare('SELECT id,name,phone,role,city,neighborhood,dob,gender,lat,lng,created_at FROM users WHERE id=?').get(req.user.id);
  if(!u) return res.status(404).json({error:'Account-ka lama helin.'});
  const store=u.role==='seller' ? db.prepare('SELECT * FROM stores WHERE seller_id=?').get(u.id) : null;
  res.json({user:{...u,store}});
});

app.post('/api/register/seller',(req,res)=>{
  const {name,phone,password,storeName,city,neighborhood,address,lat,lng}=req.body||{}; const p=normalizePhone(phone);
  if(!name||name.trim().length<2||p.length!==9||!password||password.length<6||!storeName||!city||!neighborhood) return res.status(400).json({error:'Fadlan buuxi xogta iibiyaha iyo bakhaarka.'});
  if(db.prepare('SELECT id FROM users WHERE phone=?').get(p)) return res.status(409).json({error:'Lambarkan hore ayaa account loogu sameeyay.'});
  const tx=db.transaction(()=>{
    const hash=bcrypt.hashSync(password,12);
    const u=db.prepare("INSERT INTO users(name,phone,password_hash,role,city,neighborhood,lat,lng,active) VALUES(?,?,?,?,?,?,?,?,0)").run(name.trim(),p,hash,'seller',city,neighborhood,lat||null,lng||null);
    const st=db.prepare("INSERT INTO stores(seller_id,name,phone,city,neighborhood,address,lat,lng,active,approval_status) VALUES(?,?,?,?,?,?,?,?,0,'pending')").run(u.lastInsertRowid,storeName.trim(),p,city,neighborhood,address||'',lat||null,lng||null);
    return {userId:u.lastInsertRowid,storeId:st.lastInsertRowid};
  });
  const out=tx(); audit(null,'seller_application','store',out.storeId,{userId:out.userId,status:'pending'});
  res.json({ok:true,pending:true,message:'Waad ku guulaysatey inaad diwaangaliso bakhaarkaaga fadlan sug inta la soo aqblayo foomkaaga ugu badnaan 24hours mahadsanid.'});
});

app.post('/api/admin/sellers',auth,requireRole('admin'),(req,res)=>{
  const {name,phone,password,storeName,city,neighborhood,address,lat,lng}=req.body||{}; const p=normalizePhone(phone);
  if(!name||p.length!==9||!password||password.length<6||!storeName||!city||!neighborhood) return res.status(400).json({error:'Fadlan buuxi xogta iibiyaha iyo bakhaarka.'});
  if(db.prepare('SELECT id FROM users WHERE phone=?').get(p)) return res.status(409).json({error:'Lambarkan hore ayaa loo isticmaalay.'});
  const tx=db.transaction(()=>{
    const hash=bcrypt.hashSync(password,12);
    const u=db.prepare('INSERT INTO users(name,phone,password_hash,role,city,neighborhood,lat,lng) VALUES(?,?,?,?,?,?,?,?)').run(name.trim(),p,hash,'seller',city,neighborhood,lat||null,lng||null);
    const s=db.prepare('INSERT INTO stores(seller_id,name,phone,city,neighborhood,address,lat,lng) VALUES(?,?,?,?,?,?,?,?)').run(u.lastInsertRowid,storeName.trim(),p,city,neighborhood,address||'',lat||null,lng||null);
    return {userId:u.lastInsertRowid,storeId:s.lastInsertRowid};
  });
  const out=tx(); audit(req.user.id,'create','seller',out.userId,{storeId:out.storeId}); res.json(out);
});

app.get('/api/admin/customers',auth,requireRole('admin'),(req,res)=>{ const rows=db.prepare("SELECT id,name,phone,city,neighborhood,active,created_at FROM users WHERE role='customer' ORDER BY id DESC").all(); res.json({customers:rows}); });
app.get('/api/admin/sellers',auth,requireRole('admin'),(req,res)=>{
  const rows=db.prepare(`SELECT u.id,u.name,u.phone,u.city,u.neighborhood,u.active,u.created_at,s.id store_id,s.name store_name,s.address,s.lat,s.lng,s.approval_status
    FROM users u LEFT JOIN stores s ON s.seller_id=u.id WHERE u.role='seller' ORDER BY u.id DESC`).all(); res.json({sellers:rows});
});
app.patch('/api/admin/sellers/:id/approval',auth,requireRole('admin'),(req,res)=>{
  const id=Number(req.params.id); const status=String(req.body.status||'');
  if(!['approved','rejected','pending'].includes(status)) return res.status(400).json({error:'Xaalad ansixin aan sax ahayn.'});
  const seller=db.prepare("SELECT u.id,s.id store_id FROM users u JOIN stores s ON s.seller_id=u.id WHERE u.id=? AND u.role='seller'").get(id);
  if(!seller) return res.status(404).json({error:'Iibiyaha lama helin.'});
  const active=status==='approved'?1:0;
  const tx=db.transaction(()=>{
    db.prepare('UPDATE users SET active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(active,id);
    db.prepare('UPDATE stores SET active=?,approval_status=? WHERE seller_id=?').run(active,status,id);
  }); tx(); audit(req.user.id,'seller_approval','store',seller.store_id,{status});
  res.json({ok:true,status});
});

app.patch('/api/admin/users/:id/active',auth,requireRole('admin'),(req,res)=>{ const id=Number(req.params.id); db.prepare('UPDATE users SET active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(req.body.active?1:0,id); audit(req.user.id,'set_active','user',id,{active:!!req.body.active}); res.json({ok:true}); });

app.get('/api/categories',(req,res)=>res.json({categories:db.prepare('SELECT * FROM categories WHERE active=1 ORDER BY name').all()}));

app.get('/api/products',(req,res)=>{
  const city=String(req.query.city||''); const neighborhood=String(req.query.neighborhood||'');
  const q=String(req.query.q||'').trim();
  let sql=`SELECT p.*, s.name store_name, s.phone store_phone, s.city store_city, s.neighborhood store_neighborhood, s.address store_address, s.lat store_lat, s.lng store_lng FROM products p JOIN stores s ON s.id=p.store_id WHERE p.active=1 AND s.active=1`;
  const params=[];
  if(q){sql+=' AND (LOWER(p.name) LIKE ? OR LOWER(COALESCE(p.description,\'\')) LIKE ? OR LOWER(COALESCE(p.category,\'\')) LIKE ?)';const like='%'+q.toLowerCase()+'%';params.push(like,like,like);}
  sql+=' ORDER BY CASE WHEN s.neighborhood=? THEN 0 WHEN s.city=? THEN 1 ELSE 2 END, p.id DESC'; params.push(neighborhood,city);
  const rows=db.prepare(sql).all(...params); res.json({products:rows});
});

app.get('/api/seller/products',auth,requireRole('seller'),(req,res)=>res.json({products:db.prepare('SELECT * FROM products WHERE seller_id=? ORDER BY id DESC').all(req.user.id)}));
app.post('/api/seller/products',auth,requireRole('seller'),(req,res)=>{
  const {name,description,price,stock,unit,image,category}=req.body||{}; if(!name||Number(price)<0||Number.isNaN(Number(price))) return res.status(400).json({error:'Magaca iyo qiimaha alaabta waa qasab.'});
  const store=db.prepare('SELECT id FROM stores WHERE seller_id=?').get(req.user.id); if(!store) return res.status(400).json({error:'Bakhaarka iibiyaha lama helin.'});
  const info=db.prepare('INSERT INTO products(seller_id,store_id,name,description,price,stock,unit,image,category) VALUES(?,?,?,?,?,?,?,?,?)').run(req.user.id,store.id,name.trim(),description||'',Number(price),Math.max(0,Number(stock||0)),unit||'',image||'',category||''); audit(req.user.id,'create','product',info.lastInsertRowid,{name}); res.json({id:info.lastInsertRowid});
});
app.patch('/api/seller/products/:id',auth,requireRole('seller'),(req,res)=>{
  const id=Number(req.params.id); const old=db.prepare('SELECT * FROM products WHERE id=? AND seller_id=?').get(id,req.user.id); if(!old)return res.status(404).json({error:'Alaabtaas adiga ma lihid.'});
  const next={...old,...req.body};
  db.prepare('UPDATE products SET name=?,description=?,price=?,stock=?,unit=?,image=?,category=?,active=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND seller_id=?').run(String(next.name),next.description||'',Number(next.price),Math.max(0,Number(next.stock||0)),next.unit||'',next.image||'',next.category||'',next.active===false?0:1,id,req.user.id); audit(req.user.id,'update','product',id,{before:old,after:next}); res.json({ok:true});
});
app.delete('/api/seller/products/:id',auth,requireRole('seller'),(req,res)=>{ const id=Number(req.params.id); const r=db.prepare('UPDATE products SET active=0,updated_at=CURRENT_TIMESTAMP WHERE id=? AND seller_id=?').run(id,req.user.id); if(!r.changes)return res.status(404).json({error:'Alaabta lama helin.'}); audit(req.user.id,'delete','product',id); res.json({ok:true}); });

app.get('/api/seller/orders',auth,requireRole('seller'),(req,res)=>{
  const rows=db.prepare(`SELECT o.*, p.amount payment_amount,p.method payment_method2,p.reference payment_reference2 FROM orders o LEFT JOIN payments p ON p.order_id=o.id WHERE o.seller_id=? ORDER BY o.id DESC`).all(req.user.id);
  for(const r of rows) r.items=db.prepare('SELECT * FROM order_items WHERE order_id=?').all(r.id);
  res.json({orders:rows});
});

app.post('/api/orders',auth,requireRole('customer'),(req,res)=>{
  const {storeId,items,paymentMethod,paymentReference,city,neighborhood,address,lat,lng,deliveryFee=0}=req.body||{};
  if(!storeId||!Array.isArray(items)||!items.length)return res.status(400).json({error:'Dalabku ma dhammaystirna.'});
  const customer=db.prepare('SELECT * FROM users WHERE id=? AND role=\'customer\' AND active=1').get(req.user.id);
  const store=db.prepare('SELECT s.*,u.active seller_active FROM stores s JOIN users u ON u.id=s.seller_id WHERE s.id=? AND s.active=1').get(Number(storeId));
  if(!customer||!store||!store.seller_active)return res.status(400).json({error:'Bakhaarka lama heli karo.'});
  const tx=db.transaction(()=>{
    let subtotal=0; const lines=[];
    for(const item of items){
      const p=db.prepare('SELECT * FROM products WHERE id=? AND store_id=? AND active=1').get(Number(item.productId),store.id);
      const q=Math.floor(Number(item.quantity)); if(!p||q<1)throw new Error('Alaab aan sax ahayn.');
      if(p.stock<q)throw new Error(`Stock-ku kuma filna: ${p.name}.`);
      const line=p.price*q; subtotal+=line; lines.push({p,q,line});
    }
    const total=subtotal+Number(deliveryFee||0); const no=orderNo();
    const info=db.prepare(`INSERT INTO orders(order_no,customer_id,seller_id,store_id,subtotal,delivery_fee,total,payment_method,payment_reference,payment_status,status,customer_name,customer_phone,city,neighborhood,address,lat,lng) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(no,customer.id,store.seller_id,store.id,subtotal,Number(deliveryFee||0),total,paymentMethod||'mobile-money',paymentReference||'', 'processing','processing',customer.name,customer.phone,city||customer.city,neighborhood||customer.neighborhood,address||'',typeof lat==='number'?lat:customer.lat,typeof lng==='number'?lng:customer.lng);
    for(const l of lines){ db.prepare('INSERT INTO order_items(order_id,product_id,name,price,quantity,line_total) VALUES(?,?,?,?,?,?)').run(info.lastInsertRowid,l.p.id,l.p.name,l.p.price,l.q,l.line); db.prepare('UPDATE products SET stock=stock-? WHERE id=?').run(l.q,l.p.id); }
    db.prepare('INSERT INTO payments(order_id,amount,method,reference,status) VALUES(?,?,?,?,?)').run(info.lastInsertRowid,total,paymentMethod||'mobile-money',paymentReference||'','processing');
    return {id:info.lastInsertRowid,orderNo:no,total,storePhone:store.phone};
  });
  try{ const out=tx(); audit(req.user.id,'create','order',out.id,{orderNo:out.orderNo,sellerId:store.seller_id}); res.json(out); }catch(e){ return res.status(400).json({error:e.message||'Dalabka lama samayn.'}); }
});

app.get('/api/orders',auth,requireRole('customer'),(req,res)=>{
  const rows=db.prepare(`SELECT o.*,s.name store_name,s.phone store_phone FROM orders o JOIN stores s ON s.id=o.store_id WHERE o.customer_id=? ORDER BY o.id DESC`).all(req.user.id);
  for(const r of rows) r.items=db.prepare('SELECT * FROM order_items WHERE order_id=?').all(r.id);
  res.json({orders:rows});
});

app.patch('/api/seller/orders/:id/status',auth,requireRole('seller'),(req,res)=>{
  const id=Number(req.params.id); const status=String(req.body.status||''); const allowed=['processing','accepted','ready','delivering','delivered','rejected'];
  if(!allowed.includes(status))return res.status(400).json({error:'Status aan sax ah.'});
  const o=db.prepare('SELECT * FROM orders WHERE id=? AND seller_id=?').get(id,req.user.id); if(!o)return res.status(404).json({error:'Dalabka lama helin.'});
  const paid=o.payment_method==='Cash'||o.payment_status==='confirmed';
  if(status==='accepted'&&!paid)return res.status(409).json({error:'Lacagta weli lama xaqiijin. Dalabku Processing ayuu ku jiraa.'});
  if(status==='rejected'){
    const tx=db.transaction(()=>{
      db.prepare('UPDATE orders SET status=?,payment_status=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND seller_id=?').run('rejected',o.payment_status==='confirmed'?'refunded':'rejected',id,req.user.id);
      db.prepare('UPDATE payments SET status=? WHERE order_id=?').run(o.payment_status==='confirmed'?'refunded':'rejected',id);
      for(const item of db.prepare('SELECT product_id,quantity FROM order_items WHERE order_id=?').all(id)) db.prepare('UPDATE products SET stock=stock+? WHERE id=?').run(item.quantity,item.product_id);
    }); tx(); audit(req.user.id,'status','order',id,{status}); return res.json({ok:true});
  }
  db.prepare('UPDATE orders SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND seller_id=?').run(status,id,req.user.id);
  audit(req.user.id,'status','order',id,{status}); res.json({ok:true});
});

// Lacag-bixin automatic ah: provider-ka rasmiga ah ee Zaad/eDahab ayaa halkan callback ku soo diri kara.
// App-ku ma sheeganayo in lacag la bixiyay ilaa callback saxiixan uu xaqiijiyo.
app.post('/api/payments/webhook',(req,res)=>{
  const secret=req.headers['x-payment-webhook-secret'];
  if(!secret||secret!==PAYMENT_WEBHOOK_SECRET)return res.status(401).json({error:'Webhook aan la oggolayn.'});
  const {orderNo,reference,status,amount,method}=req.body||{};
  if(!orderNo||!status)return res.status(400).json({error:'orderNo iyo status waa qasab.'});
  const o=db.prepare('SELECT * FROM orders WHERE order_no=?').get(String(orderNo)); if(!o)return res.status(404).json({error:'Dalabka lama helin.'});
  const st=String(status).toLowerCase(); if(!['confirmed','failed','rejected'].includes(st))return res.status(400).json({error:'Payment status aan la aqbalin.'});
  if(st==='confirmed'&&amount!=null&&Math.abs(Number(amount)-Number(o.total))>0.01)return res.status(409).json({error:'Lacagta la xaqiijiyay kama dhigna wadarta dalabka.'});
  const finalStatus=st==='confirmed'?'confirmed':'failed';
  const tx=db.transaction(()=>{
    db.prepare('UPDATE orders SET payment_reference=COALESCE(?,payment_reference),payment_status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(reference||null,finalStatus,o.id);
    db.prepare('UPDATE payments SET reference=COALESCE(?,reference),method=COALESCE(?,method),status=? WHERE order_id=?').run(reference||null,method||null,finalStatus,o.id);
  }); tx(); audit(null,'payment_webhook','order',o.id,{status:st,reference,amount,method}); res.json({ok:true,orderNo:o.order_no,paymentStatus:finalStatus});
});

app.get('/api/admin/stats',auth,requireRole('admin'),(req,res)=>{
  const customers=db.prepare("SELECT COUNT(*) c FROM users WHERE role='customer'").get().c;
  const sellers=db.prepare("SELECT COUNT(*) c FROM users WHERE role='seller'").get().c;
  const products=db.prepare('SELECT COUNT(*) c FROM products WHERE active=1').get().c;
  const orders=db.prepare('SELECT COUNT(*) c FROM orders').get().c;
  const processing=db.prepare("SELECT COUNT(*) c FROM orders WHERE status='processing'").get().c;
  const sales=db.prepare('SELECT COALESCE(SUM(total),0) s FROM orders WHERE status IN (\'accepted\',\'ready\',\'delivering\',\'delivered\')').get().s;
  res.json({customers,sellers,products,orders,processing,sales});
});
app.get('/api/admin/orders',auth,requireRole('admin'),(req,res)=>{ const rows=db.prepare(`SELECT o.*,s.name store_name,s.phone store_phone FROM orders o JOIN stores s ON s.id=o.store_id ORDER BY o.id DESC`).all(); for(const r of rows)r.items=db.prepare('SELECT * FROM order_items WHERE order_id=?').all(r.id); res.json({orders:rows}); });
app.get('/api/admin/products',auth,requireRole('admin'),(req,res)=>res.json({products:db.prepare(`SELECT p.*,s.name store_name,s.phone store_phone FROM products p JOIN stores s ON s.id=p.store_id ORDER BY p.id DESC`).all()}));
app.patch('/api/admin/products/:id',auth,requireRole('admin'),(req,res)=>{const id=Number(req.params.id);const p=db.prepare('SELECT * FROM products WHERE id=?').get(id);if(!p)return res.status(404).json({error:'Alaabta lama helin.'});const next={...p,...req.body};db.prepare('UPDATE products SET name=?,description=?,price=?,stock=?,unit=?,image=?,category=?,active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(String(next.name),next.description||'',Number(next.price),Math.max(0,Number(next.stock||0)),next.unit||'',next.image||'',next.category||'',next.active===false?0:1,id);audit(req.user.id,'admin_update','product',id,{before:p,after:next});res.json({ok:true});});

app.get('/health',(req,res)=>res.json({ok:true,service:'Fududeeye Online'}));
app.get('/admin',(req,res)=>res.sendFile(path.join(__dirname,'index.html')));
app.use(express.static(__dirname));
app.listen(PORT,()=>console.log(`Fududeeye server running on http://localhost:${PORT}`));
