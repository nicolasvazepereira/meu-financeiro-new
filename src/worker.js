const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };

const TABLES = {
  accounts: ['name', 'type', 'initial_balance', 'color'],
  categories: ['name', 'type', 'color'],
  transactions: ['account_id', 'category_id', 'description', 'amount', 'type', 'date', 'status', 'notes'],
  cards: ['account_id', 'name', 'brand', 'credit_limit', 'closing_day', 'due_day', 'color'],
  invoices: ['card_id', 'reference_month', 'amount', 'status', 'due_date'],
  budgets: ['category_id', 'name', 'amount', 'reference_month'],
  goals: ['name', 'target_amount', 'current_amount', 'target_date', 'color']
};

const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');

async function hash(password, salt) {
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: new TextEncoder().encode(salt), iterations: 120000, hash: 'SHA-256' }, km, 256));
}
function token() { return b64(crypto.getRandomValues(new Uint8Array(32))).replace(/[+/=]/g, ''); }
async function body(req) { try { return await req.json() } catch { return null } }

async function auth(req, env) {
  const h = req.headers.get('authorization') || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!t) return null;
  return env.DB.prepare("SELECT u.id,u.name,u.email,s.token FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires_at>datetime('now')").bind(t).first();
}

let migrated = false;
async function migrate(env) {
  if (migrated) return;
  const stmts = [
    env.DB.prepare('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,salt TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)'),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS accounts(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,name TEXT NOT NULL,type TEXT NOT NULL DEFAULT 'checking',initial_balance REAL NOT NULL DEFAULT 0,color TEXT NOT NULL DEFAULT '#22c55e',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,name TEXT NOT NULL,type TEXT NOT NULL DEFAULT 'expense',color TEXT NOT NULL DEFAULT '#3b82f6',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS transactions(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,account_id INTEGER,category_id INTEGER,description TEXT,amount REAL NOT NULL DEFAULT 0,type TEXT NOT NULL DEFAULT 'expense',date TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'paid',notes TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS cards(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,account_id INTEGER,name TEXT NOT NULL,brand TEXT,credit_limit REAL NOT NULL DEFAULT 0,closing_day INTEGER,due_day INTEGER,color TEXT NOT NULL DEFAULT '#3b82f6',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS invoices(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,card_id INTEGER,reference_month TEXT,amount REAL NOT NULL DEFAULT 0,status TEXT NOT NULL DEFAULT 'pending',due_date TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS budgets(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,category_id INTEGER,name TEXT NOT NULL,amount REAL NOT NULL DEFAULT 0,reference_month TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS goals(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,name TEXT NOT NULL,target_amount REAL NOT NULL DEFAULT 0,current_amount REAL NOT NULL DEFAULT 0,target_date TEXT,color TEXT NOT NULL DEFAULT '#22c55e',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)")
  ];
  try {
    await env.DB.batch(stmts);
  } catch (e) {
    console.error('Migration table error:', e.message);
    throw e;
  }
  try {
    await env.DB.batch([
      env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)'),
      env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions(user_id)'),
      env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_transactions_date ON transactions(date)'),
      env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_accounts_user ON accounts(user_id)'),
      env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_categories_user ON categories(user_id)'),
      env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_cards_user ON cards(user_id)'),
      env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_invoices_user ON invoices(user_id)'),
      env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_budgets_user ON budgets(user_id)'),
      env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_goals_user ON goals(user_id)')
    ]);
  } catch (e) {
    console.error('Migration index error:', e.message);
  }
  migrated = true;
}

async function api(req, env) {
  const url = new URL(req.url), path = url.pathname, method = req.method;
  try { await migrate(env); } catch (e) {
    console.error('Migration failed:', e.message);
    return json({ error: 'Erro de migração: ' + e.message }, 500);
  }

  if (path === '/api/health') return json({ ok: true, service: 'MinhasFinancas' });

  if (path === '/api/auth/register' && method === 'POST') {
    const d = await body(req);
    if (!d?.name || !d?.email || !d?.password || d.password.length < 8)
      return json({ error: 'Informe nome, e-mail e senha com 8 ou mais caracteres.' }, 400);
    const salt = token(), ph = await hash(d.password, salt);
    try {
      const r = await env.DB.prepare('INSERT INTO users(name,email,password_hash,salt) VALUES(?,?,?,?)').bind(d.name.trim(), d.email.trim().toLowerCase(), ph, salt).run();
      await seed(env, r.meta.last_row_id);
      return json({ ok: true }, 201);
    } catch (e) {
      const msg = String(e?.message || e);
      if (msg.includes('UNIQUE')) return json({ error: 'E-mail já cadastrado.' }, 409);
      console.error('Register error:', msg);
      return json({ error: 'Erro ao criar conta: ' + msg }, 500);
    }
  }

  if (path === '/api/auth/login' && method === 'POST') {
    const d = await body(req), u = await env.DB.prepare('SELECT * FROM users WHERE email=? COLLATE NOCASE').bind(d?.email || '').first();
    if (!u || await hash(d?.password || '', u.salt) !== u.password_hash)
      return json({ error: 'Credenciais inválidas.' }, 401);
    const t = token();
    await env.DB.prepare("INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,datetime('now','+30 days'))").bind(t, u.id).run();
    return json({ token: t, user: { id: u.id, name: u.name, email: u.email } });
  }

  const user = await auth(req, env);
  if (!user) return json({ error: 'Não autorizado.' }, 401);

  if (path === '/api/auth/me') return json({ user });

  if (path === '/api/auth/logout' && method === 'POST') {
    await env.DB.prepare('DELETE FROM sessions WHERE token=?').bind(user.token).run();
    return json({ ok: true });
  }

  if (path === '/api/dashboard') {
    const month = url.searchParams.get('month') || new Date().toISOString().slice(0, 7);
    const [totals, recent, byCategory] = await Promise.all([
      env.DB.prepare("SELECT COALESCE(SUM(CASE WHEN type='income' THEN amount ELSE 0 END),0) income,COALESCE(SUM(CASE WHEN type='expense' THEN amount ELSE 0 END),0) expense FROM transactions WHERE user_id=? AND substr(date,1,7)=?").bind(user.id, month).first(),
      env.DB.prepare('SELECT t.*,c.name category,a.name account FROM transactions t LEFT JOIN categories c ON c.id=t.category_id LEFT JOIN accounts a ON a.id=t.account_id WHERE t.user_id=? ORDER BY date DESC,id DESC LIMIT 8').bind(user.id).all(),
      env.DB.prepare("SELECT COALESCE(c.name,'Sem categoria') name,SUM(t.amount) value FROM transactions t LEFT JOIN categories c ON c.id=t.category_id WHERE t.user_id=? AND t.type='expense' AND substr(t.date,1,7)=? GROUP BY c.name ORDER BY value DESC LIMIT 6").bind(user.id, month).all()
    ]);
    const now = new Date();
    const months = [];
    for (let i = 5; i >= 0; i--) months.push(new Date(now.getFullYear(), now.getMonth() - i, 1).toISOString().slice(0, 7));
    const placeholders = months.map(() => '?').join(',');
    const monthlyData = await env.DB.prepare(
      `SELECT substr(date,1,7) month,SUM(CASE WHEN type='income' THEN amount ELSE 0 END) income,SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) expense FROM transactions WHERE user_id=? AND substr(date,1,7) IN (${placeholders}) GROUP BY substr(date,1,7)`
    ).bind(user.id, ...months).all();
    const monthlyMap = {};
    for (const row of monthlyData.results) monthlyMap[row.month] = row;
    const monthly = months.map(m => ({ month: m, income: monthlyMap[m]?.income || 0, expense: monthlyMap[m]?.expense || 0 }));
    return json({ month, totals: { ...totals, balance: totals.income - totals.expense }, recent: recent.results, byCategory: byCategory.results, monthly });
  }

  if (path === '/api/export/transactions.csv') {
    const r = await env.DB.prepare('SELECT date,type,description,amount,status FROM transactions WHERE user_id=? ORDER BY date DESC').bind(user.id).all();
    const esc = v => '"' + String(v ?? '').replaceAll('"', '""') + '"';
    return new Response(['data,tipo,descricao,valor,status', ...r.results.map(x => [x.date, x.type, x.description, x.amount, x.status].map(esc).join(','))].join('\n'), {
      headers: { 'content-type': 'text/csv; charset=utf-8', 'content-disposition': 'attachment; filename="transacoes.csv"' }
    });
  }

  if (path === '/api/bootstrap' && method === 'GET') {
    const [accounts, categories, cards] = await Promise.all([
      env.DB.prepare('SELECT * FROM accounts WHERE user_id=? ORDER BY id DESC').bind(user.id).all(),
      env.DB.prepare('SELECT * FROM categories WHERE user_id=? ORDER BY id DESC').bind(user.id).all(),
      env.DB.prepare('SELECT * FROM cards WHERE user_id=? ORDER BY id DESC').bind(user.id).all()
    ]);
    return json({ accounts: accounts.results, categories: categories.results, cards: cards.results });
  }

  const m = path.match(/^\/api\/(accounts|categories|transactions|cards|invoices|budgets|goals)(?:\/(\d+))?$/);
  if (!m) return json({ error: 'Rota não encontrada.' }, 404);
  const [_, table, id] = m, allowed = TABLES[table];

  if (method === 'GET') {
    let sql = `SELECT * FROM ${table} WHERE user_id=?`, args = [user.id];
    if (id) { sql += ' AND id=?'; args.push(+id); }
    if (table === 'transactions') {
      const q = url.searchParams.get('q'), type = url.searchParams.get('type'), month = url.searchParams.get('month');
      if (q) { sql += ' AND description LIKE ?'; args.push('%' + q + '%'); }
      if (type) { sql += ' AND type=?'; args.push(type); }
      if (month) { sql += ' AND substr(date,1,7)=?'; args.push(month); }
    }
    sql += ' ORDER BY id DESC';
    const r = await env.DB.prepare(sql).bind(...args).all();
    return json(id ? (r.results[0] || null) : r.results);
  }

  const d = await body(req);
  if (!d) return json({ error: 'JSON inválido.' }, 400);

  if (method === 'POST') {
    const keys = allowed.filter(k => d[k] !== undefined);
    if (!keys.length) return json({ error: 'Nenhum campo válido.' }, 400);
    const vals = keys.map(k => d[k]);
    const r = await env.DB.prepare(`INSERT INTO ${table}(user_id,${keys.join(',')}) VALUES(?,${keys.map(() => '?').join(',')})`).bind(user.id, ...vals).run();
    return json({ id: r.meta.last_row_id }, 201);
  }

  if (method === 'PUT' && id) {
    const keys = allowed.filter(k => d[k] !== undefined);
    if (!keys.length) return json({ error: 'Nenhum campo válido.' }, 400);
    await env.DB.prepare(`UPDATE ${table} SET ${keys.map(k => k + '=?').join(',')} WHERE id=? AND user_id=?`).bind(...keys.map(k => d[k]), +id, user.id).run();
    return json({ ok: true });
  }

  if (method === 'DELETE' && id) {
    await env.DB.prepare(`DELETE FROM ${table} WHERE id=? AND user_id=?`).bind(+id, user.id).run();
    return json({ ok: true });
  }

  return json({ error: 'Método não permitido.' }, 405);
}

async function seed(env, uid) {
  await env.DB.batch([
    env.DB.prepare("INSERT INTO accounts(user_id,name,type,initial_balance,color) VALUES(?,?,?,?,?)").bind(uid, 'Conta principal', 'checking', 0, '#22c55e'),
    env.DB.prepare("INSERT INTO categories(user_id,name,type,color) VALUES(?,?,?,?)").bind(uid, 'Salário', 'income', '#22c55e'),
    env.DB.prepare("INSERT INTO categories(user_id,name,type,color) VALUES(?,?,?,?)").bind(uid, 'Alimentação', 'expense', '#f97316'),
    env.DB.prepare("INSERT INTO categories(user_id,name,type,color) VALUES(?,?,?,?)").bind(uid, 'Moradia', 'expense', '#3b82f6'),
    env.DB.prepare("INSERT INTO categories(user_id,name,type,color) VALUES(?,?,?,?)").bind(uid, 'Transporte', 'expense', '#8b5cf6')
  ]);
}

const CSS = `:root{--bg:#0f172a;--surface:#1e293b;--surface2:#334155;--text:#f1f5f9;--muted:#94a3b8;--primary:#3b82f6;--danger:#ef4444;--success:#22c55e;--warning:#f59e0b;--border:#334155;--radius:12px}body[data-theme="light"]{--bg:#f8fafc;--surface:#fff;--surface2:#f1f5f9;--text:#0f172a;--muted:#64748b;--border:#e2e8f0}*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);min-height:100vh}input,select,button,textarea{font:inherit;color:inherit}input,select,textarea{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 12px;width:100%}input:focus,select:focus,textarea:focus{outline:2px solid var(--primary)}button{cursor:pointer;border:none;border-radius:8px;padding:10px 16px;font-weight:600}button[type="submit"]{background:var(--primary);color:#fff}button[type="submit"]:hover{opacity:.9}.danger{background:var(--danger)!important;color:#fff;padding:4px 12px;font-size:.85rem}.topbar{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;background:var(--surface);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100}.topbar-left{display:flex;align-items:center;gap:12px}.topbar-left strong{font-size:1.1rem}.topbar-right{display:flex;gap:8px;align-items:center}.topbar-right select{width:auto;padding:6px 8px}.topbar-right button{padding:6px 12px;background:var(--surface2)}.hamburger{display:flex;flex-direction:column;gap:4px;cursor:pointer;padding:4px;background:none;border:none}.hamburger span{width:24px;height:3px;background:var(--text);border-radius:2px;transition:.3s}.hamburger.open span:nth-child(1){transform:rotate(45deg) translate(5px,5px)}.hamburger.open span:nth-child(2){opacity:0}.hamburger.open span:nth-child(3){transform:rotate(-45deg) translate(6px,-6px)}.sidebar{position:fixed;top:0;left:-260px;width:240px;height:100vh;background:var(--surface);border-right:1px solid var(--border);z-index:200;transition:left .3s ease;padding:16px 0;overflow-y:auto}.sidebar.open{left:0}.sidebar-overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.5);z-index:150;display:none}.sidebar-overlay.show{display:block}.sidebar-header{padding:0 16px 16px;border-bottom:1px solid var(--border);margin-bottom:8px}.sidebar-header strong{font-size:1.1rem}.nav{display:flex;flex-direction:column;gap:2px;padding:0 8px}.nav a{display:flex;align-items:center;gap:10px;padding:12px 14px;color:var(--muted);font-size:.95rem;font-weight:500;border-radius:8px;transition:background .15s;cursor:pointer;text-decoration:none}.nav a:hover{background:var(--surface2)}.nav a.active{color:var(--primary);background:rgba(59,130,246,.12)}.nav a .nav-icon{font-size:1.2rem;width:24px;text-align:center}.sidebar-footer{position:absolute;bottom:0;left:0;right:0;padding:12px 16px;border-top:1px solid var(--border)}.container{max-width:1000px;margin:0 auto;padding:16px}.section{background:var(--surface);border-radius:var(--radius);padding:16px;margin-bottom:16px}.section h2{font-size:1.1rem;margin-bottom:12px}.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}.form-grid button{grid-column:1/-1}@media(min-width:600px){.form-grid{grid-template-columns:repeat(3,1fr)}}.stats{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px}@media(min-width:600px){.stats{grid-template-columns:repeat(4,1fr)}}.stat-card{background:var(--surface);border-radius:var(--radius);padding:16px;text-align:center}.stat-card span{display:block;color:var(--muted);font-size:.85rem;margin-bottom:4px}.stat-card b{font-size:1.3rem}.stat-card.income b{color:var(--success)}.stat-card.expense b{color:var(--danger)}.stat-card.balance b{color:var(--primary)}.card{background:var(--surface);border-radius:var(--radius);padding:14px;margin-bottom:10px}.card b{font-size:1rem}.card .meta{display:flex;flex-wrap:wrap;gap:12px;color:var(--muted);font-size:.85rem;margin-top:4px}.card button{margin-top:8px}.muted{color:var(--muted)}.badge{display:inline-block;padding:2px 8px;border-radius:6px;font-size:.8rem;font-weight:600}.badge.paid,.badge.income{background:rgba(34,197,94,.2);color:var(--success)}.badge.pending,.badge.expense{background:rgba(245,158,11,.2);color:var(--warning)}.badge.overdue{background:rgba(239,68,68,.2);color:var(--danger)}.chart-wrap{position:relative;height:320px;margin-top:8px}.login-wrap{max-width:400px;margin:60px auto}.login-wrap h1{text-align:center;margin-bottom:24px}.login-wrap .card{background:var(--surface);border-radius:var(--radius);padding:20px;margin-bottom:16px}.login-wrap h2{font-size:1rem;margin-bottom:12px;color:var(--muted)}.login-wrap form{display:flex;flex-direction:column;gap:10px}.msg{padding:10px;border-radius:8px;text-align:center;font-size:.9rem;display:none}.msg.error{display:block;background:rgba(239,68,68,.15);color:var(--danger)}.msg.ok{display:block;background:rgba(34,197,94,.15);color:var(--success)}.progress{height:8px;background:var(--surface2);border-radius:4px;overflow:hidden;margin-top:8px}.progress-bar{height:100%;background:var(--primary);border-radius:4px;transition:width .3s}.filters{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;align-items:center}.filters input,.filters select{width:auto;min-width:120px}.filters button,.filters a{padding:10px 16px;border-radius:8px;font-weight:600;text-decoration:none;color:var(--text);background:var(--surface2);border:none;cursor:pointer}`;

const APP_JS = `const $=s=>document.querySelector(s),$$=s=>document.querySelectorAll(s);
const money=v=>(+v||0).toLocaleString('pt-BR',{style:'currency',currency:'BRL'});
const today=()=>new Date().toISOString().slice(0,10);
const curMonth=()=>new Date().toISOString().slice(0,7);
let TOKEN=localStorage.getItem('mf_token');
let USER=JSON.parse(localStorage.getItem('mf_user')||'null');
async function api(path,opt={}){
  let r;
  try{r=await fetch('/api/'+path,{headers:{'content-type':'application/json',...(TOKEN?{'authorization':'Bearer '+TOKEN}:{}),...opt.headers},...opt})}
  catch(e){throw new Error('Sem conexão')}
  let j;
  try{j=await r.json()}catch{throw new Error('Erro (status '+r.status+')')}
  if(!r.ok)throw new Error(j.error||'Erro');
  return j;
}
const post=(p,b)=>api(p,{method:'POST',body:JSON.stringify(b)});
const put=(p,b)=>api(p,{method:'PUT',body:JSON.stringify(b)});
const del=(p)=>api(p,{method:'DELETE'});
const NAV=[['dashboard','Dashboard','📊'],['transactions','Transações','💰'],['accounts','Contas','🏦'],['categories','Categorias','🏷️'],['cards','Cartões','💳'],['invoices','Faturas','📄'],['budgets','Orçamentos','🎯'],['goals','Metas','🏆']];
let currentPage='dashboard',chartInstance=null,accountsCache=[],categoriesCache=[],cardsCache=[],cacheLoaded=false;
async function loadCache(force=false){
  if(cacheLoaded&&!force)return;
  try{
    const b=await api('bootstrap');
    accountsCache=b.accounts||[];
    categoriesCache=b.categories||[];
    cardsCache=b.cards||[];
    cacheLoaded=true;
  }catch{
    try{accountsCache=await api('accounts')}catch{accountsCache=[]}
    try{categoriesCache=await api('categories')}catch{categoriesCache=[]}
    try{cardsCache=await api('cards')}catch{cardsCache=[]}
    cacheLoaded=true;
  }
}
function renderNav(){
  $('.nav').innerHTML=NAV.map(([id,n,i])=>'<a data-page="'+id+'" class="'+(currentPage===id?'active':'')+'"><span class="nav-icon">'+i+'</span>'+n+'</a>').join('');
  $$('.nav a').forEach(a=>a.onclick=e=>{e.preventDefault();currentPage=a.dataset.page;navigate()});
}
async function navigate(){
  try{
    $$('.nav a').forEach(a=>a.classList.toggle('active',a.dataset.page===currentPage));
    const titles={dashboard:'Dashboard',transactions:'Transações',accounts:'Contas',categories:'Categorias',cards:'Cartões',invoices:'Faturas',budgets:'Orçamentos',goals:'Metas'};
    $('#pageTitle').textContent=titles[currentPage]||'';
    await loadCache();
    const pages={dashboard:renderDashboard,transactions:renderTransactions,accounts:renderAccounts,categories:renderCategories,cards:renderCards,invoices:renderInvoices,budgets:renderBudgets,goals:renderGoals};
    (pages[currentPage]||renderDashboard)();
    closeMenu();
  }catch(e){console.error(e)}
}
function closeMenu(){$('#sidebar').classList.remove('open');$('#hamburger').classList.remove('open');$('#sidebarOverlay').classList.remove('show')}
function initLogin(){
  if(TOKEN){location.href='/';return}
  $('#loginForm').onsubmit=async e=>{
    e.preventDefault();
    try{const r=await post('auth/login',{email:$('#lemail').value,password:$('#lpass').value});TOKEN=r.token;USER=r.user;localStorage.setItem('mf_token',TOKEN);localStorage.setItem('mf_user',JSON.stringify(USER));location.href='/'}
    catch(x){showMsg(x.message)}
  };
  $('#registerForm').onsubmit=async e=>{
    e.preventDefault();
    try{await post('auth/register',{name:$('#rname').value,email:$('#remail').value,password:$('#rpass').value});showMsg('Conta criada! Faça login acima.',true)}
    catch(x){showMsg(x.message)}
  };
}
function showMsg(t,ok=false){let m=$('#msg');if(!m)return;m.className='msg '+(ok?'ok':'error');m.textContent=t}
async function initApp(){
  if(!TOKEN){location.href='/login.html';return}
  try{const me=await api('auth/me');USER=me.user;$('#userName').textContent=USER.name}
  catch{TOKEN=null;localStorage.removeItem('mf_token');location.href='/login.html';return}
  let theme=localStorage.getItem('mf_theme')||'dark';
  document.body.dataset.theme=theme;
  $('#theme').value=theme;
  $('#theme').onchange=e=>{localStorage.setItem('mf_theme',e.target.value);document.body.dataset.theme=e.target.value};
  $('#logout').onclick=$('#logout2').onclick=async()=>{try{await post('auth/logout')}catch{}TOKEN=null;localStorage.removeItem('mf_token');localStorage.removeItem('mf_user');location.href='/login.html'};
  const ham=$('#hamburger'),sb=$('#sidebar'),ov=$('#sidebarOverlay');
  ham.onclick=()=>{sb.classList.toggle('open');ham.classList.toggle('open');ov.classList.toggle('show')};
  ov.onclick=closeMenu;
  renderNav();
  navigate();
}
async function renderDashboard(){
  $('#content').innerHTML='<div class="stats"><div class="stat-card balance"><span>Saldo do mês</span><b id="dBalance">—</b></div><div class="stat-card income"><span>Receitas</span><b id="dIncome">—</b></div><div class="stat-card expense"><span>Despesas</span><b id="dExpense">—</b></div><div class="stat-card"><span>Transações recentes</span><b id="dCount">—</b></div></div><div class="section"><h2>Receitas vs Despesas (6 meses)</h2><div class="chart-wrap"><canvas id="dChart"></canvas></div></div><div class="section"><h2>Despesas por categoria</h2><div id="dCatChart"></div></div><div class="section"><h2>Transações recentes</h2><div id="dRecent"></div></div>';
  try{
    const d=await api('dashboard');
    $('#dBalance').textContent=money(d.totals.balance);
    $('#dIncome').textContent=money(d.totals.income);
    $('#dExpense').textContent=money(d.totals.expense);
    $('#dCount').textContent=d.recent.length;
    $('#dRecent').innerHTML=d.recent.map(t=>'<div class="card"><b>'+(t.description||'—')+'</b> <span class="badge '+t.type+'">'+(t.type==='income'?'Receita':'Despesa')+'</span><div class="meta"><span>'+t.date+'</span><span>'+(t.category||'—')+'</span><span>'+(t.account||'—')+'</span><span style="color:'+(t.type==='income'?'var(--success)':'var(--danger)')+'">'+money(t.amount)+'</span></div></div>').join('')||'<p class="muted">Nenhuma transação.</p>';
    if(d.byCategory.length){
      const max=Math.max(...d.byCategory.map(c=>c.value),1);
      $('#dCatChart').innerHTML=d.byCategory.map(c=>'<div style="margin-bottom:8px"><div style="display:flex;justify-content:space-between;font-size:.85rem"><span>'+c.name+'</span><b>'+money(c.value)+'</b></div><div class="progress"><div class="progress-bar" style="width:'+(c.value/max*100).toFixed(0)+'%"></div></div></div>').join('');
    }else{$('#dCatChart').innerHTML='<p class="muted">Sem despesas neste mês.</p>'}
    const labels=d.monthly.map(m=>{const y=m.month.split('-')[0],mo=m.month.split('-')[1];return['Jan','Fev','Mar','Abr','Mai','Jun','Jul','Ago','Set','Out','Nov','Dez'][+mo-1]+'/'+y.slice(2)});
    const incomeData=d.monthly.map(m=>m.income);
    const expenseData=d.monthly.map(m=>m.expense);
    if(chartInstance)chartInstance.destroy();
    chartInstance=new Chart($('#dChart'),{type:'bar',data:{labels,datasets:[{label:'Receitas',data:incomeData,backgroundColor:'rgba(34,197,94,.7)'},{label:'Despesas',data:expenseData,backgroundColor:'rgba(239,68,68,.7)'}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'top'}},scales:{y:{ticks:{callback:v=>money(v)}}}}});
  }catch(e){$('#dRecent').innerHTML='<p class="muted">Erro: '+e.message+'</p>'}
}
async function renderTransactions(){
  const accOpts=accountsCache.map(a=>'<option value="'+a.id+'">'+a.name+'</option>').join('');
  const catOpts=categoriesCache.map(c=>'<option value="'+c.id+'">'+c.name+'</option>').join('');
  $('#content').innerHTML='<div class="section"><h2>Nova transação</h2><form id="form" class="form-grid"><input name="date" type="date" value="'+today()+'" required><input name="description" placeholder="Descrição" required><input name="amount" type="number" step="0.01" placeholder="Valor" required><select name="type"><option value="expense">Despesa</option><option value="income">Receita</option></select><select name="account_id"><option value="">Conta</option>'+accOpts+'</select><select name="category_id"><option value="">Categoria</option>'+catOpts+'</select><select name="status"><option value="paid">Pago</option><option value="pending">Pendente</option></select><input name="notes" placeholder="Observações"><button type="submit">Adicionar</button></form></div><div class="section"><h2>Transações</h2><div class="filters"><input id="tSearch" placeholder="Buscar..." style="width:200px"><select id="tType"><option value="">Todos os tipos</option><option value="income">Receitas</option><option value="expense">Despesas</option></select><input id="tMonth" type="month" value="'+curMonth()+'"><button id="tFilter">Filtrar</button><button id="exportBtn">Exportar CSV</button></div><div id="cards"></div></div>';
  $('#form').onsubmit=async e=>{e.preventDefault();const o=Object.fromEntries(new FormData(e.target));if(o.account_id)o.account_id=+o.account_id;if(o.category_id)o.category_id=+o.category_id;o.amount=+o.amount;try{await post('transactions',o);e.target.reset();loadTransactions()}catch(x){alert(x.message)}};
  $('#tFilter').onclick=loadTransactions;
  $('#exportBtn').onclick=exportCSV;
  loadTransactions();
}
async function loadTransactions(){
  const params=new URLSearchParams();
  const q=$('#tSearch').value,type=$('#tType').value,month=$('#tMonth').value;
  if(q)params.set('q',q);if(type)params.set('type',type);if(month)params.set('month',month);
  try{
    const r=await api('transactions?'+params);
    $('#cards').innerHTML=r.map(t=>'<div class="card"><b>'+(t.description||'—')+'</b> <span class="badge '+t.type+'">'+(t.type==='income'?'Receita':'Despesa')+'</span><div class="meta"><span>'+t.date+'</span><span>Status: '+t.status+'</span><span style="color:'+(t.type==='income'?'var(--success)':'var(--danger)')+'">'+money(t.amount)+'</span></div><button class="danger" onclick="delItem(\\'transactions\\','+t.id+')">Excluir</button></div>').join('')||'<p class="muted">Nenhuma transação.</p>';
  }catch(e){$('#cards').innerHTML='<p class="muted">Erro: '+e.message+'</p>'}
}
async function exportCSV(){
  try{const r=await fetch('/api/export/transactions.csv',{headers:{'authorization':'Bearer '+TOKEN}});const blob=await r.blob();const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='transacoes.csv';a.click();URL.revokeObjectURL(url)}catch(e){alert(e.message)}
}
async function renderAccounts(){
  $('#content').innerHTML='<div class="section"><h2>Nova conta</h2><form id="form" class="form-grid"><input name="name" placeholder="Nome" required><select name="type"><option value="checking">Conta corrente</option><option value="savings">Poupança</option><option value="cash">Dinheiro</option><option value="credit">Crédito</option></select><input name="initial_balance" type="number" step="0.01" placeholder="Saldo inicial" value="0"><input name="color" type="color" value="#22c55e"><button type="submit">Adicionar</button></form></div><div class="section"><h2>Contas</h2><div id="cards"></div></div>';
  $('#form').onsubmit=async e=>{e.preventDefault();const o=Object.fromEntries(new FormData(e.target));o.initial_balance=+o.initial_balance;try{await post('accounts',o);e.target.reset();loadAccounts()}catch(x){alert(x.message)}};
  loadAccounts();
}
async function loadAccounts(){
  try{const r=await api('accounts');accountsCache=r;const types={checking:'Conta corrente',savings:'Poupança',cash:'Dinheiro',credit:'Crédito'};
    $('#cards').innerHTML=r.map(a=>'<div class="card"><b>'+a.name+'</b><div class="meta"><span>'+(types[a.type]||a.type)+'</span><span>Saldo inicial: '+money(a.initial_balance)+'</span></div><button class="danger" onclick="delItem(\\'accounts\\','+a.id+')">Excluir</button></div>').join('')||'<p class="muted">Nenhuma conta.</p>';
  }catch(e){$('#cards').innerHTML='<p class="muted">Erro: '+e.message+'</p>'}
}
async function renderCategories(){
  $('#content').innerHTML='<div class="section"><h2>Nova categoria</h2><form id="form" class="form-grid"><input name="name" placeholder="Nome" required><select name="type"><option value="expense">Despesa</option><option value="income">Receita</option></select><input name="color" type="color" value="#3b82f6"><button type="submit">Adicionar</button></form></div><div class="section"><h2>Categorias</h2><div id="cards"></div></div>';
  $('#form').onsubmit=async e=>{e.preventDefault();const o=Object.fromEntries(new FormData(e.target));try{await post('categories',o);e.target.reset();loadCategories()}catch(x){alert(x.message)}};
  loadCategories();
}
async function loadCategories(){
  try{const r=await api('categories');categoriesCache=r;
    $('#cards').innerHTML=r.map(c=>'<div class="card"><b>'+c.name+'</b> <span class="badge '+c.type+'">'+(c.type==='income'?'Receita':'Despesa')+'</span><button class="danger" onclick="delItem(\\'categories\\','+c.id+')">Excluir</button></div>').join('')||'<p class="muted">Nenhuma categoria.</p>';
  }catch(e){$('#cards').innerHTML='<p class="muted">Erro: '+e.message+'</p>'}
}
async function renderCards(){
  const accOpts=accountsCache.map(a=>'<option value="'+a.id+'">'+a.name+'</option>').join('');
  $('#content').innerHTML='<div class="section"><h2>Novo cartão</h2><form id="form" class="form-grid"><input name="name" placeholder="Nome" required><input name="brand" placeholder="Bandeira (Visa, Mastercard...)"><select name="account_id"><option value="">Conta</option>'+accOpts+'</select><input name="credit_limit" type="number" step="0.01" placeholder="Limite" value="0"><input name="closing_day" type="number" placeholder="Dia fechamento" min="1" max="31"><input name="due_day" type="number" placeholder="Dia vencimento" min="1" max="31"><input name="color" type="color" value="#3b82f6"><button type="submit">Adicionar</button></form></div><div class="section"><h2>Cartões</h2><div id="cards"></div></div>';
  $('#form').onsubmit=async e=>{e.preventDefault();const o=Object.fromEntries(new FormData(e.target));if(o.account_id)o.account_id=+o.account_id;if(o.credit_limit)o.credit_limit=+o.credit_limit;if(o.closing_day)o.closing_day=+o.closing_day;if(o.due_day)o.due_day=+o.due_day;try{await post('cards',o);e.target.reset();loadCards()}catch(x){alert(x.message)}};
  loadCards();
}
async function loadCards(){
  try{const r=await api('cards');cardsCache=r;
    $('#cards').innerHTML=r.map(c=>'<div class="card"><b>'+c.name+'</b><div class="meta"><span>Bandeira: '+(c.brand||'—')+'</span><span>Limite: '+money(c.credit_limit)+'</span><span>Fechamento: '+(c.closing_day||'—')+'</span><span>Vencimento: '+(c.due_day||'—')+'</span></div><button class="danger" onclick="delItem(\\'cards\\','+c.id+')">Excluir</button></div>').join('')||'<p class="muted">Nenhum cartão.</p>';
  }catch(e){$('#cards').innerHTML='<p class="muted">Erro: '+e.message+'</p>'}
}
async function renderInvoices(){
  const cardOpts=cardsCache.map(c=>'<option value="'+c.id+'">'+c.name+'</option>').join('');
  $('#content').innerHTML='<div class="section"><h2>Nova fatura</h2><form id="form" class="form-grid"><select name="card_id"><option value="">Cartão</option>'+cardOpts+'</select><input name="reference_month" type="month" value="'+curMonth()+'" required><input name="amount" type="number" step="0.01" placeholder="Valor" required><select name="status"><option value="pending">Pendente</option><option value="paid">Paga</option></select><input name="due_date" type="date"><button type="submit">Adicionar</button></form></div><div class="section"><h2>Faturas</h2><div id="cards"></div></div>';
  $('#form').onsubmit=async e=>{e.preventDefault();const o=Object.fromEntries(new FormData(e.target));if(o.card_id)o.card_id=+o.card_id;o.amount=+o.amount;try{await post('invoices',o);e.target.reset();loadInvoices()}catch(x){alert(x.message)}};
  loadInvoices();
}
async function loadInvoices(){
  try{const r=await api('invoices');
    $('#cards').innerHTML=r.map(i=>{const card=cardsCache.find(c=>c.id===i.card_id);return '<div class="card"><b>'+(card?card.name:'—')+'</b> <span class="badge '+i.status+'">'+(i.status==='paid'?'Paga':'Pendente')+'</span><div class="meta"><span>Referência: '+(i.reference_month||'—')+'</span><span>Vencimento: '+(i.due_date||'—')+'</span><span>'+money(i.amount)+'</span></div><button class="danger" onclick="delItem(\\'invoices\\','+i.id+')">Excluir</button></div>'}).join('')||'<p class="muted">Nenhuma fatura.</p>';
  }catch(e){$('#cards').innerHTML='<p class="muted">Erro: '+e.message+'</p>'}
}
async function renderBudgets(){
  const catOpts=categoriesCache.map(c=>'<option value="'+c.id+'">'+c.name+'</option>').join('');
  $('#content').innerHTML='<div class="section"><h2>Novo orçamento</h2><form id="form" class="form-grid"><input name="name" placeholder="Nome" required><select name="category_id"><option value="">Categoria</option>'+catOpts+'</select><input name="amount" type="number" step="0.01" placeholder="Valor" required><input name="reference_month" type="month" value="'+curMonth()+'"><button type="submit">Adicionar</button></form></div><div class="section"><h2>Orçamentos</h2><div id="cards"></div></div>';
  $('#form').onsubmit=async e=>{e.preventDefault();const o=Object.fromEntries(new FormData(e.target));if(o.category_id)o.category_id=+o.category_id;o.amount=+o.amount;try{await post('budgets',o);e.target.reset();loadBudgets()}catch(x){alert(x.message)}};
  loadBudgets();
}
async function loadBudgets(){
  try{const r=await api('budgets');
    $('#cards').innerHTML=r.map(b=>{const cat=categoriesCache.find(c=>c.id===b.category_id);return '<div class="card"><b>'+b.name+'</b><div class="meta"><span>Categoria: '+(cat?cat.name:'—')+'</span><span>Referência: '+(b.reference_month||'—')+'</span><span>'+money(b.amount)+'</span></div><button class="danger" onclick="delItem(\\'budgets\\','+b.id+')">Excluir</button></div>'}).join('')||'<p class="muted">Nenhum orçamento.</p>';
  }catch(e){$('#cards').innerHTML='<p class="muted">Erro: '+e.message+'</p>'}
}
async function renderGoals(){
  $('#content').innerHTML='<div class="section"><h2>Nova meta</h2><form id="form" class="form-grid"><input name="name" placeholder="Nome" required><input name="target_amount" type="number" step="0.01" placeholder="Alvo" required><input name="current_amount" type="number" step="0.01" placeholder="Atual" value="0"><input name="target_date" type="date"><input name="color" type="color" value="#22c55e"><button type="submit">Adicionar</button></form></div><div class="section"><h2>Metas</h2><div id="cards"></div></div>';
  $('#form').onsubmit=async e=>{e.preventDefault();const o=Object.fromEntries(new FormData(e.target));o.target_amount=+o.target_amount;o.current_amount=+o.current_amount;try{await post('goals',o);e.target.reset();loadGoals()}catch(x){alert(x.message)}};
  loadGoals();
}
async function loadGoals(){
  try{const r=await api('goals');
    $('#cards').innerHTML=r.map(g=>{const pct=g.target_amount>0?Math.min(g.current_amount/g.target_amount*100,100):0;return '<div class="card"><b>'+g.name+'</b><div class="meta"><span>Alvo: '+money(g.target_amount)+'</span><span>Atual: '+money(g.current_amount)+'</span><span>Prazo: '+(g.target_date||'—')+'</span></div><div class="progress"><div class="progress-bar" style="width:'+pct.toFixed(0)+'%;background:'+(g.color||'var(--primary)')+'"></div></div><button class="danger" onclick="delItem(\\'goals\\','+g.id+')">Excluir</button></div>'}).join('')||'<p class="muted">Nenhuma meta.</p>';
  }catch(e){$('#cards').innerHTML='<p class="muted">Erro: '+e.message+'</p>'}
}
async function delItem(table,id){
  if(!confirm('Excluir?'))return;
  try{await del(table+'/'+id);
    cacheLoaded=false;
    const loaders={transactions:loadTransactions,accounts:loadAccounts,categories:loadCategories,cards:loadCards,invoices:loadInvoices,budgets:loadBudgets,goals:loadGoals};
    if(loaders[table])loaders[table]();
  }catch(x){alert(x.message)}
}
window.delItem=delItem;window.exportCSV=exportCSV;`;

const LOGIN_HTML = '<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Minhas Finanças — Login</title><link rel="stylesheet" href="/style.css"></head><body data-theme="dark"><div class="login-wrap"><h1>💰 Minhas Finanças</h1><div class="card"><h2>Entrar</h2><form id="loginForm"><input id="lemail" type="email" placeholder="E-mail" required><input id="lpass" type="password" placeholder="Senha" required><button type="submit">Entrar</button></form></div><div class="card"><h2>Criar conta</h2><form id="registerForm"><input id="rname" placeholder="Nome" required><input id="remail" type="email" placeholder="E-mail" required><input id="rpass" type="password" placeholder="Senha (mín. 8 caracteres)" required minlength="8"><button type="submit">Criar conta</button></form></div><div id="msg" class="msg"></div></div><script src="/app.js"></scr'+'ipt><script>initLogin()</scr'+'ipt></body></html>';

const APP_HTML = '<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Minhas Finanças</title><link rel="stylesheet" href="/style.css"><script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></scr'+'ipt></head><body data-theme="dark"><header class="topbar"><div class="topbar-left"><button class="hamburger" id="hamburger"><span></span><span></span><span></span></button><strong>💰 Minhas Finanças</strong></div><div class="topbar-right"><span id="userName" class="muted"></span><select id="theme"><option value="dark">Dark</option><option value="light">Light</option></select><button id="logout">Sair</button></div></header><div class="sidebar-overlay" id="sidebarOverlay"></div><aside class="sidebar" id="sidebar"><div class="sidebar-header"><strong>💰 Minhas Finanças</strong></div><nav class="nav"></nav><div class="sidebar-footer"><button id="logout2" style="width:100%;background:var(--surface2)">Sair</button></div></aside><main class="container"><h2 id="pageTitle" style="margin-bottom:16px"></h2><div id="content"></div></main><script src="/app.js"></scr'+'ipt><script>initApp()</scr'+'ipt></body></html>';

function serveHTML(url) {
  const p = url.pathname;
  if (p === '/style.css') return new Response(CSS, { headers: { 'content-type': 'text/css; charset=utf-8', 'cache-control': 'no-store' } });
  if (p === '/app.js') return new Response(APP_JS, { headers: { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'no-store' } });
  if (p === '/login.html' || p === '/login') return new Response(LOGIN_HTML, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
  return new Response(APP_HTML, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
}

export default {
  async fetch(req, env) {
    try {
      const url = new URL(req.url);
      if (url.pathname.startsWith('/api/')) return await api(req, env);
      return serveHTML(url);
    } catch (e) {
      console.error(e);
      return json({ error: 'Erro interno.' }, 500);
    }
  }
};
