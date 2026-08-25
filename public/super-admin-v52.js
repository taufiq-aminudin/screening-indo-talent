window.addEventListener('error',e=>{const m=document.querySelector('#m');if(m)m.textContent='Super Admin script error: '+(e.message||'unknown error')});

const $=s=>document.querySelector(s);
const money=n=>'Rp '+Number(n||0).toLocaleString('id-ID');
const num=n=>Number(n||0).toLocaleString('id-ID');
function esc(v){return String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
async function api(p,o={}){o={...o,headers:{...(o.headers||{})}};const t=sessionStorage.getItem('ai_screening_admin_token');if(t&&!o.headers.Authorization)o.headers.Authorization='Bearer '+t;const r=await fetch(p,{credentials:'same-origin',cache:'no-store',...o});const d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.error||d.detail||'request_failed');return d}
function statusPill(s){return '<span class="pill '+esc(s)+'">'+esc(s)+'</span>'}
function orderRows(orders){return orders.map(x=>'<tr><td><b>'+esc(x.company_name||'-')+'</b><div class="small">'+esc(x.company_email||'')+'</div></td><td>'+esc(x.package_code)+'</td><td>'+num(x.credits)+'</td><td>'+money(x.amount_idr)+'</td><td>'+statusPill(x.status)+'</td><td>'+esc(x.payment_method||'-')+'</td><td>'+esc(x.payment_reference||'-')+'</td><td>'+esc(x.created_at?new Date(x.created_at).toLocaleString('id-ID'):'-')+'</td><td><div class="actions">'+(x.payment_proof_key?'<a class="btn secondary" target="_blank" rel="noopener" href="/api/billing/orders/'+encodeURIComponent(x.id)+'/payment-proof">View proof</a>':'<span class="small proof-missing">Upload proof required</span>')+((['pending','awaiting_payment','payment_submitted'].includes(x.status)&&x.payment_proof_key)?'<button class="btn" type="button" onclick="approveOrder(&quot;'+esc(x.id)+'&quot;)">Approve</button>':'')+(['pending','awaiting_payment','payment_submitted'].includes(x.status)?'<button class="btn danger" type="button" onclick="rejectOrder(&quot;'+esc(x.id)+'&quot;)">Reject</button>':'')+'</div></td></tr>').join('');}
function render(o,c,orders){
  const pending=(orders||[]).filter(x=>['pending','awaiting_payment','payment_submitted'].includes(x.status)).length;
  const paid=(orders||[]).filter(x=>x.status==='paid').length;
  const rejected=(orders||[]).filter(x=>x.status==='rejected').length;
  const packages=[{n:'Starter',c:1000,p:99000},{n:'Growth',c:5000,p:399000},{n:'Professional',c:15000,p:999000},{n:'Enterprise',c:50000,p:2999000}];
  const packageHtml=packages.map(x=>'<div class="package"><h3>'+x.n+'</h3><div class="price">'+money(x.p)+'</div><b>'+num(x.c)+' credits</b><div class="tag">Customer-facing credits, not provider tokens.</div></div>').join('');
  const companyHtml=(c||[]).map(x=>'<tr><td><b>'+esc(x.company_name||'-')+'</b></td><td>'+esc(x.email||'-')+'</td><td><span class="pill">'+num(x.balance)+'</span></td><td>'+num(x.lifetime_purchased)+'</td></tr>').join('');
  $('#root').innerHTML='<div class="card"><div style="display:flex;justify-content:space-between;align-items:center;gap:15px"><div><div class="brand" style="margin:0">Super Admin Dashboard</div><div class="muted">Commercial, companies, credits, orders and platform overview</div></div><button class="btn" type="button" onclick="logout()">Logout</button></div></div>'+
  '<div class="grid"><div class="card metric">Users<b>'+num(o.users)+'</b></div><div class="card metric">Companies<b>'+num(o.companies)+'</b></div><div class="card metric">Active jobs<b>'+num(o.jobs)+'</b></div><div class="card metric">Revenue<b>'+money(o.revenue_idr)+'</b></div></div>'+
  '<div class="card"><h2>AI Screening Credits</h2><div class="packages">'+packageHtml+'</div></div>'+
  '<div class="card"><div class="section-head"><div><h2 style="margin:0 0 4px">Credit Purchase Requests</h2><div class="muted">Process company package requests and activate credits after payment verification.</div></div><div class="filters"><button class="btn secondary" type="button" onclick="loadOrders()">Refresh</button><button class="btn" type="button" onclick="filterOrders(\'pending\')">Pending ('+pending+')</button><button class="btn secondary" type="button" onclick="filterOrders(\'paid\')">Paid ('+paid+')</button><button class="btn secondary" type="button" onclick="filterOrders(\'rejected\')">Rejected ('+rejected+')</button><button class="btn secondary" type="button" onclick="filterOrders(\'all\')">All</button></div></div><div class="table-wrap"><table class="table"><thead><tr><th>Company</th><th>Package</th><th>Credits</th><th>Amount</th><th>Status</th><th>Payment method</th><th>Payment reference</th><th>Created</th><th>Action</th></tr></thead><tbody id="orderRows">'+orderRows(orders)+'</tbody></table></div></div>'+
  '<div class="card"><h2>Client companies</h2><div class="table-wrap"><table class="table" style="min-width:700px"><thead><tr><th>Company</th><th>Contact</th><th>Credits</th><th>Purchased</th></tr></thead><tbody>'+companyHtml+'</tbody></table></div></div>';
}
async function load(){
  const root=$('#root');
  try{
    const me=await api('/api/auth/me');
    if(!me.user||me.user.role!=='admin')throw Error('admin_required');
    // Load each admin section independently. A single failing query must never
    // leave the entire dashboard stuck on "Loading dashboard".
    const results=await Promise.all([
      api('/api/admin/overview').then(v=>({ok:true,value:v})).catch(e=>({ok:false,error:e})),
      api('/api/admin/companies').then(v=>({ok:true,value:v})).catch(e=>({ok:false,error:e})),
      api('/api/admin/orders').then(v=>({ok:true,value:v})).catch(e=>({ok:false,error:e}))
    ]);
    const [ov,co,or]=results;
    if(!ov.ok && !co.ok && !or.ok){
      throw Error('Dashboard API gagal dimuat. Overview: '+ov.error.message+' | Companies: '+co.error.message+' | Orders: '+or.error.message);
    }
    const o=ov.ok?ov.value:{users:0,companies:0,jobs:0,revenue_idr:0};
    const c=co.ok?co.value:[];
    const orders=or.ok?or.value:[];
    render(o,c,orders);
    const warnings=[];
    if(!ov.ok)warnings.push('Overview: '+ov.error.message);
    if(!co.ok)warnings.push('Companies: '+co.error.message);
    if(!or.ok)warnings.push('Orders: '+or.error.message);
    if(warnings.length){
      const rootNow=$('#root');
      const w=document.createElement('div');
      w.className='card admin-warning';
      w.innerHTML='<b>Some dashboard data could not be loaded.</b><div class="small">'+esc(warnings.join(' · '))+'</div><button class="btn secondary" type="button" style="margin-top:10px" onclick="load()">Retry</button>';
      rootNow.prepend(w);
    }
  }catch(e){
    if(root){
      root.innerHTML='<div class="card" style="max-width:760px;margin:60px auto"><h2>Super Admin</h2><p class="muted">Dashboard gagal dimuat.</p><div class="admin-error">'+esc(e.message||'unknown_error')+'</div><button class="btn" type="button" onclick="load()">Retry</button><button class="btn secondary" type="button" style="margin-left:8px" onclick="logout()">Logout</button></div>';
    }
  }
}
async function loadOrders(status='all'){
  try{const d=await api('/api/admin/orders?status='+encodeURIComponent(status));const rows=$('#orderRows');if(rows)rows.innerHTML=orderRows(d)}catch(e){alert('Gagal memuat orders: '+e.message)}
}
window.filterOrders=loadOrders;
async function approveOrder(id){const ref=prompt('Payment reference / transfer reference (optional):','');if(ref===null)return;try{const r=await api('/api/admin/orders/'+encodeURIComponent(id)+'/approve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payment_reference:ref})});alert('Payment approved. '+num(r.balance)+' credits sekarang tersedia untuk perusahaan.');await load()}catch(e){alert('Approve gagal: '+e.message)}}
async function rejectOrder(id){const reason=prompt('Alasan reject:','Payment not verified');if(reason===null)return;try{await api('/api/admin/orders/'+encodeURIComponent(id)+'/reject',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({reason})});alert('Order ditolak.');await load()}catch(e){alert('Reject gagal: '+e.message)}}
async function logout(){try{await api('/api/auth/logout',{method:'POST'})}catch{}sessionStorage.removeItem('ai_screening_admin_token');location.reload()}
const form=$('#f');
if(form){
  api('/api/admin/config-status').then(x=>{const cfg=$('#cfg');if(cfg)cfg.textContent=x.ok?'Secure configuration ready · '+x.auth_mode+' · '+x.configured_email_masked:'Configuration incomplete · set SUPER_ADMIN_EMAIL and SUPER_ADMIN_PASSWORD in this Worker'}).catch(()=>{const cfg=$('#cfg');if(cfg)cfg.textContent='Configuration status unavailable'});
  form.onsubmit=async e=>{e.preventDefault();const m=$('#m');if(m)m.textContent='Signing in...';try{const login=await api('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:$('#e').value,password:$('#p').value})});if(login.admin_token)sessionStorage.setItem('ai_screening_admin_token',login.admin_token);await load()}catch(x){if(m)m.textContent=x.message==='admin_not_configured'?'Bootstrap Super Admin belum terlihat oleh deployment Worker ini. Pastikan Secret SUPER_ADMIN_EMAIL dan SUPER_ADMIN_PASSWORD sudah tersimpan pada Worker yang sama lalu deploy versi terbaru.':x.message==='invalid_admin_credentials'?'Email atau password Super Admin tidak cocok. Gunakan credential Super Admin, bukan login perusahaan.':x.message}};
}
load();
