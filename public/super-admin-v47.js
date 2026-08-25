window.addEventListener('error',e=>{const m=document.querySelector('#m');if(m)m.textContent='Super Admin script error: '+(e.message||'unknown error')});

const $=s=>document.querySelector(s);
const money=n=>'Rp '+Number(n||0).toLocaleString('id-ID');
const num=n=>Number(n||0).toLocaleString('id-ID');
function esc(v){return String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}
async function api(p,o={}){const r=await fetch(p,{credentials:'same-origin',cache:'no-store',...o});const d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.error||d.detail||'request_failed');return d}
function statusPill(s){return '<span class="pill '+esc(s)+'">'+esc(s)+'</span>'}
function orderRows(orders){
  if(!(orders||[]).length)return '<tr><td colspan="8" class="empty">No credit purchase requests found.</td></tr>';
  return orders.map(x=>'<tr><td><b>'+esc(x.company_name||'-')+'</b><div class="small">'+esc(x.company_email||'')+'</div></td><td>'+esc(x.package_code)+'</td><td>'+num(x.credits)+'</td><td>'+money(x.amount_idr)+'</td><td>'+statusPill(x.status)+'</td><td>'+esc(x.payment_reference||'-')+'</td><td>'+esc(x.created_at?new Date(x.created_at).toLocaleString('id-ID'):'-')+'</td><td>'+(x.status==='pending'?'<div class="actions"><button class="btn" type="button" onclick="approveOrder(&quot;'+esc(x.id)+'&quot;)">Approve</button><button class="btn danger" type="button" onclick="rejectOrder(&quot;'+esc(x.id)+'&quot;)">Reject</button></div>':'<span class="small">'+(x.paid_at?esc(new Date(x.paid_at).toLocaleString('id-ID')):'Processed')+'</span>')+'</td></tr>').join('');
}
function render(o,c,orders){
  const pending=(orders||[]).filter(x=>x.status==='pending').length;
  const paid=(orders||[]).filter(x=>x.status==='paid').length;
  const rejected=(orders||[]).filter(x=>x.status==='rejected').length;
  const packages=[{n:'Starter',c:1000,p:99000},{n:'Growth',c:5000,p:399000},{n:'Professional',c:15000,p:999000},{n:'Enterprise',c:50000,p:2999000}];
  const packageHtml=packages.map(x=>'<div class="package"><h3>'+x.n+'</h3><div class="price">'+money(x.p)+'</div><b>'+num(x.c)+' credits</b><div class="tag">Customer-facing credits, not provider tokens.</div></div>').join('');
  const companyHtml=(c||[]).map(x=>'<tr><td><b>'+esc(x.company_name||'-')+'</b></td><td>'+esc(x.email||'-')+'</td><td><span class="pill">'+num(x.balance)+'</span></td><td>'+num(x.lifetime_purchased)+'</td></tr>').join('');
  $('#root').innerHTML='<div class="card"><div style="display:flex;justify-content:space-between;align-items:center;gap:15px"><div><div class="brand" style="margin:0">Super Admin Dashboard</div><div class="muted">Commercial, companies, credits, orders and platform overview</div></div><button class="btn" type="button" onclick="logout()">Logout</button></div></div>'+
  '<div class="grid"><div class="card metric">Users<b>'+num(o.users)+'</b></div><div class="card metric">Companies<b>'+num(o.companies)+'</b></div><div class="card metric">Active jobs<b>'+num(o.jobs)+'</b></div><div class="card metric">Revenue<b>'+money(o.revenue_idr)+'</b></div></div>'+
  '<div class="card"><h2>AI Screening Credits</h2><div class="packages">'+packageHtml+'</div></div>'+
  '<div class="card"><div class="section-head"><div><h2 style="margin:0 0 4px">Credit Purchase Requests</h2><div class="muted">Process company package requests and activate credits after payment verification.</div></div><div class="filters"><button class="btn secondary" type="button" onclick="loadOrders()">Refresh</button><button class="btn" type="button" onclick="filterOrders(\'pending\')">Pending ('+pending+')</button><button class="btn secondary" type="button" onclick="filterOrders(\'paid\')">Paid ('+paid+')</button><button class="btn secondary" type="button" onclick="filterOrders(\'rejected\')">Rejected ('+rejected+')</button><button class="btn secondary" type="button" onclick="filterOrders(\'all\')">All</button></div></div><div class="table-wrap"><table class="table"><thead><tr><th>Company</th><th>Package</th><th>Credits</th><th>Amount</th><th>Status</th><th>Payment reference</th><th>Created</th><th>Action</th></tr></thead><tbody id="orderRows">'+orderRows(orders)+'</tbody></table></div></div>'+
  '<div class="card"><h2>Client companies</h2><div class="table-wrap"><table class="table" style="min-width:700px"><thead><tr><th>Company</th><th>Contact</th><th>Credits</th><th>Purchased</th></tr></thead><tbody>'+companyHtml+'</tbody></table></div></div>';
}
async function load(){
  try{
    const me=await api('/api/auth/me');
    if(me.user.role!=='admin')throw Error('admin_required');
    const [o,c,orders]=await Promise.all([api('/api/admin/overview'),api('/api/admin/companies'),api('/api/admin/orders')]);
    render(o,c,orders);
  }catch(e){
    const m=$('#m');
    if(m && e.message!=='unauthorized')m.textContent=e.message;
  }
}
async function loadOrders(status='all'){
  try{const d=await api('/api/admin/orders?status='+encodeURIComponent(status));const rows=$('#orderRows');if(rows)rows.innerHTML=orderRows(d)}catch(e){alert('Gagal memuat orders: '+e.message)}
}
window.filterOrders=loadOrders;
async function approveOrder(id){const ref=prompt('Payment reference / transfer reference (optional):','');if(ref===null)return;try{const r=await api('/api/admin/orders/'+encodeURIComponent(id)+'/approve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payment_reference:ref})});alert('Payment approved. '+num(r.balance)+' credits sekarang tersedia untuk perusahaan.');await load()}catch(e){alert('Approve gagal: '+e.message)}}
async function rejectOrder(id){const reason=prompt('Alasan reject:','Payment not verified');if(reason===null)return;try{await api('/api/admin/orders/'+encodeURIComponent(id)+'/reject',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({reason})});alert('Order ditolak.');await load()}catch(e){alert('Reject gagal: '+e.message)}}
async function logout(){await api('/api/auth/logout',{method:'POST'});location.reload()}
api('/api/admin/config-status').then(x=>{$('#cfg').textContent=x.ok?'Secure configuration ready · '+x.auth_mode+' · '+x.configured_email_masked:'Configuration incomplete · set SUPER_ADMIN_EMAIL and SUPER_ADMIN_PASSWORD in this Worker'}).catch(()=>{$('#cfg').textContent='Configuration status unavailable'});
$('#f').onsubmit=async e=>{e.preventDefault();const m=$('#m');m.textContent='Signing in...';try{await api('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:$('#e').value,password:$('#p').value})});await load()}catch(x){m.textContent=x.message==='admin_not_configured'?'Bootstrap Super Admin belum terlihat oleh deployment Worker ini. Pastikan Secret SUPER_ADMIN_EMAIL dan SUPER_ADMIN_PASSWORD sudah tersimpan pada Worker yang sama lalu deploy versi terbaru.':x.message==='invalid_admin_credentials'?'Email atau password Super Admin tidak cocok. Gunakan credential Super Admin, bukan login perusahaan.':x.message}};
load();
