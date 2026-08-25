
const $=s=>document.querySelector(s); const $$=s=>[...document.querySelectorAll(s)];
let registerMode=false;
async function api(path,opt={}){const r=await fetch(path,{credentials:'same-origin',...opt});const data=await r.json().catch(()=>({}));if(!r.ok){const base=data.error||'request_failed';const message=data.detail?base+': '+data.detail:base;throw new Error(message)}return data}
function setMode(){registerMode=!registerMode;$('#authTitle').textContent=registerMode?'Create organization':'Sign in';$('#authBtn').textContent=registerMode?'Create account':'Sign in';$('#orgField').classList.toggle('hidden',!registerMode);$('#name').required=registerMode;$('#toggleAuth').textContent=registerMode?'Back to sign in':'Create an organization'}
$('#toggleAuth').onclick=e=>{e.preventDefault();setMode()};
$('#authForm').onsubmit=async e=>{e.preventDefault();$('#authMsg').textContent='Working...';try{const path=registerMode?'/api/auth/register':'/api/auth/login';const body=registerMode?{organization_name:$('#org').value,name:$('#name').value,email:$('#email').value,password:$('#password').value}:{email:$('#email').value,password:$('#password').value};const r=await api(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});$('#auth').classList.add('hidden');$('#app').classList.remove('hidden');$('#who').textContent=r.user.name+' · '+(r.user.company_name||'');$('#authMsg').textContent='Loading dashboard...';try{await refresh();$('#authMsg').textContent=''}catch(e){$('#authMsg').textContent='Dashboard error: '+e.message}}catch(err){$('#authMsg').textContent=err.message}}
$('#logout').onclick=async()=>{await api('/api/auth/logout',{method:'POST'});location.reload()};
$$('.tabs button').forEach(b=>b.onclick=()=>{$$('.tabs button').forEach(x=>x.classList.add('secondary'));b.classList.remove('secondary');$$('.tab').forEach(x=>x.classList.add('hidden'));$('#'+b.dataset.tab).classList.remove('hidden');if(b.dataset.tab==='jobs')loadJobs();if(b.dataset.tab==='candidates')loadCandidates();if(b.dataset.tab==='applications')loadApps();if(b.dataset.tab==='billing')loadBilling()});
async function loadJobs(){
  const jobs=await api('/api/jobs');
  window.jobsCache=jobs;
  const body=$('#jobsBody');
  body.innerHTML=jobs.length?jobs.map(j=>{
    const req=extractJobRequirements(j.description);
    return `<tr>
      <td><div class="job-title-cell"><strong>${esc(j.title)}</strong><span>${esc(j.salary||'Salary not specified')}</span></div></td>
      <td>${esc(j.location||'Not specified')}</td>
      <td><span class="job-status ${String(j.status||'open')!=='open'?'closed':''}">${esc(j.status||'open')}</span></td>
      <td>${j.created_at?new Date(j.created_at).toLocaleString():'-'}</td>
      <td><div class="job-actions"><button type="button" class="btn secondary job-action" data-job-action="edit" data-job-id="${esc(j.id)}">Edit</button><button type="button" class="btn secondary job-action job-danger" data-job-action="delete" data-job-id="${esc(j.id)}">Delete</button></div></td>
    </tr>`;
  }).join(''):'<tr><td colspan="5" class="job-empty"><strong>No active jobs</strong><br><span>Create your first position above.</span></td></tr>';
  $('#candidateJob').innerHTML='<option value="">Attach to job (optional)</option>'+jobs.map(j=>`<option value="${esc(j.id)}">${esc(j.title)}</option>`).join('');
}

function extractJobRequirements(description){
  const m=String(description||'').match(/Required skills:\s*([\s\S]*)$/i);
  if(!m)return '';
  return m[1].split(/\n/).map(x=>x.replace(/^\s*-\s*/, '').trim()).filter(Boolean).join(', ');
}
function startJobEdit(j){
  $('#editingJobId').value=j.id;$('#jobFormTitle').textContent='Edit job';$('#jobSubmitBtn').textContent='Save changes';$('#jobResetBtn').classList.remove('hidden');$('#cancelJobEdit').classList.remove('hidden');
  $('#jobTitle').value=j.title||'';$('#jobLocation').value=j.location||'';$('#jobSalary').value=j.salary||'';$('#jobDescription').value=String(j.description||'').replace(/\n\nRequired skills:\n(?:- .*\n?)+$/i,'').trim();$('#jobSkills').value=extractJobRequirements(j.description);
  $('#jobMsg').textContent='Editing '+j.title;
  window.scrollTo({top:0,behavior:'smooth'});
}
window.editJob=id=>{const j=(window.jobsCache||[]).find(x=>x.id===id);if(j)startJobEdit(j)};
document.addEventListener('click',e=>{
  const btn=e.target.closest('[data-job-action]');
  if(!btn)return;
  const id=btn.dataset.jobId;
  if(btn.dataset.jobAction==='edit')window.editJob(id);
  if(btn.dataset.jobAction==='delete')window.deleteJob(id);
});
function resetJobForm(){
  $('#editingJobId').value='';$('#jobForm').reset();$('#jobFormTitle').textContent='Create job';$('#jobSubmitBtn').textContent='Create job';$('#jobResetBtn').classList.add('hidden');$('#cancelJobEdit').classList.add('hidden');$('#jobMsg').textContent='';
}
async function deleteJob(id){
  const j=(window.jobsCache||[]).find(x=>x.id===id);
  if(!j)return;
  const ok=confirm('Delete job "'+j.title+'"?\n\nThe job will be removed from the active Jobs list. Existing candidate applications and screening history will be preserved.');
  if(!ok)return;
  try{await api('/api/jobs/'+encodeURIComponent(id)+'/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});if($('#editingJobId').value===id)resetJobForm();$('#jobMsg').textContent='Job deleted successfully.';await refresh()}catch(e){$('#jobMsg').textContent='Delete job failed: '+e.message}
}
window.deleteJob=deleteJob;
$('#refreshJobs').onclick=()=>loadJobs();$('#cancelJobEdit').onclick=resetJobForm;$('#jobResetBtn').onclick=resetJobForm;$('#manageJobsBtn').onclick=()=>document.querySelector('.tabs button[data-tab="jobs"]').click();
async function loadCandidates(){
  try{
    const rows=await api('/api/candidates');
    const body=$('#candidatesBody');
    if(!rows.length){body.innerHTML='<tr><td colspan="5" class="pool-empty"><strong>No CVs in screening pool</strong><br><span>Upload one or more CVs and attach them to a job to begin screening.</span></td></tr>';return}
    body.innerHTML=rows.map(x=>{
      const file=String(x.cv_url||x.full_name||'CV Candidate').split('/').pop()||'CV Candidate';
      const score=x.screened_at&&x.score!=null?x.score:'—';
      const status=String(x.status||'Uploaded');
      const ready=Boolean(x.extraction_ready);
      const stage=ready?(x.screened_at?'Screened':'Ready for screening'):'Extraction required';
      const stageClass=ready?(x.screened_at?'stage-screened':'stage-ready'):'stage-pending';
      return '<tr><td><div class="pool-cv"><strong>'+esc(file)+'</strong><span>'+esc(x.full_name||'Candidate CV')+'</span></div></td><td>'+esc(x.job_title||'—')+'</td><td><div class="pool-score">'+(score==='—'?'<span class="score-dash">—</span>':'<strong>'+esc(score)+'</strong><span>/100</span>')+'</div></td><td><span class="pill">'+esc(status)+'</span></td><td><span class="pool-stage '+stageClass+'"><i></i>'+esc(stage)+'</span></td></tr>';
    }).join('');
  }catch(e){$('#candidatesBody').innerHTML='<tr><td colspan="5" class="pool-error">Candidate pool could not be loaded: '+esc(e.message)+'</td></tr>'}
}
async function loadApps(){
  try{
    const rows=await api('/api/applications');
    $('#appsBody').innerHTML=rows.map(x=>{
      const score=x.screening_score==null?'-':x.screening_score;
      return '<tr><td>'+esc(x.candidate_name||'CV Candidate')+'</td><td>'+esc(x.job_title||'-')+'</td><td><strong>'+score+'</strong></td><td><span class="pill">'+esc(x.status||'Review')+'</span></td><td><button type="button" class="btn secondary" onclick="extractCv(\''+x.id+'\')">Extract CV</button> <button type="button" class="btn secondary" onclick="rule(\''+x.id+'\')">Rule</button> <button type="button" class="btn" onclick="ai(\''+x.id+'\')">AI Screen</button></td></tr>';
    }).join('');
  }catch(e){
    $('#appsBody').innerHTML='<tr><td colspan="5">Screening load failed: '+esc(e.message)+'</td></tr>';
  }
}

function resultEsc(v){return esc(v==null?"":String(v))}
function resultList(v){
  let a=v;
  if(typeof a==="string"){try{a=JSON.parse(a)}catch{a=a.split(/\n|,/).map(x=>x.trim()).filter(Boolean)}}
  return Array.isArray(a)?a.filter(Boolean):[]
}

(function(){
  if(document.getElementById('screening-result-ui-style'))return;
  const s=document.createElement('style');s.id='screening-result-ui-style';
  s.textContent=`
    #resultText{white-space:normal!important}
    .screen-result-card{border:1px solid #dbe4f0;border-radius:16px;background:#fff;overflow:hidden;box-shadow:0 6px 20px rgba(15,23,42,.06)}
    .screen-result-top{padding:22px 24px;display:flex;justify-content:space-between;align-items:center;gap:18px;border-bottom:1px solid #e8edf5}
    .screen-eyebrow{font-size:11px;letter-spacing:.08em;font-weight:800;color:#64748b;margin-bottom:5px}
    .screen-result-title{font-size:21px;font-weight:750;color:#102a4c}
    .screen-score{min-width:110px;text-align:center;padding:10px 14px;border-radius:14px;background:#f8fafc}
    .screen-score-number{font-size:34px;font-weight:800;line-height:1;color:#102a4c}.screen-score-label{font-size:13px;color:#64748b}
    .score-strong{background:#ecfdf5}.score-strong .screen-score-number{color:#047857}
    .score-good{background:#eff6ff}.score-good .screen-score-number{color:#1d4ed8}
    .score-review{background:#fff7ed}.score-review .screen-score-number{color:#c2410c}
    .score-low{background:#fff1f2}.score-low .screen-score-number{color:#be123c}
    .screen-status-row{padding:14px 24px 0}.screen-status{display:inline-flex;padding:6px 11px;border-radius:999px;font-size:12px;font-weight:700}
    .status-strong{background:#dcfce7;color:#166534}.status-potential{background:#dbeafe;color:#1d4ed8}.status-low{background:#fee2e2;color:#991b1b}.status-review{background:#f1f5f9;color:#475569}
    .screen-section{padding:20px 24px 0}.screen-section-title{font-size:13px;font-weight:750;color:#17365d;margin-bottom:9px}
    .screen-summary,.screen-recommendation{font-size:14px;line-height:1.65;color:#475569;background:#f8fafc;border:1px solid #e2e8f0;border-radius:11px;padding:13px 15px}
    .screen-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;padding:20px 24px 0}.screen-panel{border:1px solid #e2e8f0;border-radius:12px;padding:15px}
    .screen-list{margin:0;padding-left:20px;color:#475569;font-size:13px;line-height:1.7}.screen-empty{color:#94a3b8;font-size:13px}
    .skill-wrap{display:flex;flex-wrap:wrap;gap:7px}.skill-chip{padding:6px 9px;border-radius:999px;font-size:12px;font-weight:650}.skill-match{background:#ecfdf5;color:#047857}.skill-missing{background:#fff1f2;color:#be123c}
    .screen-meta{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.screen-meta div{padding:11px;border:1px solid #e2e8f0;border-radius:10px}.screen-meta span{display:block;font-size:11px;color:#94a3b8;margin-bottom:4px}.screen-meta strong{font-size:13px;color:#334155}
    .screen-recommendation{margin:20px 24px 24px;background:#f8fafc}
    .screen-error-card{border:1px solid #fecaca;border-radius:16px;background:#fff;overflow:hidden;box-shadow:0 6px 20px rgba(127,29,29,.05)}
    .screen-error-head{padding:20px 24px;background:#fff7f7;border-bottom:1px solid #fee2e2;display:flex;justify-content:space-between;align-items:center;gap:12px}
    .screen-error-title{font-size:19px;font-weight:750;color:#991b1b}.screen-error-sub{font-size:12px;color:#9f1239;margin-top:4px}
    .screen-error-icon{width:36px;height:36px;border-radius:50%;background:#fee2e2;color:#b91c1c;display:flex;align-items:center;justify-content:center;font-weight:800}
    .screen-error-body{padding:20px 24px}.screen-error-message{font-size:14px;line-height:1.6;color:#7f1d1d}
    .screen-error-code{display:inline-block;margin-top:12px;padding:5px 9px;border-radius:7px;background:#fef2f2;color:#991b1b;font:600 12px ui-monospace,SFMono-Regular,Menlo,monospace}
    .screen-error-action{margin-top:14px;padding:12px 14px;border-radius:10px;background:#f8fafc;border:1px solid #e2e8f0;color:#475569;font-size:12px}
    .screen-extraction{border:1px solid #cfe0f5;border-radius:16px;background:#fff;overflow:hidden;box-shadow:0 6px 20px rgba(15,23,42,.05)}
    .screen-extraction-head{padding:20px 24px;background:#f7fbff;border-bottom:1px solid #e2edf8;display:flex;justify-content:space-between;gap:16px;align-items:center}
    .screen-extraction-title{font-size:19px;font-weight:750;color:#12365a}.screen-extraction-sub{font-size:12px;color:#64748b;margin-top:5px}.extract-ready{padding:7px 11px;border-radius:999px;background:#dcfce7;color:#166534;font-size:12px;font-weight:750}
    .screen-extraction-body{padding:20px 24px}.extract-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.extract-metric{padding:14px;border:1px solid #e2e8f0;border-radius:12px;background:#f8fafc}.extract-metric span{display:block;font-size:11px;color:#64748b;margin-bottom:5px}.extract-metric strong{font-size:14px;color:#17365d}.extract-source{margin-top:16px;padding:12px 14px;border-radius:10px;background:#eff6ff;border:1px solid #dbeafe;color:#1e40af;font-size:12px;line-height:1.5}
    .pool-cv{display:flex;flex-direction:column;gap:4px}.pool-cv strong{color:#17365d;font-size:13px}.pool-cv span{color:#94a3b8;font-size:11px}.pool-score{display:inline-flex;align-items:baseline;gap:3px;min-width:55px}.pool-score strong{font-size:16px;color:#102a43}.pool-score span{font-size:11px;color:#94a3b8}.score-dash{font-size:18px!important;color:#94a3b8!important}.pool-stage{display:inline-flex;align-items:center;gap:7px;padding:6px 10px;border-radius:999px;font-size:11px;font-weight:750;white-space:nowrap}.pool-stage i{width:7px;height:7px;border-radius:50%;background:currentColor}.stage-ready{background:#ecfdf5;color:#047857}.stage-screened{background:#eff6ff;color:#1d4ed8}.stage-pending{background:#fff7ed;color:#c2410c}.pool-empty,.pool-error{text-align:center;padding:34px!important;color:#64748b}.pool-empty strong{color:#17365d}.pool-empty span{font-size:12px}.pool-error{color:#991b1b;background:#fff7f7}.score-breakdown{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.score-row{padding:11px 12px;border:1px solid #e5ebf3;border-radius:10px;background:#f8fafc}.score-row-head{display:flex;justify-content:space-between;gap:10px;font-size:12px;color:#475569}.score-row-head strong{color:#17365d}.score-track{height:6px;background:#e7edf5;border-radius:999px;margin-top:8px;overflow:hidden}.score-track span{display:block;height:100%;background:#1769e0;border-radius:999px}@media(max-width:700px){.score-breakdown{grid-template-columns:1fr}}
    @media(max-width:700px){.screen-result-top{align-items:flex-start}.screen-grid,.screen-meta,.extract-grid{grid-template-columns:1fr}}
    @media(max-width:700px){.screen-result-top{align-items:flex-start}.screen-grid,.screen-meta{grid-template-columns:1fr}}
  `;
  document.head.appendChild(s);
})();

function renderScreeningResult(data){
  const box=$('#result'),out=$('#resultText'); box.classList.remove('hidden');
  if(data&&data.loading){out.innerHTML='<div class="screen-loading"><span class="loader-dot"></span><div><strong>Running screening…</strong><small>Comparing job requirements with candidate evidence.</small></div></div>';return;}
  if(data&&data.error){
    const detail=data.detail||data.message||data.error;
    let title='AI screening could not be completed', message='The AI service could not process this screening request.', action='Please check the AI service configuration and available credits, then try again.';
    if(String(data.error)==='cv_not_extracted'){title='CV extraction required';message='Candidate information has not been extracted from the CV yet.';action='Click “Extract CV” first. Rule Screening will then compare the extracted CV with the selected job.'}
    else if(String(data.error)==='ai_quota_exhausted'){title='AI credits unavailable';message='The OpenAI API rejected the request because the configured account has no remaining credits.';action='Add API credits or configure another AI provider. Rule Screening can still be used after CV extraction.'}
    else if(String(data.error)==='ai_not_configured'){title='AI service is not configured';message='No AI provider is currently configured for this workspace.';action='Add a valid AI API configuration before running screening.'}
    else if(String(data.error)==='ai_request_failed'){title='AI screening temporarily unavailable';message='The AI provider rejected or could not complete this request.';action='Check API credits/quota and configuration, then retry. No candidate score was changed.'}
    else if(String(data.error)==='cv_text_not_extractable'){title='CV text could not be extracted';message='This CV appears to be image-based or uses a format that has no readable text layer.';action='For scanned/image CVs, configure AI extraction. Text-based PDF and DOCX files can be extracted locally without AI credits.'}
    else if(String(data.error)==='cv_extraction_failed'){title='CV extraction failed';message='The CV could not be processed.';action='Retry extraction. If this is a scanned PDF, AI extraction is required.'}
    out.innerHTML='<div class="screen-error-card"><div class="screen-error-head"><div><div class="screen-error-title">'+resultEsc(title)+'</div><div class="screen-error-sub">AI Screening</div></div><div class="screen-error-icon">!</div></div><div class="screen-error-body"><div class="screen-error-message">'+resultEsc(message)+'</div><div class="screen-error-action">'+resultEsc(action)+'</div><div class="screen-error-code">'+resultEsc(data.error)+'</div></div></div>';
    return;
  }
  const score=Number(data?.overall_score??data?.ai_score), hasScore=Number.isFinite(score);
  const status=String(data?.status||data?.ai_recommendation||"Review");
  const summary=String(data?.summary||data?.ai_summary||"");
  const strengths=resultList(data?.strengths||data?.ai_strengths);
  const gaps=resultList(data?.gaps||data?.weaknesses||data?.ai_weaknesses);
  const matched=resultList(data?.matched_skills||data?.ai_matched_skills);
  const missing=resultList(data?.missing_skills||data?.ai_missing_skills);
  const education=String(data?.education||""),position=String(data?.current_position||"");
  const experience=data?.experience_years;
  const recommendation=String(data?.recommendation||data?.ai_recommendation||"");
  const scoreClass=!hasScore?"score-na":score>=85?"score-strong":score>=70?"score-good":score>=50?"score-review":"score-low";
  const statusClass=/strong/i.test(status)?"status-strong":/potential/i.test(status)?"status-potential":/low/i.test(status)?"status-low":"status-review";
  const listHtml=(items,empty)=>items.length?'<ul class="screen-list">'+items.map(x=>'<li>'+resultEsc(x)+'</li>').join('')+'</ul>':'<div class="screen-empty">'+resultEsc(empty)+'</div>';
  out.innerHTML='<div class="screen-result-card">'+
    '<div class="screen-result-top"><div><div class="screen-eyebrow">AI SCREENING RESULT</div><div class="screen-result-title">Candidate assessment</div></div>'+
    '<div class="screen-score '+scoreClass+'"><span class="screen-score-number">'+(hasScore?resultEsc(score):'—')+'</span><span class="screen-score-label">/ 100</span></div></div>'+
    '<div class="screen-status-row"><span class="screen-status '+statusClass+'">'+resultEsc(status)+'</span></div>'+
    (summary?'<div class="screen-section"><div class="screen-section-title">Assessment Summary</div><div class="screen-summary">'+resultEsc(summary)+'</div></div>':'')+
    '<div class="screen-grid"><div class="screen-panel"><div class="screen-section-title">Strengths</div>'+listHtml(strengths,'No strengths identified yet.')+'</div>'+
    '<div class="screen-panel"><div class="screen-section-title">Areas to Review</div>'+listHtml(gaps.length?gaps:missing,'No gaps identified yet.')+'</div></div>'+
    ((matched.length||missing.length)?'<div class="screen-section"><div class="screen-section-title">Skills Match</div><div class="skill-wrap">'+matched.map(x=>'<span class="skill-chip skill-match">✓ '+resultEsc(x)+'</span>').join('')+missing.map(x=>'<span class="skill-chip skill-missing">× '+resultEsc(x)+'</span>').join('')+'</div></div>':'')+
    (data?.breakdown?'<div class="screen-section"><div class="screen-section-title">Score Breakdown</div><div class="score-breakdown">'+Object.entries(data.breakdown).map(([k,v])=>{const label=String(k).replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase());const n=Number(v?.score||0),m=Number(v?.max||0);const pct=m?Math.round(n/m*100):0;return '<div class="score-row"><div class="score-row-head"><span>'+resultEsc(label)+'</span><strong>'+n+' / '+m+'</strong></div><div class="score-track"><span style="width:'+pct+'%"></span></div></div>'}).join('')+'</div></div>':'')+
    (data?.evidence?.length?'<div class="screen-section"><div class="screen-section-title">Candidate Evidence</div>'+listHtml(data.evidence,'No evidence identified.')+'</div>':'')+
    ((education||position||experience!=null)?'<div class="screen-section"><div class="screen-section-title">Profile Snapshot</div><div class="screen-meta">'+
      (position?'<div><span>Current Position</span><strong>'+resultEsc(position)+'</strong></div>':'')+
      (experience!=null?'<div><span>Experience</span><strong>'+resultEsc(experience)+' years</strong></div>':'')+
      (education?'<div><span>Education</span><strong>'+resultEsc(education)+'</strong></div>':'')+
      '</div></div>':'')+
    (recommendation?'<div class="screen-recommendation"><div class="screen-section-title">Recommendation</div><div>'+resultEsc(recommendation)+'</div></div>':'')+
    '</div>';
}

function renderExtractionResult(payload){
  const box=$('#result'),out=$('#resultText');box.classList.remove('hidden');
  const d=payload?.extraction||payload||{};
  const skills=resultList(d.skills),langs=resultList(d.languages),history=resultList(d.work_history),achievements=resultList(d.achievements);
  const source=String(payload?.source||'local');
  const sourceLabel=source==='openai'?'AI-assisted extraction':'Local CV extraction';
  const sourceNote=source==='openai'?'OpenAI was used because local text extraction was not sufficient.':'Text was extracted directly from the uploaded CV. This does not consume OpenAI credits.';
  const summary=String(d.summary||'').trim();
  const position=String(d.current_position||'').trim(),education=String(d.education||'').trim();
  out.innerHTML='<div class="screen-extraction"><div class="screen-extraction-head"><div><div class="screen-eyebrow">CV EXTRACTION</div><div class="screen-extraction-title">CV is ready for screening</div><div class="screen-extraction-sub">The extracted profile can now be compared against the selected job.</div></div><span class="extract-ready">Ready</span></div><div class="screen-extraction-body"><div class="extract-grid"><div class="extract-metric"><span>Current Position</span><strong>'+resultEsc(position||'Not identified')+'</strong></div><div class="extract-metric"><span>Experience</span><strong>'+resultEsc(d.experience_years||0)+' years</strong></div><div class="extract-metric"><span>Education</span><strong>'+resultEsc(education||'Not identified')+'</strong></div></div><div class="screen-section"><div class="screen-section-title">Recognised Skills</div><div class="skill-wrap">'+(skills.length?skills.map(x=>'<span class="skill-chip skill-match">'+resultEsc(x)+'</span>').join(''):'<span class="screen-empty">No recognised skills yet.</span>')+'</div></div>'+(summary?'<div class="screen-section"><div class="screen-section-title">CV Summary</div><div class="screen-summary">'+resultEsc(summary)+'</div></div>':'')+'<div class="extract-source"><strong>'+resultEsc(sourceLabel)+'</strong><br>'+resultEsc(sourceNote)+' Rule Screening is now available.</div></div></div>';
}

async function extractCv(id){
  if(window.extractingCv)return;
  window.extractingCv=true;
  const box=$('#result');
  const out=$('#resultText');
  box.classList.remove('hidden');
  out.textContent='Extracting CV from R2...';
  try{
    const r=await api('/api/candidates/extract',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({application_id:id})
    });
    renderExtractionResult(r);
    await refresh();
    await loadApps();
    await loadCandidates();
  }catch(e){
    renderScreeningResult({error:String(e.message||e).includes('cv_text_not_extractable')?'cv_text_not_extractable':'cv_extraction_failed',detail:e.message});
  }finally{
    window.extractingCv=false;
  }
}
async function loadProfile(){
  const r=await api('/api/profile'); const p=r.profile||{};
  const map={company_name:'pf_company_name',legal_name:'pf_legal_name',industry:'pf_industry',website:'pf_website',contact_name:'pf_contact_name',contact_email:'pf_contact_email',contact_phone:'pf_contact_phone',city:'pf_city',province:'pf_province',country:'pf_country',registration_number:'pf_registration_number',address:'pf_address',description:'pf_description'};
  Object.entries(map).forEach(([k,id])=>{if($('#'+id))$('#'+id).value=p[k]||''});
}
async function openProfile(){await loadProfile();$('#profileModal').classList.remove('hidden')}
function closeProfile(){$('#profileModal').classList.add('hidden')}
async function saveProfile(e){e.preventDefault();$('#profileMsg').textContent='Saving...';const fields=['company_name','legal_name','industry','website','contact_name','contact_email','contact_phone','city','province','country','registration_number','address','description'];const body={};fields.forEach(k=>body[k]=$('#pf_'+k).value);try{await api('/api/profile',{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});$('#profileMsg').textContent='Profile updated successfully.';$('#whoName').textContent=body.contact_name||body.company_name||'Account';$('#whoCompany').textContent=body.company_name||'';setTimeout(closeProfile,600)}catch(e){$('#profileMsg').textContent='Profile update failed: '+e.message}}
async function loadBilling(){
  try{const d=await api('/api/billing');const w=d.wallet||{};$('#creditBalance').textContent=Number(w.balance||0).toLocaleString('id-ID')+' credits';
    $('#creditPackages').innerHTML=(d.packages||[]).map((p,i)=>'<div class="credit-package '+(i===1?'featured':'')+'"><div class="pool-kicker">'+(p.tag||'')+'</div><h3>'+esc(p.name)+'</h3><div class="credit-price">Rp '+Number(p.price_idr).toLocaleString('id-ID')+'</div><b>'+Number(p.credits).toLocaleString('id-ID')+' credits</b><div class="credit-tag">AI Screening Credits. Provider tokens remain internal.</div><button class="btn credit-buy" onclick="buyCredits(\''+esc(p.code)+'\')">Request package</button></div>').join('');
    $('#creditUsage').innerHTML=(d.usage||[]).length?(d.usage||[]).map(x=>'<div class="usage-card"><span>'+esc(x.operation)+'</span><b>'+Number(x.credits||0).toLocaleString('id-ID')+' credits</b><span>'+Number(x.runs||0)+' runs</span></div>').join(''):'<div class="usage-card"><span>No usage yet</span><b>0 credits</b><span>Start screening to see usage.</span></div>';
    $('#creditOrders').innerHTML=(d.orders||[]).length?(d.orders||[]).map(x=>'<tr><td>'+esc(x.package_code)+'</td><td>'+Number(x.credits).toLocaleString('id-ID')+'</td><td>Rp '+Number(x.amount_idr).toLocaleString('id-ID')+'</td><td><span class="pill">'+esc(x.status)+'</span></td><td>'+esc(new Date(x.created_at).toLocaleString('id-ID'))+'</td></tr>').join(''):'<tr><td colspan="5" class="job-empty">No orders yet.</td></tr>';
  }catch(e){$('#creditPackages').innerHTML='<div class="screen-error-card"><div class="screen-error-body"><strong>Billing unavailable</strong><br>'+esc(e.message)+'</div></div>'}
}
window.buyCredits=async code=>{try{const r=await api('/api/billing/orders',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({package_code:code})});alert('Order dibuat. Order ID: '+r.order_id+'\nStatus: pending\nSuper Admin akan memproses pembayaran dan mengaktifkan credits.');await loadBilling()}catch(e){alert('Order gagal: '+e.message)}};
$('#profileBtn').onclick=e=>{e.stopPropagation();$('#accountMenu').classList.toggle('hidden')};$('#openProfile').onclick=()=>{closeProfile();$('#accountMenu').classList.add('hidden');openProfile()};$('#openBilling').onclick=()=>{document.querySelector('.tabs button[data-tab="billing"]').click();$('#accountMenu').classList.add('hidden')};$('#closeProfile').onclick=closeProfile;document.querySelector('[data-close-profile]')?.addEventListener('click',closeProfile);$('#profileForm').onsubmit=saveProfile;document.addEventListener('click',e=>{if(!e.target.closest('.header-account'))$('#accountMenu')?.classList.add('hidden')});

async function refresh(){const d=await api('/api/dashboard');$('#mJobs').textContent=d.jobs;$('#mCandidates').textContent=d.candidates;$('#mApplications').textContent=d.applications;$('#mStrong').textContent=d.strong_matches;await loadJobs()}
$('#jobForm').onsubmit=async e=>{
  e.preventDefault();
  const msg=$('#jobMsg');const id=$('#editingJobId').value;
  msg.textContent=id?'Saving changes...':'Creating job...';
  try{
    const body={title:$('#jobTitle').value,location:$('#jobLocation').value,salary:$('#jobSalary').value,description:$('#jobDescription').value,requirements:$('#jobSkills').value.split(',').map(x=>x.trim()).filter(Boolean)};
    const endpoint=id?('/api/jobs/'+encodeURIComponent(id)+'/update'):'/api/jobs';
    await api(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    resetJobForm();msg.textContent=id?'Job updated successfully.':'Job created successfully.';
    await refresh();
  }catch(err){msg.textContent=(id?'Update job failed: ':'Create job failed: ')+err.message;}
}
$('#candidateForm').onsubmit=async e=>{
  e.preventDefault();
  const files=[...$('#candidateFiles').files,...$('#candidateFolder').files];
  const unique=[];
  const seen=new Set();
  for(const file of files){
    const key=file.name+'|'+file.size+'|'+file.lastModified;
    if(!seen.has(key)){seen.add(key);unique.push(file)}
  }
  if(!$('#candidateJob').value){$('#candidateMsg').textContent='Pilih posisi/job terlebih dahulu.';return}
  if(!unique.length){$('#candidateMsg').textContent='Pilih file CV atau folder CV terlebih dahulu.';return}
  if(unique.length>50){$('#candidateMsg').textContent='Maksimal 50 CV per upload.';return}

  const msg=$('#candidateMsg');
  const errors=[];
  let uploaded=0;

  // Upload one CV per request. This avoids a large multipart request hanging
  // when many PDF/DOCX files are selected at once.
  for(let i=0;i<unique.length;i++){
    const file=unique[i];
    msg.textContent='Uploading CV '+(i+1)+'/'+unique.length+': '+file.name;
    const fd=new FormData();
    fd.append('job_id',$('#candidateJob').value);
    fd.append('files',file,file.name);
    try{
      const r=await api('/api/candidates/upload',{method:'POST',body:fd});
      if(r.uploaded)uploaded+=r.uploaded;
      else uploaded++;
    }catch(err){
      errors.push(file.name+': '+err.message);
    }
  }

  if(errors.length){
    msg.textContent=uploaded+' CV berhasil, '+errors.length+' gagal. '+errors.slice(0,3).join(' | ');
  }else{
    msg.textContent=uploaded+' CV berhasil diupload.';
  }

  e.target.reset();
  await refresh();
  await loadCandidates();
}
window.rule=async id=>{
  showResult({loading:true});
  try{const r=await api('/api/screenings/rule',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({application_id:id})});showResult(r);await refresh();await loadApps()}
  catch(e){const msg=String(e.message||e);showResult({error:msg.startsWith('cv_not_extracted')?'cv_not_extracted':msg.startsWith('unauthorized')?'unauthorized':'rule_screen_failed',detail:msg})}
}
window.ai=async id=>{
  showResult({loading:true});
  try{const r=await api('/api/ai/screen',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({application_id:id})});showResult(r);await refresh();await loadApps()}
  catch(e){const msg=String(e.message||e);showResult({error:msg.includes('insufficient_quota')||msg.includes('credit_balance_exhausted')?'ai_quota_exhausted':msg.startsWith('cv_not_extracted')?'cv_not_extracted':'ai_request_failed',detail:msg})}
}
function showResult(x){renderScreeningResult(x)}
function esc(s){return String(s??'').replace(/[&<>'"]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[m]))}
async function boot(){try{const r=await api('/api/auth/me');$('#auth').classList.add('hidden');$('#app').classList.remove('hidden');$('#whoName').textContent=r.user.name||'Account';$('#whoCompany').textContent=r.user.company_name||'';await refresh();$('#authMsg').textContent=''}catch(e){$('#authMsg').textContent='Login/session error: '+e.message;$('#auth').classList.remove('hidden');$('#app').classList.add('hidden')}}
boot();
