import { Hono } from "hono";
import { cors } from "hono/cors";
import { secureHeaders } from "hono/secure-headers";

interface Env {
  DB: D1Database;
  CV_BUCKET: R2Bucket;
  APP_NAME: string;
  OPENAI_API_KEY?: string;
  OPENAI_MODEL?: string;
  SESSION_SECRET?: string;
}

type AuthUser = { id:string; company_id:string; name:string; email:string; role:string; company_name:string };

const app = new Hono<{ Bindings: Env; Variables: { user: AuthUser } }>();
app.use("*", secureHeaders());
app.use("/api/*", cors({ origin: (origin) => origin || "*", allowMethods: ["GET","POST","PATCH","DELETE","OPTIONS"], allowHeaders: ["Content-Type","Authorization"], credentials: true }));
const id=()=>crypto.randomUUID(); const enc=new TextEncoder();
function b64url(bytes:Uint8Array){let binary="";for(const b of bytes)binary+=String.fromCharCode(b);return btoa(binary).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}
function hex(bytes:Uint8Array){return [...bytes].map(b=>b.toString(16).padStart(2,"0")).join("")}
async function sha256(v:string){return hex(new Uint8Array(await crypto.subtle.digest("SHA-256",enc.encode(v))))}
async function passwordHash(password:string){const salt=new Uint8Array(16);crypto.getRandomValues(salt);const key=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveBits"]);const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations:100000,hash:"SHA-256"},key,256);return `pbkdf2$100000$${b64url(salt)}$${b64url(new Uint8Array(bits))}`}
async function passwordVerify(password:string,stored:string){try{const [scheme,it,saltText,expected]=stored.split("$");if(scheme!=="pbkdf2")return false;const sb=saltText.replace(/-/g,"+").replace(/_/g,"/");const bin=atob(sb+"=".repeat((4-sb.length%4)%4));const salt=Uint8Array.from(bin,c=>c.charCodeAt(0));const key=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveBits"]);const iterations=Math.min(Number(it)||100000,100000);const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations,hash:"SHA-256"},key,256);return b64url(new Uint8Array(bits))===expected}catch{return false}}
function cookieToken(req:Request){
  const h=req.headers.get("Cookie")||"";
  return h.match(/(?:^|;\s*)ats_session=([^;]+)/)?.[1]
    || h.match(/(?:^|;\s*)session=([^;]+)/)?.[1]
    || null;
}
function setCookie(token:string,maxAge:number){
  return `ats_session=${token}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}
function clearLegacyCookie(){
  return "session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax";
}
async function columns(db:D1Database,table:string){const r=await db.prepare(`PRAGMA table_info(${table})`).all<any>();return new Set((r.results||[]).map((x:any)=>String(x.name)))}
async function createSession(c:any,u:AuthUser){
  const token=b64url(crypto.getRandomValues(new Uint8Array(32)));
  const expires=new Date(Date.now()+7*86400000).toISOString();
  await c.env.DB.prepare("INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)")
    .bind(await sha256(token),u.id,expires).run();
  c.header("Set-Cookie",setCookie(token,7*86400));
}
async function currentUser(c:any):Promise<AuthUser|null>{
  const raw=cookieToken(c.req.raw);
  if(!raw)return null;
  try{
    const row=await c.env.DB.prepare(
      "SELECT u.id,u.company_id,u.name,u.email,u.role,COALESCE(cp.company_name,u.name) company_name " +
      "FROM sessions s JOIN users u ON u.id=s.user_id " +
      "LEFT JOIN company_profiles cp ON cp.user_id=u.company_id " +
      "WHERE s.token=? AND s.expires_at>CURRENT_TIMESTAMP LIMIT 1"
    ).bind(await sha256(raw)).first<AuthUser>();
    return row||null;
  }catch(e:any){
    throw new Error("session_lookup_failed: "+String(e?.message||e));
  }
}
async function requireAuth(c:any,next:any){
  try{
    const u=await currentUser(c);
    if(!u)return c.json({error:"unauthorized"},401);
    c.set("user",u);await next();
  }catch(e:any){
    return c.json({error:"auth_failed",detail:String(e?.message||e)},500);
  }
}
async function audit(c:any,u:AuthUser,action:string,entityId?:string){try{const cs=await columns(c.env.DB,"admin_audit_logs");const fields:string[]=[];const vals:any[]=[];const add=(n:string,v:any)=>{if(cs.has(n)){fields.push(n);vals.push(v)}};add("id",id());add("user_id",u.id);add("action",action);add("entity_id",entityId||null);add("company_id",u.company_id);add("created_at",new Date().toISOString());if(fields.length)await c.env.DB.prepare(`INSERT INTO admin_audit_logs(${fields.join(",")}) VALUES(${fields.map(()=>"?").join(",")})`).bind(...vals).run()}catch{}}
async function appMeta(db:D1Database){const cs=await columns(db,"applications");return {cs,candidate:cs.has("candidate_id")?"candidate_id":cs.has("user_id")?"user_id":null,tenant:cs.has("company_id")?"company_id":cs.has("organization_id")?"organization_id":null}}
async function createApplication(c:any,u:AuthUser,jobId:string,candidateUserId:string){const m=await appMeta(c.env.DB);if(!m.candidate)throw new Error("applications_missing_candidate_key");const f=["id","job_id",m.candidate],v:any[]=[id(),jobId,candidateUserId];if(m.tenant){f.push(m.tenant);v.push(u.company_id)}if(m.cs.has("status")){f.push("status");v.push("Review")}if(m.cs.has("score")){f.push("score");v.push(0)}await c.env.DB.prepare(`INSERT INTO applications(${f.join(",")}) VALUES(${f.map(()=>"?").join(",")})`).bind(...v).run()}
app.get("/api/health",async c=>{try{await c.env.DB.prepare("SELECT 1").first();return c.json({ok:true,app:c.env.APP_NAME,version:"v6.2-schema-aligned",database:"indo-talent-db",storage:"r2"})}catch{return c.json({ok:false,error:"database_unavailable"},503)}});
app.post("/api/auth/register",async c=>{
  try{
    const b=await c.req.json<any>();
    const company=String(b.organization_name||"").trim();
    const name=String(b.name||"").trim();
    const email=String(b.email||"").trim().toLowerCase();
    const password=String(b.password||"");
    if(!company||!name||!email||password.length<10)
      return c.json({error:"organization_name,name,email,password_min_10_required"},400);
    if(await c.env.DB.prepare("SELECT id FROM users WHERE email=? LIMIT 1").bind(email).first())
      return c.json({error:"email_already_registered"},409);

    const uid=id();
    const hash=await passwordHash(password);

    try{
      await c.env.DB.prepare(
        "INSERT INTO users(id,role,email,password_hash,name,status,company_id,approval_status,email_verified) VALUES(?,?,?,?,?,?,?,?,?)"
      ).bind(uid,"company",email,hash,name,"active",uid,"approved",0).run();
    }catch(e:any){
      return c.json({error:"registration_failed",stage:"users_insert",detail:String(e?.message||e)},500);
    }

    try{
      await c.env.DB.prepare(
        "INSERT INTO company_profiles(user_id,company_name,contact_name,contact_email,created_at,updated_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"
      ).bind(uid,company,name,email).run();
    }catch(e:any){
      await c.env.DB.prepare("DELETE FROM users WHERE id=?").bind(uid).run().catch(()=>{});
      return c.json({error:"registration_failed",stage:"company_profile_insert",detail:String(e?.message||e)},500);
    }

    const u:AuthUser={id:uid,company_id:uid,name,email,role:"company",company_name:company};
    try{
      await createSession(c,u);
    }catch(e:any){
      return c.json({error:"registration_failed",stage:"session_insert",detail:String(e?.message||e)},500);
    }
    await audit(c,u,"auth.register",uid);
    return c.json({user:u},201);
  }catch(e:any){
    return c.json({error:"registration_failed",stage:"request",detail:String(e?.message||e)},500);
  }
});
app.post("/api/auth/login",async c=>{
  try{
    const b=await c.req.json<any>();
    const email=String(b.email||"").trim().toLowerCase();
    const password=String(b.password||"");
    if(!email||!password)return c.json({error:"email_password_required"},400);
    const r=await c.env.DB.prepare(
      "SELECT u.id,u.company_id,u.name,u.email,u.password_hash,u.role,COALESCE(cp.company_name,u.name) company_name "+
      "FROM users u LEFT JOIN company_profiles cp ON cp.user_id=u.company_id "+
      "WHERE lower(u.email)=? LIMIT 1"
    ).bind(email).first<any>();
    if(!r)return c.json({error:"invalid_credentials"},401);
    if(!(await passwordVerify(password,r.password_hash)))return c.json({error:"invalid_credentials"},401);
    const u:AuthUser={id:r.id,company_id:r.company_id||r.id,name:r.name,email:r.email,role:r.role,company_name:r.company_name};
    await createSession(c,u);
    await audit(c,u,"auth.login",u.id);
    c.header("Cache-Control","no-store");
    return c.json({user:u});
  }catch(e:any){
    return c.json({error:"login_failed",detail:String(e?.message||e)},500);
  }
});
app.post("/api/auth/logout",async c=>{
  try{
    const raw=cookieToken(c.req.raw);
    if(raw)await c.env.DB.prepare("DELETE FROM sessions WHERE token=?").bind(await sha256(raw)).run();
  }catch{}
  c.header("Set-Cookie",setCookie("",0));
  return c.json({ok:true});
});
app.get("/api/auth/me",requireAuth,c=>c.json({user:c.get("user")}));
app.get("/api/auth/status",async c=>{
  try{
    const u=await currentUser(c);
    return c.json({authenticated:!!u,cookie_present:!!cookieToken(c.req.raw),user:u?{id:u.id,role:u.role,company_id:u.company_id,email:u.email}:null});
  }catch(e:any){
    return c.json({authenticated:false,error:"auth_status_failed",detail:String(e?.message||e)},500);
  }
});
for(const p of ["/api/candidates","/api/applications","/api/dashboard","/api/screenings/*"])app.use(p,requireAuth);
app.get("/api/dashboard",async c=>{try{const u=c.get("user") as AuthUser;if(!u.company_id)return c.json({error:"company_id_missing"},403);const [j,ca,a]=await Promise.all([c.env.DB.prepare("SELECT COUNT(*) count FROM jobs WHERE company_id=?").bind(u.company_id).first<any>(),c.env.DB.prepare("SELECT COUNT(*) count FROM users WHERE company_id=? AND role='candidate'").bind(u.company_id).first<any>(),c.env.DB.prepare("SELECT COUNT(*) count FROM applications a JOIN jobs j ON j.id=a.job_id WHERE j.company_id=?").bind(u.company_id).first<any>()]);return c.json({jobs:Number(j?.count||0),candidates:Number(ca?.count||0),applications:Number(a?.count||0),strong_matches:0})}catch(e:any){return c.json({error:"dashboard_query_failed",detail:String(e?.message||e)},500)}});
app.get("/api/jobs",async c=>{
  try{
    const u=await currentUser(c);
    if(!u)return c.json({error:"unauthorized",stage:"job_auth",cookie_present:!!cookieToken(c.req.raw)},401);
    if(!u.company_id)return c.json({error:"company_context_missing"},400);
    const rows=await c.env.DB.prepare(
      "SELECT id,title,location,salary,description,status,created_at FROM jobs WHERE company_id=? ORDER BY created_at DESC"
    ).bind(u.company_id).all();
    return c.json(rows.results||[]);
  }catch(e:any){
    return c.json({error:"job_list_failed",detail:String(e?.message||e)},500);
  }
});

app.post("/api/jobs",async c=>{
  try{
    const u=await currentUser(c);
    if(!u)return c.json({error:"unauthorized",stage:"job_auth",cookie_present:!!cookieToken(c.req.raw)},401);
    if(!u.company_id)return c.json({error:"company_context_missing",stage:"job_auth"},400);
    if(u.role!=="company"&&u.role!=="admin")return c.json({error:"company_role_required",stage:"job_auth",role:u.role},403);

    const b=await c.req.json<any>();
    const title=String(b.title||"").trim();
    const location=String(b.location||"").trim();
    const salary=String(b.salary||"").trim();
    const description=String(b.description||"").trim();
    const requirements=Array.isArray(b.requirements)?b.requirements.map((x:any)=>String(x).trim()).filter(Boolean):[];
    if(!title||!description)return c.json({error:"title,description_required"},400);

    const finalDescription=requirements.length
      ? description+"\n\nRequired skills:\n"+requirements.map((x:string)=>"- "+x).join("\n")
      : description;

    const jid=id();
    await c.env.DB.prepare(
      "INSERT INTO jobs(id,company_id,title,location,salary,description,status,created_at) VALUES(?,?,?,?,?,?,?,CURRENT_TIMESTAMP)"
    ).bind(jid,u.company_id,title,location,salary,finalDescription,"open").run();

    await audit(c,u,"job.create",jid);
    return c.json({ok:true,id:jid,title},201);
  }catch(e:any){
    return c.json({error:"job_create_failed",detail:String(e?.message||e)},500);
  }
});
app.get("/api/candidates",async c=>{
  try{
    const u=await currentUser(c);
    if(!u)return c.json({error:"unauthorized"},401);
    const rows=await c.env.DB.prepare(
      "SELECT cu.id,cu.name candidate_name,cp.cv_url,cp.full_name,cp.headline,cp.summary,"+
      "a.id application_id,a.job_id,j.title job_title,a.status,a.score "+
      "FROM users cu "+
      "LEFT JOIN candidate_profiles cp ON cp.user_id=cu.id "+
      "LEFT JOIN applications a ON a.candidate_id=cu.id "+
      "LEFT JOIN jobs j ON j.id=a.job_id "+
      "WHERE cu.company_id=? AND cu.role='candidate' "+
      "ORDER BY cu.created_at DESC"
    ).bind(u.company_id).all();
    return c.json(rows.results||[]);
  }catch(e:any){
    return c.json({error:"candidates_query_failed",detail:String(e?.message||e)},500);
  }
});

app.post("/api/candidates/upload",async c=>{
  try{
    const u=await currentUser(c);
    if(!u)return c.json({error:"unauthorized",stage:"candidate_upload_auth"},401);
    if(!u.company_id)return c.json({error:"company_context_missing"},400);
    if(u.role!=="company"&&u.role!=="admin")return c.json({error:"company_role_required"},403);

    const f=await c.req.formData();
    const jobId=String(f.get("job_id")||"").trim();
    const incoming=f.getAll("files").filter((x:any)=>x instanceof File) as File[];

    if(!jobId)return c.json({error:"job_required"},400);
    if(!incoming.length)return c.json({error:"cv_files_required"},400);
    if(incoming.length>50)return c.json({error:"too_many_files_max_50"},400);

    const job=await c.env.DB.prepare(
      "SELECT id,title FROM jobs WHERE id=? AND company_id=? AND status='open' LIMIT 1"
    ).bind(jobId,u.company_id).first<any>();
    if(!job)return c.json({error:"job_not_found_or_closed"},404);

    const results:any[]=[];
    for(const file of incoming){
      if(file.size===0)continue;
      if(file.size>10*1024*1024){
        results.push({filename:file.name,status:"failed",error:"file_too_large_max_10mb"});
        continue;
      }

      const uid=id();
      const baseName=file.name
        .replace(/\.[^.]+$/,"")
        .replace(/[_-]+/g," ")
        .replace(/\s+/g," ")
        .trim();
      const candidateName=(baseName||"CV Candidate").slice(0,160);
      const email=`cv-${uid}@internal.invalid`;
      const safeName=file.name.replace(/[^a-zA-Z0-9._-]+/g,"_").slice(0,160)||"cv";
      const key=`${u.company_id}/candidates/${uid}/${safeName}`;

      await c.env.CV_BUCKET.put(key,file.stream(),{
        httpMetadata:{contentType:file.type||"application/octet-stream"}
      });

      const textContent=file.type==="text/plain"
        ?(await file.text()).slice(0,100000)
        :"";

      await c.env.DB.batch([
        c.env.DB.prepare(
          "INSERT INTO users(id,role,email,password_hash,name,phone,status,company_id,approval_status) VALUES(?,?,?,?,?,?,?,?,?)"
        ).bind(uid,"candidate",email,"!cv-upload-no-login!",candidateName,null,"active",u.company_id,"approved"),
        c.env.DB.prepare(
          "INSERT INTO candidate_profiles(user_id,phone,full_name,cv_url,summary) VALUES(?,?,?,?,?)"
        ).bind(uid,null,candidateName,key,textContent)
      ]);

      await createApplication(c,u,jobId,uid);
      await audit(c,u,"candidate.upload",uid);

      results.push({
        id:uid,
        filename:file.name,
        job_id:job.id,
        job_title:job.title,
        status:"uploaded",
        extraction_status:file.type==="text/plain"?"complete":"pending"
      });
    }

    const uploaded=results.filter(x=>x.status==="uploaded").length;
    const failed=results.filter(x=>x.status==="failed").length;
    return c.json({ok:true,job_id:job.id,job_title:job.title,total:incoming.length,uploaded,failed,results},201);
  }catch(e:any){
    return c.json({error:"candidate_bulk_upload_failed",detail:String(e?.message||e)},500);
  }
});
app.get("/api/applications",async c=>{
  try{
    const u=c.get("user") as AuthUser;
    const m=await appMeta(c.env.DB);
    if(!m.candidate)return c.json({error:"applications_missing_candidate_key"},500);
    const tenant=m.tenant?`AND a.${m.tenant}=?`:"";
    const score=m.cs.has("ai_score")?"a.ai_score":m.cs.has("score")?"a.score":"NULL";
    const sql=`SELECT a.id,a.status,${score} screening_score,a.ai_recommendation,a.ai_summary,
      a.ai_strengths,a.ai_weaknesses,a.ai_matched_skills,a.ai_missing_skills,
      a.ai_interview_questions,j.id job_id,j.title job_title,cu.id candidate_id,
      cu.name candidate_name,cp.cv_url,cp.summary cv_summary,cp.skills,cp.experience_years
      FROM applications a
      JOIN jobs j ON j.id=a.job_id
      JOIN users cu ON cu.id=a.${m.candidate}
      LEFT JOIN candidate_profiles cp ON cp.user_id=cu.id
      WHERE j.company_id=? ${tenant}
      ORDER BY a.rowid DESC`;
    const params=m.tenant?[u.company_id,u.company_id]:[u.company_id];
    return c.json((await c.env.DB.prepare(sql).bind(...params).all()).results||[]);
  }catch(e:any){
    return c.json({error:"applications_query_failed",detail:String(e?.message||e)},500);
  }
});
app.post("/api/screenings/rule",async c=>{
  try{
    const u=c.get("user") as AuthUser;
    const b=await c.req.json<any>();
    const m=await appMeta(c.env.DB);
    if(!m.candidate)return c.json({error:"applications_missing_candidate_key"},500);
    const r=await c.env.DB.prepare(
      `SELECT a.id,j.title,j.description,cu.name,cp.skills,cp.experience_years,cp.summary
       FROM applications a JOIN jobs j ON j.id=a.job_id
       JOIN users cu ON cu.id=a.${m.candidate}
       LEFT JOIN candidate_profiles cp ON cp.user_id=cu.id
       WHERE a.id=? AND j.company_id=? LIMIT 1`
    ).bind(b.application_id,u.company_id).first<any>();
    if(!r)return c.json({error:"application_not_found"},404);

    let skills:string[]=[];
    if(r.skills){
      try{skills=JSON.parse(r.skills)}catch{skills=String(r.skills).split(/[,|]/).map((x:string)=>x.trim()).filter(Boolean)}
    }
    const profile=String(r.summary||"").toLowerCase();
    const hits=skills.filter(s=>profile.includes(String(s).toLowerCase()));
    const score=skills.length?Math.round(hits.length/skills.length*100):(Number(r.experience_years||0)>0?70:50);
    const status=score>=85?"Strong Match":score>=70?"Potential Match":"Low Match";
    if(m.cs.has("ai_score")){
      await c.env.DB.prepare(
        "UPDATE applications SET ai_score=?,status=?,ai_recommendation=?,ai_summary=?,ai_matched_skills=?,ai_missing_skills=?,ai_screened_at=CURRENT_TIMESTAMP WHERE id=?"
      ).bind(score,status,"Rule-based screening",`Rule-based screening for ${r.title}.`,JSON.stringify(hits),JSON.stringify(skills.filter(s=>!hits.includes(s))),b.application_id).run();
    }else if(m.cs.has("score")){
      await c.env.DB.prepare("UPDATE applications SET score=?,status=? WHERE id=?").bind(score,status,b.application_id).run();
    }else if(m.cs.has("status")){
      await c.env.DB.prepare("UPDATE applications SET status=? WHERE id=?").bind(status,b.application_id).run();
    }
    await audit(c,u,"screening.rule",b.application_id);
    return c.json({overall_score:score,status,matched_skills:hits,missing_skills:skills.filter(s=>!hits.includes(s)),note:"Rule-based screening; recruiter makes the final decision."});
  }catch(e:any){
    return c.json({error:"rule_screen_failed",detail:String(e?.message||e)},500);
  }
});

async function extractCvWithOpenAI(c:any, fileKey:string, filename:string, mimeType:string){
  if(!c.env.OPENAI_API_KEY)throw new Error("ai_not_configured");
  const obj=await c.env.CV_BUCKET.get(fileKey);
  if(!obj)throw new Error("cv_file_not_found");
  const bytes=await obj.arrayBuffer();
  if(bytes.byteLength>12*1024*1024)throw new Error("cv_file_too_large_for_extraction");
  const base64=Array.from(new Uint8Array(bytes),b=>String.fromCharCode(b)).join("");
  const dataUrl=`data:${mimeType||"application/octet-stream"};base64,${btoa(base64)}`;
  const schema={
    type:"object",additionalProperties:false,
    properties:{
      education:{type:"string"},
      experience_years:{type:"integer",minimum:0,maximum:60},
      current_position:{type:"string"},
      skills:{type:"array",items:{type:"string"}},
      languages:{type:"array",items:{type:"string"}},
      headline:{type:"string"},
      summary:{type:"string"},
      work_history:{type:"array",items:{type:"string"}},
      achievements:{type:"array",items:{type:"string"}}
    },
    required:["education","experience_years","current_position","skills","languages","headline","summary","work_history","achievements"]
  };
  const resp=await fetch("https://api.openai.com/v1/responses",{
    method:"POST",
    headers:{Authorization:`Bearer ${c.env.OPENAI_API_KEY}`,"Content-Type":"application/json"},
    body:JSON.stringify({
      model:c.env.OPENAI_MODEL||"gpt-5.6-luna",
      store:false,
      instructions:"Extract job-relevant information from this CV. Do not extract or return email, phone number, address, date of birth, gender, religion, race, marital status, photo details, national ID, or other protected/sensitive personal information. Do not invent missing facts. Use an empty string/array or 0 when evidence is absent. Return structured JSON only.",
      input:[{role:"user",content:[
        {type:"input_text",text:`Extract the CV for screening. Filename: ${filename}`},
        {type:"input_file",file_data:dataUrl,filename:filename}
      ]}],
      text:{format:{type:"json_schema",name:"cv_extraction",strict:true,schema}}
    })
  });
  if(!resp.ok){
    const errText=await resp.text();
    throw new Error(`openai_extraction_failed_${resp.status}:${errText.slice(0,300)}`);
  }
  const d=await resp.json() as any;
  const content=d?.output?.flatMap((x:any)=>x?.content||[]).find((x:any)=>x?.type==="output_text")?.text;
  if(!content)throw new Error("empty_extraction_response");
  return JSON.parse(content);
}

app.post("/api/candidates/extract",async c=>{
  try{
    const u=await currentUser(c);if(!u)return c.json({error:"unauthorized",stage:"cv_extract_auth"},401);
    const b=await c.req.json<any>();
    const m=await appMeta(c.env.DB);
    if(!m.candidate)return c.json({error:"applications_missing_candidate_key"},500);
    const r=await c.env.DB.prepare(
      `SELECT a.id application_id,a.${m.candidate} candidate_id,cp.cv_url,cp.full_name
       FROM applications a
       JOIN jobs j ON j.id=a.job_id
       JOIN users cu ON cu.id=a.${m.candidate}
       LEFT JOIN candidate_profiles cp ON cp.user_id=cu.id
       WHERE a.id=? AND j.company_id=? LIMIT 1`
    ).bind(b.application_id,u.company_id).first<any>();
    if(!r)return c.json({error:"application_not_found"},404);
    if(!r.cv_url)return c.json({error:"cv_file_missing"},404);
    const filename=String(r.cv_url).split("/").pop()||"cv";
    const lower=filename.toLowerCase();
    const mime=lower.endsWith(".pdf")?"application/pdf":lower.endsWith(".docx")?"application/vnd.openxmlformats-officedocument.wordprocessingml.document":"text/plain";
    const data=await extractCvWithOpenAI(c,r.cv_url,filename,mime);
    const summary=String(data.summary||"").slice(0,10000);
    const skills=JSON.stringify(data.skills||[]);
    const languages=JSON.stringify(data.languages||[]);
    const history=JSON.stringify(data.work_history||[]);
    const achievements=JSON.stringify(data.achievements||[]);
    const headline=String(data.headline||"").slice(0,500);
    const currentPosition=String(data.current_position||"").slice(0,500);
    const education=String(data.education||"").slice(0,1000);
    const cols=await c.env.DB.prepare("PRAGMA table_info(candidate_profiles)").all<any>();
    const cs=new Set((cols.results||[]).map((x:any)=>x.name));
    const sets:string[]=[];const vals:any[]=[];
    const add=(col:string,val:any)=>{if(cs.has(col)){sets.push(`${col}=?`);vals.push(val)}};
    add("education",education);add("experience_years",Number(data.experience_years||0));add("current_position",currentPosition);
    add("skills",skills);add("languages",languages);add("headline",headline);add("summary",summary);
    add("updated_at",new Date().toISOString());
    if(sets.length){
      vals.push(r.candidate_id);
      await c.env.DB.prepare(`UPDATE candidate_profiles SET ${sets.join(",")} WHERE user_id=?`).bind(...vals).run();
    }
    return c.json({ok:true,application_id:r.application_id,filename,extraction:data});
  }catch(e:any){
    const msg=String(e?.message||e);
    const status=msg==="ai_not_configured"?503:msg==="cv_file_not_found"?404:500;
    return c.json({error:msg==="ai_not_configured"?"ai_not_configured":"cv_extraction_failed",detail:msg},status);
  }
});

app.post("/api/ai/screen",async c=>{try{const u=await currentUser(c);if(!u)return c.json({error:"unauthorized",stage:"ai_screen_auth"},401);if(!u.company_id)return c.json({error:"company_context_missing"},400);if(!c.env.OPENAI_API_KEY)return c.json({error:"ai_not_configured",message:"Set OPENAI_API_KEY as a Worker secret."},503);const b=await c.req.json<any>(),m=await appMeta(c.env.DB);if(!m.candidate)return c.json({error:"applications_missing_candidate_key"},500);const r=await c.env.DB.prepare(`SELECT a.id,j.title,j.description,cu.name,cp.summary,cp.skills,cp.experience_years,cp.education,cp.current_position,cp.languages FROM applications a JOIN jobs j ON j.id=a.job_id JOIN users cu ON cu.id=a.${m.candidate} LEFT JOIN candidate_profiles cp ON cp.user_id=cu.id WHERE a.id=? AND j.company_id=? LIMIT 1`).bind(b.application_id,u.company_id).first<any>();if(!r)return c.json({error:"application_not_found"},404);const schema={type:"object",additionalProperties:false,properties:{overall_score:{type:"integer",minimum:0,maximum:100},summary:{type:"string"},strengths:{type:"array",items:{type:"string"}},gaps:{type:"array",items:{type:"string"}},recommendation:{type:"string"},interview_questions:{type:"array",items:{type:"string"}}},required:["overall_score","summary","strengths","gaps","recommendation","interview_questions"]};const resp=await fetch("https://api.openai.com/v1/responses",{method:"POST",headers:{Authorization:`Bearer ${c.env.OPENAI_API_KEY}`,"Content-Type":"application/json"},body:JSON.stringify({model:c.env.OPENAI_MODEL||"gpt-5.6",store:false,instructions:"Assess job fit only from job-relevant evidence. Never infer protected traits. Return structured JSON only.",input:`JOB: ${r.title}\nDESCRIPTION: ${String(r.description).slice(0,14000)}\nCANDIDATE: ${r.name}\nEXTRACTED CV PROFILE: SUMMARY=${r.summary||""}\nEDUCATION=${r.education||""}\nCURRENT_POSITION=${r.current_position||""}\nSKILLS=${r.skills||""}\nLANGUAGES=${r.languages||""}\nEXPERIENCE_YEARS=${r.experience_years||0}`,text:{format:{type:"json_schema",name:"candidate_screening",strict:true,schema}}})});if(!resp.ok)return c.json({error:"ai_request_failed",status:resp.status},502);const d=await resp.json() as any,content=d?.output?.flatMap((x:any)=>x?.content||[]).find((x:any)=>x?.type==="output_text")?.text;if(!content)return c.json({error:"empty_ai_response"},502);let result:any;try{result=JSON.parse(content)}catch{return c.json({error:"invalid_ai_json"},502)};result.status=result.overall_score>=85?"Strong Match":result.overall_score>=70?"Potential Match":"Low Match";if(m.cs.has("ai_score"))await c.env.DB.prepare("UPDATE applications SET ai_score=?,status=?,ai_summary=?,ai_strengths=?,ai_weaknesses=?,ai_matched_skills=?,ai_missing_skills=?,ai_recommendation=?,ai_interview_questions=?,ai_model=?,ai_screened_at=CURRENT_TIMESTAMP WHERE id=?").bind(result.overall_score,result.status,result.summary,JSON.stringify(result.strengths),JSON.stringify(result.gaps),JSON.stringify(result.strengths),JSON.stringify(result.gaps),result.recommendation,JSON.stringify(result.interview_questions),c.env.OPENAI_MODEL||"gpt-5.6",b.application_id).run();else if(m.cs.has("score"))await c.env.DB.prepare("UPDATE applications SET score=?,status=? WHERE id=?").bind(result.overall_score,result.status,b.application_id).run();else if(m.cs.has("status"))await c.env.DB.prepare("UPDATE applications SET status=? WHERE id=?").bind(result.status,b.application_id).run();await audit(c,u,"screening.ai",b.application_id);return c.json(result)}catch(e:any){return c.json({error:"ai_screen_failed",detail:String(e?.message||e)},500)}});
app.get("/", (c) => c.html(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${c.env.APP_NAME}</title>
<style>
:root{font-family:Inter,system-ui,-apple-system,sans-serif;color:#10213b;background:#f6f8fb}body{margin:0}header{background:#fff;border-bottom:1px solid #e5eaf2;padding:18px 28px;display:flex;justify-content:space-between;align-items:center}main{max-width:1180px;margin:28px auto;padding:0 20px}.brand{display:flex;align-items:center;gap:12px;font-weight:800;font-size:22px}.brand img{width:42px;height:42px;object-fit:contain}.muted{color:#667085}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.card{background:#fff;border:1px solid #e4e9f1;border-radius:16px;padding:20px;box-shadow:0 3px 14px #132b4a0a;margin-bottom:18px}.metric b{font-size:30px;display:block;margin-top:8px}.tabs{display:flex;gap:8px;margin:18px 0}.tabs button,.btn{border:0;border-radius:10px;padding:10px 14px;background:#0b66ff;color:white;cursor:pointer}.tabs button.secondary,.btn.secondary{background:#edf2f8;color:#20304a}.hidden{display:none}.auth{max-width:480px;margin:60px auto}.input{width:100%;box-sizing:border-box;padding:12px;border:1px solid #d7deea;border-radius:10px;margin:6px 0 12px}.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}.table{width:100%;border-collapse:collapse}.table th,.table td{text-align:left;padding:11px;border-bottom:1px solid #edf0f5}.pill{display:inline-block;padding:4px 8px;border-radius:999px;background:#edf4ff}.danger{color:#b42318}.logo{max-width:58px;max-height:58px}@media(max-width:800px){.grid,.row{grid-template-columns:1fr}.grid{grid-template-columns:1fr 1fr}}
.upload-options{display:grid;grid-template-columns:1fr 1fr;gap:12px;width:100%}.upload-option{border:1px solid #d7deea;border-radius:10px;padding:12px;display:flex;flex-direction:column;gap:8px;font-weight:600}.upload-option input{width:100%}@media(max-width:700px){.upload-options{grid-template-columns:1fr}}</style></head><body>
<div id="auth" class="auth card"><div class="brand"><img src="/logo.png" onerror="this.style.display='none'"><span>${c.env.APP_NAME}</span></div><h2 id="authTitle">Sign in</h2><p class="muted">Secure recruiter workspace with tenant isolation.</p><form id="authForm"><div id="orgField" class="hidden"><label>Organization</label><input class="input" id="org" autocomplete="organization"></div><label>Name</label><input class="input" id="name" autocomplete="name"><label>Email</label><input class="input" id="email" type="email" autocomplete="email" required><label>Password</label><input class="input" id="password" type="password" minlength="10" autocomplete="current-password" required><button class="btn" id="authBtn">Sign in</button></form><p><button class="btn secondary" id="toggleAuth">Create an organization</button></p><div id="authMsg" class="muted"></div></div>
<div id="app" class="hidden"><header><div class="brand"><img src="/logo.png" onerror="this.style.display='none'"><span>${c.env.APP_NAME}</span></div><div><span id="who" class="muted"></span> <button class="btn secondary" id="logout">Logout</button></div></header><main><div class="tabs"><button data-tab="overview">Overview</button><button class="secondary" data-tab="jobs">Jobs</button><button class="secondary" data-tab="candidates">Candidates</button><button class="secondary" data-tab="applications">Screening</button></div>
<section id="overview" class="tab"><div class="grid"><div class="card metric">Jobs<b id="mJobs">0</b></div><div class="card metric">Candidates<b id="mCandidates">0</b></div><div class="card metric">Applications<b id="mApplications">0</b></div><div class="card metric">Strong matches<b id="mStrong">0</b></div></div><div class="card"><h2>AI Screening</h2><p class="muted">Create jobs, upload CVs, attach candidates to jobs, then run rule-based or AI screening.</p></div></section>
<section id="jobs" class="tab hidden"><div class="card"><h2>Create job</h2><form id="jobForm"><div class="row"><input class="input" id="jobTitle" placeholder="Job title" required><input class="input" id="jobLocation" placeholder="Location"></div><textarea class="input" id="jobDescription" rows="6" placeholder="Job description" required></textarea><input class="input" id="jobSkills" placeholder="Skills, comma separated"><button class="btn" type="submit">Create job</button><p id="jobMsg" class="muted"></p></form></div><div class="card"><h2>Jobs</h2><table class="table"><thead><tr><th>Title</th><th>Location</th><th>Created</th></tr></thead><tbody id="jobsBody"></tbody></table></div></section>
<section id="candidates" class="tab hidden"><div class="card"><h2>Upload CV</h2><p class="muted">Pilih satu atau banyak CV, atau satu folder. CV diproses satu per satu agar upload banyak file tidak macet. Nama, email, dan nomor HP tidak diperlukan.</p><form id="candidateForm"><div class="row"><select class="input" id="candidateJob" required><option value="">Select job position</option></select><div class="upload-options"><label class="upload-option"><span>📄 Upload file(s)</span><input class="input" id="candidateFiles" type="file" accept=".pdf,.docx,.txt" multiple></label><label class="upload-option"><span>📁 Upload folder</span><input class="input" id="candidateFolder" type="file" accept=".pdf,.docx,.txt" multiple webkitdirectory directory></label></div></div><button class="btn">Upload CVs</button><p id="candidateMsg" class="muted"></p></form></div><div class="card"><h2>Candidate Screening Pool</h2><table class="table"><thead><tr><th>CV</th><th>Job</th><th>Score</th><th>Status</th></tr></thead><tbody id="candidatesBody"></tbody></table></div></section>
<section id="applications" class="tab hidden"><div class="card"><h2>Screening pipeline</h2><table class="table"><thead><tr><th>Candidate</th><th>Job</th><th>Score</th><th>Status</th><th>Actions</th></tr></thead><tbody id="appsBody"></tbody></table></div><div id="result" class="card hidden"><h2>Screening result</h2><pre id="resultText" style="white-space:pre-wrap"></pre></div></section>
</main></div>
<script>
const $=s=>document.querySelector(s); const $$=s=>[...document.querySelectorAll(s)];
let registerMode=false;
async function api(path,opt={}){const r=await fetch(path,{credentials:'same-origin',...opt});const data=await r.json().catch(()=>({}));if(!r.ok){const base=data.error||'request_failed';const message=data.detail?base+': '+data.detail:base;throw new Error(message)}return data}
function setMode(){registerMode=!registerMode;$('#authTitle').textContent=registerMode?'Create organization':'Sign in';$('#authBtn').textContent=registerMode?'Create account':'Sign in';$('#orgField').classList.toggle('hidden',!registerMode);$('#name').required=registerMode;$('#toggleAuth').textContent=registerMode?'Back to sign in':'Create an organization'}
$('#toggleAuth').onclick=e=>{e.preventDefault();setMode()};
$('#authForm').onsubmit=async e=>{e.preventDefault();$('#authMsg').textContent='Working...';try{const path=registerMode?'/api/auth/register':'/api/auth/login';const body=registerMode?{organization_name:$('#org').value,name:$('#name').value,email:$('#email').value,password:$('#password').value}:{email:$('#email').value,password:$('#password').value};const r=await api(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});$('#auth').classList.add('hidden');$('#app').classList.remove('hidden');$('#who').textContent=r.user.name+' · '+(r.user.company_name||'');$('#authMsg').textContent='Loading dashboard...';try{await refresh();$('#authMsg').textContent=''}catch(e){$('#authMsg').textContent='Dashboard error: '+e.message}}catch(err){$('#authMsg').textContent=err.message}}
$('#logout').onclick=async()=>{await api('/api/auth/logout',{method:'POST'});location.reload()};
$$('.tabs button').forEach(b=>b.onclick=()=>{$$('.tabs button').forEach(x=>x.classList.add('secondary'));b.classList.remove('secondary');$$('.tab').forEach(x=>x.classList.add('hidden'));$('#'+b.dataset.tab).classList.remove('hidden');if(b.dataset.tab==='jobs')loadJobs();if(b.dataset.tab==='candidates')loadCandidates();if(b.dataset.tab==='applications')loadApps()});
async function loadJobs(){const jobs=await api('/api/jobs');$('#jobsBody').innerHTML=jobs.map(j=>\`<tr><td>\${esc(j.title)}</td><td>\${esc(j.location||'-')}</td><td>\${new Date(j.created_at).toLocaleString()}</td></tr>\`).join('');$('#candidateJob').innerHTML='<option value="">Attach to job (optional)</option>'+jobs.map(j=>\`<option value="\${j.id}">\${esc(j.title)}</option>\`).join('')}
async function loadCandidates(){const rows=await api('/api/candidates');$('#candidatesBody').innerHTML=rows.map(x=>'<tr><td>'+esc(x.cv_url||x.full_name||'-')+'</td><td>'+esc(x.job_title||'-')+'</td><td>'+(x.score==null?'-':x.score)+'</td><td><span class="pill">'+esc(x.status||'Uploaded')+'</span></td></tr>').join('')}
async function loadApps(){
  try{
    const rows=await api('/api/applications');
    $('#appsBody').innerHTML=rows.map(x=>{
      const score=x.screening_score==null?'-':x.screening_score;
      return '<tr><td>'+esc(x.candidate_name||'CV Candidate')+'</td><td>'+esc(x.job_title||'-')+'</td><td><strong>'+score+'</strong></td><td><span class="pill">'+esc(x.status||'Review')+'</span></td><td><button type="button" class="btn secondary" onclick="extractCv(\\''+x.id+'\\')">Extract CV</button> <button type="button" class="btn secondary" onclick="rule(\\''+x.id+'\\')">Rule</button> <button type="button" class="btn" onclick="ai(\\''+x.id+'\\')">AI Screen</button></td></tr>';
    }).join('');
  }catch(e){
    $('#appsBody').innerHTML='<tr><td colspan="5">Screening load failed: '+esc(e.message)+'</td></tr>';
  }
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
    out.textContent=JSON.stringify(r.extraction||r,null,2);
    await refresh();
    await loadApps();
  }catch(e){
    out.textContent='CV extraction failed: '+e.message;
  }finally{
    window.extractingCv=false;
  }
}
async function refresh(){const d=await api('/api/dashboard');$('#mJobs').textContent=d.jobs;$('#mCandidates').textContent=d.candidates;$('#mApplications').textContent=d.applications;$('#mStrong').textContent=d.strong_matches;await loadJobs()}
$('#jobForm').onsubmit=async e=>{
  e.preventDefault();
  const msg=$('#jobMsg');
  msg.textContent='Creating job...';
  try{
    const r=await api('/api/jobs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
      title:$('#jobTitle').value,
      location:$('#jobLocation').value,
      description:$('#jobDescription').value,
      requirements:$('#jobSkills').value.split(',').map(x=>x.trim()).filter(Boolean)
    })});
    e.target.reset();
    msg.textContent='Job created successfully.';
    await refresh();
  }catch(err){
    msg.textContent='Create job failed: '+err.message;
  }
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
window.rule=async id=>{try{const r=await api('/api/screenings/rule',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({application_id:id})});showResult(r);await refresh();loadApps()}catch(e){showResult({error:e.message})}}
window.ai=async id=>{try{const r=await api('/api/ai/screen',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({application_id:id})});showResult(r);await refresh();loadApps()}catch(e){showResult({error:e.message})}}
function showResult(x){$('#result').classList.remove('hidden');$('#resultText').textContent=JSON.stringify(x,null,2)}
function esc(s){return String(s??'').replace(/[&<>'"]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[m]))}
async function boot(){try{const r=await api('/api/auth/me');$('#auth').classList.add('hidden');$('#app').classList.remove('hidden');$('#who').textContent=r.user.name+' · '+(r.user.company_name||'');await refresh();$('#authMsg').textContent=''}catch(e){$('#authMsg').textContent='Login/session error: '+e.message;$('#auth').classList.remove('hidden');$('#app').classList.add('hidden')}}
boot();
</script></body></html>`));

app.notFound((c) => c.json({ error: "not_found" }, 404));

export default app;
