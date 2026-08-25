// superAdminLogin.js
import { HMAC } from 'crypto';

export default async function handleAdminLogin(request) {
  const { email, password } = await request.json();

  // Ambil secret dari environment Worker
  const SUPER_ADMIN_EMAIL = process.env.SUPER_ADMIN_EMAIL;
  const SUPER_ADMIN_PASSWORD = process.env.SUPER_ADMIN_PASSWORD;
  const SESSION_SECRET = process.env.SESSION_SECRET;

  // Validasi kredensial
  if (email !== SUPER_ADMIN_EMAIL || password !== SUPER_ADMIN_PASSWORD) {
    return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 });
  }

  // Buat cookie ats_admin dengan HMAC
  const hmac = new HMAC("sha256", SESSION_SECRET);
  hmac.update(email + Date.now());
  const signature = hmac.digest("hex");

  const cookieValue = `${email}:${signature}`;
  const headers = new Headers();
  headers.append("Set-Cookie", `ats_admin=${cookieValue}; HttpOnly; Secure; SameSite=Strict; Path=/`);

  return new Response(JSON.stringify({ success: true, stage: "V6.44" }), {
    status: 200,
    headers
  });
}
