// cloudflare/routes/superAdminLogin.js
export default async function handleAdminLogin(request) {
  const { email, password } = await request.json();

  const SUPER_ADMIN_EMAIL = process.env.SUPER_ADMIN_EMAIL;
  const SUPER_ADMIN_PASSWORD = process.env.SUPER_ADMIN_PASSWORD;
  const SESSION_SECRET = process.env.SESSION_SECRET;

  if (email !== SUPER_ADMIN_EMAIL || password !== SUPER_ADMIN_PASSWORD) {
    return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 });
  }

  // Buat cookie ats_admin dengan HMAC
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(SESSION_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(email + Date.now())
  );

  const cookieValue = `${email}:${Buffer.from(signature).toString("hex")}`;
  const headers = new Headers();
  headers.append("Set-Cookie", `ats_admin=${cookieValue}; HttpOnly; Secure; SameSite=Strict; Path=/`);

  return new Response(JSON.stringify({ success: true, stage: "V6.44" }), {
    status: 200,
    headers
  });
}
