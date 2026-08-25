// cloudflare/routes/authMe.js
export default async function handleAuthMe(request) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = Object.fromEntries(
    cookieHeader.split(";").map(c => {
      const [k, v] = c.trim().split("=");
      return [k, v];
    })
  );

  const atsAdmin = cookies["ats_admin"];
  if (!atsAdmin) {
    return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 });
  }

  const [email, signature] = atsAdmin.split(":");
  const SESSION_SECRET = process.env.SESSION_SECRET;

  // Verifikasi HMAC
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(SESSION_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    Buffer.from(signature, "hex"),
    encoder.encode(email) // bisa ditambah timestamp jika ingin lebih ketat
  );

  if (!valid) {
    return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 });
  }

  // Jika valid, kembalikan info Super Admin
  return new Response(JSON.stringify({
    email,
    role: "super-admin",
    stage: "V6.44"
  }), { status: 200 });
}
