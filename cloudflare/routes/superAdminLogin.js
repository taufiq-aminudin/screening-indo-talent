export default async function handleAdminLogin(request, env) {
  const { email, password } = await request.json();

  const SUPER_ADMIN_EMAIL = env.SUPER_ADMIN_EMAIL;
  const SUPER_ADMIN_PASSWORD = env.SUPER_ADMIN_PASSWORD;
  const SESSION_SECRET = env.SESSION_SECRET;

  if (
    email !== SUPER_ADMIN_EMAIL ||
    password !== SUPER_ADMIN_PASSWORD
  ) {
    return new Response(
      JSON.stringify({ error: "unauthorized" }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json"
        }
      }
    );
  }

  const encoder = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(SESSION_SECRET),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(email)
  );

  const signatureHex = Array.from(
    new Uint8Array(signature)
  )
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  const cookieValue = `${email}:${signatureHex}`;

  return new Response(
    JSON.stringify({
      success: true,
      stage: "V6.44"
    }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Set-Cookie":
          `ats_admin=${cookieValue}; HttpOnly; Secure; SameSite=Strict; Path=/`
      }
    }
  );
}
