function clean(value) {
  return String(value ?? "").replace(/\r?\n$/g, "");
}

function base64UrlToBytes(value) {
  const s = value.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(s + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, ch => ch.charCodeAt(0));
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

async function verifyPassword(password, stored) {
  try {
    const parts = String(stored || "").split("$");
    if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;

    const iterations = Number(parts[1]);
    if (!Number.isInteger(iterations) || iterations < 1 || iterations > 100000) {
      return false;
    }

    const salt = base64UrlToBytes(parts[2]);
    const expected = parts[3];
    const encoder = new TextEncoder();

    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256"
      },
      key,
      256
    );

    const actual = bytesToBase64Url(new Uint8Array(bits));

    if (actual.length !== expected.length) return false;

    let diff = 0;
    for (let i = 0; i < actual.length; i++) {
      diff |= actual.charCodeAt(i) ^ expected.charCodeAt(i);
    }
    return diff === 0;
  } catch {
    return false;
  }
}

async function signEmail(email, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(email)
  );

  return Array.from(new Uint8Array(signature))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

export default async function handleAdminLogin(request, env) {
  try {
    const { email, password } = await request.json();

    const configuredEmail = clean(env.SUPER_ADMIN_EMAIL).trim();
    const passwordHash = clean(env.SUPER_ADMIN_PASSWORD_HASH).trim();
    const sessionSecret = clean(env.SESSION_SECRET);

    if (!configuredEmail || !passwordHash || !sessionSecret) {
      return new Response(
        JSON.stringify({ error: "server_configuration_error" }),
        {
          status: 500,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    if (String(email ?? "").trim() !== configuredEmail) {
      return new Response(
        JSON.stringify({ error: "unauthorized" }),
        {
          status: 401,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    const validPassword = await verifyPassword(String(password ?? ""), passwordHash);
    if (!validPassword) {
      return new Response(
        JSON.stringify({ error: "unauthorized" }),
        {
          status: 401,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    // Login and /api/auth/me sign exactly the same payload: email.
    const signature = await signEmail(configuredEmail, sessionSecret);
    const cookieValue = `${configuredEmail}:${signature}`;

    return new Response(
      JSON.stringify({ success: true, stage: "V6.44" }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
          "Set-Cookie": `ats_admin=${cookieValue}; HttpOnly; Secure; SameSite=Strict; Path=/`
        }
      }
    );
  } catch {
    return new Response(
      JSON.stringify({ error: "server_error" }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
}
