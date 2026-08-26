function clean(value) {
  return String(value ?? "").replace(/\r?\n$/g, "");
}

function hexToBytes(value) {
  return new Uint8Array(value.match(/.{2}/g).map(byte => parseInt(byte, 16)));
}

export default async function handleAuthMe(request, env) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const match = cookieHeader.match(/(?:^|;\s*)ats_admin=([^;]+)/);
  const atsAdmin = match ? match[1] : null;

  if (!atsAdmin) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
    });
  }

  const separator = atsAdmin.indexOf(":");
  if (separator === -1) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
    });
  }

  const email = atsAdmin.slice(0, separator);
  const signature = atsAdmin.slice(separator + 1);
  const configuredEmail = clean(env.SUPER_ADMIN_EMAIL).trim();
  const sessionSecret = clean(env.SESSION_SECRET);

  if (!configuredEmail || !sessionSecret || email !== configuredEmail) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
    });
  }

  if (!/^[0-9a-fA-F]{64}$/.test(signature)) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
    });
  }

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(sessionSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    hexToBytes(signature),
    encoder.encode(email)
  );

  if (!valid) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
    });
  }

  return new Response(
    JSON.stringify({
      email,
      role: "super-admin",
      stage: "V6.44"
    }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Cache-Control": "no-store"
      }
    }
  );
}
