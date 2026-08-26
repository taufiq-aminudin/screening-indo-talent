export default async function handleAuthMe(request, env) {
  const cookieHeader = request.headers.get("Cookie") || "";

  const cookies = Object.fromEntries(
    cookieHeader.split(";").map(c => {
      const [k, ...rest] = c.trim().split("=");
      return [k, rest.join("=")];
    })
  );

  const atsAdmin = cookies["ats_admin"];

  if (!atsAdmin) {
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

  const separator = atsAdmin.indexOf(":");

  if (separator === -1) {
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

  const email = atsAdmin.slice(0, separator);
  const signature = atsAdmin.slice(separator + 1);

  const SESSION_SECRET = env.SESSION_SECRET;

  if (!SESSION_SECRET) {
    return new Response(
      JSON.stringify({ error: "server_configuration_error" }),
      {
        status: 500,
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
    ["verify"]
  );

  let signatureBytes;

  try {
    if (!/^[0-9a-fA-F]+$/.test(signature) || signature.length % 2 !== 0) {
      throw new Error("Invalid signature");
    }

    signatureBytes = new Uint8Array(
      signature.match(/.{2}/g).map(byte => parseInt(byte, 16))
    );
  } catch {
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

  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    signatureBytes,
    encoder.encode(email)
  );

  if (!valid) {
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

  return new Response(
    JSON.stringify({
      email,
      role: "super-admin",
      stage: "V6.44"
    }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json"
      }
    }
  );
}
