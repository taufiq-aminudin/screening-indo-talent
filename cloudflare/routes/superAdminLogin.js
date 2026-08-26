export default async function handleAdminLogin(request, env) {
  try {
    const { email, password } = await request.json();

    const SUPER_ADMIN_EMAIL = env.SUPER_ADMIN_EMAIL;
    const SUPER_ADMIN_PASSWORD = env.SUPER_ADMIN_PASSWORD;
    const SESSION_SECRET = env.SESSION_SECRET;

    if (!SUPER_ADMIN_EMAIL || !SUPER_ADMIN_PASSWORD || !SESSION_SECRET) {
      return new Response(
        JSON.stringify({
          error: "server_configuration_error"
        }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json"
          }
        }
      );
    }

    if (
      email !== SUPER_ADMIN_EMAIL ||
      password !== SUPER_ADMIN_PASSWORD
    ) {
      return new Response(
        JSON.stringify({
          error: "unauthorized"
        }),
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

    // IMPORTANT:
    // Login dan /api/auth/me harus menandatangani
    // data yang sama.
    const signature = await crypto.subtle.sign(
      "HMAC",
      key,
      encoder.encode(email)
    );

    const signatureHex = Array.from(
      new Uint8Array(signature)
    )
      .map(byte => byte.toString(16).padStart(2, "0"))
      .join("");

    const cookieValue =
      `${email}:${signatureHex}`;

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

  } catch (error) {
    return new Response(
      JSON.stringify({
        error: "server_error"
      }),
      {
        status: 500,
        headers: {
          "Content-Type": "application/json"
        }
      }
    );
  }
}
