import handleAdminLogin from "./routes/superAdminLogin.js";
import handleAuthMe from "./routes/authMe.js";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/admin/login" && request.method === "POST") {
      return handleAdminLogin(request, env);
    }

    if (url.pathname === "/api/auth/me" && request.method === "GET") {
      return handleAuthMe(request, env);
    }

    return new Response("Not Found", { status: 404 });
  }
};
