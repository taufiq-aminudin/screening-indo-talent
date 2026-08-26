// cloudflare/index.js
import handleAdminLogin from "./routes/superAdminLogin.js";

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/api/admin/login" && request.method === "POST") {
      return handleAdminLogin(request);
    }

    return new Response("Not Found", { status: 404 });
  }
};
// cloudflare/index.js
import handleAdminLogin from "./routes/superAdminLogin.js";
import handleAuthMe from "./routes/authMe.js";

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/api/admin/login" && request.method === "POST") {
      return handleAdminLogin(request);
    }

    if (url.pathname === "/api/auth/me" && request.method === "GET") {
      return handleAuthMe(request);
    }

    return new Response("Not Found", { status: 404 });
  }
};
// cloudflare/index.js
import handleAdminLogin from "./routes/superAdminLogin.js";
import handleAuthMe from "./routes/authMe.js";

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/api/admin/login" && request.method === "POST") {
      return handleAdminLogin(request);
    }

    if (url.pathname === "/api/auth/me" && request.method === "GET") {
      return handleAuthMe(request);
    }

    return new Response("Not Found", { status: 404 });
  }
};
import handleAdminLogin from "./routes/superAdminLogin.js";
import handleAuthMe from "./routes/authMe.js";

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/api/admin/login" && request.method === "POST") {
      return handleAdminLogin(request);
    }

    if (url.pathname === "/api/auth/me" && request.method === "GET") {
      return handleAuthMe(request);
    }

    return new Response("Not Found", { status: 404 });
  }
};

