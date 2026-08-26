# FINAL AUTH FIX — existing cloudflare structure

This patch intentionally keeps the existing structure:

cloudflare/
  routes/
  index.js
  package.json
  wrangler.toml

It does NOT introduce src/ or public/.

Changes:
- index.js passes env to both auth handlers.
- Super Admin password verification uses SUPER_ADMIN_PASSWORD_HASH with PBKDF2.
- PBKDF2 supports the V6.5/V6.6 format `pbkdf2$100000$...` and never exceeds 100,000 iterations.
- Login signs HMAC(email).
- /api/auth/me verifies the same HMAC(email).
- Existing ats_admin cookie format remains email:hex-signature.

Before testing, delete the old `ats_admin` cookie in the browser and log in again.

Required Worker values:
- SUPER_ADMIN_EMAIL
- SUPER_ADMIN_PASSWORD_HASH
- SESSION_SECRET

Do not commit real secrets to Git.
