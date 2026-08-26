# AI Screening SaaS — V6 Cloudflare Foundation

This V6 starts the migration from the V5 Flask/SQLite MVP to a Cloudflare-first architecture.

## Target

- GitHub for source control
- Cloudflare Workers for API/runtime
- Cloudflare D1 for relational data
- Cloudflare R2 for CV/document storage
- AI API only when needed
- Brand-neutral and multi-tenant

## Important

The `legacy/ai_screening` folder contains the original V5 application for reference. It is NOT used by the Worker.

V6 is intentionally a foundation: the next implementation step is authentication + secure tenant context, then R2 CV upload and PDF/DOCX extraction, then the recruiter UI.

## Cloudflare setup

1. Create a D1 database named `ai_screening`.
2. Create an R2 bucket named `ai-screening-cv`.
3. Put the returned D1 database ID into `wrangler.toml`.
4. Install dependencies:
   `npm install`
5. Apply D1 migration locally:
   `npm run db:migrate:local`
6. Test:
   `npm run dev`
7. Set the AI secret when needed:
   `npx wrangler secret put OPENAI_API_KEY`
8. Deploy:
   `npm run deploy`

## Custom domain

After deployment, add `screening.indo-talent.my.id` as a Custom Domain in Cloudflare Workers/Pages. No new domain is required.

## Cost-control strategy

Rule screening runs before AI. AI is used only for candidates/jobs that need semantic evaluation. Do not process every CV with AI automatically.

## Security direction

Never trust a client-supplied organization_id for authorization in production. V6's next step is authenticated tenant context so organization scope comes from the session/token, not request data.

AI output is decision support, not an automatic hiring decision.

## V6.1 update

The foundation now includes authentication, tenant-isolated protected routes, D1-backed sessions, R2 CV upload, a recruiter dashboard, rule-based screening, and an OpenAI Responses API screening endpoint. Apply `migrations/0002_auth_uploads.sql` to `indo-talent-db` before using the new authenticated routes.
