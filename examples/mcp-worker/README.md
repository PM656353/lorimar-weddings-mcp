# Lorimar Weddings Tripleseat MCP

This version adds authenticated, read-only Tripleseat tools to Lorimar's existing Cloudflare Worker. It does not send email, update Tripleseat, schedule tours, or run unattended follow-ups.

## Current status

Prepared locally, not deployed. The previous public greeting server remains the live deployment until these changes are committed and built. Configuration and live Tripleseat validation are still required. The Lorimar OAuth KV namespace ID has been configured.

The MCP endpoint is:

https://lorimar-weddings-mcp.patrick-07a.workers.dev/mcp

The callback route implemented in this code is:

https://lorimar-weddings-mcp.patrick-07a.workers.dev/oauth/callback

This callback is for the new Tripleseat OAuth application. It is not the ChatGPT return URL. The callback must be deployed before a real sign-in is attempted.

## Setup in order

1. Completed: the Workers KV namespace `lorimar-weddings-oauth` is configured as `OAUTH_KV` with ID `f2d516f780854267990150f7cc7d5833`.
2. Create the dedicated Tripleseat OAuth application, `Lorimar Weddings MCP`, with the callback above. Use `https://www.lorimarwinery.com` as the product URL, AI Application / Lead Agent, and `weddings@lorimarwinery.com` as the contact. Request only `leads:read contacts:read events:read sites:read`. Verify the available scope names in Tripleseat. Do not reuse the earlier broad application.
3. Confirmed September 23: Lorimar's Tripleseat **site ID is 6368**, from a successful GET /v1/sites response. A site ID is not necessarily a location ID. This implementation authorizes only accounts whose `/v1/sites` response includes that exact site ID.
4. In this Worker's Cloudflare settings, add encrypted secrets named `TRIPLESEAT_CLIENT_ID`, `TRIPLESEAT_CLIENT_SECRET`, and `TOKEN_ENCRYPTION_KEY`. Use a password manager or a local cryptographic generator to create a fresh 32-byte key encoded as 64 hexadecimal characters for `TOKEN_ENCRYPTION_KEY`. Never paste the values into chat or commit them to GitHub. Keep the key stable: changing it requires everyone to reconnect.
5. Add the `TRIPLESEAT_SITE_ID` Worker variable. `PUBLIC_ORIGIN` is already set in Wrangler. For reproducible deployments, add the non-secret site ID to `vars` in `wrangler.jsonc` as well. Wrangler deployments may replace variables configured only in the dashboard.
6. Upload the changed source files to the existing GitHub repository. Do not upload this ZIP as a single file and do not create a repository inside the repository. Preserve the directory paths listed in `LORIMAR_SETUP.md` at the repository root. The new Durable Object binding and SQLite migration are already in Wrangler.
7. Retain the working Cloudflare build settings: root `/`, build `pnpm run build`, deploy `pnpm --dir examples/mcp-worker run deploy`. Check the resulting build log.
8. Before connecting real data, verify that an unauthenticated request to `/mcp` returns 401 and `/.well-known/oauth-authorization-server` advertises S256, `/authorize`, and `/oauth/token`. Verify `/.well-known/oauth-protected-resource/mcp` as well. The old anonymous `hello` tool is removed.
9. Create the custom MCP connection with OAuth using the MCP endpoint above. Follow its sign-in flow, review the displayed client/return address, and authorize with a Tripleseat customer administrator. Tripleseat documents that regular users cannot authorize this integration. Keep the connection private to authorized Lorimar staff.
10. Test `connection_status`, then `list_recent_leads`, and one known lead/contact/event. Compare IDs and results with Tripleseat. Test revocation and reconnection before routine use. A successful local build does not prove live Tripleseat permissions or that the target ChatGPT agent supports this connection; both remain live acceptance checks.

## Tools

- `connection_status`: configured site and read-only capability information; not a credential health check.
- `list_recent_leads`: newest-created leads, 50 per page, optional date and name filters. Results include all lead types; the assistant must inspect event type to identify weddings. Pagination is explicit. Date filtering does not provide a precise timestamp watermark or unattended lead monitoring.
- `get_lead`, `get_contact`, `get_event`: one record by ID in the configured site.

Lead content is untrusted data, not instructions. Tools expose no general URL fetcher and accept no arbitrary site ID. No write or delete endpoints are exposed. Review the fields returned by real Tripleseat records before making this available beyond the wedding team.

## Authentication and storage

Cloudflare's OAuth provider manages the MCP-side OAuth flow, metadata, grants, and tokens in the dedicated KV namespace. S256 PKCE is required; implicit and plain-PKCE flows are disabled. Tripleseat uses its separately documented authorization-code flow on the upstream side.

The local consent page requires a same-origin POST. State is browser-bound, expires after ten minutes, and is consumed before exchanging a Tripleseat code. Only an account with access to the configured site is accepted. Client-supplied text is HTML-escaped. Responses do not log or display upstream token bodies.

Each authorization has a Durable Object with AES-GCM-encrypted Tripleseat tokens. Token refresh is serialized to prevent simultaneous use of rotating refresh tokens. An uncertain or interrupted refresh requires reconnection. All API reads include the server-selected site ID. Connections expire after 30 days and their stored data is deleted by an alarm; authorization state expires after ten minutes. Failed connection attempts are cleaned up by that same short alarm. Customer records are returned to the MCP caller but not persisted by this implementation.

## Local verification

From the repository root after installing dependencies and building the Agents package:

```sh
pnpm --dir examples/mcp-worker exec vitest run --config tests/vitest.config.ts
pnpm --dir examples/mcp-worker exec tsc --noEmit
pnpm --dir examples/mcp-worker exec vite build
pnpm run check
```

Security tests exercise site isolation, no arbitrary API paths, browser-bound one-use consent, S256 enforcement, redirect validation, encrypted token storage, serialized renewal, metadata, and anonymous-access rejection. They use mocked storage and Tripleseat HTTP responses. The metadata/401 test uses the actual OAuth provider with a stub MCP handler. These are not Cloudflare-runtime or live-account end-to-end tests.

## Sources

- https://support.tripleseat.com/hc/en-us/articles/40652011678231-OAuth-2-0-Implementation
- https://support.tripleseat.com/hc/en-us/articles/41942861771543-API-Overview-Resources
- https://api.tripleseat.com/api-docs/v1/openapi.yaml

The upstream API specification and documentation were retrieved while preparing this implementation. Live validation is still required for Lorimar's account.
