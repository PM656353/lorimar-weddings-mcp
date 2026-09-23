import type { LorimarEnv } from "./connection";
import { digest, READ_SCOPE, UPSTREAM_SCOPES } from "./connection";

const headers = {
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "no-store",
  // Preserve Origin on the consent POST without leaking URLs cross-origin.
  "Referrer-Policy": "same-origin",
  "X-Content-Type-Options": "nosniff",
  "Content-Security-Policy":
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
};
export function escapeHtml(text: string): string {
  return text.replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!
  );
}
function page(body: string, status = 200, cookie?: string): Response {
  return new Response(
    `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Lorimar Weddings</title><style>body{font:18px system-ui;max-width:640px;margin:60px auto;padding:24px;line-height:1.6}button{padding:12px 20px;font:inherit}</style><h1>Lorimar Weddings</h1>${body}</html>`,
    {
      status,
      headers: { ...headers, ...(cookie ? { "Set-Cookie": cookie } : {}) }
    }
  );
}
function cookieValue(request: Request): string {
  return (
    (request.headers.get("Cookie") ?? "")
      .split(";")
      .map((p) => p.trim())
      .find((p) => p.startsWith("__Host-lorimar_auth="))
      ?.slice("__Host-lorimar_auth=".length) ?? ""
  );
}
const clearCookie =
  "__Host-lorimar_auth=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0";
function ready(env: LorimarEnv): boolean {
  return !!(
    env.TRIPLESEAT_CLIENT_ID &&
    env.TRIPLESEAT_CLIENT_SECRET &&
    /^[1-9][0-9]*$/.test(env.TRIPLESEAT_SITE_ID ?? "") &&
    /^[a-f0-9]{64}$/i.test(env.TOKEN_ENCRYPTION_KEY ?? "")
  );
}
export const authHandler = {
  async fetch(request: Request, env: LorimarEnv): Promise<Response> {
    const url = new URL(request.url);
    if (url.origin !== env.PUBLIC_ORIGIN)
      return new Response("Use the configured production address.", {
        status: 400
      });
    if (url.pathname === "/")
      return page(
        "<p>The Lorimar Weddings connection is online. Connect through your assistant to authorize read-only access to Tripleseat.</p>"
      );
    if (!ready(env))
      return page(
        "<p>The connection is awaiting administrator setup. No Tripleseat access is enabled.</p>",
        503
      );
    try {
      if (url.pathname === "/authorize" && request.method === "GET") {
        const info = await env.OAUTH_PROVIDER.parseAuthRequest(request);
        const client = await env.OAUTH_PROVIDER.lookupClient(info.clientId);
        if (
          !client ||
          !client.redirectUris.includes(info.redirectUri) ||
          info.responseType !== "code" ||
          info.codeChallengeMethod !== "S256" ||
          !/^[A-Za-z0-9_-]{43}$/.test(info.codeChallenge ?? "") ||
          info.scope.some((s) => s !== READ_SCOPE)
        ) {
          return page(
            "<p>Invalid authorization request. Start again from your assistant.</p>",
            400
          );
        }
        const resources = info.resource
          ? Array.isArray(info.resource)
            ? info.resource
            : [info.resource]
          : [];
        if (resources.some((r) => r !== `${env.PUBLIC_ORIGIN}/mcp`))
          return page("<p>Invalid resource.</p>", 400);
        info.scope = [READ_SCOPE];
        const state = crypto.randomUUID();
        const browser = crypto.randomUUID();
        await env.CONNECTIONS.get(env.CONNECTIONS.idFromName(state)).begin(
          info,
          await digest(browser)
        );
        return page(
          `<p><strong>${escapeHtml(client.clientName || "Your assistant")}</strong> requests read-only access to Lorimar's Tripleseat leads, contacts, and events.</p><p>Return address: ${escapeHtml(info.redirectUri)}</p><p>It cannot send messages, change records, or book tours. Continue only if you started this connection.</p><form method="post" action="/authorize"><input type="hidden" name="state" value="${state}"><button type="submit">Continue to Tripleseat</button></form>`,
          200,
          `__Host-lorimar_auth=${browser}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600`
        );
      }
      if (url.pathname === "/authorize" && request.method === "POST") {
        if (request.headers.get("Origin") !== env.PUBLIC_ORIGIN)
          return page("<p>Invalid origin.</p>", 403);
        const form = await request.formData();
        const state = form.get("state");
        const browser = cookieValue(request);
        if (typeof state !== "string" || !/^[a-f0-9-]{36}$/.test(state))
          return page(
            "<p>Sign-in form is missing its session identifier (AUTH_FORM). Reopen the connection from your assistant.</p>",
            400
          );
        if (!browser)
          return page(
            "<p>Your browser did not return the sign-in cookie (AUTH_COOKIE). Open this connection in a regular browser tab with cookies enabled.</p>",
            400
          );
        if (
          !(await env.CONNECTIONS.get(
            env.CONNECTIONS.idFromName(state)
          ).approve(await digest(browser)))
        )
          return page(
            "<p>The sign-in session no longer matches this browser, has expired, or was already used (AUTH_SESSION). Close other Lorimar sign-in tabs and reconnect.</p>",
            400
          );
        const upstream = new URL(
          "https://login.tripleseat.com/oauth2/authorize"
        );
        upstream.search = new URLSearchParams({
          client_id: env.TRIPLESEAT_CLIENT_ID,
          redirect_uri: `${env.PUBLIC_ORIGIN}/oauth/callback`,
          response_type: "code",
          scope: UPSTREAM_SCOPES,
          state
        }).toString();
        return new Response(null, {
          status: 302,
          headers: {
            Location: upstream.toString(),
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer"
          }
        });
      }
      if (url.pathname === "/oauth/callback" && request.method === "GET") {
        const state = url.searchParams.get("state") ?? "";
        const code = url.searchParams.get("code") ?? "";
        const browser = cookieValue(request);
        if (
          url.searchParams.has("error") ||
          !/^[a-f0-9-]{36}$/.test(state) ||
          !code ||
          code.length > 4096 ||
          !browser
        )
          return page(
            "<p>Authorization was declined or expired. Start again from your assistant.</p>",
            400,
            clearCookie
          );
        const info = await env.CONNECTIONS.get(
          env.CONNECTIONS.idFromName(state)
        ).finish(await digest(browser), code);
        if (!info)
          return page(
            "<p>Expired authorization. Start again.</p>",
            400,
            clearCookie
          );
        const result = await env.OAUTH_PROVIDER.completeAuthorization({
          request: info,
          userId: state,
          scope: [READ_SCOPE],
          metadata: { label: "Lorimar Tripleseat read-only connection" },
          props: { connectionId: state }
        });
        return new Response(null, {
          status: 302,
          headers: {
            Location: result.redirectTo,
            "Set-Cookie": clearCookie,
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer"
          }
        });
      }
      return page("<p>Page not found.</p>", 404);
    } catch {
      // Never expose upstream bodies, authorization codes, or credentials.
      return page(
        "<p>Unable to authorize. Ask your administrator to check the Tripleseat application, read permissions, site ID, and encrypted secrets, then reconnect.</p>",
        400,
        clearCookie
      );
    }
  }
};
