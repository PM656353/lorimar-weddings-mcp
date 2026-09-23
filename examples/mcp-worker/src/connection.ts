import { DurableObject } from "cloudflare:workers";
import type {
  AuthRequest,
  OAuthHelpers
} from "@cloudflare/workers-oauth-provider";

export interface LorimarEnv {
  OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER: OAuthHelpers;
  CONNECTIONS: DurableObjectNamespace<TripleseatConnection>;
  TRIPLESEAT_CLIENT_ID: string;
  TRIPLESEAT_CLIENT_SECRET: string;
  TRIPLESEAT_SITE_ID: string;
  TOKEN_ENCRYPTION_KEY: string;
  PUBLIC_ORIGIN: string;
}
export const READ_SCOPE = "tripleseat:read";
export const UPSTREAM_SCOPES =
  "leads:read contacts:read events:read sites:read";
const API = "https://api.tripleseat.com";
const TTL = 30 * 24 * 60 * 60 * 1000;
type Pending = {
  request: AuthRequest;
  browser: string;
  expires: number;
  stage: "consent" | "upstream";
};
type Tokens = {
  access: string;
  refresh: string;
  expires: number;
  site: string;
};
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
export function hasSite(value: unknown, siteId: string): boolean {
  return (
    Array.isArray(value) &&
    value.some((entry) => {
      if (!isRecord(entry)) return false;
      const site = isRecord(entry.site) ? entry.site : entry;
      return String(site.id) === siteId;
    })
  );
}
export function validReadPath(path: string): boolean {
  return /^\/v1\/(leads\/search|(?:leads|contacts|events)\/[1-9][0-9]*)$/.test(
    path
  );
}
export async function digest(value: string): Promise<string> {
  const bytes = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))
  );
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
async function key(env: LorimarEnv): Promise<CryptoKey> {
  if (!/^[a-f0-9]{64}$/i.test(env.TOKEN_ENCRYPTION_KEY ?? ""))
    throw new Error("Encryption key is not configured");
  const bytes = Uint8Array.from(env.TOKEN_ENCRYPTION_KEY.match(/../g)!, (v) =>
    parseInt(v, 16)
  );
  return crypto.subtle.importKey("raw", bytes, "AES-GCM", false, [
    "encrypt",
    "decrypt"
  ]);
}
async function seal(
  env: LorimarEnv,
  value: Tokens
): Promise<{ iv: number[]; data: number[] }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    await key(env),
    new TextEncoder().encode(JSON.stringify(value))
  );
  return { iv: Array.from(iv), data: Array.from(new Uint8Array(data)) };
}
async function open(
  env: LorimarEnv,
  value: { iv: number[]; data: number[] }
): Promise<Tokens> {
  const bytes = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(value.iv) },
    await key(env),
    new Uint8Array(value.data)
  );
  return JSON.parse(new TextDecoder().decode(bytes)) as Tokens;
}
async function tokenRequest(
  env: LorimarEnv,
  fields: Record<string, string>
): Promise<Tokens> {
  let response: Response;
  try {
    response = await fetch(`${API}/oauth2/token`, {
      method: "POST",
      redirect: "manual",
      signal: AbortSignal.timeout(15000),
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json"
      },
      body: new URLSearchParams({
        ...fields,
        client_id: env.TRIPLESEAT_CLIENT_ID,
        client_secret: env.TRIPLESEAT_CLIENT_SECRET
      })
    });
  } catch (error) {
    const name = error instanceof Error ? error.name : "";
    const label =
      name === "TimeoutError" || name === "AbortError"
        ? "AUTH_TOKEN_TIMEOUT"
        : name === "TypeError"
          ? "AUTH_TOKEN_FETCH_TYPE"
          : "AUTH_TOKEN_FETCH_FAILED";
    throw new Error(label);
  }
  if (response.status >= 300 && response.status < 400)
    throw new Error("AUTH_TOKEN_REDIRECT");
  if (!response.ok) throw new Error(`AUTH_TOKEN_HTTP_${response.status}`);
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new Error("AUTH_TOKEN_NOT_JSON");
  }
  if (
    !isRecord(body) ||
    typeof body.access_token !== "string" ||
    typeof body.refresh_token !== "string" ||
    typeof body.expires_in !== "number" ||
    body.expires_in <= 0
  ) {
    throw new Error("AUTH_TOKEN_FORMAT");
  }
  if (
    typeof body.scope === "string" &&
    UPSTREAM_SCOPES.split(" ").some(
      (scope) => !body.scope!.toString().split(" ").includes(scope)
    )
  ) {
    throw new Error("AUTH_SCOPE_MISSING");
  }
  return {
    access: body.access_token,
    refresh: body.refresh_token,
    expires: Date.now() + body.expires_in * 1000,
    site: env.TRIPLESEAT_SITE_ID
  };
}

// One object per authorization grant. RPC methods are accessible only through
// the Worker binding. Serializing token use prevents refresh-token rotation races.
export class TripleseatConnection extends DurableObject<LorimarEnv> {
  async begin(request: AuthRequest, browser: string): Promise<void> {
    await this.ctx.storage.put<Pending>("pending", {
      request,
      browser,
      expires: Date.now() + 600000,
      stage: "consent"
    });
    await this.ctx.storage.setAlarm(Date.now() + 600000);
  }
  async approve(browser: string): Promise<string> {
    return this.ctx.blockConcurrencyWhile(async () => {
      const p = await this.ctx.storage.get<Pending>("pending");
      if (!p) return "AUTH_STATE_MISSING";
      if (p.browser !== browser) return "AUTH_BROWSER_MISMATCH";
      if (p.expires < Date.now()) return "AUTH_TIMED_OUT";
      if (p.stage !== "consent") return "AUTH_ALREADY_USED";
      await this.ctx.storage.put("pending", { ...p, stage: "upstream" });
      return "approved";
    });
  }
  async finish(
    browser: string,
    code: string
  ): Promise<AuthRequest | { diagnostic: string } | null> {
    return this.ctx.blockConcurrencyWhile(async () => {
      const p = await this.ctx.storage.get<Pending>("pending");
      if (
        !p ||
        p.browser !== browser ||
        p.expires < Date.now() ||
        p.stage !== "upstream"
      )
        return null;
      let stage = "AUTH_TOKEN_NETWORK";
      try {
        // Consume before the external request so a code/state cannot be replayed.
        await this.ctx.storage.delete("pending");
        const tokens = await tokenRequest(this.env, {
          grant_type: "authorization_code",
          code,
          redirect_uri: `${this.env.PUBLIC_ORIGIN}/oauth/callback`
        });
        stage = "AUTH_SITES_NETWORK";
        let sites: Response;
        try {
          sites = await fetch(`${API}/v1/sites`, {
            headers: {
              Authorization: `Bearer ${tokens.access}`,
              Accept: "application/json"
            },
            redirect: "manual",
            signal: AbortSignal.timeout(15000)
          });
        } catch (error) {
          const name = error instanceof Error ? error.name : "";
          throw new Error(
            name === "TimeoutError" || name === "AbortError"
              ? "AUTH_SITES_TIMEOUT"
              : name === "TypeError"
                ? "AUTH_SITES_FETCH_TYPE"
                : "AUTH_SITES_FETCH_FAILED"
          );
        }
        // Never forward bearer credentials to a redirected destination.
        if (sites.status >= 300 && sites.status < 400)
          throw new Error("AUTH_SITES_REDIRECT");
        if (!sites.ok) throw new Error(`AUTH_SITES_HTTP_${sites.status}`);
        stage = "AUTH_SITES_FORMAT";
        if (!hasSite(await sites.json(), this.env.TRIPLESEAT_SITE_ID))
          throw new Error("AUTH_SITE_MISMATCH: configured Lorimar site");
        stage = "AUTH_TOKEN_ENCRYPTION";
        const encrypted = await seal(this.env, tokens);
        stage = "AUTH_TOKEN_STORAGE";
        await this.ctx.storage.put("tokens", encrypted);
        await this.ctx.storage.put("deadline", Date.now() + TTL);
        await this.ctx.storage.setAlarm(Date.now() + TTL);
        return p.request;
      } catch (error) {
        // Return sanitized data: throwing inside blockConcurrencyWhile resets
        // the object and can obscure the original failure across RPC.
        const message = error instanceof Error ? error.message : "";
        const diagnostic =
          message.match(
            /\bAUTH_(?:TOKEN_HTTP_[1-5][0-9]{2}|SITES_HTTP_[1-5][0-9]{2}|TOKEN_FORMAT|TOKEN_TIMEOUT|TOKEN_FETCH_TYPE|TOKEN_FETCH_FAILED|TOKEN_REDIRECT|TOKEN_NOT_JSON|SITES_TIMEOUT|SITES_FETCH_TYPE|SITES_FETCH_FAILED|SITES_REDIRECT|SCOPE_MISSING|SITE_MISMATCH)\b/
          )?.[0] ?? stage;
        return { diagnostic };
      }
    });
  }
  async read(
    path: string,
    query: Record<string, string>
  ): Promise<{ status: number; data?: string }> {
    if (!validReadPath(path)) return { status: 400 };
    const allowed = new Set([
      "page",
      "created_after",
      "created_before",
      "query",
      "order",
      "sort_direction"
    ]);
    if (Object.keys(query).some((k) => !allowed.has(k))) return { status: 400 };
    return this.ctx.blockConcurrencyWhile(async () => {
      const stored = await this.ctx.storage.get<{
        iv: number[];
        data: number[];
      }>("tokens");
      const deadline = await this.ctx.storage.get<number>("deadline");
      if (!stored || !deadline || Date.now() >= deadline)
        return { status: 401 };
      let tokens = await open(this.env, stored);
      if (tokens.site !== this.env.TRIPLESEAT_SITE_ID) return { status: 403 };
      if (tokens.expires <= Date.now() + 60000) {
        // An interrupted rotating-token refresh requires reauthorization rather
        // than retrying an old refresh token whose outcome is unknown.
        await this.ctx.storage.delete("tokens");
        tokens = await tokenRequest(this.env, {
          grant_type: "refresh_token",
          refresh_token: tokens.refresh
        });
        await this.ctx.storage.put("tokens", await seal(this.env, tokens));
      }
      const url = new URL(path, API);
      for (const [k, v] of Object.entries(query)) url.searchParams.set(k, v);
      url.searchParams.set("site_id", tokens.site);
      const response = await fetch(url, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${tokens.access}`,
          Accept: "application/json"
        },
        redirect: "manual",
        signal: AbortSignal.timeout(15000)
      });
      if (!response.ok) return { status: response.status };
      return { status: 200, data: await response.text() };
    });
  }
  async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}
