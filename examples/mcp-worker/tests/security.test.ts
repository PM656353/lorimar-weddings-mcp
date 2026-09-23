vi.mock("agents/mcp/server", () => ({
  createMcpHandler: () => () => new Response("authenticated test stub")
}));
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  TripleseatConnection,
  digest,
  hasSite,
  validReadPath
} from "../src/connection";
import type { LorimarEnv } from "../src/connection";
import { authHandler, escapeHtml } from "../src/auth";
const origin = "https://lorimar-weddings-mcp.patrick-07a.workers.dev";
function fixture() {
  const data = new Map<string, unknown>();
  let chain = Promise.resolve();
  const ctx = {
    storage: {
      get: async (k: string) => data.get(k),
      put: async (k: string, v: unknown) => {
        data.set(k, v);
      },
      delete: async (k: string) => data.delete(k),
      deleteAll: async () => data.clear(),
      setAlarm: async () => {}
    },
    blockConcurrencyWhile: <T>(cb: () => Promise<T>) => {
      const result = chain.then(cb);
      chain = result.then(
        () => {},
        () => {}
      );
      return result;
    }
  } as unknown as DurableObjectState;
  const env = {
    PUBLIC_ORIGIN: origin,
    TRIPLESEAT_SITE_ID: "42",
    TRIPLESEAT_CLIENT_ID: "test-id",
    TRIPLESEAT_CLIENT_SECRET: "test-secret",
    TOKEN_ENCRYPTION_KEY: "a".repeat(64)
  } as LorimarEnv;
  const connection = new TripleseatConnection(ctx, env);
  const info = {
    responseType: "code",
    clientId: "test-client",
    redirectUri: "https://chatgpt.com/callback",
    scope: ["tripleseat:read"],
    state: "client-state",
    codeChallenge: "x".repeat(43),
    codeChallengeMethod: "S256"
  };
  env.CONNECTIONS = {
    idFromName: (id: string) => id,
    get: () => connection
  } as unknown as LorimarEnv["CONNECTIONS"];
  env.OAUTH_PROVIDER = {
    parseAuthRequest: vi.fn(async () => ({ ...info })),
    lookupClient: vi.fn(async () => ({
      clientName: "ChatGPT",
      redirectUris: [info.redirectUri]
    }))
  } as unknown as LorimarEnv["OAUTH_PROVIDER"];
  return { data, env, connection, info };
}
afterEach(() => {
  vi.unstubAllGlobals();
});
describe("read-only boundary", () => {
  it("allows only the four intended API path shapes", () => {
    expect(validReadPath("/v1/leads/search")).toBe(true);
    expect(validReadPath("/v1/contacts/23")).toBe(true);
    for (const path of [
      "/v1/sites",
      "/v1/leads/0",
      "/v1/leads/../events",
      "https://evil.example",
      "/v1/events/1/notes",
      "/v1/events/1?site_id=2"
    ])
      expect(validReadPath(path)).toBe(false);
  });
  it("requires an exact authorized site", () => {
    expect(hasSite([{ site: { id: 42 } }], "42")).toBe(true);
    expect(hasSite([{ site: { id: 4 } }], "42")).toBe(false);
    expect(hasSite({ id: 42 }, "42")).toBe(false);
  });
  it("rejects site override and missing credentials without an upstream call", async () => {
    const { connection } = fixture();
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    expect(
      (await connection.read("/v1/leads/search", { site_id: "99" })).status
    ).toBe(400);
    expect((await connection.read("/v1/leads/search", {})).status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
describe("authorization", () => {
  it("escapes client-controlled HTML", () => {
    expect(escapeHtml('<img src=x onerror="x">')).toBe(
      "&lt;img src=x onerror=&quot;x&quot;&gt;"
    );
  });
  it("fails closed before configuration", async () => {
    const { env } = fixture();
    env.TRIPLESEAT_CLIENT_SECRET = "";
    expect(
      (await authHandler.fetch(new Request(`${origin}/authorize`), env)).status
    ).toBe(503);
  });
  it("rejects preview hosts", async () => {
    const { env } = fixture();
    expect(
      (
        await authHandler.fetch(
          new Request("https://preview.example/authorize"),
          env
        )
      ).status
    ).toBe(400);
  });
  it("requires S256 PKCE", async () => {
    const { env, info } = fixture();
    vi.mocked(env.OAUTH_PROVIDER.parseAuthRequest).mockResolvedValue({
      ...info,
      codeChallengeMethod: "plain"
    });
    expect(
      (await authHandler.fetch(new Request(`${origin}/authorize`), env)).status
    ).toBe(400);
  });
  it("rejects unregistered redirect URIs", async () => {
    const { env, info } = fixture();
    vi.mocked(env.OAUTH_PROVIDER.parseAuthRequest).mockResolvedValue({
      ...info,
      redirectUri: "https://evil.example"
    });
    expect(
      (await authHandler.fetch(new Request(`${origin}/authorize`), env)).status
    ).toBe(400);
  });
  it("requires same-origin consent POST", async () => {
    const { env } = fixture();
    expect(
      (
        await authHandler.fetch(
          new Request(`${origin}/authorize`, {
            method: "POST",
            headers: { Origin: "https://evil.example" }
          }),
          env
        )
      ).status
    ).toBe(403);
  });
  it("keeps overlapping browser sign-ins independent and rejects replay", async () => {
    const { env } = fixture();
    const connections = new Map<string, TripleseatConnection>();
    env.CONNECTIONS = {
      idFromName: (id: string) => id,
      get: (id: string) => {
        if (!connections.has(id)) connections.set(id, fixture().connection);
        return connections.get(id)!;
      }
    } as unknown as LorimarEnv["CONNECTIONS"];
    const first = await authHandler.fetch(
      new Request(`${origin}/authorize`),
      env
    );
    const second = await authHandler.fetch(
      new Request(`${origin}/authorize`),
      env
    );
    const html = await first.text();
    const state = html.match(/name="state" value="([^"]+)"/)![1];
    const firstCookie = first.headers.get("Set-Cookie")!.split(";")[0];
    const secondCookie = second.headers.get("Set-Cookie")!.split(";")[0];
    expect(firstCookie.split("=")[0]).not.toBe(secondCookie.split("=")[0]);
    const submit = (cookie: string) =>
      authHandler.fetch(
        new Request(`${origin}/authorize`, {
          method: "POST",
          headers: { Origin: origin, Cookie: cookie },
          body: new URLSearchParams({ state })
        }),
        env
      );
    expect((await submit(secondCookie)).status).toBe(400);
    const approved = await submit(`${firstCookie}; ${secondCookie}`);
    expect(approved.status).toBe(302);
    expect(new URL(approved.headers.get("Location")!).hostname).toBe(
      "login.tripleseat.com"
    );
    expect((await submit(firstCookie)).status).toBe(400);
  });
  it("reproduces a cleared cookie after a failed callback and offers a fresh start", async () => {
    const { env } = fixture();
    const startUrl = `${origin}/authorize?client_id=test-client&state=client-state`;
    const start = await authHandler.fetch(new Request(startUrl), env);
    const html = await start.text();
    const state = html.match(/name="state" value="([^"]+)"/)![1];
    const cookie = start.headers.get("Set-Cookie")!.split(";")[0];
    expect(cookie).toMatch(/^__Host-lorimar_auth_/);
    expect(start.headers.get("Set-Cookie")).toContain(
      "Secure; HttpOnly; SameSite=Lax"
    );
    const submit = (value: string) =>
      authHandler.fetch(
        new Request(startUrl, {
          method: "POST",
          headers: { Origin: origin, Cookie: value },
          body: new URLSearchParams({ state })
        }),
        env
      );
    expect((await submit(cookie)).status).toBe(302);
    const fetchMock = vi.fn().mockRejectedValue(new TypeError("network"));
    vi.stubGlobal("fetch", fetchMock);
    const failed = await authHandler.fetch(
      new Request(`${origin}/oauth/callback?state=${state}&code=test-code`, {
        headers: { Cookie: cookie }
      }),
      env
    );
    expect(failed.headers.get("Set-Cookie")).toContain("Max-Age=0");
    // Returning to the old consent page after that response has no cookie.
    const stale = await submit("");
    expect(stale.status).toBe(400);
    const message = await stale.text();
    expect(message).toContain("AUTH_COOKIE");
    expect(message).toContain("Start a fresh sign-in");
    expect(message).toContain(
      "/authorize?client_id=test-client&amp;state=client-state"
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const fresh = await authHandler.fetch(new Request(startUrl), env);
    expect(fresh.headers.get("Set-Cookie")!.split(";")[0]).not.toBe(cookie);
  });
  it("binds consent to the browser and consumes it once", async () => {
    const { connection, info } = fixture();
    await connection.begin(info, await digest("browser"));
    expect(await connection.approve(await digest("other"))).toBe(
      "AUTH_BROWSER_MISMATCH"
    );
    expect(await connection.approve(await digest("browser"))).toBe("approved");
    expect(await connection.approve(await digest("browser"))).toBe(
      "AUTH_ALREADY_USED"
    );
  });
  it("rejects unapproved callback without token exchange", async () => {
    const { connection, info } = fixture();
    await connection.begin(info, "browser");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    expect(await connection.finish("browser", "code")).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });
  it("rejects a different Tripleseat account and consumes callback state", async () => {
    const { connection, info, data } = fixture();
    await connection.begin(info, "browser");
    await connection.approve("browser");
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        Response.json({
          access_token: "secret-access",
          refresh_token: "secret-refresh",
          expires_in: 7200
        })
      )
      .mockResolvedValueOnce(Response.json([{ site: { id: 99 } }]));
    vi.stubGlobal("fetch", fetchMock);
    expect(await connection.finish("browser", "code")).toEqual({
      diagnostic: "AUTH_SITE_MISMATCH"
    });
    expect(data.has("tokens")).toBe(false);
    expect(await connection.finish("browser", "code")).toBeNull();
  });
  it.each([
    [
      "AUTH_SITES_REDIRECT",
      () =>
        Promise.resolve(
          new Response(null, {
            status: 302,
            headers: { Location: "https://other.example/sites" }
          })
        )
    ],
    [
      "AUTH_SITES_TIMEOUT",
      () => Promise.reject(new DOMException("timeout", "TimeoutError"))
    ],
    [
      "AUTH_SITES_FETCH_TYPE",
      () => Promise.reject(new TypeError("private detail"))
    ],
    [
      "AUTH_SITES_FETCH_FAILED",
      () => Promise.reject(new Error("private detail"))
    ]
  ] as const)(
    "returns %s without storing tokens or replaying requests",
    async (diagnostic, siteResponse) => {
      const { connection, info, data } = fixture();
      await connection.begin(info, "browser");
      await connection.approve("browser");
      const fetchMock = vi
        .fn()
        .mockResolvedValueOnce(
          Response.json({
            access_token: "secret-access",
            refresh_token: "secret-refresh",
            expires_in: 7200
          })
        )
        .mockImplementationOnce(siteResponse);
      vi.stubGlobal("fetch", fetchMock);
      expect(await connection.finish("browser", "code")).toEqual({
        diagnostic
      });
      expect(fetchMock).toHaveBeenCalledTimes(2);
      expect(fetchMock.mock.calls[1][1].redirect).toBe("manual");
      expect(data.has("tokens")).toBe(false);
      expect(await connection.finish("browser", "code")).toBeNull();
    }
  );
  it("encrypts tokens, serializes rotating refresh, and scopes all reads", async () => {
    const { connection, info, data } = fixture();
    await connection.begin(info, "browser");
    await connection.approve("browser");
    const urls: string[] = [];
    let tokenCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL, options: RequestInit) => {
        const url = String(input);
        urls.push(url);
        if (url.endsWith("/oauth2/token")) {
          tokenCalls++;
          return Response.json({
            access_token: "secret-access",
            refresh_token: "secret-refresh",
            expires_in: tokenCalls === 1 ? 1 : 7200
          });
        }
        if (url.endsWith("/v1/sites"))
          return Response.json([{ site: { id: 42 } }]);
        expect(options.method).toBe("GET");
        return Response.json({ lead: { id: 1 } });
      })
    );
    expect(await connection.finish("browser", "code")).toEqual(info);
    expect(JSON.stringify(data.get("tokens"))).not.toContain("secret-access");
    const results = await Promise.all([
      connection.read("/v1/leads/1", {}),
      connection.read("/v1/leads/2", {})
    ]);
    expect(results.map((r) => r.status)).toEqual([200, 200]);
    expect(tokenCalls).toBe(2);
    expect(
      urls
        .filter((u) => u.includes("/v1/leads/"))
        .every((u) => new URL(u).searchParams.get("site_id") === "42")
    ).toBe(true);
    expect(await connection.finish("browser", "code")).toBeNull();
  });
});

describe("MCP OAuth boundary", () => {
  it("advertises S256 and rejects anonymous tool access", async () => {
    const { env } = fixture();
    const { default: worker } = await import("../src/server");
    const ctx = { waitUntil: () => {} } as unknown as ExecutionContext;
    const meta = await worker.fetch(
      new Request(`${origin}/.well-known/oauth-authorization-server`),
      env,
      ctx
    );
    expect(meta.status).toBe(200);
    const body = (await meta.json()) as Record<string, unknown>;
    expect(body.code_challenge_methods_supported).toEqual(["S256"]);
    expect(body.authorization_endpoint).toBe(`${origin}/authorize`);
    const denied = await worker.fetch(
      new Request(`${origin}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" })
      }),
      env,
      ctx
    );
    expect(denied.status).toBe(401);
    expect(denied.headers.get("WWW-Authenticate")).toContain(
      "resource_metadata"
    );
  });
});
