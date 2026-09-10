/**
 * Tests for the remote (HTTP + OAuth) entry point.
 *
 * These drive a real listening server over fetch rather than calling handlers
 * directly, because most of what can go wrong in an MCP connector handshake is
 * in the HTTP envelope: status codes, WWW-Authenticate, and the discovery
 * documents.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Server } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalizeResource, loadHttpConfig, type HttpConfig } from "../src/http/config.js";
import { hashPassword, verifyPassword } from "../src/http/password.js";
import { OAuthStore } from "../src/http/store.js";
import { LocalOAuthProvider } from "../src/http/provider.js";
import { createApp } from "../src/http/app.js";
import {
  authorizationServerMetadata,
  protectedResourceMetadata,
} from "../src/http/metadata.js";
import { TeamleaderClient } from "../src/api/client.js";
import { TeamleaderAuth } from "../src/api/auth.js";

const PASSWORD = "correct horse battery staple";
const CLAUDE_REDIRECT = "https://claude.ai/api/mcp/auth_callback";

function testConfig(overrides: Partial<NodeJS.ProcessEnv> = {}): HttpConfig {
  return loadHttpConfig({
    PUBLIC_BASE_URL: "https://mcp.example.com",
    MCP_CONSENT_PASSWORD_HASH: hashPassword(PASSWORD),
    OAUTH_DB_PATH: ":memory:",
    ...overrides,
  } as NodeJS.ProcessEnv);
}

function pkce(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

describe("canonicalizeResource", () => {
  it("normalises scheme, host, default port, trailing slash and fragment", () => {
    expect(canonicalizeResource("HTTPS://MCP.Example.COM/mcp")).toBe("https://mcp.example.com/mcp");
    expect(canonicalizeResource("https://mcp.example.com:443/mcp")).toBe("https://mcp.example.com/mcp");
    expect(canonicalizeResource("https://mcp.example.com/mcp/")).toBe("https://mcp.example.com/mcp");
    expect(canonicalizeResource("https://mcp.example.com/mcp#frag")).toBe("https://mcp.example.com/mcp");
    expect(canonicalizeResource("https://mcp.example.com/")).toBe("https://mcp.example.com");
  });
});

describe("config", () => {
  it("derives issuer and resource from PUBLIC_BASE_URL", () => {
    const config = testConfig();
    expect(config.baseUrl).toBe("https://mcp.example.com");
    expect(config.resource).toBe("https://mcp.example.com/mcp");
    expect(config.allowedAudiences).toContain("https://mcp.example.com/mcp");
    expect(config.allowedAudiences).toContain("https://mcp.example.com");
  });

  it("defaults the redirect URI allowlist to Claude's callback only", () => {
    expect(testConfig().allowedRedirectUris).toEqual([CLAUDE_REDIRECT]);
  });

  it("rejects a non-https base URL that is not localhost", () => {
    expect(() => testConfig({ PUBLIC_BASE_URL: "http://mcp.example.com" })).toThrow(/https/);
  });

  it("rejects a base URL with a query string", () => {
    expect(() => testConfig({ PUBLIC_BASE_URL: "https://mcp.example.com?a=b" })).toThrow(/query/);
  });
});

describe("consent password", () => {
  it("accepts the right password and rejects everything else", () => {
    const hash = hashPassword(PASSWORD);
    expect(verifyPassword(PASSWORD, hash)).toBe(true);
    expect(verifyPassword("wrong", hash)).toBe(false);
    expect(verifyPassword(PASSWORD, "not-a-hash")).toBe(false);
    expect(verifyPassword(PASSWORD, "scrypt$1$2$3$bad$bad")).toBe(false);
  });

  it("produces a different hash each time (random salt)", () => {
    expect(hashPassword(PASSWORD)).not.toBe(hashPassword(PASSWORD));
  });
});

describe("metadata documents", () => {
  const config = testConfig();

  it("advertises S256 PKCE and dynamic client registration", () => {
    const meta = authorizationServerMetadata(config);
    expect(meta.code_challenge_methods_supported).toEqual(["S256"]);
    expect(meta.registration_endpoint).toBe("https://mcp.example.com/register");
    expect(meta.grant_types_supported).toContain("refresh_token");
    expect(meta.authorization_response_iss_parameter_supported).toBe(true);
  });

  it("does not advertise CIMD, so Claude falls back to DCR", () => {
    expect(authorizationServerMetadata(config)).not.toHaveProperty(
      "client_id_metadata_document_supported"
    );
  });

  it("offers offline_access on the AS but not on the resource", () => {
    // Claude appends offline_access only when the AS lists it, and the MCP spec
    // says the resource must not require it.
    expect(authorizationServerMetadata(config).scopes_supported).toContain("offline_access");
    expect(protectedResourceMetadata(config).scopes_supported).not.toContain("offline_access");
  });

  it("names this server as the resource and itself as the authorization server", () => {
    const prm = protectedResourceMetadata(config);
    expect(prm.resource).toBe("https://mcp.example.com/mcp");
    expect(prm.authorization_servers).toEqual(["https://mcp.example.com"]);
  });
});

describe("client registration", () => {
  it("rejects a redirect_uri that is not on the allowlist", () => {
    const store = new OAuthStore(":memory:", [CLAUDE_REDIRECT]);
    expect(() =>
      store.registerClient({ redirect_uris: ["https://evil.example.com/cb"] })
    ).toThrow(/redirect_uri not allowed/);
    store.close();
  });

  it("rejects a client that mixes an allowed and a disallowed redirect_uri", () => {
    const store = new OAuthStore(":memory:", [CLAUDE_REDIRECT]);
    expect(() =>
      store.registerClient({ redirect_uris: [CLAUDE_REDIRECT, "https://evil.example.com/cb"] })
    ).toThrow(/redirect_uri not allowed/);
    store.close();
  });

  it("accepts Claude's callback and assigns a client_id", () => {
    const store = new OAuthStore(":memory:", [CLAUDE_REDIRECT]);
    const client = store.registerClient({ redirect_uris: [CLAUDE_REDIRECT] });
    expect(client.client_id).toBeTruthy();
    expect(store.getClient(client.client_id)?.redirect_uris).toEqual([CLAUDE_REDIRECT]);
    expect(store.countClients()).toBe(1);
    store.close();
  });
});

describe("store persistence", () => {
  const dir = mkdtempSync(join(tmpdir(), "tl-mcp-store-"));
  const file = join(dir, "oauth-store.json");

  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("survives a restart: clients and tokens reload from the file", () => {
    const first = new OAuthStore(file, [CLAUDE_REDIRECT]);
    const client = first.registerClient({
      client_name: "Claude",
      redirect_uris: [CLAUDE_REDIRECT],
    });
    first.putAccessToken("tok", {
      clientId: client.client_id,
      scopes: ["teamleader"],
      resource: "https://mcp.example.com/mcp",
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
    });
    first.close();

    // A new process reading the same file must see both.
    const second = new OAuthStore(file, [CLAUDE_REDIRECT]);
    expect(second.getClient(client.client_id)?.client_name).toBe("Claude");
    expect(second.getAccessToken("tok")?.clientId).toBe(client.client_id);
    expect(second.countClients()).toBe(1);
    second.close();
  });

  it("drops expired tokens but keeps non-expiring refresh tokens on reload", () => {
    const store = new OAuthStore(file, [CLAUDE_REDIRECT]);
    const client = store.registerClient({ redirect_uris: [CLAUDE_REDIRECT] });
    const base = {
      clientId: client.client_id,
      scopes: ["teamleader"],
      resource: "https://mcp.example.com/mcp",
    };
    store.putAccessToken("expired", { ...base, expiresAt: Math.floor(Date.now() / 1000) - 10 });
    // expiresAt 0 means "never" for a refresh token, so a sweep must not eat it.
    store.putRefreshToken("eternal", { ...base, expiresAt: 0 });
    store.close();

    const reloaded = new OAuthStore(file, [CLAUDE_REDIRECT]);
    expect(reloaded.getAccessToken("expired")).toBeUndefined();
    expect(reloaded.consumeRefreshToken("eternal")?.clientId).toBe(client.client_id);
    reloaded.close();
  });

  it("refuses to start on a corrupt store rather than dropping every client", () => {
    const bad = join(dir, "corrupt.json");
    writeFileSync(bad, "{not json");
    expect(() => new OAuthStore(bad, [CLAUDE_REDIRECT])).toThrow(/Could not read the OAuth store/);
  });

  it("starts clean when the file does not exist yet", () => {
    const fresh = join(dir, "nested", "new-store.json");
    const store = new OAuthStore(fresh, [CLAUDE_REDIRECT]);
    expect(store.countClients()).toBe(0);
    store.close();
    expect(existsSync(fresh)).toBe(true);
  });
});

describe("provider grants", () => {
  function setup() {
    const config = testConfig();
    const store = new OAuthStore(":memory:", config.allowedRedirectUris);
    const provider = new LocalOAuthProvider(store, config);
    const client = store.registerClient({ redirect_uris: [CLAUDE_REDIRECT] });
    return { config, store, provider, client };
  }

  it("issues an access token bound to this resource as the audience", async () => {
    const { config, store, provider, client } = setup();
    const { challenge } = pkce();
    const code = store.createAuthCode({
      clientId: client.client_id,
      redirectUri: CLAUDE_REDIRECT,
      codeChallenge: challenge,
      scopes: [config.scope],
      resource: config.resource,
    });
    const tokens = await provider.exchangeAuthorizationCode(client, code, undefined, CLAUDE_REDIRECT);
    const info = await provider.verifyAccessToken(tokens.access_token);
    expect(info.resource?.href).toBe(`${config.resource}`);
    expect(info.scopes).toEqual([config.scope]);
    store.close();
  });

  it("treats an authorization code as single-use", async () => {
    const { config, store, provider, client } = setup();
    const { challenge } = pkce();
    const code = store.createAuthCode({
      clientId: client.client_id,
      redirectUri: CLAUDE_REDIRECT,
      codeChallenge: challenge,
      scopes: [config.scope],
      resource: config.resource,
    });
    await provider.exchangeAuthorizationCode(client, code, undefined, CLAUDE_REDIRECT);
    await expect(
      provider.exchangeAuthorizationCode(client, code, undefined, CLAUDE_REDIRECT)
    ).rejects.toThrow(/Invalid authorization code/);
    store.close();
  });

  it("rejects a code redeemed with a different redirect_uri", async () => {
    const { config, store, provider, client } = setup();
    const { challenge } = pkce();
    const code = store.createAuthCode({
      clientId: client.client_id,
      redirectUri: CLAUDE_REDIRECT,
      codeChallenge: challenge,
      scopes: [config.scope],
      resource: config.resource,
    });
    await expect(
      provider.exchangeAuthorizationCode(client, code, undefined, "https://claude.ai/other")
    ).rejects.toThrow(/redirect_uri does not match/);
    store.close();
  });

  it("rotates the refresh token and invalidates the presented one", async () => {
    const { config, store, provider, client } = setup();
    const { challenge } = pkce();
    const code = store.createAuthCode({
      clientId: client.client_id,
      redirectUri: CLAUDE_REDIRECT,
      codeChallenge: challenge,
      scopes: [config.scope],
      resource: config.resource,
    });
    const first = await provider.exchangeAuthorizationCode(client, code, undefined, CLAUDE_REDIRECT);
    const second = await provider.exchangeRefreshToken(client, first.refresh_token!);

    expect(second.refresh_token).toBeTruthy();
    expect(second.refresh_token).not.toBe(first.refresh_token);
    // OAuth 2.1 requires rotation for public clients: replaying the old one fails.
    await expect(provider.exchangeRefreshToken(client, first.refresh_token!)).rejects.toThrow(
      /Invalid or expired refresh token/
    );
    store.close();
  });

  it("refuses to mint a token for a resource it does not serve", async () => {
    const { store, provider, client } = setup();
    const res = { redirect: () => undefined } as never;
    await expect(
      provider.authorize(
        client,
        {
          codeChallenge: pkce().challenge,
          redirectUri: CLAUDE_REDIRECT,
          resource: new URL("https://someone-else.example.com/mcp"),
        },
        res
      )
    ).rejects.toThrow(/does not issue tokens for resource/);
    store.close();
  });

  it("rejects an access token whose audience is a different resource", async () => {
    const { config, store, provider, client } = setup();
    // Simulates a token minted by the same issuer for another resource server.
    const foreign = "foreign-token";
    store.putAccessToken(foreign, {
      clientId: client.client_id,
      scopes: [config.scope],
      resource: "https://someone-else.example.com/mcp",
      expiresAt: Math.floor(Date.now() / 1000) + 600,
    });
    await expect(provider.verifyAccessToken(foreign)).rejects.toThrow(
      /not issued for this resource server/
    );
    store.close();
  });

  it("rejects an expired access token", async () => {
    const { config, store, provider, client } = setup();
    store.putAccessToken("stale", {
      clientId: client.client_id,
      scopes: [config.scope],
      resource: config.resource,
      expiresAt: Math.floor(Date.now() / 1000) - 1,
    });
    await expect(provider.verifyAccessToken("stale")).rejects.toThrow(/expired/);
    store.close();
  });

  it("rejects an unknown access token", async () => {
    const { store, provider } = setup();
    await expect(provider.verifyAccessToken("nope")).rejects.toThrow(/Unknown or revoked/);
    store.close();
  });

  it("does not let a refresh widen the granted scope set", async () => {
    const { config, store, provider, client } = setup();
    const code = store.createAuthCode({
      clientId: client.client_id,
      redirectUri: CLAUDE_REDIRECT,
      codeChallenge: pkce().challenge,
      scopes: [config.scope],
      resource: config.resource,
    });
    const tokens = await provider.exchangeAuthorizationCode(client, code, undefined, CLAUDE_REDIRECT);
    await expect(
      provider.exchangeRefreshToken(client, tokens.refresh_token!, [config.scope, "admin"])
    ).rejects.toThrow(/exceeds the original grant/);
    store.close();
  });
});

describe("HTTP surface", () => {
  let server: Server;
  let base: string;
  let store: OAuthStore;
  const config = testConfig();

  beforeAll(async () => {
    store = new OAuthStore(":memory:", config.allowedRedirectUris);
    const auth = new TeamleaderAuth({ clientId: "", clientSecret: "", refreshToken: "" });
    const app = createApp({ config, store, client: new TeamleaderClient(auth) });
    await new Promise<void>((resolve) => {
      server = app.listen(0, "127.0.0.1", () => resolve());
    });
    const address = server.address();
    if (address === null || typeof address === "string") throw new Error("no port");
    base = `http://127.0.0.1:${address.port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    store.close();
  });

  it("serves /healthz without authentication", async () => {
    const res = await fetch(`${base}/healthz`);
    expect(res.status).toBe(200);
    expect((await res.json()).status).toBe("ok");
  });

  it("answers an unauthenticated MCP request with 401 and a resource_metadata pointer", async () => {
    const res = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    expect(res.status).toBe(401);
    const header = res.headers.get("www-authenticate") ?? "";
    expect(header).toMatch(/^Bearer /);
    expect(header).toContain(
      'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"'
    );
    // Claude uses the scope hint to decide what to request during authorization.
    expect(header).toContain(`scope="${config.scope}"`);
  });

  it("rejects a bearer token it never issued", async () => {
    const res = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer made-up-token",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    expect(res.status).toBe(401);
  });

  it("serves protected resource metadata at both the sub-path and the root", async () => {
    for (const path of [
      "/.well-known/oauth-protected-resource/mcp",
      "/.well-known/oauth-protected-resource",
    ]) {
      const res = await fetch(`${base}${path}`);
      expect(res.status, path).toBe(200);
      expect((await res.json()).resource).toBe("https://mcp.example.com/mcp");
    }
  });

  it("serves authorization server metadata", async () => {
    const res = await fetch(`${base}/.well-known/oauth-authorization-server`);
    expect(res.status).toBe(200);
    const meta = await res.json();
    expect(meta.issuer).toBe("https://mcp.example.com");
    expect(meta.code_challenge_methods_supported).toEqual(["S256"]);
  });

  it("registers a client via DCR and rejects a foreign redirect_uri", async () => {
    const ok = await fetch(`${base}/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "Claude",
        redirect_uris: [CLAUDE_REDIRECT],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      }),
    });
    expect(ok.status).toBe(201);
    expect((await ok.json()).client_id).toBeTruthy();

    const bad = await fetch(`${base}/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        client_name: "Evil",
        redirect_uris: ["https://evil.example.com/cb"],
        token_endpoint_auth_method: "none",
      }),
    });
    expect(bad.status).toBe(400);
    expect((await bad.json()).error).toBe("invalid_client_metadata");
  });

  it("answers 401 invalid_client for a token request from an unknown client", async () => {
    // Claude re-registers after a 401 here; a 400 would be terminal, so this is
    // what lets a connector recover from a deleted client record.
    const res = await fetch(`${base}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: "deleted-client-id",
        refresh_token: "whatever",
      }).toString(),
    });
    expect(res.status).toBe(401);
    expect((await res.json()).error).toBe("invalid_client");
  });

  it("rejects a non-S256 code challenge at the authorization endpoint", async () => {
    const client = store.registerClient({ redirect_uris: [CLAUDE_REDIRECT] });
    const params = new URLSearchParams({
      response_type: "code",
      client_id: client.client_id,
      redirect_uri: CLAUDE_REDIRECT,
      code_challenge: "plain-challenge",
      code_challenge_method: "plain",
      resource: config.resource,
    });
    const res = await fetch(`${base}/authorize?${params}`, { redirect: "manual" });
    // Rejected post-validation, so the error is delivered to the redirect URI.
    expect(res.status).toBe(302);
    const location = new URL(res.headers.get("location")!);
    expect(location.origin + location.pathname).toBe(CLAUDE_REDIRECT);
    expect(location.searchParams.get("error")).toBe("invalid_request");
  });

  it("rejects an authorization request with an unregistered redirect_uri", async () => {
    const client = store.registerClient({ redirect_uris: [CLAUDE_REDIRECT] });
    const params = new URLSearchParams({
      response_type: "code",
      client_id: client.client_id,
      redirect_uri: "https://evil.example.com/cb",
      code_challenge: pkce().challenge,
      code_challenge_method: "S256",
    });
    const res = await fetch(`${base}/authorize?${params}`, { redirect: "manual" });
    expect(res.status).toBe(400);
  });

  it("sends a valid authorization request to the consent page", async () => {
    const client = store.registerClient({ redirect_uris: [CLAUDE_REDIRECT] });
    const params = new URLSearchParams({
      response_type: "code",
      client_id: client.client_id,
      redirect_uri: CLAUDE_REDIRECT,
      code_challenge: pkce().challenge,
      code_challenge_method: "S256",
      scope: config.scope,
      state: "xyz",
      resource: config.resource,
    });
    const res = await fetch(`${base}/authorize?${params}`, { redirect: "manual" });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toMatch(/^\/consent\?rid=/);
  });

  it("only accepts POST on the MCP endpoint", async () => {
    for (const method of ["GET", "DELETE"]) {
      const res = await fetch(`${base}/mcp`, { method });
      expect(res.status, method).toBe(405);
      expect(res.headers.get("allow")).toBe("POST");
    }
  });

  it("completes the full authorization code flow with PKCE", async () => {
    const client = store.registerClient({ redirect_uris: [CLAUDE_REDIRECT] });
    const { verifier, challenge } = pkce();

    // 1. Authorization request -> consent page.
    const authParams = new URLSearchParams({
      response_type: "code",
      client_id: client.client_id,
      redirect_uri: CLAUDE_REDIRECT,
      code_challenge: challenge,
      code_challenge_method: "S256",
      scope: config.scope,
      state: "state-123",
      resource: config.resource,
    });
    const authRes = await fetch(`${base}/authorize?${authParams}`, { redirect: "manual" });
    const rid = new URL(authRes.headers.get("location")!, base).searchParams.get("rid")!;

    // 2. Wrong password must not hand out a code.
    const wrong = await fetch(`${base}/consent`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ rid, password: "nope" }).toString(),
      redirect: "manual",
    });
    expect(wrong.status).toBe(401);

    // 3. Correct password redirects back with code, state and iss.
    const consent = await fetch(`${base}/consent`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ rid, password: PASSWORD }).toString(),
      redirect: "manual",
    });
    expect(consent.status).toBe(302);
    const callback = new URL(consent.headers.get("location")!);
    expect(callback.origin + callback.pathname).toBe(CLAUDE_REDIRECT);
    expect(callback.searchParams.get("state")).toBe("state-123");
    expect(callback.searchParams.get("iss")).toBe(config.baseUrl);
    const code = callback.searchParams.get("code")!;
    expect(code).toBeTruthy();

    // 4. A wrong PKCE verifier is refused.
    const badPkce = await fetch(`${base}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: client.client_id,
        code,
        code_verifier: randomBytes(32).toString("base64url"),
        redirect_uri: CLAUDE_REDIRECT,
      }).toString(),
    });
    expect(badPkce.status).toBe(400);
    expect((await badPkce.json()).error).toBe("invalid_grant");

    // 5. The correct verifier yields tokens.
    const tokenRes = await fetch(`${base}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: client.client_id,
        code,
        code_verifier: verifier,
        redirect_uri: CLAUDE_REDIRECT,
        resource: config.resource,
      }).toString(),
    });
    expect(tokenRes.status).toBe(200);
    const tokens = await tokenRes.json();
    expect(tokens.token_type).toBe("Bearer");
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.refresh_token).toBeTruthy();

    // 6. The access token gets through to the MCP layer and lists tools.
    const mcpRes = await fetch(`${base}/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${tokens.access_token}`,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "test", version: "0" },
        },
      }),
    });
    expect(mcpRes.status).toBe(200);
    const initialized = await mcpRes.json();
    expect(initialized.result.serverInfo.name).toBe("teamleader");
  });
});
