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
import { UserStore } from "../src/http/users.js";
import { BRIEFING_TOOLS, createBriefingServer } from "../src/http/readOnly.js";
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

function testUsers(password = PASSWORD): UserStore {
  return new UserStore([{ username: "malte", passwordHash: hashPassword(password) }]);
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
    expect(config.work.resource).toBe("https://mcp.example.com/mcp");
    expect(config.briefing.resource).toBe("https://mcp.example.com/mcp/briefing");
    // Exactly the two endpoint resources: a wider audience (the bare origin,
    // say) would be accepted at both endpoints and defeat the separation.
    expect(config.allowedAudiences).toEqual([
      "https://mcp.example.com/mcp",
      "https://mcp.example.com/mcp/briefing",
    ]);
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
    expect(protectedResourceMetadata(config, config.work).scopes_supported).not.toContain("offline_access");
  });

  it("names this server as the resource and itself as the authorization server", () => {
    const prm = protectedResourceMetadata(config, config.work);
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

describe("accounts", () => {
  const dir = mkdtempSync(join(tmpdir(), "tl-mcp-users-"));
  const file = join(dir, "users.json");
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("accepts the password without a name while there is one account", () => {
    const users = new UserStore([{ username: "malte", passwordHash: hashPassword(PASSWORD) }]);
    expect(users.isSingleUser).toBe(true);
    expect(users.verify(undefined, PASSWORD)).toBe("malte");
    expect(users.verify("malte", PASSWORD)).toBe("malte");
    expect(users.verify(undefined, "wrong")).toBeUndefined();
  });

  it("requires the name once a second account exists, with no code change", () => {
    const users = new UserStore([
      { username: "malte", passwordHash: hashPassword(PASSWORD) },
      { username: "kollege", passwordHash: hashPassword("zweites-passwort") },
    ]);
    expect(users.isSingleUser).toBe(false);
    // Ambiguous without a name, so it must not authenticate anyone.
    expect(users.verify(undefined, PASSWORD)).toBeUndefined();
    expect(users.verify("malte", PASSWORD)).toBe("malte");
    expect(users.verify("kollege", "zweites-passwort")).toBe("kollege");
    // No credential sharing between accounts.
    expect(users.verify("kollege", PASSWORD)).toBeUndefined();
    expect(users.verify("unbekannt", PASSWORD)).toBeUndefined();
  });

  it("stores accounts in a file so a second one is a config change", () => {
    const store = UserStore.initFile(file);
    store.addUser("malte", PASSWORD);
    store.addUser("kollege", "zweites-passwort");

    const reloaded = UserStore.load({ MCP_USERS_FILE: file } as NodeJS.ProcessEnv);
    expect(reloaded.usernames().sort()).toEqual(["kollege", "malte"]);
    expect(reloaded.verify("kollege", "zweites-passwort")).toBe("kollege");
  });

  it("changes and removes accounts, but never the last one", () => {
    const store = UserStore.load({ MCP_USERS_FILE: file } as NodeJS.ProcessEnv);
    store.setPassword("kollege", "neues-passwort");
    expect(store.verify("kollege", "neues-passwort")).toBe("kollege");

    store.removeUser("kollege");
    expect(store.usernames()).toEqual(["malte"]);
    expect(() => store.removeUser("malte")).toThrow(/last account/);
    expect(() => store.removeUser("niemand")).toThrow(/No such user/);
  });

  it("falls back to the single-hash environment variable", () => {
    const users = UserStore.load({
      MCP_CONSENT_PASSWORD_HASH: hashPassword(PASSWORD),
    } as NodeJS.ProcessEnv);
    expect(users.usernames()).toEqual(["admin"]);
    expect(users.verify(undefined, PASSWORD)).toBe("admin");
  });

  it("refuses to start with no login configured", () => {
    expect(() => UserStore.load({} as NodeJS.ProcessEnv)).toThrow(/No login configured/);
  });
});

describe("read-only briefing server", () => {
  const auth = new TeamleaderAuth({ clientId: "", clientSecret: "", refreshToken: "" });
  const client = new TeamleaderClient(auth);

  it("registers only non-mutating tools", () => {
    const { registered, skipped } = createBriefingServer(client);
    expect(registered.length).toBeGreaterThan(0);
    expect(skipped.length).toBeGreaterThan(0);
    for (const name of registered) expect(BRIEFING_TOOLS.has(name)).toBe(true);
  });

  it("excludes every write tool by name", () => {
    const { registered } = createBriefingServer(client);
    const forbidden = /_(create|update|delete|close|reopen|duplicate|assign|unassign|add|remove|link|unlink|complete)(_|$)/;
    const writeTools = registered.filter((name) => forbidden.test(name));
    expect(writeTools).toEqual([]);
  });

  it("drops the write tools the interactive server keeps", () => {
    const { skipped } = createBriefingServer(client);
    // Spot-check the ones that would be visible to a customer if they ran.
    expect(skipped).toContain("teamleader_create_event");
    expect(skipped).toContain("teamleader_create_task");
    expect(skipped).toContain("teamleader_create_company");
    expect(skipped).toContain("teamleader_update_deal");
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
      scopes: [config.work.scope],
      resource: config.work.resource,
    });
    const tokens = await provider.exchangeAuthorizationCode(client, code, undefined, CLAUDE_REDIRECT);
    const info = await provider.verifyAccessToken(tokens.access_token);
    expect(info.resource?.href).toBe(`${config.work.resource}`);
    expect(info.scopes).toEqual([config.work.scope]);
    store.close();
  });

  it("treats an authorization code as single-use", async () => {
    const { config, store, provider, client } = setup();
    const { challenge } = pkce();
    const code = store.createAuthCode({
      clientId: client.client_id,
      redirectUri: CLAUDE_REDIRECT,
      codeChallenge: challenge,
      scopes: [config.work.scope],
      resource: config.work.resource,
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
      scopes: [config.work.scope],
      resource: config.work.resource,
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
      scopes: [config.work.scope],
      resource: config.work.resource,
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
      scopes: [config.work.scope],
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
      scopes: [config.work.scope],
      resource: config.work.resource,
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
      scopes: [config.work.scope],
      resource: config.work.resource,
    });
    const tokens = await provider.exchangeAuthorizationCode(client, code, undefined, CLAUDE_REDIRECT);
    await expect(
      provider.exchangeRefreshToken(client, tokens.refresh_token!, [config.work.scope, "admin"])
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
    const app = createApp({ config, store, users: testUsers(), client: new TeamleaderClient(auth) });
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
    expect(header).toContain(`scope="${config.work.scope}"`);
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
      resource: config.work.resource,
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
      scope: config.work.scope,
      state: "xyz",
      resource: config.work.resource,
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

  /** Runs the whole flow and returns an access token for one endpoint. */
  async function tokenFor(resource: string): Promise<string> {
    const client = store.registerClient({ redirect_uris: [CLAUDE_REDIRECT] });
    const { verifier, challenge } = pkce();
    const authRes = await fetch(
      `${base}/authorize?` +
        new URLSearchParams({
          response_type: "code",
          client_id: client.client_id,
          redirect_uri: CLAUDE_REDIRECT,
          code_challenge: challenge,
          code_challenge_method: "S256",
          resource,
        }),
      { redirect: "manual" }
    );
    const rid = new URL(authRes.headers.get("location")!, base).searchParams.get("rid")!;
    const consent = await fetch(`${base}/consent`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ rid, password: PASSWORD }).toString(),
      redirect: "manual",
    });
    const code = new URL(consent.headers.get("location")!).searchParams.get("code")!;
    const tokenRes = await fetch(`${base}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: client.client_id,
        code,
        code_verifier: verifier,
        redirect_uri: CLAUDE_REDIRECT,
        resource,
      }).toString(),
    });
    return (await tokenRes.json()).access_token as string;
  }

  async function rpc(path: string, token: string, body: unknown): Promise<Response> {
    return fetch(`${base}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(body),
    });
  }

  it("keeps the two endpoints apart: a token works only where it was issued", async () => {
    const workToken = await tokenFor(config.work.resource);
    const briefingToken = await tokenFor(config.briefing.resource);
    const list = { jsonrpc: "2.0", id: 1, method: "tools/list" };

    // Each token works on its own endpoint ...
    expect((await rpc(config.work.path, workToken, list)).status).toBe(200);
    expect((await rpc(config.briefing.path, briefingToken, list)).status).toBe(200);

    // ... and nowhere else. This is the guarantee that the unattended briefing
    // cannot reach the writable endpoint.
    const crossed = await rpc(config.work.path, briefingToken, list);
    expect(crossed.status).toBe(401);
    expect(crossed.headers.get("www-authenticate")).toContain('error="invalid_token"');

    expect((await rpc(config.briefing.path, workToken, list)).status).toBe(401);
  });

  it("serves no write tools on the briefing endpoint", async () => {
    const token = await tokenFor(config.briefing.resource);
    const res = await rpc(config.briefing.path, token, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
    });
    const names: string[] = (await res.json()).result.tools.map((t: { name: string }) => t.name);
    expect(names.length).toBeGreaterThan(0);
    expect(names).toContain("teamleader_list_events");
    expect(names).toContain("teamleader_users_list");
    expect(names).not.toContain("teamleader_create_event");
    expect(names).not.toContain("teamleader_create_task");
    for (const name of names) expect(BRIEFING_TOOLS.has(name)).toBe(true);
  });

  it("serves write tools on the interactive endpoint", async () => {
    const token = await tokenFor(config.work.resource);
    const res = await rpc(config.work.path, token, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
    });
    const names: string[] = (await res.json()).result.tools.map((t: { name: string }) => t.name);
    expect(names).toContain("teamleader_create_event");
    expect(names.length).toBeGreaterThan(BRIEFING_TOOLS.size);
  });

  it("refuses a briefing tool call that does not exist there", async () => {
    const token = await tokenFor(config.briefing.resource);
    const res = await rpc(config.briefing.path, token, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "teamleader_create_event", arguments: {} },
    });
    // Reached the MCP layer, which has no such tool registered.
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.error ?? body.result?.isError).toBeTruthy();
  });

  it("serves protected resource metadata for the briefing endpoint", async () => {
    const res = await fetch(`${base}/.well-known/oauth-protected-resource/mcp/briefing`);
    expect(res.status).toBe(200);
    const prm = await res.json();
    expect(prm.resource).toBe("https://mcp.example.com/mcp/briefing");
    expect(prm.scopes_supported).toEqual([config.briefing.scope]);
  });

  it("challenges the briefing endpoint with its own scope and metadata URL", async () => {
    const res = await fetch(`${base}${config.briefing.path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    expect(res.status).toBe(401);
    const header = res.headers.get("www-authenticate") ?? "";
    expect(header).toContain(`scope="${config.briefing.scope}"`);
    expect(header).toContain(
      'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp/briefing"'
    );
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
      scope: config.work.scope,
      state: "state-123",
      resource: config.work.resource,
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
        resource: config.work.resource,
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
