/**
 * Configuration for the remote (HTTP) entry point.
 *
 * Everything the OAuth layer advertises about itself is derived from
 * PUBLIC_BASE_URL. That value becomes the issuer, the base of every metadata
 * document, and — together with MCP_PATH — the resource identifier that ends up
 * in the audience of every access token. It therefore has to match the URL that
 * is entered in claude.ai exactly; see docs/REMOTE.md.
 */

export interface HttpConfig {
  /** Port the Node process listens on (nginx proxies to it). */
  port: number;
  /** Interface to bind. Defaults to loopback because nginx terminates TLS. */
  host: string;
  /** Issuer / base URL, without trailing slash, e.g. https://mcp.example.com */
  baseUrl: string;
  /** Path of the MCP endpoint, e.g. /mcp */
  mcpPath: string;
  /** RFC 8707 resource identifier of this server, e.g. https://mcp.example.com/mcp */
  resource: string;
  /**
   * Audience values accepted when validating an access token. Contains the
   * canonical resource and the bare origin, because clients differ in how
   * specific a `resource` value they send.
   */
  allowedAudiences: string[];
  /** SQLite file holding registered clients, codes and tokens. */
  dbPath: string;
  /** scrypt hash of the consent password (see `npm run hash-password`). */
  consentPasswordHash: string;
  /** Exact redirect URIs accepted at dynamic client registration. No wildcards. */
  allowedRedirectUris: string[];
  /** Access token lifetime in seconds. */
  accessTokenTtlSec: number;
  /** Refresh token lifetime in seconds; 0 means it does not expire. */
  refreshTokenTtlSec: number;
  /** The single scope this resource server requires. */
  scope: string;
  /** Value for Express' "trust proxy" setting. */
  trustProxy: number | boolean;
  /** Origins accepted on the MCP endpoint; empty means any. */
  allowedOrigins: string[];
}

const CLAUDE_REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback";

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (!value || !value.trim()) {
    throw new Error(`${name} is required for the HTTP server. See docs/REMOTE.md.`);
  }
  return value.trim();
}

function intEnv(env: NodeJS.ProcessEnv, name: string, fallback: number): number {
  const raw = env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`${name} must be a non-negative integer, got "${raw}".`);
  }
  return parsed;
}

function listEnv(env: NodeJS.ProcessEnv, name: string, fallback: string[]): string[] {
  const raw = env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  return raw.split(",").map((s) => s.trim()).filter(Boolean);
}

/**
 * Normalises a resource identifier for comparison, per RFC 8707 §2 and the
 * guidance in Anthropic's connector docs: compare canonical forms rather than
 * byte-for-byte. `new URL` already lowercases scheme and host and drops a
 * default port; we additionally drop query, fragment and a trailing slash.
 */
export function canonicalizeResource(value: string): string {
  const url = new URL(value);
  url.search = "";
  url.hash = "";
  const path = url.pathname === "/" ? "" : url.pathname.replace(/\/$/, "");
  return `${url.protocol}//${url.host}${path}`;
}

export function loadHttpConfig(env: NodeJS.ProcessEnv = process.env): HttpConfig {
  const rawBase = required(env, "PUBLIC_BASE_URL");
  let base: URL;
  try {
    base = new URL(rawBase);
  } catch {
    throw new Error(`PUBLIC_BASE_URL is not a valid URL: "${rawBase}".`);
  }
  if (base.search || base.hash) {
    throw new Error("PUBLIC_BASE_URL must not contain a query string or fragment.");
  }
  const isLoopback = base.hostname === "localhost" || base.hostname === "127.0.0.1";
  if (base.protocol !== "https:" && !isLoopback) {
    throw new Error("PUBLIC_BASE_URL must use https (http is only allowed for localhost).");
  }
  const baseUrl = `${base.protocol}//${base.host}${base.pathname.replace(/\/$/, "")}`;

  const mcpPath = "/" + (env.MCP_PATH ?? "/mcp").trim().replace(/^\/+|\/+$/g, "");
  const resource = canonicalizeResource(`${baseUrl}${mcpPath}`);
  const origin = canonicalizeResource(baseUrl);

  return {
    port: intEnv(env, "PORT", 8787),
    host: env.HOST?.trim() || "127.0.0.1",
    baseUrl,
    mcpPath,
    resource,
    // A token minted for the bare origin is still a token for this server;
    // anything else is not and is rejected in verifyAccessToken.
    allowedAudiences: Array.from(new Set([resource, origin])),
    dbPath: env.OAUTH_DB_PATH?.trim() || "./data/oauth.sqlite",
    consentPasswordHash: required(env, "MCP_CONSENT_PASSWORD_HASH"),
    allowedRedirectUris: listEnv(env, "OAUTH_ALLOWED_REDIRECT_URIS", [CLAUDE_REDIRECT_URI]),
    accessTokenTtlSec: intEnv(env, "ACCESS_TOKEN_TTL", 3600),
    refreshTokenTtlSec: intEnv(env, "REFRESH_TOKEN_TTL", 0),
    scope: env.MCP_SCOPE?.trim() || "teamleader",
    trustProxy: intEnv(env, "TRUST_PROXY", 1),
    allowedOrigins: listEnv(env, "MCP_ALLOWED_ORIGINS", []),
  };
}
