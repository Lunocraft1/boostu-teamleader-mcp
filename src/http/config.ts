/**
 * Configuration for the remote (HTTP) entry point.
 *
 * Everything the OAuth layer advertises about itself is derived from
 * PUBLIC_BASE_URL. That value becomes the issuer, the base of every metadata
 * document, and — together with the endpoint paths — the resource identifiers
 * that end up in the audience of every access token. It therefore has to match
 * the URL entered in claude.ai exactly; see docs/REMOTE.md.
 */

/** One MCP endpoint: its own resource identifier, scope and tool set. */
export interface McpEndpointConfig {
  /** Stable key used in logs and startup output. */
  id: "work" | "briefing";
  /** Human-readable name for the consent screen and metadata. */
  name: string;
  /** Path below the base URL, e.g. /mcp */
  path: string;
  /** RFC 8707 resource identifier, e.g. https://mcp.example.com/mcp */
  resource: string;
  /** Scope a token must carry to use this endpoint. */
  scope: string;
  /** When true, only non-mutating tools are served. */
  readOnly: boolean;
}

export interface HttpConfig {
  /** Port the Node process listens on (nginx proxies to it). */
  port: number;
  /** Interface to bind. Defaults to loopback because nginx terminates TLS. */
  host: string;
  /** Issuer / base URL, without trailing slash, e.g. https://mcp.example.com */
  baseUrl: string;
  /** The read/write endpoint, used interactively. */
  work: McpEndpointConfig;
  /** The read-only endpoint, used by the unattended briefing. */
  briefing: McpEndpointConfig;
  /** Both of the above, in advertising order. */
  endpoints: McpEndpointConfig[];
  /**
   * Audience values this server issues tokens for — exactly the endpoint
   * resources, nothing wider. A token is additionally checked against the
   * specific endpoint it is presented to, which is what keeps a briefing
   * token from reaching the writable endpoint.
   */
  allowedAudiences: string[];
  /** Union of endpoint scopes, for authorization server metadata. */
  scopesSupported: string[];
  /** JSON file holding registered clients, codes and tokens. */
  dbPath: string;
  /** Exact redirect URIs accepted at dynamic client registration. No wildcards. */
  allowedRedirectUris: string[];
  /** Access token lifetime in seconds. */
  accessTokenTtlSec: number;
  /** Refresh token lifetime in seconds; 0 means it does not expire. */
  refreshTokenTtlSec: number;
  /** Value for Express' "trust proxy" setting. */
  trustProxy: number | boolean;
  /** Origins accepted on the MCP endpoints; empty means any. */
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

function normalisePath(raw: string): string {
  return "/" + raw.trim().replace(/^\/+|\/+$/g, "");
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

  const workPath = normalisePath(env.MCP_PATH ?? "/mcp");
  const briefingPath = normalisePath(env.MCP_BRIEFING_PATH ?? "/mcp/briefing");
  if (workPath === briefingPath) {
    throw new Error("MCP_PATH and MCP_BRIEFING_PATH must differ.");
  }

  const work: McpEndpointConfig = {
    id: "work",
    name: "Teamleader Focus",
    path: workPath,
    resource: canonicalizeResource(`${baseUrl}${workPath}`),
    scope: env.MCP_SCOPE?.trim() || "teamleader",
    readOnly: false,
  };
  const briefing: McpEndpointConfig = {
    id: "briefing",
    name: "Teamleader Focus (read-only briefing)",
    path: briefingPath,
    resource: canonicalizeResource(`${baseUrl}${briefingPath}`),
    scope: env.MCP_BRIEFING_SCOPE?.trim() || "teamleader.read",
    readOnly: true,
  };
  if (work.scope === briefing.scope) {
    throw new Error("MCP_SCOPE and MCP_BRIEFING_SCOPE must differ.");
  }

  const endpoints = [work, briefing];

  return {
    port: intEnv(env, "PORT", 8787),
    host: env.HOST?.trim() || "127.0.0.1",
    baseUrl,
    work,
    briefing,
    endpoints,
    allowedAudiences: endpoints.map((endpoint) => endpoint.resource),
    scopesSupported: Array.from(new Set(endpoints.map((endpoint) => endpoint.scope))),
    dbPath: env.OAUTH_DB_PATH?.trim() || "./data/oauth-store.json",
    allowedRedirectUris: listEnv(env, "OAUTH_ALLOWED_REDIRECT_URIS", [CLAUDE_REDIRECT_URI]),
    accessTokenTtlSec: intEnv(env, "ACCESS_TOKEN_TTL", 3600),
    refreshTokenTtlSec: intEnv(env, "REFRESH_TOKEN_TTL", 0),
    trustProxy: intEnv(env, "TRUST_PROXY", 1),
    allowedOrigins: listEnv(env, "MCP_ALLOWED_ORIGINS", []),
  };
}

/** Finds the endpoint a resource identifier belongs to, if any. */
export function endpointForResource(
  config: HttpConfig,
  resource: string
): McpEndpointConfig | undefined {
  const canonical = canonicalizeResource(resource);
  return config.endpoints.find((endpoint) => endpoint.resource === canonical);
}
