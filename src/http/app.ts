/**
 * Express application: MCP resource server + OAuth authorization server.
 *
 * Both roles live in one process, which is why the issuer and the resources
 * share a host. Two MCP endpoints are served from the same Teamleader
 * connection:
 *
 *   /mcp           read and write, for interactive use
 *   /mcp/briefing  read-only, for the unattended morning briefing
 *
 * They are separated by audience, not by convention: a token is minted for one
 * resource identifier and rejected at the other. The read-only endpoint also
 * physically lacks the write tools, so even a correctly scoped token cannot
 * change anything there.
 *
 * Each endpoint is stateless Streamable HTTP: a fresh transport and McpServer
 * per POST, no session table. That is what makes a restart invisible to a
 * connected client — there is no per-connection state to lose, only the
 * tokens, and those are on disk.
 */

import express, { type Express, type NextFunction, type Request, type Response } from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { authorizationHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/authorize.js";
import { tokenHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/token.js";
import { clientRegistrationHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/register.js";
import { revocationHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/revoke.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { TeamleaderClient } from "../api/client.js";
import { createServer } from "../server.js";
import { canonicalizeResource, type HttpConfig, type McpEndpointConfig } from "./config.js";
import { metadataRouter, resourceMetadataUrl } from "./metadata.js";
import { consentRouter } from "./consent.js";
import { LocalOAuthProvider } from "./provider.js";
import { requestLogger } from "./logging.js";
import { createBriefingServer } from "./readOnly.js";
import type { OAuthStore } from "./store.js";
import type { UserStore } from "./users.js";

/**
 * Answers 401 (not 400) for every failed client authentication at the token
 * endpoint.
 *
 * RFC 6749 §5.2 allows 401 for `invalid_client`, and Claude relies on it: after
 * a 401 it discards the stored client and re-registers via DCR, which is the
 * only way a connector recovers from a client record that no longer exists.
 * The SDK's built-in check answers 400, which Claude treats as terminal — so
 * this runs first and the SDK's own check becomes a no-op.
 */
function clientAuthGate(store: OAuthStore) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const body = req.body as Record<string, unknown> | undefined;
    const clientId = typeof body?.client_id === "string" ? body.client_id : undefined;
    const clientSecret = typeof body?.client_secret === "string" ? body.client_secret : undefined;

    const fail = (description: string): void => {
      res.status(401).setHeader("Cache-Control", "no-store");
      res.json({ error: "invalid_client", error_description: description });
    };

    if (!clientId) {
      // Let the SDK produce the canonical invalid_request response.
      next();
      return;
    }
    const client = await store.getClient(clientId);
    if (!client) {
      console.warn(`[auth] token request for unknown client ${clientId} -> 401 invalid_client`);
      fail("Unknown client. Register again via dynamic client registration.");
      return;
    }
    if (client.client_secret) {
      if (!clientSecret || clientSecret !== client.client_secret) {
        fail("Invalid client credentials.");
        return;
      }
      const expiresAt = client.client_secret_expires_at;
      if (expiresAt && expiresAt < Math.floor(Date.now() / 1000)) {
        fail("Client secret has expired. Register again.");
        return;
      }
    }
    next();
  };
}

/** Rejects a cross-origin browser caller; server-side clients send no Origin. */
function originGuard(config: HttpConfig) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const origin = req.headers.origin;
    if (!origin || config.allowedOrigins.length === 0) {
      next();
      return;
    }
    if (!config.allowedOrigins.includes(origin)) {
      res.status(403).json({
        jsonrpc: "2.0",
        error: { code: -32600, message: `Origin ${origin} is not allowed.` },
      });
      return;
    }
    next();
  };
}

/** Builds the `WWW-Authenticate` challenge for one endpoint. */
function challenge(
  config: HttpConfig,
  endpoint: McpEndpointConfig,
  error: string,
  description: string
): string {
  return (
    `Bearer error="${error}", ` +
    `error_description="${description}", ` +
    `scope="${endpoint.scope}", ` +
    `resource_metadata="${resourceMetadataUrl(config, endpoint)}"`
  );
}

/**
 * Answers the very first, tokenless request.
 *
 * This is the handshake Claude depends on, so the challenge is built here
 * rather than left to the SDK: it must carry the `scope` hint, which the SDK's
 * middleware only emits when it is configured with required scopes — and
 * configuring those would make it reject a wrong-audience token as a scope
 * problem before the audience is ever compared. See requireAudience.
 */
function challengeIfNoToken(config: HttpConfig, endpoint: McpEndpointConfig) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const header = req.headers.authorization;
    const looksLikeBearer = header && /^bearer\s+\S/i.test(header);
    if (looksLikeBearer) {
      next();
      return;
    }
    res
      .status(401)
      .set(
        "WWW-Authenticate",
        challenge(config, endpoint, "invalid_token", "Authentication required")
      )
      .json({ error: "invalid_token", error_description: "Authentication required." });
  };
}

/**
 * Requires the presented token to have been issued for *this* endpoint.
 *
 * Without this, a token for the read-only briefing endpoint would be accepted
 * at the writable one, because verifyAccessToken can only tell that the
 * audience is one this server issues — not which endpoint is being addressed.
 *
 * This runs before the scope check on purpose. A token minted for a different
 * resource is `invalid_token` (401), not `insufficient_scope` (403): the
 * latter invites the client to re-authorize for more permissions, which is
 * exactly the wrong answer when the real problem is that the token belongs to
 * another endpoint.
 */
function requireAudience(config: HttpConfig, endpoint: McpEndpointConfig) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const presented = req.auth?.resource?.href;
    if (presented && canonicalizeResource(presented) === endpoint.resource) {
      next();
      return;
    }
    console.warn(
      `[auth] token for "${presented ?? "(no audience)"}" rejected at ${endpoint.path} ` +
        `(expects "${endpoint.resource}")`
    );
    res
      .status(401)
      .set(
        "WWW-Authenticate",
        challenge(config, endpoint, "invalid_token", "Token was not issued for this endpoint")
      )
      .json({
        error: "invalid_token",
        error_description: "Token was not issued for this endpoint.",
      });
  };
}

/** Requires the endpoint's scope, once the audience is known to be right. */
function requireScope(config: HttpConfig, endpoint: McpEndpointConfig) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (req.auth?.scopes.includes(endpoint.scope)) {
      next();
      return;
    }
    res
      .status(403)
      .set(
        "WWW-Authenticate",
        challenge(config, endpoint, "insufficient_scope", "Missing scope for this endpoint")
      )
      .json({
        error: "insufficient_scope",
        error_description: `This endpoint requires the "${endpoint.scope}" scope.`,
      });
  };
}

export interface AppDeps {
  config: HttpConfig;
  store: OAuthStore;
  users: UserStore;
  client: TeamleaderClient;
}

export function createApp({ config, store, users, client }: AppDeps): Express {
  const app = express();
  // nginx terminates TLS; without this the rate limiters would key every
  // request to the proxy's address and req.ip would be useless in the log.
  app.set("trust proxy", config.trustProxy);
  app.disable("x-powered-by");
  app.use(requestLogger);

  const provider = new LocalOAuthProvider(store, config);

  // ── Health check (no auth, per the brief) ─────────────────────────────────
  app.get("/healthz", (_req: Request, res: Response) => {
    res.status(200).json({
      status: "ok",
      issuer: config.baseUrl,
      endpoints: config.endpoints.map((endpoint) => ({
        path: endpoint.path,
        resource: endpoint.resource,
        readOnly: endpoint.readOnly,
      })),
      accounts: users.count(),
      registeredClients: store.countClients(),
      uptimeSeconds: Math.round(process.uptime()),
    });
  });

  // ── Discovery ─────────────────────────────────────────────────────────────
  app.use(metadataRouter(config));

  // ── Authorization server ──────────────────────────────────────────────────
  app.use("/authorize", authorizationHandler({ provider }));
  app.use("/consent", consentRouter(store, config, users));
  app.use(
    "/register",
    clientRegistrationHandler({
      clientsStore: store.clients,
      // 0 = never expire. A secret that lapses after 30 days would break an
      // unattended connector for no gain: the client record is the credential.
      clientSecretExpirySeconds: 0,
    })
  );
  app.use("/token", express.urlencoded({ extended: false }), clientAuthGate(store));
  app.use("/token", tokenHandler({ provider }));
  app.use("/revoke", revocationHandler({ provider }));

  // ── MCP endpoints ─────────────────────────────────────────────────────────
  for (const endpoint of config.endpoints) {
    const buildServer = (): McpServer =>
      endpoint.readOnly ? createBriefingServer(client).server : createServer(client);

    app.post(
      endpoint.path,
      originGuard(config),
      express.json({ limit: "4mb" }),
      challengeIfNoToken(config, endpoint),
      // No requiredScopes here: the scope check has to come after the audience
      // check, so it is a separate step below.
      requireBearerAuth({
        verifier: provider,
        resourceMetadataUrl: resourceMetadataUrl(config, endpoint),
      }),
      requireAudience(config, endpoint),
      requireScope(config, endpoint),
      async (req: Request, res: Response) => {
        // Stateless: no session id, single JSON response instead of an SSE
        // stream. Nothing to resume, nothing to lose across a restart.
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: undefined,
          enableJsonResponse: true,
        });
        const server = buildServer();
        res.on("close", () => {
          void transport.close();
          void server.close();
        });
        try {
          await server.connect(transport);
          await transport.handleRequest(req, res, req.body);
        } catch (error) {
          console.error(`[mcp] request to ${endpoint.path} failed:`, error);
          if (!res.headersSent) {
            res.status(500).json({
              jsonrpc: "2.0",
              error: { code: -32603, message: "Internal error" },
              id: null,
            });
          }
        }
      }
    );

    // This build is stateless, so there is no standalone stream to open and no
    // session to delete.
    app.all(endpoint.path, (_req: Request, res: Response) => {
      res.status(405).set("Allow", "POST").json({
        jsonrpc: "2.0",
        error: { code: -32600, message: "Only POST is supported on this endpoint." },
      });
    });
  }

  app.use((_req: Request, res: Response) => {
    res.status(404).json({ error: "not_found" });
  });

  return app;
}
