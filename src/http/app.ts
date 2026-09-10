/**
 * Express application: MCP resource server + OAuth authorization server.
 *
 * Both roles live in one process, which is why the issuer and the resource
 * share a host. The MCP endpoint is stateless Streamable HTTP: a fresh
 * transport and McpServer per POST, no session table. That is what makes a
 * restart invisible to a connected client — there is no per-connection state
 * to lose, only the tokens, and those are in SQLite.
 */

import express, { type Express, type NextFunction, type Request, type Response } from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { authorizationHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/authorize.js";
import { tokenHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/token.js";
import { clientRegistrationHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/register.js";
import { revocationHandler } from "@modelcontextprotocol/sdk/server/auth/handlers/revoke.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import type { TeamleaderClient } from "../api/client.js";
import { createServer } from "../server.js";
import type { HttpConfig } from "./config.js";
import { metadataRouter, resourceMetadataUrl } from "./metadata.js";
import { consentRouter } from "./consent.js";
import { LocalOAuthProvider } from "./provider.js";
import { requestLogger } from "./logging.js";
import type { OAuthStore } from "./store.js";

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

export interface AppDeps {
  config: HttpConfig;
  store: OAuthStore;
  client: TeamleaderClient;
}

export function createApp({ config, store, client }: AppDeps): Express {
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
      resource: config.resource,
      issuer: config.baseUrl,
      registeredClients: store.countClients(),
      uptimeSeconds: Math.round(process.uptime()),
    });
  });

  // ── Discovery ─────────────────────────────────────────────────────────────
  app.use(metadataRouter(config));

  // ── Authorization server ──────────────────────────────────────────────────
  app.use("/authorize", authorizationHandler({ provider }));
  app.use("/consent", consentRouter(store, config));
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

  // ── MCP resource server ───────────────────────────────────────────────────
  const bearerAuth = requireBearerAuth({
    verifier: provider,
    requiredScopes: [config.scope],
    resourceMetadataUrl: resourceMetadataUrl(config),
  });

  app.post(
    config.mcpPath,
    originGuard(config),
    express.json({ limit: "4mb" }),
    bearerAuth,
    async (req: Request, res: Response) => {
      // Stateless: no session id, single JSON response instead of an SSE
      // stream. Nothing to resume, nothing to lose across a restart.
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      const server = createServer(client);
      res.on("close", () => {
        void transport.close();
        void server.close();
      });
      try {
        await server.connect(transport);
        await transport.handleRequest(req, res, req.body);
      } catch (error) {
        console.error("[mcp] request failed:", error);
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
  app.all(config.mcpPath, (_req: Request, res: Response) => {
    res.status(405).set("Allow", "POST").json({
      jsonrpc: "2.0",
      error: { code: -32600, message: "Only POST is supported on this endpoint." },
    });
  });

  app.use((_req: Request, res: Response) => {
    res.status(404).json({ error: "not_found" });
  });

  return app;
}
