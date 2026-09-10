#!/usr/bin/env node
/**
 * Remote entry point: serves this MCP server over Streamable HTTP with an
 * OAuth 2.1 authorization server in front, so it can be registered in
 * claude.ai as a custom connector.
 *
 * The stdio entry point (src/index.ts) is untouched; both share createServer().
 */

import { loadHttpConfig } from "./http/config.js";
import { createApp } from "./http/app.js";
import { OAuthStore } from "./http/store.js";
import { SerializedTeamleaderAuth, lockTokenStore } from "./http/teamleader.js";
import { TeamleaderClient } from "./api/client.js";

function getEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    // Mirrors the stdio entry point: the server still boots and answers
    // introspection without credentials, so a connector can be wired up and
    // debugged before the Teamleader side is finished. Tool calls fail with a
    // clear auth error until the variable is set.
    console.error(`[teamleader-mcp] ${name} is not set. Configure it before calling tools.`);
  }
  return value ?? "";
}

async function main(): Promise<void> {
  const config = loadHttpConfig();

  const releaseLock = process.env.TEAMLEADER_TOKEN_STORE
    ? lockTokenStore(process.env.TEAMLEADER_TOKEN_STORE)
    : () => {
        console.warn(
          "[teamleader-mcp] TEAMLEADER_TOKEN_STORE is not set. The rotating refresh token " +
            "will not survive a restart."
        );
      };

  const auth = new SerializedTeamleaderAuth({
    clientId: getEnv("TEAMLEADER_CLIENT_ID"),
    clientSecret: getEnv("TEAMLEADER_CLIENT_SECRET"),
    refreshToken: getEnv("TEAMLEADER_REFRESH_TOKEN"),
  });
  const client = new TeamleaderClient(auth);

  const store = new OAuthStore(config.dbPath, config.allowedRedirectUris);
  const app = createApp({ config, store, client });

  const server = app.listen(config.port, config.host, () => {
    console.log(`[teamleader-mcp] listening on http://${config.host}:${config.port}`);
    console.log(`[teamleader-mcp] MCP endpoint      ${config.resource}`);
    console.log(`[teamleader-mcp] issuer            ${config.baseUrl}`);
    console.log(`[teamleader-mcp] token store       ${process.env.TEAMLEADER_TOKEN_STORE ?? "(none)"}`);
    console.log(`[teamleader-mcp] oauth database    ${config.dbPath}`);
    console.log(`[teamleader-mcp] registered clients ${store.countClients()}`);
    console.log(`[teamleader-mcp] tool groups       ${process.env.TEAMLEADER_TOOLS ?? "(all)"}`);
  });

  let shuttingDown = false;
  const shutdown = (signal: string): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`[teamleader-mcp] ${signal} received, shutting down`);
    server.close(() => {
      store.close();
      releaseLock();
      process.exit(0);
    });
    // Do not hang forever on a stuck connection.
    setTimeout(() => {
      store.close();
      releaseLock();
      process.exit(0);
    }, 10_000).unref();
  };

  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

main().catch((error) => {
  console.error("Fatal error:", error instanceof Error ? error.message : error);
  process.exit(1);
});
