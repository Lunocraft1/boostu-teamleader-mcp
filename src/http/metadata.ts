/**
 * OAuth discovery documents.
 *
 * Written by hand rather than via the SDK's mcpAuthRouter for two reasons:
 *
 *  1. The protected resource metadata has to be served at BOTH
 *     /.well-known/oauth-protected-resource/<mcp-path> and at the root.
 *     Clients try the path-specific form first and fall back to the root; the
 *     SDK only mounts the path-specific one.
 *  2. `offline_access` must appear in the authorization server's
 *     scopes_supported (that is how Claude knows to ask for a refresh token)
 *     but must NOT appear in the protected resource metadata, which the MCP
 *     spec reserves for scopes the resource itself requires.
 */

import { Router, type Request, type Response } from "express";
import cors from "cors";
import type { HttpConfig } from "./config.js";

/** Scope Claude appends when the AS advertises it, to obtain a refresh token. */
export const OFFLINE_ACCESS = "offline_access";

export function authorizationServerMetadata(config: HttpConfig): Record<string, unknown> {
  return {
    issuer: config.baseUrl,
    authorization_endpoint: `${config.baseUrl}/authorize`,
    token_endpoint: `${config.baseUrl}/token`,
    registration_endpoint: `${config.baseUrl}/register`,
    revocation_endpoint: `${config.baseUrl}/revoke`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    // "none" is required for public clients; Claude registers as one via DCR.
    token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
    revocation_endpoint_auth_methods_supported: ["client_secret_post", "none"],
    // PKCE is mandatory and S256-only. Clients refuse to proceed if this is absent.
    code_challenge_methods_supported: ["S256"],
    scopes_supported: [config.scope, OFFLINE_ACCESS],
    // RFC 9207 — we always include `iss` on the authorization response.
    authorization_response_iss_parameter_supported: true,
    service_documentation: "https://github.com/boostuagency/boostu-teamleader-mcp",
  };
}

export function protectedResourceMetadata(config: HttpConfig): Record<string, unknown> {
  return {
    resource: config.resource,
    authorization_servers: [config.baseUrl],
    scopes_supported: [config.scope],
    bearer_methods_supported: ["header"],
    resource_name: "Teamleader Focus",
    resource_documentation: "https://github.com/boostuagency/boostu-teamleader-mcp",
  };
}

export function metadataRouter(config: HttpConfig): Router {
  const router = Router();
  // Discovery is fetched by browser-based clients too.
  router.use(cors());

  const send = (payload: Record<string, unknown>) => (_req: Request, res: Response) => {
    res.setHeader("Cache-Control", "public, max-age=300");
    res.status(200).json(payload);
  };

  router.get("/.well-known/oauth-authorization-server", send(authorizationServerMetadata(config)));

  const prm = protectedResourceMetadata(config);
  // Path-specific form (tried first when the resource URL has a path) …
  router.get(`/.well-known/oauth-protected-resource${config.mcpPath}`, send(prm));
  // … and the root form clients fall back to.
  router.get("/.well-known/oauth-protected-resource", send(prm));

  return router;
}

/**
 * The URL advertised in the `resource_metadata` parameter of the
 * WWW-Authenticate challenge on 401 responses.
 */
export function resourceMetadataUrl(config: HttpConfig): string {
  return `${config.baseUrl}/.well-known/oauth-protected-resource${config.mcpPath}`;
}
