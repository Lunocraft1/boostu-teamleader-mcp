/**
 * OAuth 2.1 authorization server for this MCP endpoint.
 *
 * Implements the SDK's OAuthServerProvider so the SDK's tested /token and
 * /register handlers can be reused. Everything user-facing (the consent page)
 * lives in consent.ts; `authorize()` only parks the validated request and
 * redirects there.
 *
 * Tokens are bound to one endpoint via their audience. That is the mechanism
 * that keeps a token issued for the read-only briefing endpoint from being
 * usable against the writable one.
 */

import type { Response } from "express";
import type {
  OAuthClientInformationFull,
  OAuthTokenRevocationRequest,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import type {
  AuthorizationParams,
  OAuthServerProvider,
} from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import {
  InvalidGrantError,
  InvalidTargetError,
  InvalidTokenError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import {
  canonicalizeResource,
  endpointForResource,
  type HttpConfig,
  type McpEndpointConfig,
} from "./config.js";
import { OAuthStore, randomToken } from "./store.js";
import { OFFLINE_ACCESS } from "./metadata.js";

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

export class LocalOAuthProvider implements OAuthServerProvider {
  constructor(
    private readonly store: OAuthStore,
    private readonly config: HttpConfig
  ) {}

  get clientsStore() {
    return this.store.clients;
  }

  /**
   * Resolves which endpoint a grant is for.
   *
   * A client that asks for a resource we do not serve gets `invalid_target`
   * rather than a token that would fail validation later. With no resource at
   * all — a client that predates RFC 8707 — the writable endpoint is assumed,
   * since that is the URL a person enters by hand.
   */
  private resolveEndpoint(requested?: URL): McpEndpointConfig {
    if (!requested) return this.config.work;
    const endpoint = endpointForResource(this.config, requested.href);
    if (!endpoint) {
      throw new InvalidTargetError(
        `This server does not issue tokens for resource ` +
          `"${canonicalizeResource(requested.href)}".`
      );
    }
    return endpoint;
  }

  /**
   * The scopes a grant actually receives.
   *
   * Always includes the endpoint's own scope, so the token works where it was
   * requested, plus offline_access when asked for (Claude appends it to obtain
   * a refresh token). Nothing else is granted, whatever was requested.
   */
  private grantedScopes(endpoint: McpEndpointConfig, requested?: string[]): string[] {
    const scopes = [endpoint.scope];
    if (requested?.includes(OFFLINE_ACCESS)) scopes.push(OFFLINE_ACCESS);
    return scopes;
  }

  // ── Authorization endpoint ────────────────────────────────────────────────

  /**
   * Called by the SDK's authorization handler after it has validated
   * client_id, an exactly-matching redirect_uri, response_type=code and
   * code_challenge_method=S256. We persist the request and hand over to the
   * consent page, which is what actually authenticates the user.
   */
  async authorize(
    client: OAuthClientInformationFull,
    params: AuthorizationParams,
    res: Response
  ): Promise<void> {
    const endpoint = this.resolveEndpoint(params.resource);
    const requestId = this.store.createPendingAuth({
      clientId: client.client_id,
      redirectUri: params.redirectUri,
      codeChallenge: params.codeChallenge,
      state: params.state,
      scopes: this.grantedScopes(endpoint, params.scopes),
      resource: endpoint.resource,
    });
    res.redirect(302, `/consent?rid=${encodeURIComponent(requestId)}`);
  }

  // ── Token endpoint ────────────────────────────────────────────────────────

  async challengeForAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string
  ): Promise<string> {
    const record = this.store.getAuthCode(authorizationCode);
    if (!record || record.clientId !== client.client_id) {
      throw new InvalidGrantError("Invalid authorization code.");
    }
    if (record.expiresAt < nowSec()) {
      throw new InvalidGrantError("Authorization code has expired.");
    }
    return record.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL
  ): Promise<OAuthTokens> {
    // Single use: the code is gone whether or not the rest validates.
    const record = this.store.consumeAuthCode(authorizationCode);
    if (!record || record.clientId !== client.client_id) {
      throw new InvalidGrantError("Invalid authorization code.");
    }
    if (record.expiresAt < nowSec()) {
      throw new InvalidGrantError("Authorization code has expired.");
    }
    if (redirectUri !== undefined && redirectUri !== record.redirectUri) {
      throw new InvalidGrantError("redirect_uri does not match the authorization request.");
    }

    const granted = record.resource ?? this.config.work.resource;
    if (resource && canonicalizeResource(resource.href) !== granted) {
      throw new InvalidTargetError("resource does not match the authorization request.");
    }

    return this.issueTokens(client.client_id, record.scopes, granted, record.username);
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL
  ): Promise<OAuthTokens> {
    // Rotation: the presented token is consumed here and replaced below.
    const record = this.store.consumeRefreshToken(refreshToken);
    if (!record || record.clientId !== client.client_id) {
      throw new InvalidGrantError("Invalid or expired refresh token.");
    }
    if (resource && canonicalizeResource(resource.href) !== record.resource) {
      throw new InvalidTargetError("resource does not match the original grant.");
    }
    // A refresh may narrow the scope set but never widen it.
    const granted = scopes?.length
      ? scopes.filter((scope) => record.scopes.includes(scope))
      : record.scopes;
    if (scopes?.length && granted.length !== scopes.length) {
      throw new InvalidGrantError("Requested scope exceeds the original grant.");
    }
    return this.issueTokens(client.client_id, granted, record.resource, record.username);
  }

  private issueTokens(
    clientId: string,
    scopes: string[],
    resource: string,
    username?: string
  ): OAuthTokens {
    const accessToken = randomToken();
    const refreshToken = randomToken();
    const accessExpiresAt = nowSec() + this.config.accessTokenTtlSec;
    const refreshExpiresAt =
      this.config.refreshTokenTtlSec > 0 ? nowSec() + this.config.refreshTokenTtlSec : 0;

    this.store.putAccessToken(accessToken, {
      clientId,
      scopes,
      resource,
      username,
      expiresAt: accessExpiresAt,
    });
    this.store.putRefreshToken(refreshToken, {
      clientId,
      scopes,
      resource,
      username,
      expiresAt: refreshExpiresAt,
    });

    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: this.config.accessTokenTtlSec,
      refresh_token: refreshToken,
      scope: scopes.join(" "),
    };
  }

  // ── Resource server ───────────────────────────────────────────────────────

  /**
   * Validates a bearer token presented at an MCP endpoint.
   *
   * The audience check is done here on purpose: the SDK's requireBearerAuth
   * middleware verifies scopes and expiry but never compares AuthInfo.resource
   * against anything, so a token minted for another resource would otherwise be
   * accepted. This rejects an audience this server never issues; matching the
   * token to the *specific* endpoint it was presented to happens in
   * requireAudience, which is the check that separates the two endpoints.
   */
  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const record = this.store.getAccessToken(token);
    if (!record) {
      throw new InvalidTokenError("Unknown or revoked access token.");
    }
    if (record.expiresAt <= nowSec()) {
      this.store.deleteAccessToken(token);
      throw new InvalidTokenError("Access token has expired.");
    }
    if (!this.config.allowedAudiences.includes(canonicalizeResource(record.resource))) {
      throw new InvalidTokenError("Access token was not issued for this resource server.");
    }
    return {
      token,
      clientId: record.clientId,
      scopes: record.scopes,
      expiresAt: record.expiresAt,
      resource: new URL(record.resource),
      extra: record.username ? { sub: record.username } : undefined,
    };
  }

  async revokeToken(
    _client: OAuthClientInformationFull,
    request: OAuthTokenRevocationRequest
  ): Promise<void> {
    // RFC 7009: revoking an already-invalid token is not an error.
    this.store.deleteAccessToken(request.token);
    this.store.deleteRefreshToken(request.token);
  }
}
