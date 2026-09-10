/**
 * Persistent state for the authorization server.
 *
 * Registered clients MUST outlive a restart: Claude registers once via dynamic
 * client registration and then keeps using that client_id. If the record is
 * gone after a restart, the connector is dead until the user re-authorizes.
 *
 * Codes and tokens live here too, so an access token stays valid across a
 * deploy. Only hashes are stored — a database copy does not yield usable
 * credentials.
 */

import Database from "better-sqlite3";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import { InvalidClientMetadataError } from "@modelcontextprotocol/sdk/server/auth/errors.js";

export function randomToken(): string {
  return randomBytes(32).toString("base64url");
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

export interface PendingAuthRecord {
  requestId: string;
  clientId: string;
  clientName: string;
  redirectUri: string;
  codeChallenge: string;
  state?: string;
  scopes: string[];
  resource?: string;
  expiresAt: number;
}

export interface AuthCodeRecord {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  resource?: string;
  expiresAt: number;
}

export interface TokenRecord {
  clientId: string;
  scopes: string[];
  resource: string;
  expiresAt: number;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS clients (
  client_id   TEXT PRIMARY KEY,
  created_at  INTEGER NOT NULL,
  metadata    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_auth (
  request_id     TEXT PRIMARY KEY,
  client_id      TEXT NOT NULL,
  redirect_uri   TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  state          TEXT,
  scopes         TEXT NOT NULL,
  resource       TEXT,
  expires_at     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_codes (
  code_hash      TEXT PRIMARY KEY,
  client_id      TEXT NOT NULL,
  redirect_uri   TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  scopes         TEXT NOT NULL,
  resource       TEXT,
  expires_at     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS access_tokens (
  token_hash TEXT PRIMARY KEY,
  client_id  TEXT NOT NULL,
  scopes     TEXT NOT NULL,
  resource   TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  client_id  TEXT NOT NULL,
  scopes     TEXT NOT NULL,
  resource   TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
`;

export class OAuthStore {
  private db: Database.Database;
  readonly clients: OAuthRegisteredClientsStore;

  /**
   * @param dbPath  SQLite file path, or ":memory:" for tests.
   * @param allowedRedirectUris  Exact-match allowlist enforced at registration.
   */
  constructor(dbPath: string, private allowedRedirectUris: string[]) {
    if (dbPath !== ":memory:") mkdirSync(dirname(dbPath), { recursive: true });
    this.db = new Database(dbPath);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    this.db.exec(SCHEMA);
    this.purgeExpired();

    this.clients = {
      getClient: (clientId) => this.getClient(clientId),
      registerClient: (client) => this.registerClient(client),
    };
  }

  close(): void {
    this.db.close();
  }

  /** Drops rows that can no longer be used. Cheap; run at boot. */
  purgeExpired(): void {
    const now = nowSec();
    this.db.prepare("DELETE FROM pending_auth WHERE expires_at < ?").run(now);
    this.db.prepare("DELETE FROM auth_codes WHERE expires_at < ?").run(now);
    this.db.prepare("DELETE FROM access_tokens WHERE expires_at < ?").run(now);
    this.db.prepare("DELETE FROM refresh_tokens WHERE expires_at > 0 AND expires_at < ?").run(now);
  }

  // ── Clients ────────────────────────────────────────────────────────────────

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    const row = this.db
      .prepare("SELECT metadata FROM clients WHERE client_id = ?")
      .get(clientId) as { metadata: string } | undefined;
    return row ? (JSON.parse(row.metadata) as OAuthClientInformationFull) : undefined;
  }

  countClients(): number {
    const row = this.db.prepare("SELECT COUNT(*) AS n FROM clients").get() as { n: number };
    return row.n;
  }

  /**
   * Stores a client registered via RFC 7591.
   *
   * Every requested redirect_uri must be on the allowlist verbatim. Claude only
   * ever uses https://claude.ai/api/mcp/auth_callback, so accepting anything
   * else would only widen the attack surface.
   */
  registerClient(
    client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at"> &
      Partial<Pick<OAuthClientInformationFull, "client_id" | "client_id_issued_at">>
  ): OAuthClientInformationFull {
    const rejected = client.redirect_uris.filter((uri) => !this.allowedRedirectUris.includes(uri));
    if (rejected.length > 0) {
      throw new InvalidClientMetadataError(
        `redirect_uri not allowed: ${rejected.join(", ")}. ` +
          `Allowed: ${this.allowedRedirectUris.join(", ")}`
      );
    }
    const issuedAt = nowSec();
    // The SDK's registration handler assigns these by default, but the
    // interface type does not promise them.
    const stored: OAuthClientInformationFull = {
      ...client,
      client_id: client.client_id ?? randomUUID(),
      client_id_issued_at: client.client_id_issued_at ?? issuedAt,
    };
    this.db
      .prepare("INSERT INTO clients (client_id, created_at, metadata) VALUES (?, ?, ?)")
      .run(stored.client_id, issuedAt, JSON.stringify(stored));
    return stored;
  }

  deleteClient(clientId: string): void {
    this.db.prepare("DELETE FROM clients WHERE client_id = ?").run(clientId);
  }

  // ── Pending authorization (consent screen) ────────────────────────────────

  createPendingAuth(input: Omit<PendingAuthRecord, "requestId" | "expiresAt" | "clientName">, ttlSec = 600): string {
    const requestId = randomToken();
    this.db
      .prepare(
        `INSERT INTO pending_auth
           (request_id, client_id, redirect_uri, code_challenge, state, scopes, resource, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        requestId,
        input.clientId,
        input.redirectUri,
        input.codeChallenge,
        input.state ?? null,
        JSON.stringify(input.scopes),
        input.resource ?? null,
        nowSec() + ttlSec
      );
    return requestId;
  }

  getPendingAuth(requestId: string): PendingAuthRecord | undefined {
    const row = this.db
      .prepare("SELECT * FROM pending_auth WHERE request_id = ?")
      .get(requestId) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    if ((row.expires_at as number) < nowSec()) {
      this.deletePendingAuth(requestId);
      return undefined;
    }
    const client = this.getClient(row.client_id as string);
    return {
      requestId: row.request_id as string,
      clientId: row.client_id as string,
      clientName: client?.client_name ?? (row.client_id as string),
      redirectUri: row.redirect_uri as string,
      codeChallenge: row.code_challenge as string,
      state: (row.state as string | null) ?? undefined,
      scopes: JSON.parse(row.scopes as string) as string[],
      resource: (row.resource as string | null) ?? undefined,
      expiresAt: row.expires_at as number,
    };
  }

  deletePendingAuth(requestId: string): void {
    this.db.prepare("DELETE FROM pending_auth WHERE request_id = ?").run(requestId);
  }

  // ── Authorization codes ───────────────────────────────────────────────────

  createAuthCode(record: Omit<AuthCodeRecord, "expiresAt">, ttlSec = 60): string {
    const code = randomToken();
    this.db
      .prepare(
        `INSERT INTO auth_codes
           (code_hash, client_id, redirect_uri, code_challenge, scopes, resource, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        hashToken(code),
        record.clientId,
        record.redirectUri,
        record.codeChallenge,
        JSON.stringify(record.scopes),
        record.resource ?? null,
        nowSec() + ttlSec
      );
    return code;
  }

  getAuthCode(code: string): AuthCodeRecord | undefined {
    const row = this.db
      .prepare("SELECT * FROM auth_codes WHERE code_hash = ?")
      .get(hashToken(code)) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    return {
      clientId: row.client_id as string,
      redirectUri: row.redirect_uri as string,
      codeChallenge: row.code_challenge as string,
      scopes: JSON.parse(row.scopes as string) as string[],
      resource: (row.resource as string | null) ?? undefined,
      expiresAt: row.expires_at as number,
    };
  }

  /** Reads and deletes in one step — an authorization code is single-use. */
  consumeAuthCode(code: string): AuthCodeRecord | undefined {
    const record = this.getAuthCode(code);
    this.db.prepare("DELETE FROM auth_codes WHERE code_hash = ?").run(hashToken(code));
    return record;
  }

  // ── Access tokens ─────────────────────────────────────────────────────────

  putAccessToken(token: string, record: TokenRecord): void {
    this.db
      .prepare(
        "INSERT INTO access_tokens (token_hash, client_id, scopes, resource, expires_at) VALUES (?, ?, ?, ?, ?)"
      )
      .run(hashToken(token), record.clientId, JSON.stringify(record.scopes), record.resource, record.expiresAt);
  }

  getAccessToken(token: string): TokenRecord | undefined {
    const row = this.db
      .prepare("SELECT * FROM access_tokens WHERE token_hash = ?")
      .get(hashToken(token)) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    return {
      clientId: row.client_id as string,
      scopes: JSON.parse(row.scopes as string) as string[],
      resource: row.resource as string,
      expiresAt: row.expires_at as number,
    };
  }

  deleteAccessToken(token: string): void {
    this.db.prepare("DELETE FROM access_tokens WHERE token_hash = ?").run(hashToken(token));
  }

  // ── Refresh tokens ────────────────────────────────────────────────────────

  putRefreshToken(token: string, record: TokenRecord): void {
    this.db
      .prepare(
        `INSERT INTO refresh_tokens (token_hash, client_id, scopes, resource, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
      .run(
        hashToken(token),
        record.clientId,
        JSON.stringify(record.scopes),
        record.resource,
        record.expiresAt,
        nowSec()
      );
  }

  /**
   * Reads and deletes a refresh token. OAuth 2.1 requires refresh token
   * rotation for public clients, and Claude registers as one.
   */
  consumeRefreshToken(token: string): TokenRecord | undefined {
    const row = this.db
      .prepare("SELECT * FROM refresh_tokens WHERE token_hash = ?")
      .get(hashToken(token)) as Record<string, unknown> | undefined;
    this.db.prepare("DELETE FROM refresh_tokens WHERE token_hash = ?").run(hashToken(token));
    if (!row) return undefined;
    const expiresAt = row.expires_at as number;
    if (expiresAt > 0 && expiresAt < nowSec()) return undefined;
    return {
      clientId: row.client_id as string,
      scopes: JSON.parse(row.scopes as string) as string[],
      resource: row.resource as string,
      expiresAt,
    };
  }

  deleteRefreshToken(token: string): void {
    this.db.prepare("DELETE FROM refresh_tokens WHERE token_hash = ?").run(hashToken(token));
  }
}
