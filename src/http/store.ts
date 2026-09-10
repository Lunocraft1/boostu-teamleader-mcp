/**
 * Persistent state for the authorization server.
 *
 * Registered clients MUST outlive a restart: Claude registers once via dynamic
 * client registration and then keeps using that client_id. If the record is
 * gone after a restart, the connector is dead until the user re-authorizes.
 * Codes and tokens live here too, so an access token stays valid across a
 * deploy. Only hashes are stored — a copy of this file does not yield usable
 * credentials.
 *
 * Storage is a single JSON file held in memory and rewritten atomically
 * (write to a temporary file, then rename) on every mutation. That is a
 * deliberate choice over SQLite: the whole dataset is a handful of clients and
 * tokens, writes happen a few times an hour, and there is exactly one process
 * by design. A native module would have to be recompiled whenever the host's
 * Node version changes, which for an unattended service means it stops
 * starting at some later date for a reason unrelated to any change made here.
 */

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import { InvalidClientMetadataError } from "@modelcontextprotocol/sdk/server/auth/errors.js";

/** Pass as the path to keep everything in memory (tests). */
export const IN_MEMORY = ":memory:";

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
  /** Absolute epoch seconds; 0 means "does not expire" (refresh tokens only). */
  expiresAt: number;
}

interface StoredClient {
  createdAt: number;
  metadata: OAuthClientInformationFull;
}

interface StoredPendingAuth extends Omit<PendingAuthRecord, "clientName"> {}

interface Snapshot {
  version: 1;
  clients: Record<string, StoredClient>;
  pendingAuth: Record<string, StoredPendingAuth>;
  authCodes: Record<string, AuthCodeRecord>;
  accessTokens: Record<string, TokenRecord>;
  refreshTokens: Record<string, TokenRecord & { createdAt: number }>;
}

function emptySnapshot(): Snapshot {
  return {
    version: 1,
    clients: {},
    pendingAuth: {},
    authCodes: {},
    accessTokens: {},
    refreshTokens: {},
  };
}

export class OAuthStore {
  private data: Snapshot;
  private readonly persistent: boolean;
  readonly clients: OAuthRegisteredClientsStore;

  /**
   * @param dbPath  JSON file path, or IN_MEMORY for tests.
   * @param allowedRedirectUris  Exact-match allowlist enforced at registration.
   */
  constructor(
    private readonly dbPath: string,
    private readonly allowedRedirectUris: string[]
  ) {
    this.persistent = dbPath !== IN_MEMORY;
    this.data = this.persistent ? this.load() : emptySnapshot();
    this.purgeExpired();

    this.clients = {
      getClient: (clientId) => this.getClient(clientId),
      registerClient: (client) => this.registerClient(client),
    };
  }

  private load(): Snapshot {
    mkdirSync(dirname(this.dbPath), { recursive: true });
    let raw: string;
    try {
      raw = readFileSync(this.dbPath, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return emptySnapshot();
      throw error;
    }
    if (!raw.trim()) return emptySnapshot();
    try {
      const parsed = JSON.parse(raw) as Snapshot;
      if (parsed.version !== 1) {
        throw new Error(`unsupported store version ${String(parsed.version)}`);
      }
      // Tolerate a file written by an older build that lacked a table.
      return { ...emptySnapshot(), ...parsed };
    } catch (error) {
      // Refuse to start rather than silently discarding every registered
      // client — that would look like a working server that no client can use.
      throw new Error(
        `Could not read the OAuth store at ${this.dbPath}: ${(error as Error).message}. ` +
          `Move the file aside to start fresh; every client will have to authorize again.`
      );
    }
  }

  private persist(): void {
    if (!this.persistent) return;
    const tmp = `${this.dbPath}.tmp`;
    // Write-then-rename: a reader never sees a partially written file.
    writeFileSync(tmp, JSON.stringify(this.data), { mode: 0o600 });
    renameSync(tmp, this.dbPath);
  }

  close(): void {
    this.persist();
  }

  /** Drops rows that can no longer be used. Cheap; run at boot. */
  purgeExpired(): void {
    const now = nowSec();
    let changed = false;
    const sweep = <T extends { expiresAt: number }>(
      table: Record<string, T>,
      neverExpires = false
    ): void => {
      for (const [key, value] of Object.entries(table)) {
        if (neverExpires && value.expiresAt === 0) continue;
        if (value.expiresAt < now) {
          delete table[key];
          changed = true;
        }
      }
    };
    sweep(this.data.pendingAuth);
    sweep(this.data.authCodes);
    sweep(this.data.accessTokens);
    sweep(this.data.refreshTokens, true);
    if (changed) this.persist();
  }

  // ── Clients ────────────────────────────────────────────────────────────────

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    return this.data.clients[clientId]?.metadata;
  }

  countClients(): number {
    return Object.keys(this.data.clients).length;
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
    this.data.clients[stored.client_id] = { createdAt: issuedAt, metadata: stored };
    this.persist();
    return stored;
  }

  deleteClient(clientId: string): void {
    delete this.data.clients[clientId];
    this.persist();
  }

  // ── Pending authorization (consent screen) ────────────────────────────────

  createPendingAuth(
    input: Omit<PendingAuthRecord, "requestId" | "expiresAt" | "clientName">,
    ttlSec = 600
  ): string {
    const requestId = randomToken();
    this.data.pendingAuth[requestId] = {
      requestId,
      clientId: input.clientId,
      redirectUri: input.redirectUri,
      codeChallenge: input.codeChallenge,
      state: input.state,
      scopes: input.scopes,
      resource: input.resource,
      expiresAt: nowSec() + ttlSec,
    };
    this.persist();
    return requestId;
  }

  getPendingAuth(requestId: string): PendingAuthRecord | undefined {
    const record = this.data.pendingAuth[requestId];
    if (!record) return undefined;
    if (record.expiresAt < nowSec()) {
      this.deletePendingAuth(requestId);
      return undefined;
    }
    return {
      ...record,
      clientName: this.getClient(record.clientId)?.client_name ?? record.clientId,
    };
  }

  deletePendingAuth(requestId: string): void {
    delete this.data.pendingAuth[requestId];
    this.persist();
  }

  // ── Authorization codes ───────────────────────────────────────────────────

  createAuthCode(record: Omit<AuthCodeRecord, "expiresAt">, ttlSec = 60): string {
    const code = randomToken();
    this.data.authCodes[hashToken(code)] = { ...record, expiresAt: nowSec() + ttlSec };
    this.persist();
    return code;
  }

  getAuthCode(code: string): AuthCodeRecord | undefined {
    return this.data.authCodes[hashToken(code)];
  }

  /** Reads and deletes in one step — an authorization code is single-use. */
  consumeAuthCode(code: string): AuthCodeRecord | undefined {
    const key = hashToken(code);
    const record = this.data.authCodes[key];
    if (record) {
      delete this.data.authCodes[key];
      this.persist();
    }
    return record;
  }

  // ── Access tokens ─────────────────────────────────────────────────────────

  putAccessToken(token: string, record: TokenRecord): void {
    this.data.accessTokens[hashToken(token)] = record;
    this.persist();
  }

  getAccessToken(token: string): TokenRecord | undefined {
    return this.data.accessTokens[hashToken(token)];
  }

  deleteAccessToken(token: string): void {
    const key = hashToken(token);
    if (this.data.accessTokens[key]) {
      delete this.data.accessTokens[key];
      this.persist();
    }
  }

  // ── Refresh tokens ────────────────────────────────────────────────────────

  putRefreshToken(token: string, record: TokenRecord): void {
    this.data.refreshTokens[hashToken(token)] = { ...record, createdAt: nowSec() };
    this.persist();
  }

  /**
   * Reads and deletes a refresh token. OAuth 2.1 requires refresh token
   * rotation for public clients, and Claude registers as one.
   */
  consumeRefreshToken(token: string): TokenRecord | undefined {
    const key = hashToken(token);
    const record = this.data.refreshTokens[key];
    if (!record) return undefined;
    delete this.data.refreshTokens[key];
    this.persist();
    if (record.expiresAt > 0 && record.expiresAt < nowSec()) return undefined;
    return record;
  }

  deleteRefreshToken(token: string): void {
    const key = hashToken(token);
    if (this.data.refreshTokens[key]) {
      delete this.data.refreshTokens[key];
      this.persist();
    }
  }
}
