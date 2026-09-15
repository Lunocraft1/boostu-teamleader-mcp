/**
 * Who may approve an authorization request.
 *
 * There is one user today, but the accounts live in configuration rather than
 * in code, so a second one is a file edit and not a rewrite. Each issued token
 * records which account approved it, which is what makes per-user revocation
 * and audit possible later without touching the token format again.
 *
 * Two sources, in order of precedence:
 *
 *  1. MCP_USERS_FILE — a JSON array of {username, passwordHash}. The real
 *     mechanism; manage it with `npm run user`.
 *  2. MCP_CONSENT_PASSWORD_HASH — a single hash with no file. Kept so an
 *     existing single-user deployment keeps working untouched; the account is
 *     named by MCP_CONSENT_USERNAME, default "admin".
 */

import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { hashPassword, verifyPassword } from "./password.js";

export interface UserRecord {
  username: string;
  passwordHash: string;
}

export class UserStore {
  private users: UserRecord[];

  constructor(users: UserRecord[], private readonly filePath?: string) {
    this.users = users;
  }

  static load(env: NodeJS.ProcessEnv = process.env): UserStore {
    const filePath = env.MCP_USERS_FILE?.trim();
    if (filePath) {
      return new UserStore(UserStore.readFile(filePath), filePath);
    }
    const hash = env.MCP_CONSENT_PASSWORD_HASH?.trim();
    if (hash) {
      const username = env.MCP_CONSENT_USERNAME?.trim() || "admin";
      return new UserStore([{ username, passwordHash: hash }]);
    }
    throw new Error(
      "No login configured. Set MCP_USERS_FILE (see `npm run user -- --help`) " +
        "or MCP_CONSENT_PASSWORD_HASH."
    );
  }

  private static readFile(filePath: string): UserRecord[] {
    let raw: string;
    try {
      raw = readFileSync(filePath, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        throw new Error(
          `MCP_USERS_FILE points at ${filePath}, which does not exist. ` +
            `Create the first account with: npm run user -- add <name>`
        );
      }
      throw error;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new Error(`${filePath} is not valid JSON: ${(error as Error).message}`);
    }
    if (!Array.isArray(parsed) || parsed.length === 0) {
      throw new Error(`${filePath} must be a non-empty JSON array of {username, passwordHash}.`);
    }
    return parsed.map((entry, index) => {
      const record = entry as Partial<UserRecord>;
      if (typeof record.username !== "string" || !record.username.trim()) {
        throw new Error(`${filePath}: entry ${index} has no username.`);
      }
      if (typeof record.passwordHash !== "string" || !record.passwordHash.trim()) {
        throw new Error(`${filePath}: entry ${index} ("${record.username}") has no passwordHash.`);
      }
      return { username: record.username.trim(), passwordHash: record.passwordHash.trim() };
    });
  }

  count(): number {
    return this.users.length;
  }

  usernames(): string[] {
    return this.users.map((user) => user.username);
  }

  /** True while a single account exists, which lets the login omit the name. */
  get isSingleUser(): boolean {
    return this.users.length === 1;
  }

  /**
   * Checks a login and returns the account name on success.
   *
   * `username` may be omitted while there is exactly one account, so the login
   * stays a single field today and needs no change when a second is added.
   * Every candidate is checked rather than short-circuiting on the first
   * match, so a wrong name and a wrong password cost the same.
   */
  verify(username: string | undefined, password: string): string | undefined {
    const name = username?.trim();
    const candidates =
      name && name.length > 0
        ? this.users.filter((user) => user.username === name)
        : this.isSingleUser
          ? this.users
          : [];

    let authenticated: string | undefined;
    for (const user of candidates) {
      if (verifyPassword(password, user.passwordHash)) authenticated = user.username;
    }
    if (authenticated) return authenticated;

    // Spend comparable effort on an unknown account so the response time does
    // not reveal whether the name exists.
    if (candidates.length === 0 && this.users.length > 0) {
      verifyPassword(password, this.users[0].passwordHash);
    }
    return undefined;
  }

  // ── Management (used by the `npm run user` CLI) ───────────────────────────

  private persist(): void {
    if (!this.filePath) {
      throw new Error(
        "This deployment uses MCP_CONSENT_PASSWORD_HASH, which holds a single account and " +
          "cannot be edited. Switch to MCP_USERS_FILE to manage accounts."
      );
    }
    mkdirSync(dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.users, null, 2) + "\n", { mode: 0o600 });
    renameSync(tmp, this.filePath);
  }

  addUser(username: string, password: string): void {
    const name = username.trim();
    if (!name) throw new Error("Username must not be empty.");
    if (this.users.some((user) => user.username === name)) {
      throw new Error(`User "${name}" already exists.`);
    }
    this.users.push({ username: name, passwordHash: hashPassword(password) });
    this.persist();
  }

  setPassword(username: string, password: string): void {
    const user = this.users.find((candidate) => candidate.username === username.trim());
    if (!user) throw new Error(`No such user: "${username}".`);
    user.passwordHash = hashPassword(password);
    this.persist();
  }

  removeUser(username: string): void {
    const name = username.trim();
    if (!this.users.some((user) => user.username === name)) {
      throw new Error(`No such user: "${name}".`);
    }
    if (this.users.length === 1) {
      throw new Error("Refusing to remove the last account — nobody could authorize again.");
    }
    this.users = this.users.filter((user) => user.username !== name);
    this.persist();
  }

  /** Creates an empty store file so the first account can be added. */
  static initFile(filePath: string): UserStore {
    mkdirSync(dirname(filePath), { recursive: true });
    writeFileSync(filePath, "[]\n", { mode: 0o600 });
    return new UserStore([], filePath);
  }
}
