/**
 * Teamleader credentials for the long-running HTTP server.
 *
 * Two hazards are specific to running this over HTTP rather than stdio:
 *
 *  1. Teamleader rotates the refresh token on every refresh and accepts each
 *     one exactly once. Two concurrent refreshes therefore destroy the
 *     credential: the second call presents a token the first already spent.
 *     Over stdio one client sends one request at a time; over HTTP Claude
 *     happily issues parallel tool calls. `SerializedTeamleaderAuth` collapses
 *     concurrent refreshes into one.
 *
 *  2. The same reasoning applies across processes, where no in-process lock can
 *     help. A second instance sharing these credentials — a forgotten local
 *     test, a second replica — invalidates the token store for good. `lockTokenStore`
 *     makes that fail loudly at boot instead of silently mid-operation.
 */

import { existsSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { TeamleaderAuth } from "../api/auth.js";

export class SerializedTeamleaderAuth extends TeamleaderAuth {
  private inflight: Promise<string> | null = null;

  async getAccessToken(): Promise<string> {
    // A valid cached token short-circuits inside super; only an actual refresh
    // is expensive, and only that must never run twice at once.
    if (this.inflight) return this.inflight;
    this.inflight = super.getAccessToken().finally(() => {
      this.inflight = null;
    });
    return this.inflight;
  }
}

/**
 * Takes an advisory lock next to the token store so a second process using the
 * same Teamleader credentials refuses to start.
 *
 * @returns a release function to call on shutdown.
 */
export function lockTokenStore(tokenStorePath: string): () => void {
  const lockPath = `${tokenStorePath}.lock`;

  if (existsSync(lockPath)) {
    const raw = readFileSync(lockPath, "utf8").trim();
    const pid = Number(raw);
    if (Number.isInteger(pid) && pid > 0 && pid !== process.pid) {
      let alive = false;
      try {
        // Signal 0 tests for existence without touching the process.
        process.kill(pid, 0);
        alive = true;
      } catch (error) {
        // EPERM means it exists but belongs to another user.
        alive = (error as NodeJS.ErrnoException).code === "EPERM";
      }
      if (alive) {
        throw new Error(
          `Another instance (pid ${pid}) already holds ${lockPath}. ` +
            `Teamleader rotates the refresh token on every call, so only one process may use ` +
            `these credentials. Stop the other instance, or use a separate Teamleader ` +
            `integration for local testing.`
        );
      }
    }
    // Stale lock from a crashed process.
    console.warn(`[teamleader] removing stale lock ${lockPath} (pid ${raw})`);
    unlinkSync(lockPath);
  }

  writeFileSync(lockPath, `${process.pid}\n`, { mode: 0o600 });
  return () => {
    try {
      if (existsSync(lockPath) && readFileSync(lockPath, "utf8").trim() === String(process.pid)) {
        unlinkSync(lockPath);
      }
    } catch {
      // Shutdown path: a failure to unlink must not mask the original exit.
    }
  };
}
