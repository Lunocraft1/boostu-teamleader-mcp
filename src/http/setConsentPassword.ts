#!/usr/bin/env node
/**
 * Changes the consent-page password on the remote server.
 *
 *   npm run set-password              # account "malte" on the default server
 *   npm run set-password -- benjamin
 *
 * The password is typed into this process with echo disabled and is never
 * printed, never passed as an argument, and never sent anywhere: only the
 * scrypt hash leaves the machine. Afterwards the stored hash is read back and
 * checked against what was typed, so a lock-out is caught here rather than at
 * the next attempt to connect.
 */

import { spawnSync } from "node:child_process";
import { hashPassword, verifyPassword } from "./password.js";
import { readHiddenTwice } from "./prompt.js";

const SERVER = process.env.MCP_SERVER ?? "root@178.104.62.11";
const USERS_FILE = process.env.REMOTE_USERS_FILE ?? "/var/lib/teamleader-mcp/users.json";
const SERVICE = process.env.MCP_SERVICE ?? "teamleader-mcp";

interface UserRecord {
  username: string;
  passwordHash: string;
}

function ssh(command: string, input?: string): string {
  const result = spawnSync("ssh", ["-o", "BatchMode=yes", SERVER, command], {
    input,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(
      `ssh failed (exit ${result.status}): ${(result.stderr || result.stdout || "").trim()}`
    );
  }
  return result.stdout;
}

function readUsers(): UserRecord[] {
  const raw = ssh(`cat ${USERS_FILE}`);
  const parsed = JSON.parse(raw) as UserRecord[];
  if (!Array.isArray(parsed)) throw new Error(`${USERS_FILE} is not a JSON array.`);
  return parsed;
}

function writeUsers(users: UserRecord[]): void {
  // The file arrives on stdin; the script itself carries no secret. Written to
  // a temporary file in the same directory and moved into place, so the service
  // never reads a half-written file.
  const script = [
    "set -e",
    "umask 077",
    `tmp=$(mktemp "$(dirname ${USERS_FILE})/.users.XXXXXX")`,
    'cat > "$tmp"',
    'chown teamleader-mcp:teamleader-mcp "$tmp"',
    'chmod 600 "$tmp"',
    `mv "$tmp" ${USERS_FILE}`,
  ].join("\n");
  ssh(script, JSON.stringify(users, null, 2) + "\n");
}

async function main(): Promise<void> {
  const username = process.argv[2]?.trim() || "malte";

  process.stderr.write(`Server:  ${SERVER}\n`);
  process.stderr.write(`Konto:   ${username}\n`);
  process.stderr.write("Die Eingabe wird nicht angezeigt.\n\n");

  const users = readUsers();
  const existing = users.find((user) => user.username === username);
  if (!existing) {
    process.stderr.write(
      `Hinweis: Konto "${username}" existiert noch nicht und wird angelegt. ` +
        `Vorhanden: ${users.map((u) => u.username).join(", ") || "(keine)"}\n\n`
    );
  }

  const password = await readHiddenTwice();
  const hash = hashPassword(password);
  if (!verifyPassword(password, hash)) {
    throw new Error("Generated hash does not verify — aborting without changing anything.");
  }

  if (existing) {
    existing.passwordHash = hash;
  } else {
    users.push({ username, passwordHash: hash });
  }
  writeUsers(users);
  process.stderr.write("Hash gespeichert.\n");

  // Accounts are read at startup, so the service has to be restarted.
  ssh(`systemctl restart ${SERVICE}`);
  const active = ssh(`systemctl is-active ${SERVICE} || true`).trim();
  process.stderr.write(`Dienst: ${active}\n`);

  // Read the stored hash back and check it against what was typed.
  const stored = readUsers().find((user) => user.username === username);
  if (!stored) throw new Error(`Account "${username}" is missing after the write.`);
  if (!verifyPassword(password, stored.passwordHash)) {
    throw new Error(
      "The stored hash does not match the password that was entered. " +
        "The old password may still be in effect — check before relying on it."
    );
  }
  process.stderr.write("Gegenprobe: das gespeicherte Passwort passt zur Eingabe.\n");
  process.stderr.write("\nFertig. Das Passwort wurde nicht angezeigt; gespeichert ist nur der Hash.\n");
}

main().catch((error) => {
  process.stderr.write(`\nFehlgeschlagen: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
