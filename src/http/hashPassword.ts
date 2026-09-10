#!/usr/bin/env node
/**
 * Prints a scrypt hash for MCP_CONSENT_PASSWORD_HASH.
 *
 *   npm run hash-password -- 'my consent password'
 *
 * Passing the password as an argument leaves it in the shell history; with no
 * argument the password is read from stdin instead.
 */

import { hashPassword } from "./password.js";

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
}

async function main(): Promise<void> {
  const fromArgs = process.argv.slice(2).join(" ");
  const password = fromArgs || (await readStdin());
  if (!password) {
    console.error("Usage: npm run hash-password -- '<password>'   (or pipe it on stdin)");
    process.exit(1);
  }
  console.log(hashPassword(password));
}

void main();
