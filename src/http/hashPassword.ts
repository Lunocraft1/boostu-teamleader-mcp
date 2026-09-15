#!/usr/bin/env node
/**
 * Prints a scrypt hash for the consent login, and nothing else on stdout.
 *
 *   node dist/http/hashPassword.js            # prompts twice, input hidden
 *   node dist/http/hashPassword.js 'secret'   # non-interactive (leaves shell history)
 *   echo 'secret' | node dist/http/hashPassword.js
 *
 * Only the hash goes to stdout, so the caller can do:
 *   HASH="$(node dist/http/hashPassword.js)"
 * without the password ever leaving this process.
 */

import { hashPassword, verifyPassword } from "./password.js";
import { isInteractive, readHiddenTwice, readStdin } from "./prompt.js";

async function main(): Promise<void> {
  const fromArgs = process.argv.slice(2).join(" ");
  let password: string;

  if (fromArgs) {
    process.stderr.write(
      "Warning: the password was passed as an argument and is now in your shell " +
        "history and was briefly visible in the process list. Prefer running this " +
        "with no arguments.\n"
    );
    password = fromArgs;
  } else if (isInteractive()) {
    password = await readHiddenTwice();
  } else {
    password = await readStdin();
  }

  if (!password) {
    process.stderr.write("No password given.\n");
    process.exit(1);
  }
  const hash = hashPassword(password);
  // Guard against ever emitting a hash the password does not open.
  if (!verifyPassword(password, hash)) {
    process.stderr.write("Internal error: generated hash does not verify.\n");
    process.exit(1);
  }
  // stdout carries the hash only.
  process.stdout.write(hash + "\n");
}

main().catch((error) => {
  process.stderr.write(`Error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
