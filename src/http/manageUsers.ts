#!/usr/bin/env node
/**
 * Account management for the consent login.
 *
 *   npm run user -- list
 *   npm run user -- add <name>
 *   npm run user -- passwd <name>
 *   npm run user -- remove <name>
 *
 * Reads MCP_USERS_FILE. Passwords are prompted with echo disabled and never
 * taken as an argument, so they stay out of the terminal scrollback, the shell
 * history and the process list.
 */

import { existsSync } from "node:fs";
import { UserStore } from "./users.js";
import { readHiddenTwice } from "./prompt.js";

function usage(): never {
  console.error(
    [
      "Usage: npm run user -- <command>",
      "",
      "  list             show all accounts",
      "  add <name>       create an account (prompts for a password)",
      "  passwd <name>    change an account's password",
      "  remove <name>    delete an account (never the last one)",
      "",
      "Requires MCP_USERS_FILE to point at the accounts file, e.g.",
      "  MCP_USERS_FILE=/var/lib/teamleader-mcp/users.json npm run user -- list",
    ].join("\n")
  );
  process.exit(1);
}

async function main(): Promise<void> {
  const [command, name] = process.argv.slice(2);
  if (!command || command === "--help" || command === "-h") usage();

  const filePath = process.env.MCP_USERS_FILE?.trim();
  if (!filePath) {
    console.error("MCP_USERS_FILE is not set.");
    usage();
  }

  // `add` is the one command that may run before the file exists.
  const store =
    existsSync(filePath) || command !== "add"
      ? UserStore.load({ MCP_USERS_FILE: filePath } as NodeJS.ProcessEnv)
      : UserStore.initFile(filePath);

  switch (command) {
    case "list": {
      const names = store.usernames();
      console.log(`${names.length} account(s) in ${filePath}:`);
      for (const username of names) console.log(`  ${username}`);
      break;
    }
    case "add": {
      if (!name) usage();
      store.addUser(name, await readHiddenTwice());
      console.log(`Added "${name}". Restart the service so it reloads the accounts.`);
      break;
    }
    case "passwd": {
      if (!name) usage();
      store.setPassword(name, await readHiddenTwice());
      console.log(`Password changed for "${name}". Restart the service.`);
      break;
    }
    case "remove": {
      if (!name) usage();
      store.removeUser(name);
      console.log(`Removed "${name}". Restart the service.`);
      break;
    }
    default:
      usage();
  }
}

main().catch((error) => {
  console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
