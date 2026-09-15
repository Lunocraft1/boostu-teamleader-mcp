/**
 * Reading a password from a terminal without echoing it.
 *
 * The prompt goes to stderr, never stdout, so a caller can capture the
 * resulting hash with a command substitution while the user still sees the
 * question. Nothing typed here is ever written to the terminal, so the password
 * does not end up in the scrollback, and because it is typed rather than passed
 * as an argument it stays out of the shell history and the process list.
 */

import { createInterface } from "node:readline";

export function isInteractive(): boolean {
  return Boolean(process.stdin.isTTY);
}

export async function readHidden(question: string): Promise<string> {
  if (!isInteractive()) {
    throw new Error(
      "No terminal available for a hidden prompt. Run this command directly in a " +
        "terminal, or pipe the password on stdin."
    );
  }
  process.stderr.write(question);
  const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true });
  // readline echoes each keypress through _writeToOutput; silencing it hides
  // the input (and the re-rendered prompt, which is why the question above is
  // written directly to stderr first).
  (rl as unknown as { _writeToOutput: (chunk: string) => void })._writeToOutput = () => {};
  try {
    const answer = await new Promise<string>((resolve) => rl.question("", resolve));
    return answer;
  } finally {
    process.stderr.write("\n");
    rl.close();
  }
}

/** Asks twice and requires the two entries to match. */
export async function readHiddenTwice(
  first = "Neues Passwort: ",
  second = "Passwort wiederholen: "
): Promise<string> {
  const a = await readHidden(first);
  if (!a) throw new Error("Password must not be empty.");
  const b = await readHidden(second);
  if (a !== b) throw new Error("Passwords do not match.");
  return a;
}

export async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8").replace(/\r?\n$/, "");
}
