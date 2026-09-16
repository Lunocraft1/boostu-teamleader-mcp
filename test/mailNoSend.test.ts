/**
 * Guards the property that matters most about the draft tool: sending is not
 * possible, not merely forbidden.
 *
 * The draft is assembled with nodemailer's MailComposer, which lives in the
 * same package as its SMTP client. Importing the package root, or calling
 * createTransport, would create a code path to the outside world. These tests
 * fail if anyone ever does.
 */

import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

function sourceFiles(dir: string, found: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) sourceFiles(full, found);
    else if (entry.endsWith(".ts")) found.push(full);
  }
  return found;
}

const files = sourceFiles("src");

/**
 * Strips comments so the guards examine code and not prose.
 *
 * Without this the check trips over its own documentation: draft.ts explains in
 * a comment which nodemailer function is deliberately never called, and naming
 * it there is exactly what the comment is for.
 */
function codeOnly(body: string): string {
  return body.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:])\/\/.*$/gm, "$1");
}

describe("no sending capability", () => {
  it("never calls nodemailer.createTransport", () => {
    for (const file of files) {
      const body = codeOnly(readFileSync(file, "utf8"));
      expect(body, file).not.toMatch(/createTransport/);
    }
  });

  it("imports only the MIME composer, never the nodemailer package root", () => {
    for (const file of files) {
      const body = codeOnly(readFileSync(file, "utf8"));
      const imports = [...body.matchAll(/from\s+["']([^"']+)["']/g)].map((m) => m[1]);
      for (const spec of imports) {
        if (!spec.startsWith("nodemailer")) continue;
        // mail-composer assembles a message; the package root exposes sending.
        expect(spec, `${file}: ${spec}`).toMatch(/^nodemailer\/lib\/mail-composer/);
      }
    }
  });

  it("configures no SMTP anywhere", () => {
    for (const file of files) {
      // The Bridge does listen on an SMTP port, but nothing here may use it.
      const body = codeOnly(readFileSync(file, "utf8"));
      expect(body, file).not.toMatch(/MAIL_SMTP|smtpPort|sendMail\s*\(/);
    }
  });

  it("the mail tools expose exactly one writing tool", async () => {
    const { MAIL_READ_TOOLS, MAIL_WRITE_TOOLS } = await import("../src/http/mail/tools.js");
    expect([...MAIL_WRITE_TOOLS]).toEqual(["mail_draft_reply"]);
    // Nothing in the read set may look like a mutation.
    for (const name of MAIL_READ_TOOLS) {
      expect(name, name).not.toMatch(/send|delete|move|append|draft|flag|mark/);
    }
  });

  it("never issues IMAP commands that would delete or move mail", () => {
    for (const file of files) {
      const body = codeOnly(readFileSync(file, "utf8"));
      for (const forbidden of [
        "messageDelete",
        "messageMove",
        "messageFlagsSet",
        "messageFlagsAdd",
        "messageFlagsRemove",
        "mailboxDelete",
      ]) {
        expect(body, `${file}: ${forbidden}`).not.toContain(forbidden);
      }
    }
  });
});
