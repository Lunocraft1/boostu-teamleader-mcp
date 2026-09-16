/**
 * Composing a reply and putting it in the Drafts folder.
 *
 * This is the only tool in the mail group that writes anything, and it is the
 * single exception to the briefing endpoint being read-only. The reasoning is
 * that the drafts should be finished when the user gets up, and the blast
 * radius is small: nothing leaves the building and nothing existing is
 * modified. The worst case is an unusable draft sitting in a folder.
 *
 * **Sending is not possible, not merely forbidden.** No SMTP is configured
 * anywhere, and only nodemailer's MailComposer submodule is imported — the
 * part that assembles a MIME message. `nodemailer.createTransport`, the
 * function that would make sending possible, is never imported and never
 * called. There is no code path from here to the outside world.
 */

import MailComposer from "nodemailer/lib/mail-composer/index.js";

export type DraftStyle = "sachlich" | "persoenlich" | "foermlich";

/**
 * Salutation and closing per register.
 *
 * Deliberately free of gendered forms: the mailbox knows a display name, not a
 * person's gender, and "Sehr geehrter Herr" against a guess is worse than a
 * neutral greeting. The personal register uses a first name only when one can
 * actually be read off the sender.
 */
export function greetingFor(style: DraftStyle, firstName?: string): string {
  switch (style) {
    case "persoenlich":
      return firstName ? `Hallo ${firstName},` : "Hallo,";
    case "foermlich":
      return "Sehr geehrte Damen und Herren,";
    case "sachlich":
    default:
      return "Guten Tag,";
  }
}

export function closingFor(style: DraftStyle): string {
  return style === "persoenlich" ? "Viele Grüße" : "Mit freundlichen Grüßen";
}

/** Subject prefixes that already mark a reply, German and English. */
const REPLY_PREFIX = /^\s*(re|aw|antw|antwort|fw|fwd|wg)\s*:/i;

/**
 * Identity of a reply, for recognising one that already exists.
 *
 * Header-based matching is not available: Proton strips In-Reply-To, References
 * and every custom header from a draft appended over IMAP and substitutes its
 * own internal ids (verified against the live mailbox). What survives is the
 * recipient and the subject, so those identify the reply — which is also the
 * right semantics: if a draft to the same person about the same subject is
 * already waiting, a second one is noise.
 */
export function replyKey(toAddress: string, subject: string): string {
  const address = toAddress.toLowerCase().trim();
  let base = subject.replace(/\s+/g, " ").trim();
  // Strip any number of stacked reply prefixes so "Re: AW: X" matches "X".
  while (REPLY_PREFIX.test(base)) base = base.replace(REPLY_PREFIX, "").trim();
  return `${address}|${base.toLowerCase()}`;
}

/** Bare email address out of a "Name <addr>" string. */
export function bareAddress(value: string): string {
  const match = /<([^>]+)>/.exec(value);
  return (match ? match[1] : value).trim().toLowerCase();
}

/** Adds "Re: " unless the subject already carries a reply prefix. */
export function replySubject(original?: string): string {
  const subject = (original ?? "").replace(/\s+/g, " ").trim();
  if (!subject) return "Re: (kein Betreff)";
  return REPLY_PREFIX.test(subject) ? subject : `Re: ${subject}`;
}

/**
 * Builds the References header for a reply.
 *
 * RFC 5322: the parent's References, then the parent's Message-ID. Getting this
 * wrong is what leaves a draft floating in Proton as a loose message instead of
 * hanging on the conversation.
 */
export function buildReferences(
  parentMessageId: string,
  parentReferences?: string
): string {
  const ids: string[] = [];
  const push = (value: string): void => {
    const id = value.trim();
    if (id && !ids.includes(id)) ids.push(id);
  };
  for (const match of (parentReferences ?? "").matchAll(/<[^>]+>/g)) push(match[0]);
  push(parentMessageId.startsWith("<") ? parentMessageId : `<${parentMessageId}>`);
  return ids.join(" ");
}

/** Extracts a usable first name from a display name, if there is one. */
export function firstNameOf(displayName?: string): string | undefined {
  const name = (displayName ?? "").replace(/"/g, "").trim();
  if (!name || name.includes("@")) return undefined;
  // "Hofmann, Patrick" -> Patrick
  if (name.includes(",")) {
    const after = name.split(",")[1]?.trim().split(/\s+/)[0];
    return after && /^[\p{L}][\p{L}.'-]{1,}$/u.test(after) ? after : undefined;
  }
  const first = name.split(/\s+/)[0];
  // A single token that is all caps or looks like a company is not a first name.
  if (!first || first.length < 2) return undefined;
  if (!/^[\p{Lu}][\p{Ll}.'-]+$/u.test(first)) return undefined;
  return first;
}

export interface DraftInput {
  from: string;
  to: string;
  cc?: string;
  subject: string;
  inReplyTo: string;
  references: string;
  greeting: string;
  body: string;
  closing: string;
  signature?: string;
}

/** Assembles the final plain-text body. */
export function composeText(input: DraftInput): string {
  const parts = [input.greeting, "", input.body.trim(), "", input.closing];
  if (input.signature?.trim()) parts.push(input.signature.trim());
  return parts.join("\n").replace(/\n{3,}/g, "\n\n") + "\n";
}

/**
 * Builds the RFC 5322 message for the draft.
 *
 * Plain text only: a draft the user opens and edits in Proton before sending
 * does not benefit from HTML, and plain text cannot carry a tracking pixel or a
 * broken layout.
 */
export async function buildDraftMime(input: DraftInput): Promise<Buffer> {
  const composer = new MailComposer({
    from: input.from,
    to: input.to,
    ...(input.cc ? { cc: input.cc } : {}),
    subject: input.subject,
    inReplyTo: input.inReplyTo,
    references: input.references,
    text: composeText(input),
  });
  return await new Promise<Buffer>((resolve, reject) => {
    composer.compile().build((error: Error | null, message: Buffer) => {
      if (error) reject(error);
      else resolve(message);
    });
  });
}
