/**
 * Turning a mail body into the short, readable text the briefing is allowed to
 * see.
 *
 * The agreed data scope is sender, subject, date and a shortened body — no full
 * threads, no attachments. Two things follow from that:
 *
 *  - Quoted history has to go. It is the previous conversation repeated, so it
 *    is both the largest part of a typical reply and the part already covered
 *    by the thread-context tool when it is actually wanted.
 *  - Signatures have to go. They are contact details of real people, repeated
 *    on every message, and they carry nothing about what the mail is asking.
 */

import { convert } from "html-to-text";

/**
 * Markers that begin quoted history.
 *
 * German and English, because the mailbox has both. Matched at line start on a
 * trimmed line; the first hit truncates everything after it.
 */
const QUOTE_MARKERS: RegExp[] = [
  /^-{2,}\s*(original|urspr[üu]ngliche)\s*(message|nachricht)/i,
  /^-{3,}\s*forwarded message/i,
  /^am\s.{0,80}\sschrieb\b/i, // "Am 12.09.2026 um 10:12 schrieb Max:"
  /^on\s.{0,80}\swrote:/i,
  /^von:\s/i, // Outlook-style quoted header block
  /^from:\s.{0,120}$/i,
  /^gesendet:\s/i,
  /^-{5,}$/,
  /^_{5,}$/,
];

/** Lines that start a signature block. */
const SIGNATURE_MARKERS: RegExp[] = [
  /^--\s*$/, // RFC 3676 signature separator
  /^__+\s*$/,
  /^mit freundlichen gr[üu][ßs]en/i,
  /^freundliche gr[üu][ßs]e/i,
  /^beste gr[üu][ßs]e/i,
  /^viele gr[üu][ßs]e/i,
  /^liebe gr[üu][ßs]e/i,
  /^kind regards/i,
  /^best regards/i,
  /^regards,?\s*$/i,
  /^sent from my /i,
  /^von meinem iphone gesendet/i,
];

export interface BodyExtract {
  /** The shortened, cleaned text. */
  text: string;
  /** True when content was dropped by the length limit. */
  truncated: boolean;
  /** True when a quoted-history block was removed. */
  quoteRemoved: boolean;
  /** True when a signature block was removed. */
  signatureRemoved: boolean;
}

function htmlToText(html: string): string {
  return convert(html, {
    wordwrap: false,
    selectors: [
      // Link URLs double the length and are rarely what the mail is about.
      { selector: "a", options: { ignoreHref: true } },
      { selector: "img", format: "skip" },
      // Tracking pixels and layout tables produce long runs of empty cells.
      { selector: "table", options: { uppercaseHeaderCells: false } },
    ],
  });
}

/**
 * Extracts the readable part of a message body.
 *
 * @param plain  text/plain part, if the message had one
 * @param html   text/html part, used when there is no plain text
 * @param limit  maximum characters to keep
 */
export function extractBody(
  plain: string | undefined,
  html: string | undefined,
  limit = 1200
): BodyExtract {
  let raw = (plain ?? "").trim();
  if (!raw && html) raw = htmlToText(html).trim();
  if (!raw) {
    return { text: "", truncated: false, quoteRemoved: false, signatureRemoved: false };
  }

  const lines = raw.replace(/\r\n/g, "\n").split("\n");

  let cut = lines.length;
  let quoteRemoved = false;
  let signatureRemoved = false;
  let consecutiveQuoted = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // A run of quoted lines is history even without an introducing marker.
    if (line.startsWith(">")) {
      consecutiveQuoted++;
      if (consecutiveQuoted >= 2) {
        cut = Math.max(0, i - 1);
        quoteRemoved = true;
        break;
      }
      continue;
    }
    consecutiveQuoted = 0;

    if (QUOTE_MARKERS.some((re) => re.test(line))) {
      cut = i;
      quoteRemoved = true;
      break;
    }
    if (SIGNATURE_MARKERS.some((re) => re.test(line))) {
      cut = i;
      signatureRemoved = true;
      break;
    }
  }

  let text = lines
    .slice(0, cut)
    .join("\n")
    // Collapse the blank-line runs that HTML conversion leaves behind.
    .replace(/\n{3,}/g, "\n\n")
    .replace(/[ \t]+$/gm, "")
    .trim();

  let truncated = false;
  if (text.length > limit) {
    // Prefer cutting at a sentence or line end so the tail is not mid-word.
    const window = text.slice(0, limit);
    const boundary = Math.max(window.lastIndexOf("\n"), window.lastIndexOf(". "));
    text = (boundary > limit * 0.6 ? window.slice(0, boundary + 1) : window).trimEnd();
    truncated = true;
  }

  return { text, truncated, quoteRemoved, signatureRemoved };
}

/**
 * Recognises mail that must never receive a generated reply draft.
 *
 * Automated senders do not read answers, so a draft for them is pure noise in
 * the drafts folder — and a reply to a no-reply address bounces.
 */
export function isAutomated(fields: {
  from?: string;
  subject?: string;
  headerNames?: string[];
  listUnsubscribe?: boolean;
  autoSubmitted?: string;
  precedence?: string;
}): { automated: boolean; reason?: string } {
  const from = (fields.from ?? "").toLowerCase();
  const subject = (fields.subject ?? "").toLowerCase();

  // RFC 3834: the header exists precisely to mark automatic messages.
  if (fields.autoSubmitted && fields.autoSubmitted.toLowerCase() !== "no") {
    return { automated: true, reason: "Auto-Submitted-Header" };
  }
  if (fields.listUnsubscribe) {
    return { automated: true, reason: "Newsletter (List-Unsubscribe)" };
  }
  if (["bulk", "junk", "list"].includes((fields.precedence ?? "").toLowerCase())) {
    return { automated: true, reason: "Precedence: " + fields.precedence };
  }
  // Matched against the local part rather than the whole address: a person
  // called "Liston" must not look like a mailing list, and "notifications@"
  // must match even though it is plural — an earlier word-boundary pattern for
  // the singular silently missed every Teamleader notification.
  const local = from.split("@")[0] ?? "";
  const AUTOMATED_LOCAL: [RegExp, string][] = [
    [/^no[-_.]?reply/, "No-Reply-Absender"],
    [/^do[-_.]?not[-_.]?reply/, "No-Reply-Absender"],
    [/^mailer[-_.]?daemon/, "Systemadresse"],
    [/^postmaster/, "Systemadresse"],
    [/^bounces?[-_.]?/, "Systemadresse"],
    [/^notifications?([-_.]|$)/, "Benachrichtigungsadresse"],
    [/^notify([-_.]|$)/, "Benachrichtigungsadresse"],
    [/^newsletters?([-_.]|$)/, "Newsletter-Absender"],
    [/^mailings?([-_.]|$)/, "Newsletter-Absender"],
    [/^invoicing([-_.]|$)/, "Rechnungsautomatik"],
    [/^billing([-_.]|$)/, "Rechnungsautomatik"],
    [/^automat/, "Automatikadresse"],
  ];
  for (const [pattern, reason] of AUTOMATED_LOCAL) {
    if (pattern.test(local)) return { automated: true, reason };
  }
  if (/@no[-_.]?reply\./.test(from)) {
    return { automated: true, reason: "No-Reply-Absender" };
  }
  if (/^(undelivered mail|mail delivery|zustellung fehlgeschlagen|automatische antwort|automatic reply|out of office|abwesenheit)/.test(subject)) {
    return { automated: true, reason: "Betreff deutet auf Automatik" };
  }
  return { automated: false };
}
