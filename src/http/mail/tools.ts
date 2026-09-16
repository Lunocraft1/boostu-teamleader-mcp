/**
 * Mail reading tools (group "mail"), strictly separated from the Teamleader
 * tools and strictly read-only.
 *
 * What these deliberately do NOT do:
 *
 *  - They never change mailbox state. Mailboxes are opened read-only and
 *    content is fetched with BODY.PEEK, so a briefing run cannot mark a
 *    customer's mail as read.
 *  - They never pull the whole mailbox. Every query is bounded by a time window
 *    that is clamped to MAIL_MAX_LOOKBACK_DAYS.
 *  - They never hand over full threads or attachments. The agreed data scope is
 *    sender, subject, date and a shortened body; attachments appear as filename
 *    and size only.
 *  - They never report a failure as an empty result. "Nothing new" and "cannot
 *    reach the mailbox" are different answers and are always distinguishable.
 */

import type { ImapFlow, MessageStructureObject } from "imapflow";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  MailUnavailableError,
  checkHealth,
  describeFailure,
  resolveSince,
  withConnection,
  withMailbox,
  type MailConfig,
} from "./imap.js";
import { extractBody, isAutomated } from "./text.js";
import { decodeBodyPart } from "./decode.js";

export const MAIL_READ_TOOLS = [
  "mail_health",
  "mail_inbox_since",
  "mail_spam",
  "mail_message",
  "mail_thread_previous",
] as const;

const MAILBOX = {
  inbox: "INBOX",
  drafts: "Drafts",
  sent: "Sent",
  spam: "Spam",
  all: "All Mail",
} as const;

/** Headers worth having: automation markers plus thread identity. */
const WANTED_HEADERS = [
  "list-unsubscribe",
  "auto-submitted",
  "precedence",
  "message-id",
  "in-reply-to",
  "references",
  "reply-to",
];

function text(payload: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(payload) }] };
}

function failure(message: string) {
  return { content: [{ type: "text" as const, text: message }], isError: true as const };
}

/** Wraps a tool body so every mailbox failure is reported with its cause. */
async function guard<T>(run: () => Promise<T>) {
  try {
    return text(await run());
  } catch (error) {
    if (error instanceof MailUnavailableError) return failure(describeFailure(error));
    return failure(`Postfach-Fehler: ${(error as Error).message}`);
  }
}

/** ImapFlow types envelope dates as Date | string; normalise to ISO or undefined. */
function toIso(value: Date | string | undefined): string | undefined {
  if (!value) return undefined;
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

function addr(list?: { name?: string; address?: string }[]): string {
  if (!list?.length) return "";
  return list
    .map((a) => (a.name ? `${a.name} <${a.address ?? ""}>` : (a.address ?? "")))
    .join(", ");
}

function firstAddress(list?: { name?: string; address?: string }[]): string {
  return list?.[0]?.address ?? "";
}

interface TextPart {
  part: string;
  type: string;
  /** Content-Transfer-Encoding, needed to decode a batched bodyParts fetch. */
  encoding?: string;
  charset?: string;
}

/** Walks the MIME tree for the part best suited to reading. */
function findTextPart(node?: MessageStructureObject): TextPart | undefined {
  if (!node) return undefined;
  const preferred: TextPart[] = [];
  const fallback: TextPart[] = [];

  const walk = (n: MessageStructureObject): void => {
    const type = (n.type ?? "").toLowerCase();
    const isAttachment = (n.disposition ?? "").toLowerCase() === "attachment";
    if (!isAttachment && n.part) {
      const entry: TextPart = {
        part: n.part,
        type,
        encoding: n.encoding,
        charset: n.parameters?.charset,
      };
      if (type === "text/plain") preferred.push(entry);
      else if (type === "text/html") fallback.push(entry);
    }
    for (const child of n.childNodes ?? []) walk(child);
  };
  walk(node);

  // A single-part message has no part number; "1" addresses its only body.
  if (!preferred.length && !fallback.length) {
    const type = (node.type ?? "").toLowerCase();
    if (type.startsWith("text/")) {
      return { part: "1", type, encoding: node.encoding, charset: node.parameters?.charset };
    }
    return undefined;
  }
  return preferred[0] ?? fallback[0];
}

interface AttachmentMeta {
  name: string;
  bytes?: number;
  type?: string;
}

/** Attachment metadata only — never the content. */
function collectAttachments(node?: MessageStructureObject): AttachmentMeta[] {
  if (!node) return [];
  const found: AttachmentMeta[] = [];
  const walk = (n: MessageStructureObject): void => {
    const disposition = (n.disposition ?? "").toLowerCase();
    const name = n.dispositionParameters?.filename ?? n.parameters?.name;
    if (name && (disposition === "attachment" || disposition === "inline" || !n.childNodes)) {
      if (disposition === "attachment" || name) {
        found.push({ name, bytes: n.size, type: n.type });
      }
    }
    for (const child of n.childNodes ?? []) walk(child);
  };
  walk(node);
  // Deduplicate: the same filename can appear via both parameter sets.
  const seen = new Set<string>();
  return found.filter((a) => {
    const key = `${a.name}:${a.bytes ?? ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function headerValue(headers: Map<string, string> | undefined, key: string): string | undefined {
  return headers?.get(key) ?? undefined;
}

/**
 * Parses the raw header block ImapFlow returns for `headers: [...]`.
 *
 * Folded continuation lines are joined, because References in particular is
 * routinely wrapped across several lines and a naive split loses most of it.
 */
function parseHeaders(raw?: Buffer | string): Map<string, string> {
  const map = new Map<string, string>();
  if (!raw) return map;
  const lines = raw.toString("utf8").replace(/\r\n/g, "\n").split("\n");
  let current = "";
  const flush = (): void => {
    const idx = current.indexOf(":");
    if (idx > 0) {
      const key = current.slice(0, idx).trim().toLowerCase();
      const value = current.slice(idx + 1).trim();
      map.set(key, map.has(key) ? `${map.get(key)} ${value}` : value);
    }
    current = "";
  };
  for (const line of lines) {
    if (/^[ \t]/.test(line) && current) {
      current += " " + line.trim();
    } else {
      if (current) flush();
      current = line;
    }
  }
  if (current) flush();
  return map;
}

/** Message-IDs extracted from an In-Reply-To or References value. */
function messageIds(value?: string): string[] {
  if (!value) return [];
  return [...value.matchAll(/<([^>]+)>/g)].map((m) => m[1]);
}

/**
 * Message-IDs that already have a reply or a waiting draft.
 *
 * Used to keep a second briefing run from producing a second draft for the
 * same mail — the failure mode the brief calls out explicitly.
 *
 * Runs on an existing connection and fetches envelopes only: In-Reply-To is
 * part of the envelope, so the much larger header block is not needed. Doing
 * this on its own connection per folder cost three TCP/TLS handshakes and was
 * a measurable part of a listing that timed out.
 */
async function referencedElsewhere(
  client: ImapFlow,
  since: Date
): Promise<{ drafted: Set<string>; replied: Set<string> }> {
  const drafted = new Set<string>();
  const replied = new Set<string>();

  const scan = async (path: string, into: Set<string>): Promise<void> => {
    try {
      await client.mailboxOpen(path, { readOnly: true });
      const uids = (await client.search({ since }, { uid: true })) || [];
      if (!uids.length) return;
      for await (const msg of client.fetch(
        { uid: uids.join(",") },
        { uid: true, envelope: true },
        { uid: true }
      )) {
        const parent = msg.envelope?.inReplyTo;
        if (parent) into.add(parent.replace(/[<>]/g, ""));
      }
    } catch {
      // A missing or unreadable Drafts/Sent folder must not fail the listing;
      // the flags simply stay unknown.
    }
  };

  await scan(MAILBOX.drafts, drafted);
  await scan(MAILBOX.sent, replied);
  return { drafted, replied };
}

/**
 * Fetches the readable body part for many messages in as few commands as
 * possible.
 *
 * Downloading per message cost one IMAP round trip each, which made a listing
 * of 25 messages exceed the request timeout. Messages are instead grouped by
 * the part number their text lives in — in practice two or three distinct
 * values across a whole inbox — and each group is fetched in one command.
 */
async function fetchBodiesBatched(
  client: ImapFlow,
  targets: (TextPart & { uid: number })[],
  maxBytes: number
): Promise<Map<number, { plain?: string; html?: string }>> {
  const result = new Map<number, { plain?: string; html?: string }>();

  // Grouped by part number *and* encoding, because the decode step differs and
  // a bodyParts fetch returns the part still in its transfer encoding.
  const groups = new Map<string, { target: TextPart; uids: number[] }>();
  for (const t of targets) {
    const key = `${t.part}|${t.encoding ?? ""}|${t.charset ?? ""}|${t.type}`;
    const entry = groups.get(key) ?? { target: t, uids: [] };
    entry.uids.push(t.uid);
    groups.set(key, entry);
  }

  for (const { target, uids } of groups.values()) {
    try {
      for await (const msg of client.fetch(
        { uid: uids.join(",") },
        { uid: true, bodyParts: [target.part] },
        { uid: true }
      )) {
        const raw = msg.bodyParts?.get(target.part);
        if (!raw) continue;
        const body = decodeBodyPart(
          raw.subarray(0, maxBytes),
          target.encoding,
          target.charset
        );
        result.set(msg.uid, target.type === "text/html" ? { html: body } : { plain: body });
      }
    } catch {
      // Leave the preview empty for this group rather than failing the listing.
    }
  }
  return result;
}

async function downloadText(
  client: ImapFlow,
  uid: number,
  structure: MessageStructureObject | undefined,
  maxBytes: number
): Promise<{ plain?: string; html?: string }> {
  const target = findTextPart(structure);
  if (!target) return {};
  try {
    const { content } = await client.download(String(uid), target.part, { uid: true, maxBytes });
    if (!content) return {};
    const chunks: Buffer[] = [];
    for await (const chunk of content) chunks.push(Buffer.from(chunk));
    const body = Buffer.concat(chunks).toString("utf8");
    return target.type === "text/html" ? { html: body } : { plain: body };
  } catch {
    return {};
  }
}

export function registerMailTools(server: McpServer, config: MailConfig | undefined): void {
  // ── Health ────────────────────────────────────────────────────────────────

  server.tool(
    "mail_health",
    "Checks whether the mailbox can actually be reached and read. Call this " +
      "before reporting that there is no new mail — an empty mail section and a " +
      "broken mailbox connection are different statements.",
    {},
    async () => {
      const health = await checkHealth(config);
      if (!health.reachable) {
        return failure(
          `POSTFACH NICHT ABRUFBAR — dies ist NICHT die Aussage "keine neuen Mails". ` +
            `${health.detail ?? ""}`
        );
      }
      return text(health);
    }
  );

  if (!config) {
    // Without credentials the remaining tools cannot do anything useful, and a
    // tool that always fails is worse than one that is absent.
    return;
  }

  // ── Inbox ─────────────────────────────────────────────────────────────────

  server.tool(
    "mail_inbox_since",
    "New mail in the inbox since a point in time, with sender, subject, date and " +
      "a shortened preview. Flags whether a message is automated, already " +
      "answered, or already has a draft waiting. Use this for the mail section " +
      "of a briefing. Read-only: nothing is marked as read.",
    {
      since: z
        .string()
        .optional()
        .describe("ISO 8601 cut-off, e.g. 2026-09-16T06:00:00+02:00. Defaults to 24h ago."),
      limit: z.number().int().positive().max(100).optional().describe("Max messages (default 40)"),
      preview_chars: z
        .number()
        .int()
        .min(0)
        .max(2000)
        .optional()
        .describe("Preview length; 0 omits the body entirely (default 300)"),
      only_unread: z.boolean().optional().describe("Restrict to unread messages"),
    },
    async (p) =>
      guard(async () => {
        const { since, clamped } = resolveSince(config, p.since);
        const limit = p.limit ?? 40;
        const previewChars = p.preview_chars ?? 300;

        // One connection for all three mailboxes. Opening a connection per
        // folder cost three TLS handshakes and helped push an earlier version
        // past the request timeout.
        return await withConnection(config, async (client) => {
          const { drafted, replied } = await referencedElsewhere(client, since);

          await client.mailboxOpen(MAILBOX.inbox, { readOnly: true });
          // IMAP SINCE has date granularity, so the exact cut-off is applied
          // again below on the real timestamp.
          const criteria = p.only_unread ? { since, seen: false } : { since };
          const uids = (await client.search(criteria, { uid: true })) || [];
          if (uids.length === 0) {
            return {
              status: "ok" as const,
              since: since.toISOString(),
              clamped,
              count: 0,
              messages: [],
              note: "Keine neuen Nachrichten in diesem Zeitraum (Postfach war erreichbar).",
            };
          }

          // Newest first, and only as many as asked for — the metadata pass is
          // cheap but the body pass is not.
          const newestFirst = [...uids].sort((a, b) => b - a);
          const selected = newestFirst.slice(0, Math.min(limit * 2, newestFirst.length));

          interface Row {
            row: Record<string, unknown>;
            at?: Date;
            part?: TextPart & { uid: number };
          }
          const collected: Row[] = [];

          for await (const msg of client.fetch(
            { uid: selected.join(",") },
            {
              uid: true,
              envelope: true,
              flags: true,
              internalDate: true,
              size: true,
              bodyStructure: true,
              headers: WANTED_HEADERS,
            },
            { uid: true }
          )) {
            const when = msg.envelope?.date ?? msg.internalDate;
            const at = when ? new Date(when) : undefined;
            if (at && at.getTime() < since.getTime()) continue;

            const headers = parseHeaders(msg.headers);
            const messageId = (msg.envelope?.messageId ?? headerValue(headers, "message-id") ?? "")
              .replace(/[<>]/g, "");
            const auto = isAutomated({
              from: firstAddress(msg.envelope?.from),
              subject: msg.envelope?.subject,
              listUnsubscribe: Boolean(headerValue(headers, "list-unsubscribe")),
              autoSubmitted: headerValue(headers, "auto-submitted"),
              precedence: headerValue(headers, "precedence"),
            });
            const attachments = collectAttachments(msg.bodyStructure);
            const flags = msg.flags ?? new Set<string>();

            const row: Record<string, unknown> = {
              uid: msg.uid,
              von: addr(msg.envelope?.from),
              betreff: msg.envelope?.subject ?? "(kein Betreff)",
              datum: toIso(when),
              ungelesen: !flags.has("\\Seen"),
              beantwortet: flags.has("\\Answered") || (messageId ? replied.has(messageId) : false),
              entwurf_vorhanden: messageId ? drafted.has(messageId) : false,
              automatisch: auto.automated,
              bytes: msg.size,
            };
            if (auto.reason) row.automatisch_grund = auto.reason;
            if (messageId) row.message_id = messageId;
            if (attachments.length) {
              row.anhaenge = attachments.map((a) => ({ name: a.name, bytes: a.bytes }));
            }
            if (msg.envelope?.inReplyTo) row.ist_antwort_auf = msg.envelope.inReplyTo;

            const target = findTextPart(msg.bodyStructure);
            collected.push({
              row,
              at,
              part: target ? { ...target, uid: msg.uid } : undefined,
            });
            if (collected.length >= limit) break;
          }

          collected.sort((a, b) => (b.at?.getTime() ?? 0) - (a.at?.getTime() ?? 0));

          if (previewChars > 0 && collected.length) {
            const bodies = await fetchBodiesBatched(
              client,
              collected.map((c) => c.part).filter((t): t is NonNullable<typeof t> => Boolean(t)),
              64 * 1024
            );
            for (const entry of collected) {
              const body = bodies.get(entry.row.uid as number);
              if (!body) continue;
              const extract = extractBody(body.plain, body.html, previewChars);
              entry.row.vorschau = extract.text;
              if (extract.truncated) entry.row.vorschau_gekuerzt = true;
            }
          }

          return {
            status: "ok" as const,
            since: since.toISOString(),
            clamped,
            count: collected.length,
            ...(uids.length > collected.length
              ? { weitere_vorhanden: uids.length - collected.length }
              : {}),
            messages: collected.map((c) => c.row),
          };
        });
      })
  );

  // ── Spam ──────────────────────────────────────────────────────────────────

  server.tool(
    "mail_spam",
    "How much is sitting in the spam folder, and optionally what. Proton runs " +
      "the spam folder itself; this only counts and reads it.",
    {
      list: z.boolean().optional().describe("Also list the messages (default: count only)"),
      since: z.string().optional().describe("ISO 8601 cut-off. Defaults to 24h ago."),
      limit: z.number().int().positive().max(100).optional().describe("Max messages when listing"),
    },
    async (p) =>
      guard(async () => {
        const { since, clamped } = resolveSince(config, p.since);
        return await withMailbox(config, MAILBOX.spam, async (client, mailbox) => {
          const uids = (await client.search({ since }, { uid: true })) || [];
          const result: Record<string, unknown> = {
            status: "ok",
            ordner_gesamt: mailbox.exists,
            im_zeitraum: uids.length,
            since: since.toISOString(),
            clamped,
          };
          if (!p.list || uids.length === 0) return result;

          const rows: Record<string, unknown>[] = [];
          const limit = p.limit ?? 30;
          for await (const msg of client.fetch(
            { uid: [...uids].sort((a, b) => b - a).join(",") },
            { uid: true, envelope: true, internalDate: true },
            { uid: true }
          )) {
            rows.push({
              uid: msg.uid,
              von: addr(msg.envelope?.from),
              betreff: msg.envelope?.subject ?? "(kein Betreff)",
              datum: toIso(msg.envelope?.date ?? msg.internalDate),
            });
            if (rows.length >= limit) break;
          }
          result.messages = rows;
          return result;
        });
      })
  );

  // ── Single message ────────────────────────────────────────────────────────

  server.tool(
    "mail_message",
    "One message in full-but-shortened form: sender, recipients, subject, date " +
      "and the readable body with quoted history and signature removed. " +
      "Attachments are listed by name and size only, never fetched.",
    {
      uid: z.number().int().positive().describe("UID from mail_inbox_since"),
      mailbox: z
        .enum(["INBOX", "Spam", "Drafts", "Sent", "All Mail"])
        .optional()
        .describe("Defaults to INBOX"),
      body_chars: z
        .number()
        .int()
        .positive()
        .max(8000)
        .optional()
        .describe("Maximum body characters (default 1500)"),
    },
    async (p) =>
      guard(async () => {
        const path = p.mailbox ?? MAILBOX.inbox;
        const bodyChars = p.body_chars ?? 1500;
        return await withMailbox(config, path, async (client) => {
          const list = await client.fetchAll(
            { uid: String(p.uid) },
            {
              uid: true,
              envelope: true,
              flags: true,
              internalDate: true,
              size: true,
              bodyStructure: true,
              headers: WANTED_HEADERS,
            },
            { uid: true }
          );
          const msg = list?.[0];
          if (!msg) {
            return { status: "not_found" as const, uid: p.uid, mailbox: path };
          }
          const headers = parseHeaders(msg.headers);
          const body = await downloadText(client, msg.uid, msg.bodyStructure, 256 * 1024);
          const extract = extractBody(body.plain, body.html, bodyChars);
          const auto = isAutomated({
            from: firstAddress(msg.envelope?.from),
            subject: msg.envelope?.subject,
            listUnsubscribe: Boolean(headerValue(headers, "list-unsubscribe")),
            autoSubmitted: headerValue(headers, "auto-submitted"),
            precedence: headerValue(headers, "precedence"),
          });
          const flags = msg.flags ?? new Set<string>();

          return {
            status: "ok" as const,
            uid: msg.uid,
            mailbox: path,
            von: addr(msg.envelope?.from),
            antwort_an: addr(msg.envelope?.replyTo) || headerValue(headers, "reply-to") || undefined,
            an: addr(msg.envelope?.to),
            cc: addr(msg.envelope?.cc) || undefined,
            betreff: msg.envelope?.subject ?? "(kein Betreff)",
            datum: toIso(msg.envelope?.date ?? msg.internalDate),
            message_id: (msg.envelope?.messageId ?? "").replace(/[<>]/g, "") || undefined,
            ist_antwort_auf: msg.envelope?.inReplyTo ?? undefined,
            ungelesen: !flags.has("\\Seen"),
            beantwortet: flags.has("\\Answered"),
            automatisch: auto.automated,
            automatisch_grund: auto.reason,
            text: extract.text,
            text_gekuerzt: extract.truncated,
            zitat_entfernt: extract.quoteRemoved,
            signatur_entfernt: extract.signatureRemoved,
            anhaenge: collectAttachments(msg.bodyStructure).map((a) => ({
              name: a.name,
              bytes: a.bytes,
              typ: a.type,
            })),
          };
        });
      })
  );

  // ── Thread context ────────────────────────────────────────────────────────

  server.tool(
    "mail_thread_previous",
    "The one previous message of the same conversation, if there is one. Use " +
      "this sparingly — it is for the case where a reply cannot be understood " +
      "without what came before. Returns nothing for a message that starts a " +
      "thread.",
    {
      uid: z.number().int().positive().describe("UID from mail_inbox_since"),
      mailbox: z.enum(["INBOX", "Spam", "All Mail"]).optional().describe("Defaults to INBOX"),
      body_chars: z.number().int().positive().max(4000).optional().describe("Default 800"),
    },
    async (p) =>
      guard(async () => {
        const path = p.mailbox ?? MAILBOX.inbox;
        const bodyChars = p.body_chars ?? 800;

        // Step 1: which message does this one answer?
        const parentId = await withMailbox(config, path, async (client) => {
          const list = await client.fetchAll(
            { uid: String(p.uid) },
            { uid: true, envelope: true, headers: WANTED_HEADERS },
            { uid: true }
          );
          const msg = list?.[0];
          if (!msg) return undefined;
          const headers = parseHeaders(msg.headers);
          const direct = msg.envelope?.inReplyTo ?? headerValue(headers, "in-reply-to");
          if (direct) return messageIds(direct.startsWith("<") ? direct : `<${direct}>`)[0];
          // No In-Reply-To: fall back to the last entry of References.
          const refs = messageIds(headerValue(headers, "references"));
          return refs.length ? refs[refs.length - 1] : undefined;
        });

        if (!parentId) {
          return {
            status: "no_previous" as const,
            hinweis: "Diese Nachricht beginnt den Verlauf, es gibt keine Vorgängerin.",
          };
        }

        // Step 2: find it. All Mail covers inbox and sent in one pass.
        return await withMailbox(config, MAILBOX.all, async (client) => {
          const uids =
            (await client.search({ header: { "message-id": parentId } }, { uid: true })) || [];
          if (uids.length === 0) {
            return {
              status: "not_found" as const,
              gesucht: parentId,
              hinweis: "Die Vorgänger-Nachricht liegt nicht mehr im Postfach.",
            };
          }
          const list = await client.fetchAll(
            { uid: String(uids[uids.length - 1]) },
            { uid: true, envelope: true, internalDate: true, bodyStructure: true },
            { uid: true }
          );
          const msg = list?.[0];
          if (!msg) return { status: "not_found" as const, gesucht: parentId };
          const body = await downloadText(client, msg.uid, msg.bodyStructure, 128 * 1024);
          const extract = extractBody(body.plain, body.html, bodyChars);
          return {
            status: "ok" as const,
            von: addr(msg.envelope?.from),
            an: addr(msg.envelope?.to),
            betreff: msg.envelope?.subject ?? "(kein Betreff)",
            datum: toIso(msg.envelope?.date ?? msg.internalDate),
            text: extract.text,
            text_gekuerzt: extract.truncated,
          };
        });
      })
  );
}
