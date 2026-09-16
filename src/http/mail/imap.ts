/**
 * IMAP access to the local Proton Mail Bridge.
 *
 * Two properties matter more than anything else here.
 *
 * **Nothing may change in the mailbox.** Mailboxes are opened read-only, which
 * makes the server refuse to set \Seen, and ImapFlow issues BODY.PEEK rather
 * than BODY for message content. Either alone would do; both together mean a
 * briefing run cannot quietly mark a customer's mail as read.
 *
 * **"Nothing new" and "cannot reach the mailbox" must never look alike.** The
 * Bridge's Proton session expires eventually. If that surfaced as an empty
 * list, the briefing would report a quiet morning on the day it stopped
 * working, which is the worst possible failure. Every failure is therefore
 * classified and reported as an error with a cause, never as an empty result.
 */

import { ImapFlow, AuthenticationFailure, type MailboxObject } from "imapflow";

export interface MailConfig {
  host: string;
  port: number;
  user: string;
  password: string;
  /** Hard cap on how far back a query may look, in days. */
  maxLookbackDays: number;
  /** Sign-off appended under the closing of a generated draft. */
  draftSignature?: string;
}

export type MailFailureReason =
  | "not_configured"
  | "bridge_unreachable"
  | "login_failed"
  | "timeout"
  | "unknown";

/** A failure that must never be mistaken for "no messages". */
export class MailUnavailableError extends Error {
  constructor(
    readonly reason: MailFailureReason,
    message: string
  ) {
    super(message);
    this.name = "MailUnavailableError";
  }
}

const GERMAN_CAUSE: Record<MailFailureReason, string> = {
  not_configured: "Das Postfach ist auf diesem Server nicht eingerichtet.",
  bridge_unreachable:
    "Die Proton-Verbindung (Bridge) antwortet nicht. Läuft der Dienst protonmail-bridge?",
  login_failed:
    "Die Anmeldung am Postfach wurde abgewiesen. Sehr wahrscheinlich ist die " +
    "Proton-Anmeldung der Bridge abgelaufen und muss einmal neu erteilt werden.",
  timeout: "Das Postfach hat nicht rechtzeitig geantwortet.",
  unknown: "Unerwarteter Fehler beim Zugriff auf das Postfach.",
};

/** Human-readable explanation, for the message the model will relay. */
export function describeFailure(error: MailUnavailableError): string {
  return (
    `POSTFACH NICHT ABRUFBAR — dies ist NICHT die Aussage "keine neuen Mails". ` +
    `${GERMAN_CAUSE[error.reason]} (technisch: ${error.message})`
  );
}

export function loadMailConfig(env: NodeJS.ProcessEnv = process.env): MailConfig | undefined {
  const host = env.MAIL_IMAP_HOST?.trim();
  const user = env.MAIL_IMAP_USER?.trim();
  const password = env.MAIL_IMAP_PASSWORD;
  if (!host || !user || !password) return undefined;

  const port = Number(env.MAIL_IMAP_PORT ?? 1143);
  if (!Number.isInteger(port) || port <= 0) {
    throw new Error(`MAIL_IMAP_PORT must be a positive integer, got "${env.MAIL_IMAP_PORT}".`);
  }
  const maxLookbackDays = Number(env.MAIL_MAX_LOOKBACK_DAYS ?? 14);
  if (!Number.isInteger(maxLookbackDays) || maxLookbackDays <= 0) {
    throw new Error("MAIL_MAX_LOOKBACK_DAYS must be a positive integer.");
  }
  return {
    host,
    port,
    user,
    password,
    maxLookbackDays,
    draftSignature: env.MAIL_DRAFT_SIGNATURE?.trim() || undefined,
  };
}

function classify(error: unknown): MailUnavailableError {
  if (error instanceof MailUnavailableError) return error;
  const err = error as NodeJS.ErrnoException & { authenticationFailed?: boolean };
  const message = err?.message ?? String(error);

  if (error instanceof AuthenticationFailure || err?.authenticationFailed) {
    return new MailUnavailableError("login_failed", message);
  }
  if (err?.code === "ECONNREFUSED" || err?.code === "EHOSTUNREACH" || err?.code === "ENOTFOUND") {
    return new MailUnavailableError("bridge_unreachable", `${err.code}: ${message}`);
  }
  if (err?.code === "ETIMEDOUT" || /timed? ?out/i.test(message)) {
    return new MailUnavailableError("timeout", message);
  }
  // The Bridge answers NO [AUTHENTICATIONFAILED] once its Proton session dies.
  if (/authenticat/i.test(message)) {
    return new MailUnavailableError("login_failed", message);
  }
  return new MailUnavailableError("unknown", message);
}

function makeClient(config: MailConfig): ImapFlow {
  return new ImapFlow({
    host: config.host,
    port: config.port,
    // false means: upgrade via STARTTLS when the server offers it, which the
    // Bridge does.
    secure: false,
    auth: { user: config.user, pass: config.password },
    // The Bridge presents a self-signed certificate for the loopback listener.
    // There is no name to verify and the traffic never leaves the host.
    tls: { rejectUnauthorized: false },
    // Connections here are short-lived and command-driven; IDLE would only add
    // round-trips.
    disableAutoIdle: true,
    logger: false,
    clientInfo: { name: "teamleader-mcp-mail" },
  });
}

/**
 * Opens one mailbox read-only, runs `fn`, and always disconnects.
 *
 * @throws MailUnavailableError for every failure, so callers never have to
 *         guess whether an empty result meant "empty" or "broken".
 */
export async function withMailbox<T>(
  config: MailConfig,
  path: string,
  fn: (client: ImapFlow, mailbox: MailboxObject) => Promise<T>
): Promise<T> {
  const client = makeClient(config);
  try {
    await client.connect();
  } catch (error) {
    throw classify(error);
  }
  try {
    const mailbox = await client.mailboxOpen(path, { readOnly: true });
    return await fn(client, mailbox);
  } catch (error) {
    throw classify(error);
  } finally {
    // logout() can itself fail on a half-dead socket; the result is already in
    // hand at that point, so it must not turn a success into an error.
    await client.logout().catch(() => client.close());
  }
}

/** Runs `fn` with an authenticated connection but no mailbox selected. */
export async function withConnection<T>(
  config: MailConfig,
  fn: (client: ImapFlow) => Promise<T>
): Promise<T> {
  const client = makeClient(config);
  try {
    await client.connect();
  } catch (error) {
    throw classify(error);
  }
  try {
    return await fn(client);
  } catch (error) {
    throw classify(error);
  } finally {
    await client.logout().catch(() => client.close());
  }
}

export interface MailHealth {
  reachable: boolean;
  reason?: MailFailureReason;
  detail?: string;
  mailboxes?: number;
  inbox?: { total: number; unseen: number };
}

/**
 * Checks that the mailbox can actually be reached and read.
 *
 * Worth calling at the start of a briefing run: it turns "the mail section is
 * empty" into a definite statement about which of the two possible causes it is.
 */
export async function checkHealth(config: MailConfig | undefined): Promise<MailHealth> {
  if (!config) {
    return { reachable: false, reason: "not_configured", detail: GERMAN_CAUSE.not_configured };
  }
  try {
    return await withConnection(config, async (client) => {
      const list = await client.list();
      const status = await client.status("INBOX", { messages: true, unseen: true });
      return {
        reachable: true,
        mailboxes: list.length,
        inbox: { total: status.messages ?? 0, unseen: status.unseen ?? 0 },
      };
    });
  } catch (error) {
    const failure = classify(error);
    return { reachable: false, reason: failure.reason, detail: describeFailure(failure) };
  }
}

/**
 * Resolves a lookback into an absolute cutoff, clamped to the configured
 * maximum so no single call can walk the whole mailbox.
 */
export function resolveSince(
  config: MailConfig,
  since?: string,
  defaultHours = 24
): { since: Date; clamped: boolean } {
  const now = Date.now();
  const floor = now - config.maxLookbackDays * 86_400_000;

  let requested: number;
  if (since) {
    const parsed = Date.parse(since);
    if (Number.isNaN(parsed)) {
      throw new Error(`"${since}" is not a valid date/time. Use ISO 8601, e.g. 2026-09-16T06:00:00+02:00.`);
    }
    requested = parsed;
  } else {
    requested = now - defaultHours * 3_600_000;
  }

  if (requested < floor) return { since: new Date(floor), clamped: true };
  return { since: new Date(requested), clamped: false };
}
