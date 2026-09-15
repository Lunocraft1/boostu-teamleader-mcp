/**
 * Consent page.
 *
 * The only interactive part of the authorization server. Accounts come from
 * the UserStore (configuration, not code), so a second person can be added
 * later without touching this file. While exactly one account exists the name
 * field may be left empty, which keeps the login to a single box today and
 * still works unchanged once there are two.
 */

import { Router, type Request, type Response } from "express";
import express from "express";
import { rateLimit } from "express-rate-limit";
import { endpointForResource, type HttpConfig } from "./config.js";
import type { OAuthStore, PendingAuthRecord } from "./store.js";
import type { UserStore } from "./users.js";

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function page(body: string): string {
  return `<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Zugriff freigeben</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; margin: 0;
         min-height: 100vh; display: grid; place-items: center; background: #f6f5f4; color: #1c1917; }
  @media (prefers-color-scheme: dark) { body { background: #17181a; color: #f5f5f4; } }
  main { width: min(28rem, calc(100vw - 2rem)); background: #fff; border-radius: 12px;
         padding: 1.75rem; box-shadow: 0 1px 3px rgba(0,0,0,.12), 0 8px 24px rgba(0,0,0,.08); }
  @media (prefers-color-scheme: dark) { main { background: #232427; box-shadow: none; border: 1px solid #34353a; } }
  h1 { font-size: 1.15rem; margin: 0 0 .75rem; }
  dl { margin: 1rem 0; font-size: .9rem; }
  dt { font-weight: 600; margin-top: .6rem; }
  dd { margin: .1rem 0 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
  label { display: block; font-size: .9rem; font-weight: 600; margin: 1.1rem 0 .35rem; }
  input { width: 100%; box-sizing: border-box; padding: .6rem .7rem; font-size: 1rem;
          border: 1px solid #d6d3d1; border-radius: 8px; background: inherit; color: inherit; }
  button { width: 100%; margin-top: 1rem; padding: .7rem; font-size: 1rem; font-weight: 600;
           border: 0; border-radius: 8px; background: #c2410c; color: #fff; cursor: pointer; }
  .err { margin: 1rem 0 0; padding: .6rem .7rem; border-radius: 8px;
         background: #fef2f2; color: #991b1b; font-size: .9rem; }
  @media (prefers-color-scheme: dark) { .err { background: #45191a; color: #fca5a5; } }
  .badge { display: inline-block; padding: .15rem .5rem; border-radius: 999px; font-size: .78rem;
           font-weight: 600; background: #ecfdf5; color: #065f46; }
  @media (prefers-color-scheme: dark) { .badge { background: #06281f; color: #6ee7b7; } }
  .badge.rw { background: #fff7ed; color: #9a3412; }
  @media (prefers-color-scheme: dark) { .badge.rw { background: #3a2008; color: #fdba74; } }
  .muted { font-size: .82rem; opacity: .7; margin-top: 1rem; }
</style>
</head>
<body><main>${body}</main></body>
</html>`;
}

function consentForm(
  record: PendingAuthRecord,
  config: HttpConfig,
  users: UserStore,
  error?: string
): string {
  // The redirect URI host is shown because the MCP spec requires the
  // authorization server to display where the code will be sent.
  const redirectHost = new URL(record.redirectUri).host;
  const endpoint = record.resource
    ? endpointForResource(config, record.resource)
    : config.work;
  const badge = endpoint?.readOnly
    ? '<span class="badge">nur lesen</span>'
    : '<span class="badge rw">lesen und schreiben</span>';

  const nameField = users.isSingleUser
    ? ""
    : `
    <label for="username">Benutzername</label>
    <input id="username" name="username" type="text" autocomplete="username" required>`;

  return page(`
  <h1>Zugriff auf Teamleader freigeben</h1>
  <p style="font-size:.9rem;margin:0">Ein Programm möchte über diesen Server auf Deine
  Teamleader-Daten zugreifen.</p>
  <dl>
    <dt>Programm</dt><dd>${escapeHtml(record.clientName)}</dd>
    <dt>Weiterleitung an</dt><dd>${escapeHtml(redirectHost)}</dd>
    <dt>Zugang</dt><dd>${badge} ${escapeHtml(endpoint?.name ?? "unbekannt")}</dd>
    <dt>Adresse</dt><dd>${escapeHtml(record.resource ?? config.work.resource)}</dd>
  </dl>
  ${error ? `<p class="err">${escapeHtml(error)}</p>` : ""}
  <form method="post" action="/consent">
    <input type="hidden" name="rid" value="${escapeHtml(record.requestId)}">${nameField}
    <label for="password">Passwort</label>
    <input id="password" name="password" type="password" autocomplete="current-password"
           autofocus required>
    <button type="submit">Freigeben</button>
  </form>
  <p class="muted">Die Freigabe gilt, bis Du sie im Programm widerrufst.</p>
  `);
}

function expiredPage(): string {
  return page(
    `<h1>Anfrage abgelaufen</h1><p style="font-size:.9rem">Diese Anfrage ist nicht mehr
     gültig. Bitte starte das Verbinden im Programm noch einmal.</p>`
  );
}

export function consentRouter(store: OAuthStore, config: HttpConfig, users: UserStore): Router {
  const router = Router();
  router.use(express.urlencoded({ extended: false }));

  // Brute-force protection for the login. Deliberately tighter than the OAuth
  // endpoint limits.
  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: "Zu viele Fehlversuche. Bitte später erneut versuchen.",
  });

  router.get("/", (req: Request, res: Response) => {
    const rid = typeof req.query.rid === "string" ? req.query.rid : "";
    const record = rid ? store.getPendingAuth(rid) : undefined;
    res.setHeader("Cache-Control", "no-store");
    if (!record) {
      res.status(400).send(expiredPage());
      return;
    }
    res.status(200).send(consentForm(record, config, users));
  });

  router.post("/", loginLimiter, (req: Request, res: Response) => {
    const body = req.body as Record<string, unknown> | undefined;
    const rid = typeof body?.rid === "string" ? body.rid : "";
    const password = typeof body?.password === "string" ? body.password : "";
    const username = typeof body?.username === "string" ? body.username : undefined;
    const record = rid ? store.getPendingAuth(rid) : undefined;
    res.setHeader("Cache-Control", "no-store");

    if (!record) {
      res.status(400).send(expiredPage());
      return;
    }

    const authenticated = users.verify(username, password);
    if (!authenticated) {
      // Re-render rather than redirecting the client with access_denied: a typo
      // should not tear down the whole OAuth flow.
      console.warn(
        `[auth] failed consent login from ${req.ip}` +
          (username ? ` for "${username}"` : "")
      );
      res
        .status(401)
        .send(
          consentForm(
            record,
            config,
            users,
            users.isSingleUser ? "Falsches Passwort." : "Benutzername oder Passwort falsch."
          )
        );
      return;
    }

    const code = store.createAuthCode({
      clientId: record.clientId,
      redirectUri: record.redirectUri,
      codeChallenge: record.codeChallenge,
      scopes: record.scopes,
      resource: record.resource,
      username: authenticated,
    });
    store.deletePendingAuth(record.requestId);

    const target = new URL(record.redirectUri);
    target.searchParams.set("code", code);
    if (record.state !== undefined) target.searchParams.set("state", record.state);
    // RFC 9207: lets the client confirm which authorization server answered.
    target.searchParams.set("iss", config.baseUrl);

    console.log(
      `[auth] authorization code issued to client ${record.clientId} ` +
        `for ${authenticated} on ${record.resource ?? config.work.resource}`
    );
    res.redirect(302, target.href);
  });

  return router;
}
