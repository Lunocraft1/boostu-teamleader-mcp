/**
 * Consent page.
 *
 * This is the only interactive part of the authorization server. There is one
 * user, so "login" is a single password checked against a scrypt hash from the
 * environment — no user table, no session store. Approving the request mints
 * the authorization code and redirects back to the client.
 */

import { Router, type Request, type Response } from "express";
import express from "express";
import { rateLimit } from "express-rate-limit";
import type { HttpConfig } from "./config.js";
import { verifyPassword } from "./password.js";
import type { OAuthStore, PendingAuthRecord } from "./store.js";

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
  label { display: block; font-size: .9rem; font-weight: 600; margin: 1.25rem 0 .35rem; }
  input { width: 100%; box-sizing: border-box; padding: .6rem .7rem; font-size: 1rem;
          border: 1px solid #d6d3d1; border-radius: 8px; background: inherit; color: inherit; }
  button { width: 100%; margin-top: 1rem; padding: .7rem; font-size: 1rem; font-weight: 600;
           border: 0; border-radius: 8px; background: #c2410c; color: #fff; cursor: pointer; }
  .err { margin: 1rem 0 0; padding: .6rem .7rem; border-radius: 8px;
         background: #fef2f2; color: #991b1b; font-size: .9rem; }
  @media (prefers-color-scheme: dark) { .err { background: #45191a; color: #fca5a5; } }
  .muted { font-size: .82rem; opacity: .7; margin-top: 1rem; }
</style>
</head>
<body><main>${body}</main></body>
</html>`;
}

function consentForm(record: PendingAuthRecord, config: HttpConfig, error?: string): string {
  // The redirect URI host is shown because the MCP spec requires the
  // authorization server to display where the code will be sent.
  const redirectHost = new URL(record.redirectUri).host;
  const scopes = record.scopes.length ? record.scopes.join(", ") : "(keine)";
  return page(`
  <h1>Zugriff auf Teamleader freigeben</h1>
  <p style="font-size:.9rem;margin:0">Ein MCP-Client möchte im Namen dieses Servers auf die
  Teamleader-Focus-Daten zugreifen.</p>
  <dl>
    <dt>Client</dt><dd>${escapeHtml(record.clientName)}</dd>
    <dt>Weiterleitung an</dt><dd>${escapeHtml(redirectHost)}</dd>
    <dt>Berechtigungen</dt><dd>${escapeHtml(scopes)}</dd>
    <dt>Ressource</dt><dd>${escapeHtml(record.resource ?? config.resource)}</dd>
  </dl>
  ${error ? `<p class="err">${escapeHtml(error)}</p>` : ""}
  <form method="post" action="/consent">
    <input type="hidden" name="rid" value="${escapeHtml(record.requestId)}">
    <label for="password">Passwort</label>
    <input id="password" name="password" type="password" autocomplete="current-password"
           autofocus required>
    <button type="submit">Freigeben</button>
  </form>
  <p class="muted">Die Freigabe gilt bis sie im Client widerrufen wird.</p>
  `);
}

export function consentRouter(store: OAuthStore, config: HttpConfig): Router {
  const router = Router();
  router.use(express.urlencoded({ extended: false }));

  // Brute-force protection for the single password. Deliberately tighter than
  // the OAuth endpoint limits.
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
      res
        .status(400)
        .send(
          page(
            `<h1>Anfrage abgelaufen</h1><p style="font-size:.9rem">Diese Autorisierungsanfrage ist
             nicht mehr gültig. Bitte den Verbindungsvorgang im Client neu starten.</p>`
          )
        );
      return;
    }
    res.status(200).send(consentForm(record, config));
  });

  router.post("/", loginLimiter, (req: Request, res: Response) => {
    const rid = typeof req.body?.rid === "string" ? req.body.rid : "";
    const password = typeof req.body?.password === "string" ? req.body.password : "";
    const record = rid ? store.getPendingAuth(rid) : undefined;
    res.setHeader("Cache-Control", "no-store");

    if (!record) {
      res
        .status(400)
        .send(
          page(
            `<h1>Anfrage abgelaufen</h1><p style="font-size:.9rem">Bitte den Verbindungsvorgang
             im Client neu starten.</p>`
          )
        );
      return;
    }

    if (!verifyPassword(password, config.consentPasswordHash)) {
      // Re-render rather than redirecting the client with access_denied: a typo
      // should not tear down the whole OAuth flow.
      console.warn(`[auth] failed consent password attempt from ${req.ip}`);
      res.status(401).send(consentForm(record, config, "Falsches Passwort."));
      return;
    }

    const code = store.createAuthCode({
      clientId: record.clientId,
      redirectUri: record.redirectUri,
      codeChallenge: record.codeChallenge,
      scopes: record.scopes,
      resource: record.resource,
    });
    store.deletePendingAuth(record.requestId);

    const target = new URL(record.redirectUri);
    target.searchParams.set("code", code);
    if (record.state !== undefined) target.searchParams.set("state", record.state);
    // RFC 9207: lets the client confirm which authorization server answered.
    target.searchParams.set("iss", config.baseUrl);

    console.log(`[auth] authorization code issued to client ${record.clientId}`);
    res.redirect(302, target.href);
  });

  return router;
}
