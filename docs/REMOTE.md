# Remote MCP server (Streamable HTTP + OAuth 2.1)

This fork adds a second entry point, `src/http.ts`, which serves the same tools
as the stdio server over HTTP with an OAuth 2.1 authorization server in front,
so the endpoint can be registered in claude.ai under
**Settings → Connectors → Add custom connector**.

`src/index.ts` (stdio) is unchanged, and `createServer()` is shared. Upstream
changes can be merged without touching any of this.

## Why it is built this way

| Decision | Reason |
|---|---|
| Two endpoints, separated by token audience | The briefing runs unattended on a schedule. A scheduled run that writes to the CRM is visible to customers, so the read-only endpoint must be incapable of writing, not merely expected not to. `/mcp/briefing` serves only non-mutating tools and accepts only tokens minted for its own resource identifier. |
| Accounts in a file, not in code | One user today, but adding a second is a file edit (`npm run user -- add`) rather than a rewrite, and every token records which account approved it. |
| Stateless Streamable HTTP (`sessionIdGenerator: undefined`, `enableJsonResponse: true`) | A fresh transport and `McpServer` per POST means there is no per-connection state to lose on restart. Only tokens persist, and those are in SQLite. |
| No SSE fallback | The GET/SSE stream and protocol-level sessions were removed in MCP revision `2026-07-28`; Claude speaks Streamable HTTP over POST. Adding SSE would mean maintaining a transport that is on its way out. |
| Resource server and authorization server in one process | Claude fetches protected resource metadata from the MCP host and then discovers the authorization server separately. Same host means one certificate, one nginx block, and no second WAF to get wrong. |
| Dynamic Client Registration | Claude has no pre-registered client here. CIMD would also work and avoids a client database, but DCR is what a single-user setup needs and is supported out of the box. |
| Opaque tokens, stored as SHA-256 hashes | No signing keys to manage or rotate, and revocation is a delete. |
| A JSON file, not SQLite | The dataset is a handful of clients and tokens and there is one process by design. A native module such as `better-sqlite3` must be recompiled whenever the host's Node version changes, so an unattended service would eventually stop starting for a reason unrelated to any change here. The file is rewritten atomically (write, then rename). |
| systemd, not Docker | The target host already runs nginx on :80/:443 and three PM2 apps. Docker is not installed, and a container runtime for one Node process buys nothing here. `Type=simple` also guarantees exactly one process, which the Teamleader refresh-token rotation requires. |

## Endpoints

| Path | Auth | Purpose |
|---|---|---|
| `POST /mcp` | Bearer (`teamleader`) | Read/write MCP endpoint for interactive use. |
| `POST /mcp/briefing` | Bearer (`teamleader.read`) | Read-only MCP endpoint for the unattended briefing. |
| `GET /healthz` | none | Liveness, plus resource/issuer and registered-client count. |
| `GET /.well-known/oauth-protected-resource/mcp` | none | RFC 9728 metadata for the read/write endpoint. Also served at the root as a fallback. |
| `GET /.well-known/oauth-protected-resource/mcp/briefing` | none | RFC 9728 metadata for the read-only endpoint. |
| `GET /.well-known/oauth-authorization-server` | none | RFC 8414. |
| `GET|POST /authorize` | none | Authorization endpoint; redirects to the consent page. |
| `GET|POST /consent` | password | Login and consent screen. Shows which endpoint is being authorized and whether it can write. |
| `POST /register` | none | RFC 7591 dynamic client registration. |
| `POST /token` | client | Authorization code and refresh token grants. |
| `POST /revoke` | client | RFC 7009 revocation. |

## Deviations from the SDK's defaults, and why

The SDK ships an OAuth toolkit, but three of its behaviours are wrong for a
Claude connector. All three are handled in this fork:

1. **`invalid_client` must be `401`, not `400`.** The SDK's `authenticateClient`
   answers `400`, which Claude treats as terminal. RFC 6749 §5.2 allows `401`,
   and Claude reacts to it by discarding its stored client and re-registering
   via DCR — the only way a connector recovers after the client record is gone.
   `clientAuthGate` in `src/http/app.ts` runs first and answers `401`.
2. **Protected resource metadata must be served at the root too.** The SDK's
   `mcpAuthMetadataRouter` mounts it only at
   `/.well-known/oauth-protected-resource/mcp`. Clients try that first and then
   fall back to the root, so both are served here.
3. **`requireBearerAuth` does not check the audience.** It validates scopes and
   expiry, but never compares `AuthInfo.resource` to anything. The MCP spec
   requires rejecting a token issued for a different resource, so
   `verifyAccessToken` does that check itself (`src/http/provider.ts`).

Two further details that are easy to get wrong:

- `offline_access` is advertised in the **authorization server** metadata but
  not in the protected resource metadata. Claude appends it to obtain a refresh
  token only when the AS lists it, while the MCP spec says a resource must not
  require it.
- Registered client secrets never expire (`clientSecretExpirySeconds: 0`). The
  SDK's 30-day default would break an unattended connector for no gain.

## The two endpoints

Both are served by the same process over the same Teamleader connection, and
they differ in two independent ways:

1. **Tool set.** `/mcp/briefing` registers only the tools in `BRIEFING_TOOLS`
   (`src/http/readOnly.ts`) — an allowlist of non-mutating tools, so a tool
   upstream adds later is absent until it is named there explicitly. The write
   tools are not merely hidden; they are never registered, so nothing can call
   them.
2. **Token audience.** Each endpoint has its own resource identifier and scope.
   A token minted for the briefing endpoint is refused at `/mcp` with `401
   invalid_token`, and vice versa.

The audience check deliberately runs *before* the scope check. A token for the
wrong resource is `invalid_token` (401), not `insufficient_scope` (403) — the
latter would invite the client to re-authorize for broader permissions, which
is the wrong answer when the token simply belongs to another endpoint.

Register `https://mcp.von-falken.de/mcp/briefing` as the connector for the
scheduled briefing, and `https://mcp.von-falken.de/mcp` for interactive work.

### Known coverage gaps, upstream

These are limits of the upstream repo, not of this fork, and worth knowing
before relying on them:

- **Tasks (Teamleader todos)** can be listed and created, but not changed or
  completed.
- **Events** can be listed, read and created, but not moved or cancelled.
- **Planned calls / follow-ups** (`calls.list`, `calls.add`, `calls.complete`)
  live in the `activities` tool group, which is *not* enabled — and the
  Teamleader integration has no Calls scope ticked, so enabling the group would
  fail with a rights error until that scope is added in the dev portal.
- Write paths in general are, per the upstream maintainer, implemented from the
  documentation and not all verified against a real account. Try each one
  against a dummy record before relying on it.

## Concurrency: the one thing that will silently destroy the setup

Teamleader rotates the refresh token on **every** refresh and accepts each token
exactly once. Two overlapping refreshes therefore invalidate the credential
permanently — the second presents a token the first already spent. Over stdio
this cannot happen; over HTTP, Claude issues parallel tool calls.

Two guards:

- `SerializedTeamleaderAuth` collapses concurrent refreshes in-process into one.
- `lockTokenStore` takes an advisory lock next to `TEAMLEADER_TOKEN_STORE`, so a
  second process using the same credentials fails at boot with a clear error
  instead of corrupting the token store.

**For local testing, register a second Teamleader integration.** Never point a
development instance at the production credentials.

## Deployment (Ubuntu, nginx, systemd)

### 1. DNS

Add an `A` record for the hostname pointing at the server, and confirm it from
outside your network — Claude rejects any hostname that resolves to a private
address, and connectors are IPv4-only:

```bash
dig +short YOUR.DOMAIN.EXAMPLE A   # must return the public IPv4
```

**If you cannot edit the zone of your own domain**, a free dynamic-DNS hostname
works, but only from a provider listed on the
[Public Suffix List](https://publicsuffix.org/list/). Let's Encrypt applies its
rate limits per registered domain, so a provider that is *not* on the list
shares one quota across all of its users worldwide and issuance almost always
fails. Verified at the time of writing:

| Works | Does not work |
|---|---|
| `duckdns.org`, `dedyn.io`, `dynv6.net`, `nsupdate.info` | `nip.io`, `sslip.io`, `afraid.org`, `traefik.me` |

With a dynamic-DNS provider, set the address by hand to the server's IP. These
services default to the IP of whoever is signed in, which is the browser's
connection, not the server.

Changing the hostname later means changing `PUBLIC_BASE_URL`, which changes the
token audience: every connected client has to be removed and re-added in Claude
and authorized again. Nothing is lost, but it is not transparent.

### 2. Teamleader integration

1. Sign in at <https://marketplace.focus.teamleader.eu> → **Developer** →
   **My integrations** → **Create integration**.
2. Add `http://localhost:8000/oauth/callback` as a redirect URI (used by the
   one-off helper below).
3. Note the **Client ID** and **Client Secret**.
4. Run the OAuth flow once to get the initial refresh token:

   ```bash
   echo "TEAMLEADER_CLIENT_ID=<id>"         >> .env
   echo "TEAMLEADER_CLIENT_SECRET=<secret>" >> .env
   echo "REDIRECT_URI=http://localhost:8000/oauth/callback" >> .env
   node get-refresh-token.mjs
   ```

   This is a one-time bootstrap; from then on the token store is the source of
   truth.

### 3. Application

```bash
ssh root@<server>
adduser --system --group --home /opt/teamleader-mcp --shell /usr/sbin/nologin teamleader-mcp
git clone https://github.com/<you>/boostu-teamleader-mcp /opt/teamleader-mcp/repo
cd /opt/teamleader-mcp/repo
git checkout feat/remote-http-oauth
npm ci && npm run build && npm prune --omit=dev
```

Write `/etc/teamleader-mcp.env` from `.env.remote.example` (`chmod 600`,
owned by root — systemd reads it before dropping privileges), then create the
first account:

```bash
MCP_USERS_FILE=/var/lib/teamleader-mcp/users.json npm run user -- add malte
```

Adding a second person later is the same command; no code change and no
redeploy, just a restart so the file is re-read.

To change a password on a running server from a workstation, without the
password appearing anywhere:

```bash
npm run set-password            # account "malte"
npm run set-password -- name    # another account
```

It prompts with echo disabled, sends only the scrypt hash, restarts the
service, then reads the stored hash back and checks it against what was typed —
so a lock-out surfaces there rather than at the next connection attempt.

Then:

```bash
cp deploy/teamleader-mcp.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now teamleader-mcp
journalctl -u teamleader-mcp -f
```

Seed the token store with the refresh token from step 2:

```bash
install -o teamleader-mcp -g teamleader-mcp -m 600 /dev/null \
  /var/lib/teamleader-mcp/teamleader-refresh-token
echo '<refresh-token>' > /var/lib/teamleader-mcp/teamleader-refresh-token
systemctl restart teamleader-mcp
```

### 4. nginx and TLS

```bash
cp deploy/nginx-mcp.conf /etc/nginx/sites-available/teamleader-mcp
ln -s /etc/nginx/sites-available/teamleader-mcp /etc/nginx/sites-enabled/

# Only needed if no vhost on this host declares default_server. Without it,
# nginx promotes the alphabetically first block to be the catch-all, which on
# this host is the MCP vhost — so it would receive all scanner traffic aimed at
# the bare IP.
cp deploy/nginx-default-deny.conf /etc/nginx/sites-available/000-default-deny
ln -s /etc/nginx/sites-available/000-default-deny /etc/nginx/sites-enabled/

nginx -t && systemctl reload nginx
certbot --nginx -d mcp.von-falken.de
```

## Testing, in this order

Do not start with claude.ai — a failure there could be in either your server or
the connector, and you would be debugging two unknowns at once.

**1. Endpoint and discovery, from a public network:**

```bash
curl -i https://mcp.von-falken.de/healthz
curl -i -X POST https://mcp.von-falken.de/mcp \
  -H 'content-type: application/json' \
  -H 'accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
# expect 401 with:
#   WWW-Authenticate: Bearer error="invalid_token", ...,
#     resource_metadata="https://mcp.von-falken.de/.well-known/oauth-protected-resource/mcp"

curl -s https://mcp.von-falken.de/.well-known/oauth-protected-resource | jq
curl -s https://mcp.von-falken.de/.well-known/oauth-authorization-server | jq
curl -sI https://mcp.von-falken.de/mcp | head -1   # must NOT be a 3xx to another host
```

**2. Endpoint separation:** obtain a token for the briefing endpoint and
confirm it is refused at `/mcp` with `401` (see the test
"keeps the two endpoints apart" for the exact sequence).

**3. MCP Inspector, which walks the whole OAuth flow and shows where it stops:**

Add the Inspector's callback to the allowlist first, restart, and remove it
afterwards:

```bash
# in /etc/teamleader-mcp.env
OAUTH_ALLOWED_REDIRECT_URIS=https://claude.ai/api/mcp/auth_callback,http://localhost:6274/oauth/callback
```

```bash
npx @modelcontextprotocol/inspector
# Transport: Streamable HTTP, URL: https://mcp.von-falken.de/mcp
```

**4. A Teamleader read**, in the Inspector: run `teamleader_users_list`, then
`teamleader_list_events` with `starts_after` / `starts_before` bracketing today.

**5. claude.ai:** Settings → Connectors → **Add custom connector**, URL
`https://mcp.von-falken.de/mcp`, authentication **Always required**, OAuth client
**No client ID — register one automatically** (DCR). New connectors can only be
added from the web or desktop app, not the mobile apps.

**6. Check the tools actually arrive.** In a fresh chat, open the **+** menu →
**Connectors** and confirm the tools are listed. A connector can show as
connected and still deliver no tools; `journalctl -u teamleader-mcp -f` shows
whether a `tools/list` even arrived (`rpc=tools/list` in the log line). If it
did and returned 200, the problem is on the client side, not here.

## Troubleshooting

Every request is logged with path, status, whether an `Authorization` header
arrived, and the JSON-RPC method:

```
[http] POST /mcp 200 auth=bearer ip=160.79.104.7 34ms rpc=tools/call
[http] POST /token 401 auth=none ip=160.79.104.7 2ms
```

| Symptom | Cause |
|---|---|
| "Couldn't reach the MCP server", nothing in the log | DNS resolves to a non-public address, or a firewall blocks Anthropic's range `160.79.104.0/21`. |
| `auth=none` on every `/mcp` request | A cross-host redirect is dropping the `Authorization` header. Register the URL nginx actually serves. |
| Repeated `POST /register` | Claude is not keeping the client. Check that `OAUTH_DB_PATH` is on persistent storage and writable. |
| `401 invalid_client` at `/token`, then a fresh `/register` | Normal recovery after the client record was removed. |
| Connector connects, no tools | Check for `rpc=tools/list` in the log. If it returned 200, this is the known client-side failure mode. |
| `Failed to refresh Teamleader token: 400` | The refresh token was spent twice — almost always a second instance. Re-run `get-refresh-token.mjs` and check the lock file. |
