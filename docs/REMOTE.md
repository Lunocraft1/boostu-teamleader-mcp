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
| Stateless Streamable HTTP (`sessionIdGenerator: undefined`, `enableJsonResponse: true`) | A fresh transport and `McpServer` per POST means there is no per-connection state to lose on restart. Only tokens persist, and those are in SQLite. |
| No SSE fallback | The GET/SSE stream and protocol-level sessions were removed in MCP revision `2026-07-28`; Claude speaks Streamable HTTP over POST. Adding SSE would mean maintaining a transport that is on its way out. |
| Resource server and authorization server in one process | Claude fetches protected resource metadata from the MCP host and then discovers the authorization server separately. Same host means one certificate, one nginx block, and no second WAF to get wrong. |
| Dynamic Client Registration | Claude has no pre-registered client here. CIMD would also work and avoids a client database, but DCR is what a single-user setup needs and is supported out of the box. |
| Opaque tokens in SQLite | No signing keys to manage or rotate, and revocation is a `DELETE`. Only SHA-256 hashes are stored. |
| systemd, not Docker | The target host already runs nginx on :80/:443 and three PM2 apps. Docker is not installed, and a container runtime for one Node process buys nothing here. `Type=simple` also guarantees exactly one process, which the Teamleader refresh-token rotation requires. |

## Endpoints

| Path | Auth | Purpose |
|---|---|---|
| `POST /mcp` | Bearer | The MCP endpoint. Unauthenticated requests get `401` + `WWW-Authenticate`. |
| `GET /healthz` | none | Liveness, plus resource/issuer and registered-client count. |
| `GET /.well-known/oauth-protected-resource[/mcp]` | none | RFC 9728. Served at both the sub-path and the root. |
| `GET /.well-known/oauth-authorization-server` | none | RFC 8414. |
| `GET|POST /authorize` | none | Authorization endpoint; redirects to the consent page. |
| `GET|POST /consent` | password | The single-user login and consent screen. |
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

Add an `A` record for the subdomain pointing at the server, and confirm it from
outside your network — Claude rejects any hostname that resolves to a private
address, and connectors are IPv4-only:

```bash
dig +short mcp.von-falken.de A     # must return the public IPv4
```

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
git clone https://github.com/<you>/boostu-teamleader-mcp /opt/teamleader-mcp
cd /opt/teamleader-mcp
git checkout feat/remote-http-oauth
npm ci --omit=dev --ignore-scripts && npm ci && npm run build && npm prune --omit=dev
```

Write `/etc/teamleader-mcp.env` from `.env.remote.example` (`chmod 600`,
owned by root — systemd reads it before dropping privileges), including the
consent password hash:

```bash
npm run hash-password -- 'your consent password'
```

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

**2. MCP Inspector, which walks the whole OAuth flow and shows where it stops:**

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

**3. A Teamleader read**, in the Inspector: run `teamleader_users_list`, then
`teamleader_list_events` with `starts_after` / `starts_before` bracketing today.

**4. claude.ai:** Settings → Connectors → **Add custom connector**, URL
`https://mcp.von-falken.de/mcp`, authentication **Always required**, OAuth client
**No client ID — register one automatically** (DCR). New connectors can only be
added from the web or desktop app, not the mobile apps.

**5. Check the tools actually arrive.** In a fresh chat, open the **+** menu →
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
| Repeated `POST /register` | Claude is not keeping the client. Check that `OAUTH_DB_PATH` is on persistent storage. |
| `401 invalid_client` at `/token`, then a fresh `/register` | Normal recovery after the client record was removed. |
| Connector connects, no tools | Check for `rpc=tools/list` in the log. If it returned 200, this is the known client-side failure mode. |
| `Failed to refresh Teamleader token: 400` | The refresh token was spent twice — almost always a second instance. Re-run `get-refresh-token.mjs` and check the lock file. |
