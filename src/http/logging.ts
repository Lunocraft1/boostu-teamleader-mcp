/**
 * Request logging.
 *
 * The OAuth handshake is impossible to debug without knowing, per request, the
 * path, the status and whether an Authorization header actually arrived — a
 * dropped credential on a redirect looks identical to a rejected one from the
 * outside. For MCP requests the JSON-RPC method is logged too, which is what
 * distinguishes "connected but no tools" (no tools/list) from a failing
 * tools/list.
 */

import type { NextFunction, Request, Response } from "express";

function authKind(header: string | undefined): string {
  if (!header) return "none";
  const [scheme] = header.split(" ");
  return scheme?.toLowerCase() === "bearer" ? "bearer" : `other(${scheme ?? "?"})`;
}

function rpcMethod(body: unknown): string | undefined {
  const messages = Array.isArray(body) ? body : [body];
  const methods = messages
    .map((msg) =>
      msg && typeof msg === "object" ? (msg as { method?: unknown }).method : undefined
    )
    .filter((m): m is string => typeof m === "string");
  return methods.length ? methods.join(",") : undefined;
}

export function requestLogger(req: Request, res: Response, next: NextFunction): void {
  const start = process.hrtime.bigint();
  res.on("finish", () => {
    const ms = Number(process.hrtime.bigint() - start) / 1e6;
    const parts = [
      `[http]`,
      req.method,
      req.originalUrl.split("?")[0],
      String(res.statusCode),
      `auth=${authKind(req.headers.authorization)}`,
      `ip=${req.ip ?? "-"}`,
      `${ms.toFixed(0)}ms`,
    ];
    const method = rpcMethod(req.body);
    if (method) parts.push(`rpc=${method}`);
    const ua = req.headers["user-agent"];
    if (ua) parts.push(`ua="${String(ua).slice(0, 60)}"`);
    console.log(parts.join(" "));
  });
  next();
}
