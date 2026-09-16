/**
 * Read-only variant of the MCP server, for the unattended briefing endpoint.
 *
 * The briefing runs on a schedule with nobody watching. If it ever wrote to
 * Teamleader, the damage would be visible to customers, so this endpoint must
 * be incapable of writing rather than merely discouraged from it.
 *
 * `TEAMLEADER_TOOLS` cannot express this: it filters by tool *group*, and every
 * group mixes reads with writes (the events group has list, get and create).
 * So the filter is per tool name, and it is an allowlist: a tool that upstream
 * adds later is absent from the briefing until it is named here explicitly.
 * Denying by default is the only safe direction for this endpoint.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { TeamleaderClient } from "../api/client.js";
import { createServer } from "../server.js";

/**
 * Every non-mutating tool across the groups the briefing needs (todos, events,
 * users/departments, companies, contacts, projects, deals).
 *
 * Verified against src/tools/*.ts. Two gaps worth knowing about, both upstream
 * limitations rather than choices made here: tasks can be listed and created
 * but not updated or completed, and events can be listed, read and created but
 * not moved or cancelled.
 */
export const BRIEFING_TOOLS: ReadonlySet<string> = new Set([
  // tasks (Teamleader "todos")
  "teamleader_list_tasks",
  // events
  "teamleader_list_events",
  "teamleader_get_event",
  // org: users, teams, departments
  "teamleader_users_list",
  "teamleader_users_info",
  "teamleader_users_me",
  "teamleader_teams_list",
  "teamleader_departments_list",
  // projects
  "teamleader_projects_list",
  "teamleader_projects_info",
  // companies
  "teamleader_list_companies",
  "teamleader_get_company",
  // contacts
  "teamleader_list_contacts",
  "teamleader_get_contact",
  // deals
  "teamleader_list_deals",
  "teamleader_get_deal",
]);

/**
 * Upstream's own time tracking tools.
 *
 * They are suppressed everywhere in favour of src/http/timeTrackingTools.ts,
 * which follows the documented API where upstream does not. Filtering by name
 * rather than by group is deliberate: `TEAMLEADER_TOOLS` being unset enables
 * every upstream group, so a configuration check would miss the default case
 * and the duplicate registration would only surface as a 500 on tools/list.
 */
export const UPSTREAM_TIME_TRACKING_TOOLS: ReadonlySet<string> = new Set([
  "teamleader_time_tracking_list",
  "teamleader_time_tracking_add",
  "teamleader_time_tracking_update",
  "teamleader_timer_start",
  "teamleader_timer_stop",
]);

export interface FilteredServer {
  server: McpServer;
  registered: string[];
  skipped: string[];
}

export interface FilterOptions {
  /** When set, only these tool names are registered. */
  allow?: ReadonlySet<string>;
  /** Tool names to suppress. Applied after `allow`. */
  deny?: ReadonlySet<string>;
  /**
   * Require that the filter actually suppressed something. Guards against an
   * upstream change routing registrations past the wrapped methods, which would
   * otherwise silently serve tools that were meant to be excluded.
   */
  expectSkips?: boolean;
}

/** Stand-in for the RegisteredTool handle of a tool we did not register. */
const NOT_REGISTERED = {
  enabled: false,
  enable() {},
  disable() {},
  update() {},
  remove() {},
} as unknown as ReturnType<McpServer["tool"]>;

/**
 * Builds an McpServer containing only the tools in {@link BRIEFING_TOOLS}.
 *
 * `createServer` constructs its own McpServer and does not return the tool
 * handles, so there is nothing to remove afterwards without reaching into SDK
 * internals. Instead the public registration methods are wrapped for the
 * duration of the (synchronous, single-threaded) call, which means the filter
 * sits on the same entry point the upstream registrars actually use.
 */
/**
 * Builds an McpServer with a filtered tool set.
 *
 * `createServer` constructs its own McpServer and does not return the tool
 * handles, so there is nothing to remove afterwards without reaching into SDK
 * internals. Instead the public registration methods are wrapped for the
 * duration of the (synchronous, single-threaded) call, which means the filter
 * sits on the same entry point the upstream registrars actually use.
 */
export function createFilteredServer(
  client: TeamleaderClient,
  options: FilterOptions
): FilteredServer {
  const proto = McpServer.prototype as unknown as Record<string, unknown>;
  const originalTool = proto.tool;
  const originalRegisterTool = proto.registerTool;

  const registered: string[] = [];
  const skipped: string[] = [];

  const permitted = (name: string): boolean => {
    if (options.allow && !options.allow.has(name)) return false;
    if (options.deny?.has(name)) return false;
    return true;
  };

  const wrap = (original: unknown) =>
    function (this: McpServer, name: string, ...rest: unknown[]) {
      if (!permitted(name)) {
        skipped.push(name);
        return NOT_REGISTERED;
      }
      registered.push(name);
      return (original as (this: McpServer, ...args: unknown[]) => unknown).apply(this, [
        name,
        ...rest,
      ]);
    };

  proto.tool = wrap(originalTool);
  // Upstream uses the deprecated tool(); registerTool is wrapped too so a
  // future migration cannot quietly bypass the filter.
  proto.registerTool = wrap(originalRegisterTool);

  let server: McpServer;
  try {
    server = createServer(client);
  } finally {
    proto.tool = originalTool;
    proto.registerTool = originalRegisterTool;
  }

  if (registered.length === 0 || (options.expectSkips && skipped.length === 0)) {
    throw new Error(
      `Tool filter did not take effect (registered ${registered.length}, ` +
        `skipped ${skipped.length}). Tools that were meant to be excluded would be ` +
        `served, so refusing to start. Check how src/server.ts registers tools.`
    );
  }

  return { server, registered, skipped };
}

/** The read-only server behind the unattended briefing endpoint. */
export function createBriefingServer(client: TeamleaderClient): FilteredServer {
  return createFilteredServer(client, { allow: BRIEFING_TOOLS, expectSkips: true });
}

/** The interactive server: everything upstream offers, minus its time tracking. */
export function createWorkServer(client: TeamleaderClient): FilteredServer {
  return createFilteredServer(client, { deny: UPSTREAM_TIME_TRACKING_TOOLS });
}
