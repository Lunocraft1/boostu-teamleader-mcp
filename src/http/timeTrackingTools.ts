/**
 * Time tracking tools, verified line by line against the official Teamleader
 * API definition (github.com/teamleadercrm/api, src/09-time-tracking).
 *
 * These replace the upstream `timeTracking` group rather than extending it.
 * That group is left disabled because three of its five tools do not match the
 * documented API:
 *
 *  - `timers.stop` takes no parameters at all — it stops *the current* timer.
 *    Upstream requires a timer id, which the caller has no way to know and
 *    which the endpoint does not accept.
 *  - The `subject` type enum is company, contact, event, todo, milestone or
 *    ticket. Upstream documents "project, task, deal" to the model, none of
 *    which are valid, so those calls fail.
 *  - `timeTracking.list` accepts only `user_id`, omitting every date filter —
 *    which makes the obvious question ("how much did someone book this week")
 *    impossible to ask.
 *
 * It also fills in the five endpoints upstream has no tool for at all:
 * timeTracking.info, .delete, .resume, timers.current and timers.update.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { TeamleaderClient } from "../api/client.js";

/** Read-only tools: safe on the unattended briefing endpoint too. */
export const TIME_TRACKING_READ_TOOLS = [
  "teamleader_time_tracking_list",
  "teamleader_time_tracking_info",
  "teamleader_timer_current",
] as const;

/** Tools that change something: interactive endpoint only. */
export const TIME_TRACKING_WRITE_TOOLS = [
  "teamleader_time_tracking_add",
  "teamleader_time_tracking_update",
  "teamleader_time_tracking_delete",
  "teamleader_time_tracking_resume",
  "teamleader_timer_start",
  "teamleader_timer_stop",
  "teamleader_timer_update",
] as const;

/** Subject types a time entry or timer can be attached to, per the API. */
const SUBJECT_TYPES = ["company", "contact", "event", "todo", "milestone", "ticket"] as const;

/** Subjects that `relates_to` accepts — a different, smaller set. */
const RELATES_TO_TYPES = ["milestone", "project"] as const;

const ISO_DATETIME = "ISO 8601, e.g. 2026-09-16T08:00:00+02:00";

function text(payload: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }] };
}

function failure(message: string) {
  return { content: [{ type: "text" as const, text: message }], isError: true as const };
}

/**
 * Turns a Teamleader error into something actionable.
 *
 * A missing OAuth scope is by far the most likely cause of a 403 here: the
 * integration's scopes are ticked in the developer portal up front and are not
 * negotiable at authorization time, so an endpoint the integration was never
 * granted fails no matter what the code does.
 */
function explain(endpoint: string, error: unknown): string {
  const message = (error as Error).message ?? String(error);
  if (/\b(401|403)\b/.test(message)) {
    return (
      `${message}\n\n` +
      `Hinweis: ${endpoint} braucht sehr wahrscheinlich den Scope "Time tracking" ` +
      `in der Teamleader-Integration. Scopes werden im Developer Portal vorab ` +
      `angehakt; nach dem Nachtragen muss die Freigabe einmal neu erteilt werden.`
    );
  }
  return message;
}

export interface TimeTrackingOptions {
  /** When false, only the read-only tools are registered. */
  includeWrites: boolean;
}

export function registerTimeTrackingTools(
  server: McpServer,
  client: TeamleaderClient,
  options: TimeTrackingOptions
): void {
  const call = async (endpoint: string, body: Record<string, unknown>) => {
    try {
      return text(await client.request({ endpoint, body }));
    } catch (error) {
      return failure(explain(endpoint, error));
    }
  };

  // ── Read ──────────────────────────────────────────────────────────────────

  server.tool(
    "teamleader_time_tracking_list",
    "List tracked time. Supports filtering by user and by period, which is what " +
      "makes questions like 'how much did this person book this week' answerable.",
    {
      page: z.number().int().positive().optional(),
      page_size: z.number().int().positive().max(100).optional().describe("max 100"),
      user_id: z.string().optional().describe("Only this user's entries"),
      started_after: z.string().optional().describe(`Started on or after — ${ISO_DATETIME}`),
      started_before: z.string().optional().describe(`Started on or before — ${ISO_DATETIME}`),
      ended_after: z.string().optional().describe(`Ended on or after — ${ISO_DATETIME}`),
      ended_before: z.string().optional().describe(`Ended on or before — ${ISO_DATETIME}`),
      ids: z.array(z.string()).optional().describe("Specific time tracking entry ids"),
      subject_type: z.enum(SUBJECT_TYPES).optional().describe("Requires subject_id"),
      subject_id: z.string().optional().describe("Requires subject_type"),
      subject_types: z
        .array(z.enum(SUBJECT_TYPES))
        .optional()
        .describe("Only entries attached to one of these kinds of subject"),
      relates_to_type: z.enum(RELATES_TO_TYPES).optional().describe("Requires relates_to_id"),
      relates_to_id: z
        .string()
        .optional()
        .describe("Finds time linked directly and indirectly to this subject"),
      sort_order: z.enum(["asc", "desc"]).optional().describe("Order by start date"),
    },
    async (p) => {
      const filter: Record<string, unknown> = {};
      if (p.user_id) filter.user_id = p.user_id;
      if (p.started_after) filter.started_after = p.started_after;
      if (p.started_before) filter.started_before = p.started_before;
      if (p.ended_after) filter.ended_after = p.ended_after;
      if (p.ended_before) filter.ended_before = p.ended_before;
      if (p.ids?.length) filter.ids = p.ids;
      if (p.subject_type && p.subject_id) {
        filter.subject = { type: p.subject_type, id: p.subject_id };
      }
      if (p.subject_types?.length) filter.subject_types = p.subject_types;
      if (p.relates_to_type && p.relates_to_id) {
        filter.relates_to = { type: p.relates_to_type, id: p.relates_to_id };
      }

      const body: Record<string, unknown> = {};
      if (Object.keys(filter).length) body.filter = filter;
      if (p.page || p.page_size) {
        body.page = { number: p.page ?? 1, size: p.page_size ?? 50 };
      }
      if (p.sort_order) body.sort = [{ field: "starts_on", order: p.sort_order }];
      return call("timeTracking.list", body);
    }
  );

  server.tool(
    "teamleader_time_tracking_info",
    "Details of one tracked time entry.",
    {
      id: z.string().describe("Time tracking entry id"),
      includes: z
        .string()
        .optional()
        .describe("Comma-separated optional includes, e.g. 'materials,relates_to'"),
    },
    async (p) => {
      const body: Record<string, unknown> = { id: p.id };
      if (p.includes) body.includes = p.includes;
      return call("timeTracking.info", body);
    }
  );

  server.tool(
    "teamleader_timer_current",
    "The timer running right now for the authenticated user, if any. Returns no " +
      "data when nothing is running. Check this before starting another timer.",
    {},
    async () => call("timers.current", {})
  );

  if (!options.includeWrites) return;

  // ── Write ─────────────────────────────────────────────────────────────────

  server.tool(
    "teamleader_time_tracking_add",
    "Record tracked time that has already happened. SIDE EFFECT: creates a time " +
      "log entry. Give exactly one of: started_at+duration, started_at+ended_at, " +
      "or started_on+duration.",
    {
      started_at: z.string().optional().describe(`Start — ${ISO_DATETIME}`),
      ended_at: z.string().optional().describe(`End — ${ISO_DATETIME}. Alternative to duration.`),
      started_on: z
        .string()
        .optional()
        .describe("Date only, YYYY-MM-DD. Only if duration-based tracking is enabled."),
      duration: z.number().int().positive().optional().describe("Duration in SECONDS"),
      work_type_id: z.string().optional(),
      subject_type: z.enum(SUBJECT_TYPES).optional().describe("Requires subject_id"),
      subject_id: z.string().optional().describe("Requires subject_type"),
      description: z.string().optional(),
      invoiceable: z.boolean().optional(),
    },
    async (p) => {
      // The API accepts three mutually exclusive combinations; rejecting a bad
      // one here gives a clearer message than the API's validation error.
      const hasStartDuration = Boolean(p.started_at && p.duration);
      const hasStartEnd = Boolean(p.started_at && p.ended_at);
      const hasDayDuration = Boolean(p.started_on && p.duration);
      if ([hasStartDuration, hasStartEnd, hasDayDuration].filter(Boolean).length !== 1) {
        return failure(
          "Give exactly one of: started_at + duration, started_at + ended_at, " +
            "or started_on + duration."
        );
      }

      const body: Record<string, unknown> = {};
      if (hasStartEnd) {
        body.started_at = p.started_at;
        body.ended_at = p.ended_at;
      } else if (hasStartDuration) {
        body.started_at = p.started_at;
        body.duration = p.duration;
      } else {
        body.started_on = p.started_on;
        body.duration = p.duration;
      }
      if (p.work_type_id) body.work_type_id = p.work_type_id;
      if (p.subject_type && p.subject_id) {
        body.subject = { type: p.subject_type, id: p.subject_id };
      }
      if (p.description) body.description = p.description;
      if (p.invoiceable !== undefined) body.invoiceable = p.invoiceable;
      return call("timeTracking.add", body);
    }
  );

  server.tool(
    "teamleader_time_tracking_update",
    "Change an existing tracked time entry. SIDE EFFECT: modifies a time log entry.",
    {
      id: z.string().describe("Time tracking entry id"),
      started_at: z.string().optional().describe(`New start — ${ISO_DATETIME}`),
      ended_at: z.string().optional().describe(`New end — ${ISO_DATETIME}`),
      duration: z.number().int().positive().optional().describe("New duration in SECONDS"),
      work_type_id: z.string().optional(),
      subject_type: z.enum(SUBJECT_TYPES).optional().describe("Requires subject_id"),
      subject_id: z.string().optional().describe("Requires subject_type"),
      description: z.string().optional(),
      invoiceable: z.boolean().optional(),
    },
    async (p) => {
      const body: Record<string, unknown> = { id: p.id };
      if (p.started_at) body.started_at = p.started_at;
      if (p.ended_at) body.ended_at = p.ended_at;
      if (p.duration !== undefined) body.duration = p.duration;
      if (p.work_type_id) body.work_type_id = p.work_type_id;
      if (p.subject_type && p.subject_id) {
        body.subject = { type: p.subject_type, id: p.subject_id };
      }
      if (p.description !== undefined) body.description = p.description;
      if (p.invoiceable !== undefined) body.invoiceable = p.invoiceable;
      return call("timeTracking.update", body);
    }
  );

  server.tool(
    "teamleader_time_tracking_delete",
    "Delete a tracked time entry. SIDE EFFECT: removes the entry permanently.",
    { id: z.string().describe("Time tracking entry id") },
    async (p) => call("timeTracking.delete", { id: p.id })
  );

  server.tool(
    "teamleader_time_tracking_resume",
    "Start a new timer that continues an existing tracked time entry, reusing its " +
      "work type, subject and description. SIDE EFFECT: starts a running timer.",
    {
      id: z.string().describe("Time tracking entry to resume"),
      started_at: z.string().optional().describe(`Start — ${ISO_DATETIME}. Defaults to now.`),
    },
    async (p) => {
      const body: Record<string, unknown> = { id: p.id };
      if (p.started_at) body.started_at = p.started_at;
      return call("timeTracking.resume", body);
    }
  );

  server.tool(
    "teamleader_timer_start",
    "Start a running timer. SIDE EFFECT: a timer keeps running until stopped. " +
      "Check teamleader_timer_current first — only one timer can run at a time.",
    {
      started_at: z.string().optional().describe(`Start — ${ISO_DATETIME}. Defaults to now.`),
      work_type_id: z.string().optional(),
      subject_type: z.enum(SUBJECT_TYPES).optional().describe("Requires subject_id"),
      subject_id: z.string().optional().describe("Requires subject_type"),
      description: z.string().optional(),
      invoiceable: z.boolean().optional(),
    },
    async (p) => {
      const body: Record<string, unknown> = {};
      if (p.started_at) body.started_at = p.started_at;
      if (p.work_type_id) body.work_type_id = p.work_type_id;
      if (p.subject_type && p.subject_id) {
        body.subject = { type: p.subject_type, id: p.subject_id };
      }
      if (p.description) body.description = p.description;
      if (p.invoiceable !== undefined) body.invoiceable = p.invoiceable;
      return call("timers.start", body);
    }
  );

  server.tool(
    "teamleader_timer_stop",
    "Stop the timer that is currently running and turn it into a tracked time " +
      "entry. SIDE EFFECT: ends the timer. Takes no arguments — the API always " +
      "stops the current user's running timer.",
    {},
    async () => call("timers.stop", {})
  );

  server.tool(
    "teamleader_timer_update",
    "Change the timer that is currently running. SIDE EFFECT: modifies the live " +
      "timer. Only works while a timer is running.",
    {
      started_at: z.string().optional().describe(`New start — ${ISO_DATETIME}`),
      work_type_id: z.string().optional(),
      subject_type: z.enum(SUBJECT_TYPES).optional().describe("Requires subject_id"),
      subject_id: z.string().optional().describe("Requires subject_type"),
      description: z.string().optional(),
      invoiceable: z.boolean().optional(),
    },
    async (p) => {
      const body: Record<string, unknown> = {};
      if (p.started_at) body.started_at = p.started_at;
      if (p.work_type_id) body.work_type_id = p.work_type_id;
      if (p.subject_type && p.subject_id) {
        body.subject = { type: p.subject_type, id: p.subject_id };
      }
      if (p.description !== undefined) body.description = p.description;
      if (p.invoiceable !== undefined) body.invoiceable = p.invoiceable;
      return call("timers.update", body);
    }
  );
}
