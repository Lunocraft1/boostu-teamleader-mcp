/**
 * Compact, briefing-shaped tools registered on top of the upstream tool set.
 *
 * They live here rather than in src/tools/ so no upstream file is touched and
 * merges stay clean. Two reasons they exist at all:
 *
 *  1. **Addresses.** Only about half of the calendar events carry a location of
 *     their own; the rest only link to a contact or company. Resolving that
 *     needs an extra call per event, which a model would otherwise have to
 *     orchestrate itself — several round trips and a lot of raw JSON in the
 *     context for every single morning.
 *  2. **Context size.** The generic list tools return every field Teamleader
 *     knows. A briefing needs a handful of them, and the unattended run pays
 *     for the rest in context on every execution.
 *
 * Read-only by construction: only *.list and *.info endpoints are called.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { TeamleaderClient } from "../api/client.js";

const TZ = "Europe/Berlin";

export const BRIEFING_TOOL_NAMES = [
  "teamleader_briefing_agenda",
  "teamleader_briefing_open_deals",
  "teamleader_briefing_due_tasks",
] as const;

// ── Shapes we rely on (only the fields actually read) ─────────────────────────

interface IdRef {
  type?: string;
  id?: string;
}

interface TlAddress {
  type?: string;
  address?: {
    line_1?: string | null;
    postal_code?: string | null;
    city?: string | null;
    country?: string | null;
  } | null;
}

interface TlEvent {
  id?: string;
  title?: string | null;
  starts_at?: string | null;
  ends_at?: string | null;
  location?: string | null;
  description?: string | null;
  attendees?: IdRef[] | null;
  links?: IdRef[] | null;
}

interface TlUser {
  id?: string;
  first_name?: string | null;
  last_name?: string | null;
  status?: string | null;
}

interface ListResponse<T> {
  data?: T[] | null;
}

/** Address labels as Teamleader names them, in German for the output. */
const ADDRESS_LABEL: Record<string, string> = {
  visiting: "Besuchsadresse",
  primary: "Hauptadresse",
  delivery: "Lieferadresse",
  invoicing: "Rechnungsadresse",
};

/**
 * Picks the address a technician should drive to.
 *
 * "visiting" wins over "primary" deliberately: on real records the two differ
 * (a customer's billing street is not the building being worked on), and
 * sending someone to the wrong one is a wasted trip. The chosen label travels
 * with the value so the reader can see which one it is.
 */
function pickAddress(addresses: TlAddress[] | null | undefined):
  | { text: string; label: string }
  | undefined {
  if (!addresses?.length) return undefined;
  const order = ["visiting", "primary", "delivery", "invoicing"];
  const sorted = [...addresses].sort(
    (a, b) =>
      (order.indexOf(a.type ?? "") + 1 || 99) - (order.indexOf(b.type ?? "") + 1 || 99)
  );
  for (const entry of sorted) {
    const parts = [
      entry.address?.line_1,
      [entry.address?.postal_code, entry.address?.city].filter(Boolean).join(" "),
    ]
      .map((p) => (p ?? "").trim())
      .filter(Boolean);
    if (parts.length) {
      return {
        text: parts.join(", "),
        label: ADDRESS_LABEL[entry.type ?? ""] ?? entry.type ?? "Adresse",
      };
    }
  }
  return undefined;
}

/** UTC offset (e.g. "+02:00") in force in Berlin on the given date. */
function offsetFor(date: string): string {
  const probe = new Date(`${date}T12:00:00Z`);
  const name = new Intl.DateTimeFormat("en-US", {
    timeZone: TZ,
    timeZoneName: "longOffset",
  })
    .formatToParts(probe)
    .find((part) => part.type === "timeZoneName")?.value;
  const offset = (name ?? "GMT+00:00").replace("GMT", "");
  return offset || "+00:00";
}

function todayInBerlin(): string {
  // en-CA renders as YYYY-MM-DD.
  return new Intl.DateTimeFormat("en-CA", { timeZone: TZ }).format(new Date());
}

function hhmm(iso: string | null | undefined): string {
  if (!iso) return "--:--";
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return "--:--";
  return new Intl.DateTimeFormat("de-DE", {
    timeZone: TZ,
    hour: "2-digit",
    minute: "2-digit",
  }).format(parsed);
}

function clean(value: string | null | undefined): string | undefined {
  const text = (value ?? "").replace(/\s+/g, " ").trim();
  return text || undefined;
}

function text(payload: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(payload) }] };
}

function failure(message: string) {
  return { content: [{ type: "text" as const, text: message }], isError: true as const };
}

export function registerBriefingTools(server: McpServer, client: TeamleaderClient): void {
  /** users.list is needed by every tool here; fetched at most once per call. */
  async function userNames(): Promise<Map<string, string>> {
    const response = await client.request<ListResponse<TlUser>>({
      endpoint: "users.list",
      body: { page: { size: 100, number: 1 } },
    });
    const names = new Map<string, string>();
    for (const user of response.data ?? []) {
      if (!user.id) continue;
      const name = [user.first_name, user.last_name].filter(Boolean).join(" ").trim();
      names.set(user.id, name || user.id);
    }
    return names;
  }

  server.tool(
    "teamleader_briefing_agenda",
    "Appointments for one day, grouped by the user they are assigned to, with " +
      "the on-site address resolved. Falls back to the linked contact's or " +
      "company's visiting address when the event itself has no location. " +
      "Read-only. Use this for a daily briefing instead of teamleader_list_events.",
    {
      date: z
        .string()
        .regex(/^\d{4}-\d{2}-\d{2}$/)
        .optional()
        .describe("Day in YYYY-MM-DD, Europe/Berlin. Defaults to today."),
    },
    async (params) => {
      try {
        const date = params.date ?? todayInBerlin();
        const offset = offsetFor(date);

        const [events, names] = await Promise.all([
          client.request<ListResponse<TlEvent>>({
            endpoint: "events.list",
            body: {
              page: { size: 100, number: 1 },
              filter: {
                starts_after: `${date}T00:00:00${offset}`,
                starts_before: `${date}T23:59:59${offset}`,
              },
            },
          }),
          userNames(),
        ]);

        // One lookup per distinct contact/company, however many events use it.
        const cache = new Map<
          string,
          { name?: string; address?: { text: string; label: string } }
        >();
        async function lookup(ref: IdRef): Promise<{
          name?: string;
          address?: { text: string; label: string };
        }> {
          const key = `${ref.type}:${ref.id}`;
          const hit = cache.get(key);
          if (hit) return hit;
          let result: { name?: string; address?: { text: string; label: string } } = {};
          try {
            if (ref.type === "contact") {
              const r = await client.request<{
                data?: {
                  first_name?: string | null;
                  last_name?: string | null;
                  addresses?: TlAddress[] | null;
                } | null;
              }>({ endpoint: "contacts.info", body: { id: ref.id } });
              result = {
                name: clean([r.data?.first_name, r.data?.last_name].filter(Boolean).join(" ")),
                address: pickAddress(r.data?.addresses),
              };
            } else if (ref.type === "company") {
              const r = await client.request<{
                data?: { name?: string | null; addresses?: TlAddress[] | null } | null;
              }>({ endpoint: "companies.info", body: { id: ref.id } });
              result = { name: clean(r.data?.name), address: pickAddress(r.data?.addresses) };
            }
          } catch {
            // A single unreadable customer must not sink the whole briefing.
            result = {};
          }
          cache.set(key, result);
          return result;
        }

        const grouped = new Map<string, Record<string, unknown>[]>();
        const unassigned: Record<string, unknown>[] = [];
        let resolved = 0;

        const sorted = [...(events.data ?? [])].sort((a, b) =>
          (a.starts_at ?? "").localeCompare(b.starts_at ?? "")
        );

        for (const event of sorted) {
          const links = event.links ?? [];
          // Prefer a contact (the person on site) over the company record.
          const ref =
            links.find((l) => l.type === "contact") ?? links.find((l) => l.type === "company");
          const info = ref ? await lookup(ref) : {};

          const own = clean(event.location);
          let address = own;
          let addressFrom: string | undefined;
          if (!address && info.address) {
            address = info.address.text;
            addressFrom = `${ref?.type === "company" ? "Firma" : "Kontakt"} (${info.address.label})`;
            resolved++;
          }

          const entry: Record<string, unknown> = {
            von: hhmm(event.starts_at),
            bis: hhmm(event.ends_at),
            titel: clean(event.title) ?? "(ohne Titel)",
          };
          if (info.name) entry.kunde = info.name;
          if (address) entry.adresse = address;
          if (addressFrom) entry.adresse_aus = addressFrom;
          if (!address) entry.adresse = null;
          if (links.some((l) => l.type === "deal")) entry.hat_deal = true;

          const attendees = (event.attendees ?? []).filter((a) => a.id && names.has(a.id));
          if (attendees.length === 0) {
            unassigned.push(entry);
            continue;
          }
          for (const attendee of attendees) {
            const name = names.get(attendee.id!)!;
            const list = grouped.get(name) ?? [];
            list.push(entry);
            grouped.set(name, list);
          }
        }

        return text({
          datum: date,
          termine_gesamt: sorted.length,
          adressen_nachgeladen: resolved,
          je_nutzer: [...grouped.entries()]
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([nutzer, termine]) => ({ nutzer, termine })),
          ...(unassigned.length ? { ohne_zuordnung: unassigned } : {}),
        });
      } catch (error) {
        return failure(`Agenda konnte nicht geladen werden: ${(error as Error).message}`);
      }
    }
  );

  server.tool(
    "teamleader_briefing_open_deals",
    "Deals that are neither won nor lost, i.e. still undecided. Covers both " +
      "the 'new' and 'open' Teamleader states. Read-only and compact.",
    {},
    async () => {
      try {
        const [deals, names] = await Promise.all([
          client.request<
            ListResponse<{
              id?: string;
              title?: string | null;
              status?: string | null;
              estimated_value?: { amount?: number | null; currency?: string | null } | null;
              estimated_closing_date?: string | null;
              estimated_probability?: number | null;
              responsible_user?: IdRef | null;
              lead?: { customer?: IdRef | null } | null;
            }>
          >({ endpoint: "deals.list", body: { page: { size: 100, number: 1 } } }),
          userNames(),
        ]);

        // "new" is the first pipeline phase, not a separate kind of deal, so a
        // briefing that showed only "open" would hide most of the pipeline.
        const undecided = (deals.data ?? []).filter(
          (deal) => deal.status === "new" || deal.status === "open"
        );
        let total = 0;
        const rows = undecided
          .map((deal) => {
            const amount = deal.estimated_value?.amount;
            if (typeof amount === "number") total += amount;
            const row: Record<string, unknown> = {
              titel: clean(deal.title) ?? "(ohne Titel)",
              zustand: deal.status === "new" ? "neu" : "in Bearbeitung",
            };
            if (typeof amount === "number") {
              row.wert = amount;
              row.waehrung = deal.estimated_value?.currency ?? undefined;
            }
            if (deal.estimated_closing_date) row.abschluss_erwartet = deal.estimated_closing_date;
            const owner = deal.responsible_user?.id;
            if (owner && names.has(owner)) row.verantwortlich = names.get(owner);
            return row;
          })
          .sort((a, b) => Number(b.wert ?? 0) - Number(a.wert ?? 0));

        return text({ anzahl: rows.length, summe_wert: total, deals: rows });
      } catch (error) {
        return failure(`Deals konnten nicht geladen werden: ${(error as Error).message}`);
      }
    }
  );

  server.tool(
    "teamleader_briefing_due_tasks",
    "Open tasks with a due date up to and including a cut-off day — these are " +
      "the follow-ups. Read-only and compact.",
    {
      until: z
        .string()
        .regex(/^\d{4}-\d{2}-\d{2}$/)
        .optional()
        .describe("Cut-off day in YYYY-MM-DD, Europe/Berlin. Defaults to today."),
    },
    async (params) => {
      try {
        const until = params.until ?? todayInBerlin();
        const [tasks, names] = await Promise.all([
          client.request<
            ListResponse<{
              title?: string | null;
              due_on?: string | null;
              completed?: boolean | null;
              assignee?: IdRef | null;
              deal?: IdRef | null;
              customer?: IdRef | null;
            }>
          >({ endpoint: "tasks.list", body: { page: { size: 100, number: 1 } } }),
          userNames(),
        ]);

        const today = todayInBerlin();
        const due = (tasks.data ?? [])
          .filter((task) => !task.completed && task.due_on && task.due_on <= until)
          .sort((a, b) => (a.due_on ?? "").localeCompare(b.due_on ?? ""))
          .map((task) => {
            const row: Record<string, unknown> = {
              faellig: task.due_on,
              titel: clean(task.title) ?? "(ohne Titel)",
            };
            if (task.due_on && task.due_on < today) row.ueberfaellig = true;
            const who = task.assignee?.id;
            if (who && names.has(who)) row.zustaendig = names.get(who);
            if (task.deal?.id) row.hat_deal = true;
            return row;
          });

        return text({
          stichtag: until,
          anzahl: due.length,
          davon_ueberfaellig: due.filter((row) => row.ueberfaellig).length,
          aufgaben: due,
        });
      } catch (error) {
        return failure(`Aufgaben konnten nicht geladen werden: ${(error as Error).message}`);
      }
    }
  );
}
