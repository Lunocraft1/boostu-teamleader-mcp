import { describe, it, expect, beforeEach } from "vitest";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { TeamleaderClient } from "../src/api/client.js";
import { registerContactTools } from "../src/tools/contacts.js";

type Handler = (params: Record<string, unknown>) => Promise<unknown>;

const handlers = new Map<string, Handler>();
const requests: { endpoint: string; body?: Record<string, unknown> }[] = [];

const server = {
  tool(name: string, _description: string, _schema: unknown, handler: Handler) {
    handlers.set(name, handler);
  },
} as unknown as McpServer;

const client = {
  async request(options: { endpoint: string; body?: Record<string, unknown> }) {
    requests.push(options);
    return {};
  },
} as unknown as TeamleaderClient;

registerContactTools(server, client);

beforeEach(() => {
  requests.length = 0;
});

async function call(tool: string, params: Record<string, unknown>) {
  const handler = handlers.get(tool);
  if (!handler) throw new Error(`tool ${tool} is not registered`);
  return handler(params);
}

describe("contact ↔ company link tools", () => {
  it("sends decision_maker: false instead of dropping it", async () => {
    await call("teamleader_update_contact_company_link", {
      id: "c1",
      company_id: "co1",
      decision_maker: false,
    });

    expect(requests[0].endpoint).toBe("contacts.updateCompanyLink");
    expect(requests[0].body).toEqual({
      id: "c1",
      company_id: "co1",
      decision_maker: false,
    });
  });

  it("omits optional fields that were not supplied", async () => {
    await call("teamleader_link_contact_to_company", { id: "c1", company_id: "co1" });

    expect(requests[0].endpoint).toBe("contacts.linkToCompany");
    expect(requests[0].body).toEqual({ id: "c1", company_id: "co1" });
  });

  it("forwards position and decision_maker when linking", async () => {
    await call("teamleader_link_contact_to_company", {
      id: "c1",
      company_id: "co1",
      position: "CEO",
      decision_maker: true,
    });

    expect(requests[0].body).toEqual({
      id: "c1",
      company_id: "co1",
      position: "CEO",
      decision_maker: true,
    });
  });

  it("unlinks with only the two identifiers", async () => {
    await call("teamleader_unlink_contact_from_company", { id: "c1", company_id: "co1" });

    expect(requests[0].endpoint).toBe("contacts.unlinkFromCompany");
    expect(requests[0].body).toEqual({ id: "c1", company_id: "co1" });
  });

  it("returns an MCP error result when the API call fails", async () => {
    const failing = {
      async request() {
        throw new Error("403 Forbidden");
      },
    } as unknown as TeamleaderClient;
    const failingHandlers = new Map<string, Handler>();
    registerContactTools(
      {
        tool(name: string, _d: string, _s: unknown, handler: Handler) {
          failingHandlers.set(name, handler);
        },
      } as unknown as McpServer,
      failing
    );

    const result = (await failingHandlers.get("teamleader_link_contact_to_company")!({
      id: "c1",
      company_id: "co1",
    })) as { isError?: boolean; content: { text: string }[] };

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain("403 Forbidden");
  });
});
