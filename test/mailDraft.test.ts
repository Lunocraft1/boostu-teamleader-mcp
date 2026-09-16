import { describe, expect, it } from "vitest";
import { decodeBodyPart } from "../src/http/mail/decode.js";
import {
  bareAddress,
  buildDraftMime,
  buildReferences,
  closingFor,
  composeText,
  firstNameOf,
  greetingFor,
  replyKey,
  replySubject,
} from "../src/http/mail/draft.js";

describe("replySubject", () => {
  it("prefixes a plain subject", () => {
    expect(replySubject("Angebot Badsanierung")).toBe("Re: Angebot Badsanierung");
  });

  it("does not stack prefixes on an existing reply", () => {
    // German clients write AW:, so a naive prefix would produce "Re: AW: ...".
    expect(replySubject("AW: Angebot ECM")).toBe("AW: Angebot ECM");
    expect(replySubject("Re: Angebot ECM")).toBe("Re: Angebot ECM");
    expect(replySubject("RE: Angebot")).toBe("RE: Angebot");
    expect(replySubject("Antwort: Angebot")).toBe("Antwort: Angebot");
    expect(replySubject("WG: Angebot")).toBe("WG: Angebot");
  });

  it("collapses whitespace and handles a missing subject", () => {
    expect(replySubject("  Zwei   Wörter  ")).toBe("Re: Zwei Wörter");
    expect(replySubject(undefined)).toBe("Re: (kein Betreff)");
    expect(replySubject("")).toBe("Re: (kein Betreff)");
  });
});

describe("buildReferences", () => {
  it("appends the parent's Message-ID to its References", () => {
    expect(buildReferences("<c@x>", "<a@x> <b@x>")).toBe("<a@x> <b@x> <c@x>");
  });

  it("works when the parent has no References", () => {
    expect(buildReferences("<c@x>")).toBe("<c@x>");
  });

  it("adds angle brackets when they are missing", () => {
    expect(buildReferences("c@x")).toBe("<c@x>");
  });

  it("does not duplicate an id already present", () => {
    expect(buildReferences("<b@x>", "<a@x> <b@x>")).toBe("<a@x> <b@x>");
  });
});

describe("greeting and closing", () => {
  it("uses the first name only in the personal register", () => {
    expect(greetingFor("persoenlich", "Patrick")).toBe("Hallo Patrick,");
    expect(greetingFor("sachlich", "Patrick")).toBe("Guten Tag,");
    expect(greetingFor("foermlich", "Patrick")).toBe("Sehr geehrte Damen und Herren,");
  });

  it("falls back when no first name is known", () => {
    expect(greetingFor("persoenlich")).toBe("Hallo,");
  });

  it("never guesses a gendered salutation for an individual", () => {
    // "Sehr geehrte Damen und Herren" is the neutral collective form and is
    // fine; what must never appear is a singular "Herr X" or "Frau X", because
    // the mailbox knows a display name and not a person's gender.
    for (const style of ["sachlich", "persoenlich", "foermlich"] as const) {
      const g = greetingFor(style, "Patrick");
      expect(g, style).not.toMatch(/\b(Herrn?|Frau)\s+\p{Lu}/u);
      expect(g, style).not.toMatch(/geehrter?\s+(Herr|Frau)\b/);
    }
  });

  it("matches the closing to the register", () => {
    expect(closingFor("persoenlich")).toBe("Viele Grüße");
    expect(closingFor("sachlich")).toBe("Mit freundlichen Grüßen");
    expect(closingFor("foermlich")).toBe("Mit freundlichen Grüßen");
  });
});

describe("firstNameOf", () => {
  it("reads a first name from a normal display name", () => {
    expect(firstNameOf("Patrick Hofmann")).toBe("Patrick");
    expect(firstNameOf("Benjamin Link")).toBe("Benjamin");
  });

  it("handles the surname-first form", () => {
    expect(firstNameOf("Hofmann, Patrick")).toBe("Patrick");
  });

  it("refuses things that are not first names", () => {
    expect(firstNameOf("von Falken GmbH & Co. KG")).toBeUndefined();
    expect(firstNameOf("OPENAI")).toBeUndefined();
    expect(firstNameOf("service@von-falken.de")).toBeUndefined();
    expect(firstNameOf("")).toBeUndefined();
    expect(firstNameOf(undefined)).toBeUndefined();
    expect(firstNameOf("A")).toBeUndefined();
  });
});

describe("composeText", () => {
  const base = {
    from: "malte.link@von-falken.de",
    to: "kunde@example.com",
    subject: "Re: Test",
    inReplyTo: "<a@x>",
    references: "<a@x>",
    greeting: "Guten Tag,",
    body: "hier die Antwort.",
    closing: "Mit freundlichen Grüßen",
  };

  it("assembles greeting, body and closing", () => {
    expect(composeText(base)).toBe(
      "Guten Tag,\n\nhier die Antwort.\n\nMit freundlichen Grüßen\n"
    );
  });

  it("appends a signature when configured", () => {
    expect(composeText({ ...base, signature: "Malte Link\nvon Falken" })).toBe(
      "Guten Tag,\n\nhier die Antwort.\n\nMit freundlichen Grüßen\nMalte Link\nvon Falken\n"
    );
  });

  it("collapses accidental blank-line runs in the body", () => {
    const text = composeText({ ...base, body: "Zeile eins\n\n\n\nZeile zwei" });
    expect(text).not.toMatch(/\n{3}/);
  });
});

describe("buildDraftMime", () => {
  it("produces a message that hangs on the thread", async () => {
    const mime = (
      await buildDraftMime({
        from: "malte.link@von-falken.de",
        to: "Hofmann, Patrick <patrick@carrier.com>",
        subject: "Re: BV. Gemünder",
        inReplyTo: "<parent@carrier.com>",
        references: "<older@x> <parent@carrier.com>",
        greeting: "Hallo Patrick,",
        body: "danke für das Schema.",
        closing: "Viele Grüße",
        signature: "Malte",
      })
    ).toString("utf8");

    // These two headers are what make Proton file the draft on the conversation
    // instead of leaving it as a loose message.
    expect(mime).toContain("In-Reply-To: <parent@carrier.com>");
    expect(mime).toContain("References: <older@x> <parent@carrier.com>");
    expect(mime).toMatch(/^To: .*patrick@carrier\.com/m);
    expect(mime).toMatch(/^From: .*malte\.link@von-falken\.de/m);
    expect(mime).toMatch(/Subject: .*/);

    // The body carries umlauts, so it is quoted-printable in the wire format.
    // Decoding it here also proves the composer and the reader agree.
    const [headers, ...rest] = mime.split("\r\n\r\n");
    const encoding = /Content-Transfer-Encoding:\s*(\S+)/i.exec(headers)?.[1];
    const body = decodeBodyPart(Buffer.from(rest.join("\r\n\r\n"), "ascii"), encoding, "utf-8");
    expect(body).toContain("Hallo Patrick,");
    expect(body).toContain("danke für das Schema.");
    expect(body).toContain("Viele Grüße");
    expect(body).toContain("Malte");
  });

  it("is plain text only — no HTML part and no attachments", async () => {
    const mime = (
      await buildDraftMime({
        from: "a@b.de",
        to: "c@d.de",
        subject: "Re: X",
        inReplyTo: "<p@x>",
        references: "<p@x>",
        greeting: "Guten Tag,",
        body: "kurz.",
        closing: "Mit freundlichen Grüßen",
      })
    ).toString("utf8");
    expect(mime).toContain("Content-Type: text/plain");
    expect(mime).not.toContain("text/html");
    expect(mime).not.toContain("multipart/");
  });

  it("carries a Cc only when one was given", async () => {
    const withCc = (
      await buildDraftMime({
        from: "a@b.de", to: "c@d.de", cc: "e@f.de", subject: "Re: X",
        inReplyTo: "<p@x>", references: "<p@x>",
        greeting: "Guten Tag,", body: "kurz.", closing: "Mit freundlichen Grüßen",
      })
    ).toString("utf8");
    expect(withCc).toMatch(/^Cc: .*e@f\.de/m);

    const without = (
      await buildDraftMime({
        from: "a@b.de", to: "c@d.de", subject: "Re: X",
        inReplyTo: "<p@x>", references: "<p@x>",
        greeting: "Guten Tag,", body: "kurz.", closing: "Mit freundlichen Grüßen",
      })
    ).toString("utf8");
    expect(without).not.toMatch(/^Cc:/m);
  });
});

describe("replyKey", () => {
  it("identifies the same reply regardless of the prefix used", () => {
    // Proton strips In-Reply-To from an appended draft, so recipient plus
    // subject is the only identity left to recognise an existing draft by.
    const a = replyKey("patrick@carrier.com", "BV. Gemünder beiblatt");
    expect(replyKey("patrick@carrier.com", "Re: BV. Gemünder beiblatt")).toBe(a);
    expect(replyKey("patrick@carrier.com", "AW: BV. Gemünder beiblatt")).toBe(a);
    // Stacked prefixes, which is what happens after a few round trips.
    expect(replyKey("patrick@carrier.com", "Re: AW: BV. Gemünder beiblatt")).toBe(a);
  });

  it("is case- and whitespace-insensitive", () => {
    expect(replyKey("Patrick@Carrier.COM", "  Angebot   ECM ")).toBe(
      replyKey("patrick@carrier.com", "Angebot ECM")
    );
  });

  it("separates different recipients and different subjects", () => {
    const base = replyKey("a@x.de", "Angebot");
    expect(replyKey("b@x.de", "Angebot")).not.toBe(base);
    expect(replyKey("a@x.de", "Rechnung")).not.toBe(base);
  });
});

describe("bareAddress", () => {
  it("extracts the address from a display-name form", () => {
    expect(bareAddress('"Hofmann, Patrick" <Patrick.Hofmann1@carrier.com>')).toBe(
      "patrick.hofmann1@carrier.com"
    );
  });

  it("passes a plain address through", () => {
    expect(bareAddress("angebote@viessmann.de")).toBe("angebote@viessmann.de");
  });
});
