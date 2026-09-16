import { describe, expect, it } from "vitest";
import { extractBody, isAutomated } from "../src/http/mail/text.js";

describe("extractBody", () => {
  it("keeps a plain message unchanged", () => {
    const r = extractBody("Guten Tag,\n\nkönnen Sie Donnerstag kommen?\n", undefined);
    expect(r.text).toBe("Guten Tag,\n\nkönnen Sie Donnerstag kommen?");
    expect(r.truncated).toBe(false);
    expect(r.quoteRemoved).toBe(false);
  });

  it("cuts the German reply marker and everything after it", () => {
    const r = extractBody(
      [
        "Ja, Donnerstag passt.",
        "",
        "Am 15.09.2026 um 10:12 schrieb Malte Link:",
        "> Wann können wir kommen?",
        "> Viele Grüße",
      ].join("\n"),
      undefined
    );
    expect(r.text).toBe("Ja, Donnerstag passt.");
    expect(r.quoteRemoved).toBe(true);
  });

  it("cuts the English reply marker", () => {
    const r = extractBody(
      "Sounds good.\n\nOn Tue, 15 Sep 2026 at 10:12, Malte wrote:\n> original",
      undefined
    );
    expect(r.text).toBe("Sounds good.");
    expect(r.quoteRemoved).toBe(true);
  });

  it("cuts an Outlook-style quoted header block", () => {
    const r = extractBody(
      "Anbei das Angebot.\n\nVon: Malte Link\nGesendet: Montag, 14. September 2026\nAn: Kunde",
      undefined
    );
    expect(r.text).toBe("Anbei das Angebot.");
    expect(r.quoteRemoved).toBe(true);
  });

  it("cuts a run of quoted lines even without a marker", () => {
    const r = extractBody("Passt so.\n> alte Zeile eins\n> alte Zeile zwei", undefined);
    expect(r.text).toBe("Passt so.");
    expect(r.quoteRemoved).toBe(true);
  });

  it("keeps a single quote-like line that is not a quote run", () => {
    // A lone ">" line is more often a typo or a prompt than quoted history.
    const r = extractBody("Er sagte:\n> kurz\nund weiter geht es.", undefined);
    expect(r.text).toContain("und weiter geht es.");
    expect(r.quoteRemoved).toBe(false);
  });

  it("removes the RFC signature separator and what follows", () => {
    const r = extractBody("Kurze Frage zum Termin.\n\n-- \nMax Mustermann\nTel 0123", undefined);
    expect(r.text).toBe("Kurze Frage zum Termin.");
    expect(r.signatureRemoved).toBe(true);
  });

  it("removes a German closing and the contact block after it", () => {
    const r = extractBody(
      "Bitte um Rückruf.\n\nMit freundlichen Grüßen\nMax Mustermann\nMusterstr. 1\n01234 Ort",
      undefined
    );
    expect(r.text).toBe("Bitte um Rückruf.");
    expect(r.signatureRemoved).toBe(true);
    expect(r.text).not.toContain("Musterstr");
  });

  it("removes a phone signature line", () => {
    const r = extractBody("Bin unterwegs, rufe an.\n\nVon meinem iPhone gesendet", undefined);
    expect(r.text).toBe("Bin unterwegs, rufe an.");
    expect(r.signatureRemoved).toBe(true);
  });

  it("falls back to the HTML part when there is no plain text", () => {
    const r = extractBody(
      undefined,
      "<html><body><p>Hallo,</p><p>bitte Angebot senden.</p></body></html>"
    );
    expect(r.text).toContain("Hallo,");
    expect(r.text).toContain("bitte Angebot senden.");
    expect(r.text).not.toContain("<p>");
  });

  it("drops link targets and images from HTML", () => {
    const r = extractBody(
      undefined,
      '<p>Siehe <a href="https://example.com/very/long/tracking/url?x=1">hier</a></p>' +
        '<img src="https://example.com/pixel.gif">'
    );
    expect(r.text).toContain("hier");
    expect(r.text).not.toContain("example.com");
  });

  it("prefers plain text over HTML when both exist", () => {
    const r = extractBody("Klartext-Fassung", "<p>HTML-Fassung</p>");
    expect(r.text).toBe("Klartext-Fassung");
  });

  it("truncates at the limit and says so", () => {
    const long = "Satz eins. ".repeat(400);
    const r = extractBody(long, undefined, 200);
    expect(r.truncated).toBe(true);
    expect(r.text.length).toBeLessThanOrEqual(200);
  });

  it("prefers a sentence boundary when truncating", () => {
    const r = extractBody("Erster Satz. Zweiter Satz. " + "x".repeat(300), undefined, 40);
    expect(r.truncated).toBe(true);
    // Should not end mid-word in the middle of the x-run.
    expect(r.text.endsWith("x")).toBe(false);
  });

  it("handles an empty body without throwing", () => {
    const r = extractBody(undefined, undefined);
    expect(r.text).toBe("");
    expect(r.truncated).toBe(false);
  });

  it("collapses the blank-line runs HTML conversion leaves behind", () => {
    const r = extractBody("Zeile eins\n\n\n\n\nZeile zwei", undefined);
    expect(r.text).toBe("Zeile eins\n\nZeile zwei");
  });
});

describe("isAutomated", () => {
  it("flags a no-reply sender", () => {
    expect(isAutomated({ from: "no-reply@shop.example" }).automated).toBe(true);
    expect(isAutomated({ from: "noreply@shop.example" }).automated).toBe(true);
    expect(isAutomated({ from: "do_not_reply@shop.example" }).automated).toBe(true);
  });

  it("flags a newsletter by List-Unsubscribe", () => {
    const r = isAutomated({ from: "info@lieferant.example", listUnsubscribe: true });
    expect(r.automated).toBe(true);
    expect(r.reason).toMatch(/Newsletter/);
  });

  it("flags Auto-Submitted per RFC 3834", () => {
    expect(isAutomated({ from: "a@b.example", autoSubmitted: "auto-replied" }).automated).toBe(true);
    // "no" is the explicit value for a human-sent message.
    expect(isAutomated({ from: "a@b.example", autoSubmitted: "no" }).automated).toBe(false);
  });

  it("flags bulk precedence", () => {
    expect(isAutomated({ from: "a@b.example", precedence: "bulk" }).automated).toBe(true);
  });

  it("flags bounces and system addresses", () => {
    expect(isAutomated({ from: "MAILER-DAEMON@mx.example" }).automated).toBe(true);
    expect(isAutomated({ from: "postmaster@mx.example" }).automated).toBe(true);
  });

  it("flags out-of-office replies by subject", () => {
    expect(isAutomated({ from: "kunde@example.com", subject: "Automatische Antwort: Angebot" }).automated).toBe(true);
    expect(isAutomated({ from: "kunde@example.com", subject: "Out of Office" }).automated).toBe(true);
  });

  it("leaves a normal customer mail alone", () => {
    const r = isAutomated({
      from: "frank.orthen@example.com",
      subject: "Frage zum Angebot Badsanierung",
    });
    expect(r.automated).toBe(false);
    expect(r.reason).toBeUndefined();
  });

  it("does not mistake a person whose name contains 'list'", () => {
    expect(isAutomated({ from: "christa.liston@example.com" }).automated).toBe(false);
  });

  it("flags plural notification addresses", () => {
    // Real sender from the live mailbox. A word-boundary pattern for the
    // singular "notification" silently missed every one of these.
    const r = isAutomated({ from: "notifications@teamleader.eu" });
    expect(r.automated).toBe(true);
    expect(r.reason).toMatch(/Benachrichtigung/);
  });

  it("flags an invoicing automat with a dotted local part", () => {
    const r = isAutomated({ from: "invoicing.focus@teamleader.eu" });
    expect(r.automated).toBe(true);
    expect(r.reason).toMatch(/Rechnung/);
  });

  it("flags notify- and newsletter-style local parts", () => {
    expect(isAutomated({ from: "notify-me@service.example" }).automated).toBe(true);
    expect(isAutomated({ from: "newsletters@shop.example" }).automated).toBe(true);
    expect(isAutomated({ from: "mailing@shop.example" }).automated).toBe(true);
  });

  it("leaves real people and shared human mailboxes alone", () => {
    // These are people or mailboxes a human reads; a draft reply is wanted.
    for (const from of [
      "patrick.hofmann1@carrier.com",
      "service@von-falken.de",
      "info@lieferant.example",
      "buchhaltung@kunde.example",
      "notarius.mueller@kanzlei.example",
    ]) {
      expect(isAutomated({ from }).automated, from).toBe(false);
    }
  });
});
