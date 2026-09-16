import { describe, expect, it } from "vitest";
import { decodeBodyPart } from "../src/http/mail/decode.js";

describe("decodeBodyPart", () => {
  it("decodes quoted-printable with UTF-8 umlauts", () => {
    // This is the exact shape that showed up as "Heizk=C3=B6rpertausch".
    const raw = Buffer.from("Heizk=C3=B6rpertausch und Bad", "ascii");
    expect(decodeBodyPart(raw, "quoted-printable", "utf-8")).toBe("Heizkörpertausch und Bad");
  });

  it("handles quoted-printable soft line breaks", () => {
    const raw = Buffer.from("Dies ist ein langer=\r\n Satz", "ascii");
    expect(decodeBodyPart(raw, "quoted-printable", "utf-8")).toBe("Dies ist ein langer Satz");
  });

  it("decodes base64", () => {
    const raw = Buffer.from(Buffer.from("Grüße aus Mauer", "utf8").toString("base64"), "ascii");
    expect(decodeBodyPart(raw, "base64", "utf-8")).toBe("Grüße aus Mauer");
  });

  it("ignores line breaks inside base64", () => {
    const b64 = Buffer.from("Ein etwas längerer Text mit Umlauten äöü", "utf8").toString("base64");
    const wrapped = b64.replace(/(.{10})/g, "$1\r\n");
    expect(decodeBodyPart(Buffer.from(wrapped, "ascii"), "base64", "utf-8")).toBe(
      "Ein etwas längerer Text mit Umlauten äöü"
    );
  });

  it("passes 7bit and 8bit through unchanged", () => {
    expect(decodeBodyPart(Buffer.from("plain text", "utf8"), "7bit", "utf-8")).toBe("plain text");
    expect(decodeBodyPart(Buffer.from("acht bit", "utf8"), "8bit", "utf-8")).toBe("acht bit");
  });

  it("treats a missing encoding as as-is", () => {
    expect(decodeBodyPart(Buffer.from("roh", "utf8"), undefined, "utf-8")).toBe("roh");
  });

  it("decodes latin-1 bodies", () => {
    const raw = Buffer.from([0x47, 0x72, 0xfc, 0xdf, 0x65]); // "Grüße" in latin1
    expect(decodeBodyPart(raw, "8bit", "iso-8859-1")).toBe("Grüße");
  });

  it("decodes windows-1252", () => {
    const raw = Buffer.from([0x41, 0x6e, 0x67, 0x65, 0x62, 0x6f, 0x74, 0x20, 0x80]); // € at 0x80
    expect(decodeBodyPart(raw, "8bit", "windows-1252")).toBe("Angebot €");
  });

  it("falls back to UTF-8 for an unknown charset", () => {
    const raw = Buffer.from("Umlaut ä", "utf8");
    expect(decodeBodyPart(raw, "8bit", "x-totally-made-up")).toBe("Umlaut ä");
  });

  it("tolerates a quoted charset parameter", () => {
    const raw = Buffer.from("Gr=C3=BC=C3=9Fe", "ascii");
    expect(decodeBodyPart(raw, "quoted-printable", '"UTF-8"')).toBe("Grüße");
  });

  it("is case-insensitive about the encoding name", () => {
    const raw = Buffer.from("Gr=C3=BC=C3=9Fe", "ascii");
    expect(decodeBodyPart(raw, "Quoted-Printable", "UTF-8")).toBe("Grüße");
  });
});
