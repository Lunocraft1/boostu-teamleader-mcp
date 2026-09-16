/**
 * Decoding a raw MIME body part.
 *
 * Fetching body parts in batches is far cheaper than downloading each message
 * separately, but it hands back the part exactly as it sits in the message:
 * still in its transfer encoding and still in its original charset. ImapFlow's
 * download() decodes for you; a bodyParts fetch does not. Skipping this step
 * shows German mail as "Heizk=C3=B6rpertausch".
 */

import { decode as decodeQuotedPrintable } from "libqp";
import { decode as iconvDecode, encodingExists } from "iconv-lite";

/** Charset names seen in the wild that iconv-lite does not know verbatim. */
const CHARSET_ALIASES: Record<string, string> = {
  "utf8": "utf-8",
  "utf-8": "utf-8",
  "us-ascii": "ascii",
  "ansi_x3.4-1968": "ascii",
  "iso8859-1": "latin1",
  "iso-8859-1": "latin1",
  "iso-8859-15": "iso-8859-15",
  "windows-1252": "win1252",
  "cp1252": "win1252",
};

function normaliseCharset(charset?: string): string {
  const key = (charset ?? "utf-8").trim().toLowerCase().replace(/^["']|["']$/g, "");
  const mapped = CHARSET_ALIASES[key] ?? key;
  return encodingExists(mapped) ? mapped : "utf-8";
}

/**
 * @param raw       the part exactly as the server returned it
 * @param encoding  Content-Transfer-Encoding from the body structure
 * @param charset   charset parameter from the body structure
 */
export function decodeBodyPart(
  raw: Buffer,
  encoding?: string,
  charset?: string
): string {
  const transfer = (encoding ?? "").trim().toLowerCase();

  let bytes: Buffer;
  switch (transfer) {
    case "base64":
      // Line breaks inside base64 are legal and must be ignored.
      bytes = Buffer.from(raw.toString("ascii").replace(/[\r\n]/g, ""), "base64");
      break;
    case "quoted-printable":
      bytes = decodeQuotedPrintable(raw.toString("ascii"));
      break;
    // 7bit, 8bit, binary and an absent header all mean "as-is".
    default:
      bytes = raw;
      break;
  }

  return iconvDecode(bytes, normaliseCharset(charset));
}
