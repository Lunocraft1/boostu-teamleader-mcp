/**
 * Minimal typings for libqp, which ships none.
 *
 * Only the one function used here is declared, so an unexpected API change
 * surfaces as a type error rather than as silently untyped `any`.
 */
declare module "libqp" {
  /** Decodes a quoted-printable string into raw bytes. */
  export function decode(input: string): Buffer;
  /** Encodes bytes as quoted-printable. */
  export function encode(input: string | Buffer): string;
}
