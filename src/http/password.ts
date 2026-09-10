/**
 * Consent password hashing.
 *
 * There is exactly one user, so there is no user table — the consent page
 * checks a single password against a hash from the environment. scrypt from
 * node:crypto keeps this dependency-free.
 *
 * Format: scrypt$<N>$<r>$<p>$<saltBase64>$<hashBase64>
 */

import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

const N = 16384;
const R = 8;
const P = 1;
const KEYLEN = 32;

export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(password, salt, KEYLEN, { N, r: R, p: P });
  return ["scrypt", N, R, P, salt.toString("base64"), hash.toString("base64")].join("$");
}

export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const n = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  if (!Number.isInteger(n) || !Number.isInteger(r) || !Number.isInteger(p)) return false;

  let expected: Buffer;
  try {
    expected = Buffer.from(parts[5], "base64");
  } catch {
    return false;
  }
  const salt = Buffer.from(parts[4], "base64");

  let actual: Buffer;
  try {
    actual = scryptSync(password, salt, expected.length, { N: n, r, p });
  } catch {
    return false;
  }
  // Lengths are equal by construction, but timingSafeEqual throws otherwise.
  if (actual.length !== expected.length) return false;
  return timingSafeEqual(actual, expected);
}
