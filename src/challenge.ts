import type { Challenge } from "./types.ts";

export const CHALLENGE_TTL_MS = 5 * 60 * 1000;

export function buildMessage(c: Pick<Challenge, "did" | "listingId" | "nonce" | "issuedAt" | "expiresAt">): string {
  return [
    "LAX listing challenge",
    `DID: ${c.did}`,
    `Listing: ${c.listingId}`,
    `Nonce: ${c.nonce}`,
    `Issued: ${new Date(c.issuedAt).toISOString()}`,
    `Expires: ${new Date(c.expiresAt).toISOString()}`,
  ].join("\n");
}

export function randomNonce(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function createChallenge(input: {
  did: string;
  listingId: string;
  now: number;
  nonce?: string;
}): Challenge {
  const nonce = input.nonce ?? randomNonce();
  const base = {
    did: input.did,
    listingId: input.listingId,
    nonce,
    issuedAt: input.now,
    expiresAt: input.now + CHALLENGE_TTL_MS,
  };
  return { ...base, message: buildMessage(base) };
}
