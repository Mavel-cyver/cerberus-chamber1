import { verifyMessage, isAddress, type Address, type Hex } from "viem";
import { buildMessage } from "./challenge.ts";
import type { Challenge, VerifyResult } from "./types.ts";

export type VerifyInput = {
  challenge: Challenge;
  signature: Hex;
  ownerAddress: Address;
  now: number;
  expectedDid?: string;
  expectedListingId?: string;
  /** Nonces already used. A nonce found here is refused; a valid one is added. Pass the same Set to every call. */
  seenNonces?: Set<string>;
};

export async function verifyChallenge(input: VerifyInput): Promise<VerifyResult> {
  const { challenge, signature, ownerAddress, now, expectedDid, expectedListingId, seenNonces } = input;
  const fail = (reason: Extract<VerifyResult, { ok: false }>["reason"]): VerifyResult => ({ ok: false, reason });

  if (expectedDid !== undefined && challenge.did !== expectedDid) return fail("wrong_did");
  if (expectedListingId !== undefined && challenge.listingId !== expectedListingId) return fail("wrong_listing");
  if (now >= challenge.expiresAt) return fail("expired");
  if (now < challenge.issuedAt) return fail("not_yet_valid");

  const rebuilt = buildMessage(challenge);
  if (rebuilt !== challenge.message) return fail("tampered_message");

  if (seenNonces?.has(challenge.nonce)) return fail("replayed_nonce");

  if (!isAddress(ownerAddress)) return fail("wrong_signer");

  let recovered: boolean;
  try {
    recovered = await verifyMessage({ address: ownerAddress, message: challenge.message, signature });
  } catch {
    return fail("bad_signature");
  }
  if (!recovered) return fail("wrong_signer");

  seenNonces?.add(challenge.nonce);
  return { ok: true, reason: "valid" };
}
