import { test } from "node:test";
import assert from "node:assert/strict";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { createChallenge, verifyChallenge, randomNonce, CHALLENGE_TTL_MS } from "../src/index.ts";

const DID = "did:web:square-meadow-3f83.marenjeamar4734.workers.dev";
const LISTING = "lax-ext-ac9586229efa";
const NOW = 1_800_000_000_000;

const owner = privateKeyToAccount(generatePrivateKey());
const other = privateKeyToAccount(generatePrivateKey());

async function signed(now = NOW, did = DID) {
  const challenge = createChallenge({ did, listingId: LISTING, now, nonce: "a".repeat(32) });
  const signature = await owner.signMessage({ message: challenge.message });
  return { challenge, signature };
}

test("valid signature from the listing owner is accepted", async () => {
  const { challenge, signature } = await signed();
  const r = await verifyChallenge({ challenge, signature, ownerAddress: owner.address, now: NOW + 1000 });
  assert.deepEqual(r, { ok: true, reason: "valid" });
});

test("signature from a wrong signer is refused", async () => {
  const { challenge } = await signed();
  const sig = await other.signMessage({ message: challenge.message });
  const r = await verifyChallenge({ challenge, signature: sig, ownerAddress: owner.address, now: NOW + 1000 });
  assert.deepEqual(r, { ok: false, reason: "wrong_signer" });
});

test("malformed signature is refused as bad_signature", async () => {
  const { challenge } = await signed();
  const r = await verifyChallenge({ challenge, signature: "0x1234", ownerAddress: owner.address, now: NOW + 1000 });
  assert.equal(r.ok, false);
  assert.ok(r.ok === false && (r.reason === "bad_signature" || r.reason === "wrong_signer"));
});

test("expired challenge is refused", async () => {
  const { challenge, signature } = await signed();
  const r = await verifyChallenge({
    challenge, signature, ownerAddress: owner.address, now: NOW + CHALLENGE_TTL_MS,
  });
  assert.deepEqual(r, { ok: false, reason: "expired" });
});

test("challenge not yet valid is refused", async () => {
  const { challenge, signature } = await signed();
  const r = await verifyChallenge({ challenge, signature, ownerAddress: owner.address, now: NOW - 1 });
  assert.deepEqual(r, { ok: false, reason: "not_yet_valid" });
});

test("replayed nonce is refused, first use accepted", async () => {
  const { challenge, signature } = await signed();
  const seen = new Set<string>();
  const args = { challenge, signature, ownerAddress: owner.address, now: NOW + 1000, seenNonces: seen };
  assert.deepEqual(await verifyChallenge(args), { ok: true, reason: "valid" });
  assert.deepEqual(await verifyChallenge(args), { ok: false, reason: "replayed_nonce" });
});

test("tampered DID is refused", async () => {
  const { challenge, signature } = await signed();
  const tampered = { ...challenge, did: "did:web:evil.example.com" };
  const r = await verifyChallenge({ challenge: tampered, signature, ownerAddress: owner.address, now: NOW + 1000 });
  assert.deepEqual(r, { ok: false, reason: "tampered_message" });
});

test("expected DID and listing checks are enforced", async () => {
  const { challenge, signature } = await signed();
  const base = { challenge, signature, ownerAddress: owner.address, now: NOW + 1000 };
  assert.deepEqual(await verifyChallenge({ ...base, expectedDid: "did:web:other" }), { ok: false, reason: "wrong_did" });
  assert.deepEqual(await verifyChallenge({ ...base, expectedListingId: "lax-x" }), { ok: false, reason: "wrong_listing" });
  assert.deepEqual(await verifyChallenge({ ...base, expectedDid: DID, expectedListingId: LISTING }), { ok: true, reason: "valid" });
});

test("tampered expiry is refused", async () => {
  const { challenge, signature } = await signed();
  const tampered = { ...challenge, expiresAt: challenge.expiresAt + 10 * CHALLENGE_TTL_MS };
  const r = await verifyChallenge({ challenge: tampered, signature, ownerAddress: owner.address, now: NOW + 1000 });
  assert.deepEqual(r, { ok: false, reason: "tampered_message" });
});

test("invalid owner address is refused", async () => {
  const { challenge, signature } = await signed();
  const r = await verifyChallenge({ challenge, signature, ownerAddress: "0xnope" as `0x${string}`, now: NOW + 1000 });
  assert.deepEqual(r, { ok: false, reason: "wrong_signer" });
});

test("createChallenge without a nonce draws a fresh 32 hex nonce", () => {
  const a = createChallenge({ did: DID, listingId: LISTING, now: NOW });
  const b = createChallenge({ did: DID, listingId: LISTING, now: NOW });
  assert.match(a.nonce, /^[0-9a-f]{32}$/);
  assert.notEqual(a.nonce, b.nonce);
  assert.match(randomNonce(), /^[0-9a-f]{32}$/);
});
