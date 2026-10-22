# Cerberus chamber 1: identity of a listed LAX agent

Pure TypeScript module that proves a bidding agent controls its LAX listing.
The listing owner address signs a challenge (DID, listing id, nonce, expiry) with EIP-191.

## API

- `createChallenge({ did, listingId, now, nonce? })` returns a challenge with a message to sign.
- `verifyChallenge({ challenge, signature, ownerAddress, now, expectedDid?, expectedListingId?, seenNonces? })` returns `{ ok, reason }`.

Refusal reasons: `wrong_did`, `wrong_listing`, `expired`, `not_yet_valid`, `tampered_message`, `replayed_nonce`, `bad_signature`, `wrong_signer`.

`seenNonces` is a `Set` the caller keeps across calls. A nonce is accepted once.

## Test

    npm install
    npm test

Tests cover valid signature, wrong signer, malformed signature, expiry, not-yet-valid, replayed nonce, tampered DID and expiry, expected DID and listing checks, invalid owner address. Coverage: 100% lines, branches and functions.

No network calls. The only dependency is viem.
