export type Challenge = {
  did: string;
  listingId: string;
  nonce: string;
  issuedAt: number;
  expiresAt: number;
  message: string;
};

export type VerifyResult = { ok: true; reason: "valid" } | { ok: false; reason: VerifyFailure };

export type VerifyFailure =
  | "wrong_did"
  | "wrong_listing"
  | "expired"
  | "not_yet_valid"
  | "replayed_nonce"
  | "tampered_message"
  | "bad_signature"
  | "wrong_signer";
