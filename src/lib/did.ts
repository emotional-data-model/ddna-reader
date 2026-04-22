/**
 * DID utilities for did:key format
 * Implements Ed25519 public key encoding/decoding as did:key
 *
 * Copied from deepadata-com/lib/ddna/did.ts for standalone use per ADR-0020
 * Source: deepadata-com/lib/ddna/did.ts
 */

import { base58btc } from 'multiformats/bases/base58';

// Multicodec prefix for Ed25519 public key (0xed01)
// Source: https://github.com/multiformats/multicodec/blob/master/table.csv
const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

/**
 * Encode an Ed25519 public key as a did:key identifier
 */
export function publicKeyToDid(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error(`Invalid public key length: expected 32 bytes, got ${publicKey.length}`);
  }

  const multicodecKey = new Uint8Array(ED25519_MULTICODEC_PREFIX.length + publicKey.length);
  multicodecKey.set(ED25519_MULTICODEC_PREFIX, 0);
  multicodecKey.set(publicKey, ED25519_MULTICODEC_PREFIX.length);

  const encoded = base58btc.encode(multicodecKey);
  return `did:key:${encoded}`;
}

/**
 * Decode a did:key identifier to extract the Ed25519 public key
 */
export function didToPublicKey(did: string): Uint8Array {
  if (!did.startsWith('did:key:z')) {
    throw new Error(`Invalid did:key format: must start with "did:key:z", got "${did.slice(0, 20)}..."`);
  }

  const multibaseKey = did.slice(8);

  let decoded: Uint8Array;
  try {
    decoded = base58btc.decode(multibaseKey);
  } catch (error) {
    throw new Error(`Invalid base58-btc encoding in did:key: ${error}`);
  }

  if (decoded.length < ED25519_MULTICODEC_PREFIX.length) {
    throw new Error('Invalid did:key: decoded value too short');
  }

  if (decoded[0] !== ED25519_MULTICODEC_PREFIX[0] || decoded[1] !== ED25519_MULTICODEC_PREFIX[1]) {
    throw new Error(
      `Invalid multicodec prefix: expected Ed25519 (0xed01), got 0x${decoded[0].toString(16)}${decoded[1].toString(16)}`
    );
  }

  const publicKey = decoded.slice(ED25519_MULTICODEC_PREFIX.length);

  if (publicKey.length !== 32) {
    throw new Error(`Invalid public key length: expected 32 bytes, got ${publicKey.length}`);
  }

  return publicKey;
}

/**
 * Validate a DID URL format
 */
export function isValidDidUrl(didUrl: string): boolean {
  const didBase = didUrl.split('#')[0];

  if (didBase.startsWith('did:key:z')) {
    try {
      didToPublicKey(didBase);
      return true;
    } catch {
      return false;
    }
  }

  if (didBase.startsWith('did:web:')) {
    const remainder = didBase.slice(8);
    return remainder.length > 0 && /^[a-zA-Z0-9.-]+/.test(remainder);
  }

  return false;
}
