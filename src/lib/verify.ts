/**
 * Verification: .ddna envelope -> validity result
 * Verifies W3C Data Integrity Proofs with eddsa-jcs-2022 cryptosuite
 *
 * Copied from deepadata-com/lib/ddna/verify.ts for standalone use per ADR-0020
 * Source: deepadata-com/lib/ddna/verify.ts
 *
 * Implements injected resolver pattern per ADR-0020 §"did:web Resolution"
 */

import * as ed25519 from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { sha256 } from '@noble/hashes/sha256';
import canonicalize from 'canonicalize';
import { base58btc } from 'multiformats/bases/base58';
import { didToPublicKey } from './did.js';
import type {
  DdnaEnvelope,
  DataIntegrityProof,
  ProofOptions,
  SigningDocument,
  VerifyResult,
} from './types.js';

// Configure ed25519 to use sha512
// Source: @noble/ed25519 documentation
ed25519.etc.sha512Sync = (...msgs) => {
  const h = sha512.create();
  for (const msg of msgs) h.update(msg);
  return h.digest();
};

/**
 * Validate envelope structure
 */
function validateEnvelopeStructure(envelope: unknown): asserts envelope is DdnaEnvelope {
  if (!envelope || typeof envelope !== 'object') {
    throw new Error('Invalid envelope: must be an object');
  }

  const e = envelope as Record<string, unknown>;

  if (!e.ddna_header || typeof e.ddna_header !== 'object') {
    throw new Error('Invalid envelope: missing ddna_header');
  }

  if (!e.edm_payload || typeof e.edm_payload !== 'object') {
    throw new Error('Invalid envelope: missing edm_payload');
  }

  if (!e.proof) {
    throw new Error('Invalid envelope: missing proof');
  }
}

/**
 * Validate proof structure according to spec
 * Source: W3C Data Integrity specification, eddsa-jcs-2022 cryptosuite
 */
function validateProofStructure(proof: unknown): asserts proof is DataIntegrityProof {
  if (!proof || typeof proof !== 'object') {
    throw new Error("Invalid proof structure: missing field 'proof'");
  }

  const p = proof as Record<string, unknown>;

  if (p.type !== 'DataIntegrityProof') {
    throw new Error(`Invalid proof structure: type must be "DataIntegrityProof", got "${p.type}"`);
  }

  if (p.cryptosuite !== 'eddsa-jcs-2022') {
    throw new Error(
      `Invalid proof structure: cryptosuite must be "eddsa-jcs-2022", got "${p.cryptosuite}"`
    );
  }

  if (!p.created || typeof p.created !== 'string') {
    throw new Error("Invalid proof structure: missing field 'created'");
  }

  const createdDate = new Date(p.created);
  if (isNaN(createdDate.getTime())) {
    throw new Error(`Invalid proof structure: 'created' is not a valid ISO 8601 timestamp`);
  }

  if (!p.verificationMethod || typeof p.verificationMethod !== 'string') {
    throw new Error("Invalid proof structure: missing field 'verificationMethod'");
  }

  if (p.proofPurpose !== 'assertionMethod') {
    throw new Error(
      `Invalid proof structure: proofPurpose must be "assertionMethod", got "${p.proofPurpose}"`
    );
  }

  if (!p.proofValue || typeof p.proofValue !== 'string') {
    throw new Error("Invalid proof structure: missing field 'proofValue'");
  }

  if (!p.proofValue.startsWith('z')) {
    throw new Error(
      `Invalid proof structure: proofValue must be multibase base58-btc (prefix 'z')`
    );
  }
}

/**
 * Reconstruct the signing input from envelope
 * Per eddsa-jcs-2022 cryptosuite: hash(proofOptions) || hash(document)
 * Source: W3C Data Integrity eddsa-jcs-2022 §3.3.3
 */
function reconstructSigningInput(
  proofOptions: ProofOptions,
  document: SigningDocument
): Uint8Array {
  const canonicalProofOptions = canonicalize(proofOptions);
  const canonicalDocument = canonicalize(document);

  if (!canonicalProofOptions || !canonicalDocument) {
    throw new Error('Canonicalization failed during verification');
  }

  const proofOptionsHash = sha256(new TextEncoder().encode(canonicalProofOptions));
  const documentHash = sha256(new TextEncoder().encode(canonicalDocument));

  const signingInput = new Uint8Array(64);
  signingInput.set(proofOptionsHash, 0);
  signingInput.set(documentHash, 32);

  return signingInput;
}

/**
 * Extract proof options from a full proof (remove proofValue)
 */
function extractProofOptions(proof: DataIntegrityProof): ProofOptions {
  const { proofValue: _, ...proofOptions } = proof;
  return proofOptions as ProofOptions;
}

/**
 * DID resolver function type for injected resolver pattern
 * Per ADR-0020 §"did:web Resolution: Injected Resolver Pattern"
 *
 * @param did - The DID string to resolve
 * @returns Promise resolving to the raw Ed25519 public key bytes (32 bytes)
 */
export type DidResolver = (did: string) => Promise<Uint8Array>;

/**
 * Verification options
 * Per ADR-0020 §"did:web Resolution: Injected Resolver Pattern"
 */
export interface VerifyOptions {
  /** Clock skew tolerance in milliseconds (default: 5 minutes) */
  clockSkewMs?: number;
  /** Skip timestamp validation (proof.created and proof.expires) */
  skipTimestampCheck?: boolean;
  /**
   * Custom DID resolver for did:web or other methods
   *
   * If provided, this resolver is called for ALL DID methods.
   * If not provided:
   * - did:key is resolved locally
   * - did:web throws Error: "did:web requires didResolver option"
   */
  didResolver?: DidResolver;
}

/**
 * Resolve a verification method to a public key
 * Implements injected resolver pattern per ADR-0020
 */
async function resolveVerificationMethod(
  verificationMethod: string,
  didResolver?: DidResolver
): Promise<Uint8Array> {
  // If custom resolver provided, use it for all DIDs
  if (didResolver) {
    return didResolver(verificationMethod);
  }

  // Default: did:key resolves locally
  if (verificationMethod.startsWith('did:key:')) {
    const didPart = verificationMethod.split('#')[0];
    return didToPublicKey(didPart);
  }

  // Default: did:web requires custom resolver
  if (verificationMethod.startsWith('did:web:')) {
    throw new Error(
      'did:web requires didResolver option. Provide a didResolver function to verify did:web signatures.'
    );
  }

  throw new Error(`Unsupported DID method: ${verificationMethod}`);
}

/**
 * Verify a .ddna envelope signature
 *
 * @param envelope - The .ddna envelope object to verify
 * @param options - Verification options including optional custom DID resolver
 * @returns Promise resolving to verification result
 *
 * @example
 * // Verify with did:key (default, offline)
 * const result = await verify(envelope);
 *
 * @example
 * // Verify with custom did:web resolver
 * const result = await verify(envelope, {
 *   didResolver: async (did) => {
 *     if (did.startsWith('did:key:')) {
 *       return didKeyToPublicKey(did);
 *     }
 *     if (did.startsWith('did:web:')) {
 *       const doc = await fetch(didToUrl(did)).then(r => r.json());
 *       return extractPublicKey(doc);
 *     }
 *     throw new Error(`Unsupported DID method: ${did}`);
 *   }
 * });
 */
export async function verify(
  envelope: object,
  options?: VerifyOptions
): Promise<VerifyResult> {
  const clockSkewMs = options?.clockSkewMs ?? 5 * 60 * 1000;

  try {
    validateEnvelopeStructure(envelope);

    const proofArray = Array.isArray(envelope.proof) ? envelope.proof : [envelope.proof];
    const proof = proofArray[0];
    validateProofStructure(proof);

    if (!options?.skipTimestampCheck) {
      const now = Date.now();
      const createdTime = new Date(proof.created).getTime();

      if (createdTime > now + clockSkewMs) {
        return {
          valid: false,
          reason: `Proof created timestamp is in the future: ${proof.created}`,
          verificationMethod: proof.verificationMethod,
          created: proof.created,
        };
      }

      if (proof.expires) {
        const expiresTime = new Date(proof.expires).getTime();
        if (now > expiresTime + clockSkewMs) {
          return {
            valid: false,
            reason: `Proof has expired: ${proof.expires}`,
            verificationMethod: proof.verificationMethod,
            created: proof.created,
          };
        }
      }
    }

    let publicKey: Uint8Array;
    try {
      publicKey = await resolveVerificationMethod(proof.verificationMethod, options?.didResolver);
    } catch (error) {
      return {
        valid: false,
        reason: `Failed to resolve verification method: ${error instanceof Error ? error.message : error}`,
        verificationMethod: proof.verificationMethod,
        created: proof.created,
      };
    }

    const document: SigningDocument = {
      ddna_header: envelope.ddna_header,
      edm_payload: envelope.edm_payload,
    };

    const proofOptions = extractProofOptions(proof);
    const signingInput = reconstructSigningInput(proofOptions, document);

    let signature: Uint8Array;
    try {
      signature = base58btc.decode(proof.proofValue);
    } catch (error) {
      return {
        valid: false,
        reason: `Failed to decode proofValue: ${error instanceof Error ? error.message : error}`,
        verificationMethod: proof.verificationMethod,
        created: proof.created,
      };
    }

    if (signature.length !== 64) {
      return {
        valid: false,
        reason: `Invalid signature length: expected 64 bytes, got ${signature.length}`,
        verificationMethod: proof.verificationMethod,
        created: proof.created,
      };
    }

    const isValid = await ed25519.verifyAsync(signature, signingInput, publicKey);

    if (isValid) {
      return {
        valid: true,
        verificationMethod: proof.verificationMethod,
        created: proof.created,
      };
    } else {
      return {
        valid: false,
        reason: 'Signature verification failed',
        verificationMethod: proof.verificationMethod,
        created: proof.created,
      };
    }
  } catch (error) {
    return {
      valid: false,
      reason: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Synchronous verification (only supports did:key)
 *
 * @param envelope - The .ddna envelope object to verify
 * @param options - Verification options (didResolver not supported in sync mode)
 * @returns Verification result
 *
 * @example
 * const result = verifySync(envelope);
 * if (result.valid) {
 *   console.log('Verified by:', result.verificationMethod);
 * } else {
 *   console.log('Verification failed:', result.reason);
 * }
 */
export function verifySync(envelope: object, options?: Omit<VerifyOptions, 'didResolver'>): VerifyResult {
  const clockSkewMs = options?.clockSkewMs ?? 5 * 60 * 1000;

  try {
    validateEnvelopeStructure(envelope);

    const proofArray = Array.isArray(envelope.proof) ? envelope.proof : [envelope.proof];
    const proof = proofArray[0];
    validateProofStructure(proof);

    if (!options?.skipTimestampCheck) {
      const now = Date.now();
      const createdTime = new Date(proof.created).getTime();

      if (createdTime > now + clockSkewMs) {
        return {
          valid: false,
          reason: `Proof created timestamp is in the future: ${proof.created}`,
          verificationMethod: proof.verificationMethod,
          created: proof.created,
        };
      }

      if (proof.expires) {
        const expiresTime = new Date(proof.expires).getTime();
        if (now > expiresTime + clockSkewMs) {
          return {
            valid: false,
            reason: `Proof has expired: ${proof.expires}`,
            verificationMethod: proof.verificationMethod,
            created: proof.created,
          };
        }
      }
    }

    if (!proof.verificationMethod.startsWith('did:key:')) {
      return {
        valid: false,
        reason: 'Synchronous verification only supports did:key method. Use verify() with didResolver for did:web.',
        verificationMethod: proof.verificationMethod,
        created: proof.created,
      };
    }

    const didPart = proof.verificationMethod.split('#')[0];
    const publicKey = didToPublicKey(didPart);

    const document: SigningDocument = {
      ddna_header: envelope.ddna_header,
      edm_payload: envelope.edm_payload,
    };

    const proofOptions = extractProofOptions(proof);
    const signingInput = reconstructSigningInput(proofOptions, document);

    const signature = base58btc.decode(proof.proofValue);
    if (signature.length !== 64) {
      return {
        valid: false,
        reason: `Invalid signature length: expected 64 bytes, got ${signature.length}`,
        verificationMethod: proof.verificationMethod,
        created: proof.created,
      };
    }

    const isValid = ed25519.verify(signature, signingInput, publicKey);

    return {
      valid: isValid,
      reason: isValid ? undefined : 'Signature verification failed',
      verificationMethod: proof.verificationMethod,
      created: proof.created,
    };
  } catch (error) {
    return {
      valid: false,
      reason: error instanceof Error ? error.message : String(error),
    };
  }
}
