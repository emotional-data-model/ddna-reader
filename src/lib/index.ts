/**
 * deepadata-ddna-reader
 *
 * Read-only tools for inspecting, validating, and verifying .ddna envelopes.
 *
 * This package provides:
 * - Structure validation (does this JSON conform to the .ddna envelope schema?)
 * - Inspection (read and display envelope contents)
 * - Cryptographic signature verification (Ed25519 via eddsa-jcs-2022 cryptosuite)
 *
 * This package does NOT provide:
 * - Sealing/signing envelopes (use ddna-tools)
 * - Key generation (use ddna-tools)
 * - Registry lookup (use DeepaData API at deepadata.com)
 *
 * Verification is open per ADR-0020. Anyone can verify that:
 * - The envelope structure is valid
 * - The signature matches the content
 * - The DID in verificationMethod resolves to a valid public key
 * - The proof has not expired (if expires is present)
 */

// Inspection functions
export {
  inspect,
  inspectEnvelope,
  inspectJson,
  validateStructure,
} from './inspect.js';

export type { ValidationResult } from './inspect.js';

// Verification functions
export {
  verify,
  verifySync,
} from './verify.js';

export type { VerifyOptions, DidResolver } from './verify.js';

// DID utilities
export {
  publicKeyToDid,
  didToPublicKey,
  isValidDidUrl,
} from './did.js';

// Type definitions
export type {
  DdnaEnvelope,
  DdnaHeader,
  DataIntegrityProof,
  EdmPayload,
  EdmMeta,
  InspectionResult,
  RetentionPolicy,
  AuditEntry,
  ProofOptions,
  SigningDocument,
  VerifyResult,
} from './types.js';
