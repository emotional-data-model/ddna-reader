# ddna-reader

Read-only tools for inspecting and validating `.ddna` envelope structure.

## What This Package Does

- **Inspect** `.ddna` envelope contents in human-readable or JSON format
- **Validate** envelope structure against the expected schema
- **Read** governance metadata, EDM payload structure, and proof details

## What This Package Does NOT Do

- **Seal** or sign envelopes (use [ddna-tools](https://github.com/emotional-data-model/ddna-tools))
- **Verify** cryptographic signatures (use [ddna-tools](https://github.com/emotional-data-model/ddna-tools))
- **Generate** signing keys (use [ddna-tools](https://github.com/emotional-data-model/ddna-tools))

For Certified (Level 3) attestation on Extended or Full profile artifacts, see [deepadata.com](https://deepadata.com).

## Installation

```bash
npm install ddna-reader
```

Or use directly with npx:

```bash
npx ddna-reader inspect <file>
```

## CLI Usage

### Inspect an envelope

Display envelope contents in human-readable format:

```bash
ddna-reader inspect envelope.ddna
```

Output as JSON:

```bash
ddna-reader inspect envelope.ddna --json
```

### Validate structure

Check if an envelope has valid structure (schema validation only):

```bash
ddna-reader validate envelope.ddna
```

Treat warnings as errors:

```bash
ddna-reader validate envelope.ddna --strict
```

## Library Usage

```typescript
import {
  inspect,
  inspectEnvelope,
  inspectJson,
  validateStructure,
} from 'ddna-reader';

// Read a .ddna file
const envelope = JSON.parse(fs.readFileSync('artifact.ddna', 'utf-8'));

// Get human-readable inspection
const output = inspect(envelope);
console.log(output);

// Get structured inspection result
const result = inspectEnvelope(envelope);
console.log(result.jurisdiction);
console.log(result.schemaVersion);

// Validate structure only
const validation = validateStructure(envelope);
if (validation.valid) {
  console.log('Structure is valid');
} else {
  console.log('Errors:', validation.errors);
}
```

## Envelope Structure

A `.ddna` envelope contains three components:

```json
{
  "ddna_header": {
    "ddna_version": "1.1",
    "created_at": "2026-02-19T10:00:00Z",
    "edm_version": "0.7.0",
    "jurisdiction": "GDPR",
    "consent_basis": "consent",
    "exportability": "allowed",
    "retention_policy": { ... }
  },
  "edm_payload": {
    "meta": { ... },
    "core": { ... },
    "constellation": { ... },
    "governance": { ... }
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "verificationMethod": "did:key:z6Mk...",
    "proofPurpose": "assertionMethod",
    "proofValue": "z..."
  }
}
```

## Architecture

The `.ddna` envelope format uses W3C Data Integrity Proofs with Ed25519 signatures.

- **Sealing** (Level 2 - Sealed) is open: anyone can seal artifacts with their own Ed25519 keys using [ddna-tools](https://github.com/emotional-data-model/ddna-tools)
- **Verification** is local: self-sealed artifacts are verified against the embedded `verificationMethod` (did:key)
- **Certification** (Level 3 - Certified) is commercial: DeepaData provides third-party attestation for Extended and Full profile artifacts

This package focuses on read-only inspection and structural validation. For sealing and verification, use ddna-tools.

## Related

- [emotionaldatamodel.org](https://emotionaldatamodel.org) - Open specification for the Emotional Data Model
- [ddna-tools](https://github.com/emotional-data-model/ddna-tools) - Sealing and verification tools
- [deepadata.com](https://deepadata.com) - Certification authority for Level 3 attestation
- [deepadata-edm-spec](https://github.com/emotional-data-model/edm-spec) - Canonical EDM schema and examples

## License

MIT
