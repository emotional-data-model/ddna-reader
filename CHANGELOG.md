# Changelog

## v0.2.0

- feat: add Ed25519 cryptographic verification per ADR-0020 Phase 1
- feat: add CLI 'ddna-reader verify' command
- feat: add injected resolver pattern for did:web (library makes
  no HTTP calls; caller provides resolver)
- feat: bundled canonical test vectors from edm-spec for conformance
  testing (10 vectors covering valid sigs, tampered envelopes,
  malformed proofs, did:web, and expired proofs)
- test: full conformance test suite passes
- Note: registry lookup remains API-only (use deepadata.com for
  Certified status)

## v0.1.0

- Initial release
- Read-only .ddna envelope inspection
- CLI 'ddna-reader inspect' command
- Envelope structure validation
