# ddna-reader

Read-only parser for .ddna envelopes.

## What This Repo Is

A lightweight, read-only library for parsing and displaying
.ddna envelopes. No cryptographic operations, no sealing —
just envelope parsing and field extraction.

- **Current version:** v0.1.0
- **License:** MIT (open source)
- **Remote:** github.com/emotional-data-model/ddna-reader

## Role in the DeepaData System

```
   ddna-tools (seal, verify)
       ↓ produces envelopes
→ ddna-reader (parse, display) ← YOU ARE HERE
       ↓ consumed by
   Applications that need to read .ddna files
```

Use ddna-reader when you need to display envelope contents
without verification overhead. Use ddna-tools when you need
cryptographic operations.

## What This Repo Does

- Parse .ddna envelope structure
- Extract EDM artifact from envelope
- Display envelope metadata (issuer, created_at, proof)

## What This Repo Does NOT Do

- Seal or sign envelopes (use ddna-tools)
- Verify signatures (use ddna-tools)
- Write to registry (use deepadata-com API)

## OSS Boundary

This repo is MIT licensed. Read-only by design.

## Source of Truth

→ **See `deepadata-com/planning/CLAUDE_PROJECT.md`**
