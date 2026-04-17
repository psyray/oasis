"""
Structured LLM output for ChunkDeepAnalysis: field normalization, prompts, and JSON repair.

- ``deep`` — path-based normalizers, retry heuristics, instruction blocks.
- ``json_repair`` — markdown fence stripping, decode/repair pipeline, safe-minimal fallback.
- ``json_repair_scan`` — low-level delimiter and escape scanners (used by ``json_repair``).
"""
