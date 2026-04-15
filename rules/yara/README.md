# NortonEDR YARA Rules

Rules are stratified by **fidelity tier**, controlled by the directory a rule file lives in. The loader derives a YARA **namespace** from the path (see `DeriveYaraNamespace` in `main.cpp`) and the scanner uses that namespace to decide whether a match is allowed to trigger auto-action.

## Tiers

### `quarantine-safe/`
- **Namespace:** `quarantine-safe`
- **Policy:** On match during a `--scan --quarantine` run, the matched file is XOR-neutralized and moved to `C:\ProgramData\NortonEDR\Quarantine\`.
- **Criteria for placement here:**
  - Zero matches against the goodware corpus (`C:\Windows\System32`, `C:\Program Files`) validated by `tests/yara_fp_test.py`.
  - Unambiguous malware identifiers (hard-coded C2 domain, tool-specific mutex, unique opcode tuple).
  - Never broad heuristics like "uses CreateRemoteThread" or "contains encoded PowerShell".

### `signal-only/`
- **Namespace:** `signal-only`
- **Policy:** Matches are logged and pushed to the UI/Elastic pipeline but **never** trigger quarantine or process termination.
- **Use for:** Neo23x0 signature-base, YARA Forge extended set, anything imported wholesale without per-rule FP validation.

### `memory/`
- **Namespace:** `memory`
- **Policy:** Targeted by `--scan-memory`. Rules here should match opcode patterns / unbacked shellcode / decrypted config blobs — **not** PE headers (those rarely exist in `MEM_PRIVATE` regions).
- **Examples:** Cobalt Strike beacon configs, Meterpreter reverse_tcp stager, Sliver/Brute Ratel launchers.

## Adding rules

1. Pick a tier. **If unsure, put it in `signal-only/`.**
2. Run `python tests/yara_fp_test.py --tier quarantine-safe` before promoting anything into `quarantine-safe/`.
3. File extension must be `.yar` or `.yara` — anything else is ignored.
4. The loader recurses, so you can organize by family (`quarantine-safe/ransomware/lockbit.yar` etc.).

## Out-of-tree rule sets

The binary also loads rules from `D:\githubProjects\Loaded-Potato\detections\yara` if present (legacy compatibility) and from any `--yara-rules <dir>` path. All rules from paths not matching one of the tier keywords are treated as `signal-only`.
