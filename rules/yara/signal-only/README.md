# signal-only

Rules placed here match on detection but never trigger auto-quarantine or process termination. Use for:

- Broad heuristics ("contains PowerShell download cradle", "uses WMI for execution")
- Upstream rule sets imported wholesale (Neo23x0/signature-base, YARA Forge extended, Florian Roth's packer rules)
- Any rule that has not been FP-validated by `tests/yara_fp_test.py`

The loader assigns any rule without a tier keyword in its path to this namespace by default — so dropping an unsorted third-party pack into `rules/yara/` behaves correctly without per-rule curation.
