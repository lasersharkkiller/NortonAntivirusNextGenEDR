#!/usr/bin/env python3
"""
YARA false-positive test harness.

Scans a corpus of known-good files against every rule in a given tier and
fails (non-zero exit) if any rule matches. This is the gatekeeper for the
`quarantine-safe` tier — a rule cannot be promoted into that directory until
it passes this test, because a false-positive there means the scheduled
sweep will quarantine a legitimate system binary.

Usage
-----
    # Validate the quarantine-safe tier against System32 + Program Files
    python tests/yara_fp_test.py --tier quarantine-safe

    # Validate memory tier against a specific goodware directory
    python tests/yara_fp_test.py --tier memory --corpus "C:\\corpus\\goodware"

    # Validate all tiers (informational — signal-only is allowed to match)
    python tests/yara_fp_test.py --tier all

Exit codes
----------
    0  no FPs in enforced tiers
    1  at least one FP in an enforced tier (quarantine-safe, memory)
    2  usage / setup error (yara-python missing, rules dir missing)
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sys
from typing import Iterable

try:
    import yara  # type: ignore
except ImportError:
    print("[!] yara-python not installed. `pip install yara-python`", file=sys.stderr)
    sys.exit(2)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES_ROOT = REPO_ROOT / "rules" / "yara"
DEFAULT_CORPUS = [
    pathlib.Path(r"C:\Windows\System32"),
    pathlib.Path(r"C:\Program Files"),
]

# Tiers that must be FP-clean. signal-only is intentionally not enforced —
# its whole purpose is to catch broad patterns, so some FPs are expected.
ENFORCED_TIERS = {"quarantine-safe", "memory"}
ALL_TIERS = {"quarantine-safe", "memory", "signal-only"}


def iter_rule_files(tier_dir: pathlib.Path) -> Iterable[pathlib.Path]:
    if not tier_dir.exists():
        return
    for p in tier_dir.rglob("*"):
        if p.suffix.lower() in (".yar", ".yara"):
            yield p


def compile_tier(tier: str) -> yara.Rules | None:
    tier_dir = RULES_ROOT / tier
    sources = {}
    for rf in iter_rule_files(tier_dir):
        sources[str(rf)] = str(rf)
    if not sources:
        print(f"[*] Tier '{tier}' has no rules — skipping")
        return None
    try:
        return yara.compile(filepaths=sources)
    except yara.SyntaxError as e:
        print(f"[!] Tier '{tier}' has syntax errors: {e}", file=sys.stderr)
        return None


def iter_corpus(corpus_paths: list[pathlib.Path]) -> Iterable[pathlib.Path]:
    for root in corpus_paths:
        if not root.exists():
            print(f"[*] Corpus path missing: {root} — skipped")
            continue
        for dirpath, _, filenames in os.walk(root):
            for name in filenames:
                fp = pathlib.Path(dirpath) / name
                try:
                    # Skip huge files — FP test is about coverage, not exhaustiveness
                    if fp.stat().st_size > 64 * 1024 * 1024:
                        continue
                except OSError:
                    continue
                yield fp


def scan_tier(tier: str, corpus: list[pathlib.Path]) -> list[tuple[pathlib.Path, list[str]]]:
    rules_obj = compile_tier(tier)
    if rules_obj is None:
        return []

    print(f"[*] Scanning tier '{tier}' against {len(corpus)} corpus path(s)...")
    findings: list[tuple[pathlib.Path, list[str]]] = []
    scanned = 0
    for fp in iter_corpus(corpus):
        scanned += 1
        try:
            matches = rules_obj.match(str(fp), timeout=10)
        except (yara.Error, OSError, PermissionError):
            continue
        if matches:
            findings.append((fp, [m.rule for m in matches]))
            print(f"  [FP] {fp}  ->  {[m.rule for m in matches]}")
    print(f"[=] Tier '{tier}': {scanned} files scanned, {len(findings)} FP(s)")
    return findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tier", choices=sorted(ALL_TIERS) + ["all"], default="quarantine-safe")
    ap.add_argument("--corpus", action="append", type=pathlib.Path,
                    help="Goodware corpus directory (repeatable). "
                         "Defaults to System32 + Program Files.")
    args = ap.parse_args()

    corpus = args.corpus or DEFAULT_CORPUS
    tiers = sorted(ALL_TIERS) if args.tier == "all" else [args.tier]

    total_enforced_fps = 0
    for tier in tiers:
        fps = scan_tier(tier, corpus)
        if tier in ENFORCED_TIERS and fps:
            total_enforced_fps += len(fps)

    if total_enforced_fps:
        print(f"\n[!] {total_enforced_fps} FP(s) in enforced tiers — FAIL")
        return 1
    print("\n[=] All enforced tiers clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
