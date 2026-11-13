"""Command line entry point for the exFAT directory fuzzer.

Examples
--------
List the fixed-seed corpus and its bounded-walker verdicts::

    python -m tests.fuzz list

Dump the minimal samples to a directory for offline triage::

    python -m tests.fuzz dump-samples ./samples

Run one sample against a real subprocess boundary (or the control walker)::

    python -m tests.fuzz process fat_backedge --mode control-walker
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tests.fuzz.bounded_walker import classify
from tests.fuzz.process_runner import DEFAULT_TIMEOUT, run_in_subprocess
from tests.fuzz.structured_fuzz import SEED_CORPUS, generate_cases


def _cmd_list(args: argparse.Namespace) -> int:
    for case in generate_cases(args.seed, depth=args.depth, per_mutator=args.per_mutator):
        verdict = classify(case.image)
        print(f"{case.expected.value:10} {verdict.value:10} {len(case.image):6d}B  {case.name}")
    return 0


def _cmd_dump(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = []
    for case in generate_cases(args.seed, depth=args.depth, per_mutator=args.per_mutator):
        # Keep filenames filesystem friendly while retaining the case identity.
        safe_name = case.name.replace("[", "_").replace("]", "").replace(" ", "").replace(">", "-").replace("/", "_")
        path = out_dir / f"{safe_name}.bin"
        path.write_bytes(case.image)
        manifest.append(
            {"sample": path.name, "case": case.name, "expected": case.expected.value, "bytes": len(case.image)}
        )
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"wrote {len(manifest)} samples and manifest.json to {out_dir}")
    return 0


def _cmd_process(args: argparse.Namespace) -> int:
    cases = generate_cases(args.seed, depth=args.depth, per_mutator=args.per_mutator)
    matches = [case for case in cases if case.name.startswith(args.case_prefix)]
    if not matches:
        print(f"no corpus case starts with {args.case_prefix!r}", file=sys.stderr)
        return 1
    result = run_in_subprocess(matches[0].image, args.mode, timeout=args.timeout)
    print(json.dumps({"case": matches[0].name, **result.as_dict()}))
    return 0 if result.result.value == "completed" else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="exFAT directory structural fuzzer")
    parser.add_argument("--seed", type=int, default=SEED_CORPUS)
    parser.add_argument("--depth", type=int, default=3)
    parser.add_argument("--per-mutator", type=int, default=4)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list corpus cases and bounded-walker verdicts").set_defaults(func=_cmd_list)

    dump = sub.add_parser("dump-samples", help="write minimal sample images and a manifest")
    dump.add_argument("out_dir")
    dump.set_defaults(func=_cmd_dump)

    proc = sub.add_parser("process", help="run one sample through a process-boundary worker")
    proc.add_argument("case_prefix")
    proc.add_argument("--mode", choices=["real-parser", "control-walker", "bounded-walker"], required=True)
    proc.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    proc.set_defaults(func=_cmd_process)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover - CLI shim
    sys.exit(main())
