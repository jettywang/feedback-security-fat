"""Regression tests for the exFAT directory structural fuzzer.

The fast, in-process cases assert the budget-bounded walker's verdicts and the
replayability / coordination of the mutation corpus. The process-boundary case
runs the real parser and the deliberately unguarded control walker in separate
subprocesses to prove the guards actually prevent loss of termination, while a
well-formed nested image still parses end to end.
"""

from __future__ import annotations

import io

import pytest

from dissect.fat.exfat import ExFAT
from tests.fuzz.bounded_walker import BoundedExfatWalker, Budget, ExhaustionError, Outcome, classify
from tests.fuzz.exfat_image import ExfatImageBuilder
from tests.fuzz.process_runner import ProcessResult, run_in_subprocess
from tests.fuzz.structured_fuzz import SEED_CORPUS
from tests.fuzz.structured_fuzz import generate_cases
from tests.fuzz.structured_fuzz import run as run_fuzz

PROCESS_TIMEOUT = 4.0


def _by_prefix(cases: list, prefix: str):
    return next(case for case in cases if case.name.startswith(prefix))


def test_baseline_image_is_valid_multilevel_directory() -> None:
    """A normal multi-level directory must parse and walk cleanly (no false alarm)."""
    image = ExfatImageBuilder(depth=4).build()
    assert classify(image) is Outcome.OK

    filesystem = ExFAT(io.BytesIO(image))
    leaves: list[str] = []

    def descend(mapping: dict) -> None:
        for name, (_entry, children) in mapping.items():
            if children is None:
                leaves.append(name)
            else:
                descend(children)

    descend(filesystem.files["/"][1])
    assert leaves == ["leaf.txt"]


def test_corpus_is_deterministic_for_fixed_seed() -> None:
    first = [(case.name, case.expected, case.image) for case in generate_cases(SEED_CORPUS)]
    second = [(case.name, case.expected, case.image) for case in generate_cases(SEED_CORPUS)]
    assert first == second
    # A different seed must change at least one generated sample.
    other = [(case.name, case.image) for case in generate_cases(SEED_CORPUS + 1)]
    assert [item[1] for item in other] != [item[2] for item in first]


def test_every_corpus_case_matches_its_expected_verdict() -> None:
    for case, verdict in run_fuzz(SEED_CORPUS, per_mutator=4):
        assert verdict is case.expected, f"{case.name}: expected {case.expected}, got {verdict}"


def test_malformed_images_are_not_reported_as_exhaustion() -> None:
    """Format anomalies alone must never be classified as a vulnerability."""
    for case, verdict in run_fuzz(SEED_CORPUS, per_mutator=4):
        if case.expected is Outcome.MALFORMED:
            assert verdict is Outcome.MALFORMED
        if verdict is Outcome.EXHAUSTION:
            assert case.expected is Outcome.EXHAUSTION


def test_budgets_are_independent_of_image_size() -> None:
    """A tight read budget trips before the whole image is consumed."""
    image = ExfatImageBuilder(depth=3).build()
    tight = Budget(max_bytes_read=64)
    with pytest.raises(ExhaustionError):
        BoundedExfatWalker(image, tight).walk()
    # The generous default budget still accepts the same image.
    assert classify(image) is Outcome.OK


def test_fat_backedge_and_directory_backedge_are_flagged() -> None:
    cases = generate_cases(SEED_CORPUS, per_mutator=1)
    assert classify(_by_prefix(cases, "fat_backedge").image) is Outcome.EXHAUSTION
    assert classify(_by_prefix(cases, "directory_pointer").image) is Outcome.EXHAUSTION


@pytest.mark.parametrize(
    ("mode", "sample_prefix", "expected"),
    [
        ("bounded-walker", "baseline", ProcessResult.COMPLETED),
        ("control-walker", "baseline", ProcessResult.COMPLETED),
        ("real-parser", "baseline", ProcessResult.COMPLETED),
        ("bounded-walker", "fat_backedge", ProcessResult.COMPLETED),
        ("control-walker", "fat_backedge", ProcessResult.TIMEOUT),
        ("real-parser", "fat_backedge", ProcessResult.TIMEOUT),
        ("bounded-walker", "directory_pointer", ProcessResult.COMPLETED),
        ("control-walker", "directory_pointer", ProcessResult.CRASHED),
        ("real-parser", "directory_pointer", ProcessResult.CRASHED),
    ],
)
def test_process_boundary_detects_loss_of_termination(mode: str, sample_prefix: str, expected: ProcessResult) -> None:
    case = _by_prefix(generate_cases(SEED_CORPUS, per_mutator=1), sample_prefix)
    result = run_in_subprocess(case.image, mode, timeout=PROCESS_TIMEOUT)
    assert result.result is expected
