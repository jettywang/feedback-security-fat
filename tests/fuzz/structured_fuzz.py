"""Small, deterministic structural fuzzer for exFAT directory parsing.

The fuzzer does not perform byte-level random flipping. Instead it applies
*coordinated* mutations to the semantic fields the directory parser relies on:

* the FILE entry ``subentry_count`` (secondary count), kept in sync with the
  actual number of secondary entries that follow it,
* the STREAM entry flags (allocation possible / not-fragmented),
* the FILENAME secondary entries that belong to an entry-set,
* the STREAM entry directory ``location`` pointer (directory back-edges),
* and FAT cluster chain entries (cluster back-edges).

A fixed LCG seed makes every run replayable: the same seed always yields the
same sequence of (mutator, target) choices. Each mutated image is then fed to
:mod:`tests.fuzz.bounded_walker` for a budget-bounded verdict, separating
ordinary malformed images from genuine cycle / expansion exhaustion.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from tests.fuzz.bounded_walker import Outcome, classify
from tests.fuzz.exfat_image import ExfatImageBuilder

FAT_ENTRY_SIZE = 4
STREAM_FLAGS_OFFSET = 0x01
STREAM_LOCATION_OFFSET = 0x14
FILE_SUBENTRY_OFFSET = 0x01
FILENAME_TYPE_OFFSET = 0x00
FILENAME_ENTRY_INUSE = 0xC1
FLAG_NOT_FRAGMENTED = 0x02

#: Fixed seed so the whole corpus is replayable bit-for-bit.
SEED_CORPUS = 0x5EED


class DeterministicRng:
    """Tiny fixed-seed LCG so runs are replayable without third party deps."""

    def __init__(self, seed: int):
        self.state = seed & 0xFFFFFFFF

    def next_u32(self) -> int:
        # Numerical Recipes constants.
        self.state = (1664525 * self.state + 1013904223) & 0xFFFFFFFF
        return self.state

    def randrange(self, stop: int) -> int:
        if stop <= 0:
            raise ValueError("stop must be positive")
        return self.next_u32() % stop

    def choice(self, options: list) -> object:
        return options[self.randrange(len(options))]


@dataclass
class FuzzCase:
    name: str
    image: bytes
    expected: Outcome


def _patch_u8(buf: bytearray, offset: int, value: int) -> None:
    buf[offset] = value & 0xFF


def _patch_u32(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", buf, offset, value & 0xFFFFFFFF)


def _patch_u64(buf: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<Q", buf, offset, value & 0xFFFFFFFFFFFFFFFF)


def _entry_set_roles(builder: ExfatImageBuilder) -> list[str]:
    return [role for role in builder.entry_sets if ":" in role]


def _directory_roles(builder: ExfatImageBuilder) -> list[str]:
    """Entry-sets whose metadata marks a directory (exclude plain files)."""
    return [role for role in _entry_set_roles(builder) if not role.split(":", 1)[1].endswith(".txt")]


def mutate_secondary_count(builder: ExfatImageBuilder, image: bytes, rng: DeterministicRng) -> FuzzCase:
    """Inflate/deflate subentry_count so the parser's fn loop diverges."""
    buf = bytearray(image)
    role = rng.choice(_entry_set_roles(builder))
    meta_off, _ = builder.entry_sets[role]["metadata"]
    original = buf[meta_off + FILE_SUBENTRY_OFFSET]
    # Either claim far more secondary entries than exist, or too few (<2).
    value = rng.choice([1, 255, max(1, original + rng.randrange(8))])
    _patch_u8(buf, meta_off + FILE_SUBENTRY_OFFSET, value)
    # A single 32-byte cluster cannot host the claimed secondary entries, so the
    # entry-set overflows its directory boundary: a structural error, not an
    # unbounded expansion. The count < 2 variant is likewise purely structural.
    return FuzzCase(f"secondary_count[{role}]->{value}", bytes(buf), Outcome.MALFORMED)


def mutate_stream_flags(builder: ExfatImageBuilder, image: bytes, rng: DeterministicRng) -> FuzzCase:
    """Toggle the not-fragmented flag so a directory is resolved via the FAT."""
    buf = bytearray(image)
    role = rng.choice(_entry_set_roles(builder))
    stream_off, _ = builder.entry_sets[role]["stream"]
    current = buf[stream_off + STREAM_FLAGS_OFFSET]
    # Clear the not-fragmented bit: the parser will now follow the FAT chain.
    value = current & ~FLAG_NOT_FRAGMENTED
    _patch_u8(buf, stream_off + STREAM_FLAGS_OFFSET, value)
    # The FAT still terminates with EOC, so this stays well-formed, just slower.
    return FuzzCase(f"stream_flags[{role}]->fragmented", bytes(buf), Outcome.OK)


def mutate_filename_entries(builder: ExfatImageBuilder, image: bytes, rng: DeterministicRng) -> FuzzCase:
    """Corrupt a FILENAME secondary entry's type while keeping counts aligned."""
    buf = bytearray(image)
    role = rng.choice(_entry_set_roles(builder))
    filenames = builder.entry_sets[role]["filenames"]
    fn_off, _ = filenames[rng.randrange(len(filenames))]
    # Mark the secondary as not-in-use / wrong type; counts stay consistent so
    # this is a structural mismatch, not an expansion.
    _patch_u8(buf, fn_off + FILENAME_TYPE_OFFSET, FILENAME_ENTRY_INUSE & 0x7F)
    return FuzzCase(f"filename_entry[{role}]->inactive", bytes(buf), Outcome.MALFORMED)


def mutate_directory_pointer(builder: ExfatImageBuilder, image: bytes, rng: DeterministicRng) -> FuzzCase:
    """Redirect a directory's STREAM location to an already-visited cluster."""
    buf = bytearray(image)
    roles = _directory_roles(builder)
    role = roles[rng.randrange(len(roles))]
    stream_off, _ = builder.entry_sets[role]["stream"]
    # Point the child back at the root directory, creating a directory cycle.
    target = builder.root_dir_cluster
    _patch_u32(buf, stream_off + STREAM_LOCATION_OFFSET, target)
    # Keep the size coherent; the cycle, not the size, is the exhaustion.
    return FuzzCase(f"directory_pointer[{role}]->root", bytes(buf), Outcome.EXHAUSTION)


def mutate_fat_backedge(builder: ExfatImageBuilder, image: bytes, rng: DeterministicRng) -> FuzzCase:
    """Turn a FAT chain into a self loop by removing its EOC terminator."""
    buf = bytearray(image)
    fat_base, _ = builder.layout["fat"]
    # The root directory is always FAT-backed, so looping its first cluster is
    # enough to remove the parser's chain termination condition.
    cluster = builder.root_dir_cluster
    _patch_u32(buf, fat_base + cluster * FAT_ENTRY_SIZE, cluster)
    return FuzzCase(f"fat_backedge[cluster {cluster}]", bytes(buf), Outcome.EXHAUSTION)


def mutate_invalid_cluster(builder: ExfatImageBuilder, image: bytes, rng: DeterministicRng) -> FuzzCase:
    """Point a directory outside the cluster heap (bounds, not a cycle)."""
    buf = bytearray(image)
    role = rng.choice(_directory_roles(builder))
    stream_off, _ = builder.entry_sets[role]["stream"]
    bogus = builder.cluster_count + 100
    _patch_u32(buf, stream_off + STREAM_LOCATION_OFFSET, bogus)
    return FuzzCase(f"invalid_cluster[{role}]", bytes(buf), Outcome.MALFORMED)


MUTATORS = [
    mutate_secondary_count,
    mutate_stream_flags,
    mutate_filename_entries,
    mutate_directory_pointer,
    mutate_fat_backedge,
    mutate_invalid_cluster,
]


def generate_cases(seed: int = SEED_CORPUS, depth: int = 3, per_mutator: int = 4) -> list[FuzzCase]:
    """Produce a deterministic, replayable corpus for a fixed seed."""
    builder = ExfatImageBuilder(depth=depth)
    baseline = builder.build()
    cases: list[FuzzCase] = [FuzzCase("baseline", baseline, Outcome.OK)]
    for mutator in MUTATORS:
        # A private RNG per mutator, still derived from the fixed seed, keeps
        # each mutator's choices independent of corpus ordering.
        rng = DeterministicRng(seed ^ (MUTATORS.index(mutator) + 1) * 0x9E3779B1)
        for _ in range(per_mutator):
            cases.append(mutator(builder, baseline, rng))
    return cases


def run(seed: int = SEED_CORPUS, depth: int = 3, per_mutator: int = 4) -> list[tuple[FuzzCase, Outcome]]:
    """Generate the corpus and classify each case through the bounded walker."""
    results: list[tuple[FuzzCase, Outcome]] = []
    for case in generate_cases(seed, depth, per_mutator):
        results.append((case, classify(case.image)))
    return results
