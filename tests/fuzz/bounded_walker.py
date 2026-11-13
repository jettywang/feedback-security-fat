"""Budget-bounded, cycle-aware exFAT directory walker.

This is deliberately a *standalone* reader implemented on top of raw bytes
rather than the production parser. The production :class:`dissect.fat.exfat.ExFAT`
parser follows FAT chains and recurses into subdirectories without any
termination guard, so it cannot be used as the oracle for "would a malicious
image exhaust the forensic process".

The walker mirrors the same on-disk semantics (FAT cluster chains, entry-sets
made of a file entry + stream entry + filename entries) but enforces an
independent read budget and keeps:

* a seen-set of clusters while following each FAT chain (cluster back-edges),
* a visited-set of directory cluster locations while walking the tree
  (directory back-edges),
* explicit depth / entry / chain step ceilings.

Outcomes distinguish an ordinary malformed image from a real exhaustion:
structural nonsense raises :class:`MalformedImage`, while hitting a guard that
a naive parser lacks raises :class:`ExhaustionError`.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum

DIR_ENTRY_SIZE = 32
FAT_ENTRY_SIZE = 4
EOC = 0xFFFFFFFF

FILE_ENTRY_INUSE = 0x85
STREAM_ENTRY_INUSE = 0xC0
FILENAME_ENTRY_INUSE = 0xC1
END_OF_DIRECTORY = 0x00
ATTRIBUTE_DIRECTORY = 0x10
STREAM_LOCATION_OFFSET = 0x14
STREAM_DATA_LENGTH_OFFSET = 0x18
METADATA_SUBENTRY_OFFSET = 0x01


class Outcome(str, Enum):
    OK = "ok"
    MALFORMED = "malformed"
    EXHAUSTION = "exhaustion"


class MalformedImage(Exception):
    """The image violates exFAT structure but terminates on its own."""


class ExhaustionError(Exception):
    """A guard tripped that an unbounded parser would not enforce."""


@dataclass
class Budget:
    """Independent read/expansion ceilings, deliberately independent of size."""

    max_bytes_read: int = 256 * 1024
    max_dir_entries: int = 4096
    max_directory_depth: int = 64
    max_chain_steps: int = 1024
    max_directories: int = 512

    def __post_init__(self) -> None:
        self.bytes_read = 0
        self.dir_entries = 0
        self.chain_steps = 0
        self.directories = 0

    def charge_read(self, amount: int) -> None:
        self.bytes_read += amount
        if self.bytes_read > self.max_bytes_read:
            raise ExhaustionError(f"read budget exceeded ({self.bytes_read} bytes)")

    def charge_entry(self) -> None:
        self.dir_entries += 1
        if self.dir_entries > self.max_dir_entries:
            raise ExhaustionError(f"directory entry budget exceeded ({self.dir_entries})")

    def charge_chain_step(self) -> None:
        self.chain_steps += 1
        if self.chain_steps > self.max_chain_steps:
            raise ExhaustionError(f"cluster chain step budget exceeded ({self.chain_steps})")

    def charge_directory(self, depth: int) -> None:
        if depth > self.max_directory_depth:
            raise ExhaustionError(f"directory depth budget exceeded ({depth})")
        self.directories += 1
        if self.directories > self.max_directories:
            raise ExhaustionError(f"directory count budget exceeded ({self.directories})")


class BoundedExfatWalker:
    def __init__(self, image: bytes, budget: Budget | None = None):
        self.image = image
        self.budget = budget or Budget()
        self.sector_size = 1 << image[0x6C]
        self.sectors_per_cluster = 1 << image[0x6D]
        self.cluster_size = self.sector_size * self.sectors_per_cluster
        self.fat_sector = struct.unpack_from("<I", image, 0x50)[0]
        self.fat_sector_count = struct.unpack_from("<I", image, 0x54)[0]
        self.cluster_heap_sector = struct.unpack_from("<I", image, 0x58)[0]
        self.cluster_count = struct.unpack_from("<I", image, 0x5C)[0]
        self.root_dir_cluster = struct.unpack_from("<I", image, 0x60)[0]
        self.fat_base = self.fat_sector * self.sector_size
        self.max_cluster = self.cluster_count + 2

    def _read(self, offset: int, length: int) -> bytes:
        if offset < 0 or offset + length > len(self.image):
            raise MalformedImage(f"read past end of image at offset {offset}")
        self.budget.charge_read(length)
        return self.image[offset : offset + length]

    def cluster_offset(self, cluster: int) -> int:
        return (self.cluster_heap_sector + (cluster - 2) * self.sectors_per_cluster) * self.sector_size

    def _fat_next(self, cluster: int) -> int:
        fat_offset = self.fat_base + cluster * FAT_ENTRY_SIZE
        if fat_offset + FAT_ENTRY_SIZE > self.fat_base + self.fat_sector_count * self.sector_size:
            raise MalformedImage("FAT chain walks outside the FAT region")
        return struct.unpack("<I", self._read(fat_offset, FAT_ENTRY_SIZE))[0]

    def resolve_chain(self, start_cluster: int) -> list[int]:
        """Resolve a FAT chain with explicit back-edge detection and a step cap."""
        if start_cluster < 2:
            return []
        if start_cluster >= self.max_cluster:
            raise MalformedImage(f"start cluster {start_cluster} outside cluster heap")
        chain: list[int] = []
        seen: set[int] = set()
        cluster = start_cluster
        while cluster != EOC:
            self.budget.charge_chain_step()
            if cluster in seen:
                raise ExhaustionError(f"FAT cluster back-edge detected at cluster {cluster}")
            if not (2 <= cluster < self.max_cluster):
                raise MalformedImage(f"chain references invalid cluster {cluster}")
            seen.add(cluster)
            chain.append(cluster)
            cluster = self._fat_next(cluster)
        return chain

    def _directory_bytes(self, location: int, not_fragmented: bool, declared_size: int) -> bytes:
        if location < 2 or location >= self.max_cluster:
            raise MalformedImage(f"directory points at invalid cluster {location}")
        if not_fragmented:
            size = declared_size if declared_size > 0 else self.cluster_size
            if size > self.cluster_size:
                raise MalformedImage("contiguous directory claims more than one cluster")
            return self._read(self.cluster_offset(location), self.cluster_size)
        # Fragmented / root directories are resolved through the FAT, which is
        # where a cluster back-edge becomes observable.
        chain = self.resolve_chain(location)
        return b"".join(self._read(self.cluster_offset(cluster), self.cluster_size) for cluster in chain)

    @staticmethod
    def _entry_sets(raw: bytes) -> list[tuple[bool, int, int, bool]]:
        """Parse file entry-sets, returning (is_dir, location, data_len, not_fragmented)."""
        sets: list[tuple[bool, int, int, bool]] = []
        offset = 0
        while offset + DIR_ENTRY_SIZE <= len(raw):
            entry_type = raw[offset]
            if entry_type == END_OF_DIRECTORY:
                break
            if entry_type != FILE_ENTRY_INUSE:
                # Volume label / bitmap / upcase and padding entries are skipped,
                # mirroring the production parser's _non_file_entries path.
                offset += DIR_ENTRY_SIZE
                continue
            subentry_count = raw[offset + METADATA_SUBENTRY_OFFSET]
            if subentry_count < 2:
                raise MalformedImage(f"file entry declares only {subentry_count} secondary entries")
            stream_offset = offset + DIR_ENTRY_SIZE
            if stream_offset + DIR_ENTRY_SIZE > len(raw):
                raise MalformedImage("stream entry runs past directory boundary")
            if raw[stream_offset] != STREAM_ENTRY_INUSE:
                raise MalformedImage(f"expected stream secondary entry, got 0x{raw[stream_offset]:02x}")
            fn_count = subentry_count - 1
            filename_end = stream_offset + (1 + fn_count) * DIR_ENTRY_SIZE
            if filename_end > len(raw):
                raise MalformedImage("entry-set overflows its directory cluster")
            for idx in range(fn_count):
                fn_offset = stream_offset + (1 + idx) * DIR_ENTRY_SIZE
                if raw[fn_offset] != FILENAME_ENTRY_INUSE:
                    raise MalformedImage("expected filename secondary entry")
            attributes = struct.unpack_from("<H", raw, offset + 0x04)[0]
            location = struct.unpack_from("<I", raw, stream_offset + STREAM_LOCATION_OFFSET)[0]
            data_length = struct.unpack_from("<Q", raw, stream_offset + STREAM_DATA_LENGTH_OFFSET)[0]
            flags = raw[stream_offset + 0x01]
            not_fragmented = bool(flags & 0x02)
            sets.append((bool(attributes & ATTRIBUTE_DIRECTORY), location, data_length, not_fragmented))
            offset = filename_end
        return sets

    def walk(self) -> Outcome:
        """Walk the directory tree iteratively with a directory visited-set."""
        visited: set[int] = set()
        # (cluster, depth, not_fragmented). The root dir is always FAT-backed.
        stack: list[tuple[int, int, bool]] = [(self.root_dir_cluster, 0, False)]
        while stack:
            location, depth, not_fragmented = stack.pop()
            self.budget.charge_directory(depth)
            if location in visited:
                raise ExhaustionError(f"directory back-edge detected at cluster {location}")
            visited.add(location)
            raw = self._directory_bytes(location, not_fragmented=not_fragmented, declared_size=0)
            for is_directory, child_location, _data_length, child_not_fragmented in self._entry_sets(raw):
                self.budget.charge_entry()
                if is_directory:
                    stack.append((child_location, depth + 1, child_not_fragmented))
        return Outcome.OK


def classify(image: bytes, budget: Budget | None = None) -> Outcome:
    """Convenience wrapper returning the :class:`Outcome` for an image."""
    walker = BoundedExfatWalker(image, budget)
    try:
        return walker.walk()
    except ExhaustionError:
        return Outcome.EXHAUSTION
    except MalformedImage:
        return Outcome.MALFORMED
