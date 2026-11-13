"""Forensic cross-format cluster-chain verification for FAT12, FAT16 and FAT32.

These tests never derive expectations from the production runlist code. Instead a tiny, independent
FAT-table encoder writes short synthetic volumes from hand-written *logical cluster sequences*.
The same logical layout (same chain shapes, same cluster numbers) is encoded in all three formats
and the production ``get`` / ``chain`` / ``runlist`` and file extraction are checked against it.

The checks are layered so a failure pinpoints the broken stage:
  * bitfield decoding  -> FAT12 even/odd nibble sharing and sector-crossing reads, FAT32 high nibble;
  * chain state        -> free / bad / reserved / end-of-chain entries stop or reject a chain;
  * run merging        -> contiguous clusters collapse into a single run, fragments stay split;
  * extraction         -> the reconstructed file bytes follow the logical order.
"""

from __future__ import annotations

import io
import struct
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterator

import pytest

from dissect.fat import fat
from dissect.fat.c_fat import (
    BAD_CLUSTER,
    DATA_CLUSTER_MAX,
    DATA_CLUSTER_MIN,
    END_OF_CLUSTER_MAX,
    END_OF_CLUSTER_MIN,
    FREE_CLUSTER,
    Fattype,
)
from dissect.fat.exceptions import BadClusterError, FreeClusterError
from dissect.util.stream import RangeStream

SECTOR_SIZE = 512
SECTORS_PER_CLUS = 1
CLUSTER_SIZE = SECTOR_SIZE * SECTORS_PER_CLUS

# FAT entry bookkeeping values expressed in the *logical* (28-bit) number space.
# These are pinned to the on-disk FAT spec (fatgen103), not imported from production, so a wrong
# production constant cannot make the test oracle silently move with the code under test.
FAT32_HIGH_NIBBLE = 0xF0000000  # reserved FAT32 bits that a decoder must ignore
FAT12_BAD = 0xFF7
FAT16_BAD = 0xFFF7
SPEC_FAT12_EOC = 0xFF0  # FAT12-specific end-of-chain code
FAT12_EOC = SPEC_FAT12_EOC  # local alias used by the state oracle and encoders
FAT16_EOC = 0xFFF8
FAT32_EOC = 0x0FFFFFF8
RESERVED_LOGICAL = {
    Fattype.FAT12: 0xFF2,
    Fattype.FAT16: 0xFFF2,
    Fattype.FAT32: 0x0FFFFFF2,
}

# Marker entries shared (by logical cluster number) by every synthetic volume.
FREE_MARKER = 10
BAD_MARKER = 11
RESERVED_MARKER = 12
EOC_MARKER = 13

# FAT-level decode tables exercise every nibble combination and sector boundaries.
TABLE_ENTRY_COUNT = {Fattype.FAT12: 682, Fattype.FAT16: 512, Fattype.FAT32: 256}


@dataclass(frozen=True)
class FileLayout:
    """A file described purely by its logical cluster sequence and byte size."""

    name: str
    chain: tuple[int, ...]
    size: int


# The identical logical layout encoded for FAT12, FAT16 and FAT32.
FILE_LAYOUTS = (
    FileLayout("CONTIG.TXT", (3, 4, 5, 6), 4 * CLUSTER_SIZE),
    FileLayout("FRAG.TXT", (7, 9, 14, 15, 20), 5 * CLUSTER_SIZE),
    FileLayout("SHORT.TXT", (16, 17), CLUSTER_SIZE + 128),  # last cluster is a short read
)


def reference_runlist(chain: tuple[int, ...]) -> list[tuple[int, int]]:
    """Independent oracle: merge a *logical* cluster sequence into (lcn, length) runs.

    LCNs are zero-based data cluster numbers, so FAT cluster numbers are shifted by the two
    reserved clusters. Boundaries are detected by non-adjacent successors in the logical sequence,
    rather than by replaying the production running-offset logic.
    """
    boundaries = [0]
    boundaries += [index for index in range(1, len(chain)) if chain[index] != chain[index - 1] + 1]

    runs: list[tuple[int, int]] = []
    for left, right in zip(boundaries, boundaries[1:] + [len(chain)]):
        runs.append((chain[left] - 2, right - left))
    return runs


def reference_classify(fattype: Fattype, value: int) -> str:
    """Independent state oracle for a decoded FAT entry value."""
    if value == FREE_CLUSTER:
        return "free"
    if value == fat.mask(BAD_CLUSTER, _bits(fattype)):
        return "bad"
    # FAT12 dedicates the FAT12_EOC code to end-of-chain; its generic EOC band only starts at 0xFF8.
    if fattype == Fattype.FAT12 and value == FAT12_EOC:
        return "eoc"
    if fat.mask(END_OF_CLUSTER_MIN, _bits(fattype)) <= value <= fat.mask(END_OF_CLUSTER_MAX, _bits(fattype)):
        return "eoc"
    if DATA_CLUSTER_MIN <= value <= fat.mask(DATA_CLUSTER_MAX, _bits(fattype)):
        return "data"
    return "reserved"


def _bits(fattype: Fattype) -> int:
    return {Fattype.FAT12: 12, Fattype.FAT16: 16, Fattype.FAT32: 32}[fattype]


def _eoc_value(fattype: Fattype) -> int:
    return {Fattype.FAT12: FAT12_EOC, Fattype.FAT16: FAT16_EOC, Fattype.FAT32: FAT32_EOC}[fattype]


def _bad_value(fattype: Fattype) -> int:
    return {Fattype.FAT12: FAT12_BAD, Fattype.FAT16: FAT16_BAD, Fattype.FAT32: BAD_CLUSTER}[fattype]


def encode_fat_table(fattype: Fattype, entries: dict[int, int]) -> bytearray:
    """Encode a sparse map of cluster -> logical entry value into one raw FAT sector stream."""
    bits = _bits(fattype)
    highest = max(entries)
    if bits == 12:
        # Entries are packed 3 bytes per two clusters and share their middle byte.
        raw = bytearray((((highest + 1) * 3) + 1) // 2)
        for cluster, value in entries.items():
            packed_offset = cluster + cluster // 2
            if cluster & 1:
                # Odd entry: low nibble of the first byte and the whole second byte.
                raw[packed_offset] |= (value & 0x0F) << 4
                raw[packed_offset + 1] |= (value >> 4) & 0xFF
            else:
                # Even entry: the whole first byte and the low nibble of the second byte.
                raw[packed_offset] |= value & 0xFF
                raw[packed_offset + 1] |= (value >> 8) & 0x0F
        return raw

    width = bits // 8
    raw = bytearray((highest + 1) * width)
    for cluster, value in entries.items():
        struct.pack_into("<H" if width == 2 else "<I", raw, cluster * width, value)
    return raw


def _decode_pattern_value(cluster: int) -> int:
    """Deterministic 12-bit pattern covering both nibbles for every entry index."""
    return ((cluster * 7 + 3) & 0x0F) | (((cluster * 5 + 1) & 0x0F) << 4) | 0x00F


def build_decode_table(fattype: Fattype) -> tuple[RangeStream, bytes, dict[int, int]]:
    """A standalone FAT stream (two sectors), its raw bytes, and the independently expected values."""
    count = TABLE_ENTRY_COUNT[fattype]
    logical: dict[int, int] = {}
    for cluster in range(count):
        if cluster == FREE_MARKER:
            logical[cluster] = FREE_CLUSTER
        elif cluster == BAD_MARKER:
            logical[cluster] = _bad_value(fattype)
        elif cluster == RESERVED_MARKER:
            logical[cluster] = RESERVED_LOGICAL[fattype]
        elif cluster == EOC_MARKER:
            logical[cluster] = _eoc_value(fattype)
        elif cluster < 2:
            continue
        else:
            logical[cluster] = _decode_pattern_value(cluster)

    if fattype == Fattype.FAT32:
        stored = {cluster: value | FAT32_HIGH_NIBBLE for cluster, value in logical.items()}
    else:
        stored = dict(logical)
    stored[0] = _eoc_value(fattype)
    stored[1] = {Fattype.FAT12: 0xFFF, Fattype.FAT16: 0xFFFF, Fattype.FAT32: 0x0FFFFFFF}[fattype]

    raw = encode_fat_table(fattype, stored)
    padded = bytes(raw + bytearray(2 * SECTOR_SIZE - len(raw)))
    stream = RangeStream(io.BytesIO(padded), 0, len(padded))
    return stream, padded, logical


@dataclass(frozen=True)
class VolumeGeometry:
    fattype: Fattype
    reserved_sectors: int
    fat_sectors: int
    root_entries: int
    total_sectors: int
    root_cluster: int | None


_GEOMETRY = {
    Fattype.FAT12: VolumeGeometry(Fattype.FAT12, 1, 2, 16, 160, None),
    Fattype.FAT16: VolumeGeometry(Fattype.FAT16, 1, 2, 16, 12320, None),
    Fattype.FAT32: VolumeGeometry(Fattype.FAT32, 32, 2, 0, 131104, 2),
}


def build_volume(fattype: Fattype) -> io.BytesIO:
    """Encode FILE_LAYOUTS + state markers into a minimal but valid FAT volume image."""
    geometry = _GEOMETRY[fattype]
    image = bytearray(geometry.total_sectors * SECTOR_SIZE)

    root_dir_sectors = (geometry.root_entries * 32 + SECTOR_SIZE - 1) // SECTOR_SIZE
    first_data_sector = geometry.reserved_sectors + geometry.fat_sectors + root_dir_sectors

    # FAT entries: file chains, the FAT32 root directory, then the state markers.
    entries: dict[int, int] = {
        0: _eoc_value(fattype),
        1: {Fattype.FAT12: 0xFFF, Fattype.FAT16: 0xFFFF, Fattype.FAT32: 0x0FFFFFFF}[fattype],
        FREE_MARKER: FREE_CLUSTER,
        BAD_MARKER: _bad_value(fattype),
        RESERVED_MARKER: RESERVED_LOGICAL[fattype],
        EOC_MARKER: _eoc_value(fattype),
    }
    for layout in FILE_LAYOUTS:
        for cluster, next_cluster in zip(layout.chain, layout.chain[1:]):
            entries[cluster] = next_cluster
        entries[layout.chain[-1]] = _eoc_value(fattype)

    if fattype == Fattype.FAT32:
        entries[geometry.root_cluster] = _eoc_value(fattype)
        # Set the reserved high nibble on every non-zero entry; the 28-bit value itself is unchanged.
        stored_entries = {
            cluster: (value | FAT32_HIGH_NIBBLE if value else value) for cluster, value in entries.items()
        }
    else:
        stored_entries = entries

    fat_raw = encode_fat_table(fattype, stored_entries)
    fat_offset = geometry.reserved_sectors * SECTOR_SIZE
    image[fat_offset : fat_offset + len(fat_raw)] = fat_raw

    # Root directory: FAT12/16 use a fixed area, FAT32 stores it in root cluster 2.
    directory = bytearray(root_dir_sectors * SECTOR_SIZE if root_dir_sectors else CLUSTER_SIZE)
    for offset, layout in enumerate(sorted(FILE_LAYOUTS, key=lambda item: item.name)):
        directory[offset * 32 : offset * 32 + 32] = _pack_dirent(layout)

    if fattype == Fattype.FAT32:
        root_offset = first_data_sector * SECTOR_SIZE
    else:
        root_offset = fat_offset + geometry.fat_sectors * SECTOR_SIZE
    image[root_offset : root_offset + len(directory)] = directory

    # Distinct, position-aware payload bytes so fragment reordering is detectable on extraction.
    for layout in FILE_LAYOUTS:
        written = 0
        for index, cluster in enumerate(layout.chain):
            take = min(CLUSTER_SIZE, layout.size - written)
            payload = bytes([(cluster * 31 + index) & 0xFF]) * take
            cluster_offset = (first_data_sector + (cluster - 2) * SECTORS_PER_CLUS) * SECTOR_SIZE
            image[cluster_offset : cluster_offset + len(payload)] = payload
            written += take

    image[0:3] = b"\xeb\x3c\x90"
    struct.pack_into("<H", image, 11, SECTOR_SIZE)
    image[13] = SECTORS_PER_CLUS
    struct.pack_into("<H", image, 14, geometry.reserved_sectors)
    image[16] = 1
    struct.pack_into("<H", image, 17, geometry.root_entries)
    struct.pack_into("<H", image, 19, geometry.total_sectors if fattype != Fattype.FAT32 else 0)
    image[21] = 0xF8
    struct.pack_into("<H", image, 22, geometry.fat_sectors if fattype != Fattype.FAT32 else 0)
    struct.pack_into("<I", image, 32, geometry.total_sectors)

    if fattype == Fattype.FAT32:
        struct.pack_into("<I", image, 36, geometry.fat_sectors)
        struct.pack_into("<I", image, 44, geometry.root_cluster)
        image[64] = 0x80
        image[66] = 0x29
        struct.pack_into("<I", image, 67, 0x12345678)
        image[71:82] = b"LABEL      "
        image[82:90] = b"FAT32   "
    else:
        image[36] = 0x80
        image[38] = 0x29
        struct.pack_into("<I", image, 39, 0x12345678)
        image[43:54] = b"LABEL      "
        image[54:62] = {Fattype.FAT12: b"FAT12   ", Fattype.FAT16: b"FAT16   "}[fattype]
    image[510:512] = b"\x55\xaa"

    return io.BytesIO(bytes(image))


def _pack_dirent(layout: FileLayout) -> bytes:
    base, _, extension = layout.name.partition(".")
    name = f"{base:<8}{extension:<3}".encode("ibm437")
    first_cluster = layout.chain[0]
    return struct.pack(
        "<11sBBBHHHHHHHI",
        name,
        0x20,  # archive attribute
        0,
        0,
        0,
        0,
        0,
        (first_cluster >> 16) & 0xFFFF,
        0,
        0,
        first_cluster & 0xFFFF,
        layout.size,
    )


def expected_file_bytes(layout: FileLayout) -> bytes:
    """Oracle payload: bytes are generated per logical cluster, independent of the FAT format."""
    result = bytearray()
    for index, cluster in enumerate(layout.chain):
        take = min(CLUSTER_SIZE, layout.size - len(result))
        result += bytes([(cluster * 31 + index) & 0xFF]) * take
    return bytes(result)


@lru_cache(maxsize=None)
def _cached_volume(fattype: Fattype) -> fat.FATFS:
    return fat.FATFS(build_volume(fattype))


@pytest.fixture(params=[Fattype.FAT12, Fattype.FAT16, Fattype.FAT32], ids=["fat12", "fat16", "fat32"])
def volume(request: pytest.FixtureRequest) -> fat.FATFS:
    return _cached_volume(request.param)


@pytest.fixture
def fattype(volume: fat.FATFS) -> Fattype:
    return volume.type


def walk_chain(table: fat.FAT, start: int, bound: int = 256) -> list[int]:
    """Bounded chain walk: a non-terminating entry fails instead of hanging the test suite.

    A runaway chain either loops forever or dereferences an out-of-range cluster; both are raised as
    assertions so a broken termination judgment cannot wedge or silently escape the table.
    """
    seen: list[int] = []
    chain = table.chain(start)
    for _ in range(bound):
        try:
            seen.append(next(chain))
        except StopIteration:
            return seen
        except ValueError as exc:
            raise AssertionError(f"chain starting at {start} escaped the FAT table: {exc}") from exc
    raise AssertionError(f"chain starting at {start} never terminated: {seen}")


# --------------------------------------------------------------------------------------------------
# Layer 1: bitfield decoding
# --------------------------------------------------------------------------------------------------


def test_get_decodes_every_entry_and_ignores_fat32_high_nibble() -> None:
    for fattype in (Fattype.FAT12, Fattype.FAT16, Fattype.FAT32):
        stream, raw, expected = build_decode_table(fattype)
        table = fat.FAT(stream, fattype)

        for cluster, logical_value in expected.items():
            assert table.get(cluster) == logical_value, f"bitfield decode mismatch for {fattype.name} cluster {cluster}"

        if fattype == Fattype.FAT32:
            for cluster, logical_value in expected.items():
                stored = struct.unpack_from("<I", raw, cluster * 4)[0]
                assert stored & FAT32_HIGH_NIBBLE  # the reserved high bits are physically present
                assert table.get(cluster) == logical_value  # ...but must be stripped during decoding


def test_get_handles_fat12_nibble_sharing_across_sector_boundary() -> None:
    # Reading odd entry 341 pulls a 16-bit word at byte offset 511, i.e. bytes 511 and 512: the read
    # straddles the first 512-byte FAT sector. The (340, 341) pair shares byte 511.
    entries = {340: 0x123, 341: 0x456, 342: 0x789, 343: 0xABC}
    raw = bytes(encode_fat_table(Fattype.FAT12, entries)) + b"\x00" * 4
    stream = RangeStream(io.BytesIO(raw), 0, len(raw))
    table = fat.FAT(stream, Fattype.FAT12)

    assert [table.get(cluster) for cluster in entries] == [0x123, 0x456, 0x789, 0xABC]
    # Shared byte 511: low nibble of odd entry 341 (0x6) in the high nibble, high nibble of even
    # entry 340 (0x1) in the low nibble.
    shared_offset = 341 + 341 // 2
    assert raw[shared_offset] == ((0x456 & 0x0F) << 4) | ((0x123 >> 8) & 0x0F)
    assert shared_offset == 511  # the 16-bit word read crosses into the next sector at byte 512


def test_get_rejects_cluster_past_table_end() -> None:
    stream, _, _ = build_decode_table(Fattype.FAT16)
    table = fat.FAT(stream, Fattype.FAT16)
    with pytest.raises(ValueError):
        table.get(TABLE_ENTRY_COUNT[Fattype.FAT16])


# --------------------------------------------------------------------------------------------------
# Layer 2: chain state (free, bad, reserved, end-of-chain)
# --------------------------------------------------------------------------------------------------


def test_chain_state_matches_independent_classifier(fattype: Fattype) -> None:
    table = _cached_volume(fattype).fat
    probes = {
        FREE_MARKER: "free",
        BAD_MARKER: "bad",
        RESERVED_MARKER: "reserved",
        EOC_MARKER: "eoc",
    }
    for cluster, expected_state in probes.items():
        assert reference_classify(fattype, table.get(cluster)) == expected_state
        assert (
            table.get(cluster)
            == {
                "free": FREE_CLUSTER,
                "bad": _bad_value(fattype),
                "reserved": RESERVED_LOGICAL[fattype],
                "eoc": _eoc_value(fattype),
            }[expected_state]
        )


def test_free_and_bad_entries_reject_the_chain(fattype: Fattype) -> None:
    table = _cached_volume(fattype).fat

    with pytest.raises(FreeClusterError):
        walk_chain(table, FREE_MARKER)
    with pytest.raises(BadClusterError):
        walk_chain(table, BAD_MARKER)


def test_reserved_entry_is_never_accepted_as_data(fattype: Fattype) -> None:
    # A reserved value sits in the gap between the largest data cluster and the bad-cluster code.
    # The independent state oracle must label it "reserved" and it must never satisfy the data or
    # end-of-chain bands that legitimately continue or terminate a chain.
    reserved_value = RESERVED_LOGICAL[fattype]

    assert reference_classify(fattype, reserved_value) == "reserved"
    assert not (DATA_CLUSTER_MIN <= reserved_value <= fat.mask(DATA_CLUSTER_MAX, _bits(fattype)))
    assert not (
        fat.mask(END_OF_CLUSTER_MIN, _bits(fattype)) <= reserved_value <= fat.mask(END_OF_CLUSTER_MAX, _bits(fattype))
    )
    assert reserved_value != fat.mask(BAD_CLUSTER, _bits(fattype))
    assert reserved_value != FREE_CLUSTER

    # A reserved value cannot be a valid continuation. Encode a chain that reaches it: the walk
    # must surface a rejection rather than returning the reserved cluster as file data. The reserved
    # code names a cluster beyond this short table, so dereferencing it escapes the table.
    entries = {DATA_CLUSTER_MIN: reserved_value}
    if fattype == Fattype.FAT32:
        entries = {cluster: value | FAT32_HIGH_NIBBLE for cluster, value in entries.items()}
    raw = encode_fat_table(fattype, entries)
    stream = RangeStream(io.BytesIO(bytes(raw) + b"\x00" * SECTOR_SIZE), 0, len(raw) + SECTOR_SIZE)
    table = fat.FAT(stream, fattype)

    with pytest.raises(AssertionError, match="escaped the FAT table"):
        walk_chain(table, DATA_CLUSTER_MIN)


def test_end_of_chain_terminates_and_includes_last_cluster(fattype: Fattype) -> None:
    table = _cached_volume(fattype).fat
    for layout in FILE_LAYOUTS:
        assert walk_chain(table, layout.chain[0]) == list(layout.chain)

    assert walk_chain(table, EOC_MARKER) == [EOC_MARKER]


def test_last_valid_entry_before_table_end_still_terminates() -> None:
    for fattype in (Fattype.FAT12, Fattype.FAT16, Fattype.FAT32):
        last_cluster = TABLE_ENTRY_COUNT[fattype] - 2  # leave room for FAT12's two-cluster packing
        entries = {last_cluster: _eoc_value(fattype)}
        raw = encode_fat_table(fattype, entries)
        table_size = TABLE_ENTRY_COUNT[fattype] * _bits(fattype) // 8
        stream = RangeStream(io.BytesIO(bytes(raw) + bytearray(table_size - len(raw))), 0, table_size)
        table = fat.FAT(stream, fattype)

        assert walk_chain(table, last_cluster) == [last_cluster]


# --------------------------------------------------------------------------------------------------
# Layer 3: contiguous run merging against the logical oracle
# --------------------------------------------------------------------------------------------------


def test_runlist_matches_logical_sequence_oracle(volume: fat.FATFS) -> None:
    for layout in FILE_LAYOUTS:
        production = list(volume.fat.runlist(layout.chain[0]))
        assert production == reference_runlist(layout.chain)


def test_contiguous_chain_collapses_into_single_run(volume: fat.FATFS) -> None:
    contig = next(layout for layout in FILE_LAYOUTS if layout.name == "CONTIG.TXT")
    assert list(volume.fat.runlist(contig.chain[0])) == [(contig.chain[0] - 2, len(contig.chain))]


def test_fragmented_chain_keeps_every_gap_as_a_new_run(volume: fat.FATFS) -> None:
    frag = next(layout for layout in FILE_LAYOUTS if layout.name == "FRAG.TXT")
    runs = list(volume.fat.runlist(frag.chain[0]))
    assert runs == [(5, 1), (7, 1), (12, 2), (18, 1)]
    assert sum(run_length for _, run_length in runs) == len(frag.chain)


# --------------------------------------------------------------------------------------------------
# Layer 4: end-to-end get / chain / runlist / extraction consistency
# --------------------------------------------------------------------------------------------------


def test_same_logical_layout_is_consistent_across_all_formats(volume: fat.FATFS) -> None:
    entries = {entry.name: entry for entry in volume.root.iterdir()}
    assert set(entries) == {layout.name for layout in FILE_LAYOUTS}

    for layout in FILE_LAYOUTS:
        entry = entries[layout.name]
        assert entry.cluster == layout.chain[0]
        assert walk_chain(volume.fat, entry.cluster) == list(layout.chain)
        assert entry.dataruns() == reference_runlist(layout.chain)
        assert entry.open().read() == expected_file_bytes(layout)


def test_short_read_returns_declared_file_size(volume: fat.FATFS) -> None:
    short = next(layout for layout in FILE_LAYOUTS if layout.name == "SHORT.TXT")
    entry = next(item for item in volume.root.iterdir() if item.name == short.name)

    extracted = entry.open().read()
    assert len(extracted) == short.size
    assert extracted == expected_file_bytes(short)
    assert len(extracted) < sum(run_length for _, run_length in entry.dataruns()) * CLUSTER_SIZE


# --------------------------------------------------------------------------------------------------
# Regression mutations: the tests above must genuinely fail when the logic is broken
# --------------------------------------------------------------------------------------------------


class NibbleSwappedFAT(fat.FAT):
    """FAT12 decoder with the even/odd nibble selection reversed."""

    def get(self, cluster: int) -> int | None:  # type: ignore[override]
        if self.bits_per_entry != 12:
            return super().get(cluster)
        self.fh.seek(cluster + cluster // 2)
        value = struct.unpack("<H", self.fh.read(2))[0]
        return value & 0x0FFF if cluster & 1 else value >> 4


class WrongTerminationFAT(fat.FAT):
    """FAT12 chain walker whose termination judgment omits the FAT12-specific EOC code.

    A genuine FAT12_EOC (0xFF0) marker then falls through every branch and the chain keeps
    following entries, proving that the state-judgment layer (not bitfield decoding or run
    merging) is responsible for stopping a chain.
    """

    def chain(self, cluster: int) -> Iterator[int]:  # type: ignore[override]
        while True:
            value = self.get(cluster)
            if DATA_CLUSTER_MIN <= value <= fat.mask(DATA_CLUSTER_MAX, self.bits_per_entry):
                yield cluster
            elif value > FAT12_EOC and value <= fat.mask(END_OF_CLUSTER_MAX, self.bits_per_entry):
                # Wrong lower bound: the FAT12-specific FAT12_EOC (0xFF0) code falls just below it.
                yield cluster
                return
            elif value == fat.mask(BAD_CLUSTER, self.bits_per_entry):
                raise BadClusterError(cluster)
            elif value == FREE_CLUSTER:
                raise FreeClusterError(cluster)
            else:
                cluster = value


def test_mutation_wrong_fat12_nibble_selection_is_caught() -> None:
    stream, _, expected = build_decode_table(Fattype.FAT12)
    correct = fat.FAT(stream, Fattype.FAT12)
    broken = NibbleSwappedFAT(stream, Fattype.FAT12)

    mismatches = [cluster for cluster in expected if broken.get(cluster) != correct.get(cluster)]
    assert mismatches  # the bitfield-decoding layer must detect the swapped nibbles
    with pytest.raises(AssertionError, match="bitfield decode mismatch"):
        for cluster, value in expected.items():
            assert broken.get(cluster) == value, f"bitfield decode mismatch for FAT12 cluster {cluster}"


def test_mutation_wrong_termination_code_is_caught() -> None:
    # The FAT12 EOC marker is encoded at a spec-pinned value (0xFF0). A correct walker stops on it;
    # a walker whose termination judgment drops that code treats it as a cluster pointer and runs
    # past the end of the table, which the bounded walk reports as a non-terminating chain.
    entries = {EOC_MARKER: FAT12_EOC}
    raw = encode_fat_table(Fattype.FAT12, entries)
    stream = RangeStream(io.BytesIO(bytes(raw)), 0, len(raw))
    correct = fat.FAT(stream, Fattype.FAT12)
    broken = WrongTerminationFAT(stream, Fattype.FAT12)

    assert correct.get(EOC_MARKER) == FAT12_EOC
    assert reference_classify(Fattype.FAT12, FAT12_EOC) == "eoc"
    assert walk_chain(correct, EOC_MARKER) == [EOC_MARKER]

    with pytest.raises(AssertionError, match=r"never terminated|escaped the FAT table"):
        walk_chain(broken, EOC_MARKER)
