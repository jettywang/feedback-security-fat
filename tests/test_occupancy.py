"""Tests for the read-only FAT cluster occupancy analysis.

A small FAT12 image is built entirely in memory. Besides legitimate directory
aliases (``.`` / ``..``) it deliberately contains:

- two files whose cluster chains cross and then merge into a shared tail;
- a linear orphan chain and a cyclic orphan chain (allocated, never referenced);
- a file whose chain runs into a bad cluster;
- a normal file and a normal subdirectory as control objects.
"""
from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

import pytest

from dissect.fat.c_fat import c_fat
from dissect.fat.fat import FATFS
from dissect.fat.occupancy import (
    ByteRange,
    EdgeType,
    TerminationReason,
    analyze,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.fat.occupancy import OccupancyGraph, Occupant

SECTOR_SIZE = 512
SECTORS_PER_CLUSTER = 4
CLUSTER_SIZE = SECTOR_SIZE * SECTORS_PER_CLUSTER
RESERVED_SECTORS = 2
FAT_COUNT = 2
ROOT_ENTRIES = 16
TOTAL_SECTORS = 36
ROOT_DIR_SECTORS = (ROOT_ENTRIES * 32) // SECTOR_SIZE
FAT_SECTORS = 2
FIRST_DATA_SECTOR = RESERVED_SECTORS + FAT_COUNT * FAT_SECTORS + ROOT_DIR_SECTORS

CLUSTER_SUBDIR = 2
CLUSTER_FILE_A = 3
CLUSTER_SHARED = 4
CLUSTER_FILE_B = 5
CLUSTER_GOOD = 6
CLUSTER_BAD_REF = 7
CLUSTER_BAD = 8
CLUSTER_ORPHAN_1 = 9
CLUSTER_ORPHAN_2 = 10
CLUSTER_CYCLE_1 = 11
CLUSTER_CYCLE_2 = 12
CLUSTER_INSIDE = 13


def _fat12_pack(entries: dict[int, int]) -> bytes:
    highest = max(entries)
    buf = bytearray(((highest + 1) * 3 + 1) // 2)
    for cluster, value in entries.items():
        offset = cluster + cluster // 2
        if cluster & 1:
            buf[offset] |= (value & 0x0F) << 4
            buf[offset + 1] = value >> 4
        else:
            buf[offset] = value & 0xFF
            buf[offset + 1] |= (value >> 8) & 0x0F
    return bytes(buf)


def _dir_entry(
    name: str,
    first_cluster: int,
    size: int,
    attr: int,
) -> bytes:
    struct = c_fat.Dirent()
    struct.DIR_Name = name.encode("ibm437").ljust(11, b" ")
    struct.DIR_Attr = attr
    struct.DIR_FstClusHI = (first_cluster >> 16) & 0xFFFF
    struct.DIR_FstClusLO = first_cluster & 0xFFFF
    struct.DIR_FileSize = size
    return struct.dumps()


def _build_image() -> BytesIO:
    image = bytearray(TOTAL_SECTORS * SECTOR_SIZE)

    boot = c_fat.Bpb()
    boot.BS_jmpBoot = b"\xeb\x3c\x90"
    boot.BS_OEMName = b"MSWIN4.1"
    boot.BPB_BytsPerSec = SECTOR_SIZE
    boot.BPB_SecPerClus = SECTORS_PER_CLUSTER
    boot.BPB_RsvdSecCnt = RESERVED_SECTORS
    boot.BPB_NumFATs = FAT_COUNT
    boot.BPB_RootEntCnt = ROOT_ENTRIES
    boot.BPB_TotSec16 = TOTAL_SECTORS
    boot.BPB_Media = 0xF8
    boot.BPB_FATSz16 = FAT_SECTORS

    boot_ext = c_fat.Bpb16()
    boot_ext.BS_BootSig = 0x29
    boot_ext.BS_VolID = 0x11223344
    boot_ext.BS_VolLab = b"OCCUPANCY" + b" " * 2
    boot_ext.BS_FilSysType = b"FAT12   "

    image[0 : len(boot.dumps())] = boot.dumps()
    image[len(boot.dumps()) : len(boot.dumps()) + len(boot_ext.dumps())] = boot_ext.dumps()

    fat_entries = {
        0: 0xFF8,
        1: 0xFFF,
        CLUSTER_SUBDIR: 0xFFF,
        CLUSTER_FILE_A: CLUSTER_SHARED,
        CLUSTER_SHARED: 0xFFF,
        CLUSTER_FILE_B: CLUSTER_SHARED,
        CLUSTER_GOOD: 0xFFF,
        CLUSTER_BAD_REF: CLUSTER_BAD,
        CLUSTER_BAD: 0xFF7,
        CLUSTER_ORPHAN_1: CLUSTER_ORPHAN_2,
        CLUSTER_ORPHAN_2: 0xFFF,
        CLUSTER_CYCLE_1: CLUSTER_CYCLE_2,
        CLUSTER_CYCLE_2: CLUSTER_CYCLE_1,
        CLUSTER_INSIDE: 0xFFF,
    }
    fat_blob = _fat12_pack(fat_entries)
    for fat_index in range(FAT_COUNT):
        fat_offset = (RESERVED_SECTORS + fat_index * FAT_SECTORS) * SECTOR_SIZE
        image[fat_offset : fat_offset + len(fat_blob)] = fat_blob

    root_offset = (RESERVED_SECTORS + FAT_COUNT * FAT_SECTORS) * SECTOR_SIZE
    root_entries = b"".join(
        [
            _dir_entry("OCCUPANCY" + " " * 2, 0, 0, c_fat.ATTR_VOLUME_ID),
            _dir_entry("CROSS_A TXT", CLUSTER_FILE_A, 3 * CLUSTER_SIZE, 0),
            _dir_entry("CROSS_B TXT", CLUSTER_FILE_B, CLUSTER_SIZE + 128, 0),
            _dir_entry("GOOD    TXT", CLUSTER_GOOD, 128, 0),
            _dir_entry("BADREF  TXT", CLUSTER_BAD_REF, 2 * CLUSTER_SIZE, 0),
            _dir_entry("SUBDIR     ", CLUSTER_SUBDIR, CLUSTER_SIZE, c_fat.ATTR_DIRECTORY),
        ]
    )
    image[root_offset : root_offset + len(root_entries)] = root_entries

    subdir_entries = b"".join(
        [
            _dir_entry(".          ", CLUSTER_SUBDIR, 0, c_fat.ATTR_DIRECTORY),
            _dir_entry("..         ", 0, 0, c_fat.ATTR_DIRECTORY),
            _dir_entry("INSIDE  TXT", CLUSTER_INSIDE, 128, 0),
        ]
    )
    subdir_offset = _cluster_offset(CLUSTER_SUBDIR)
    image[subdir_offset : subdir_offset + len(subdir_entries)] = subdir_entries

    contents = {
        CLUSTER_FILE_A: b"AAAA cluster 3 (only cross A reaches here)\n",
        CLUSTER_SHARED: b"SSSS shared tail cluster 4 (both files)\n",
        CLUSTER_FILE_B: b"BBBB cluster 5 (only cross B reaches here)\n",
        CLUSTER_GOOD: b"GOOD cluster 6\n",
        CLUSTER_BAD_REF: b"RRRR cluster 7 before the bad cluster\n",
        CLUSTER_ORPHAN_1: b"ORPHAN linear cluster 9\n",
        CLUSTER_ORPHAN_2: b"ORPHAN linear cluster 10\n",
        CLUSTER_CYCLE_1: b"CYCLE cluster 11\n",
        CLUSTER_CYCLE_2: b"CYCLE cluster 12\n",
        CLUSTER_INSIDE: b"INSIDE cluster 13\n",
    }
    for cluster, payload in contents.items():
        offset = _cluster_offset(cluster)
        image[offset : offset + len(payload)] = payload

    return BytesIO(bytes(image))


def _cluster_offset(cluster: int) -> int:
    return (FIRST_DATA_SECTOR + (cluster - 2) * SECTORS_PER_CLUSTER) * SECTOR_SIZE


@pytest.fixture
def occupancy_image() -> Iterator[BinaryIO]:
    yield _build_image()


def _by_path(graph: OccupancyGraph) -> dict[str, Occupant]:
    return {occupant.path: occupant for occupant in graph.occupants.values()}


def test_basic_layout_and_directory_aliases(occupancy_image: BinaryIO) -> None:
    fs = FATFS(occupancy_image)
    graph = analyze(fs)

    names = set(_by_path(graph))
    assert names == {
        "",
        "CROSS_A.TXT",
        "CROSS_B.TXT",
        "GOOD.TXT",
        "BADREF.TXT",
        "SUBDIR",
        "SUBDIR\\INSIDE.TXT",
    }

    aliases = {(alias.name, alias.target_cluster) for alias in graph.aliases}
    assert aliases == {(".", CLUSTER_SUBDIR), ("..", None)}

    alias_edges = [edge for edge in graph.edges if edge.type == EdgeType.ALIAS_EDGE]
    assert len(alias_edges) == 2
    assert all(edge.detail is None for edge in alias_edges)

    alias_nodes = {edge.source for edge in alias_edges}
    assert alias_nodes == {"SUBDIR"}


def test_cross_linked_files_pinpoint_first_conflict_and_shared_tail(occupancy_image: BinaryIO) -> None:
    fs = FATFS(occupancy_image)
    graph = analyze(fs)

    occupants = _by_path(graph)
    id_a = occupants["CROSS_A.TXT"].id
    id_b = occupants["CROSS_B.TXT"].id

    assert occupants["CROSS_A.TXT"].cluster_chain == [CLUSTER_FILE_A, CLUSTER_SHARED]
    assert occupants["CROSS_B.TXT"].cluster_chain == [CLUSTER_FILE_B, CLUSTER_SHARED]

    assert len(graph.conflicts) == 1
    conflict = graph.conflicts[0]
    assert set(conflict.occupant_ids) == {id_a, id_b}
    assert conflict.shared_clusters == (CLUSTER_SHARED,)
    assert conflict.first_conflict == CLUSTER_SHARED
    assert conflict.shared_tail == (CLUSTER_SHARED,)

    assert graph.range_for(id_a, CLUSTER_SHARED) == ByteRange(CLUSTER_SIZE, 2 * CLUSTER_SIZE, False)
    range_b = graph.range_for(id_b, CLUSTER_SHARED)
    assert (range_b.start, range_b.end, range_b.clamped) == (CLUSTER_SIZE, CLUSTER_SIZE + 128, True)

    assert graph.clusters[CLUSTER_SHARED].is_shared
    assert len({ref.occupant_id for ref in graph.clusters[CLUSTER_SHARED].references}) == 2


def test_orphan_chains_include_linear_and_cyclic_terminations(occupancy_image: BinaryIO) -> None:
    fs = FATFS(occupancy_image)
    graph = analyze(fs)

    orphan_sets = {chain.clusters: chain.termination.reason for chain in graph.orphans}
    assert orphan_sets[(CLUSTER_ORPHAN_1, CLUSTER_ORPHAN_2)] == TerminationReason.END_OF_CHAIN
    assert orphan_sets[(CLUSTER_CYCLE_1, CLUSTER_CYCLE_2)] == TerminationReason.CYCLE

    orphan_cluster_numbers = {info.cluster for info in graph.orphan_clusters()}
    assert orphan_cluster_numbers == {
        CLUSTER_ORPHAN_1,
        CLUSTER_ORPHAN_2,
        CLUSTER_CYCLE_1,
        CLUSTER_CYCLE_2,
    }


def test_bad_cluster_is_a_termination_reason_not_a_global_flag(occupancy_image: BinaryIO) -> None:
    fs = FATFS(occupancy_image)
    graph = analyze(fs)

    badref = _by_path(graph)["BADREF.TXT"]
    assert badref.cluster_chain == [CLUSTER_BAD_REF, CLUSTER_BAD]
    assert badref.termination.reason == TerminationReason.BAD_CLUSTER
    assert badref.termination.at == CLUSTER_BAD
    assert graph.clusters[CLUSTER_BAD].fat_value == 0xFF7

    good = _by_path(graph)["GOOD.TXT"]
    assert good.termination.reason == TerminationReason.END_OF_CHAIN
    assert good.cluster_chain == [CLUSTER_GOOD]


def test_report_names_files_and_byte_ranges(occupancy_image: BinaryIO) -> None:
    fs = FATFS(occupancy_image)
    graph = analyze(fs)
    report = graph.to_text()

    assert "first conflict at cluster 4" in report
    assert "CROSS_A.TXT" in report and "CROSS_B.TXT" in report
    assert f"[{CLUSTER_SIZE}, {2 * CLUSTER_SIZE})" in report
    assert f"[{CLUSTER_SIZE}, {CLUSTER_SIZE + 128}) (clamped to size)" in report
    assert "cycle at cluster 11" in report
    assert "bad_cluster at cluster 8" in report


def _image_with_first_fat(entries: dict[int, int]) -> BytesIO:
    image = bytearray(_build_image().getvalue())
    blob = _fat12_pack(entries)
    fat_offset = RESERVED_SECTORS * SECTOR_SIZE
    image[fat_offset : fat_offset + len(blob)] = blob
    return BytesIO(bytes(image))


def test_directory_cluster_cycle_terminates_and_keeps_children() -> None:
    entries = {
        0: 0xFF8,
        1: 0xFFF,
        CLUSTER_SUBDIR: CLUSTER_SUBDIR,
        CLUSTER_FILE_A: CLUSTER_SHARED,
        CLUSTER_SHARED: 0xFFF,
        CLUSTER_FILE_B: CLUSTER_SHARED,
        CLUSTER_GOOD: 0xFFF,
        CLUSTER_BAD_REF: CLUSTER_BAD,
        CLUSTER_BAD: 0xFF7,
        CLUSTER_ORPHAN_1: CLUSTER_ORPHAN_2,
        CLUSTER_ORPHAN_2: 0xFFF,
        CLUSTER_CYCLE_1: CLUSTER_CYCLE_2,
        CLUSTER_CYCLE_2: CLUSTER_CYCLE_1,
        CLUSTER_INSIDE: 0xFFF,
    }

    graph = analyze(FATFS(_image_with_first_fat(entries)))

    subdir = _by_path(graph)["SUBDIR"]
    assert subdir.termination.reason == TerminationReason.CYCLE
    assert subdir.termination.at == CLUSTER_SUBDIR
    assert subdir.cluster_chain == [CLUSTER_SUBDIR]
    assert "SUBDIR\\INSIDE.TXT" in _by_path(graph)


def test_free_cluster_mid_chain_is_a_termination_reason() -> None:
    entries = {
        0: 0xFF8,
        1: 0xFFF,
        CLUSTER_SUBDIR: 0xFFF,
        CLUSTER_FILE_A: CLUSTER_INSIDE,
        CLUSTER_INSIDE: 0x000,
        CLUSTER_SHARED: 0xFFF,
        CLUSTER_FILE_B: CLUSTER_SHARED,
        CLUSTER_GOOD: 0xFFF,
        CLUSTER_BAD_REF: CLUSTER_BAD,
        CLUSTER_BAD: 0xFF7,
        CLUSTER_ORPHAN_1: CLUSTER_ORPHAN_2,
        CLUSTER_ORPHAN_2: 0xFFF,
        CLUSTER_CYCLE_1: CLUSTER_CYCLE_2,
        CLUSTER_CYCLE_2: CLUSTER_CYCLE_1,
    }

    graph = analyze(FATFS(_image_with_first_fat(entries)))

    cross_a = _by_path(graph)["CROSS_A.TXT"]
    assert cross_a.cluster_chain == [CLUSTER_FILE_A, CLUSTER_INSIDE]
    assert cross_a.termination.reason == TerminationReason.FREE_CLUSTER
    assert cross_a.termination.at == CLUSTER_INSIDE
    assert cross_a.termination.value == 0

