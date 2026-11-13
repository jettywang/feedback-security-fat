from __future__ import annotations

import struct
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

import pytest

from dissect.fat.c_fat import c_fat
from dissect.fat.fat_diagnostics import (
    EXTFLAGS_ACTIVE_FAT_MASK,
    EXTFLAGS_MIRROR_DISABLED,
    diagnose,
    render_text,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

BYTES_PER_SEC = 512
SEC_PER_CLUS = 1
RSVD_SECTORS = 32
NUM_FATS = 2
FAT_SIZE_SECTORS = 512
FAT_ENTRIES = FAT_SIZE_SECTORS * BYTES_PER_SEC // 4
ROOT_CLUS = 2
SUBDIR_CLUS = 3
FILE_A_CLUS = 4
FILE_B_CLUS = 5
FILE_C_CLUS = 6
EOC = 0x0FFFFFFF


class FAT32ImageBuilder:
    """Minimal, sparse FAT32 image builder used to synthesize divergence samples."""

    def __init__(self, path: Path, ext_flags: int) -> None:
        self.path = path
        self.ext_flags = ext_flags
        self.fats: list[dict[int, int]] = [{}, {}]
        self.cluster_data: dict[int, bytes] = {}
        self.root_entries: list[bytes] = []
        self.subdir_entries: list[bytes] = []
        self.truncate_at: int | None = None

        for fat in self.fats:
            fat[0] = 0x0FFFF000 | 0xF8
            fat[1] = EOC
            fat[ROOT_CLUS] = EOC
            fat[SUBDIR_CLUS] = EOC

    def set_fat(self, fat_index: int, mapping: dict[int, int]) -> None:
        self.fats[fat_index].update(mapping)

    def add_file(self, name: str, cluster: int, size: int, data: bytes, subdir: bool = False) -> None:
        self.cluster_data[cluster] = data
        target = self.subdir_entries if subdir else self.root_entries
        target.append(_short_dirent(name, cluster, size, c_fat.ATTR_ARCHIVE))

    def finalize(self) -> None:
        self.root_entries.append(_volume_label("EVIDENCE"))
        self.root_entries.append(_short_dirent("SUBDIR1", SUBDIR_CLUS, 0, c_fat.ATTR_DIRECTORY))
        self.subdir_entries.insert(0, _dot_dirent(SUBDIR_CLUS))
        self.subdir_entries.insert(1, _dotdot_dirent(ROOT_CLUS))

        self.cluster_data[ROOT_CLUS] = b"".join(self.root_entries)
        self.cluster_data[SUBDIR_CLUS] = b"".join(self.subdir_entries)

        total_sectors = RSVD_SECTORS + NUM_FATS * FAT_SIZE_SECTORS + FAT_ENTRIES
        with self.path.open("wb") as fh:
            fh.write(_boot_sector(self.ext_flags, total_sectors))
            fh.truncate(total_sectors * BYTES_PER_SEC)

            for index, fat in enumerate(self.fats):
                _write_fat(fh, index, fat)
            for cluster, data in self.cluster_data.items():
                fh.seek(_cluster_offset(cluster))
                fh.write(data)

            if self.truncate_at is not None:
                fh.truncate(self.truncate_at)


def _boot_sector(ext_flags: int, total_sectors: int) -> bytes:
    bpb = struct.pack(
        "<3s8sH B H B H H B H H H I I",
        b"\xeb\x58\x90",
        b"MSWIN4.1",
        BYTES_PER_SEC,
        SEC_PER_CLUS,
        RSVD_SECTORS,
        NUM_FATS,
        0,
        0,
        0xF8,
        0,
        63,
        255,
        0,
        total_sectors,
    )
    bpb32 = struct.pack(
        "<I H H I H H 12s B B B I 11s 8s",
        FAT_SIZE_SECTORS,
        ext_flags,
        0,
        ROOT_CLUS,
        1,
        6,
        b"\x00" * 12,
        0x80,
        0,
        0x29,
        0x12345678,
        b"EVIDENCE   ",
        b"FAT32   ",
    )
    sector = bpb + bpb32
    return sector + b"\x00" * (BYTES_PER_SEC - len(sector))


def _write_fat(fh: BinaryIO, index: int, entries: dict[int, int]) -> None:
    base = (RSVD_SECTORS + index * FAT_SIZE_SECTORS) * BYTES_PER_SEC
    for entry, value in entries.items():
        fh.seek(base + entry * 4)
        fh.write(struct.pack("<I", value))


def _cluster_offset(cluster: int) -> int:
    first_data_sector = RSVD_SECTORS + NUM_FATS * FAT_SIZE_SECTORS
    return (first_data_sector + (cluster - 2) * SEC_PER_CLUS) * BYTES_PER_SEC


def _pack_dirent(dir_name: bytes, attr: int, cluster: int, size: int) -> bytes:
    return struct.pack(
        "<11sBBBHHHHHHHI",
        dir_name,
        attr,
        0,
        0,
        0,
        0,
        0,
        cluster >> 16,
        0,
        0,
        cluster & 0xFFFF,
        size,
    )


def _short_dirent(name: str, cluster: int, size: int, attr: int) -> bytes:
    base, ext = (name.split(".") + [""])[:2] if "." in name else (name, "")
    dir_name = base.upper().ljust(8)[:8] + ext.upper().ljust(3)[:3]
    return _pack_dirent(dir_name.encode("ascii"), attr, cluster, size)


def _volume_label(label: str) -> bytes:
    return _pack_dirent(label.upper().ljust(11)[:11].encode("ascii"), c_fat.ATTR_VOLUME_ID, 0, 0)


def _dot_dirent(cluster: int) -> bytes:
    return _pack_dirent(b".          ", c_fat.ATTR_DIRECTORY, cluster, 0)


def _dotdot_dirent(cluster: int) -> bytes:
    return _pack_dirent(b"..         ", c_fat.ATTR_DIRECTORY, cluster, 0)


def _open(path: Path) -> Iterator[BinaryIO]:
    with path.open("rb") as fh:
        yield fh


@pytest.fixture
def sample_mirror_disabled_active_fat1(tmp_path: Path) -> Iterator[BinaryIO]:
    path = tmp_path / "sample_a.bin"
    builder = FAT32ImageBuilder(path, EXTFLAGS_MIRROR_DISABLED | 1)
    builder.add_file("FILE_A.TXT", FILE_A_CLUS, 5, b"AAAAA")
    builder.add_file("FILE_B.TXT", FILE_B_CLUS, 5, b"BBBBB")
    builder.add_file("FILE_C.TXT", FILE_C_CLUS, 5, b"CCCCC", subdir=True)

    builder.set_fat(0, {FILE_A_CLUS: EOC, FILE_B_CLUS: EOC, FILE_C_CLUS: EOC})
    builder.set_fat(1, {FILE_A_CLUS: 0x0FFFFFF8, FILE_B_CLUS: EOC, FILE_C_CLUS: EOC})
    builder.finalize()
    yield from _open(path)


@pytest.fixture
def sample_plausible_tail_divergence(tmp_path: Path) -> Iterator[BinaryIO]:
    path = tmp_path / "sample_b.bin"
    builder = FAT32ImageBuilder(path, 0)
    builder.add_file("FILE_A.TXT", FILE_A_CLUS, 5, b"AAAAA")
    builder.add_file("FILE_B.TXT", FILE_B_CLUS, 5, b"BBBBB")

    builder.set_fat(0, {FILE_A_CLUS: EOC, FILE_B_CLUS: EOC})
    builder.set_fat(1, {FILE_A_CLUS: 0x0FFFFFF8, FILE_B_CLUS: EOC})
    builder.finalize()
    yield from _open(path)


@pytest.fixture
def sample_truncated_second_fat(tmp_path: Path) -> Iterator[BinaryIO]:
    path = tmp_path / "sample_c.bin"
    builder = FAT32ImageBuilder(path, 0)
    builder.add_file("FILE_A.TXT", FILE_A_CLUS, 5, b"AAAAA")
    builder.set_fat(0, {FILE_A_CLUS: EOC, ROOT_CLUS: 3000})
    builder.set_fat(1, {FILE_A_CLUS: 0x0FFFFFF8})

    fat1_start = (RSVD_SECTORS + FAT_SIZE_SECTORS) * BYTES_PER_SEC
    readable_fat1_sectors = 16
    builder.truncate_at = fat1_start + readable_fat1_sectors * BYTES_PER_SEC
    builder.finalize()
    yield from _open(path)


def test_ext_flags_decode_contract() -> None:
    disabled = EXTFLAGS_MIRROR_DISABLED | (2 & EXTFLAGS_ACTIVE_FAT_MASK)
    assert disabled == 0x0082


def test_mirror_disabled_second_fat_active(sample_mirror_disabled_active_fat1: BinaryIO) -> None:
    report = diagnose(sample_mirror_disabled_active_fat1)

    assert report.fat_type == "FAT32"
    assert report.ext_flags.mirroring_disabled is True
    assert report.ext_flags.active_fat_index == 1
    assert report.on_disk_selection["selected_fat"] == 1
    assert report.on_disk_selection["definite"] is True
    assert report.extractor["selected_fat"] == 0

    diff_entries = {diff.entry: diff for diff in report.differing_entries}
    assert set(diff_entries) == {FILE_A_CLUS}
    copies = {item.fat_index: item for item in diff_entries[FILE_A_CLUS].copies}
    assert copies[0].raw == EOC
    assert copies[1].raw == 0x0FFFFFF8

    files = {item.path: item for item in report.files}
    assert files["FILE_A.TXT"].divergent is True
    chains = {chain.fat_index: chain for chain in files["FILE_A.TXT"].chains}
    assert chains[0].terminal == "eoc"
    assert chains[1].terminal == "eoc"
    assert chains[0].terminal_raw == EOC
    assert chains[1].terminal_raw == 0x0FFFFFF8
    assert report.walk_failure is None

    text = render_text(report)
    assert "冲突" in text
    assert "FAT#1" in text and "FAT#0" in text


def test_plausible_tail_divergence_undecidable(sample_plausible_tail_divergence: BinaryIO) -> None:
    report = diagnose(sample_plausible_tail_divergence)

    assert report.ext_flags.mirroring_disabled is False
    assert report.ext_flags.active_fat_index is None
    assert report.on_disk_selection["selected_fat"] is None
    assert report.on_disk_selection["definite"] is False
    assert report.extractor["selected_fat"] == 0

    diff_entries = {diff.entry for diff in report.differing_entries}
    assert diff_entries == {FILE_A_CLUS}

    files = {item.path: item for item in report.files}
    file_a = files["FILE_A.TXT"]
    assert file_a.divergent is True
    terminals = {chain.fat_index: chain.terminal for chain in file_a.chains}
    assert terminals == {0: "eoc", 1: "eoc"}
    raw_terminals = {chain.fat_index: chain.terminal_raw for chain in file_a.chains}
    assert raw_terminals == {0: EOC, 1: 0x0FFFFFF8}

    text = render_text(report)
    assert "无法在卷内确定" in text
    assert "实现选择" in text


def test_truncated_second_fat(sample_truncated_second_fat: BinaryIO) -> None:
    report = diagnose(sample_truncated_second_fat)

    readable_entries = 16 * BYTES_PER_SEC // 4
    assert report.copies[0].truncated is False
    assert report.copies[1].truncated is True
    assert report.copies[1].entry_count == readable_entries

    assert len(report.unreadable_ranges) == 1
    gap = report.unreadable_ranges[0]
    assert gap.fat_index == 1
    assert gap.first_entry == readable_entries
    assert gap.last_entry == FAT_ENTRIES - 1

    # The first FAT1 sectors survive, so early entries (root cluster and
    # cluster 4) can still be compared raw; the rest is reported as unreadable.
    diff_entries = {diff.entry for diff in report.differing_entries}
    assert diff_entries == {ROOT_CLUS, FILE_A_CLUS}

    assert report.walk_failure is not None
    text = render_text(report)
    assert "目录遍历未能完成" in text
    assert "不可读" in text
    assert "UNREADABLE" not in text


def test_report_is_serializable(sample_mirror_disabled_active_fat1: BinaryIO) -> None:
    import json

    report = diagnose(sample_mirror_disabled_active_fat1)
    payload = json.dumps(report.to_dict(), ensure_ascii=False)
    decoded = json.loads(payload)
    assert decoded["extractor"]["selected_fat"] == 0
    assert decoded["on_disk_selection"]["selected_fat"] == 1
