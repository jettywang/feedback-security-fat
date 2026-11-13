"""Independent exFAT boot region verifier.

Implements boot region validation directly from the exFAT specification
using only the standard library. Nothing here imports ``dissect.fat``:
verdicts produced here are the independent ground truth that the production
reader is measured against.

Three deliberately separated layers:

1. checksum validity   -- boot checksum of each region, uniformity of the
                          repeated values in the checksum sector
2. structural sanity   -- signature fields and geometry bounds of each
                          region, plus main/backup agreement
3. content locatable   -- an independent directory walk from raw boot
                          region bytes down to one actual file read
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

EOC = 0xFFFFFFFF
CHECKSUM_EXCLUDED_OFFSETS = (0x6A, 0x6B, 0x70)
MAX_CHAIN = 1 << 16


def _ror1(value: int, bits: int) -> int:
    return ((value >> 1) | ((value & 1) << (bits - 1))) & ((1 << bits) - 1)


def boot_checksum(eleven_sectors: bytes) -> int:
    checksum = 0
    for index, byte in enumerate(eleven_sectors):
        if index in CHECKSUM_EXCLUDED_OFFSETS:
            continue
        checksum = (_ror1(checksum, 32) + byte) & 0xFFFFFFFF
    return checksum


def entry_set_checksum(entry_set: bytes) -> int:
    checksum = 0
    for index, byte in enumerate(entry_set):
        if index in (2, 3):
            continue
        checksum = (_ror1(checksum, 16) + byte) & 0xFFFF
    return checksum


def upcase_checksum(table: bytes) -> int:
    checksum = 0
    for byte in table:
        checksum = (_ror1(checksum, 32) + byte) & 0xFFFFFFFF
    return checksum


@dataclass
class BootSector:
    volume_offset: int
    volume_sector_count: int
    fat_sector: int
    fat_sector_count: int
    heap_sector: int
    heap_count: int
    root_dir_cluster: int
    volume_flags: int
    percent_in_use: int
    bytes_per_sector_exp: int
    sectors_per_cluster_exp: int
    number_of_fats: int

    @classmethod
    def parse(cls, sector: bytes) -> BootSector:
        return cls(
            volume_offset=struct.unpack_from("<Q", sector, 0x40)[0],
            volume_sector_count=struct.unpack_from("<Q", sector, 0x48)[0],
            fat_sector=struct.unpack_from("<L", sector, 0x50)[0],
            fat_sector_count=struct.unpack_from("<L", sector, 0x54)[0],
            heap_sector=struct.unpack_from("<L", sector, 0x58)[0],
            heap_count=struct.unpack_from("<L", sector, 0x5C)[0],
            root_dir_cluster=struct.unpack_from("<L", sector, 0x60)[0],
            volume_flags=struct.unpack_from("<H", sector, 0x6A)[0],
            percent_in_use=sector[0x70],
            bytes_per_sector_exp=sector[0x6C],
            sectors_per_cluster_exp=sector[0x6D],
            number_of_fats=sector[0x6E],
        )


@dataclass
class RegionReport:
    checksum_valid: bool
    checksums_uniform: bool
    computed_checksum: int
    stored_checksum: int
    structural_checks: dict[str, bool]
    boot: BootSector

    @property
    def structural_ok(self) -> bool:
        return all(self.structural_checks.values())


@dataclass
class ContentReport:
    locatable: bool
    volume_label: str | None = None
    upcase_checksum_valid: bool | None = None
    entry_set_checksum_valid: bool | None = None
    found_files: list[str] = field(default_factory=list)
    content: bytes | None = None
    sha256: str | None = None
    notes: list[str] = field(default_factory=list)


@dataclass
class ImageReport:
    sector_size: int
    main: RegionReport
    backup: RegionReport
    regions_agree: bool
    current_volume_flags: int
    current_percent_in_use: int
    content_via_main: ContentReport
    content_via_backup: ContentReport


def _structural_checks(sector: bytes, boot: BootSector, image_sectors: int) -> dict[str, bool]:
    sector_size = 1 << boot.bytes_per_sector_exp if boot.bytes_per_sector_exp <= 12 else 0
    sectors_per_cluster = 1 << boot.sectors_per_cluster_exp if boot.sectors_per_cluster_exp <= 25 else 0
    heap_sectors = boot.heap_count * sectors_per_cluster
    extended_ok = (
        all(struct.unpack_from("<L", sector, (index + 1) * sector_size - 4)[0] == 0xAA550000 for index in range(1, 9))
        if sector_size
        else False
    )
    return {
        "fs_name": sector[3:11] == b"EXFAT   ",
        "must_be_zero": sector[11:64] == bytes(53),
        "boot_signature": struct.unpack_from("<H", sector, 0x1FE)[0] == 0xAA55,
        "extended_boot_signatures": extended_ok,
        "sector_shift_range": 9 <= boot.bytes_per_sector_exp <= 12,
        "cluster_shift_range": boot.bytes_per_sector_exp + boot.sectors_per_cluster_exp <= 25,
        "single_fat": boot.number_of_fats == 1,
        "fs_version_1_0": sector[0x68] == 0 and sector[0x69] == 1,
        "fat_after_boot_regions": boot.fat_sector >= 24,
        "fat_before_heap": boot.fat_sector + boot.fat_sector_count <= boot.heap_sector,
        "heap_within_volume": boot.heap_sector + heap_sectors <= boot.volume_sector_count,
        "root_cluster_in_heap": 2 <= boot.root_dir_cluster < 2 + boot.heap_count,
        "percent_in_use_range": boot.percent_in_use <= 100 or boot.percent_in_use == 0xFF,
        "image_size_matches_volume": image_sectors == boot.volume_sector_count,
    }


def verify_region(data: bytes, region_base: int, sector_size: int, image_sectors: int) -> RegionReport:
    region = data[region_base : region_base + 12 * sector_size]
    boot_sector = region[:sector_size]
    boot = BootSector.parse(boot_sector)

    computed = boot_checksum(region[: 11 * sector_size])
    checksum_sector = region[11 * sector_size : 12 * sector_size]
    stored_values = struct.unpack(f"<{sector_size // 4}L", checksum_sector)
    uniform = all(value == stored_values[0] for value in stored_values)

    return RegionReport(
        checksum_valid=uniform and stored_values[0] == computed,
        checksums_uniform=uniform,
        computed_checksum=computed,
        stored_checksum=stored_values[0],
        structural_checks=_structural_checks(region, boot, image_sectors),
        boot=boot,
    )


def _regions_agree(data: bytes, sector_size: int) -> bool:
    """Compare the checksummed bytes (sectors 0-10) of both regions.

    VolumeFlags and PercentInUse are excluded, exactly like the boot
    checksum excludes them: those bytes may legitimately differ.
    """
    main = bytearray(data[: 11 * sector_size])
    backup = bytearray(data[12 * sector_size : 23 * sector_size])
    for offset in CHECKSUM_EXCLUDED_OFFSETS:
        main[offset] = backup[offset] = 0
    return bytes(main) == bytes(backup)


def _cluster_chain(data: bytes, fat_offset: int, start: int) -> list[int]:
    chain = []
    cluster = start
    while cluster != EOC and len(chain) < MAX_CHAIN:
        if cluster < 2:
            break
        chain.append(cluster)
        entry_offset = fat_offset + cluster * 4
        if entry_offset + 4 > len(data):
            break
        cluster = struct.unpack_from("<L", data, entry_offset)[0]
    return chain


def locate_file(data: bytes, sector_size: int, region_base: int, name: str) -> ContentReport:
    """Walk from raw boot region bytes to one actual file read."""
    boot = BootSector.parse(data[region_base : region_base + sector_size])
    report = ContentReport(locatable=False)
    cluster_size = sector_size << boot.sectors_per_cluster_exp
    heap_offset = boot.heap_sector * sector_size
    fat_offset = boot.fat_sector * sector_size

    def cluster_bytes(cluster: int) -> bytes:
        start = heap_offset + (cluster - 2) * cluster_size
        return data[start : start + cluster_size]

    chain = _cluster_chain(data, fat_offset, boot.root_dir_cluster)
    if not chain:
        report.notes.append("root directory cluster chain is empty")
        return report
    root = b"".join(cluster_bytes(cluster) for cluster in chain)

    upcase_entry = None
    offset = 0
    while offset + 32 <= len(root):
        entry = root[offset : offset + 32]
        entry_type = entry[0]
        if entry_type == 0x00:
            break
        if entry_type == 0x83:
            label_length = entry[1]
            report.volume_label = entry[2 : 2 + 2 * label_length].decode("utf-16-le")
        elif entry_type == 0x82:
            upcase_entry = entry
        elif entry_type == 0x85:
            subentries = entry[1]
            entry_set = root[offset : offset + 32 * (1 + subentries)]
            if len(entry_set) < 32 * (1 + subentries):
                report.notes.append("truncated file entry set")
                return report
            stored = struct.unpack_from("<H", entry_set, 2)[0]
            set_valid = entry_set_checksum(entry_set) == stored
            stream = entry_set[32:64]
            filename = b"".join(entry_set[32 * index + 2 : 32 * index + 32] for index in range(2, 1 + subentries))[
                : 2 * stream[3]
            ].decode("utf-16-le", errors="replace")
            report.found_files.append(filename)
            if filename == name:
                report.entry_set_checksum_valid = set_valid
                location = struct.unpack_from("<L", stream, 20)[0]
                length = struct.unpack_from("<Q", stream, 24)[0]
                not_fragmented = bool(stream[1] & 0x02)
                if not_fragmented:
                    raw = cluster_bytes(location)[:length]
                else:
                    file_chain = _cluster_chain(data, fat_offset, location)
                    raw = b"".join(cluster_bytes(cluster) for cluster in file_chain)[:length]
                report.content = raw
                report.sha256 = hashlib.sha256(raw).hexdigest()
                report.locatable = True
            offset += 32 * (1 + subentries)
            continue
        offset += 32

    if upcase_entry is not None:
        table_cluster = struct.unpack_from("<L", upcase_entry, 20)[0]
        table_length = struct.unpack_from("<Q", upcase_entry, 24)[0]
        table = cluster_bytes(table_cluster)[:table_length]
        report.upcase_checksum_valid = upcase_checksum(table) == struct.unpack_from("<L", upcase_entry, 4)[0]
    return report


def verify_image(data: bytes, sector_size: int | None = None) -> ImageReport:
    if sector_size is None:
        sector_size = 1 << data[0x6C]
    image_sectors = len(data) // sector_size
    main = verify_region(data, 0, sector_size, image_sectors)
    backup = verify_region(data, 12 * sector_size, sector_size, image_sectors)
    return ImageReport(
        sector_size=sector_size,
        main=main,
        backup=backup,
        regions_agree=_regions_agree(data, sector_size),
        # Current state comes from the MAIN region only. The backup region's
        # VolumeFlags/PercentInUse are a snapshot, not the current state.
        current_volume_flags=main.boot.volume_flags,
        current_percent_in_use=main.boot.percent_in_use,
        content_via_main=locate_file(data, sector_size, 0, "HELLO.TXT"),
        content_via_backup=locate_file(data, sector_size, 12 * sector_size, "HELLO.TXT"),
    )


def trace_file_read(data: bytes, expected_content: bytes | None = None) -> str:
    """Human-readable evidence chain: raw boot bytes -> actual file read."""
    sector_size = 1 << data[0x6C]
    boot = BootSector.parse(data[:sector_size])
    lines = [f"sector_size = {sector_size} (bytes_per_sector_exp = {boot.bytes_per_sector_exp})"]

    def raw(offset: int, length: int) -> str:
        return data[offset : offset + length].hex(" ")

    lines.append("[1] main boot sector geometry (raw little-endian bytes):")
    lines.append(f"    0x50 fat_sector          = {raw(0x50, 4)} -> {boot.fat_sector}")
    lines.append(f"    0x54 fat_sector_count    = {raw(0x54, 4)} -> {boot.fat_sector_count}")
    lines.append(f"    0x58 cluster_heap_sector = {raw(0x58, 4)} -> {boot.heap_sector}")
    lines.append(f"    0x5C cluster_heap_count  = {raw(0x5C, 4)} -> {boot.heap_count}")
    lines.append(f"    0x60 root_dir_cluster    = {raw(0x60, 4)} -> {boot.root_dir_cluster}")

    computed = boot_checksum(data[: 11 * sector_size])
    stored = struct.unpack_from("<L", data, 11 * sector_size)[0]
    lines.append(f"[2] boot checksum: computed 0x{computed:08x}, stored 0x{stored:08x} (sector 11)")

    fat_offset = boot.fat_sector * sector_size
    root_next = struct.unpack_from("<L", data, fat_offset + boot.root_dir_cluster * 4)[0]
    lines.append(
        f"[3] FAT[{boot.root_dir_cluster}] @ byte 0x{fat_offset + boot.root_dir_cluster * 4:x}"
        f" = 0x{root_next:08x} (EOC) -> root dir chain = [{boot.root_dir_cluster}]"
    )

    spc = 1 << boot.sectors_per_cluster_exp
    root_sector = boot.heap_sector + (boot.root_dir_cluster - 2) * spc
    lines.append(
        f"[4] root dir sector = {boot.heap_sector} + ({boot.root_dir_cluster}-2)*{spc}"
        f" = {root_sector} (byte 0x{root_sector * sector_size:x})"
    )

    report = locate_file(data, sector_size, 0, "HELLO.TXT")
    lines.append(
        f"[5] root dir entries: volume label {report.volume_label!r},"
        f" upcase checksum valid = {report.upcase_checksum_valid}, files = {report.found_files}"
    )
    lines.append(f"[6] HELLO.TXT entry-set checksum valid = {report.entry_set_checksum_valid}")
    if report.content is not None:
        file_sector = boot.heap_sector + (5 - 2) * spc
        lines.append(
            f"[7] file content @ sector {file_sector} (byte 0x{file_sector * sector_size:x}),"
            f" {len(report.content)} bytes, sha256 = {report.sha256}"
        )
        lines.append(f"    content = {report.content!r}")
        if expected_content is not None:
            verdict = "MATCH" if report.content == expected_content else "MISMATCH"
            lines.append(f"    expected sha256 = {hashlib.sha256(expected_content).hexdigest()} -> {verdict}")
    else:
        lines.append("[7] file content NOT locatable")
    return "\n".join(lines)
