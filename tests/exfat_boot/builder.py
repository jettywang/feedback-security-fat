"""Independent exFAT boot-region sample builder.

This module constructs exFAT images directly from the exFAT boot region
specification (main boot region sectors 0-11, backup boot region sectors
12-23). It deliberately does NOT import or call any production parser code
from ``dissect.fat`` so that expectations derived here stay independent of
the reader under test.

On-disk layout (sector indexes, identical for 512 and 4096 byte sectors):

    0-10   main boot region (boot sector, 8 extended boot sectors,
           OEM parameters, reserved)
    11     main checksum sector
    12-23  backup boot region (same layout)
    24..   FAT at ``fat_sector``, cluster heap at ``heap_sector``

Cluster heap occupants (both sector sizes):

    cluster 2  allocation bitmap
    cluster 3  upcase table
    cluster 4  root directory (volume label, bitmap, upcase, HELLO.TXT)
    cluster 5  HELLO.TXT file content
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

EOC = 0xFFFFFFFF
MEDIA_DESCRIPTOR = 0xFFFFFFF8
BOOT_SIGNATURE = 0xAA55
EXTENDED_BOOT_SIGNATURE = 0xAA550000

VOLUME_LABEL = "EVIDENCE"
FILE_NAME = "HELLO.TXT"
VOLUME_SERIAL = 0x1A2B3C4D
# 2026-01-01 00:00:00 in exFAT timestamp format (year 46, month 1, day 1).
FIXED_TIMESTAMP = (46 << 25) | (1 << 21) | (1 << 16)

BITMAP_CLUSTER = 2
UPCASE_CLUSTER = 3
ROOT_CLUSTER = 4
FILE_CLUSTER = 5

# Boot sector offsets of the fields that are excluded from the boot checksum.
CHECKSUM_EXCLUDED_OFFSETS = (0x6A, 0x6B, 0x70)  # VolumeFlags, PercentInUse


@dataclass(frozen=True)
class Layout:
    sector_size: int
    fat_sector: int
    fat_sector_count: int
    heap_sector: int
    heap_count: int

    @property
    def volume_sectors(self) -> int:
        return self.heap_sector + self.heap_count

    @property
    def bytes_per_sector_exp(self) -> int:
        return self.sector_size.bit_length() - 1


LAYOUTS = {
    512: Layout(sector_size=512, fat_sector=128, fat_sector_count=8, heap_sector=136, heap_count=64),
    4096: Layout(sector_size=4096, fat_sector=24, fat_sector_count=1, heap_sector=25, heap_count=32),
}

CASES = (
    "valid",
    "rootdir_relocated_csum_ok",
    "heap_shifted_csum_bad",
    "flags_independent",
    "checksum_sector_bit",
    "backup_geom_diverge",
)


def file_content(sector_size: int) -> bytes:
    return f"EVIDENCE-{sector_size}: exFAT boot region validation sample.\n".encode()


def _ror1(value: int, bits: int) -> int:
    return ((value >> 1) | ((value & 1) << (bits - 1))) & ((1 << bits) - 1)


def boot_checksum(eleven_sectors: bytes) -> int:
    """Boot checksum over the first 11 sectors of a boot region.

    VolumeFlags (0x6A-0x6B) and PercentInUse (0x70) of the boot sector are
    excluded per spec, so they may vary independently of the checksum.
    """
    checksum = 0
    for index, byte in enumerate(eleven_sectors):
        if index in CHECKSUM_EXCLUDED_OFFSETS:
            continue
        checksum = (_ror1(checksum, 32) + byte) & 0xFFFFFFFF
    return checksum


def entry_set_checksum(entry_set: bytes) -> int:
    """16-bit checksum over a file directory entry set (checksum field skipped)."""
    checksum = 0
    for index, byte in enumerate(entry_set):
        if index in (2, 3):
            continue
        checksum = (_ror1(checksum, 16) + byte) & 0xFFFF
    return checksum


def name_hash(upcased_utf16le: bytes) -> int:
    checksum = 0
    for byte in upcased_utf16le:
        checksum = (_ror1(checksum, 16) + byte) & 0xFFFF
    return checksum


def upcase_checksum(table: bytes) -> int:
    checksum = 0
    for byte in table:
        checksum = (_ror1(checksum, 32) + byte) & 0xFFFFFFFF
    return checksum


def build_upcase_table() -> bytes:
    """Compressed upcase table: identity except a-z -> A-Z."""
    entries = [0xFFFF, 0x0061]  # 0x0000-0x0060 identity
    entries += list(range(0x0041, 0x005B))  # 0x0061-0x007A map to A-Z
    entries += [0xFFFF, 0x10000 - 0x7B]  # 0x007B-0xFFFF identity
    return struct.pack(f"<{len(entries)}H", *entries)


def build_boot_sector(
    layout: Layout,
    *,
    root_dir_cluster: int = ROOT_CLUSTER,
    heap_sector: int | None = None,
    volume_flags: int = 0x0000,
    percent_in_use: int = 0,
) -> bytes:
    sector = bytearray(layout.sector_size)
    sector[0:3] = b"\xeb\x76\x90"
    sector[3:11] = b"EXFAT   "
    # 0x0B-0x3F MustBeZero stays zero.
    struct.pack_into("<Q", sector, 0x40, 0)  # volume offset
    struct.pack_into("<Q", sector, 0x48, layout.volume_sectors)
    struct.pack_into("<L", sector, 0x50, layout.fat_sector)
    struct.pack_into("<L", sector, 0x54, layout.fat_sector_count)
    struct.pack_into("<L", sector, 0x58, layout.heap_sector if heap_sector is None else heap_sector)
    struct.pack_into("<L", sector, 0x5C, layout.heap_count)
    struct.pack_into("<L", sector, 0x60, root_dir_cluster)
    struct.pack_into("<L", sector, 0x64, VOLUME_SERIAL)
    sector[0x68] = 0  # fs version minor
    sector[0x69] = 1  # fs version major
    struct.pack_into("<H", sector, 0x6A, volume_flags)
    sector[0x6C] = layout.bytes_per_sector_exp
    sector[0x6D] = 0  # sectors per cluster exp
    sector[0x6E] = 1  # number of FATs
    sector[0x6F] = 0x80  # drive select
    sector[0x70] = percent_in_use
    struct.pack_into("<H", sector, 0x1FE, BOOT_SIGNATURE)
    return bytes(sector)


def build_boot_region(layout: Layout, **boot_sector_kwargs: int) -> bytes:
    """12 sectors: boot sector, 8 extended boot sectors, OEM, reserved, checksum."""
    region = bytearray(12 * layout.sector_size)
    region[0 : layout.sector_size] = build_boot_sector(layout, **boot_sector_kwargs)
    for index in range(1, 9):
        struct.pack_into(
            "<L",
            region,
            index * layout.sector_size + layout.sector_size - 4,
            EXTENDED_BOOT_SIGNATURE,
        )
    # Sector 9 (OEM parameters) and sector 10 (reserved) stay zero.
    checksum = boot_checksum(bytes(region[: 11 * layout.sector_size]))
    region[11 * layout.sector_size :] = struct.pack("<L", checksum) * (layout.sector_size // 4)
    return bytes(region)


def _build_file_entry_set(name: str, cluster: int, size: int) -> bytes:
    metadata = bytearray(32)
    metadata[0] = 0x85
    metadata[1] = 2  # stream + filename subentries
    struct.pack_into("<H", metadata, 4, 0x20)  # archive attribute
    struct.pack_into("<L", metadata, 8, FIXED_TIMESTAMP)
    struct.pack_into("<L", metadata, 12, FIXED_TIMESTAMP)
    struct.pack_into("<L", metadata, 16, FIXED_TIMESTAMP)

    stream = bytearray(32)
    stream[0] = 0xC0
    stream[1] = 0x03  # allocation possible + not fragmented
    stream[3] = len(name)
    struct.pack_into("<H", stream, 4, name_hash(name.upper().encode("utf-16-le")))
    struct.pack_into("<Q", stream, 8, size)  # valid data length
    struct.pack_into("<L", stream, 20, cluster)
    struct.pack_into("<Q", stream, 24, size)  # data length

    filename = bytearray(32)
    filename[0] = 0xC1
    filename[2 : 2 + 2 * len(name)] = name.encode("utf-16-le")

    entry_set = bytes(metadata + stream + filename)
    struct.pack_into("<H", metadata, 2, entry_set_checksum(entry_set))
    return bytes(metadata + stream + filename)


def _build_root_dir(layout: Layout, upcase: bytes, content_size: int) -> bytes:
    entries = bytearray()

    label = bytearray(32)
    label[0] = 0x83
    label[1] = len(VOLUME_LABEL)
    label[2 : 2 + 2 * len(VOLUME_LABEL)] = VOLUME_LABEL.encode("utf-16-le")
    entries += label

    bitmap = bytearray(32)
    bitmap[0] = 0x81
    struct.pack_into("<L", bitmap, 20, BITMAP_CLUSTER)
    struct.pack_into("<Q", bitmap, 24, -(-layout.heap_count // 8))
    entries += bitmap

    upcase_entry = bytearray(32)
    upcase_entry[0] = 0x82
    struct.pack_into("<L", upcase_entry, 4, upcase_checksum(upcase))
    struct.pack_into("<L", upcase_entry, 20, UPCASE_CLUSTER)
    struct.pack_into("<Q", upcase_entry, 24, len(upcase))
    entries += upcase_entry

    entries += _build_file_entry_set(FILE_NAME, FILE_CLUSTER, content_size)
    return bytes(entries)


def build_valid_image(sector_size: int) -> bytes:
    layout = LAYOUTS[sector_size]
    content = file_content(sector_size)
    upcase = build_upcase_table()

    image = bytearray(layout.volume_sectors * layout.sector_size)
    image[0 : 12 * layout.sector_size] = build_boot_region(layout)
    image[12 * layout.sector_size : 24 * layout.sector_size] = build_boot_region(layout)

    fat = bytearray(layout.fat_sector_count * layout.sector_size)
    entries = [MEDIA_DESCRIPTOR, EOC, EOC, EOC, EOC, EOC]
    struct.pack_into(f"<{len(entries)}L", fat, 0, *entries)
    fat_start = layout.fat_sector * layout.sector_size
    image[fat_start : fat_start + len(fat)] = fat

    def cluster_offset(cluster: int) -> int:
        return (layout.heap_sector + (cluster - 2)) * layout.sector_size

    bitmap = bytearray(-(-layout.heap_count // 8))
    bitmap[0] = 0b00111100  # clusters 2-5 allocated
    image[cluster_offset(BITMAP_CLUSTER) : cluster_offset(BITMAP_CLUSTER) + len(bitmap)] = bitmap
    image[cluster_offset(UPCASE_CLUSTER) : cluster_offset(UPCASE_CLUSTER) + len(upcase)] = upcase
    root_dir = _build_root_dir(layout, upcase, len(content))
    image[cluster_offset(ROOT_CLUSTER) : cluster_offset(ROOT_CLUSTER) + len(root_dir)] = root_dir
    image[cluster_offset(FILE_CLUSTER) : cluster_offset(FILE_CLUSTER) + len(content)] = content
    return bytes(image)


def _region_base(sector_size: int, region: str) -> int:
    return 0 if region == "main" else 12 * sector_size


def patch_u32(image: bytearray, sector_size: int, region: str, offset: int, value: int) -> None:
    struct.pack_into("<L", image, _region_base(sector_size, region) + offset, value)


def patch_u16(image: bytearray, sector_size: int, region: str, offset: int, value: int) -> None:
    struct.pack_into("<H", image, _region_base(sector_size, region) + offset, value)


def refresh_checksum(image: bytearray, sector_size: int, region: str) -> None:
    base = _region_base(sector_size, region)
    checksum = boot_checksum(bytes(image[base : base + 11 * sector_size]))
    image[base + 11 * sector_size : base + 12 * sector_size] = struct.pack("<L", checksum) * (sector_size // 4)


def build_case(case: str, sector_size: int) -> bytes:
    """Build one validation sample. Mutations are byte patches on a valid image."""
    if case not in CASES:
        raise ValueError(f"unknown case: {case}")
    image = bytearray(build_valid_image(sector_size))

    if case == "rootdir_relocated_csum_ok":
        # Geometry field covered by the checksum, changed in BOTH regions,
        # checksums honestly recomputed: checksum-valid but wrong geometry.
        for region in ("main", "backup"):
            patch_u32(image, sector_size, region, 0x60, FILE_CLUSTER)
            refresh_checksum(image, sector_size, region)
    elif case == "heap_shifted_csum_bad":
        # Same class of geometry change in the MAIN region only, checksum
        # deliberately NOT recomputed: checksum-invalid, backup stays intact.
        patch_u32(image, sector_size, "main", 0x58, LAYOUTS[sector_size].heap_sector + 1)
    elif case == "flags_independent":
        # VolumeFlags/PercentInUse are excluded from the boot checksum and may
        # differ between regions. Main stays clean, backup claims dirty.
        patch_u16(image, sector_size, "main", 0x6A, 0x0000)
        image[0x70] = 75
        patch_u16(image, sector_size, "backup", 0x6A, 0x0002)  # volume dirty
        image[12 * sector_size + 0x70] = 50
    elif case == "checksum_sector_bit":
        # Corrupt exactly one repeated checksum value in the main checksum sector.
        image[11 * sector_size] ^= 0x01
    elif case == "backup_geom_diverge":
        # Backup geometry diverges from main, backup checksum recomputed so the
        # backup region alone verifies fine.
        patch_u32(image, sector_size, "backup", 0x60, 6)
        refresh_checksum(image, sector_size, "backup")
    return bytes(image)
