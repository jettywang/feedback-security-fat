"""Minimal synthetic exFAT image builder used by the directory fuzzer.

The builder intentionally uses raw :mod:`struct` packing instead of the
``dissect.cstruct`` parser types: the images produced here are *input* for the
forensic parser, so keeping generation independent avoids coupling the fuzz
harness to the very structures it is probing.

The layout is deliberately small (a single FAT and a handful of one-cluster
directories) so generated samples stay minimal while still exercising the
real entry-set and cluster-chain code paths.
"""

from __future__ import annotations

import struct

#: exFAT directory entries are always 32 bytes.
DIR_ENTRY_SIZE = 32
#: FAT entries are 32 bit little endian.
FAT_ENTRY_SIZE = 4
#: End of cluster chain marker.
EOC = 0xFFFFFFFF
#: First valid data cluster number.
FIRST_CLUSTER = 2

# Directory entry type bytes.
FILE_ENTRY = 0x85
STREAM_ENTRY = 0xC0
FILENAME_ENTRY = 0xC1
BITMAP_ENTRY = 0x81
UPCASE_ENTRY = 0x82
VOLUME_LABEL_ENTRY = 0x83

# ATTRIBUTES bit 4 (0x10) marks a directory in a FILE_DIRECTORY_ENTRY.
ATTR_DIRECTORY = 0x10
# FILE_FLAGS bits.
FLAG_NOT_FRAGMENTED = 0x02
FLAG_ALLOCATION_POSSIBLE = 0x01


class ExfatImageBuilder:
    """Builds a tiny, valid exFAT image containing a nested directory tree."""

    def __init__(self, depth: int = 3, sector_size: int = 512, sectors_per_cluster: int = 1):
        if depth < 1:
            raise ValueError("depth must be >= 1")
        self.sector_size = sector_size
        self.sectors_per_cluster = sectors_per_cluster
        self.cluster_size = sector_size * sectors_per_cluster
        self.fat_sector = 128
        self.fat_sector_count = 8
        self.cluster_heap_sector = self.fat_sector + self.fat_sector_count
        # depth subdirectories + root + upcase + bitmap = depth + 3 clusters.
        self.cluster_count = depth + 3
        self.root_dir_cluster = FIRST_CLUSTER + 1
        self.upcase_cluster = FIRST_CLUSTER
        self.bitmap_cluster = self.root_dir_cluster + 1 + depth
        self._depth = depth
        # remember(byte offset, length) -> human readable role, for patching.
        self.layout: dict[str, tuple[int, int]] = {}
        # Per directory entry-set: {"metadata": (off,len), "stream": ..., "filenames": [...]}
        self.entry_sets: dict[str, dict] = {}

    @property
    def total_sectors(self) -> int:
        return self.cluster_heap_sector + self.cluster_count * self.sectors_per_cluster

    def cluster_offset(self, cluster: int) -> int:
        """Byte offset of a data cluster inside the image."""
        sector = self.cluster_heap_sector + (cluster - FIRST_CLUSTER) * self.sectors_per_cluster
        return sector * self.sector_size

    # ------------------------------------------------------------------ packing
    @staticmethod
    def _file_entry(subentry_count: int, attributes: int) -> bytes:
        # FILE_DIRECTORY_ENTRY, checksum and timestamp fields are left zero,
        # the parser does not validate the checksum. Explicit offsets keep the
        # packed size at exactly 32 bytes.
        entry = bytearray(DIR_ENTRY_SIZE)
        entry[0x00] = FILE_ENTRY
        entry[0x01] = subentry_count & 0xFF
        struct.pack_into("<H", entry, 0x02, 0)  # checksum
        struct.pack_into("<H", entry, 0x04, attributes)
        # 0x06 zeros_1, 0x08..0x13 timestamps, 0x14..0x18 offsets/timezones,
        # 0x19 zeros_2 are all already zero from the bytearray initialisation.
        assert len(entry) == DIR_ENTRY_SIZE
        return bytes(entry)

    @staticmethod
    def _stream_entry(flags: int, filename_length: int, location: int, data_length: int) -> bytes:
        entry = bytearray(DIR_ENTRY_SIZE)
        entry[0x00] = STREAM_ENTRY
        entry[0x01] = flags & 0xFF
        entry[0x03] = filename_length & 0xFF
        struct.pack_into("<H", entry, 0x04, 0)  # filename hash
        struct.pack_into("<H", entry, 0x06, 0)  # protected
        struct.pack_into("<Q", entry, 0x08, data_length)  # valid data length
        struct.pack_into("<I", entry, 0x14, location)
        struct.pack_into("<Q", entry, 0x18, data_length)
        assert len(entry) == DIR_ENTRY_SIZE
        return bytes(entry)

    @staticmethod
    def _filename_entry(part: str) -> bytes:
        entry = bytearray(DIR_ENTRY_SIZE)
        entry[0x00] = FILENAME_ENTRY
        encoded = part.encode("utf-16-le")[: 15 * 2].ljust(15 * 2, b"\x00")
        entry[0x02:] = encoded
        assert len(entry) == DIR_ENTRY_SIZE
        return bytes(entry)

    def _file_set(
        self,
        name: str,
        location: int,
        data_length: int,
        is_directory: bool,
        not_fragmented: bool = True,
        extra_filename_parts: int = 0,
    ) -> tuple[list[bytes], int]:
        """Build a coordinated file entry-set (file + stream + N filenames)."""
        parts = [name[i : i + 15] for i in range(0, len(name), 15)] or [name]
        parts += [""] * extra_filename_parts
        parts = parts[:1] if len(parts) == 1 and not extra_filename_parts else parts
        flags = FLAG_ALLOCATION_POSSIBLE | (FLAG_NOT_FRAGMENTED if not_fragmented else 0)
        if not is_directory and data_length == 0:
            # Zero length files have no allocation possible per spec.
            flags = FLAG_NOT_FRAGMENTED if not_fragmented else 0
        attributes = ATTR_DIRECTORY if is_directory else 0
        subentry_count = 1 + len(parts)  # stream + filename entries
        entries = [
            self._file_entry(subentry_count, attributes),
            self._stream_entry(flags, len(name), location, data_length),
        ]
        entries.extend(self._filename_entry(part) for part in parts)
        return entries, subentry_count

    @staticmethod
    def _bitmap_entry(location: int, length: int) -> bytes:
        return struct.pack("<BB", BITMAP_ENTRY, 0) + b"\x00" * 18 + struct.pack("<IQ", location, length)

    @staticmethod
    def _upcase_entry(location: int, length: int) -> bytes:
        return (
            struct.pack("<BBB", UPCASE_ENTRY, 0, 0)
            + b"\x00"
            + struct.pack("<I", 0xDD319E6)
            + b"\x00" * 12
            + struct.pack("<IQ", location, length)
        )

    @staticmethod
    def _volume_label_entry(label: str) -> bytes:
        encoded = label.encode("utf-16-le")[: 11 * 2].ljust(11 * 2, b"\x00")
        return struct.pack("<BB", VOLUME_LABEL_ENTRY, len(label)) + encoded + b"\x00" * 8

    def _vbr(self) -> bytes:
        header = bytearray(512)
        header[0:3] = b"\xeb\x76\x90"
        header[3:11] = b"EXFAT   "
        struct.pack_into("<Q", header, 0x40, 0)  # volume offset
        struct.pack_into("<Q", header, 0x48, self.total_sectors)
        struct.pack_into("<I", header, 0x50, self.fat_sector)
        struct.pack_into("<I", header, 0x54, self.fat_sector_count)
        struct.pack_into("<I", header, 0x58, self.cluster_heap_sector)
        struct.pack_into("<I", header, 0x5C, self.cluster_count)
        struct.pack_into("<I", header, 0x60, self.root_dir_cluster)
        struct.pack_into("<I", header, 0x64, 0x12345678)
        header[0x68] = 0  # version minor
        header[0x69] = 1  # version major
        struct.pack_into("<H", header, 0x6A, 0)
        header[0x6C] = self.sector_size.bit_length() - 1
        header[0x6D] = self.sectors_per_cluster.bit_length() - 1
        header[0x6E] = 1  # number of FATs
        header[0x6F] = 0x80
        header[0x70] = 0
        struct.pack_into("<H", header, 0x1FE, 0xAA55)
        return bytes(header)

    # ------------------------------------------------------------------ build
    def build(self) -> bytes:
        image = bytearray(self.total_sectors * self.sector_size)
        image[0:512] = self._vbr()

        # FAT region (one FAT). Every allocated chain currently ends at EOC.
        fat_base = self.fat_sector * self.sector_size
        self.layout["fat"] = (fat_base, self.fat_sector_count * self.sector_size)
        for cluster in range(FIRST_CLUSTER, FIRST_CLUSTER + self.cluster_count):
            struct.pack_into("<I", image, fat_base + cluster * FAT_ENTRY_SIZE, EOC)

        # Upcase and allocation bitmap clusters can stay zero filled.
        self.layout["upcase_cluster"] = (self.cluster_offset(self.upcase_cluster), self.cluster_size)
        self.layout["bitmap_cluster"] = (self.cluster_offset(self.bitmap_cluster), self.cluster_size)

        # One cluster per directory: root and depth subdirectories.
        dir_clusters = [self.root_dir_cluster + i for i in range(self._depth + 1)]
        self._write_root_directory(image, dir_clusters)
        for level in range(1, self._depth + 1):
            self._write_subdirectory(image, dir_clusters, level)

        return bytes(image)

    def _record_set(self, base_offset: int, index: int, role: str, set_len: int) -> None:
        start = base_offset + index * DIR_ENTRY_SIZE
        self.entry_sets[role] = {
            "metadata": (start, DIR_ENTRY_SIZE),
            "stream": (start + DIR_ENTRY_SIZE, DIR_ENTRY_SIZE),
            "filenames": [(start + (2 + i) * DIR_ENTRY_SIZE, DIR_ENTRY_SIZE) for i in range(max(1, set_len - 1))],
        }

    def _write_root_directory(self, image: bytearray, dir_clusters: list[int]) -> None:
        offset = self.cluster_offset(self.root_dir_cluster)
        self.layout["root_dir_cluster"] = (offset, self.cluster_size)
        entries = [
            self._volume_label_entry("FUZZ"),
            self._bitmap_entry(self.bitmap_cluster, self.cluster_count // 8 + 1),
            self._upcase_entry(self.upcase_cluster, 0),
        ]
        # The single nested directory reachable from root ("d1").
        nested, nested_count = self._file_set("d1", dir_clusters[1], self.cluster_size, is_directory=True)
        entries.extend(nested)
        self._record_set(offset, 3, "root:d1", len(nested))
        self._flatten(image, offset, entries)

    def _write_subdirectory(self, image: bytearray, dir_clusters: list[int], level: int) -> None:
        cluster = dir_clusters[level]
        offset = self.cluster_offset(cluster)
        self.layout[f"dir{level}_cluster"] = (offset, self.cluster_size)
        if level < self._depth:
            name = f"d{level + 1}"
            entries, count = self._file_set(name, dir_clusters[level + 1], self.cluster_size, is_directory=True)
            role = f"dir{level}:{name}"
        else:
            # Deepest directory holds a plain file, so the tree walk terminates.
            name = "leaf.txt"
            entries, count = self._file_set(name, 0, 5, is_directory=False)
            role = f"dir{level}:{name}"
        self._record_set(offset, 0, role, count)
        self._flatten(image, offset, entries)

    def _flatten(self, image: bytearray, offset: int, entries: list[bytes]) -> None:
        if len(entries) * DIR_ENTRY_SIZE > self.cluster_size:
            raise ValueError("entry-set does not fit in one cluster")
        for index, entry in enumerate(entries):
            image[offset + index * DIR_ENTRY_SIZE : offset + (index + 1) * DIR_ENTRY_SIZE] = entry
