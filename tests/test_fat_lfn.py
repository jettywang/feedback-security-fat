from __future__ import annotations

import io
import struct
from typing import BinaryIO

from dissect.fat import fat

SHORT_A = b"FILEA   TXT"
SHORT_B = b"FILEB   TXT"
DATA_A = b"content of file a"
DATA_B = b"content of file b, which is longer"


def checksum(short_name: bytes) -> int:
    value = 0
    for c in short_name:
        value = (((value & 1) << 7) | (value >> 1)) & 0xFF
        value = (value + c) & 0xFF
    return value


def short_entry(name: bytes, attr: int = 0x20, cluster: int = 0, size: int = 0, deleted: bool = False) -> bytes:
    entry = bytearray(32)
    entry[0:11] = name
    entry[11] = attr
    struct.pack_into("<H", entry, 26, cluster)
    struct.pack_into("<I", entry, 28, size)
    if deleted:
        entry[0] = 0xE5
    return bytes(entry)


def lfn_entries(name: str, short_name: bytes) -> bytes:
    checksum_byte = checksum(short_name)
    encoded = name.encode("utf-16-le") + b"\x00\x00"
    encoded += b"\xff" * (-len(encoded) % 26)
    count = len(encoded) // 26

    result = b""
    for i in range(count, 0, -1):
        chunk = encoded[(i - 1) * 26 : i * 26]
        entry = bytearray(32)
        entry[0] = i | (0x40 if i == count else 0)
        entry[1:11] = chunk[0:10]
        entry[11] = 0x0F
        entry[13] = checksum_byte
        entry[14:26] = chunk[10:22]
        entry[28:32] = chunk[22:26]
        result += bytes(entry)
    return result


class MockFAT:
    def runlist(self, cluster: int) -> list[tuple[int, int]]:
        return [(cluster - 2, 1)]


class MockFS:
    encoding = "ibm437"
    cluster_size = 512
    fat = MockFAT()

    def __init__(self, data: bytes) -> None:
        self.data_stream = io.BytesIO(data)


def make_data() -> bytes:
    data = bytearray(512 * 4)
    data[0 : len(DATA_A)] = DATA_A  # cluster 2
    data[512 : 512 + len(DATA_B)] = DATA_B  # cluster 3
    return bytes(data)


def parse_dir(entries: bytes, data: bytes = b"") -> list[fat.DirectoryEntry]:
    return list(fat._iter_dirent(MockFS(data), io.BytesIO(entries)))


def test_lfn_name_cluster_content_correspondence() -> None:
    entries = b"".join(
        [
            lfn_entries("file a long name.txt", SHORT_A),
            short_entry(SHORT_A, cluster=2, size=len(DATA_A)),
            lfn_entries("file b long name.txt", SHORT_B),
            short_entry(SHORT_B, cluster=3, size=len(DATA_B)),
            b"\x00" * 32,
        ]
    )
    result = parse_dir(entries, make_data())

    assert [e.name for e in result] == ["file a long name.txt", "file b long name.txt"]

    entry_a, entry_b = result
    assert entry_a.short_name == "FILEA.TXT"
    assert entry_a.lfn_invalid is None
    assert entry_a.cluster == 2
    assert entry_a.open().read() == DATA_A

    assert entry_b.short_name == "FILEB.TXT"
    assert entry_b.lfn_invalid is None
    assert entry_b.cluster == 3
    assert entry_b.open().read() == DATA_B


def test_orphaned_lfn_checksum_mismatch() -> None:
    residual = lfn_entries("deleted file long name.txt", b"DELETED TXT")
    entries = residual + short_entry(SHORT_B, cluster=3, size=len(DATA_B)) + b"\x00" * 32
    result = parse_dir(entries, make_data())

    assert len(result) == 1
    entry = result[0]
    assert entry.name == "FILEB.TXT"
    assert entry.short_name == "FILEB.TXT"
    assert entry.lfn_invalid == "long name checksum does not match the short name"
    assert entry.cluster == 3
    assert entry.open().read() == DATA_B

    # the raw long name entries are preserved for review
    assert len(entry.ldirents) == len(residual) // 32
    assert b"".join(bytes(e) for e in entry.ldirents) == residual


def test_lfn_missing_sequence_number() -> None:
    long_name = lfn_entries("missing sequence number.txt", SHORT_A)
    broken = long_name[:32] + long_name[64:]  # drop the middle entry
    entries = broken + short_entry(SHORT_A, cluster=2, size=len(DATA_A)) + b"\x00" * 32
    result = parse_dir(entries, make_data())

    assert len(result) == 1
    entry = result[0]
    assert entry.name == "FILEA.TXT"
    assert entry.lfn_invalid == "long name sequence has missing or duplicate entries"
    assert entry.cluster == 2
    assert entry.open().read() == DATA_A


def test_lfn_missing_last_entry() -> None:
    long_name = lfn_entries("missing sequence number.txt", SHORT_A)
    broken = long_name[32:]  # drop the first (last-long) entry
    entries = broken + short_entry(SHORT_A, cluster=2, size=len(DATA_A)) + b"\x00" * 32
    result = parse_dir(entries, make_data())

    assert len(result) == 1
    entry = result[0]
    assert entry.name == "FILEA.TXT"
    assert entry.lfn_invalid == "long name sequence is missing the last-long entry"


def test_lfn_duplicate_sequence_number() -> None:
    long_name = lfn_entries("missing sequence number.txt", SHORT_A)
    broken = long_name[:32] + long_name[32:64] + long_name[32:]  # duplicate the middle entry
    entries = broken + short_entry(SHORT_A, cluster=2, size=len(DATA_A)) + b"\x00" * 32
    result = parse_dir(entries, make_data())

    assert len(result) == 1
    entry = result[0]
    assert entry.name == "FILEA.TXT"
    assert entry.lfn_invalid == "long name sequence has missing or duplicate entries"


def test_lfn_inconsistent_checksums() -> None:
    long_name = bytearray(lfn_entries("file a long name.txt", SHORT_A))
    long_name[13] ^= 0xFF  # corrupt the checksum of the first entry only
    entries = bytes(long_name) + short_entry(SHORT_A, cluster=2, size=len(DATA_A)) + b"\x00" * 32
    result = parse_dir(entries, make_data())

    assert len(result) == 1
    entry = result[0]
    assert entry.name == "FILEA.TXT"
    assert entry.lfn_invalid == "long name entries have inconsistent checksums"


def test_lfn_followed_by_deleted_short_entry() -> None:
    entries = b"".join(
        [
            lfn_entries("ghost file.txt", b"GHOST   TXT"),
            short_entry(b"GHOST   TXT", deleted=True),
            lfn_entries("file b long name.txt", SHORT_B),
            short_entry(SHORT_B, cluster=3, size=len(DATA_B)),
            b"\x00" * 32,
        ]
    )
    result = parse_dir(entries, make_data())

    assert len(result) == 1
    assert result[0].name == "file b long name.txt"
    assert result[0].cluster == 3
    assert result[0].open().read() == DATA_B


def test_residual_lfn_does_not_swallow_next_record() -> None:
    residual = lfn_entries("old deleted file.txt", b"OLD     TXT")
    entries = b"".join(
        [
            residual,
            lfn_entries("file b long name.txt", SHORT_B),
            short_entry(SHORT_B, cluster=3, size=len(DATA_B)),
            b"\x00" * 32,
        ]
    )
    result = parse_dir(entries, make_data())

    assert len(result) == 1
    entry = result[0]
    assert entry.name == "file b long name.txt"
    assert entry.lfn_invalid is None
    assert entry.cluster == 3
    assert entry.open().read() == DATA_B

    # all raw long name entries, including the orphaned ones, are preserved
    assert len(entry.ldirents) == 4
    assert b"".join(bytes(e) for e in entry.ldirents[:2]) == residual


def test_short_name_lookup(fat12: BinaryIO) -> None:
    fs = fat.FATFS(fat12)

    entry = fs.get("FILE1.TXT")
    assert entry.name == "file1.txt"
    assert entry.short_name == "FILE1.TXT"
    assert entry.lfn_invalid is None

    assert fs.get("file1.txt") is not None
