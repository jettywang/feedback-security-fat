from __future__ import annotations

import io
import struct
from typing import BinaryIO

import pytest
from dissect.fat import exfat
from dissect.fat.c_exfat import c_exfat

SECTOR_SIZE = 512
SECTORS_PER_CLUSTER = 2
CLUSTER_SIZE = SECTOR_SIZE * SECTORS_PER_CLUSTER
FAT_SECTOR = 1
CLUSTER_HEAP_SECTOR = 8
CLUSTER_COUNT = 64
ROOT_CLUSTER = 3
EOC = 0xFFFFFFFF


def _file_entry(name: str, location: int, size: int, *, directory: bool = False, no_fat_chain: bool = True) -> bytes:
    """Build a complete exFAT file/directory entry set for ``name``."""
    chunks = [name[index : index + 15] for index in range(0, len(name), 15)]

    metadata = c_exfat.FILE_DIRECTORY_ENTRY(
        entry_type=0x85,
        subentry_count=1 + len(chunks),
        attributes=c_exfat.ATTRIBUTES(directory=1 if directory else 0),
    ).dumps()

    stream = c_exfat.STREAM_DIRECTORY_ENTRY(
        entry_type=0xC0,
        flags=c_exfat.FILE_FLAGS(not_fragmented=1 if no_fat_chain else 0),
        filename_length=len(name),
        location=location,
        data_length=size,
    ).dumps()

    filenames = b"".join(bytes([0xC1, 0x00]) + chunk.encode("utf-16-le").ljust(30, b"\x00") for chunk in chunks)
    return metadata + stream + filenames


def _volume_entry() -> bytes:
    return c_exfat.VOLUME_DIRECTORY_ENTRY(entry_type=0x83, label_length=4, volume_label="TEST").dumps()


def _cluster_offset(cluster: int) -> int:
    return (CLUSTER_HEAP_SECTOR + (cluster - 2) * SECTORS_PER_CLUSTER) * SECTOR_SIZE


def _build_image(chain_data: list[tuple[list[int], bytes]], fat: dict[int, int], root_data: bytes) -> BinaryIO:
    total_sectors = CLUSTER_HEAP_SECTOR + CLUSTER_COUNT * SECTORS_PER_CLUSTER
    image = bytearray(total_sectors * SECTOR_SIZE)

    image[:SECTOR_SIZE] = c_exfat.EXFAT_HEADER(
        jump_boot=b"\xeb\x76\x90",
        fs_name=b"EXFAT   ",
        volume_sector_count=total_sectors,
        fat_sector=FAT_SECTOR,
        fat_sector_count=1,
        cluster_heap_sector=CLUSTER_HEAP_SECTOR,
        cluster_heap_count=CLUSTER_COUNT,
        root_dir_cluster=ROOT_CLUSTER,
        fs_version_min=0,
        fs_version_maj=1,
        bytes_per_sector_exp=9,
        sectors_per_cluster_exp=1,  # 2 sectors per cluster
        number_of_fats=1,
        drive_select=0x80,
        boot_signature=0xAA55,
    ).dumps()

    for cluster, value in {ROOT_CLUSTER: EOC, **fat}.items():
        struct.pack_into("<I", image, FAT_SECTOR * SECTOR_SIZE + cluster * 4, value)

    def write(chain: list[int], data: bytes) -> None:
        for index, cluster in enumerate(chain):
            chunk = data[index * CLUSTER_SIZE : (index + 1) * CLUSTER_SIZE]
            offset = _cluster_offset(cluster)
            image[offset : offset + len(chunk)] = chunk

    write([ROOT_CLUSTER], root_data)
    for chain, data in chain_data:
        write(chain, data)

    return io.BytesIO(bytes(image))


def _logical_directories(inner_no_fat_chain: bool) -> tuple[bytes, bytes]:
    """Return the identical logical contents of the outer and inner directories.

    ``crossing.txt`` starts 64 bytes before the end of a cluster, so its entry
    set crosses the cluster boundary. ``inner`` starts in the second cluster.
    """
    outer = bytearray(3 * CLUSTER_SIZE)
    outer[0:96] = _file_entry("first.txt", 40, 4)
    outer[CLUSTER_SIZE - 64 : CLUSTER_SIZE + 32] = _file_entry("crossing.txt", 41, 4)
    outer[CLUSTER_SIZE + 128 : CLUSTER_SIZE + 224] = _file_entry(
        "inner", 20, 2 * CLUSTER_SIZE, directory=True, no_fat_chain=inner_no_fat_chain
    )
    outer[2 * CLUSTER_SIZE : 2 * CLUSTER_SIZE + 96] = _file_entry("last.txt", 42, 4)

    inner = bytearray(2 * CLUSTER_SIZE)
    inner[0:96] = _file_entry("alpha.txt", 43, 4)
    inner[CLUSTER_SIZE - 64 : CLUSTER_SIZE + 32] = _file_entry("beta.txt", 44, 4)
    inner[CLUSTER_SIZE + 128 : CLUSTER_SIZE + 224] = _file_entry("gamma.txt", 45, 4)

    return bytes(outer), bytes(inner)


def _root_entry(outer_location: int, size: int, *, no_fat_chain: bool) -> bytes:
    return (
        _file_entry(
            "outer",
            outer_location,
            size,
            directory=True,
            no_fat_chain=no_fat_chain,
        )
        + _volume_entry()
    )


def _summarize(entries: dict) -> dict[str, tuple[bool, int, int, dict]]:
    result = {}
    for name, (entry, children) in entries.items():
        result[name] = (
            bool(entry.metadata.attributes.directory),
            entry.stream.location,
            entry.stream.data_length,
            _summarize(children) if children is not None else {},
        )
    return result


def _contiguous_image() -> BinaryIO:
    outer, inner = _logical_directories(inner_no_fat_chain=True)
    root = _root_entry(10, len(outer), no_fat_chain=True)
    return _build_image([([10, 11, 12], outer), ([20, 21], inner)], {}, root)


def _fragmented_image() -> BinaryIO:
    outer, inner = _logical_directories(inner_no_fat_chain=False)
    root = _root_entry(10, len(outer), no_fat_chain=False)
    # outer: 10 -> 30 -> 31, inner: 20 -> 40 -> 41
    fat = {10: 30, 30: 31, 31: EOC, 20: 40, 40: 41, 41: EOC}
    return _build_image([([10, 30, 31], outer), ([20, 40, 41], inner)], fat, root)


def test_contiguous_and_fragmented_directories_match() -> None:
    """Both layouts must enumerate the same names, depths and file locations."""
    contiguous = exfat.ExFAT(_contiguous_image())
    fragmented = exfat.ExFAT(_fragmented_image())

    contiguous_outer = contiguous.files["/"][1]["outer"][1]
    fragmented_outer = fragmented.files["/"][1]["outer"][1]

    assert list(contiguous_outer.keys()) == ["first.txt", "crossing.txt", "inner", "last.txt"]
    assert _summarize(contiguous_outer) == _summarize(fragmented_outer)

    assert list(contiguous_outer["inner"][1].keys()) == ["alpha.txt", "beta.txt", "gamma.txt"]
    assert _summarize(contiguous_outer["inner"][1]) == _summarize(fragmented_outer["inner"][1])

    # Sizes are declared in bytes; runs are returned in sectors.
    assert contiguous.runlist(10, True, 3 * CLUSTER_SIZE) == [(_cluster_offset(10) // SECTOR_SIZE, 6)]
    assert contiguous.runlist(20, True, 2 * CLUSTER_SIZE) == [(_cluster_offset(20) // SECTOR_SIZE, 4)]

    assert fragmented.runlist(10, False, 3 * CLUSTER_SIZE) == [
        (_cluster_offset(10) // SECTOR_SIZE, 2),
        (_cluster_offset(30) // SECTOR_SIZE, 4),
    ]
    assert fragmented.runlist(20, False, 2 * CLUSTER_SIZE) == [
        (_cluster_offset(20) // SECTOR_SIZE, 2),
        (_cluster_offset(40) // SECTOR_SIZE, 2),
    ]


def test_fragmented_directory_ignores_adjacent_clusters() -> None:
    """Decoys in physically adjacent clusters must not be enumerated."""
    image = _fragmented_image().getvalue()
    # Cluster 11 follows the first real cluster but is not in the chain.
    offset = _cluster_offset(11)
    image = bytearray(image)
    image[offset : offset + 96] = _file_entry("ghost.txt", 46, 4)
    offset = _cluster_offset(21)
    image[offset : offset + 96] = _file_entry("ghost_inner.txt", 47, 4)

    e = exfat.ExFAT(io.BytesIO(bytes(image)))
    outer = e.files["/"][1]["outer"][1]
    inner = outer["inner"][1]

    assert list(outer.keys()) == ["first.txt", "crossing.txt", "inner", "last.txt"]
    assert "ghost.txt" not in outer
    assert list(inner.keys()) == ["alpha.txt", "beta.txt", "gamma.txt"]
    assert "ghost_inner.txt" not in inner


def test_declared_size_ending_mid_entry_stops_parsing() -> None:
    """A declared size that ends mid-entry must not complete the entry from the next cluster."""
    outer = bytearray(2 * CLUSTER_SIZE)
    outer[0:96] = _file_entry("first.txt", 40, 4)
    # 'cut.txt' metadata starts 32 bytes before the declared end of the directory,
    # so its stream and filename entries fall beyond the declared size.
    outer[CLUSTER_SIZE + 512 - 32 : CLUSTER_SIZE + 512] = c_exfat.FILE_DIRECTORY_ENTRY(
        entry_type=0x85,
        subentry_count=2,
        attributes=c_exfat.ATTRIBUTES(directory=0),
    ).dumps()

    root = _root_entry(10, CLUSTER_SIZE + 512, no_fat_chain=True)
    chain_data = [
        ([10, 11], bytes(outer)),
        # Physically following cluster that contains what looks like the rest of the entry.
        ([12], _file_entry("ghost.txt", 43, 4)),
        ([13], _file_entry("ghost_continuation.txt", 44, 4)),
    ]

    e = exfat.ExFAT(_build_image(chain_data, {10: 11, 11: EOC}, root))
    entries = e.files["/"][1]["outer"][1]

    assert list(entries.keys()) == ["first.txt"]
    # 1536 bytes need two clusters (four sectors), even though the last entry is cut off.
    assert e.runlist(10, True, CLUSTER_SIZE + 512) == [(_cluster_offset(10) // SECTOR_SIZE, 4)]


def test_truncated_last_cluster_does_not_read_adjacent_data() -> None:
    """A partial entry at the end of the allocated directory is not completed from elsewhere."""
    outer = bytearray(2 * CLUSTER_SIZE)
    outer[0:96] = _file_entry("first.txt", 40, 4)
    # Complete entry crossing the boundary between the two allocated clusters.
    outer[CLUSTER_SIZE - 64 : CLUSTER_SIZE + 32] = _file_entry("crossing.txt", 41, 4)
    # Only the metadata of this entry fits before the declared end of the directory.
    outer[-32:] = b"\x85\x02\x00\x00\x10\x00" + b"\x00" * 26

    root = _root_entry(10, len(outer), no_fat_chain=False)
    fat = {10: 11, 11: EOC}
    # Physically following clusters 12 and 13 contain the remaining entries.
    # The chain ends at 11, so they must never be read.
    chain_data = [
        ([10, 11], bytes(outer)),
        ([12], _file_entry("ghost.txt", 43, 4)),
        ([13], _file_entry("ghost_continuation.txt", 44, 4)),
    ]

    e = exfat.ExFAT(_build_image(chain_data, fat, root))
    entries = e.files["/"][1]["outer"][1]

    assert list(entries.keys()) == ["first.txt", "crossing.txt"]
    assert entries["crossing.txt"][0].stream.location == 41


def test_short_fragmented_chain_does_not_read_adjacent_cluster() -> None:
    """A FAT chain shorter than the declared size must stop at the last real cluster."""
    outer = bytearray(3 * CLUSTER_SIZE)
    outer[0:96] = _file_entry("first.txt", 40, 4)
    outer[CLUSTER_SIZE - 64 : CLUSTER_SIZE + 32] = _file_entry("crossing.txt", 41, 4)
    outer[CLUSTER_SIZE + 128 : CLUSTER_SIZE + 224] = _file_entry("second.txt", 42, 4)
    # Entry starts in the final available cluster but is cut off by the chain end.
    outer[2 * CLUSTER_SIZE - 32 :] = b"\x85\x02\x00\x00\x10\x00" + b"\x00" * 26

    root = _root_entry(10, len(outer), no_fat_chain=False)
    # The chain is 10 -> 30, skipping cluster 11. Declared size is three clusters.
    fat = {10: 30, 30: EOC}
    chain_data = [
        ([10], bytes(outer[:CLUSTER_SIZE])),
        ([30], bytes(outer[CLUSTER_SIZE : 2 * CLUSTER_SIZE])),
        ([11], _file_entry("ghost_near_start.txt", 43, 4)),
        ([31], _file_entry("ghost_after_chain.txt", 44, 4)),
    ]

    e = exfat.ExFAT(_build_image(chain_data, fat, root))
    entries = e.files["/"][1]["outer"][1]

    assert list(entries.keys()) == ["first.txt", "crossing.txt", "second.txt"]
    assert e.runlist(10, False, 3 * CLUSTER_SIZE) == [
        (_cluster_offset(10) // SECTOR_SIZE, 2),
        (_cluster_offset(30) // SECTOR_SIZE, 2),
    ]


def test_runlist_units_and_size_boundaries() -> None:
    """Runlist sizes are in bytes and runs are returned in sectors."""
    e = exfat.ExFAT(
        _build_image(
            [([10], b"\x00" * CLUSTER_SIZE), ([30], b"\x00" * CLUSTER_SIZE)],
            {10: 30, 30: EOC},
            _volume_entry(),
        )
    )

    # Exactly one cluster.
    assert e.runlist(10, True, CLUSTER_SIZE) == [(_cluster_offset(10) // SECTOR_SIZE, 2)]
    # One byte more requires a second cluster.
    assert e.runlist(10, True, CLUSTER_SIZE + 1) == [(_cluster_offset(10) // SECTOR_SIZE, 4)]
    # Fragmented chains are also limited by the declared size.
    assert e.runlist(10, False, CLUSTER_SIZE) == [(_cluster_offset(10) // SECTOR_SIZE, 2)]
    assert e.runlist(10, False, CLUSTER_SIZE + 1) == [
        (_cluster_offset(10) // SECTOR_SIZE, 2),
        (_cluster_offset(30) // SECTOR_SIZE, 2),
    ]
    # A declared size of zero allocates no runs.
    assert e.runlist(10, False, 0) == []
    # A chain shorter than the declared size yields only the real chain.
    assert e.runlist(10, False, 4 * CLUSTER_SIZE) == [
        (_cluster_offset(10) // SECTOR_SIZE, 2),
        (_cluster_offset(30) // SECTOR_SIZE, 2),
    ]


@pytest.mark.parametrize("location", [0, 1, CLUSTER_COUNT + 2])
def test_runlist_invalid_starting_cluster(location: int) -> None:
    """Clusters outside the cluster heap produce no runs and no reads."""
    e = exfat.ExFAT(_build_image([], {}, _volume_entry()))

    assert e.runlist(location, True, CLUSTER_SIZE) == []
    assert e.runlist(location, False, CLUSTER_SIZE) == []
    assert e.runlist(location, False) == []
    assert e.get_cluster_chain(location) == []
