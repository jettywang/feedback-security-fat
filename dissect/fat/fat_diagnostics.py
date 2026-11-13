"""Read-only FAT redundancy diagnostics.

This module answers a single forensic question: when the File Allocation Tables
of a FAT volume disagree, which table does the current extraction code trust,
and where does the evidence stop supporting a definite answer?

It deliberately performs no repair and no majority voting. Every FAT entry is
presented with its raw on-disk value so the caller, not the tool, decides which
copy is authoritative.

The extraction behaviour being diagnosed lives in :class:`dissect.fat.fat.FATFS`:
its constructor maps the first FAT only (the region starting at
``BPB_RsvdSecCnt``) and never inspects the FAT32 ``BPB_ExtFlags`` active-FAT /
mirroring field. The findings below therefore distinguish what the on-disk
metadata selects from what the extractor actually reads.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, BinaryIO

from dissect.fat.c_fat import (
    BAD_CLUSTER,
    DATA_CLUSTER_MAX,
    DATA_CLUSTER_MIN,
    END_OF_CLUSTER_MAX,
    END_OF_CLUSTER_MIN,
    FREE_CLUSTER,
    Fattype,
    c_fat,
)
from dissect.fat.exceptions import (
    Error,
    InvalidBPB,
)
from dissect.fat.fat import FATFS, mask

if TYPE_CHECKING:
    from collections.abc import Iterator

# FAT32 BPB_ExtFlags layout (fatgen103.doc, section "extended boot record").
EXTFLAGS_MIRROR_DISABLED = 0x0080
EXTFLAGS_ACTIVE_FAT_MASK = 0x000F
ENTRY_MASK_28BIT = 0x0FFFFFFF

# Only the low 28 bits of a FAT32 entry carry a cluster number.
FAT32_ENTRY_SIZE = 4


class DiagnosticError(Error):
    """Raised when a volume cannot be diagnosed (not FAT32, unreadable BPB)."""


@dataclass(frozen=True)
class FATCopy:
    """The physical location and readable extent of one File Allocation Table."""

    index: int
    offset: int
    declared_size: int
    readable_size: int

    @property
    def entry_count(self) -> int:
        return self.readable_size // FAT32_ENTRY_SIZE

    @property
    def truncated(self) -> bool:
        return self.readable_size < self.declared_size


@dataclass(frozen=True)
class MirrorFlags:
    """Decoded interpretation of the FAT32 ``BPB_ExtFlags`` field."""

    raw: int
    mirroring_disabled: bool
    active_fat_index: int | None

    @classmethod
    def decode(cls, ext_flags: int) -> MirrorFlags:
        disabled = bool(ext_flags & EXTFLAGS_MIRROR_DISABLED)
        return cls(
            raw=ext_flags,
            mirroring_disabled=disabled,
            active_fat_index=(ext_flags & EXTFLAGS_ACTIVE_FAT_MASK) if disabled else None,
        )


@dataclass(frozen=True)
class EntryValue:
    """A single FAT entry, keeping both the raw uint32 and the masked value."""

    fat_index: int
    entry: int
    raw: int | None
    value: int | None

    @property
    def readable(self) -> bool:
        return self.raw is not None


@dataclass(frozen=True)
class EntryDiff:
    """One cluster number whose readable FAT entries do not all agree."""

    entry: int
    copies: tuple[EntryValue, ...]


@dataclass
class ChainState:
    """The outcome of walking one cluster chain against one FAT."""

    fat_index: int
    start_cluster: int
    clusters: list[int] = field(default_factory=list)
    terminal: str | None = None
    terminal_raw: int | None = None
    error: str | None = None
    error_cluster: int | None = None


@dataclass(frozen=True)
class FileChain:
    """How one directory entry's chain is resolved by every readable FAT."""

    path: str
    is_directory: bool
    start_cluster: int
    size: int
    chains: tuple[ChainState, ...]

    @property
    def divergent(self) -> bool:
        readable = [chain for chain in self.chains if chain.error is None]
        if len(readable) < 2:
            return False
        first = (tuple(readable[0].clusters), readable[0].terminal_raw)
        return any((tuple(chain.clusters), chain.terminal_raw) != first for chain in readable[1:])


@dataclass(frozen=True)
class UnreadableRange:
    """A contiguous range of FAT entries that could not be read from a copy."""

    fat_index: int
    first_entry: int
    last_entry: int
    reason: str


@dataclass(frozen=True)
class WalkFailure:
    """Why directory traversal (and therefore per-file mapping) was abandoned."""

    reason: str
    detail: str | None = None


@dataclass
class FATDiagnosis:
    """The complete read-only diagnosis for one FAT volume."""

    fat_type: str
    fat_count: int
    sector_size: int
    fat_size_sectors: int
    entry_count_per_fat: int
    ext_flags: MirrorFlags
    copies: tuple[FATCopy, ...]
    extractor: dict
    on_disk_selection: dict
    differing_entries: tuple[EntryDiff, ...]
    unreadable_ranges: tuple[UnreadableRange, ...]
    files: tuple[FileChain, ...]
    walk_failure: WalkFailure | None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["ext_flags"] = asdict(self.ext_flags)
        return data


def classify_fat32_entry(value: int) -> str:
    """Return the FAT32 role of a masked entry value (free, EOC, bad, data...)."""
    if value == FREE_CLUSTER:
        return "free"
    if value == BAD_CLUSTER:
        return "bad"
    if END_OF_CLUSTER_MIN <= value <= END_OF_CLUSTER_MAX:
        return "eoc"
    if DATA_CLUSTER_MIN <= value <= DATA_CLUSTER_MAX:
        return "data"
    if DATA_CLUSTER_MAX < value < BAD_CLUSTER:
        return "reserved"
    return "invalid"


class RawFATReader:
    """Entry-by-entry reader for one physical FAT, tolerant of short reads.

    The underlying file is only ever read, never written. Entries past the end
    of a truncated image are reported as unreadable instead of being guessed.
    """

    def __init__(self, fh: BinaryIO, copy: FATCopy):
        self.fh = fh
        self.copy = copy

    def read_raw(self, entry: int) -> int | None:
        if entry >= self.copy.entry_count:
            return None
        self.fh.seek(self.copy.offset + entry * FAT32_ENTRY_SIZE)
        buf = self.fh.read(FAT32_ENTRY_SIZE)
        if len(buf) < FAT32_ENTRY_SIZE:
            return None
        return struct.unpack("<I", buf)[0]

    def read_value(self, entry: int) -> int | None:
        raw = self.read_raw(entry)
        return None if raw is None else raw & ENTRY_MASK_28BIT

    def walk_chain(self, start_cluster: int, max_steps: int) -> ChainState:
        state = ChainState(fat_index=self.copy.index, start_cluster=start_cluster)
        cluster = start_cluster
        for _ in range(max_steps):
            if cluster >= self.copy.entry_count:
                state.terminal = "out-of-fat"
                state.error = f"cluster {cluster} exceeds readable FAT extent ({self.copy.entry_count} entries)"
                state.error_cluster = cluster
                return state

            raw = self.read_raw(cluster)
            if raw is None:
                state.terminal = "unreadable"
                state.error = f"entry {cluster} is past the readable image extent"
                state.error_cluster = cluster
                return state
            value = raw & ENTRY_MASK_28BIT

            state.clusters.append(cluster)

            if DATA_CLUSTER_MIN <= value <= mask(DATA_CLUSTER_MAX, 32):
                cluster = value
                continue
            if mask(END_OF_CLUSTER_MIN, 32) <= value <= mask(END_OF_CLUSTER_MAX, 32):
                state.terminal = "eoc"
                state.terminal_raw = raw
                return state
            if value == mask(BAD_CLUSTER, 32):
                state.terminal = "bad"
                state.terminal_raw = raw
                state.error = f"bad cluster marker at cluster {cluster}"
                state.error_cluster = cluster
                return state
            if value == FREE_CLUSTER:
                state.terminal = "free"
                state.terminal_raw = raw
                state.error = f"free cluster marker at cluster {cluster}"
                state.error_cluster = cluster
                return state

            state.terminal = "invalid"
            state.terminal_raw = raw
            state.error = f"entry {cluster} holds invalid cluster value 0x{value:08x}"
            state.error_cluster = cluster
            return state

        state.terminal = "loop-guard"
        state.error = f"chain did not terminate within {max_steps} steps (loop or corruption)"
        return state


def _read_bpb(fh: BinaryIO) -> tuple[c_fat.Bpb, c_fat.Bpb32]:
    from dissect.fat.fat import validate_bpb

    fh.seek(0)
    sector = fh.read(512)
    if len(sector) < len(c_fat.Bpb):
        raise DiagnosticError("image is shorter than the FAT boot sector")
    bpb = c_fat.Bpb(sector[: len(c_fat.Bpb)])
    try:
        validate_bpb(bpb)
    except InvalidBPB as err:
        raise DiagnosticError(f"invalid BPB: {err}") from err
    return bpb, c_fat.Bpb32(sector[len(c_fat.Bpb) :])


def _detect_fat_copies(fh: BinaryIO, bpb: c_fat.Bpb, fat_size: int) -> tuple[FATCopy, ...]:
    fh.seek(0, 2)
    image_size = fh.tell()
    copies = []
    fat_bytes = fat_size * bpb.BPB_BytsPerSec
    for index in range(bpb.BPB_NumFATs):
        offset = (bpb.BPB_RsvdSecCnt + index * fat_size) * bpb.BPB_BytsPerSec
        if offset >= image_size:
            readable = 0
        else:
            readable = min(fat_bytes, image_size - offset)
        copies.append(
            FATCopy(
                index=index,
                offset=offset,
                declared_size=fat_bytes,
                readable_size=readable - readable % FAT32_ENTRY_SIZE,
            )
        )
    return tuple(copies)


def _unreadable_ranges(copies: tuple[FATCopy, ...], declared_entries: int) -> tuple[UnreadableRange, ...]:
    ranges = []
    for copy in copies:
        if copy.entry_count < declared_entries:
            ranges.append(
                UnreadableRange(
                    fat_index=copy.index,
                    first_entry=copy.entry_count,
                    last_entry=declared_entries - 1,
                    reason="short read: image ends before the declared FAT extent",
                )
            )
    return tuple(ranges)


def _entry_diffs(fh: BinaryIO, copies: tuple[FATCopy, ...], declared_entries: int) -> tuple[EntryDiff, ...]:
    readers = [RawFATReader(fh, copy) for copy in copies]
    diffs = []
    for entry in range(declared_entries):
        values = []
        for reader, copy in zip(readers, copies, strict=True):
            raw = reader.read_raw(entry)
            values.append(
                EntryValue(
                    fat_index=copy.index,
                    entry=entry,
                    raw=raw,
                    value=None if raw is None else raw & ENTRY_MASK_28BIT,
                )
            )
        readable = [item for item in values if item.readable]
        if len(readable) >= 2 and len({item.raw for item in readable}) != 1:
            diffs.append(EntryDiff(entry=entry, copies=tuple(values)))
    return tuple(diffs)


def _iter_directory_entries(entry: object) -> Iterator[object]:
    for child in entry.iterdir():
        if child.name in (".", ".."):
            continue
        yield child
        if child.is_directory():
            yield from _iter_directory_entries(child)


def _collect_files(
    fs: FATFS, copies: tuple[FATCopy, ...], declared_entries: int
) -> tuple[FileChain, ...] | WalkFailure:
    readers = {copy.index: RawFATReader(fs.fh, copy) for copy in copies}
    files = []
    try:
        entries = [fs.root]
        entries.extend(_iter_directory_entries(fs.root))
    except (OSError, EOFError, Error) as err:
        return WalkFailure(reason=type(err).__name__, detail=str(err))

    for entry in entries:
        start = entry.cluster
        if start is None or start == FREE_CLUSTER:
            continue
        chains = tuple(readers[index].walk_chain(start, declared_entries + 1) for index in sorted(readers))
        files.append(
            FileChain(
                path=entry.path or "\\",
                is_directory=entry.is_directory(),
                start_cluster=start,
                size=entry.size,
                chains=chains,
            )
        )
    return tuple(files)


def diagnose(fh: BinaryIO) -> FATDiagnosis:
    """Diagnose FAT redundancy for an open image without modifying it.

    Args:
        fh: A binary file object positioned anywhere; it is only read.

    Returns:
        A :class:`FATDiagnosis` containing raw entry values, divergence lists,
        per-file chain states and explicit unreadable ranges.

    Raises:
        DiagnosticError: If the volume is not a parseable FAT32 image.
    """
    bpb, bpb32 = _read_bpb(fh)
    fat_size = bpb.BPB_FATSz16 or bpb32.BPB_FATSz32

    total_sectors = bpb.BPB_TotSec16 or bpb.BPB_TotSec32
    root_dir_sectors = ((bpb.BPB_RootEntCnt * 32) + (bpb.BPB_BytsPerSec - 1)) // bpb.BPB_BytsPerSec
    first_data_sector = bpb.BPB_RsvdSecCnt + (bpb.BPB_NumFATs * fat_size) + root_dir_sectors
    count_of_clusters = (total_sectors - first_data_sector) // bpb.BPB_SecPerClus
    if count_of_clusters < 65525:
        raise DiagnosticError(
            f"only FAT32 carries BPB_ExtFlags active-FAT metadata (volume has {count_of_clusters} clusters)"
        )

    copies = _detect_fat_copies(fh, bpb, fat_size)
    declared_entries = (fat_size * bpb.BPB_BytsPerSec) // FAT32_ENTRY_SIZE
    flags = MirrorFlags.decode(bpb32.BPB_ExtFlags)

    if flags.mirroring_disabled:
        on_disk = {
            "basis": "BPB_ExtFlags bit 7 set: mirroring disabled, low nibble names the active FAT",
            "selected_fat": flags.active_fat_index,
            "definite": flags.active_fat_index < bpb.BPB_NumFATs,
        }
    else:
        on_disk = {
            "basis": "BPB_ExtFlags bit 7 clear: runtime mirroring is enabled, no canonical active FAT",
            "selected_fat": None,
            "definite": False,
        }

    extractor = {
        "basis": "dissect.fat.fat.FATFS maps only the first FAT region (BPB_RsvdSecCnt); BPB_ExtFlags is never read",
        "selected_fat": 0,
        "definite": True,
    }

    diffs = _entry_diffs(fh, copies, declared_entries)
    unreadable = _unreadable_ranges(copies, declared_entries)

    walk_failure = None
    files: tuple[FileChain, ...] = ()
    try:
        fs = FATFS(fh)
    except (InvalidBPB, Error, OSError, EOFError) as err:
        walk_failure = WalkFailure(reason=type(err).__name__, detail=str(err))
    else:
        result = _collect_files(fs, copies, declared_entries)
        if isinstance(result, WalkFailure):
            walk_failure = result
        else:
            files = result

    return FATDiagnosis(
        fat_type=Fattype.FAT32.name,
        fat_count=bpb.BPB_NumFATs,
        sector_size=bpb.BPB_BytsPerSec,
        fat_size_sectors=fat_size,
        entry_count_per_fat=declared_entries,
        ext_flags=flags,
        copies=copies,
        extractor=extractor,
        on_disk_selection=on_disk,
        differing_entries=diffs,
        unreadable_ranges=unreadable,
        files=files,
        walk_failure=walk_failure,
    )


def _hex_raw(item: EntryValue) -> str:
    return "UNREADABLE" if item.raw is None else f"0x{item.raw:08x}"


def render_text(diagnosis: FATDiagnosis) -> str:
    """Render a human-readable, sectioned report in Chinese."""
    lines = []
    lines.append("FAT32 冗余诊断（只读；不执行镜像修复，不执行多数投票）")
    lines.append("=" * 68)
    lines.append(
        f"FAT 份数: {diagnosis.fat_count}  每份表项数: {diagnosis.entry_count_per_fat}  "
        f"BPB_ExtFlags 原始值: 0x{diagnosis.ext_flags.raw:04x}"
    )
    lines.append("")

    lines.append("[1] 确定的选择依据")
    lines.append(f"  磁盘标志: {diagnosis.on_disk_selection['basis']}")
    selected = diagnosis.on_disk_selection["selected_fat"]
    lines.append(
        f"  磁盘标志指定的活动 FAT: {('FAT#' + str(selected)) if selected is not None else '无（镜像模式）'}"
        f"（依据充分: {diagnosis.on_disk_selection['definite']}）"
    )
    lines.append(f"  当前提取器: {diagnosis.extractor['basis']}")
    lines.append("  当前提取器实际读取: FAT#0（依据充分: True）")
    if diagnosis.ext_flags.mirroring_disabled and diagnosis.ext_flags.active_fat_index != 0:
        lines.append(
            f"  >> 冲突: 磁盘标志要求 FAT#{diagnosis.ext_flags.active_fat_index}，"
            "提取器仍读取 FAT#0，提取结果不反映标志所指的活动表。"
        )
    lines.append("")

    lines.append("[2] 各 FAT 副本可读性（保留原始表项，缺失即报告，不补零、不推断）")
    for copy in diagnosis.copies:
        status = "截断" if copy.truncated else "完整"
        lines.append(
            f"  FAT#{copy.index}: 偏移 0x{copy.offset:x}，可读 {copy.readable_size}/"
            f"{copy.declared_size} 字节（{status}，可读表项 {copy.entry_count}）"
        )
    lines.append("")

    lines.append("[3] 差异表项（原始 uint32 值原样列出）")
    if not diagnosis.differing_entries:
        lines.append("  可读区间内未发现差异。")
    else:
        lines.append(f"  共 {len(diagnosis.differing_entries)} 项：")
        for diff in diagnosis.differing_entries:
            rendered = ", ".join(
                f"FAT#{item.fat_index}={_hex_raw(item)}"
                f"({'不可读' if not item.readable else classify_fat32_entry(item.value)})"
                for item in diff.copies
            )
            lines.append(f"  表项 {diff.entry}: {rendered}")
    lines.append("")

    lines.append("[4] 受影响文件（按每个 FAT 分别走链，不合并、不投票）")
    if diagnosis.walk_failure is not None:
        lines.append(f"  目录遍历未能完成: {diagnosis.walk_failure.reason}: {diagnosis.walk_failure.detail or ''}")
        lines.append("  因此无法把全部差异表项映射到具体文件；映射关系本身属于不可确定区间。")
    elif not diagnosis.files:
        lines.append("  卷中没有已分配起始簇的文件或目录。")
    else:
        for item in diagnosis.files:
            kind = "目录" if item.is_directory else "文件"
            lines.append(
                f"  {kind} {item.path}（起始簇 {item.start_cluster}，大小 {item.size} 字节）"
                f" 链分歧: {item.divergent}"
            )
            for chain in item.chains:
                if chain.error is not None:
                    lines.append(
                        f"    FAT#{chain.fat_index}: 在簇 {chain.error_cluster} 终止"
                        f"（{chain.terminal}: {chain.error}）"
                    )
                else:
                    lines.append(
                        f"    FAT#{chain.fat_index}: {len(chain.clusters)} 簇，终止于 {chain.terminal}"
                        f"（终止表项原始值 0x{chain.terminal_raw:08x}），链 {chain.clusters}"
                    )
    lines.append("")

    lines.append("[5] 无法确定的内容区间")
    undetermined = []
    for gap in diagnosis.unreadable_ranges:
        undetermined.append(f"  FAT#{gap.fat_index} 表项 {gap.first_entry}..{gap.last_entry} 不可读（{gap.reason}）")
    if diagnosis.ext_flags.mirroring_disabled:
        undetermined.append(
            f"  非活动 FAT 中与活动 FAT#{diagnosis.ext_flags.active_fat_index} 冲突的表项是否含有效旧数据，"
            "仅凭卷内元数据无法判定。"
        )
    else:
        undetermined.append(
            "  镜像启用时两张表地位对等；表项不同且无其它校验和/日志佐证时，正确链尾无法在卷内确定，"
            "提取器固定取 FAT#0 只是实现选择，不是证据上的裁定。"
        )
    for item in diagnosis.files:
        if item.divergent:
            undetermined.append(
                f"  {item.path}: 各 FAT 给出的簇链不一致，差异部分的文件内容无法确定（见 [4] 原始链）。"
            )
        for chain in item.chains:
            if chain.error is not None:
                undetermined.append(
                    f"  {item.path} 经 FAT#{chain.fat_index}: 自簇 {chain.error_cluster} 起的内容无法确定（{chain.terminal}）。"
                )
    if not undetermined:
        lines.append("  无：可读区间内所有表项一致，且每条链均正常终止。")
    else:
        lines.extend(undetermined)

    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only FAT32 redundancy diagnostic: which FAT does extraction trust, and what stays undecided."
    )
    parser.add_argument("image", help="path to a FAT32 image (opened read-only)")
    parser.add_argument("--json", action="store_true", dest="as_json", help="emit structured JSON instead of text")
    args = parser.parse_args(argv)

    with open(args.image, "rb") as fh:
        diagnosis = diagnose(fh)

    sys.stdout.write(
        json.dumps(diagnosis.to_dict(), indent=2, ensure_ascii=False) + "\n" if args.as_json else render_text(diagnosis)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
