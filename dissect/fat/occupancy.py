"""Read-only FAT cluster occupancy analysis.

This module builds a relationship graph between directory objects (files and
directories) and the clusters that hold their data. It is strictly read-only:
it never writes to the FAT, the directory entries or the data region.

The graph is used to answer forensic questions that a single
"file system is corrupted" flag cannot answer:

- which clusters are claimed by more than one directory object ("cross-linked"
  files), including the exact logical byte range each object maps to that
  cluster and where the first collision happens;
- where two cross-linked chains merge into a single shared chain tail;
- which allocated clusters have no active directory reference ("orphans");
- why a cluster chain terminates early: end of chain, a cycle, a bad cluster,
  a free cluster encountered mid-chain, or an out of range FAT pointer.

The special ``.`` and ``..`` directory entries are aliases of directories that
are already reachable through the tree, so they are recorded as alias edges and
are never counted as independent files.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from io import RawIOBase
from typing import TYPE_CHECKING

from dissect.util.stream import RangeStream, RunlistStream

from dissect.fat.c_fat import (
    BAD_CLUSTER,
    DATA_CLUSTER_MAX,
    DATA_CLUSTER_MIN,
    END_OF_CLUSTER_MAX,
    END_OF_CLUSTER_MIN,
    FAT12_EOC,
    FREE_CLUSTER,
)
from dissect.fat.exceptions import (
    EmptyDirectoryError,
    InvalidDirectoryError,
    LastEmptyDirectoryError,
)
from dissect.fat.fat import _iter_dirent, mask

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.fat.fat import FATFS, DirectoryEntry, RootDirectory

__all__ = [
    "Alias",
    "ByteRange",
    "ClusterInfo",
    "Conflict",
    "Edge",
    "EdgeType",
    "OccupancyGraph",
    "Occupant",
    "OrphanChain",
    "Reference",
    "Termination",
    "TerminationReason",
    "analyze",
]


class TerminationReason(str, Enum):
    """Reason why traversal of a cluster chain stopped."""

    END_OF_CHAIN = "end_of_chain"
    CYCLE = "cycle"
    BAD_CLUSTER = "bad_cluster"
    FREE_CLUSTER = "free_cluster"
    OUT_OF_RANGE = "out_of_range"
    EMPTY = "empty"


class EdgeType(str, Enum):
    """Kind of relationship represented by an :class:`Edge`."""

    DIRECTORY_EDGE = "directory_edge"
    ALIAS_EDGE = "alias_edge"
    CHAIN_EDGE = "chain_edge"
    TERMINATION_EDGE = "termination_edge"


@dataclass(frozen=True)
class Termination:
    """How and where a chain traversal ended.

    Args:
        reason: The reason traversal stopped.
        at: The cluster at which traversal stopped, or ``None`` when the chain
            was empty (a zero-length file or a directory with no first
            cluster).
        value: The raw FAT entry value that caused the termination, if any.
    """

    reason: TerminationReason
    at: int | None
    value: int | None = None


@dataclass(frozen=True)
class Reference:
    """A single active reference from an occupant to one of its clusters.

    Args:
        occupant_id: Identifier of the referencing occupant.
        path: Path of the referencing directory object.
        cluster: Referenced cluster number.
        logical_index: Zero-based position of the cluster in the object's
            chain, used to derive the mapped logical byte range.
    """

    occupant_id: int
    path: str
    cluster: int
    logical_index: int


@dataclass(frozen=True)
class ByteRange:
    """Logical byte range an occupant maps onto a cluster.

    ``end`` is exclusive and is clamped to the occupant's declared size, so the
    reported range never extends past the end of a file.

    Args:
        start: First logical byte offset (inclusive).
        end: Last logical byte offset (exclusive), clamped to the size.
        clamped: Whether ``end`` was clamped to the occupant's size.
    """

    start: int
    end: int
    clamped: bool


@dataclass(frozen=True)
class Occupant:
    """A directory object that owns a cluster chain.

    Args:
        id: Stable internal identifier of the occupant.
        path: Full path, with the volume root represented as an empty string.
        name: Base name of the directory object.
        is_directory: Whether the object is a directory.
        size: Declared size in bytes (directories report their chain size).
        first_cluster: First cluster of the chain, or ``None`` when empty.
        cluster_chain: Clusters reached while walking the chain.
        ranges: Logical byte range mapped to every cluster in ``cluster_chain``.
        termination: How the chain walk ended.
    """

    id: int
    path: str
    name: str
    is_directory: bool
    size: int
    first_cluster: int | None
    cluster_chain: list[int]
    ranges: list[ByteRange]
    termination: Termination


@dataclass(frozen=True)
class Alias:
    """A ``.`` or ``..`` directory entry.

    Aliases point at a directory that is also reachable through the real tree,
    so they are recorded separately and never counted as an independent file.

    Args:
        name: Either ``.`` or ``..``.
        parent_path: Path of the directory containing the alias entry.
        target_cluster: First cluster the alias points at, if any.
    """

    name: str
    parent_path: str
    target_cluster: int | None


@dataclass(frozen=True)
class Edge:
    """A directed relationship in the occupancy graph.

    Args:
        type: Kind of the edge.
        source: Source node identifier (a path or ``cluster:<n>``).
        target: Target node identifier (a path or ``cluster:<n>``).
        detail: Optional payload, such as a :class:`Reference` or
            :class:`Termination`.
    """

    type: EdgeType
    source: str
    target: str
    detail: Reference | Termination | None = None


@dataclass
class ClusterInfo:
    """Everything known about a single cluster.

    Args:
        cluster: Cluster number.
        allocated: Whether the FAT marks the cluster as allocated.
        fat_value: Raw value stored in the FAT entry.
        references: Active directory references pointing at the cluster.
    """

    cluster: int
    allocated: bool
    fat_value: int | None
    references: list[Reference] = field(default_factory=list)

    @property
    def is_shared(self) -> bool:
        """Whether more than one distinct occupant references the cluster."""
        return len({ref.occupant_id for ref in self.references}) > 1

    @property
    def is_orphan(self) -> bool:
        """Whether the cluster is allocated without any active reference."""
        return self.allocated and not self.references


@dataclass(frozen=True)
class Conflict:
    """A group of occupants cross-linked through one or more shared clusters.

    Args:
        occupant_ids: Identifiers of every occupant tied together by a shared
            cluster.
        shared_clusters: Clusters referenced by more than one occupant, in
            ascending cluster order.
        first_conflict: First shared cluster reached by any of the chains.
        shared_tail: Longest common cluster suffix of the involved chains,
            i.e. the shared chain tail after the merge point.
        ranges: For every shared cluster, the byte range each occupant maps to
            it, keyed by cluster number.
    """

    occupant_ids: tuple[int, ...]
    shared_clusters: tuple[int, ...]
    first_conflict: int
    shared_tail: tuple[int, ...]
    ranges: dict[int, dict[int, ByteRange]]


@dataclass(frozen=True)
class OrphanChain:
    """A run of allocated clusters without any active directory reference.

    Args:
        clusters: Clusters that make up the orphan chain, in walk order.
        termination: How the orphan chain walk ended.
    """

    clusters: tuple[int, ...]
    termination: Termination


class OccupancyGraph:
    """Read-only relationship graph between directory objects and clusters.

    Build the graph with :func:`analyze` and inspect it through the data
    structures and helper methods below. Nothing in this class mutates the
    underlying image.
    """

    def __init__(self, fs: FATFS):
        self.fs = fs
        self.cluster_size = fs.cluster_size

        self.occupants: dict[int, Occupant] = {}
        self.aliases: list[Alias] = []
        self.clusters: dict[int, ClusterInfo] = {}
        self.edges: list[Edge] = []
        self.conflicts: list[Conflict] = []
        self.orphans: list[OrphanChain] = []

        self._next_occupant_id = 0
        self._visited_directories: set[int] = set()

        self._walk_directory_tree(fs.root)
        self._scan_fat()
        self._build_conflicts()
        self._build_orphans()

    def occupant(self, occupant_id: int) -> Occupant:
        """Return the occupant with the given identifier.

        Args:
            occupant_id: Identifier returned on a :class:`Reference`.

        Returns:
            The matching occupant.

        Raises:
            KeyError: If the identifier is unknown.
        """
        return self.occupants[occupant_id]

    def shared_clusters(self) -> list[ClusterInfo]:
        """Return every cluster referenced by more than one occupant."""
        return [info for info in self.clusters.values() if info.is_shared]

    def orphan_clusters(self) -> list[ClusterInfo]:
        """Return every allocated cluster without an active directory reference."""
        return [info for info in self.clusters.values() if info.is_orphan]

    def range_for(self, occupant_id: int, cluster: int) -> ByteRange:
        """Return the logical byte range an occupant maps onto a cluster.

        Args:
            occupant_id: Identifier of the occupant.
            cluster: Cluster referenced by that occupant.

        Returns:
            The mapped byte range.

        Raises:
            KeyError: If the occupant does not reference the cluster.
        """
        occupant = self.occupants[occupant_id]
        for chain_cluster, byte_range in zip(occupant.cluster_chain, occupant.ranges, strict=True):
            if chain_cluster == cluster:
                return byte_range
        raise KeyError(f"Occupant {occupant_id} does not reference cluster {cluster}")

    def to_text(self) -> str:
        """Render a human-readable report that pinpoints each anomaly."""
        lines: list[str] = []

        lines.append(f"FAT occupancy graph for {self.fs.type.name} volume {self.fs.volume_label!r}")
        lines.append(
            f"Occupants: {len(self.occupants)}, aliases: {len(self.aliases)}, "
            f"clusters tracked: {len(self.clusters)}"
        )
        lines.append("")

        if self.conflicts:
            lines.append("Cross-linked clusters:")
            for conflict in self.conflicts:
                paths = ", ".join(self.occupants[oid].path or "\\" for oid in conflict.occupant_ids)
                lines.append(f"  first conflict at cluster {conflict.first_conflict} between: {paths}")
                lines.append(f"  shared chain tail: {_fmt_chain(conflict.shared_tail)}")
                for cluster in conflict.shared_clusters:
                    lines.append(f"  cluster {cluster}:")
                    for oid in conflict.occupant_ids:
                        byte_range = conflict.ranges[cluster].get(oid)
                        if byte_range is None:
                            continue
                        note = " (clamped to size)" if byte_range.clamped else ""
                        lines.append(
                            f"    - {self.occupants[oid].path or '\\'} bytes "
                            f"[{byte_range.start}, {byte_range.end}){note}"
                        )
        else:
            lines.append("Cross-linked clusters: none")
        lines.append("")

        if self.orphans:
            lines.append("Allocated clusters without an active directory reference:")
            for orphan in self.orphans:
                lines.append(
                    f"  chain {_fmt_chain(orphan.clusters)} terminated: {_fmt_termination(orphan.termination)}"
                )
        else:
            lines.append("Allocated clusters without an active directory reference: none")
        lines.append("")

        lines.append("Chain terminations:")
        for occupant in self.occupants.values():
            lines.append(f"  {occupant.path or '\\'}: {_fmt_termination(occupant.termination)}")

        return "\n".join(lines)

    def _walk_directory_tree(self, root: RootDirectory) -> None:
        """Register the root and every object reachable from it, cycle safe."""
        pending: list[DirectoryEntry | RootDirectory] = [root]

        while pending:
            directory = pending.pop(0)
            directory_key = directory.cluster if directory.cluster is not None else -1
            if directory_key in self._visited_directories:
                continue
            self._visited_directories.add(directory_key)

            self._register_occupant(directory)

            try:
                children = list(self._iter_directory_children(directory))
            except (EmptyDirectoryError, LastEmptyDirectoryError, InvalidDirectoryError, EOFError):
                continue

            for child in children:
                if child.is_volume_id():
                    continue

                if child.short_name in (".", ".."):
                    self._register_alias(directory, child)
                    continue

                self.edges.append(Edge(EdgeType.DIRECTORY_EDGE, _node_path(directory), _node_path(child)))

                if child.is_directory():
                    child_key = child.cluster if child.cluster != FREE_CLUSTER else -1
                    if child_key not in self._visited_directories:
                        pending.append(child)
                else:
                    self._register_occupant(child)

    def _iter_directory_children(
        self, directory: DirectoryEntry | RootDirectory
    ) -> Iterator[DirectoryEntry]:
        """Yield directory entries without trusting the library chain walker.

        The built-in walker follows FAT pointers blindly and never terminates on
        a cyclic chain. Reading through a runlist built from our own, cycle-safe
        chain keeps traversal bounded; the declared size is only used to cap the
        read and never to decide which clusters to follow.
        """
        stream = self._safe_directory_stream(directory)
        if stream is None:
            return

        yield from _iter_dirent(self.fs, stream, directory)

    def _safe_directory_stream(
        self, directory: DirectoryEntry | RootDirectory
    ) -> RawIOBase | None:
        """Open a directory stream backed by our defensive cluster walk."""
        cluster = directory.cluster
        if cluster is None:
            # FAT12/FAT16 root directory lives in a fixed, chain-free region.
            return RangeStream(
                self.fs.fh,
                self.fs.first_data_sector * self.fs.sector_size - self.fs.bpb.BPB_RootEntCnt * 32,
                self.fs.bpb.BPB_RootEntCnt * 32,
            )

        if cluster == FREE_CLUSTER:
            return None

        chain, _ = self._walk_chain(cluster)
        if not chain:
            return None

        runlist = [(cluster_number - DATA_CLUSTER_MIN, 1) for cluster_number in chain]
        size = len(chain) * self.cluster_size
        return RunlistStream(self.fs.data_stream, runlist, size, self.cluster_size)

    def _declared_size(self, entry: DirectoryEntry | RootDirectory, chain: list[int]) -> int:
        """Return the object size without invoking the non-cycle-safe walker."""
        if entry.is_directory():
            return len(chain) * self.cluster_size
        return entry.dirent.DIR_FileSize

    def _register_alias(self, parent: DirectoryEntry | RootDirectory, child: DirectoryEntry) -> None:
        """Record a ``.`` or ``..`` entry without counting it as a file."""
        target_cluster = child.cluster if child.cluster != FREE_CLUSTER else None
        self.aliases.append(Alias(name=child.short_name, parent_path=parent.path, target_cluster=target_cluster))
        target = f"cluster:{target_cluster}" if target_cluster is not None else _node_path(parent)
        self.edges.append(Edge(EdgeType.ALIAS_EDGE, _node_path(parent), target))

    def _register_occupant(self, entry: DirectoryEntry | RootDirectory) -> int:
        """Create an occupant, walk its chain and record every reference."""
        occupant_id = self._next_occupant_id
        self._next_occupant_id += 1

        first_cluster = entry.cluster if entry.cluster not in (None, FREE_CLUSTER) else None
        chain, termination = self._walk_chain(first_cluster)
        size = self._declared_size(entry, chain)
        ranges = [_byte_range(index, self.cluster_size, size) for index in range(len(chain))]

        occupant = Occupant(
            id=occupant_id,
            path=entry.path,
            name=entry.name,
            is_directory=entry.is_directory(),
            size=size,
            first_cluster=first_cluster,
            cluster_chain=chain,
            ranges=ranges,
            termination=termination,
        )
        self.occupants[occupant_id] = occupant

        node = _node_path(entry)
        for index, cluster in enumerate(chain):
            reference = Reference(
                occupant_id=occupant_id,
                path=entry.path,
                cluster=cluster,
                logical_index=index,
            )
            self._ensure_cluster(cluster).references.append(reference)
            self.edges.append(Edge(EdgeType.CHAIN_EDGE, node, f"cluster:{cluster}", reference))

        if termination.at is not None and DATA_CLUSTER_MIN <= termination.at < self.fs.fat.entry_count:
            self._ensure_cluster(termination.at)
        self.edges.append(
            Edge(
                EdgeType.TERMINATION_EDGE,
                node,
                f"cluster:{termination.at}" if termination.at is not None else node,
                termination,
            )
        )

        return occupant_id

    def _walk_chain(self, first_cluster: int | None) -> tuple[list[int], Termination]:
        """Walk a FAT chain defensively, returning reached clusters and reason."""
        if first_cluster is None:
            return [], Termination(TerminationReason.EMPTY, None)

        bits = self.fs.fat.bits_per_entry
        chain: list[int] = []
        seen: set[int] = set()
        cluster = first_cluster

        while True:
            if cluster in seen:
                return chain, Termination(TerminationReason.CYCLE, cluster)
            seen.add(cluster)

            if not DATA_CLUSTER_MIN <= cluster < self.fs.fat.entry_count:
                return chain, Termination(TerminationReason.OUT_OF_RANGE, cluster, cluster)

            value = self._fat_get(cluster)
            if value is None:
                return chain, Termination(TerminationReason.OUT_OF_RANGE, cluster)

            chain.append(cluster)

            if value == mask(BAD_CLUSTER, bits):
                return chain, Termination(TerminationReason.BAD_CLUSTER, cluster, value)

            if value == FREE_CLUSTER:
                return chain, Termination(TerminationReason.FREE_CLUSTER, cluster, value)

            if self._is_eoc(value, bits):
                return chain, Termination(TerminationReason.END_OF_CHAIN, cluster, value)

            if not DATA_CLUSTER_MIN <= value <= mask(DATA_CLUSTER_MAX, bits):
                return chain, Termination(TerminationReason.OUT_OF_RANGE, value, value)

            cluster = value

    def _fat_get(self, cluster: int) -> int | None:
        """Read a FAT entry, returning ``None`` when the entry is unreadable."""
        try:
            return self.fs.fat.get(cluster)
        except ValueError:
            return None

    @staticmethod
    def _is_eoc(value: int, bits: int) -> bool:
        if bits == 12 and value == FAT12_EOC:
            return True
        return mask(END_OF_CLUSTER_MIN, bits) <= value <= mask(END_OF_CLUSTER_MAX, bits)

    def _scan_fat(self) -> None:
        """Mark allocation state for every data cluster described by the FAT."""
        bits = self.fs.fat.bits_per_entry
        for cluster in range(DATA_CLUSTER_MIN, self.fs.fat.entry_count):
            value = self._fat_get(cluster)
            info = self._ensure_cluster(cluster)
            info.fat_value = value
            info.allocated = value is not None and not self._is_free_or_bad(value, bits)

    @staticmethod
    def _is_free_or_bad(value: int, bits: int) -> bool:
        return value == FREE_CLUSTER or value == mask(BAD_CLUSTER, bits)

    def _ensure_cluster(self, cluster: int) -> ClusterInfo:
        info = self.clusters.get(cluster)
        if info is None:
            info = ClusterInfo(cluster=cluster, allocated=False, fat_value=None)
            self.clusters[cluster] = info
        return info

    def _build_conflicts(self) -> None:
        """Group cross-linked occupants and locate first conflict and tail."""
        shared = sorted(
            (info for info in self.clusters.values() if info.is_shared),
            key=lambda info: info.cluster,
        )
        if not shared:
            return

        parent: dict[int, int] = {}

        def find(node: int) -> int:
            parent.setdefault(node, node)
            while parent[node] != node:
                parent[node] = parent[parent[node]]
                node = parent[node]
            return node

        def union(left: int, right: int) -> None:
            parent[find(left)] = find(right)

        for info in shared:
            occupant_ids = [ref.occupant_id for ref in info.references]
            for occupant_id in occupant_ids[1:]:
                union(occupant_ids[0], occupant_id)

        groups: dict[int, list[ClusterInfo]] = {}
        for info in shared:
            root = find(info.references[0].occupant_id)
            groups.setdefault(root, []).append(info)

        for group in groups.values():
            occupant_ids = tuple(sorted({ref.occupant_id for info in group for ref in info.references}))
            shared_clusters = tuple(info.cluster for info in group)
            first_conflict = self._first_conflict_cluster(group)
            chains = [self.occupants[oid].cluster_chain for oid in occupant_ids]

            ranges: dict[int, dict[int, ByteRange]] = {}
            for info in group:
                ranges[info.cluster] = {
                    ref.occupant_id: self.range_for(ref.occupant_id, info.cluster) for ref in info.references
                }

            self.conflicts.append(
                Conflict(
                    occupant_ids=occupant_ids,
                    shared_clusters=shared_clusters,
                    first_conflict=first_conflict,
                    shared_tail=tuple(_common_suffix(chains)),
                    ranges=ranges,
                )
            )

        self.conflicts.sort(key=lambda conflict: conflict.first_conflict)

    @staticmethod
    def _first_conflict_cluster(group: list[ClusterInfo]) -> int:
        def earliest(info: ClusterInfo) -> int:
            return min(ref.logical_index for ref in info.references)

        return min(group, key=earliest).cluster

    def _build_orphans(self) -> None:
        """Group allocated, unreferenced clusters into orphan chains."""
        pending = {cluster for cluster, info in self.clusters.items() if info.is_orphan}
        visited: set[int] = set()

        for start in sorted(pending):
            if start in visited:
                continue

            chain: list[int] = []
            cluster = start
            termination: Termination | None = None

            while cluster in pending and cluster not in visited:
                visited.add(cluster)
                chain.append(cluster)

                bits = self.fs.fat.bits_per_entry
                value = self._fat_get(cluster)
                if value is None:
                    termination = Termination(TerminationReason.OUT_OF_RANGE, cluster)
                    break
                if value == mask(BAD_CLUSTER, bits):
                    termination = Termination(TerminationReason.BAD_CLUSTER, cluster, value)
                    break
                if value == FREE_CLUSTER:
                    termination = Termination(TerminationReason.FREE_CLUSTER, cluster, value)
                    break
                if self._is_eoc(value, bits):
                    termination = Termination(TerminationReason.END_OF_CHAIN, cluster, value)
                    break
                if value in visited:
                    termination = Termination(TerminationReason.CYCLE, value, value)
                    break
                cluster = value

            if termination is None:
                termination = Termination(TerminationReason.CYCLE, cluster, self._fat_get(cluster))

            self.orphans.append(OrphanChain(clusters=tuple(chain), termination=termination))

        self.orphans.sort(key=lambda orphan: orphan.clusters[0])


def analyze(fs: FATFS) -> OccupancyGraph:
    """Build a read-only occupancy graph for a FAT file system.

    Args:
        fs: An opened :class:`~dissect.fat.fat.FATFS` image.

    Returns:
        The populated occupancy graph.
    """
    return OccupancyGraph(fs)


def _byte_range(logical_index: int, cluster_size: int, size: int) -> ByteRange:
    start = logical_index * cluster_size
    nominal_end = start + cluster_size
    return ByteRange(start=start, end=min(nominal_end, size), clamped=nominal_end > size)


def _common_suffix(chains: list[list[int]]) -> list[int]:
    suffix: list[int] = []
    for position in range(1, min((len(chain) for chain in chains), default=0) + 1):
        candidate = chains[0][-position]
        if any(chain[-position] != candidate for chain in chains):
            break
        suffix.append(candidate)
    suffix.reverse()
    return suffix


def _node_path(entry: DirectoryEntry | RootDirectory) -> str:
    return entry.path or "\\"


def _fmt_chain(chain: tuple[int, ...] | list[int]) -> str:
    return " -> ".join(str(cluster) for cluster in chain) if chain else "<empty>"


def _fmt_termination(termination: Termination) -> str:
    location = "empty chain" if termination.at is None else f"at cluster {termination.at}"
    value = "" if termination.value is None else f" (FAT value 0x{termination.value:x})"
    return f"{termination.reason.value} {location}{value}"
