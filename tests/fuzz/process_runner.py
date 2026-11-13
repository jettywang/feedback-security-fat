"""Process-boundary driver and deliberately unguarded control walker.

Two independent mechanisms need a hard process boundary:

* :mod:`tests.fuzz.bounded_walker` enforces budgets inside the test process and
  cannot be killed by a sample. It is the fast regression oracle.
* The *real* :class:`dissect.fat.exfat.ExFAT` parser and an explicitly
  **unbounded control walker** have no termination guards. Running them in a
  subprocess with a wall-clock timeout turns an otherwise infinite expansion
  into a clean, observable timeout instead of hanging the test suite.

The control walker is the required negative control: it parses exactly the same
directory semantics as the bounded walker but with the visited-set, FAT
back-edge and budget checks removed. On a back-edge image it never terminates,
proving the bounded walker's guards are what makes the difference.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import sys
from dataclasses import dataclass
from enum import Enum

from tests.fuzz.bounded_walker import (
    ATTRIBUTE_DIRECTORY,
    DIR_ENTRY_SIZE,
    EOC,
    FILE_ENTRY_INUSE,
    FILENAME_ENTRY_INUSE,
    STREAM_ENTRY_INUSE,
)

DEFAULT_TIMEOUT = 5.0


class ProcessResult(str, Enum):
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    CRASHED = "crashed"


@dataclass
class RunResult:
    result: ProcessResult
    detail: str = ""

    def as_dict(self) -> dict:
        return {"result": self.result.value, "detail": self.detail}


def _worker(image: bytes, mode: str, queue: mp.Queue) -> None:
    try:
        if mode == "real-parser":
            import io

            from dissect.fat.exfat import ExFAT

            ExFAT(io.BytesIO(image))
        elif mode == "control-walker":
            _unbounded_control_walk(image)
        elif mode == "bounded-walker":
            from tests.fuzz.bounded_walker import classify

            classify(image)
        else:  # pragma: no cover - defensive
            raise ValueError(f"unknown mode {mode}")
        queue.put({"result": ProcessResult.COMPLETED.value, "detail": ""})
    except RecursionError as exc:
        # The production parser recurses and hits Python's recursion limit on a
        # directory back-edge; that is still a loss of termination, not a clean
        # parse, so surface it as a crash rather than a success.
        queue.put({"result": ProcessResult.CRASHED.value, "detail": f"RecursionError: {exc}"})
    except Exception as exc:  # noqa: BLE001 - any parse error means it terminated
        queue.put({"result": ProcessResult.CRASHED.value, "detail": f"{type(exc).__name__}: {exc}"})


def run_in_subprocess(image: bytes, mode: str, timeout: float = DEFAULT_TIMEOUT) -> RunResult:
    # "fork" keeps the worker self-contained: "spawn" re-imports the caller's
    # __main__ module, which does not exist for pytest / stdin driven runs.
    ctx = mp.get_context("fork")
    queue = ctx.Queue()
    proc = ctx.Process(target=_worker, args=(image, mode, queue))
    proc.start()
    proc.join(timeout)
    if proc.is_alive():
        proc.terminate()
        proc.join()
        return RunResult(ProcessResult.TIMEOUT, f"mode {mode} exceeded {timeout}s")
    if queue.empty():
        return RunResult(ProcessResult.CRASHED, "worker exited without a result")
    payload = queue.get_nowait()
    return RunResult(ProcessResult(payload["result"]), payload["detail"])


def _unbounded_control_walk(image: bytes) -> None:
    """Same semantics as the bounded walker, but with every guard removed.

    No FAT seen-set, no directory visited-set, no depth/entry/byte budgets: a
    back-edge makes this loop or recurse forever. This is the negative control
    demonstrating that the bounded walker's checks are load-bearing.
    """
    import struct

    sector_size = 1 << image[0x6C]
    sectors_per_cluster = 1 << image[0x6D]
    cluster_size = sector_size * sectors_per_cluster
    fat_base = struct.unpack_from("<I", image, 0x50)[0] * sector_size
    heap_sector = struct.unpack_from("<I", image, 0x58)[0]
    cluster_count = struct.unpack_from("<I", image, 0x5C)[0]
    root_cluster = struct.unpack_from("<I", image, 0x60)[0]
    max_cluster = cluster_count + 2

    def cluster_offset(cluster: int) -> int:
        return (heap_sector + (cluster - 2) * sectors_per_cluster) * sector_size

    def resolve_chain(start: int) -> list[int]:
        # Deliberately no seen-set: a FAT self/back-edge never reaches EOC.
        chain = []
        cluster = start
        while cluster != EOC:
            if not (2 <= cluster < max_cluster):
                raise ValueError(f"invalid cluster {cluster}")
            chain.append(cluster)
            cluster = struct.unpack_from("<I", image, fat_base + cluster * 4)[0]
        return chain

    def entry_sets(raw: bytes) -> list[tuple[bool, int, bool]]:
        found = []
        offset = 0
        while offset + DIR_ENTRY_SIZE <= len(raw):
            if raw[offset] != FILE_ENTRY_INUSE:
                offset += DIR_ENTRY_SIZE
                continue
            subentry_count = raw[offset + 0x01]
            stream_offset = offset + DIR_ENTRY_SIZE
            fn_end = stream_offset + subentry_count * DIR_ENTRY_SIZE
            if raw[stream_offset] != STREAM_ENTRY_INUSE:
                offset += DIR_ENTRY_SIZE
                continue
            for idx in range(subentry_count - 1):
                if raw[stream_offset + (1 + idx) * DIR_ENTRY_SIZE] != FILENAME_ENTRY_INUSE:
                    break
            attributes = struct.unpack_from("<H", raw, offset + 0x04)[0]
            location = struct.unpack_from("<I", raw, stream_offset + 0x14)[0]
            not_fragmented = bool(raw[stream_offset + 0x01] & 0x02)
            found.append((bool(attributes & ATTRIBUTE_DIRECTORY), location, not_fragmented))
            offset = fn_end
        return found

    def walk_directory(location: int, not_fragmented: bool) -> None:
        # Deliberately recursive with no visited-set: directory back-edges never
        # terminate (and blow the recursion stack, another loss of control).
        if not_fragmented:
            raw = image[cluster_offset(location) : cluster_offset(location) + cluster_size]
        else:
            chain = resolve_chain(location)
            raw = b"".join(image[cluster_offset(c) : cluster_offset(c) + cluster_size] for c in chain)
        for is_directory, child_location, child_not_fragmented in entry_sets(raw):
            if is_directory:
                walk_directory(child_location, child_not_fragmented)

    walk_directory(root_cluster, False)


def _main() -> int:
    parser = argparse.ArgumentParser(description="exFAT fuzz process-boundary worker")
    parser.add_argument("image", help="path to a generated exFAT image")
    parser.add_argument("--mode", choices=["real-parser", "control-walker", "bounded-walker"], required=True)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    args = parser.parse_args()
    with open(args.image, "rb") as fh:
        image = fh.read()
    result = run_in_subprocess(image, args.mode, args.timeout)
    print(json.dumps(result.as_dict()))
    return 0 if result.result == ProcessResult.COMPLETED else 2


if __name__ == "__main__":  # pragma: no cover - CLI shim
    sys.exit(_main())
