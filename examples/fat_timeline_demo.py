"""Runnable FAT/exFAT forensic timeline demonstration.

Run with the project virtualenv::

    .venv/bin/python examples/fat_timeline_demo.py

The records below are synthetic directory-entry fields. Each decoded timestamp keeps its raw
value, granularity and timezone evidence; ordering is derived from UTC intervals rather than a
naive wall clock.
"""
from __future__ import annotations

from dissect.fat.timestamps import (
    ForensicTimestamp,
    TimeKind,
    TimezonePolicy,
    decode_exfat,
    decode_fat,
    ordering,
)


def fat_date(year: int, month: int, day: int) -> int:
    return ((year - 1980) << 9) | (month << 5) | day


def fat_time(hour: int, minute: int, second: int) -> int:
    return (hour << 11) | (minute << 5) | (second // 2)


def exfat_pack(year: int, month: int, day: int, hour: int, minute: int, second: int) -> int:
    return ((year - 1980) << 25) | (month << 21) | (day << 16) | (hour << 11) | (minute << 5) | (second // 2)


def section(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def show(record: ForensicTimestamp) -> None:
    print(record.describe())
    print(f"    raw={record.raw} precision={record.precision} filesystem={record.filesystem.value}")


def compare(label_a: str, a: ForensicTimestamp, label_b: str, b: ForensicTimestamp) -> None:
    result, reason = ordering(a, b)
    print(f"  {label_a}  vs  {label_b}: {result.value.upper()} -- {reason}")


def main() -> None:
    section("1. Raw decoding: FAT has no timezone; access is date-only")

    # FAT created: 2024-03-05 10:20:40 local, 25 centiseconds
    fat_created = decode_fat(
        TimeKind.CREATED, fat_date(2024, 3, 5), fat_time(10, 20, 40), tenths=25
    )
    # FAT last-access: only a date field is on disk
    fat_access = decode_fat(TimeKind.ACCESSED, fat_date(2024, 3, 5))
    # FAT modified with all-zero fields -> missing, NOT 1980
    fat_missing = decode_fat(TimeKind.MODIFIED, 0, 0)
    show(fat_created)
    show(fat_access)
    show(fat_missing)

    section("2. exFAT: per-field UTC offset valid bits differ, two driver conventions")

    packed = exfat_pack(2024, 3, 5, 10, 20, 40)
    # Same local wall time, but only the created offset valid bit is set.
    ex_created = decode_exfat(TimeKind.CREATED, packed, 0xE0, centiseconds=25)
    ex_modified = decode_exfat(TimeKind.MODIFIED, packed, 0x00, centiseconds=25)
    ex_access = decode_exfat(TimeKind.ACCESSED, packed, 0x00)
    show(ex_created)
    show(ex_modified)
    show(ex_access)

    print("\n  Same raw byte 0xA0 under the two driver conventions:")
    show(decode_exfat(TimeKind.MODIFIED, packed, 0xA0, centiseconds=25, policy=TimezonePolicy.SPEC))
    show(decode_exfat(TimeKind.MODIFIED, packed, 0xA0, centiseconds=25, policy=TimezonePolicy.LINUX))

    section("3. Two records that LOOK strictly ordered but are NOT determinable")

    # Record A: FAT modified, local 2024-03-05 10:20:40, timezone unknown.
    record_a = decode_fat(TimeKind.MODIFIED, fat_date(2024, 3, 5), fat_time(10, 20, 40))
    # Record B: FAT modified one minute later on the same wall clock, timezone unknown.
    record_b = decode_fat(TimeKind.MODIFIED, fat_date(2024, 3, 5), fat_time(10, 21, 40))
    show(record_a)
    show(record_b)
    print("  A could be UTC+14 while B is UTC-12, a 26h swing that swallows the 1 minute gap:")
    compare("A(10:20:40)", record_a, "B(10:21:40)", record_b)

    section("4. A second indeterminate pair: FAT date-only access vs a precise modified time")

    precise = decode_fat(TimeKind.MODIFIED, fat_date(2024, 3, 5), fat_time(12, 0, 0))
    date_only = decode_fat(TimeKind.ACCESSED, fat_date(2024, 3, 5))
    show(precise)
    show(date_only)
    compare("modified 12:00", precise, "access date 03-05", date_only)

    section("5. A pair whose order IS determinable (exFAT valid offsets, wide gap)")

    early = decode_exfat(
        TimeKind.MODIFIED,
        exfat_pack(2024, 3, 1, 9, 0, 0),
        0xE0,  # UTC+8 under spec convention
        centiseconds=0,
    )
    later = decode_exfat(
        TimeKind.MODIFIED,
        exfat_pack(2024, 3, 1, 9, 30, 0),
        0xE0,
        centiseconds=0,
    )
    show(early)
    show(later)
    compare("09:00", early, "09:30", later)

    section("6. Missing values must never become real 1980 events in a report")

    for missing in (
        decode_fat(TimeKind.CREATED, 0, 0),
        decode_exfat(TimeKind.CREATED, 0, 0x00),
    ):
        line = missing.describe()
        assert "MISSING" in line and "1980-01-01T00:00:00" not in line
        print(f"  {missing.filesystem.value:>5} {line}")

    print("\nAll assertions passed.")


if __name__ == "__main__":
    main()
