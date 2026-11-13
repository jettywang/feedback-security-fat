from __future__ import annotations

import datetime

import pytest

from dissect.fat.exfat import ExFAT, forensic_timestamps
from dissect.fat.timestamps import (
    Ordering,
    TimeKind,
    TimezonePolicy,
    decode_exfat,
    decode_exfat_timezone,
    decode_fat,
    ordering,
)


def fat_date(year: int, month: int, day: int) -> int:
    return ((year - 1980) << 9) | (month << 5) | day


def fat_time(hour: int, minute: int, second: int) -> int:
    return (hour << 11) | (minute << 5) | (second // 2)


def exfat_pack(year: int, month: int, day: int, hour: int, minute: int, second: int) -> int:
    return ((year - 1980) << 25) | (month << 21) | (day << 16) | (hour << 11) | (minute << 5) | (second // 2)


def test_fat_missing_is_not_1980() -> None:
    missing = decode_fat(TimeKind.MODIFIED, 0, 0)

    assert missing.is_missing
    assert missing.local is None
    assert missing.utc_point is None
    assert missing.interval is None
    assert "MISSING" in missing.describe()
    assert "1980-01-01T00:00:00" not in missing.describe()


def test_fat_access_is_date_only() -> None:
    access = decode_fat(TimeKind.ACCESSED, fat_date(2024, 3, 5))

    assert access.present
    assert access.precision == datetime.timedelta(days=1)
    assert access.local == datetime.datetime(2024, 3, 5)  # noqa: DTZ001
    assert access.timezone.offset_minutes is None
    earliest, latest = access.interval  # type: ignore[misc]
    assert earliest == datetime.datetime(2024, 3, 4, 10, tzinfo=datetime.timezone.utc)
    assert latest == datetime.datetime(2024, 3, 6, 12, tzinfo=datetime.timezone.utc)


def test_fat_created_precision_and_unknown_offset() -> None:
    created = decode_fat(TimeKind.CREATED, fat_date(2024, 3, 5), fat_time(10, 20, 40), tenths=25)

    assert created.precision == datetime.timedelta(milliseconds=10)
    assert created.local == datetime.datetime(2024, 3, 5, 10, 20, 40, 250000)  # noqa: DTZ001
    assert created.utc_point is None
    earliest, latest = created.interval  # type: ignore[misc]
    assert earliest.tzinfo is datetime.timezone.utc
    assert earliest < created.local.replace(tzinfo=datetime.timezone.utc) < latest


def test_exfat_missing_packed_timestamp() -> None:
    missing = decode_exfat(TimeKind.CREATED, 0, 0x00)

    assert missing.is_missing
    assert missing.local is None
    assert "MISSING" in missing.describe()


def test_exfat_timezone_validity_bit() -> None:
    invalid = decode_exfat_timezone(0x00)
    assert not invalid.valid
    assert invalid.offset_minutes is None

    valid = decode_exfat_timezone(0xE0)
    assert valid.valid
    assert valid.offset_minutes == 8 * 60


@pytest.mark.parametrize(
    ("byte", "spec_minutes", "linux_minutes"),
    [
        (0x80, -16 * 60, 0),
        (0x88, -14 * 60, 2 * 60),
        (0xA0, -8 * 60, 8 * 60),
        (0xE0, 8 * 60, -8 * 60),
        (0xFB, 14 * 60 + 45, -75),
    ],
)
def test_exfat_two_driver_conventions(byte: int, spec_minutes: int, linux_minutes: int) -> None:
    spec = decode_exfat_timezone(byte, TimezonePolicy.SPEC)
    linux = decode_exfat_timezone(byte, TimezonePolicy.LINUX)

    assert spec.offset_minutes == spec_minutes
    assert linux.offset_minutes == linux_minutes
    assert linux_minutes in spec.alternative_offsets
    assert spec_minutes in linux.alternative_offsets


def test_exfat_known_offset_gives_utc_point_and_tight_interval() -> None:
    packed = exfat_pack(2024, 3, 5, 10, 20, 40)
    created = decode_exfat(TimeKind.CREATED, packed, 0xE0, centiseconds=25)

    assert created.timezone.offset_minutes == 8 * 60
    assert created.utc_point == datetime.datetime(2024, 3, 5, 2, 20, 40, 250000)  # noqa: DTZ001
    earliest, latest = created.interval  # type: ignore[misc]
    assert latest - earliest == datetime.timedelta(milliseconds=10)


def test_exfat_accessed_has_two_second_precision() -> None:
    packed = exfat_pack(2024, 3, 5, 10, 20, 40)
    accessed = decode_exfat(TimeKind.ACCESSED, packed, 0x00)

    assert accessed.precision == datetime.timedelta(seconds=2)
    assert "centiseconds" not in accessed.raw


def test_exfat_per_field_validity_bits_differ() -> None:
    packed = exfat_pack(2024, 3, 5, 10, 20, 40)
    created = decode_exfat(TimeKind.CREATED, packed, 0xE0, centiseconds=0)
    modified = decode_exfat(TimeKind.MODIFIED, packed, 0x00, centiseconds=0)

    assert created.utc_point is not None
    assert modified.utc_point is None
    assert modified.interval is not None


def test_ordering_indeterminate_when_offsets_unknown() -> None:
    first = decode_fat(TimeKind.MODIFIED, fat_date(2024, 3, 5), fat_time(10, 20, 40))
    second = decode_fat(TimeKind.MODIFIED, fat_date(2024, 3, 5), fat_time(10, 21, 40))

    result, reason = ordering(first, second)

    assert result is Ordering.INDETERMINATE
    assert "overlap" in reason


def test_ordering_indeterminate_date_only_vs_precise() -> None:
    precise = decode_fat(TimeKind.MODIFIED, fat_date(2024, 3, 5), fat_time(12, 0, 0))
    date_only = decode_fat(TimeKind.ACCESSED, fat_date(2024, 3, 5))

    assert ordering(precise, date_only)[0] is Ordering.INDETERMINATE


def test_ordering_determinable_with_known_offsets() -> None:
    early = decode_exfat(TimeKind.MODIFIED, exfat_pack(2024, 3, 1, 9, 0, 0), 0xE0)
    later = decode_exfat(TimeKind.MODIFIED, exfat_pack(2024, 3, 1, 9, 30, 0), 0xE0)

    assert ordering(early, later)[0] is Ordering.BEFORE
    assert ordering(later, early)[0] is Ordering.AFTER


def test_ordering_missing_never_orders() -> None:
    present = decode_fat(TimeKind.MODIFIED, fat_date(2024, 3, 5), fat_time(10, 0, 0))
    missing = decode_fat(TimeKind.CREATED, 0, 0)

    assert ordering(present, missing)[0] is Ordering.INDETERMINATE


def test_legacy_utc_timezone_preserves_bias_zero_behaviour() -> None:
    assert ExFAT._utc_timezone(0x00) == {"name": "localtime", "offset": 0}
    assert ExFAT._utc_timezone(0x88) == {"name": "UTC+02:00", "offset": 120}
    assert ExFAT._utc_timezone(0xA0) == {"name": "UTC+08:00", "offset": 480}


def test_exfat_helper_on_real_image(exfat_simple) -> None:  # type: ignore[no-untyped-def]
    parsed = ExFAT(exfat_simple)
    file_entry = parsed.files["/"][1]["find_me.txt"][0]
    timestamps = forensic_timestamps(file_entry, TimezonePolicy.LINUX)

    created = timestamps[TimeKind.CREATED]
    assert created.present
    assert created.timezone.offset_minutes == 120
    assert created.utc_point == datetime.datetime(2019, 4, 17, 8, 56, 18, 30000)  # noqa: DTZ001
    assert timestamps[TimeKind.ACCESSED].precision == datetime.timedelta(seconds=2)
