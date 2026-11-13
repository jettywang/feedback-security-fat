# References:
# - Microsoft FAT: fatgen103.doc (MS-DOS Date/Time, no on-disk timezone)
# - Microsoft exFAT: [MS-XFS] ExFAT Timestamp / UTC Offset fields
# - The Sleuth Kit and relan/exfat exFAT timezone byte handling (bias-64)
# - Linux kernel exfat driver timezone handling (bias-0, signed 7-bit)
"""Forensic timestamp interpretation for FAT and exFAT.

The regular :mod:`dissect.fat` API returns naive :class:`datetime.datetime` objects and, for missing
values, a synthetic ``1980-01-01``. That is convenient for browsing but unsafe for timeline work:

* FAT stores **local wall time with no timezone anywhere on disk**.
* A FAT last-access timestamp carries a **date only** (no time of day).
* exFAT stores local wall time plus a separate UTC-offset byte per timestamp whose valid bit may be
  set on some fields and clear on others, even within the same directory entry.
* Two incompatible driver conventions exist for that byte (Microsoft/TSK bias-64 versus Linux
  bias-0), so the same raw byte can decode to different offsets.
* A zero field means *the timestamp is absent*; it must never be reported as a real event on
  1980-01-01.

This module never silently converts to a single instant. It returns a :class:`ForensicTimestamp`
that keeps the raw fields, the recorded precision, the timezone evidence (or its absence) and a UTC
*interval* describing every instant the on-disk value could represent. Ordering is derived from
those intervals, so overlapping uncertainty yields an explicit "indeterminate" result instead of a
false chronology.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from enum import Enum

from dissect.util.ts import dostimestamp

DOS_EPOCH = datetime.datetime(1980, 1, 1)  # noqa: DTZ001 - documented epoch reference only

# Widest plausible set of civilian UTC offsets, in minutes (UTC-12:00 .. UTC+14:00).
WIDEST_TZ_RANGE_MIN = (-12 * 60, 14 * 60)
TIMEZONE_INCREMENT_MIN = 15
CENTISECONDS_PER_SECOND = 100


class TimeKind(Enum):
    """The semantic timestamp slot on a directory entry."""

    CREATED = "created"
    MODIFIED = "modified"
    ACCESSED = "accessed"


class Filesystem(Enum):
    """The on-disk format the timestamp was read from."""

    FAT = "FAT"
    EXFAT = "exFAT"


class TimezonePolicy(Enum):
    """How a valid exFAT UTC-offset byte is turned into minutes.

    ``SPEC`` follows [MS-XFS], The Sleuth Kit and relan/exfat: ``offset = (byte & 0x7f) - 64``.
    ``LINUX`` follows the Linux kernel driver's signed 7-bit interpretation: ``offset =
    sign_extend(byte & 0x7f)``. Real images exist in both conventions, so the raw byte and the
    chosen policy must always be retained.
    """

    SPEC = "spec-bias64"
    LINUX = "linux-bias0"


class Ordering(Enum):
    """Deterministic ordering of two timestamps given their UTC intervals."""

    BEFORE = "before"
    AFTER = "after"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class TimezoneInfo:
    """Everything known about the UTC offset that applies to one timestamp."""

    raw: int | None
    valid: bool
    offset_minutes: int | None
    policy: TimezonePolicy | None
    alternative_offsets: tuple[int, ...] = field(default_factory=tuple)
    note: str = ""

    @property
    def offset_name(self) -> str:
        """Human-readable offset name, or ``localtime`` when no offset is known."""
        if self.offset_minutes is None:
            return "localtime (UTC offset unknown)"
        sign = "+" if self.offset_minutes >= 0 else "-"
        hours, minutes = divmod(abs(self.offset_minutes), 60)
        return f"UTC{sign}{hours:02d}:{minutes:02d}"


@dataclass(frozen=True)
class ForensicTimestamp:
    """A single timestamp with its raw value, precision and UTC uncertainty preserved."""

    kind: TimeKind
    filesystem: Filesystem
    present: bool
    raw: dict[str, int]
    local: datetime.datetime | None
    precision: datetime.timedelta
    timezone: TimezoneInfo
    tz_range_min: tuple[int, int]
    note: str = ""

    @property
    def is_missing(self) -> bool:
        """True when the on-disk field is zero, i.e. no timestamp was recorded."""
        return not self.present

    @property
    def utc_point(self) -> datetime.datetime | None:
        """A single UTC instant, available only when the offset is explicitly known."""
        if not self.present or self.timezone.offset_minutes is None:
            return None
        return self._local_naive() - datetime.timedelta(minutes=self.timezone.offset_minutes)

    def _local_naive(self) -> datetime.datetime:
        # Stored local wall time is intentionally naive; attach UTC only at conversion time.
        if self.local is None:
            raise ValueError("Missing timestamp has no local wall time")
        return self.local.replace(tzinfo=None)

    @property
    def utc_earliest(self) -> datetime.datetime | None:
        """Lower bound (inclusive) of the UTC interval, or ``None`` when missing."""
        if not self.present or self.local is None:
            return None
        offset_max = self._offset_bounds()[1]
        instant = self.local - datetime.timedelta(minutes=offset_max)
        return instant.replace(tzinfo=datetime.timezone.utc)

    @property
    def utc_latest(self) -> datetime.datetime | None:
        """Upper bound (exclusive) of the UTC interval, or ``None`` when missing."""
        if not self.present or self.local is None:
            return None
        offset_min = self._offset_bounds()[0]
        instant = self.local + self.precision - datetime.timedelta(minutes=offset_min)
        return instant.replace(tzinfo=datetime.timezone.utc)

    def _offset_bounds(self) -> tuple[int, int]:
        if self.timezone.offset_minutes is not None:
            return self.timezone.offset_minutes, self.timezone.offset_minutes
        return self.tz_range_min

    @property
    def interval(self) -> tuple[datetime.datetime, datetime.datetime] | None:
        """Half-open UTC interval ``[earliest, latest)`` the value can represent."""
        if self.utc_earliest is None or self.utc_latest is None:
            return None
        return self.utc_earliest, self.utc_latest

    def describe(self) -> str:
        """One-line, report-safe description that never fabricates a 1980 event."""
        if not self.present:
            return f"{self.kind.value}: MISSING (raw zero field; not a 1980 event) {self.note}".rstrip()
        local = self.local.isoformat() if self.local else "?"
        if self.timezone.offset_minutes is None:
            earliest, latest = self.utc_earliest, self.utc_latest
            return (
                f"{self.kind.value}: local {local} ({self.timezone.offset_name}); "
                f"UTC in [{earliest.isoformat()}, {latest.isoformat()}); "
                f"precision={_fmt_timedelta(self.precision)} {self.note}"
            ).rstrip()
        return (
            f"{self.kind.value}: local {local} -> {self.utc_point.isoformat()} "
            f"{self.timezone.offset_name}; precision={_fmt_timedelta(self.precision)} "
            f"{self.timezone.note} {self.note}"
        ).rstrip()


def _fmt_timedelta(delta: datetime.timedelta) -> str:
    seconds = delta.total_seconds()
    if seconds >= 86400:
        return f"{int(seconds // 86400)}d"
    if seconds >= 1:
        return f"{seconds:g}s"
    return f"{int(seconds * 1000)}ms"


def _format_offset(offset_minutes: int) -> str:
    sign = "+" if offset_minutes >= 0 else "-"
    hours, minutes = divmod(abs(offset_minutes), 60)
    return f"UTC{sign}{hours:02d}:{minutes:02d}"


def decode_exfat_timezone(
    byte: int, policy: TimezonePolicy = TimezonePolicy.SPEC
) -> TimezoneInfo:
    """Decode one exFAT UTC-offset byte (the per-timestamp ``*_timezone`` field).

    The high bit is the validity flag. When it is clear the timestamp is unverified local time and
    no UTC offset can be claimed. When set, the low seven bits are interpreted according to
    ``policy``; the offset produced by the other convention is kept as an alternative when it
    differs.
    """
    valid = bool(byte & 0x80)
    if not valid:
        return TimezoneInfo(
            raw=byte,
            valid=False,
            offset_minutes=None,
            policy=None,
            note="validity bit clear: local wall time, UTC offset not recorded",
        )

    low7 = byte & 0x7F
    spec_offset = (low7 - 64) * TIMEZONE_INCREMENT_MIN
    linux_signed = low7 - 128 if low7 >= 64 else low7
    linux_offset = linux_signed * TIMEZONE_INCREMENT_MIN
    offset = spec_offset if policy is TimezonePolicy.SPEC else linux_offset

    alternatives = {
        value for value in (spec_offset, linux_offset) if value != offset
    }

    note = f"raw=0x{byte:02x}, policy={policy.value}"
    if alternatives:
        rendered = ", ".join(_format_offset(value) for value in sorted(alternatives))
        note += f"; alternative driver decode: {rendered}"

    return TimezoneInfo(
        raw=byte,
        valid=True,
        offset_minutes=offset,
        policy=policy,
        alternative_offsets=tuple(sorted(alternatives)),
        note=note,
    )


def _exfat_wall(timestamp: int, centiseconds: int) -> datetime.datetime:
    # Layout matches c_exfat.TIMESTAMP bitfields (little-endian, LSB first).
    seconds = (timestamp & 0x1F) * 2
    minutes = (timestamp >> 5) & 0x3F
    hours = (timestamp >> 11) & 0x1F
    day = (timestamp >> 16) & 0x1F
    month = (timestamp >> 21) & 0x0F
    year = ((timestamp >> 25) & 0x7F) + 1980
    extra_seconds, remainder_cs = divmod(centiseconds, CENTISECONDS_PER_SECOND)
    return datetime.datetime(  # noqa: DTZ001 - local wall time, timezone handled separately
        year,
        month or 1,
        day or 1,
        hours,
        minutes,
        seconds + extra_seconds,
        remainder_cs * 10000,
    )


def decode_exfat(
    kind: TimeKind,
    timestamp: int,
    timezone_byte: int,
    centiseconds: int = 0,
    policy: TimezonePolicy = TimezonePolicy.SPEC,
    tz_range_min: tuple[int, int] = WIDEST_TZ_RANGE_MIN,
) -> ForensicTimestamp:
    """Decode an exFAT timestamp plus its centisecond and timezone bytes.

    A zero packed timestamp means the value is absent. Created/modified carry a centisecond byte
    (10 ms granularity); accessed has no centisecond byte and stays at the 2-second granularity of
    the packed field.
    """
    raw = {"timestamp": timestamp, "timezone": timezone_byte}
    if kind in (TimeKind.CREATED, TimeKind.MODIFIED):
        raw["centiseconds"] = centiseconds
        precision = datetime.timedelta(milliseconds=10)
    else:
        precision = datetime.timedelta(seconds=2)

    tz = decode_exfat_timezone(timezone_byte, policy)

    if timestamp == 0:
        return ForensicTimestamp(
            kind=kind,
            filesystem=Filesystem.EXFAT,
            present=False,
            raw=raw,
            local=None,
            precision=precision,
            timezone=tz,
            tz_range_min=tz_range_min,
            note="zero packed timestamp",
        )

    return ForensicTimestamp(
        kind=kind,
        filesystem=Filesystem.EXFAT,
        present=True,
        raw=raw,
        local=_exfat_wall(timestamp, centiseconds),
        precision=precision,
        timezone=tz,
        tz_range_min=tz_range_min,
    )


def decode_fat(
    kind: TimeKind,
    date_field: int,
    time_field: int = 0,
    tenths: int = 0,
    tz_range_min: tuple[int, int] = WIDEST_TZ_RANGE_MIN,
) -> ForensicTimestamp:
    """Decode a FAT directory-entry timestamp.

    FAT has no timezone field, so every result is local wall time whose UTC offset is unknown.
    Created and modified have 2-second granularity (created adds a 0-199 centisecond byte, reaching
    10 ms); accessed is a date-only field with one-day granularity and no time of day.
    """
    raw = {"date": date_field, "time": time_field}
    if kind is TimeKind.CREATED:
        raw["tenths"] = tenths
        precision = datetime.timedelta(milliseconds=10)
    elif kind is TimeKind.ACCESSED:
        precision = datetime.timedelta(days=1)
    else:
        precision = datetime.timedelta(seconds=2)

    tz = TimezoneInfo(
        raw=None,
        valid=False,
        offset_minutes=None,
        policy=None,
        note="FAT has no on-disk timezone; local wall time only",
    )

    if date_field == 0:
        return ForensicTimestamp(
            kind=kind,
            filesystem=Filesystem.FAT,
            present=False,
            raw=raw,
            local=None,
            precision=precision,
            timezone=tz,
            tz_range_min=tz_range_min,
            note="zero date field",
        )

    local = dostimestamp((date_field << 16) | time_field, tenths)
    return ForensicTimestamp(
        kind=kind,
        filesystem=Filesystem.FAT,
        present=True,
        raw=raw,
        local=local,
        precision=precision,
        timezone=tz,
        tz_range_min=tz_range_min,
    )


def ordering(
    first: ForensicTimestamp, second: ForensicTimestamp
) -> tuple[Ordering, str]:
    """Compare two timestamps using their UTC intervals.

    Returns a deterministic relation only when the intervals cannot overlap; otherwise
    :data:`Ordering.INDETERMINATE` with the reason. Missing values can never be ordered.
    """
    if first.is_missing or second.is_missing:
        return Ordering.INDETERMINATE, "one or both timestamps are missing"

    first_early, first_late = first.interval  # type: ignore[misc]
    second_early, second_late = second.interval  # type: ignore[misc]

    if first_late <= second_early:
        return Ordering.BEFORE, f"{first.kind.value} interval ends before {second.kind.value} begins"
    if second_late <= first_early:
        return Ordering.AFTER, f"{first.kind.value} interval begins after {second.kind.value} ends"
    return (
        Ordering.INDETERMINATE,
        "UTC intervals overlap; timezone and/or date-only precision leaves both orders possible",
    )
