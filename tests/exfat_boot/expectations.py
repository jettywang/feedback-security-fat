"""Hand-derived expected verdicts for every validation sample.

These expectations are derived from the exFAT specification and the known
mutations in ``builder.py`` -- never from running the production parser.
The ``reader`` field records the expected *current* behaviour of
``dissect.fat.exfat.ExFAT`` as established by code inspection:

- ``"accepts"``: constructor succeeds, HELLO.TXT is listed, content matches
- ``"attribute_error"``: constructor dies with an incidental AttributeError
  (``volume_entry`` is None because no volume label entry was found), which
  is NOT a deliberate validation rejection
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Expectation:
    main_checksum: bool
    backup_checksum: bool
    main_structural: bool
    backup_structural: bool
    regions_agree: bool
    content_via_main: bool
    content_via_backup: bool
    current_volume_flags: int
    current_percent_in_use: int
    trusted: bool
    reader: str


EXPECTATIONS = {
    # Both regions intact and identical. Fully trustworthy.
    "valid": Expectation(
        main_checksum=True,
        backup_checksum=True,
        main_structural=True,
        backup_structural=True,
        regions_agree=True,
        content_via_main=True,
        content_via_backup=True,
        current_volume_flags=0x0000,
        current_percent_in_use=0,
        trusted=True,
        reader="accepts",
    ),
    # root_dir_cluster 4 -> 5 in both regions, checksums honestly recomputed.
    # Checksum-valid and structurally in-bounds, yet the root directory now
    # points at file data: parseable is not trustworthy.
    "rootdir_relocated_csum_ok": Expectation(
        main_checksum=True,
        backup_checksum=True,
        main_structural=True,
        backup_structural=True,
        regions_agree=True,
        content_via_main=False,
        content_via_backup=False,
        current_volume_flags=0x0000,
        current_percent_in_use=0,
        trusted=False,
        reader="attribute_error",
    ),
    # cluster_heap_sector +1 in main only, checksum NOT recomputed. Main
    # checksum invalid AND heap out of volume bounds; backup fully intact,
    # so content remains recoverable through the backup region.
    "heap_shifted_csum_bad": Expectation(
        main_checksum=False,
        backup_checksum=True,
        main_structural=False,
        backup_structural=True,
        regions_agree=False,
        content_via_main=False,
        content_via_backup=True,
        current_volume_flags=0x0000,
        current_percent_in_use=0,
        trusted=False,
        reader="attribute_error",
    ),
    # VolumeFlags/PercentInUse differ between regions; both are excluded
    # from the boot checksum, so both checksums stay valid. Current state
    # is main's (clean); the backup's dirty flag is NOT the current state.
    "flags_independent": Expectation(
        main_checksum=True,
        backup_checksum=True,
        main_structural=True,
        backup_structural=True,
        regions_agree=True,
        content_via_main=True,
        content_via_backup=True,
        current_volume_flags=0x0000,
        current_percent_in_use=75,
        trusted=True,
        reader="accepts",
    ),
    # One repeated value in the main checksum sector corrupted. Geometry
    # and content are fine, but the main region fails verification.
    "checksum_sector_bit": Expectation(
        main_checksum=False,
        backup_checksum=True,
        main_structural=True,
        backup_structural=True,
        regions_agree=True,
        content_via_main=True,
        content_via_backup=True,
        current_volume_flags=0x0000,
        current_percent_in_use=0,
        trusted=False,
        reader="accepts",
    ),
    # Backup root_dir_cluster diverges (backup checksum recomputed, so the
    # backup verifies standalone). Main is authoritative and intact.
    "backup_geom_diverge": Expectation(
        main_checksum=True,
        backup_checksum=True,
        main_structural=True,
        backup_structural=True,
        regions_agree=False,
        content_via_main=True,
        content_via_backup=False,
        current_volume_flags=0x0000,
        current_percent_in_use=0,
        trusted=False,
        reader="accepts",
    ),
}
