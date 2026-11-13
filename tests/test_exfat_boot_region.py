"""Boot region validation material for the exFAT reader.

Layers kept separate on purpose:

- ``TestIndependentVerdicts`` checks the independent verifier against
  hand-derived expectations (no production parser involved).
- ``TestReaderAcceptance`` records what the production reader currently
  does with each sample, including the corrupted ones it accepts.
- ``TestGaps`` holds xfail(strict) tests for checks the reader does not
  have yet; each reason names the suggested integration point.
"""

from __future__ import annotations

import hashlib
import io
from typing import BinaryIO

import pytest

from dissect.fat.exceptions import InvalidHeaderMagic
from dissect.fat.exfat import ExFAT
from tests.exfat_boot import builder, verifier
from tests.exfat_boot.expectations import EXPECTATIONS
from tests.exfat_boot.generate import OUTPUT_DIR, sample_name

SECTOR_SIZES = (512, 4096)
CASE_SECTORS = [(case, size) for case in builder.CASES for size in SECTOR_SIZES]


def _reader_outcome(image: bytes) -> str:
    try:
        ExFAT(io.BytesIO(image))
    except AttributeError:
        return "attribute_error"
    return "accepts"


def _reader_file_content(fh: BinaryIO, filesystem: ExFAT, name: str) -> bytes:
    entry = filesystem.files["/"][1][name][0]
    offset = filesystem.cluster_to_sector(entry.stream.location) * filesystem.sector_size
    fh.seek(offset)
    return fh.read(entry.stream.data_length)


class TestIndependentVerdicts:
    @pytest.mark.parametrize(("case", "sector_size"), CASE_SECTORS)
    def test_verdict_matches_hand_derived_expectation(self, case: str, sector_size: int) -> None:
        report = verifier.verify_image(builder.build_case(case, sector_size))
        expected = EXPECTATIONS[case]

        assert report.main.checksum_valid is expected.main_checksum
        assert report.backup.checksum_valid is expected.backup_checksum
        assert report.main.structural_ok is expected.main_structural
        assert report.backup.structural_ok is expected.backup_structural
        assert report.regions_agree is expected.regions_agree
        assert report.content_via_main.locatable is expected.content_via_main
        assert report.content_via_backup.locatable is expected.content_via_backup
        assert report.current_volume_flags == expected.current_volume_flags
        assert report.current_percent_in_use == expected.current_percent_in_use

    @pytest.mark.parametrize("sector_size", SECTOR_SIZES)
    def test_located_content_matches_ground_truth(self, sector_size: int) -> None:
        for case in builder.CASES:
            report = verifier.verify_image(builder.build_case(case, sector_size))
            for content in (report.content_via_main, report.content_via_backup):
                if content.locatable:
                    assert content.entry_set_checksum_valid
                    assert content.content == builder.file_content(sector_size)

    @pytest.mark.parametrize("sector_size", SECTOR_SIZES)
    def test_backup_active_state_is_not_current_state(self, sector_size: int) -> None:
        report = verifier.verify_image(builder.build_case("flags_independent", sector_size))
        assert report.backup.boot.volume_flags & 0x0002  # backup claims volume dirty
        assert report.current_volume_flags == 0x0000  # current state comes from main only
        assert report.main.checksum_valid and report.backup.checksum_valid

    @pytest.mark.parametrize("sector_size", SECTOR_SIZES)
    def test_flags_and_percent_change_keeps_checksum_valid(self, sector_size: int) -> None:
        valid = builder.build_case("valid", sector_size)
        mutated = builder.build_case("flags_independent", sector_size)
        assert (
            verifier.verify_region(valid, 0, sector_size, 0).computed_checksum
            == verifier.verify_region(mutated, 0, sector_size, 0).computed_checksum
        )

    @pytest.mark.parametrize("sector_size", SECTOR_SIZES)
    def test_evidence_trace_ends_in_verified_file_read(self, sector_size: int) -> None:
        image = builder.build_case("valid", sector_size)
        trace = verifier.trace_file_read(image, builder.file_content(sector_size))
        assert hashlib.sha256(builder.file_content(sector_size)).hexdigest() in trace
        assert trace.endswith("MATCH")


class TestReaderAcceptance:
    @pytest.mark.parametrize(("case", "sector_size"), CASE_SECTORS)
    def test_reader_outcome_matrix(self, case: str, sector_size: int) -> None:
        assert _reader_outcome(builder.build_case(case, sector_size)) == EXPECTATIONS[case].reader

    @pytest.mark.parametrize("sector_size", SECTOR_SIZES)
    @pytest.mark.parametrize(
        "case",
        ["valid", "flags_independent", "checksum_sector_bit", "backup_geom_diverge"],
    )
    def test_reader_reads_file_content(self, case: str, sector_size: int) -> None:
        fh = io.BytesIO(builder.build_case(case, sector_size))
        filesystem = ExFAT(fh)
        assert filesystem.volume_label == builder.VOLUME_LABEL
        assert _reader_file_content(fh, filesystem, builder.FILE_NAME) == builder.file_content(sector_size)

    @pytest.mark.parametrize("sector_size", SECTOR_SIZES)
    @pytest.mark.parametrize("case", ["rootdir_relocated_csum_ok", "heap_shifted_csum_bad"])
    def test_reader_failure_is_incidental_not_validation(self, case: str, sector_size: int) -> None:
        # The reader does not reject these images; it crashes later with an
        # AttributeError because no volume label entry was found.
        with pytest.raises(AttributeError):
            ExFAT(io.BytesIO(builder.build_case(case, sector_size)))


class TestGaps:
    @pytest.mark.parametrize("sector_size", SECTOR_SIZES)
    @pytest.mark.parametrize("case", ["heap_shifted_csum_bad", "checksum_sector_bit"])
    @pytest.mark.xfail(
        strict=True,
        reason=(
            "GAP: ExFAT.__init__ trusts any header with the EXFAT magic; the boot "
            "checksum is never verified. Suggested integration point: "
            "dissect/fat/exfat.py:40, right after the magic check and before any "
            "geometry field is used."
        ),
    )
    def test_reader_should_reject_invalid_main_checksum(self, case: str, sector_size: int) -> None:
        with pytest.raises(InvalidHeaderMagic):
            ExFAT(io.BytesIO(builder.build_case(case, sector_size)))

    @pytest.mark.parametrize("sector_size", SECTOR_SIZES)
    @pytest.mark.xfail(
        strict=True,
        reason=(
            "GAP: the backup boot region at sector 12 is never read, so a corrupt "
            "main region is not recovered from the intact backup. Suggested "
            "integration point: dissect/fat/exfat.py:37, fall back to the backup "
            "VBR when the main one fails checksum verification."
        ),
    )
    def test_reader_should_fall_back_to_backup_region(self, sector_size: int) -> None:
        fh = io.BytesIO(builder.build_case("heap_shifted_csum_bad", sector_size))
        filesystem = ExFAT(fh)
        assert _reader_file_content(fh, filesystem, builder.FILE_NAME) == builder.file_content(sector_size)

    @pytest.mark.parametrize("sector_size", SECTOR_SIZES)
    @pytest.mark.xfail(
        strict=True,
        reason=(
            "GAP: main and backup boot regions are never cross-checked, so a "
            "diverging backup goes unnoticed. Suggested integration point: expose "
            "a region-agreement flag next to the VBR parse in dissect/fat/exfat.py."
        ),
    )
    def test_reader_should_expose_region_divergence(self, sector_size: int) -> None:
        filesystem = ExFAT(io.BytesIO(builder.build_case("backup_geom_diverge", sector_size)))
        assert getattr(filesystem, "boot_regions_agree", None) is False


def test_on_disk_samples_match_builder() -> None:
    if not OUTPUT_DIR.is_dir():
        pytest.skip("on-disk samples not generated; run python -m tests.exfat_boot.generate")
    for sector_size in SECTOR_SIZES:
        for case in builder.CASES:
            on_disk = (OUTPUT_DIR / sample_name(case, sector_size)).read_bytes()
            assert on_disk == builder.build_case(case, sector_size)
