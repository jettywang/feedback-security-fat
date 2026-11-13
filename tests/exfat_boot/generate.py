"""Write all validation samples to ``tests/data/exfat_boot/``.

Regenerate with::

    python -m tests.exfat_boot.generate
"""

from __future__ import annotations

from pathlib import Path

from tests.exfat_boot import builder

OUTPUT_DIR = Path(__file__).parent.parent / "data" / "exfat_boot"
PREFIX = {512: "exfat512", 4096: "exfat4k"}


def sample_name(case: str, sector_size: int) -> str:
    return f"{PREFIX[sector_size]}_{case}.bin"


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for sector_size in (512, 4096):
        for case in builder.CASES:
            path = OUTPUT_DIR / sample_name(case, sector_size)
            path.write_bytes(builder.build_case(case, sector_size))
            print(f"wrote {path} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
