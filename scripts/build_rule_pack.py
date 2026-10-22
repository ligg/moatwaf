from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path


SAFE_VERSION = re.compile(r"^[A-Za-z0-9._-]+$")


@dataclass(frozen=True)
class RulePack:
    archive: Path
    checksum_file: Path
    sha256: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tar_info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.size = size
    info.mode = 0o644
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def build_rule_pack(rules_dir: Path, output_dir: Path, version: str) -> RulePack:
    if not SAFE_VERSION.fullmatch(version):
        raise ValueError("version may contain only letters, numbers, dot, dash, and underscore")

    rule_files = sorted(path for path in rules_dir.glob("*.yaml") if path.is_file())
    if not rule_files:
        raise ValueError(f"no YAML rules found in {rules_dir}")

    root = f"moat-waf-rules-{version}"
    manifest = {
        "schemaVersion": 1,
        "version": version,
        "files": {
            path.name: _sha256(path.read_bytes())
            for path in rule_files
        },
    }
    manifest_bytes = (
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")

    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path in rule_files:
            content = path.read_bytes()
            archive.addfile(
                _tar_info(f"{root}/rules/{path.name}", len(content)),
                io.BytesIO(content),
            )
        archive.addfile(
            _tar_info(f"{root}/manifest.json", len(manifest_bytes)),
            io.BytesIO(manifest_bytes),
        )

    gzip_buffer = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        fileobj=gzip_buffer,
        mtime=0,
    ) as compressed:
        compressed.write(tar_buffer.getvalue())
    archive_bytes = gzip_buffer.getvalue()
    checksum = _sha256(archive_bytes)

    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / f"{root}.tar.gz"
    checksum_path = output_dir / f"{root}.tar.gz.sha256"
    archive_path.write_bytes(archive_bytes)
    checksum_path.write_text(f"{checksum}  {archive_path.name}\n", encoding="ascii")
    return RulePack(archive=archive_path, checksum_file=checksum_path, sha256=checksum)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a deterministic Moat WAF rule pack")
    parser.add_argument("--rules-dir", type=Path, default=Path("rules"))
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    parser.add_argument("--version", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    pack = build_rule_pack(args.rules_dir, args.output_dir, args.version)
    print(f"{pack.archive} sha256={pack.sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

