#!/usr/bin/env python3
"""Build self-contained connector release archives for GitHub Releases."""
from __future__ import annotations

import argparse
import re
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONNECTORS = ROOT / "connectors"
DEFAULT_OUT = ROOT / "connector-packages"

FORBIDDEN_REF = re.compile(
    r"\.\./common|\.\./shared|connectors/common|ROUTER_|NAMED_AUTH_|NAMED_PATHS_AUTH_"
)

NODEJS_EXCLUDE = {".git", "node_modules", "test", ".patcherly_backups"}
PYTHON_EXCLUDE = {".git", "__pycache__", ".pytest_cache", "tests", "dist", "build", ".patcherly_backups"}
PHP_EXCLUDE = {".git", ".patcherly_backups"}
WP_ZIP_EXCLUDE_PREFIXES = (
    "patcherly/tests/",
    "patcherly/.distignore",
    "patcherly/.editorconfig",
    "patcherly/.DS_Store",
    "patcherly/Thumbs.db",
    "patcherly/node_modules/",
    "patcherly/vendor/",
    "patcherly/phpcs.xml.dist",
)
WP_ZIP_EXCLUDE_GLOBS = (
    "patcherly/screenshot-",
    "patcherly/banner-",
    "patcherly/icon-",
)


def _fail(msg: str) -> None:
    print(f"::error::{msg}", file=sys.stderr)
    sys.exit(1)


def _should_skip(rel_posix: str, exclude_names: set[str], exclude_prefixes: tuple[str, ...] = ()) -> bool:
    parts = rel_posix.split("/")
    if any(p in exclude_names for p in parts):
        return True
    if any(p.endswith(".egg-info") for p in parts):
        return True
    for prefix in exclude_prefixes:
        if rel_posix.startswith(prefix):
            return True
    return False


def _validate_tree(root: Path, label: str) -> None:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel.startswith("tests/") or "/tests/" in rel:
            continue
        if path.suffix in {".png", ".jpg", ".jpeg", ".gif", ".mo", ".pot", ".zip", ".tar", ".gz"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            _fail(f"{label}: cannot read {path}: {exc}")
        if FORBIDDEN_REF.search(text):
            _fail(
                f"{label}: forbidden connectors/common or connectors/shared reference "
                f"in {path.relative_to(root)}"
            )


def _add_dir_to_tar(tar: tarfile.TarFile, src: Path, arc_prefix: str, exclude_names: set[str]) -> None:
    for path in sorted(src.rglob("*")):
        rel = path.relative_to(src).as_posix()
        if _should_skip(rel, exclude_names):
            continue
        arcname = f"{arc_prefix}/{rel}" if arc_prefix else rel
        tar.add(path, arcname=arcname, recursive=False)


def _add_dir_to_zip(zf: zipfile.ZipFile, src: Path, arc_prefix: str, exclude_names: set[str]) -> None:
    for path in sorted(src.rglob("*")):
        if path.is_dir():
            continue
        rel = path.relative_to(src).as_posix()
        if _should_skip(rel, exclude_names):
            continue
        arcname = f"{arc_prefix}/{rel}" if arc_prefix else rel
        zf.write(path, arcname)


def build_nodejs(out_dir: Path) -> Path:
    src = CONNECTORS / "nodejs"
    if not (src / "lib" / "api_paths.js").is_file():
        _fail("nodejs/lib/api_paths.js missing — run config/generate_api_paths.py")
    dest = out_dir / "nodejs-connector.tar.gz"
    _validate_tree(src, "nodejs")
    with tarfile.open(dest, "w:gz") as tar:
        _add_dir_to_tar(tar, src, "", NODEJS_EXCLUDE)
    return dest


def build_python(out_dir: Path) -> Path:
    src = CONNECTORS / "python"
    if not (src / "lib" / "api_paths.py").is_file():
        _fail("python/lib/api_paths.py missing — run config/generate_api_paths.py")
    dest = out_dir / "python-connector.tar.gz"
    _validate_tree(src, "python")
    with tarfile.open(dest, "w:gz") as tar:
        _add_dir_to_tar(tar, src, "", PYTHON_EXCLUDE)
    return dest


def build_php(out_dir: Path) -> Path:
    src = CONNECTORS / "php"
    if not (src / "lib" / "api_paths.php").is_file():
        _fail("php/lib/api_paths.php missing — run config/generate_api_paths.py")
    dest = out_dir / "php-connector.zip"
    _validate_tree(src, "php")
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        _add_dir_to_zip(zf, src, "", PHP_EXCLUDE)
    return dest


def _wp_zip_exclude(arcname: str) -> bool:
    if ".git" in arcname:
        return True
    for prefix in WP_ZIP_EXCLUDE_PREFIXES:
        if arcname.startswith(prefix):
            return True
    base = arcname.split("/")[-1]
    for glob_prefix in WP_ZIP_EXCLUDE_GLOBS:
        if arcname.startswith(glob_prefix) or base.startswith(glob_prefix.split("/")[-1]):
            return True
    return False


def build_patcherly(out_dir: Path) -> Path:
    src = CONNECTORS / "patcherly"
    for required in ("includes/api_paths.php", "includes/ingest_severity.php"):
        if not (src / required).is_file():
            _fail(f"patcherly/{required} missing — run generators")
    dest = out_dir / "patcherly.zip"
    _validate_tree(src, "patcherly")
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(src.rglob("*")):
            if path.is_dir():
                continue
            rel = path.relative_to(CONNECTORS).as_posix()
            if _wp_zip_exclude(rel):
                continue
            zf.write(path, rel)
    return dest


def main() -> None:
    parser = argparse.ArgumentParser(description="Build connector GitHub Release archives")
    parser.add_argument("--version", default="", help="Connector RELEASE_VER (informational)")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    out_dir = args.output_dir.resolve()
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    built = [
        build_nodejs(out_dir),
        build_python(out_dir),
        build_php(out_dir),
        build_patcherly(out_dir),
    ]
    ver = args.version or "(unspecified)"
    print(f"[SUCCESS] Connector packages built (RELEASE_VER={ver}):")
    for path in built:
        print(f"  - {path}")
    print(f"  - {len(built)} archives in {out_dir}")


if __name__ == "__main__":
    main()
