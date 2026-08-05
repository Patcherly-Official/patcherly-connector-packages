#!/usr/bin/env python3
"""Stage WordPress.org SVN trunk/ from the public patcherly/ tree.

Mirrors connectors/scripts/build_connector_packages.py WP_ZIP_EXCLUDE_* so trunk
matches what patcherly.zip would contain.

WordPress.org marketing assets (SVN top-level /assets — banners, icons,
screenshots) are managed manually outside this repo and are NOT staged here.
Do not confuse that with patcherly/assets/ (plugin CSS/JS/img), which belongs
in trunk and in the zip.

Usage (from connector-packages repo root):
  python .github/scripts/stage_wp_org_svn.py \\
    --src patcherly --trunk-out /tmp/wp/trunk --version 2.5.1
"""
from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

# Keep in sync with connectors/scripts/build_connector_packages.py
# (paths are relative to the patcherly/ plugin root, not connectors/).
WP_TRUNK_EXCLUDE_PREFIXES = (
    "tests/",
    ".distignore",
    ".editorconfig",
    ".DS_Store",
    "Thumbs.db",
    "node_modules/",
    "vendor/",
    "phpcs.xml.dist",
)
# Zip / trunk also strip WP.org *directory* marketing files if ever dropped at
# plugin root. These are NOT the same as patcherly/assets/ (runtime CSS/JS).
WP_DIR_MARKETING_BASENAME_PREFIXES = (
    "screenshot-",
    "banner-",
    "icon-",
)

STABLE_TAG_RE = re.compile(r"^Stable tag:\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
VERSION_HEADER_RE = re.compile(r"^\s*\*\s*Version:\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE)


def _fail(msg: str) -> None:
    print(f"::error::{msg}", file=sys.stderr)
    sys.exit(1)


def _is_dir_marketing_file(rel: str) -> bool:
    """True for WP.org listing images at plugin root — never for assets/js|css|img."""
    parts = rel.split("/")
    if len(parts) != 1:
        return False
    base = parts[0]
    return any(base.startswith(p) for p in WP_DIR_MARKETING_BASENAME_PREFIXES)


def _exclude_from_trunk(rel: str) -> bool:
    if ".git" in rel.split("/"):
        return True
    for prefix in WP_TRUNK_EXCLUDE_PREFIXES:
        if rel == prefix.rstrip("/") or rel.startswith(prefix):
            return True
    if _is_dir_marketing_file(rel):
        return True
    return False


def _reset_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


def stage(src: Path, trunk_out: Path) -> int:
    if not src.is_dir():
        _fail(f"Plugin source not found: {src}")
    _reset_dir(trunk_out)

    trunk_n = 0
    for path in sorted(src.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(src).as_posix()
        if _exclude_from_trunk(rel):
            continue
        dest = trunk_out / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
        trunk_n += 1
    return trunk_n


def _read_stable_tag(trunk: Path) -> str:
    readme = trunk / "readme.txt"
    if not readme.is_file():
        _fail("trunk/readme.txt missing after staging")
    text = readme.read_text(encoding="utf-8", errors="replace")
    match = STABLE_TAG_RE.search(text)
    if not match:
        _fail("Stable tag not found in trunk/readme.txt")
    return match.group(1).strip()


def _read_plugin_version(trunk: Path) -> str:
    main = trunk / "patcherly.php"
    if not main.is_file():
        _fail("trunk/patcherly.php missing after staging")
    text = main.read_text(encoding="utf-8", errors="replace")
    match = VERSION_HEADER_RE.search(text)
    if not match:
        _fail("Version header not found in trunk/patcherly.php")
    return match.group(1).strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Stage WP.org SVN trunk from patcherly/")
    parser.add_argument("--src", type=Path, default=Path("patcherly"))
    parser.add_argument("--trunk-out", type=Path, required=True)
    parser.add_argument("--version", default="", help="Expected RELEASE_VER (Stable tag + plugin Version)")
    args = parser.parse_args()

    trunk_n = stage(args.src.resolve(), args.trunk_out.resolve())
    stable = _read_stable_tag(args.trunk_out.resolve())
    plugin_ver = _read_plugin_version(args.trunk_out.resolve())

    # WP.org serves /tags/<Stable Tag>/ — "trunk" is discouraged and breaks new plugins.
    if stable.lower() == "trunk":
        _fail(
            'readme Stable tag must be a version number (e.g. 2.5.1), not "trunk". '
            "Trunk always holds the latest files; Stable Tag points at tags/<ver>."
        )

    if args.version:
        expected = args.version.strip()
        if stable != expected:
            _fail(f"readme Stable tag {stable!r} != requested RELEASE_VER {expected!r}")
        if plugin_ver != expected:
            _fail(f"patcherly.php Version {plugin_ver!r} != requested RELEASE_VER {expected!r}")

    if not (args.trunk_out / "patcherly.php").is_file():
        _fail("Main plugin file must live at trunk/patcherly.php (not trunk/patcherly/…)")

    # Sanity: plugin runtime assets must ship in trunk
    if not (args.trunk_out / "assets").is_dir():
        _fail("trunk/assets/ missing — plugin CSS/JS belong in the plugin zip / SVN trunk")

    print(f"[SUCCESS] Staged WP.org trunk: {trunk_n} files (SVN /assets not touched by CI)")
    print(f"  trunk={args.trunk_out}")
    print(f"  Stable tag={stable} Version={plugin_ver}")


if __name__ == "__main__":
    main()
