#!/usr/bin/env python3
"""Stage WordPress.org SVN trunk/ + assets/ from the public patcherly/ tree.

Mirrors connectors/scripts/build_connector_packages.py WP_ZIP_EXCLUDE_* so trunk
matches what patcherly.zip would contain. Screenshot/banner/icon files that the
zip strips are copied to assets/ instead (WP.org handbook: assets stay outside
trunk so they are not shipped in plugin downloads).

Usage (from connector-packages repo root):
  python .github/scripts/stage_wp_org_svn.py \\
    --src patcherly --trunk-out /tmp/wp/trunk --assets-out /tmp/wp/assets \\
    --version 2.5.1
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
WP_ASSET_BASENAME_PREFIXES = (
    "screenshot-",
    "banner-",
    "icon-",
)

STABLE_TAG_RE = re.compile(r"^Stable tag:\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE)
VERSION_HEADER_RE = re.compile(r"^\s*\*\s*Version:\s*(\S+)\s*$", re.IGNORECASE | re.MULTILINE)


def _fail(msg: str) -> None:
    print(f"::error::{msg}", file=sys.stderr)
    sys.exit(1)


def _is_asset(rel: str) -> bool:
    base = rel.split("/")[-1]
    return any(base.startswith(p) for p in WP_ASSET_BASENAME_PREFIXES)


def _exclude_from_trunk(rel: str) -> bool:
    if ".git" in rel.split("/"):
        return True
    for prefix in WP_TRUNK_EXCLUDE_PREFIXES:
        if rel == prefix.rstrip("/") or rel.startswith(prefix):
            return True
    if _is_asset(rel):
        return True
    return False


def _reset_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


def stage(src: Path, trunk_out: Path, assets_out: Path) -> tuple[int, int]:
    if not src.is_dir():
        _fail(f"Plugin source not found: {src}")
    _reset_dir(trunk_out)
    _reset_dir(assets_out)

    trunk_n = 0
    assets_n = 0
    for path in sorted(src.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(src).as_posix()
        if _is_asset(rel):
            dest = assets_out / path.name
            shutil.copy2(path, dest)
            assets_n += 1
            continue
        if _exclude_from_trunk(rel):
            continue
        dest = trunk_out / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
        trunk_n += 1
    return trunk_n, assets_n


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
    parser = argparse.ArgumentParser(description="Stage WP.org SVN trunk + assets from patcherly/")
    parser.add_argument("--src", type=Path, default=Path("patcherly"))
    parser.add_argument("--trunk-out", type=Path, required=True)
    parser.add_argument("--assets-out", type=Path, required=True)
    parser.add_argument("--version", default="", help="Expected RELEASE_VER (Stable tag + plugin Version)")
    args = parser.parse_args()

    trunk_n, assets_n = stage(args.src.resolve(), args.trunk_out.resolve(), args.assets_out.resolve())
    stable = _read_stable_tag(args.trunk_out.resolve())
    plugin_ver = _read_plugin_version(args.trunk_out.resolve())

    if args.version:
        expected = args.version.strip()
        if stable != expected:
            _fail(f"readme Stable tag {stable!r} != requested RELEASE_VER {expected!r}")
        if plugin_ver != expected:
            _fail(f"patcherly.php Version {plugin_ver!r} != requested RELEASE_VER {expected!r}")

    if not (args.trunk_out / "patcherly.php").is_file():
        _fail("Main plugin file must live at trunk/patcherly.php (not trunk/patcherly/…)")

    print(f"[SUCCESS] Staged WP.org payload: {trunk_n} trunk files, {assets_n} assets")
    print(f"  trunk={args.trunk_out}")
    print(f"  assets={args.assets_out}")
    print(f"  Stable tag={stable} Version={plugin_ver}")


if __name__ == "__main__":
    main()
