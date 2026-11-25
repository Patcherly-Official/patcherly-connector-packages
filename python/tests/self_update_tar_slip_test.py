"""Tar member path checks for connector self-update (defence-in-depth after SHA256).

Run:  python connectors/python/tests/self_update_tar_slip_test.py
"""

from __future__ import annotations

import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

_CONNECTOR_DIR = Path(__file__).resolve().parent.parent
if str(_CONNECTOR_DIR) not in sys.path:
    sys.path.insert(0, str(_CONNECTOR_DIR))

from lib.self_update import _extract_tar_gz, _is_safe_tar_member  # noqa: E402


def _member(name: str, *, linkname: str | None = None, sym: bool = False) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    if linkname is not None:
        info.type = tarfile.SYMTYPE if sym else tarfile.LNKTYPE
        info.linkname = linkname
    else:
        info.type = tarfile.REGTYPE
        info.size = 0
    return info


class SelfUpdateTarSlipTest(unittest.TestCase):
    def test_rejects_parent_and_absolute_members(self) -> None:
        dest = Path(tempfile.mkdtemp(prefix="patcherly-tar-"))
        self.assertFalse(_is_safe_tar_member(_member("../evil.txt"), dest))
        self.assertFalse(_is_safe_tar_member(_member("/etc/passwd"), dest))
        self.assertFalse(_is_safe_tar_member(_member("ok/../../escape"), dest))
        self.assertTrue(_is_safe_tar_member(_member("pkg/agent.py"), dest))

    def test_rejects_symlink_escape(self) -> None:
        dest = Path(tempfile.mkdtemp(prefix="patcherly-tar-"))
        self.assertFalse(
            _is_safe_tar_member(_member("link", linkname="../outside", sym=True), dest)
        )
        self.assertTrue(
            _is_safe_tar_member(_member("link", linkname="sibling.txt", sym=True), dest)
        )

    def test_extract_refuses_traversal_archive(self) -> None:
        with tempfile.TemporaryDirectory(prefix="patcherly-tar-") as tmp:
            tmp_path = Path(tmp)
            archive = tmp_path / "bad.tgz"
            with tarfile.open(archive, "w:gz") as tf:
                data = b"x"
                info = tarfile.TarInfo(name="../escape.txt")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            with self.assertRaises(ValueError):
                _extract_tar_gz(archive, tmp_path / "out")


if __name__ == "__main__":
    unittest.main()
