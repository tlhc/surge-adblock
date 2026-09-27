import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import merge


class FetchFallbackTests(unittest.TestCase):
    def test_failed_update_keeps_source_and_continues(self):
        oldData = (merge.SOURCES / "anti_ad_surge2.txt").read_bytes()
        nextData = (merge.SOURCES / "awavenue_surge.list").read_bytes()
        catalog = {
            "first": {"file": "first.txt", "url": "https://first.invalid", "kind": "domainset", "label": "first"},
            "next": {"file": "next.txt", "url": "https://next.invalid", "kind": "domainset", "label": "next"},
        }
        for case, success, payload in (("download_failure", False, b"partial"),
                                       ("empty_200", True, b""),
                                       ("html_200", True, b"<html>Service unavailable</html>")):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                sourceDir = Path(directory)
                oldPath = sourceDir / "first.txt"
                oldPath.write_bytes(oldData)

                def Download(url, dest):
                    dest.write_bytes(payload if "first" in url else nextData)
                    return (success if "first" in url else True), 200, case

                with patch.object(merge, "SOURCES", sourceDir), patch.object(merge, "SOURCES_META", catalog), \
                     patch.object(merge, "download", side_effect=Download), contextlib.redirect_stdout(io.StringIO()):
                    status = merge.fetch_all()
                self.assertEqual(oldPath.read_bytes() == oldData, True, "old source was overwritten")
                self.assertTrue(status["first"]["ok"])
                self.assertEqual(status["first"]["path"], oldPath)
                self.assertTrue(status["next"]["ok"])
                self.assertEqual((sourceDir / "next.txt").read_bytes() == nextData, True)

    def test_missing_banad_cache_preserves_outputs(self):
        status = {key: {"ok": True, "path": merge.SOURCES / meta["file"], "kind": meta["kind"]}
                  for key, meta in merge.SOURCES_META.items()}
        status["banad"] = {"ok": False, "path": None, "kind": "ruleset"}
        with tempfile.TemporaryDirectory() as directory:
            outDir = Path(directory)
            oldData = {path.name: path.read_bytes() for path in merge.OUT.iterdir() if path.is_file()}
            for name, data in oldData.items():
                (outDir / name).write_bytes(data)
            with patch.object(merge, "fetch_all", return_value=status), patch.object(merge, "OUT", outDir), \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                result = merge.main()
            self.assertEqual(result, 1)
            self.assertEqual({path.name: path.read_bytes() for path in outDir.iterdir()}, oldData)
