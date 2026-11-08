"""恢复准入与单写入方门槛：这些失败必须发生在创建或启动目标前。"""

import io
import json
from pathlib import Path
import subprocess
import tempfile
import tarfile
import unittest
from unittest.mock import Mock

from rehearse import Rehearsal, comparable_print, file_manifest, sha256, verify_snapshot


class RestoreAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        for name in ("postgres.dump", "redis.rdb", "app.tar"):
            (self.directory / name).write_bytes(name.encode())
        self.manifest = {name: sha256(self.directory / name) for name in ("postgres.dump", "redis.rdb", "app.tar")}
        (self.directory / "manifest.json").write_text(json.dumps(self.manifest))

    def test_corrupt_database_or_config_backup_never_creates_a_target(self):
        for name in self.manifest:
            with self.subTest(name=name):
                original = (self.directory / name).read_bytes()
                (self.directory / name).write_bytes(original + b"changed")
                rehearsal = Rehearsal.__new__(Rehearsal)
                rehearsal.create_side = Mock()
                with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                    rehearsal.restore("b", self.directory)
                rehearsal.create_side.assert_not_called()
                (self.directory / name).write_bytes(original)
        self.assertEqual(verify_snapshot(self.directory), self.manifest)

    def test_missing_backup_symlink_and_unexpected_path_are_refused(self):
        backup = self.directory / "redis.rdb"
        backup.unlink()
        with self.assertRaisesRegex(RuntimeError, "missing"):
            verify_snapshot(self.directory)
        backup.symlink_to(self.directory / "postgres.dump")
        with self.assertRaisesRegex(RuntimeError, "missing"):
            verify_snapshot(self.directory)
        (self.directory / "manifest.json").write_text(json.dumps({"../postgres.dump": "x"}))
        with self.assertRaisesRegex(RuntimeError, "unexpected snapshot files"):
            verify_snapshot(self.directory)

    def test_a_live_old_writer_prevents_starting_the_new_application(self):
        rehearsal = Rehearsal.__new__(Rehearsal)
        rehearsal.resources = {"container": ["demo-a-app"]}
        rehearsal.docker = Mock(return_value=subprocess.CompletedProcess([], 0, b"true\n", b""))
        rehearsal.container = Mock()
        with self.assertRaisesRegex(RuntimeError, "writer is still running"):
            rehearsal.start_app("b")
        rehearsal.container.assert_not_called()
        self.assertEqual(rehearsal.docker.call_count, 1)

    def test_source_cannot_be_stopped_while_the_entry_is_still_serving_it(self):
        rehearsal = Rehearsal.__new__(Rehearsal)
        rehearsal.active = "a"
        rehearsal.docker = Mock()
        with self.assertRaisesRegex(RuntimeError, "maintenance"):
            rehearsal.stop_and_fence("a")
        rehearsal.docker.assert_not_called()

    def test_missing_unexpired_keys_and_changed_contents_are_not_expiration(self):
        before = {"postgres": "same", "redis": "0|dbsize|1|-|-1\n0|string|key|value|expires_at_ms=2000"}
        missing = {"postgres": "same", "redis": "0|dbsize|0|-|-1"}
        self.assertNotEqual(comparable_print(before, 1999), comparable_print(missing, 1999))
        self.assertEqual(comparable_print(before, 2000), comparable_print(missing, 2000))
        permanent = {"postgres": "same", "redis": before["redis"].replace("=2000", "=-1")}
        self.assertNotEqual(comparable_print(permanent, 2000), comparable_print(missing, 2000))
        changed = {"postgres": "changed", "redis": missing["redis"]}
        self.assertNotEqual(comparable_print(before, 2000), comparable_print(changed, 2000))

    def test_configuration_content_and_permissions_survive_archiving(self):
        def archive(content=b"config", mode=0o600, mtime=10):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w") as target:
                entry = tarfile.TarInfo("config.yaml")
                entry.size = len(content)
                entry.mode = mode
                entry.mtime = mtime
                target.addfile(entry, io.BytesIO(content))
            return file_manifest(output.getvalue())

        self.assertEqual(archive(), archive(mtime=20))
        self.assertNotEqual(archive(), archive(content=b"changed"))
        self.assertNotEqual(archive(), archive(mode=0o644))


if __name__ == "__main__":
    unittest.main()
