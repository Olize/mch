"""Offline regressions for the operator-run draft publication path."""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import hashlib
import tempfile
import unittest
from unittest.mock import patch

spec = spec_from_file_location("publish", Path(__file__).with_name("publish-from-srv.py"))
release = module_from_spec(spec)
spec.loader.exec_module(release)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name)
        self.sums = {}
        for i in range(8):
            name = f"asset{i}"
            (self.folder / name).write_bytes(name.encode())
            self.sums[name] = hashlib.sha256(name.encode()).hexdigest()
        self.calls = []
        self.listed = []
        self.assets = {}
        self.enabled = True
        self.corrupt = False
        self.published = False
        self.tag = "v0.2.3"

    def service(self, method, path, token, body=None, upload=False):
        self.calls.append((method, path))
        if path == "/immutable-releases":
            return {"enabled": self.enabled}
        if path == "":
            return {"permissions":{"push":True}}
        if path.startswith("/releases?"):
            return self.listed
        if method == "POST" and path == "/releases":
            self.assertIs(body["draft"], True)
            return {"id":1}
        if upload:
            self.assertEqual(method, "POST")
            self.assertTrue(path.startswith("/releases/1/assets?name="))
            self.assets[path.split("=")[-1]] = "sha256:" + hashlib.sha256(body).hexdigest()
            return {}
        if method == "PATCH":
            self.assertEqual(len(self.assets),8)
            self.published = True
            return {}
        assets = [{"name":n, "digest":("bad" if self.corrupt else d)} for n,d in self.assets.items()]
        return {"draft":not self.published, "immutable":self.published, "tag_name":self.tag,
                "assets":assets, "html_url":"simulated release"}

    def invoke(self, tag_check=None):
        with patch.object(release, "request", side_effect=self.service), patch.object(release, "check_tag", side_effect=tag_check):
            release.publish(self.folder,self.folder,self.tag,"a"*40,self.sums,"offline-test")

    def test_draft_first_verified_seal(self):
        self.invoke()
        self.assertTrue(self.published)

    def test_existing_release_or_populated_draft_stops(self):
        for draft, assets in [(False, []),(True,[{"name":"existing"}])]:
            self.listed = [{"id":1,"tag_name":self.tag,"draft":draft,"assets":assets}]
            with self.assertRaises(ValueError):
                self.invoke()
            self.assertFalse(any(method != "GET" for method, _ in self.calls))

    def test_disabled_immutability_stops(self):
        self.enabled = False
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertFalse(self.published)

    def test_remote_digest_mismatch_stops(self):
        self.corrupt = True
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertFalse(self.published)

    def test_moved_tag_stops_before_sealing(self):
        with self.assertRaises(ValueError):
            self.invoke(tag_check=[None,ValueError("tag changed")])
        self.assertFalse(self.published)


if __name__ == "__main__":
    unittest.main()
