import contextlib
import io
import json
import os
import shutil
import tempfile
import time
import tomllib
import unittest
from unittest import mock

import RNS

import rns_push
import rns_push.cli as cli
from rns_push.cli import main
from rns_push.registry import REGISTRATION_LIFETIME


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.configdir = tempfile.mkdtemp()
        self.state = os.path.join(self.configdir, "storage", "rns_push")
        os.makedirs(self.state)

    def tearDown(self):
        shutil.rmtree(self.configdir)

    def run_status(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["status", "--config", self.configdir])
        return code, out.getvalue()

    def test_prints_the_registration_destination_and_live_registration_count(self):
        identity = RNS.Identity()
        identity.to_file(os.path.join(self.state, "identity"))
        now = time.time()
        entries = [{"destination_hash": "01" * 16, "identity_public_key": "05" * 64, "token": "aa",
                    "environment": "sandbox", "bundle_id": "co.example.push", "registered_at": now},
                   {"destination_hash": "02" * 16, "identity_public_key": "05" * 64, "token": "aa",
                    "environment": "sandbox", "bundle_id": "co.example.push",
                    "registered_at": now - REGISTRATION_LIFETIME - 1}]
        with open(os.path.join(self.state, "registrations.json"), "w") as f:
            json.dump({"v": 1, "registrations": entries}, f)
        code, output = self.run_status()
        self.assertEqual(code, 0)
        self.assertIn(RNS.Destination.hash(identity, "rnspush", "registration").hex(), output)
        self.assertIn("Registrations: 1", output)

    def test_reports_a_hub_that_has_not_started_yet(self):
        code, output = self.run_status()
        self.assertEqual(code, 0)
        self.assertIn("not created yet", output)
        self.assertIn("Registrations: 0", output)


PACKAGED_SHIM = os.path.join(os.path.dirname(os.path.abspath(rns_push.__file__)), "shim", "PushTCPServerInterface.py")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class InstallShimTests(unittest.TestCase):
    def setUp(self):
        self.configdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.configdir)
        self.destination = os.path.join(self.configdir, "interfaces", "PushTCPServerInterface.py")

    def run_install(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["install-shim", *args])
        return code, out.getvalue()

    def read(self, path):
        with open(path, "rb") as f:
            return f.read()

    def test_copies_the_packaged_shim_into_the_interfaces_directory(self):
        code, output = self.run_install("--config", self.configdir)
        self.assertEqual(code, 0)
        self.assertEqual(self.read(self.destination), self.read(PACKAGED_SHIM))
        self.assertEqual(output.strip(), self.destination)

    def test_overwrites_an_existing_shim(self):
        os.makedirs(os.path.dirname(self.destination))
        with open(self.destination, "w") as f:
            f.write("stale")
        self.run_install("--config", self.configdir)
        self.assertEqual(self.read(self.destination), self.read(PACKAGED_SHIM))

    def test_defaults_to_the_rnsd_config_directory(self):
        with mock.patch.object(cli, "default_configdir", return_value=self.configdir):
            code, output = self.run_install()
        self.assertEqual(code, 0)
        self.assertEqual(self.read(self.destination), self.read(PACKAGED_SHIM))


class PackagingTests(unittest.TestCase):
    def test_the_shim_ships_as_package_data(self):
        with open(os.path.join(REPO, "pyproject.toml"), "rb") as f:
            project = tomllib.load(f)
        self.assertIn("shim/PushTCPServerInterface.py", project["tool"]["setuptools"]["package-data"]["rns_push"])
        self.assertTrue(os.path.isfile(PACKAGED_SHIM))
        self.assertFalse(os.path.exists(os.path.join(REPO, "shim")))


if __name__ == "__main__":
    unittest.main()
