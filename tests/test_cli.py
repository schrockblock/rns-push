import contextlib
import io
import json
import os
import shutil
import tempfile
import time
import unittest

import RNS

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


if __name__ == "__main__":
    unittest.main()
