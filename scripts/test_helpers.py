#!/usr/bin/env python3
"""Safe helper tests and Python syntax checks; never executes integration code."""

import ast
import copy
import importlib.util
import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("image_lock", ROOT / "scripts/check-image-lock.py")
image_lock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(image_lock)


class ImageLockTests(unittest.TestCase):
    def setUp(self):
        # These example.invalid values exist ONLY in this parser unit fixture.
        self.document = {
            "version": 1,
            "targets": [
                {"target": "debian13-amd64", "status": "pinned", "image": {"url": "https://example.invalid/2026-01-01/image.qcow2", "sha256": "a" * 64},
                 "publisher_verification": {"signed_checksums_url": "https://example.invalid/2026-01-01/SHA256SUMS", "signature_url": "https://example.invalid/2026-01-01/SHA256SUMS.sig", "signing_key_fingerprint": "A" * 40, "verified_at": "2026-01-01T00:00:00Z", "record_sha256": "b" * 64}},
                {"target": "ubuntu24.04-amd64", "status": "pending", "image": None, "publisher_verification": None},
            ],
        }

    def select(self, document, sha256="a" * 64):
        return image_lock.select_image(json.dumps(document).encode(), "debian13-amd64", sha256)

    def test_synthetic_pinned_identity(self):
        self.assertEqual(self.select(self.document)["sha256"], "a" * 64)

    def test_pending_never_becomes_a_pass(self):
        with self.assertRaisesRegex(ValueError, "pending"):
            image_lock.select_image(json.dumps(self.document).encode(), "ubuntu24.04-amd64", "a" * 64)

    def test_rejects_mismatched_digest(self):
        with self.assertRaises(ValueError):
            self.select(self.document, "c" * 64)

    def test_rejects_incomplete_floating_and_credentialled_inputs(self):
        for key, value in (("url", "http://example.invalid/image"), ("url", "https://example.invalid/current/image"), ("url", "https://user:password@example.invalid/image"), ("url", "https://example.invalid/image?token=secret"), ("sha256", "0" * 64), ("sha256", "latest")):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                document = copy.deepcopy(self.document)
                document["targets"][0]["image"][key] = value
                self.select(document)
        for field in self.document["targets"][0]["publisher_verification"]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                document = copy.deepcopy(self.document)
                del document["targets"][0]["publisher_verification"][field]
                self.select(document)

    def test_rejects_duplicate_unknown_and_noncanonical_schema(self):
        for payload in (b'{"version":1,"version":1,"targets":[]}', b'{"version":true,"targets":[]}', b'{"version":1,"targets":[],"extra":1}'):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                image_lock.select_image(payload, "debian13-amd64", "a" * 64)
        document = copy.deepcopy(self.document)
        document["targets"].append(document["targets"][0])
        with self.assertRaises(ValueError):
            self.select(document)
        document = copy.deepcopy(self.document)
        document["targets"][0]["status"] = "pending"
        with self.assertRaises(ValueError):
            self.select(document)

    def test_checked_in_pending_records_contain_no_fabricated_pins(self):
        data = (ROOT / "packaging/vm/images.lock.json").read_bytes()
        document = json.loads(data, object_pairs_hook=image_lock.unique_object)
        for entry in document["targets"]:
            if entry["status"] == "pending":
                self.assertIsNone(entry["image"])
                self.assertIsNone(entry["publisher_verification"])
                with self.assertRaisesRegex(ValueError, "pending"):
                    image_lock.select_image(data, entry["target"], "a" * 64)
            else:
                image_lock.select_image(data, entry["target"], entry["image"]["sha256"])


if __name__ == "__main__":
    for file in sorted((ROOT / "scripts").rglob("*.py")):
        ast.parse(file.read_bytes(), filename=str(file))
    if sys.argv[1:] == ["--syntax-only"]:
        sys.exit(0)
    unittest.main()
