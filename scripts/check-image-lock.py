#!/usr/bin/env python3
"""Validate reviewed immutable VM inputs. This never downloads or boots an image."""

import argparse
import datetime
import json
import pathlib
import re
import sys
import urllib.parse


TARGETS = {"debian13-amd64", "ubuntu24.04-amd64"}
HASH = re.compile(r"[0-9a-f]{64}\Z")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate image-lock key")
        result[key] = value
    return result


def keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("unexpected image-lock fields")


def digest(value):
    if not isinstance(value, str) or not HASH.fullmatch(value) or value == "0" * 64:
        raise ValueError("an actual lowercase SHA256 is required")
    return value


def https_url(value):
    if not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 33 for c in value):
        raise ValueError("invalid immutable image/evidence URL")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("image/evidence URLs must be HTTPS without credentials, queries, or fragments")
    if any(part.lower() in {"current", "latest", "daily", "daily-live"} for part in parsed.path.split("/")):
        raise ValueError("floating image/evidence URLs are not immutable pins")
    return value


def select_image(data, target, expected_sha256):
    if len(data) > 65536:
        raise ValueError("image lock exceeds 64 KiB")
    document = json.loads(data, object_pairs_hook=unique_object)
    keys(document, {"version", "targets"})
    if type(document["version"]) is not int or document["version"] != 1 or not isinstance(document["targets"], list):
        raise ValueError("unsupported image-lock schema")
    entries = {}
    for entry in document["targets"]:
        keys(entry, {"target", "status", "image", "publisher_verification"})
        name = entry["target"]
        if not isinstance(name, str) or name not in TARGETS or name in entries:
            raise ValueError("unknown or duplicate image-lock target")
        if entry["status"] not in {"pending", "pinned"}:
            raise ValueError("unknown image-lock status")
        if entry["status"] == "pending" and (entry["image"] is not None or entry["publisher_verification"] is not None):
            raise ValueError("pending inputs must not pretend to contain verified pins")
        entries[name] = entry
    if set(entries) != TARGETS or target not in entries:
        raise ValueError("both supported targets must be explicitly represented")
    entry = entries[target]
    if entry["status"] == "pending":
        raise ValueError("VM image lock is pending for " + target + "; no validated image digest or passed VM test is claimed")
    image = entry["image"]
    verification = entry["publisher_verification"]
    keys(image, {"url", "sha256"})
    keys(verification, {"signed_checksums_url", "signature_url", "signing_key_fingerprint", "verified_at", "record_sha256"})
    https_url(image["url"])
    digest(image["sha256"])
    https_url(verification["signed_checksums_url"])
    https_url(verification["signature_url"])
    fingerprint = verification["signing_key_fingerprint"]
    if not isinstance(fingerprint, str) or not re.fullmatch(r"(?:[0-9A-F]{40}|[0-9A-F]{64})", fingerprint):
        raise ValueError("record the independently verified publisher signing-key fingerprint")
    datetime.datetime.strptime(verification["verified_at"], "%Y-%m-%dT%H:%M:%SZ")
    digest(verification["record_sha256"])
    if digest(expected_sha256) != image["sha256"]:
        raise ValueError("declared VM image differs from the reviewed immutable image lock")
    return image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1] / "packaging/vm/images.lock.json")
    parser.add_argument("--target", required=True, choices=sorted(TARGETS))
    parser.add_argument("--sha256", required=True)
    arguments = parser.parse_args()
    try:
        with arguments.lock.open("rb") as source:
            image = select_image(source.read(65537), arguments.target, arguments.sha256)
    except (OSError, ValueError, TypeError) as error:
        print("VM image lock refused: " + str(error), file=sys.stderr)
        return 1
    print(arguments.target + " sha256:" + image["sha256"] + " (input identity only; not VM validation)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
