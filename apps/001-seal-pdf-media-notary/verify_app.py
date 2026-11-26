#!/usr/bin/env python3
"""Deterministic Verification Suite for 001-seal-pdf-media-notary."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from engine import notarize_artifact, verify_notary_envelope

ENGINE_PATH = Path(__file__).resolve().parent / "engine.py"
USAGE_ERROR_EXIT_CODE = 2


def run_cli(*cli_args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(ENGINE_PATH), *cli_args], capture_output=True, text=True)


def main() -> int:
    sample_doc = b"WholeTroutMedia Sovereign Document & Media Stream " * 256
    raw_exif = {
        "Make": "SONY",
        "Model": "ILCE-1",
        "FocalLengthMm": 35.0,
        "Orientation": 6,
        "GPSLatitude": "41.0912 N",
        "GPSLongitude": "72.3581 W",
        "CameraSerialNumber": "SN-994812",
    }
    envelope = notarize_artifact(sample_doc, raw_exif, block_size=1024)
    assert verify_notary_envelope(sample_doc, envelope, block_size=1024) is True
    assert "GPSLatitude" not in envelope["normalized_metadata"]
    assert envelope["normalized_metadata"]["Orientation"] == 1
    assert envelope["normalized_metadata"]["AppliedTranspose"]["rotation_deg"] == 90

    # Tamper test: flipping a single byte must fail verification
    tampered = bytearray(sample_doc)
    tampered[42] ^= 0xFF
    assert verify_notary_envelope(bytes(tampered), envelope, block_size=1024) is False

    # CLI test: --json must print a valid JSON receipt; the default output stays human-readable
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(sample_doc)
        tmp_path = tmp.name

    try:
        json_run = run_cli("--json", tmp_path)
        assert json_run.returncode == 0, json_run.stderr
        cli_receipt = json.loads(json_run.stdout)
        assert "envelope_digest" in cli_receipt
        assert "rfc6962_merkle_root" in cli_receipt
        assert "payload_sha256" in cli_receipt
        assert cli_receipt["payload_bytes"] == len(sample_doc)
        assert cli_receipt["payload_sha256"] == envelope["payload_sha256"]

        text_run = run_cli(tmp_path)
        assert text_run.returncode == 0, text_run.stderr
        assert f"Payload SHA-256:        {envelope['payload_sha256']}" in text_run.stdout
        assert not text_run.stdout.lstrip().startswith("{")

        assert run_cli("--json", "--block-size", "0", tmp_path).returncode == USAGE_ERROR_EXIT_CODE
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    missing_run = run_cli("--json", tmp_path)
    assert missing_run.returncode == USAGE_ERROR_EXIT_CODE
    assert "cannot read" in missing_run.stderr
    assert "Traceback" not in missing_run.stderr

    print("[PASS] 001-seal-pdf-media-notary verified (RFC 6962 Merkle root + EXIF transpose + tamper rejection, exit code 0).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
