#!/usr/bin/env python3
"""Deterministic Verification Suite for 001-seal-pdf-media-notary."""

from engine import notarize_artifact, verify_notary_envelope


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

    # CLI test: --json flag must produce valid JSON with expected receipt keys on stdout
    import json
    import subprocess
    import sys
    import tempfile
    from pathlib import Path

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(sample_doc)
        tmp_path = tmp.name

    try:
        engine_path = Path(__file__).resolve().parent / "engine.py"
        proc = subprocess.run(
            [sys.executable, str(engine_path), "--json", tmp_path],
            capture_output=True,
            text=True,
            check=True,
        )
        cli_receipt = json.loads(proc.stdout)
        assert "envelope_digest" in cli_receipt
        assert "rfc6962_merkle_root" in cli_receipt
        assert "payload_sha256" in cli_receipt
        assert cli_receipt["payload_bytes"] == len(sample_doc)
        assert cli_receipt["payload_sha256"] == envelope["payload_sha256"]
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    print("[PASS] 001-seal-pdf-media-notary verified (RFC 6962 Merkle root + EXIF transpose + tamper rejection, exit code 0).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
