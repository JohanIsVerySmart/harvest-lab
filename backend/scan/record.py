"""Save ONE real scan as a dated recording, for an honest replay if venue
wifi blocks TLS. A human types the host; this never picks targets itself.

    python -m backend.scan.record google.com --network "Ensign venue wifi"

Writes backend/scan/recordings/<host>_<UTC time>.json. The UI must always
label a replay as a dated recording, never as a live result.
"""
import argparse
import json
import sys
from pathlib import Path

from backend.scan import probes
from backend.scan.api import assemble
from backend.scan.hostcheck import ScanRejected
from backend.scan.openssl_env import OpenSSLUnavailable

RECORDINGS_DIR = Path(__file__).resolve().parent / "recordings"


def record(host, network):
    scan, problem = probes.scan_public(host)
    scan = assemble(scan, problem)
    recording = {
        "recording": {
            "recorded_at": scan["scanned_at"],
            "network": network,
            "note": "Dated recording of a real scan. Not a live result.",
        },
        "scan": scan,
    }
    RECORDINGS_DIR.mkdir(exist_ok=True)
    stamp = scan["scanned_at"].replace(":", "").replace("-", "")
    path = RECORDINGS_DIR / f"{scan['target']['host']}_{stamp}.json"
    path.write_text(json.dumps(recording, indent=2) + "\n", encoding="utf-8")
    return path, scan


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("host", help="a public host name you typed, like google.com")
    parser.add_argument("--network", required=True, help='where you are, like "Ensign venue wifi"')
    args = parser.parse_args()
    try:
        path, scan = record(args.host, args.network)
    except (ScanRejected, OpenSSLUnavailable) as exc:
        sys.exit(f"Not recorded: {getattr(exc, 'message', exc)}")
    print(f"{scan['verdict']['label']}: {scan['verdict']['headline']}")
    print(f"Saved {path}")
