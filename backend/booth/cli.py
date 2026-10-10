"""Run with: python -m backend.booth.cli --bits 40."""

import argparse
import json
import statistics
import sys

from .group import BoothError
from .runner import Booth


def main():
    parser = argparse.ArgumentParser(description="Toy DH broken by a classical attack; hybrid uses real ML-KEM.")
    parser.add_argument("--bits", type=int, choices=(36, 40), default=40)
    parser.add_argument("--classical", default="Invented classical message")
    parser.add_argument("--hybrid", default="Invented hybrid message")
    parser.add_argument("--benchmark", type=int, default=0, help="Number of complete send/attack runs; use 20 at gates.")
    args = parser.parse_args()
    if not 0 <= args.benchmark <= 100:
        parser.error("benchmark must be from 0 to 100")
    booth, samples = Booth(args.bits), []
    try:
        for _ in range(args.benchmark or 1):
            sent = booth.send(args.classical, args.hybrid)
            attack = booth.qday()
            if attack["demo_verdict"] != "PASS":
                print(json.dumps(attack, ensure_ascii=True))
                return 1
            samples.append(attack["total_ms"])
        if args.benchmark:
            ordered = sorted(samples)
            import math
            print(json.dumps({"runs": len(samples), "bits": args.bits, "kem": sent["kem"],
                              "median_ms": statistics.median(samples),
                              "p95_ms": ordered[math.ceil(.95 * len(samples)) - 1],
                              "max_ms": max(samples), "samples_ms": samples,
                              "demo_verdict": "PASS", "platform": sys.platform}))
        else:
            print(json.dumps({"send": sent, "attack": attack}, ensure_ascii=True))
        return 0
    except BoothError as exc:
        print(json.dumps({"error": {"code": exc.code, "message": str(exc)}}))
        return 1
    except Exception:
        print(json.dumps({"error": {"code": "booth_failed", "message": "The booth could not complete. Reset and try again."}}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
