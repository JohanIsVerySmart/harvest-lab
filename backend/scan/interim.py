"""INTERIM assembler, used ONLY until Johan's backend/scan/verdict.py exists.

Johan owns the real truth table. api.py imports `assemble` from
backend.scan.verdict when that module exists and falls back to this file
otherwise, so the scan routes work end to end tonight. Delete this file
once verdict.py lands.

Expected interface: assemble(scan, problem) -> scan with cert, verdict,
pq_note and footer added. `problem` is None or {code, text} (DNS failure).
"""

HEADLINES = {
    "hybrid_observed": "This connection negotiated a hybrid key agreement.",
    "hybrid_supported_not_chosen": "Hybrid is supported, but this client profile was not given it.",
    "classical_observed": "Classical key agreement observed; hybrid not established.",
    "inconclusive": "We could not finish this scan. That is the honest answer.",
}
_OUTCOME_TO_REASON = {
    "timeout": "timeout",
    "net_refused": "connection_refused",
    "cert_fail": "cert_verify",
    "hs_refused": "no_tls13_handshake",
    "proto_refused": "no_tls13_handshake",
    "other_alert": "no_tls13_handshake",
    "parse_fail": "anomaly",
    "output_cap": "anomaly",
}


def _key_class(sig_type):
    sig = sig_type or ""
    if sig.startswith("ecdsa_secp256r1"):
        return "EC P-256"
    if sig.startswith("ecdsa_secp384r1"):
        return "EC P-384"
    if sig.startswith("ecdsa_secp521r1"):
        return "EC P-521"
    if sig.startswith("rsa"):
        return "RSA"
    if sig in ("ed25519", "ed448"):
        return sig.capitalize()
    return None


def _verdict(label, rule, qualifier, notes=(), reason=None):
    return {
        "label": label, "rule": rule, "headline": HEADLINES[label],
        "qualifier": qualifier, "notes": list(notes), "reason": reason,
    }


def _decide(probes, problem):
    if problem:
        return _verdict("inconclusive", "0", "No probe was run.", reason=problem)
    d, h = probes.get("default"), probes.get("hybrid_only")
    if not d:
        return _verdict("inconclusive", "0", "No probe was run.", reason={"code": "other", "text": "The probes did not run."})
    if d["outcome"] != "ok":
        code = _OUTCOME_TO_REASON.get(d["outcome"], "other")
        return _verdict("inconclusive", "5", "The default handshake did not complete.", reason={"code": code, "text": d["reason"]["text"]})
    if d["group_class"] == "hybrid":
        return _verdict("hybrid_observed", "1", "Observed once, from one OpenSSL client profile.")
    if d["group_class"] == "classical":
        if h and h["outcome"] == "ok" and h["group_class"] == "hybrid":
            return _verdict("hybrid_supported_not_chosen", "2", "A hybrid-only offer succeeded, but the default offer got a classical group.")
        why = (h or {}).get("reason") or {"text": "The hybrid-only probe did not run."}
        return _verdict(
            "classical_observed", "3", "Observed once, from one OpenSSL client profile.",
            notes=[
                f"Hybrid-only probe: {why['text']}",
                "A failed hybrid-only probe does not prove the server lacks hybrid support; network filtering can cause it.",
            ],
        )
    return _verdict("inconclusive", "4", "The negotiated group was not recognized.",
                    reason={"code": "anomaly", "text": f"Unrecognized group {d['group']!r}."})


def assemble(scan, problem=None):
    probes = scan.get("probes") or {}
    d = probes.get("default") or {}
    scan["cert"] = {"key_class": _key_class(d.get("sig_type")), "verified": d.get("outcome") == "ok"}
    scan["verdict"] = _decide(probes, problem)
    scan["pq_note"] = (
        "The key agreement decides whether recorded traffic can be unlocked later. "
        "The certificate proves who the server is; it does not decide that risk."
    )
    scan["footer"] = f"One vantage point, one time, three offers from one OpenSSL build ({scan['client_profile']})."
    return scan
