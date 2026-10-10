"""Johan can include this router; global Reset must also call reset_booth()."""

import os

from fastapi import APIRouter
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute

from .group import BoothError
from .runner import Booth

class BoothRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def guarded(request):
            try:
                return await handler(request)
            except (RequestValidationError, RecursionError, UnicodeError):
                return JSONResponse(status_code=422, content={"error": {
                    "code": "invalid_request", "message": "Provide a valid booth request."}})
        return guarded


booth = Booth(bits=int(os.environ.get("HARVEST_BOOTH_BITS", "40")))
router = APIRouter(prefix="/api/v1/booth", tags=["booth"], route_class=BoothRoute)


def error_response(exc):
    status = {"attack_running": 409, "no_session": 404, "invalid_request": 422}.get(exc.code, 500)
    return JSONResponse(status_code=status, content={"error": {"code": exc.code, "message": str(exc)}})


@router.post("/send")
def send_messages(body: dict):
    try:
        if not {"classical_message", "hybrid_message"} <= set(body) or set(body) - {"classical_message", "hybrid_message", "bits"}:
            raise BoothError("invalid_request", "Provide classical_message and hybrid_message fields.")
        if "bits" in body and (type(body["bits"]) is not int or body["bits"] not in (36, 40)):
            raise BoothError("invalid_request", "Choose a 36- or 40-bit toy modulus.")
        sent = booth.send(body["classical_message"], body["hybrid_message"], body.get("bits"))
        sizes = {}
        for channel, record in sent["transcript"]["channels"].items():
            width = (sent["bits"] + 7) // 8
            m1 = 3 * width + (1184 if channel == "hybrid" else 0)
            m2 = width + (1088 if channel == "hybrid" else 0)
            m3 = 12 + len(record["M3"]["aead_ct"]) // 2
            sizes[channel] = {"m1": m1, "m2": m2, "m3": m3, "total": m1 + m2 + m3}
        return {"session": sent["transcript"]["session"], "bits": sent["bits"], "p_bits": sent["bits"],
                "kem": {"library": "cryptography", "version": "50.0.2"},
                "warnings": ["same_plaintext"] if body["classical_message"] == body["hybrid_message"] else [],
                "wire_bytes": sizes, "transcript": sent["transcript"],
                "transcript_sha256": sent["transcript_sha256"],
                "legit": {"classical": {"ok": sent["legit_classical_ok"]},
                          "hybrid": {"ok": sent["legit_hybrid_ok"]}}}
    except BoothError as exc:
        return error_response(exc)
    except Exception:
        return JSONResponse(status_code=500, content={"error": {"code": "internal", "message": "Sending failed. Reset and try again."}})


@router.post("/qday")
def qday(body: dict):
    try:
        if set(body) != {"session"} or not isinstance(body["session"], str):
            raise BoothError("invalid_request", "Provide the recording session identifier.")
        result = booth.qday(body["session"])
        verdict = {field: result[field] for field in ("legit_classical_ok", "legit_hybrid_ok",
                   "attacker_classical_ok", "hybrid_exception", "errors", "demo_verdict")}
        return {"session": body["session"], "bits": result["bits"],
                "real_ms": result["total_ms"], "events": result["events"], "verdict": verdict}
    except BoothError as exc:
        return error_response(exc)
    except Exception:
        return JSONResponse(status_code=500, content={"error": {"code": "internal", "message": "The attack failed. Reset and try again."}})


def reset_booth():
    """Call from Johan's /api/v1/reset alongside the lab reset."""
    return booth.reset()
