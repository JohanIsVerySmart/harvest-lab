"""Scan and lab routes. Johan's backend/main.py includes `router`.

Plain synchronous handlers: FastAPI runs them on its thread pool, and the
scan module allows one scan at a time.
"""
import importlib
from typing import Literal

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from backend.scan import probes
from backend.scan.hostcheck import ScanRejected
from backend.scan.openssl_env import OpenSSLUnavailable
from lab.labctl import LAB, LabError

try:  # Johan's truth table; the interim one only while his file is missing
    _verdict_module = importlib.import_module("backend.scan.verdict")
except ModuleNotFoundError as exc:
    if exc.name != "backend.scan.verdict":
        raise  # his file exists but is broken: fail loudly, never fall back
    _verdict_module = importlib.import_module("backend.scan.interim")
assemble = _verdict_module.assemble

router = APIRouter(prefix="/api/v1")

_STATUS = {
    "invalid_host": 400,
    "blocked_address": 422,
    "ipv6_only_unsupported": 422,
    "no_public_ipv4": 422,
    "invalid_request": 422,
    "lab_switching": 409,
    "client_unavailable": 503,
    "internal": 500,
}


def error(code, message):
    return JSONResponse(status_code=_STATUS[code], content={"error": {"code": code, "message": message}})


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")  # a "port" field is rejected
    host: str


class ModeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["classical", "hybrid", "stop"]


def _run_scan(scan_fn, *args):
    try:
        scan, problem = scan_fn(*args)
    except ScanRejected as exc:
        return error(exc.code, exc.message)
    except OpenSSLUnavailable as exc:
        return error("client_unavailable", str(exc))
    except probes.ScanBusy as exc:
        return error("internal", str(exc))
    return assemble(scan, problem)


@router.post("/scan")
def scan_public(body: ScanRequest):
    return _run_scan(probes.scan_public, body.host)


@router.post("/lab/scan")
def scan_lab():
    return _run_scan(probes.scan_lab)


@router.post("/lab/mode")
def lab_mode(body: ModeRequest):
    try:
        return LAB.set_mode(body.mode)
    except LabError as exc:
        return error(exc.code, exc.message)
    except OpenSSLUnavailable as exc:
        return error("client_unavailable", str(exc))


@router.get("/lab/status")
def lab_status():
    return LAB.status()
