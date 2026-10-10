"""DEV ONLY: run the scan + lab routes without Johan's main.py.

    python -m backend.scan.devserver

The real app is backend/main.py (Johan). This file shows the four things
main.py needs from teammate A, in order:
  1. refuse to start unless the OpenSSL gate passes
  2. LAB.startup() to clean up a lab server left by a crashed run
  3. LocalOnlyGuard middleware + a 422 invalid_request handler for bad bodies
  4. include `router`
"""
import sys
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from backend.scan.api import router
from backend.scan.localguard import LocalOnlyGuard
from backend.scan.openssl_env import OpenSSLUnavailable, check_openssl
from lab.labctl import LAB, LabError


@asynccontextmanager
async def lifespan(app):
    LAB.startup()
    try:
        LAB.set_mode("classical")
    except LabError as exc:
        print(f"Lab not started: {exc.message}")
    yield
    LAB.shutdown()


app = FastAPI(lifespan=lifespan)
app.add_middleware(LocalOnlyGuard)


@app.exception_handler(RequestValidationError)
def bad_body(request, exc):
    return JSONResponse(
        status_code=422,
        content={"error": {"code": "invalid_request", "message": "The request body is not valid for this endpoint."}},
    )


@app.get("/api/v1/health")
def health():
    try:
        info = check_openssl()
    except OpenSSLUnavailable as exc:
        return {"ok": False, "problems": [str(exc)]}
    return {
        "ok": True,
        "openssl": {"version": info["version"], "path": info["path"], "ok": True},
        "trace_supported": info["trace_supported"],
        "ca_file": info["ca_file"],
    }


app.include_router(router)


if __name__ == "__main__":
    try:
        info = check_openssl()
    except OpenSSLUnavailable as exc:
        sys.exit(f"REFUSING TO START: {exc}")
    print(f"Using {info['version']} at {info['path']}")
    uvicorn.run(app, host="127.0.0.1", port=8000, workers=1)
