"""Only the Harvest Lab page itself may call the API.

Binding to 127.0.0.1 is not enough: any web page open in the same browser can
send requests to 127.0.0.1:8000. So every request must carry an exact Host
header we expect, and a browser Origin (if present) must be our own page.
Johan adds it in main.py:  app.add_middleware(LocalOnlyGuard)
"""
import json

DEFAULT_HOSTS = ("127.0.0.1:8000", "localhost:8000")


class LocalOnlyGuard:
    def __init__(self, app, allowed_hosts=DEFAULT_HOSTS):
        self.app = app
        self.hosts = set(allowed_hosts)
        self.origins = {f"http://{h}" for h in allowed_hosts}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        problem = None
        if headers.get("host") not in self.hosts:
            problem = "Requests must use http://127.0.0.1:8000."
        elif "origin" in headers and headers["origin"] not in self.origins:
            problem = "Requests from other web pages are not allowed."
        elif headers.get("sec-fetch-site") == "cross-site":
            problem = "Requests from other web pages are not allowed."
        if problem is None:
            return await self.app(scope, receive, send)

        body = json.dumps({"error": {"code": "invalid_request", "message": problem}}).encode()
        await send({
            "type": "http.response.start",
            "status": 403,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
        })
        await send({"type": "http.response.body", "body": body})
