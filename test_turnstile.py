#!/bin/python3
"""WSGI Turnstile test server."""
from __future__ import annotations
import contextlib
import getopt
import mimetypes
import os
import sys
from wsgiref.simple_server import make_server
if sys.version_info >= (3, 11):
    from wsgiref.types import WSGIApplication, WSGIEnvironment, StartResponse
else:
    from turnstile_mw import WSGIApplication, WSGIEnvironment, StartResponse
from typing import TextIO
from turnstile_mw import TurnstileMiddleware, SITE_KEY_LENGTH, SECRET_KEY_LENGTH, is_direct_fetch

# testing site keys:
SITE_KEYS = {
    "visible_pass": "1x00000000000000000000AA",
    "visible_fail": "2x00000000000000000000AB",
    "invisible_pass": "1x00000000000000000000BB",
    "invisible_fail": "2x00000000000000000000BB",
    "visible_interactive": "3x00000000000000000000FF",
}

# testing secret keys:
SECRET_KEYS = {
    "pass": "1x0000000000000000000000000000000AA",
    "fail": "2x0000000000000000000000000000000AA",
    "spent": "3x0000000000000000000000000000000AA",
}

# default configuration:
HOSTNAME = "localhost"
PORT = 8000
DEFAULT_SITE_KEY = "visible_pass"
DEFAULT_SECRET_KEY = "pass"
DEFAULT_BASE_PATH = "html"


class ExistsMiddleware(WSGIApplication):
    """Check early for path's existence."""

    def __init__(self, app: WSGIApplication, base_path: str = DEFAULT_BASE_PATH) -> None:
        """Check file's existence."""
        self.app = app
        self.base_path = base_path

    def __call__(self, environ: WSGIEnvironment, start_response: StartResponse) -> list[bytes]:
        """Generate error if file doesn't exist."""
        path_info = os.path.normpath(environ["PATH_INFO"])
        path = self.base_path + path_info
        if path_info.startswith(".") or not os.path.exists(path):
            start_response("404 Not found", [("Content-Type", "text/plain")])
            return []
        return self.app(environ, start_response)


class WSGIApp(WSGIApplication):
    """Serve existing files.

    Should be paired with ExistsMiddleware.
    """

    def __init__(self, base_path: str = DEFAULT_BASE_PATH) -> None:
        """Create WSGI application."""
        self.base_path = base_path

    def __call__(self, environ: WSGIEnvironment, start_response: StartResponse) -> list[bytes]:
        """Show file."""
        path_info = os.path.normpath(environ["PATH_INFO"])
        path = self.base_path + path_info
        mime_type = mimetypes.guess_type("file://" + path)[0]
        if not mime_type:
            mime_type = "application/octet-stream"
        start_response("200 OK", [("Content-Type", mime_type)])
        with open(path, "rb") as f:
            return [f.read()]
        return [b""]


def usage(file: TextIO = sys.stderr) -> None:
    """Show usage."""
    print(f"usage: {sys.argv[0]} [-?|--help] [-b|--base path] [-h|--host hostname] [-p|--port port] [-s|--site site_key] [-S|--secret secret_key]", file=file)
    print(file=file)
    print(f"   site_key must be a {SITE_KEY_LENGTH} byte string or one of:",
          " ".join(f"'{s}'" for s in SITE_KEYS), file=file)
    print(f"   secret_key must be a {SECRET_KEY_LENGTH} byte string or one of:",
          " ".join(f"'{s}'" for s in SECRET_KEYS), file=file)
    print(f"   default hostname: '{HOSTNAME}'", file=file)
    print(f"   default port: {PORT}", file=file)
    print(f"   default site_key: '{DEFAULT_SITE_KEY}'", file=file)
    print(f"   default secret_key: '{DEFAULT_SECRET_KEY}'", file=file)


def main() -> None:
    """Run simple test server."""
    hostname = HOSTNAME
    port = PORT
    site_key = DEFAULT_SITE_KEY
    secret_key = DEFAULT_SECRET_KEY
    base_path = DEFAULT_BASE_PATH
    try:
        opts, args = getopt.getopt(sys.argv[1:], "?b:h:p:s:S:", ["help", "host=", "port=", "site=", "secret="])
    except getopt.GetoptError as err:
        print(f"error: {err}", file=sys.stderr)
        usage()
        raise SystemExit(2) from None
    if args:
        print("error: too many arguments", file=sys.stderr)
        usage()
        raise SystemExit(2)
    for opt, arg in opts:
        if opt in ["-?", "--help"]:
            usage(sys.stdout)
            raise SystemExit(0)
        if opt in ["-b", "--base"]:
            base_path = arg
        elif opt in ["-h", "--host"]:
            hostname = arg
        elif opt in ["-p", "--port"]:
            port = int(arg)
        elif opt in ["-s", "--site"]:
            site_key = arg
        elif opt in ["-S", "--secret"]:
            secret_key = arg

    print("Site key:", site_key)
    print("Secret key:", secret_key)
    site_key = SITE_KEYS.get(site_key, site_key)
    secret_key = SECRET_KEYS.get(secret_key, secret_key)
    if len(site_key) != SITE_KEY_LENGTH:
        print(f"error: invalid site key '{site_key}'", file=sys.stderr)
        raise SystemExit(2)
    if len(secret_key) != SECRET_KEY_LENGTH:
        print("error: invalid secret key '{secret_key}'", file=sys.stderr)
        raise SystemExit(2)
    print(f"Serving files from {base_path}")

    app = ExistsMiddleware(
            TurnstileMiddleware(
                WSGIApp(base_path),
                site_key.encode(), secret_key.encode(), pass_thru=is_direct_fetch,
            ), base_path)

    server = make_server(hostname, port, app)
    print(f"Serving HTTP on {hostname} port {port}...")

    # Respond to requests until interupted
    with contextlib.suppress(KeyboardInterrupt):
        server.serve_forever()


if __name__ == "__main__":
    main()
