"""Turnstile WSGI Middleware.

TurnstileMiddleware implements the Cloudflare Turnstile algorithm as
WSGI middleware.  The middleware intercepts GET requests and sends
specially crafted HTML back to get a Cloudflare Turnstile token.
Sucessfully getting that token causes a reload (a GET request) of same
URL with the token given via a cookie.  The middleware sees that GET,
and if token verifies, falls through to the next middleware/application.

By default, Turnstile challenges are skipped for requests with authenticated
users, from private networks, and for image, audio, video, and json requests.
"""
from __future__ import annotations
import ipaddress
from http.cookies import SimpleCookie
import mimetypes
import re
import sys
import typing
import urllib.parse
import uuid
import requests
if sys.version_info >= (3, 11):
    from wsgiref.types import WSGIApplication, WSGIEnvironment, StartResponse
else:
    class WSGIEnvironment:
        """Placeholder."""
    class StartResponse:
        """Placeholder."""
    class WSGIApplication:
        """Placeholder."""
# compression packages
try:
    import brotli
    HAS_BROTLI = True
except ImportError:
    HAS_BROTLI = False
try:
    import gzip
    HAS_GZIP = True
except ImportError:
    HAS_GZIP = False
try:
    import zlib
    HAS_ZLIB = True
except ImportError:
    HAS_ZLIB = False
try:
    from compression import zstd
    HAS_ZSTD = True
except ImportError:
    try:
        import zstandard as zstd
        HAS_ZSTD = True
    except ImportError:
        HAS_ZSTD = False

SITE_KEY_LENGTH = 24
"""Length of Turnstile site key."""
SECRET_KEY_LENGTH = 35
"""Length of Turnstile secret key."""

SAFE_NETWORKS = {
    # Don't use Turnstile for local accesses
    # localhost
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv6Network("::1/128"),
    # private networks
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv6Network("fc00::/7"),
}
"""Networks to skip Turnstile check on."""

DIRECT_FETCH = {
    "audio",
    "image",
    "video",
}
"""Mime type (not including subtype) to skip Turnstile check on."""

COOKIE_NAME = "snafu"
"""Cookie used to store Turnstile token."""

CHALLENGE = b"""\
<html lang="en">
<head>
  <meta charset="UTF-8">
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit" defer></script>
</head>
<body>
  <noscript>Enable JavaScript to see content</noscript>
  <div id="w"></div>
  <script>
    onload = function() {
      c = console;
      turnstile.render(w, {
        sitekey: "SITE_KEY",
        callback: function(t) {
          document.cookie = `%s=${encodeURIComponent(t)}; max-age=1; path=/; samesite=strict`;
          location.reload()
        },
        "error-callback": function(e) {
          c.log("Error:", e)
        },
        "expired-callback": function() {
          c.log("Token expired")
        },
        "timeout-callback": function() {
          c.log("Timed out")
        },
        "unsupported-callback": function() {
          c.log("Unsupported browswer")
        }
      })
    }
  </script>
</body>
</html>
""" % (COOKIE_NAME.encode(),)


def is_safe_network(environ: WSGIEnvironment) -> bool:
    """Return if request is from a safe network.

    Checks if IP address is in :py:data:`SAFE_NETWORKS`.
    By default, private networks, and localhost are safe.
    """
    client_ip = ipaddress.ip_address(environ.get("REMOTE_ADDR"))
    return any(client_ip in network for network in SAFE_NETWORKS)


def is_user_authenticated(environ: WSGIEnvironment) -> bool:
    """Return if connection is authenticated by web server."""
    return bool(environ.get("REMOTE_USER"))


def is_direct_fetch(environ: WSGIEnvironment) -> bool:
    """Check if directly fetching into an image/audio/video.

    Turnstile will fail to work if the response won't be interpreted
    as HTML (i.e., no JavaScript support).  Since the mime types of
    the URL are guessed, most of possible Sec-Fetch-Dest values are
    not supported.  So an alternative may need to be implemented for
    your setup.
    """
    sec_fetch_dest = environ.get("HTTP_SEC_FETCH_DEST", "").lower()
    if sec_fetch_dest in DIRECT_FETCH:
        path_info = environ["PATH_INFO"]
        mime_type = mimetypes.guess_type("file://" + path_info)[0]
        if mime_type:
            mtype, subtype = mime_type.split("/")
            if sec_fetch_dest == mtype:
                # URL's mimetype matches what was requested
                return True
            if sec_fetch_dest == "json" and subtype == "json":
                return True
    return False


def default_pass_thru(environ: WSGIEnvironment) -> bool:
    """Provide default pass through function.

    Skip Turnstile challenge on (a) authenticated connections,
    (b) direct fetching of audio, video, images, and JSON,
    (c) on safe networks.
    """
    return is_user_authenticated(environ) or is_direct_fetch(environ) or is_safe_network(environ)


class TurnstileMiddleware(WSGIApplication):
    """Turnstile WSGI Middleware.

    Arguments are the Turnstile site key, secret key, and an optional
    a pass through function that is used to decide when the Turnstile
    challenge should be skipped.
    """

    TIMEOUT = 10      # how many seconds to wait for Cloudflare to respond
    MAX_RETRIES = 3   # how many times to retry validation request

    def __init__(self, app: WSGIApplication, site_key: bytes, secret_key: bytes, pass_thru: typing.Callable[[WSGIEnvironment], bool] = default_pass_thru) -> None:
        """Create middleware."""
        if len(site_key) != SITE_KEY_LENGTH:
            msg = "site_key is wrong length"
            raise ValueError(msg)
        if len(secret_key) != SECRET_KEY_LENGTH:
            msg = "secret_key is wrong length"
            raise ValueError(msg)
        self.app = app
        self.site_key = site_key
        self.secret_key = secret_key
        self.pass_thru = pass_thru
        # minify challenge
        trailing_space = re.compile(rb"([>){},:;=]) ")
        chall = CHALLENGE.replace(b"SITE_KEY", site_key).replace(b" =", b"=")
        self.challenge = trailing_space.sub(lambda t: t.group(1), b" ".join(chall.split()))
        # compressed challenges — compress once, reuse many times
        self.compressed_challenge = {}
        self.compression_order = []
        if HAS_GZIP:
            self.compression_order.append("gzip")
            self.compressed_challenge["gzip"] = gzip.compress(self.challenge, compresslevel=9)
        if HAS_ZLIB:
            self.compression_order.append("deflate")
            if sys.version_info >= (3, 11):
                self.compressed_challenge["deflate"] = zlib.compress(
                    self.challenge, level=zlib.Z_BEST_COMPRESSION, wbits=-zlib.MAX_WBITS)
            else:
                compressor = zlib.compressobj(zlib.Z_BEST_COMPRESSION, wbits=-zlib.MAX_WBITS)
                data = compressor.compress(self.challenge)
                data += compressor.flush()
                self.compressed_challenge["deflate"] = data
        if HAS_BROTLI:
            self.compression_order.append("br")
            self.compressed_challenge["br"] = brotli.compress(self.challenge)
        if HAS_ZSTD:
            self.compression_order.append("zstd")
            self.compressed_challenge["zstd"] = zstd.compress(self.challenge)
        # sort so smallest compressed challenge is last, aka, best
        self.compression_order.sort(key=lambda x: -len(self.compressed_challenge[x]))

    def __call__(self, environ: WSGIEnvironment, start_response: StartResponse) -> bytes:
        """Implement Turnstile protocol."""
        if self.pass_thru and self.pass_thru(environ):
            return self.app(environ, start_response)
        method = environ["REQUEST_METHOD"]
        if method != "GET":
            # not my problem...
            return self.app(environ, start_response)
        compressed = ""
        cookies = SimpleCookie()
        cookies.load(environ.get("HTTP_COOKIE", ""))
        if COOKIE_NAME not in cookies:
            status = "200 OK"
            content_type = "text/html; charset=utf-8"
            compressed = self.get_content_encoding(environ)
            if compressed:
                response_body = [self.compressed_challenge[compressed]]
            else:
                response_body = [self.challenge]
        else:
            try:
                self.verify_request(environ, cookies[COOKIE_NAME].value)
                return self.app(environ, start_response)
            except (RuntimeError, Exception) as err:
                response_body = [
                    b"Verification failed: ",
                    str(err).replace("-", " ").encode(errors="replace"),
                ]
            status = "400 Bad Request"
            content_type = "text/plain"

        headers = [
            ("Content-Type", content_type),
            ("Content-Length", str(sum(len(r) for r in response_body))),
        ]
        if compressed:
            headers.append(("Content-Encoding", compressed))
        start_response(status, headers)
        return response_body

    def verify_request(self, environ: WSGIEnvironment, token: str) -> None:
        """Verify Cloudflare Turnstile token."""
        token = urllib.parse.unquote(token)
        user_ip = environ.get("REMOTE_ADDR")

        # Validate against Cloudflare
        count = 0
        idempotency_key = str(uuid.uuid4())
        while count < self.MAX_RETRIES:
            try:
                response = requests.post(
                    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                    data={
                        "secret": self.secret_key,
                        "response": token,
                        "remoteip": user_ip,
                        "idempotency_key": idempotency_key,
                    },
                    timeout=self.TIMEOUT,
                )
                response.raise_for_status()
            except requests.exceptions.ConnectTimeout:
                info = {
                    "success": False,
                    "error-codes": ["Unable to connect to Cloudflare Turnstile"],
                }
            except requests.exceptions.ReadTimeout:
                info = {
                    "success": False,
                    "error-codes": ["Response from Cloudflare timed out"],
                }
            except requests.exceptions.RequestException as err:
                info = {
                    "success": False,
                    "error-codes": [str(err)],
                }
            else:
                info = response.json()
                if info.get("success", False):
                    return
                break
            count += 1
        error_codes = info.get("error-codes")
        if not error_codes:
            error_codes = ["unknown error"]
        msg = " ".join(e for e in error_codes)
        raise RuntimeError(msg)

    def get_content_encoding(self, environ: WSGIEnvironment) -> str:
        """Find preferred compression encoding for challenge response.

        Parse Accept-Encoding header with q weights.  Find compression encodings that
        are supported and return the best one.
        """
        accept_encoding = environ.get("HTTP_ACCEPT_ENCODING", "")
        if not accept_encoding:
            return ""
        encodings = [[x.strip() for x in encoding.split(";", 1)] for encoding in accept_encoding.split(",")]
        ordered = []
        for e_w in encodings:
            if len(e_w) == 1 or not e_w[1].startswith("q="):
                weight = 1.0
            else:
                try:
                    weight = float(e_w[1].split("=", 1)[1])
                except ValueError:
                    weight = 1.0
            if weight <= 0:
                continue
            try:
                c_index = self.compression_order.index(e_w[0])
            except ValueError:
                c_index = -1
            if c_index == -1:
                continue
            ordered.append((weight, c_index))
        if not ordered:
            return ""
        ordered.sort()
        return self.compression_order[ordered[-1][1]]
