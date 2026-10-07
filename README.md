WSGI Middleware for Cloudflare Turnstile
========================================

TurnstileMiddleware implements the Cloudflare Turnstile challenge
algorithm in WSGI middleware.  The middleware intercepts GET requests
and sends specially crafted HTML to get a single use Cloudflare
Turnstile token.  Successfully getting that token causes a reload (a GET
request) of same URL with the token given to the server via a cookie.
The middleware sees that cookie, and if token verifies, falls through
to the next middleware/application.


When should the Turnstile challenge be skipped?
-----------------------------------------------

By default, the TurnstileMiddleware skips the Turnstile protocol in these
cases:

* If the user has authenticated with the web server
  - avoid rechecked users you know
* If the request is from a private (unrouted) network
  - not from the Internet, so any bot access is from your bot
* If the request is for an image, audio, video, or JSON
  - Turnstile requires JavaScript to work.  So it can't be used if the
    HTTP request won't be interpreted as HTML.

An alternate "pass_thru" function should be written if any of the
above assumptions are incorrect or insufficient.


Future Improvements
-------------------

It would be nice to allow a single Turnstile challenge to authorize
multiple URL requests.  To do that, the server would need to issue a
time-limited (cryptographically signed) session cookie after a successful
challenge.  And then check that cookie on the subsequent requests.  If it
has expired, then reissue a Turnstile challenge, otherwise pass through.


References
----------

* [Cloudflare Turnstile](https://www.cloudflare.com/products/turnstile/)
* [Turnstile Developer Documentation](https://developers.cloudflare.com/turnstile/)
* [PEP 3333](https://peps.python.org/pep-3333/) – Python Web Server Gateway Interface
