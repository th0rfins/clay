#!/usr/bin/env python3
"""zentor.ai — multi-account manager (TUI)."""

import json, hashlib, base64, secrets, time, sys, re, os
import urllib.parse
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from http.cookiejar import CookieJar

# --- config ---
# moclaw.ai rebranded to zentor.ai; auth host/audience/redirect changed, OAuth
# client_id is unchanged. ZENTOR_* mirrors the old MOCLAW_* names.
SITE = os.environ.get("ZENTOR_SITE", "https://zentor.ai")
AUTH_DOMAIN = "https://auth.zentor.ai"
API_BASE = "https://api.zentor.ai"
AUDIENCE = os.environ.get("ZENTOR_AUDIENCE", API_BASE)
CLIENT_ID = "R7QyN3rYIv2DSEqkgQJjfSvvb6XFxMOu"
REDIRECT_URI = f"{SITE}/auth/callback"
TMAIL_BASE = "https://tmail.perkutut.web.id"

MOCLAW_DIR = Path(os.environ.get("MOCLAW_DIR", str(Path.home() / ".zentor")))
ACCOUNTS_FILE = MOCLAW_DIR / "accounts.json"
CURRENT_FILE = MOCLAW_DIR / "current.txt"

# --- HTTP ---
def _post(url, data):
    body = urllib.parse.urlencode(data).encode()
    req = Request(url, data=body, method="POST",
                  headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urlopen(req, timeout=10) as r:
        return json.loads(r.read())

def _post_json(url, data, token=None, timeout=30):
    body = json.dumps(data or {}).encode()
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0",
        "Origin": SITE,
        "Referer": SITE + "/",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(url, data=body, method="POST", headers=headers)
    with urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())

def _get(url, token):
    req = Request(url, headers={
        "Authorization": f"Bearer {token}",
        "User-Agent": "Mozilla/5.0",
        "Origin": SITE,
        "Referer": SITE + "/",
    })
    with urlopen(req, timeout=10) as r:
        return json.loads(r.read())

# --- storage ---
def _load_accounts():
    if ACCOUNTS_FILE.exists():
        return json.loads(ACCOUNTS_FILE.read_text())
    return {}

def _save_accounts(accounts):
    MOCLAW_DIR.mkdir(parents=True, exist_ok=True)
    ACCOUNTS_FILE.write_text(json.dumps(accounts, indent=2))

def _get_current():
    if CURRENT_FILE.exists():
        return CURRENT_FILE.read_text().strip()
    return "default"

def _set_current(name):
    MOCLAW_DIR.mkdir(parents=True, exist_ok=True)
    CURRENT_FILE.write_text(name)

def _get_account(name=None):
    if name is None:
        name = _get_current()
    accounts = _load_accounts()
    if name not in accounts:
        raise RuntimeError(f"Account '{name}' not found")
    return accounts[name]

def _save_account(name, session):
    accounts = _load_accounts()
    accounts[name] = session
    _save_accounts(accounts)

# --- auth ---
def _token_body(data):
    """Return the token payload from either flat or nested OAuth JSON."""
    body = data.get("body", data) if isinstance(data, dict) else {}
    if isinstance(body, dict) and isinstance(body.get("body"), dict):
        body = body["body"]
    return body if isinstance(body, dict) else {}


def _expiry_seconds(value, default=None):
    """Normalize expiresAt values expressed in seconds or milliseconds."""
    if value is None:
        return default
    value = float(value)
    if value > 10_000_000_000:  # JavaScript millisecond timestamp
        value /= 1000
    return value


def _jwt_expiry(access_token):
    """Read JWT exp without verifying it; only used as an expiry hint."""
    try:
        payload = access_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload).decode())
        return _expiry_seconds(claims.get("exp"))
    except (ValueError, IndexError, KeyError, UnicodeDecodeError,
            json.JSONDecodeError, TypeError):
        return None


def _session_from_token_response(data, previous=None):
    """Build a local session from an OAuth response and preserve rotation data."""
    previous = previous or {}
    body = _token_body(data)
    access_token = body.get("access_token")
    if not access_token:
        raise RuntimeError("No access_token found in token response")

    expires_at = _expiry_seconds(
        data.get("expiresAt") if isinstance(data, dict) else None,
        None,
    )
    if expires_at is None and body.get("expires_at") is not None:
        expires_at = _expiry_seconds(body["expires_at"], None)
    jwt_expires_at = _jwt_expiry(access_token)
    if jwt_expires_at is not None:
        expires_at = jwt_expires_at
    if expires_at is None:
        expires_at = time.time() + float(body.get("expires_in", 86400))

    session = dict(previous)
    session.update({
        "access_token": access_token,
        "token_type": body.get("token_type", previous.get("token_type", "Bearer")),
        "_expires_at": expires_at,
    })
    # OAuth token rotation may omit refresh_token; keep the old one then.
    refresh_token = body.get("refresh_token") or previous.get("refresh_token")
    if refresh_token:
        session["refresh_token"] = refresh_token
    return session


def import_from_json(name, json_str):
    """Parse localStorage JSON and extract tokens automatically."""
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON: {e}")

    session = _session_from_token_response(data)
    _save_account(name, session)
    _set_current(name)
    print(f"✓ Account '{name}' imported. Refresh: {'Yes' if session.get('refresh_token') else 'No'}")

def add_account(name, token):
    """Add account with access token only."""
    session = {"access_token": token, "token_type": "Bearer", "_expires_at": time.time() + 86400}
    _save_account(name, session)
    _set_current(name)
    print(f"✓ Account '{name}' added")

def _simulated_token(prefix):
    """Create an intentionally invalid token for local refresh-flow testing."""
    stamp = str(int(time.time()))
    return f"simulated-{prefix}-{stamp}-{secrets.token_urlsafe(18)}"


def refresh(name=None, simulate=False):
    """Refresh access token, or simulate token rotation for local testing."""
    if name is None:
        name = _get_current()
    session = _get_account(name)
    if not session.get("refresh_token"):
        raise RuntimeError(f"Account '{name}' has no refresh token")

    if simulate:
        new = {
            "access_token": _simulated_token("access"),
            "refresh_token": _simulated_token("refresh"),
            "token_type": "Bearer",
            "expires_in": 86400,
        }
        updated = _session_from_token_response(new, session)
        _save_account(name, updated)
        print(f"✓ [SIMULATED] Access/refresh token rotated for '{name}'")
        return updated

    response = _post(f"{AUTH_DOMAIN}/oauth/token", {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "refresh_token": session["refresh_token"],
    })
    updated = _session_from_token_response(response, session)
    _save_account(name, updated)
    print(f"✓ Token refreshed for '{name}'")
    return updated

# --- tmail mailbox / email-OTP auto-login ---
def _tmail(method, path, data=None):
    """Raw tmail API call; returns parsed JSON (dict/list or None)."""
    body = json.dumps(data).encode() if data is not None else None
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Origin": TMAIL_BASE,
        "Referer": TMAIL_BASE + "/",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = Request(TMAIL_BASE + path, data=body, method=method, headers=headers)
    try:
        with urlopen(req, timeout=30) as r:
            raw = r.read()
            return json.loads(raw) if raw else None
    except HTTPError as e:
        raw = e.read()
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            raise RuntimeError(f"tmail API error {e.code}: {raw[:160]!r}")


def create_mailbox(local_part=None, domain=None):
    """Create a fresh tmail mailbox; returns (address, token)."""
    data = {}
    if local_part:
        data["local_part"] = local_part
    if domain:
        data["domain"] = domain
    mb = _tmail("POST", "/v1/addresses", data) or {}
    if not mb.get("address") or not mb.get("token"):
        raise RuntimeError(f"tmail: unexpected create response: {mb}")
    return mb["address"], mb["token"]


def _split_email(spec):
    """Split a custom email into (local_part, domain). Bare name is allowed."""
    spec = spec.strip()
    if "@" in spec:
        local, _, domain = spec.partition("@")
        if not local or not domain:
            raise RuntimeError(f"bad email: {spec}")
        return local, domain
    return spec or None, None


def _message_ids(tmail_token):
    """Ids of messages currently present in the tmail mailbox."""
    data = _tmail("GET", f"/v1/a/{tmail_token}/messages") or {}
    return {m["id"] for m in data.get("messages", [])}


def _pkce_pair():
    """Return (verifier, S256 challenge) for Auth0's PKCE flow."""
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


class _FlowRedirect(Exception):
    def __init__(self, url):
        self.url = url


class _NoFollowHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise _FlowRedirect(newurl)


class _OAuthFlow:
    """Auth0 universal-login HTTP client that captures redirects instead of following them."""

    def __init__(self):
        self._jar = CookieJar()
        self._opener = urllib.request.build_opener(
            _NoFollowHandler, urllib.request.HTTPCookieProcessor(self._jar))

    def request(self, url, data=None, headers=None):
        h = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin" if data is not None else "none",
            "Sec-Fetch-User": "?1" if data is not None else None,
        }
        h = {k: v for k, v in h.items() if v is not None}
        if data is not None:
            h["Content-Type"] = "application/x-www-form-urlencoded"
        if headers:
            h.update(headers)
        req = Request(url, data=data, headers=h,
                      method="POST" if data is not None else "GET")
        try:
            with self._opener.open(req, timeout=30) as r:
                return ("ok", dict(r.headers), r.read())
        except _FlowRedirect as rd:
            return ("redir", rd.url, None)
        except HTTPError as e:
            return ("http", e.code, e.read())


def _build_authorize_url(verifier=None):
    """Build PKCE authorize URL for manual browser login. Returns (url, verifier)."""
    if verifier is None:
        verifier, challenge = _pkce_pair()
    else:
        _, challenge = _pkce_pair()  # never reuse: recompute below
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).rstrip(b"=").decode()
    params = urllib.parse.urlencode({
        "client_id": CLIENT_ID,
        "scope": "openid profile email offline_access",
        "audience": AUDIENCE,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "response_mode": "query",
        "state": secrets.token_urlsafe(16),
        "nonce": secrets.token_urlsafe(16),
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    return f"{AUTH_DOMAIN}/authorize?{params}", verifier


def _pending_file(name):
    return MOCLAW_DIR / f"pending_{name}.json"


def login_browser_start(name, email=None):
    """Step 1: generate authorize URL, save verifier for later finish."""
    url, verifier = _build_authorize_url()
    MOCLAW_DIR.mkdir(parents=True, exist_ok=True)
    _pending_file(name).write_text(json.dumps({
        "verifier": verifier, "email": email, "created": time.time(),
    }))
    print(f"\n  Account: {name}")
    print(f"  Open this URL in your browser:\n\n     {url}\n")
    print("  Login sampai mendarat di zentor.ai/auth/callback?code=...")
    print(f"  Lalu selesaikan via menu 'Finish login via URL' atau:\n     python3 zentor.py login-browser {name} --code <CALLBACK_URL|CODE>")
    return url


def _extract_code(raw):
    raw = (raw or "").strip()
    if not raw:
        return None
    if "code=" in raw:
        return urllib.parse.parse_qs(urllib.parse.urlparse(raw).query).get("code", [None])[0]
    return raw


def login_browser_finish(name, raw, email=None):
    """Step 2: exchange callback URL/code using saved verifier."""
    code = _extract_code(raw)
    if not code:
        raise RuntimeError("no auth code provided")
    pf = _pending_file(name)
    if not pf.exists():
        raise RuntimeError(f"no pending login for '{name}' — run Step 1 first")
    saved = json.loads(pf.read_text())
    verifier = saved.get("verifier")
    if not verifier:
        raise RuntimeError(f"pending login for '{name}' corrupt — run Step 1 again")
    email = email or saved.get("email")
    token_body = _post(f"{AUTH_DOMAIN}/oauth/token", {
        "client_id": CLIENT_ID,
        "code_verifier": verifier,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
    })
    session = _session_from_token_response(token_body)
    if email:
        session["email"] = email
    _save_account(name, session)
    _set_current(name)
    try:
        pf.unlink()
    except OSError:
        pass
    print(f"✓ Account '{name}' logged in via browser.")
    return session


def login_via_browser(name, email=None, raw=None):
    """Manual login: user completes Auth0 (incl. Turnstile captcha) in a real
    browser, then pastes back the callback URL/code. Works when server-side
    automation is blocked with HTTP 400 / requires_verification.

    One-line mode (raw=None): show URL then prompt paste in same screen.
    Two-step mode: login_browser_start() then login_browser_finish().
    """
    if raw is not None:
        # Non-interactive: verifier must already exist from Step 1, else create
        # a fresh one only if pending missing is not an option — here we require it.
        return login_browser_finish(name, raw, email=email)
    url, verifier = _build_authorize_url()
    print(f"\n  1) Open this URL in your browser:\n\n     {url}\n")
    print("  2) Complete login (solve captcha if asked).")
    print("  3) You land on zentor.ai/auth/callback?code=... — copy the full URL.")
    raw = input("\n  Paste callback URL or code: ").strip()
    code = _extract_code(raw)
    if not code:
        raise RuntimeError("no auth code provided")
    token_body = _post(f"{AUTH_DOMAIN}/oauth/token", {
        "client_id": CLIENT_ID,
        "code_verifier": verifier,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
    })
    session = _session_from_token_response(token_body)
    if email:
        session["email"] = email
    _save_account(name, session)
    _set_current(name)
    print(f"✓ Account '{name}' logged in via browser.")
    return session


def _auth0_login(email, tmail_token, timeout=90):
    """Complete the Auth0 passwordless (email OTP) login, OTP read from tmail.

    NOTE: Auth0 New Universal Login now renders a Cloudflare Turnstile widget
    (data-captcha-provider="auth0_v2") on /u/login/identifier. Headless POSTs
    without a captcha token are rejected with HTTP 400, and /passwordless/start
    returns 401 requires_verification for flagged IPs. When that happens, use
    login_via_browser() instead — a real browser solves the captcha.
    """
    verifier, challenge = _pkce_pair()
    flow = _OAuthFlow()
    seen = _message_ids(tmail_token)

    params = urllib.parse.urlencode({
        "client_id": CLIENT_ID,
        "scope": "openid profile email offline_access",
        "audience": AUDIENCE,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "response_mode": "query",
        "state": secrets.token_urlsafe(16),
        "nonce": secrets.token_urlsafe(16),
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    kind, url, _ = flow.request(f"{AUTH_DOMAIN}/authorize?{params}")
    if kind != "redir":
        raise RuntimeError(f"login: authorize failed ({kind} {url})")

    kind, _, html = flow.request(url)
    m = re.search(r'name="state"[^>]*value="([^"]*)"', html.decode("utf-8", "replace"))
    state = m.group(1) if m else None
    if not state:
        raise RuntimeError("login: no state in login page")

    form = urllib.parse.urlencode({
        "state": state, "username": email,
        "js-available": "true", "webauthn-available": "true",
        "is-brave": "false", "webauthn-platform-available": "false",
        # Must match the primary <form data-form-primary>: the submit button is
        # <button name="action" value="default">Continue</button>, plus the
        # hidden Turnstile slot <input name="captcha" value="">.
        "action": "default",
        "captcha": "",
    }).encode()
    kind, url, body = flow.request(url, data=form, headers={
        "Origin": AUTH_DOMAIN, "Referer": url,
        "Content-Type": "application/x-www-form-urlencoded"})
    if kind != "redir":
        snippet = ""
        if isinstance(body, bytes):
            snippet = body.decode("utf-8", "replace")[:300].replace("\n", " ")
        raise RuntimeError(
            f"login: identifier step failed ({kind} {url}) {snippet}. "
            "Likely Turnstile captcha (auth0_v2) or bot-detection — "
            "use 'login-browser' and complete login in a real browser instead.")

    kind, _, html = flow.request(url)
    m = re.search(r'name="state"[^>]*value="([^"]*)"', html.decode("utf-8", "replace"))
    state = m.group(1) if m else None
    if not state:
        raise RuntimeError("login: no state in OTP page")

    otp = None
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = _tmail("GET", f"/v1/a/{tmail_token}/messages") or {}
        for msg in data.get("messages", []):
            if msg["id"] not in seen and msg.get("otp"):
                otp = msg["otp"]
                break
        if otp:
            break
        time.sleep(1.5)
    if not otp:
        raise RuntimeError(f"login: no OTP email arrived for {email} in {timeout}s")

    form = urllib.parse.urlencode({"state": state, "code": otp, "action": "default"}).encode()
    kind, url, body = flow.request(url, data=form, headers={
        "Origin": AUTH_DOMAIN, "Referer": url,
        "Content-Type": "application/x-www-form-urlencoded"})
    if kind != "redir":
        raise RuntimeError(f"login: OTP rejected ({kind}): {body[:200] if body else ''}")

    kind, url, _ = flow.request(url if url.startswith("http") else AUTH_DOMAIN + url)
    if kind != "redir":
        raise RuntimeError(f"login: resume failed ({kind} {url})")
    code = urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get("code", [None])[0]
    if not code:
        raise RuntimeError(f"login: no auth code in callback: {url}")

    return _post(f"{AUTH_DOMAIN}/oauth/token", {
        "client_id": CLIENT_ID,
        "code_verifier": verifier,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
    })


def _fresh_mailbox(email):
    """Re-issue a tmail token for an existing address. Returns (address, token)."""
    if "@" not in email:
        raise RuntimeError(f"bad tmail address: {email}")
    local, domain = email.split("@", 1)
    mb = _tmail("POST", "/v1/addresses", {"local_part": local, "domain": domain}) or {}
    if not mb.get("address") or not mb.get("token"):
        raise RuntimeError(f"tmail: could not re-issue token for {email}: {mb}")
    return mb["address"], mb["token"]


def auto_login(name, email=None, tmail_token=None, domain=None, timeout=90):
    """First-time login: fetch access+refresh token via email OTP.

    No mailbox token is ever required from the user: a fresh tmail mailbox is
    created for the given email (custom local_part kept), and its token is
    obtained automatically from the tmail response.
    """
    if email and not tmail_token:
        local, dom = _split_email(email)
        email, tmail_token = create_mailbox(local_part=local, domain=dom or domain)
    elif not email and not tmail_token:
        email, tmail_token = create_mailbox(domain)
    token_body = _auth0_login(email, tmail_token, timeout=timeout)
    session = _session_from_token_response(token_body)
    session["email"] = email
    session["tmail_token"] = tmail_token
    _save_account(name, session)
    _set_current(name)
    print(f"✓ Account '{name}' logged in. email: {email}")
    return session


def relogin(name=None, timeout=90):
    """Re-login an account via email OTP (used after refresh token fails / HTTP 403).

    The tmail token is disposable: it is re-issued for the stored email every time,
    so only the email needs to be kept on the account.
    """
    if name is None:
        name = _get_current()
    session = _get_account(name)
    email = session.get("email")
    if not email:
        raise RuntimeError(f"Account '{name}' has no email stored for relogin")
    _, tmail_token = _fresh_mailbox(email)
    token_body = _auth0_login(email, tmail_token, timeout=timeout)
    updated = _session_from_token_response(token_body, session)
    updated["email"] = email
    updated["tmail_token"] = tmail_token
    _save_account(name, updated)
    print(f"✓ Relogged-in '{name}' via email OTP")
    return updated


def _can_relogin(name):
    """True when the account stores the email needed for OTP relogin (token is re-issued on demand)."""
    session = _get_account(name)
    return bool(session.get("email"))

def get_token(name=None):
    """Get valid access token; auto-refresh, then auto-relogin via email OTP if refresh fails."""
    if name is None:
        name = _get_current()
    session = _get_account(name)
    if time.time() > session.get("_expires_at", 0) - 60:
        if session.get("refresh_token"):
            try:
                session = refresh(name)
            except Exception:
                if session.get("email"):
                    session = relogin(name)
                else:
                    raise
        elif session.get("email"):
            session = relogin(name)
        else:
            raise RuntimeError(f"Token expired for '{name}', no refresh token")
    return session["access_token"]

# --- API (zentor: REST sandbox calls were replaced by gRPC-Web Connect) ---
def _grpc_post(path: str, message: dict, token: str, timeout: int = 30):
    """Call a Connect RPC. The gateway speaks plain JSON over POST, so no
    protobuf serialization is needed for these unary methods."""
    return _post_json(f"{API_BASE}/{path}", message, token, timeout=timeout)


def _with_reauth(fn, name):
    """Run fn(); on 401/403 relogin the account once and retry."""
    try:
        return fn()
    except HTTPError as e:
        if e.code in (401, 403) and _can_relogin(name):
            relogin(name)
            return fn()
        raise


def _current_user(name=None):
    """GET-er-ung proxy: POST /moclaw.user.v2.UserService/GetCurrentUser."""
    if name is None:
        name = _get_current()
    def _run():
        return _grpc_post("moclaw.user.v2.UserService/GetCurrentUser", {}, get_token(name))
    return _with_reauth(_run, name)


def default_agent_id(name=None):
    """The agent_id needed by connect_desktop. Cached on the session."""
    if name is None:
        name = _get_current()
    session = _get_account(name)
    agent_id = session.get("agent_id")
    if agent_id:
        return agent_id
    user = _current_user(name)
    agent = user.get("default_agent") or {}
    agent_id = agent.get("id")
    if not agent_id:
        raise RuntimeError(f"no default_agent for '{name}': {user}")
    session["agent_id"] = agent_id
    _save_account(name, session)
    return agent_id


def environment_status(name=None):
    """Sandbox state. The old REST /environment/status still exists, but the
    webapp now derives everything from GetCurrentUser + ConnectDesktop."""
    if name is None:
        name = _get_current()
    user = _current_user(name)
    agent = user.get("default_agent") or {}
    return {
        "agent": agent,
        "sandbox": {"sandbox_id": agent.get("id"), "status": "ready"},
    }


def sandbox_connect(sandbox_id, name=None):
    """POST /moclaw.sandbox.v2.SandboxService/ConnectDesktop.

    zentor renamed the REST route to a gRPC-Web Connect endpoint; the request
    field is agent_id (a UUID), the response carries stream_url +
    stream_auth_key. JSON encoding works because the gateway is not strict.
    """
    if name is None:
        name = _get_current()
    def _run():
        return _grpc_post(
            "moclaw.sandbox.v2.SandboxService/ConnectDesktop",
            {"agent_id": sandbox_id},
            get_token(name),
        )
    return _with_reauth(_run, name)


def environment_initialize(payload=None, name=None):
    """POST /api/v2/environment/initialize — wake/recover sandbox."""
    if name is None:
        name = _get_current()
    def _run():
        return _post_json(f"{API_BASE}/api/v2/environment/initialize", payload or {}, get_token(name))
    return _with_reauth(_run, name)

def check_token_health():
    """Check all accounts for token expiry. Auto-refresh if possible."""
    accounts = _load_accounts()
    if not accounts:
        return
    
    print("\n⏳ Checking token health...\n")
    
    issues = []
    for name, sess in accounts.items():
        expires_at = sess.get("_expires_at", 0)
        time_left = expires_at - time.time()
        
        # < 24h left
        if time_left < 86400:
            if time_left < 0:
                status = "❌ EXPIRED"
            elif time_left < 3600:
                status = "🔴 < 1h left"
            else:
                status = "🟡 < 24h left"
            
            if sess.get("refresh_token"):
                try:
                    refresh(name)
                    issues.append((name, "✓ Auto-refreshed"))
                except Exception as e:
                    issues.append((name, f"❌ Refresh failed: {str(e)[:40]}"))
            elif sess.get("email"):
                try:
                    relogin(name)
                    issues.append((name, "✓ Relogged-in via OTP (no refresh_token)"))
                except Exception as e:
                    issues.append((name, f"❌ Relogin failed: {str(e)[:40]}"))
            else:
                issues.append((name, f"{status} — no refresh_token"))
    
    if issues:
        print("Token Status:")
        for name, msg in issues:
            print(f"  {name:15} {msg}")
        print()
    else:
        print("✓ All tokens healthy\n")

def connect(name=None):
    """One-shot: status → connect."""
    if name is None:
        name = _get_current()
    token = get_token(name)
    env = environment_status(name)
    sandbox_id = env["sandbox"]["sandbox_id"]
    conn = sandbox_connect(sandbox_id, name)
    return {"account": name, "env": env, "connect": conn}

# --- UI ---
def clear():
    print("\033[2J\033[H", end="")

def show_header(title):
    """Boxed title header."""
    w = len(title) + 4
    print(f"┌{'─' * w}┐")
    print(f"│  {title}  │")
    print(f"└{'─' * w}┘\n")


def _section(title):
    """Section heading with a trailing rule."""
    print(f"  ── {title} {'─' * max(2, 53 - len(title))}")

def format_connect(result):
    """Pretty print connect result. zentor drops mcp_url/mcp_token."""
    account = result["account"]
    env = result["env"]
    conn = result["connect"]
    sb = env.get("sandbox") or {}
    agent = env.get("agent") or {}
    print(f"Account:        {account}")
    print(f"Agent ID:       {agent.get('id') or sb.get('sandbox_id') or conn.get('sandbox_id')}")
    print(f"Agent:          {agent.get('name', '-')} (active: {agent.get('is_active')})")
    print(f"Stream URL:     {conn.get('stream_url') or sb.get('stream_url')}")
    print(f"Stream Auth:    {conn.get('stream_auth_key', '-')}")
    print()

def _account_row(i, name, sess, cur):
    """One line of the account table."""
    mark = "► " if name == cur else "  "
    exp = sess.get("_expires_at", 0)
    exp_str = time.strftime("%m-%d %H:%M", time.localtime(exp)) if exp else "?"
    refresh = "✓" if sess.get("refresh_token") else "✗"
    otp = "✓" if sess.get("email") else "–"
    return f"  {i:>2}  {mark}{name:<16}  {exp_str:<11}  {refresh}     {otp}"


def list_accounts():
    """Print the account table; returns False when there are no accounts."""
    accounts = _load_accounts()
    if not accounts:
        print("  (no accounts yet)\n")
        return False
    cur = _get_current()
    print(f"  {'#':>2}  {'ACCOUNT':<18}  {'EXPIRES':<11}  REFR  RELOGIN")
    print(f"  {'─':>2}  {'─' * 18}  {'─' * 11}  ────  ───────")
    for i, (name, sess) in enumerate(accounts.items(), 1):
        print(_account_row(i, name, sess, cur))
    print()
    return True


def menu_main():
    """Main menu."""
    check_token_health()
    status = ""
    while True:
        clear()
        show_header("ZENTOR.AI — Multi-Account Manager")
        if status:
            print(f"  {status}\n")
        _section("ACCOUNTS")
        list_accounts()
        _section("ACTIONS")
        print("   1) Add account")
        print("   2) Remove account")
        print("   3) Keep-alive — pick account")
        print("   4) Keep-alive — ALL accounts")
        print("   5) Connect / wake — pick account")
        print("   0) Exit")
        print(f"  {'─' * 56}\n")
        choice = input("  Choose: ").strip()
        status = ""
        if choice == "0":
            break
        elif choice == "1":
            status = menu_add_account()
        elif choice == "2":
            status = menu_remove_account()
        elif choice == "3":
            status = menu_keepalive_pick()
        elif choice == "4":
            status = menu_keepalive_all()
        elif choice == "5":
            status = menu_connect_pick()
        else:
            status = "Unknown option"

def _pick_account():
    """Show numbered accounts; return the chosen name or None (back/invalid)."""
    if not list_accounts():
        return None
    print("  0) Back")
    choice = input("\n  Pick: ").strip()
    if choice == "0":
        return None
    try:
        idx = int(choice) - 1
        accounts = list(_load_accounts())
        if 0 <= idx < len(accounts):
            return accounts[idx]
    except ValueError:
        pass
    return None


def _interval_prompt():
    raw = input("  Interval seconds [25]: ").strip()
    try:
        interval = float(raw) if raw else 25.0
    except ValueError:
        interval = 25.0
    return interval if interval >= 5 else 5.0


def menu_keepalive_pick():
    """Pick account then keep-alive (blocks until Ctrl+C)."""
    clear()
    show_header("Keep-alive — pick account")
    name = _pick_account()
    if name is None:
        return "No accounts" if not _load_accounts() else ""
    _set_current(name)
    print(f"  ► {name}\n")
    interval = _interval_prompt()
    print()
    try:
        keepalive(name=name, interval=interval)
    except Exception as e:
        return f"Keep-alive error: {e}"
    return "Keep-alive stopped"


def menu_keepalive_all():
    """Keep-alive for ALL accounts in parallel (blocks until Ctrl+C)."""
    clear()
    show_header("Keep-alive — ALL accounts")
    accounts = _load_accounts()
    if not accounts:
        return "No accounts"
    print(f"  {len(accounts)} account(s) will be kept warm in parallel.")
    print("  Ctrl+C to stop all and return to menu.\n")
    interval = _interval_prompt()
    print()
    try:
        keepalive_all(interval=interval)
    except Exception as e:
        return f"Keep-alive error: {e}"
    return "Keep-alive stopped"


def menu_add_account():
    """Add account: returns a status message for the main menu."""
    clear()
    show_header("Add Account")
    _section("METHOD")
    print("   1) Auto-login via email OTP (auto-create tmail mailbox)")
    print("   2) Login via URL — browser 2-step (captcha-safe, ga harus 1 baris)")
    print("   3) Import from localStorage JSON")
    print("   4) Add with access token")
    print("   0) Back")
    print(f"  {'─' * 56}\n")
    choice = input("  Choose: ").strip()

    if choice == "0":
        return ""
    if choice == "1":
        return _add_auto_login()
    if choice == "2":
        return _add_browser()
    if choice == "3":
        return _add_import()
    if choice == "4":
        return _add_token()
    return "Unknown option"


def _add_auto_login():
    name = input("  Account name: ").strip()
    if not name:
        return "Account name required"
    raw = input("  Email (Enter = auto-generate, e.g. nala): ").strip()
    try:
        if raw:
            local, dom = _split_email(raw)
            email, tmail_token = create_mailbox(local_part=local, domain=dom)
        else:
            email, tmail_token = create_mailbox()
        print(f"  ✓ Created mailbox: {email}")
        print(f"  ⏳ Logging in {email} (waiting for OTP)...")
        auto_login(name, email=email, tmail_token=tmail_token)
        return f"✓ Account '{name}' added ({email})"
    except Exception as e:
        return f"Error: {e}"


def _add_browser():
    print("\n   a) Langsung (tampilkan URL + tempel callback di layar yang sama)")
    print("   b) Step 1 — cetak URL saja (buka di HP/laptop lain)")
    print("   c) Step 2 — selesaikan dengan callback URL/code")
    print("   0) Back")
    sub = input("\n  Pilih [a/b/c]: ").strip().lower()
    if sub in ("0", ""):
        return ""
    name = input("  Account name: ").strip()
    if not name:
        return "Account name required"
    try:
        if sub == "b":
            login_browser_start(name)
            input("\n  Press Enter to continue...")
            return f"URL login '{name}' dicetak — selesaikan via Step 2 (c)"
        if sub == "c":
            raw = input("  Paste callback URL atau code: ").strip()
            login_browser_finish(name, raw)
            return f"✓ Account '{name}' added via URL"
        login_via_browser(name)
        return f"✓ Account '{name}' added via browser"
    except Exception as e:
        return f"Error: {e}"


def _add_import():
    name = input("  Account name: ").strip()
    if not name:
        return "Account name required"
    print("\n  Paste full localStorage JSON, then press Enter twice:")
    lines = []
    while True:
        line = input()
        if not line:
            break
        lines.append(line)
    try:
        import_from_json(name, "\n".join(lines))
        return f"✓ Account '{name}' imported"
    except Exception as e:
        return f"Error: {e}"


def _add_token():
    name = input("  Account name: ").strip()
    token = input("  Access token: ").strip()
    if not name or not token:
        return "Name and token required"
    add_account(name, token)
    return f"✓ Account '{name}' added"


def menu_remove_account():
    """Remove account without confirmation: returns a status message."""
    clear()
    show_header("Remove Account")
    accounts = _load_accounts()
    if not accounts:
        return "No accounts"
    for i, name in enumerate(accounts, 1):
        print(f"  {i:>2}) {name}")
    print(f"  {'─' * 56}")
    print("  0) Back")
    choice = input("\n  Number to remove: ").strip()
    if choice == "0":
        return ""
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(accounts):
            name = list(accounts)[idx]
            del accounts[name]
            _save_accounts(accounts)
            if _get_current() == name:
                remaining = list(accounts)
                if remaining:
                    _set_current(remaining[0])
            return f"✓ Account '{name}' removed"
        return "Invalid number"
    except ValueError:
        return "Invalid input"


def menu_connect_pick():
    """Pick account, show status + connect credentials."""
    clear()
    show_header("Connect / wake — pick account")
    name = _pick_account()
    if name is None:
        return "No accounts" if not _load_accounts() else ""
    _set_current(name)
    try:
        result = connect(name)
        format_connect(result)
    except Exception as e:
        return f"Error: {e}"
    input("\n  Press Enter to continue...")
    return ""

def stream_host_from_url(stream_url):
    u = urllib.parse.urlparse(stream_url)
    if not u.hostname:
        raise RuntimeError(f"bad stream_url: {stream_url}")
    return u.hostname


def keepalive(name=None, interval=25.0, reinit_on_fail=True, simulate_refresh=False):
    """Keep sandbox warm and refresh the account token before/after auth failures."""
    # lazy import keep helper pieces inline (stdlib only)
    import base64, os, socket, ssl, traceback
    from urllib.request import urlopen as _urlopen

    if name is None:
        name = _get_current()

    def log(msg, blank=False):
        """Keepalive log line: [<account> <HH:MM:SS>] <msg>."""
        line = f"[{name} {time.strftime('%H:%M:%S')}] {msg}"
        print(("\n" if blank else "") + line, flush=True)

    def resolve():
        """zentor: no REST sandbox status anymore — probe ConnectDesktop directly
        and initialize only when it returns no stream_url."""
        agent = default_agent_id(name)
        conn = sandbox_connect(agent, name)
        url = conn.get("stream_url")
        if not url:
            log(f"no stream_url: {conn} → initialize...")
            environment_initialize(name=name)
            conn = sandbox_connect(agent, name)
            url = conn.get("stream_url")
        if not url:
            raise RuntimeError(f"no stream_url after initialize: {conn}")
        return agent, url, stream_host_from_url(url)

    def http_ping(host):
        t0 = time.time()
        req = Request(f"https://{host}/", headers={
            "User-Agent": "zentor-keepalive/1.0",
            "Origin": SITE,
            "Referer": SITE + "/",
        })
        with _urlopen(req, timeout=15) as r:
            r.read(256)
            return r.status, (time.time() - t0) * 1000

    def ws_open(host):
        raw = socket.create_connection((host, 443), timeout=20)
        # TCP keepalive so NAT/proxy idle timeouts don't kill the tunnel silently.
        try:
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            for opt, val in ((getattr(socket, "TCP_KEEPIDLE", None), 30),
                             (getattr(socket, "TCP_KEEPINTVL", None), 5),
                             (getattr(socket, "TCP_KEEPCNT", None), 3)):
                if opt is not None:
                    raw.setsockopt(socket.IPPROTO_TCP, opt, val)
        except OSError:
            pass  # non-Linux / unsupported
        sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET /websockify HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Origin: {SITE}\r\n"
            f"\r\n"
        )
        sock.sendall(req.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("WS closed during handshake")
            buf += chunk
        status = buf.split(b"\r\n", 1)[0].decode("iso-8859-1", "replace")
        if " 101 " not in status:
            raise ConnectionError(f"WS upgrade failed: {status}")
        return sock

    class _WSTimeout(Exception):
        """Clean frame-boundary timeout (no partial frame consumed)."""

    def _recv_exact(sock, n, deadline):
        buf = b""
        while len(buf) < n:
            left = deadline - time.time()
            if left <= 0:
                if buf:
                    raise ConnectionError("WS stream desync (timeout mid-frame)")
                raise _WSTimeout()
            sock.settimeout(left)
            try:
                chunk = sock.recv(n - len(buf))
            except socket.timeout:
                if buf:
                    raise ConnectionError("WS stream desync (timeout mid-frame)")
                continue
            if not chunk:
                raise ConnectionError("WS closed")
            buf += chunk
        return buf

    def _read_frame(sock, deadline):
        """Read one server frame. Returns (opcode, payload) or None on clean timeout."""
        try:
            hdr = _recv_exact(sock, 2, deadline)
        except _WSTimeout:
            return None
        opcode = hdr[0] & 0x0F
        masked = hdr[1] & 0x80
        ln = hdr[1] & 0x7F
        if ln == 126:
            ln = int.from_bytes(_recv_exact(sock, 2, deadline), "big")
        elif ln == 127:
            ln = int.from_bytes(_recv_exact(sock, 8, deadline), "big")
        mask = _recv_exact(sock, 4, deadline) if masked else b""
        payload = _recv_exact(sock, ln, deadline) if ln else b""
        if masked:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return opcode, payload

    def ws_ping(sock):
        mask = os.urandom(4)
        payload = b"ka"
        frame = bytes([0x89, 0x80 | len(payload)]) + mask
        frame += bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        sock.sendall(frame)
        # Wait (up to 3s) for the PONG so real server→client traffic flows every
        # cycle and resets proxy idle/read timeouts. Handle close + server pings.
        deadline = time.time() + 3.0
        while True:
            got = _read_frame(sock, deadline)
            if got is None:
                break
            op, data = got
            if op == 0x8:  # close frame
                raise ConnectionError(f"WS close from server: {data[:32]!r}")
            if op == 0x9:  # server ping → answer pong
                mask = os.urandom(4)
                f = bytes([0x8A, 0x80 | len(data)]) + mask
                f += bytes(b ^ mask[i % 4] for i, b in enumerate(data))
                sock.sendall(f)
            # 0xA pong, 0x1 text, 0x2 binary → ignore (VNC stream etc.)

    log(f"account={name} interval={interval}s refresh_simulation={simulate_refresh}")
    sock = None
    host = None
    n = 0
    fails = 0
    REINIT_AFTER = 3
    try:
        while True:
            n += 1
            try:
                session = _get_account(name)
                # Refresh proactively before the access token expires. This runs
                # independently of the WebSocket ping interval, so option 7 keeps
                # working across multi-day sessions.
                if time.time() > session.get("_expires_at", 0) - 120:
                    if session.get("refresh_token"):
                        try:
                            refresh(name, simulate=simulate_refresh)
                            log("token refreshed" + (" (simulated)" if simulate_refresh else ""))
                        except Exception as e:
                            log(f"token refresh failed: {e}")
                            if session.get("email") and not simulate_refresh:
                                try:
                                    relogin(name)
                                    log("relogin after failed refresh")
                                except Exception as e2:
                                    log(f"relogin failed: {e2}")
                    elif session.get("email") and not simulate_refresh:
                        try:
                            relogin(name)
                            log("relogin (token expired, no refresh_token)")
                        except Exception as e:
                            log(f"relogin failed: {e}")
                    else:
                        log("WARNING: token expired, no refresh_token")
                if host is None:
                    sid, url, host = resolve()
                    log(f"sandbox={sid} host={host}")
                code, ms = http_ping(host)
                msg = f"#{n} HTTP {code} {ms:.0f}ms"
                if sock is None:
                    sock = ws_open(host)
                    msg += " WS open"
                else:
                    ws_ping(sock)
                    msg += " WS ping"
                log(msg)
                fails = 0
            except Exception as e:
                # A stale access token can be rejected before its locally stored
                # expiry. On 401/403 re-authenticate immediately (403 → full OTP
                # relogin; 401 → token refresh first), then force a fresh sandbox
                # connection on the next cycle.
                if isinstance(e, HTTPError) and e.code in (401, 403):
                    sess = _get_account(name)
                    handled = False
                    if (e.code == 403 and not simulate_refresh
                            and sess.get("email")):
                        try:
                            relogin(name)
                            log("relogin after HTTP 403")
                            handled = True
                        except Exception as relogin_error:
                            log(f"relogin after HTTP 403 failed: {relogin_error}")
                    if not handled and sess.get("refresh_token"):
                        try:
                            refresh(name, simulate=simulate_refresh)
                            log(f"token refreshed after HTTP {e.code}")
                            handled = True
                        except Exception as refresh_error:
                            log(f"token refresh after HTTP {e.code} failed: {refresh_error}")
                    if handled:
                        host = None
                        if sock:
                            sock.close()
                        sock = None
                        fails = 0
                        time.sleep(1.0)
                        continue

                first_in_streak = (fails == 0)
                fails += 1
                log(f"#{n} ERR {e} (fail {fails}/{REINIT_AFTER})")
                if first_in_streak:
                    traceback.print_exc()  # shows exactly which stage raised
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass
                sock = None
                recovered = False
                if fails < REINIT_AFTER:
                    # Re-establish immediately so the dead window stays small
                    # instead of waiting for the next full interval.
                    for attempt in range(3):
                        try:
                            sid, url, host = resolve()
                            code, ms = http_ping(host)
                            sock = ws_open(host)
                            log(f"#{n} reconnected (attempt {attempt + 1}): HTTP {code} {ms:.0f}ms WS open")
                            fails = 0
                            recovered = True
                            break
                        except Exception as e2:
                            log(f"#{n} reconnect {attempt + 1}/3 failed: {e2}")
                            time.sleep(1.0 + attempt)
                if not recovered:
                    host = None
                    if reinit_on_fail and fails >= REINIT_AFTER:
                        try:
                            environment_initialize(name=name)
                            log("initialize() ok")
                        except Exception as e2:
                            log(f"initialize failed: {e2}")
                        fails = 0
                    # A single transient TLS/network error (e.g. SSL EOF) should NOT
                    # restart the sandbox. Retry with a short backoff instead of the
                    # full interval so the keep-alive gap stays small during blips.
                    delay = min(5 * (2 ** (fails - 1)), interval)
                    time.sleep(delay)
                    continue
            time.sleep(interval)
    except KeyboardInterrupt:
        log("stop", blank=True)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def keepalive_all(interval=25.0, simulate_refresh=False):
    """Run keepalive for every account in parallel. Ctrl+C stops all."""
    import multiprocessing

    def log(msg, blank=False):
        line = f"[all {time.strftime('%H:%M:%S')}] {msg}"
        print(("\n" if blank else "") + line, flush=True)

    accounts = _load_accounts()
    if not accounts:
        print("No accounts.\n")
        return
    names = list(accounts.keys())
    log(f"{len(names)} account(s): {', '.join(names)}")
    log("Ctrl+C to stop all")
    procs = []
    for n in names:
        p = multiprocessing.Process(
            target=keepalive, kwargs={
                "name": n,
                "interval": interval,
                "simulate_refresh": simulate_refresh,
            },
            name=f"ka-{n}", daemon=True)
        p.start()
        procs.append(p)
    try:
        while any(p.is_alive() for p in procs):
            time.sleep(0.5)
    except KeyboardInterrupt:
        log("stopping all keepalives...", blank=True)
        for p in procs:
            if p.is_alive():
                p.terminate()
        for p in procs:
            p.join(timeout=2)
        log("stopped")


def _cli():
    if len(sys.argv) < 2:
        menu_main()
        print("\nGoodbye!\n")
        return
    cmd = sys.argv[1].lower()
    name = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("-") else None
    if cmd == "connect":
        format_connect(connect(name))
    elif cmd == "status":
        print(json.dumps(environment_status(name), indent=2))
    elif cmd == "init" or cmd == "initialize":
        print(json.dumps(environment_initialize(name=name), indent=2))
    elif cmd == "refresh":
        simulate = "--simulate" in sys.argv or "--simulate-refresh" in sys.argv
        refresh(name=name, simulate=simulate)
    elif cmd in ("login", "autologin"):
        # moclaw.py login <name> [--email E]   E is a custom email/name; no token needed.
        email = None
        if "--email" in sys.argv:
            email = sys.argv[sys.argv.index("--email") + 1]
        auto_login(name, email=email)
    elif cmd in ("login-browser", "login_browser", "browser-login", "login-url"):
        # moclaw.py login-browser <name> [--url-only] [--code CALLBACK|--email E]
        email = None
        if "--email" in sys.argv:
            email = sys.argv[sys.argv.index("--email") + 1]
        if "--url-only" in sys.argv:
            login_browser_start(name, email=email)
        elif "--code" in sys.argv:
            login_browser_finish(name, sys.argv[sys.argv.index("--code") + 1], email=email)
        else:
            login_via_browser(name, email=email)
    elif cmd == "relogin":
        relogin(name)
    elif cmd == "keepalive" or cmd == "ka":
        interval = 25.0
        if "--interval" in sys.argv:
            interval = float(sys.argv[sys.argv.index("--interval") + 1])
        simulate_refresh = "--simulate-refresh" in sys.argv
        if simulate_refresh:
            print("WARNING: simulated tokens are invalid for the real API.")
        keepalive(name=name, interval=interval, simulate_refresh=simulate_refresh)
    elif cmd == "import":
        # python moclaw.py import <name> <json-file|->
        if len(sys.argv) < 4:
            raise SystemExit("usage: moclaw.py import <name> <file|->")
        raw = sys.stdin.read() if sys.argv[3] == "-" else Path(sys.argv[3]).read_text()
        import_from_json(sys.argv[2], raw)
    elif cmd in ("help", "-h", "--help"):
        print("usage: moclaw.py [connect|status|init|refresh|keepalive|import|login|login-browser|relogin] [account]")
        print("       options: --interval N, --simulate, --simulate-refresh")
        print("       login <name> [--email E]  # email-OTP auto-login (custom email or auto-gen)")
        print("       login-browser <name> [--url-only] [--code CALLBACK]  # 2-step browser login")
        print("       moclaw.py          # TUI")
    else:
        raise SystemExit(f"unknown command: {cmd}")


if __name__ == "__main__":
    try:
        _cli()
    except KeyboardInterrupt:
        print("\n\nExiting...\n")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
