#!/usr/bin/env python3
"""moclaw web dashboard (FastAPI) — manage accounts + keepalive 24/7.

Deploy: Railway / Docker single service.
  uvicorn app:app --host 0.0.0.0 --port $PORT
"""
import base64
import os
import socket
import ssl
import threading
import time
import traceback
from collections import deque
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import moclaw

BASE_DIR = Path(__file__).parent
TPL = BASE_DIR / "templates" / "index.html"

app = FastAPI(title="moclaw dashboard")

# ---------- log buffer ----------
LOGS: deque = deque(maxlen=3000)
LOG_LOCK = threading.Lock()


def log(account: str, msg: str):
    entry = {"ts": time.strftime("%H:%M:%S"), "account": account, "msg": msg}
    with LOG_LOCK:
        LOGS.append(entry)
    print(f"[{account} {entry['ts']}] {msg}", flush=True)


# ---------- keepalive manager (thread per account, stoppable) ----------
KA: dict = {}  # name -> {"thread": Thread, "stop": Event, "interval": float, "started": str}
KA_LOCK = threading.Lock()


def _http_ping(host: str):
    t0 = time.time()
    req = Request(f"https://{host}/", headers={
        "User-Agent": "moclaw-keepalive/1.0",
        "Origin": "https://moclaw.ai",
        "Referer": "https://moclaw.ai/",
    })
    with urlopen(req, timeout=15) as r:
        r.read(256)
        return r.status, (time.time() - t0) * 1000


def _ws_open(host: str):
    raw = socket.create_connection((host, 443), timeout=20)
    try:
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for opt, val in ((getattr(socket, "TCP_KEEPIDLE", None), 30),
                         (getattr(socket, "TCP_KEEPINTVL", None), 5),
                         (getattr(socket, "TCP_KEEPCNT", None), 3)):
            if opt is not None:
                raw.setsockopt(socket.IPPROTO_TCP, opt, val)
    except OSError:
        pass
    sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall(
        f"GET /websockify HTTP/1.1\r\nHost: {host}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        "Origin: https://moclaw.ai\r\n\r\n".encode()
    )
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


def _recv_exact(sock, n, deadline):
    buf = b""
    while len(buf) < n:
        left = deadline - time.time()
        if left <= 0:
            raise TimeoutError("ws frame timeout")
        sock.settimeout(left)
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            raise TimeoutError("ws frame timeout")
        if not chunk:
            raise ConnectionError("WS closed")
        buf += chunk
    return buf


def _ws_ping(sock):
    mask = os.urandom(4)
    payload = b"ka"
    sock.sendall(bytes([0x89, 0x80 | len(payload)]) + mask +
                 bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))
    deadline = time.time() + 3.0
    while True:
        try:
            hdr = _recv_exact(sock, 2, deadline)
        except TimeoutError:
            break
        op = hdr[0] & 0x0F
        ln = hdr[1] & 0x7F
        if ln == 126:
            ln = int.from_bytes(_recv_exact(sock, 2, deadline), "big")
        elif ln == 127:
            ln = int.from_bytes(_recv_exact(sock, 8, deadline), "big")
        masked = hdr[1] & 0x80
        mask_b = _recv_exact(sock, 4, deadline) if masked else b""
        payload_r = _recv_exact(sock, ln, deadline) if ln else b""
        if masked:
            payload_r = bytes(b ^ mask_b[i % 4] for i, b in enumerate(payload_r))
        if op == 0x8:
            raise ConnectionError(f"WS close from server: {payload_r[:32]!r}")
        if op == 0x9:
            m2 = os.urandom(4)
            sock.sendall(bytes([0x8A, 0x80 | len(payload_r)]) + m2 +
                         bytes(b ^ m2[i % 4] for i, b in enumerate(payload_r)))


def _resolve(name: str):
    env = moclaw.environment_status(name)
    sb = env.get("sandbox") or {}
    status = (sb.get("status") or env.get("runtime_state") or "").lower()
    reason = env.get("reason")
    if status in ("paused", "stopped", "unavailable", "pending", "recovering") \
            or reason in ("sandbox_paused", "sandbox_missing"):
        log(name, f"sandbox {status or reason} -> initialize...")
        moclaw.environment_initialize(name=name)
        env = moclaw.environment_status(name)
        sb = env.get("sandbox") or {}
    sid = sb.get("sandbox_id")
    if not sid:
        raise RuntimeError(f"no sandbox_id: {env}")
    conn = moclaw.sandbox_connect(sid, name)
    url = conn.get("stream_url") or sb.get("stream_url")
    if not url:
        raise RuntimeError(f"no stream_url: {conn}")
    return sid, url, moclaw.stream_host_from_url(url)


def _worker(name: str, interval: float, stop: threading.Event):
    log(name, f"keepalive start interval={interval}s")
    sock = None
    host = None
    n = 0
    fails = 0
    try:
        while not stop.is_set():
            n += 1
            try:
                sess = moclaw._get_account(name)
                if time.time() > sess.get("_expires_at", 0) - 120:
                    if sess.get("refresh_token"):
                        try:
                            moclaw.refresh(name)
                            log(name, "token refreshed")
                        except Exception as e:
                            log(name, f"refresh failed: {e}")
                            if sess.get("email"):
                                try:
                                    moclaw.relogin(name)
                                    log(name, "relogin after failed refresh")
                                except Exception as e2:
                                    log(name, f"relogin failed: {e2}")
                    elif sess.get("email"):
                        try:
                            moclaw.relogin(name)
                            log(name, "relogin (expired, no refresh_token)")
                        except Exception as e:
                            log(name, f"relogin failed: {e}")
                    else:
                        log(name, "WARNING: token expired, no refresh_token")
                if host is None:
                    sid, url, host = _resolve(name)
                    log(name, f"sandbox={sid} host={host}")
                code, ms = _http_ping(host)
                msg = f"#{n} HTTP {code} {ms:.0f}ms"
                if sock is None:
                    sock = _ws_open(host)
                    msg += " WS open"
                else:
                    _ws_ping(sock)
                    msg += " WS ping"
                log(name, msg)
                fails = 0
            except Exception as e:
                if isinstance(e, HTTPError) and e.code in (401, 403):
                    try:
                        sess = moclaw._get_account(name)
                    except Exception:
                        sess = {}
                    handled = False
                    if e.code == 403 and sess.get("email"):
                        try:
                            moclaw.relogin(name)
                            log(name, "relogin after HTTP 403")
                            handled = True
                        except Exception as re_err:
                            log(name, f"relogin 403 failed: {re_err}")
                    if not handled and sess.get("refresh_token"):
                        try:
                            moclaw.refresh(name)
                            log(name, f"token refreshed after HTTP {e.code}")
                            handled = True
                        except Exception as rf_err:
                            log(name, f"refresh {e.code} failed: {rf_err}")
                    if handled:
                        host = None
                        if sock:
                            try:
                                sock.close()
                            except Exception:
                                pass
                        sock = None
                        fails = 0
                        stop.wait(1.0)
                        continue
                fails += 1
                log(name, f"#{n} ERR {e} (fail {fails}/3)")
                if fails == 1:
                    traceback.print_exc()
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass
                sock = None
                recovered = False
                if fails < 3:
                    for attempt in range(3):
                        if stop.is_set():
                            break
                        try:
                            sid, url, host = _resolve(name)
                            code, ms = _http_ping(host)
                            sock = _ws_open(host)
                            log(name, f"#{n} reconnected (try {attempt+1}): HTTP {code} {ms:.0f}ms")
                            fails = 0
                            recovered = True
                            break
                        except Exception as e2:
                            log(name, f"reconnect {attempt+1}/3 failed: {e2}")
                            stop.wait(1.0 + attempt)
                if not recovered and not stop.is_set():
                    host = None
                    if fails >= 3:
                        try:
                            moclaw.environment_initialize(name=name)
                            log(name, "initialize() ok")
                        except Exception as e2:
                            log(name, f"initialize failed: {e2}")
                        fails = 0
                    stop.wait(min(5 * (2 ** max(fails - 1, 0)), interval))
                    continue
            stop.wait(interval)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        log(name, "keepalive stop")


def ka_start(name: str, interval: float = 25.0):
    interval = max(float(interval or 25), 5.0)
    with KA_LOCK:
        cur = KA.get(name)
        if cur and cur["thread"].is_alive():
            return False
        # validate account exists
        moclaw._get_account(name)
        stop = threading.Event()
        t = threading.Thread(target=_worker, args=(name, interval, stop),
                             name=f"ka-{name}", daemon=True)
        KA[name] = {"thread": t, "stop": stop, "interval": interval,
                    "started": time.strftime("%H:%M:%S")}
        t.start()
        return True


def ka_stop(name: str):
    with KA_LOCK:
        cur = KA.get(name)
        if not cur:
            return False
        cur["stop"].set()
    cur["thread"].join(timeout=5)
    with KA_LOCK:
        if not cur["thread"].is_alive():
            KA.pop(name, None)
            return True
        return False


def ka_status():
    with KA_LOCK:
        return {n: {"alive": v["thread"].is_alive(), "interval": v["interval"],
                    "started": v["started"]} for n, v in KA.items()}


# ---------- models ----------
class AutoLoginReq(BaseModel):
    name: str
    email: Optional[str] = None


class BrowserStartReq(BaseModel):
    name: str
    email: Optional[str] = None


class BrowserFinishReq(BaseModel):
    name: str
    code: str
    email: Optional[str] = None


class ImportReq(BaseModel):
    name: str
    json_str: str


class TokenReq(BaseModel):
    name: str
    token: str


class IntervalReq(BaseModel):
    interval: Optional[float] = 25.0


# ---------- pages ----------
@app.get("/")
def index():
    if not TPL.exists():
        return JSONResponse({"ok": True, "hint": "templates/index.html missing"})
    return FileResponse(str(TPL))


# ---------- accounts API (full fitur moclaw.py) ----------
@app.get("/api/accounts")
def api_accounts():
    accounts = moclaw._load_accounts()
    cur = moclaw._get_current()
    st = ka_status()
    out = []
    for name, sess in accounts.items():
        exp = sess.get("_expires_at", 0)
        out.append({
            "name": name,
            "current": name == cur,
            "expires_at": exp,
            "expires_str": time.strftime("%m-%d %H:%M", time.localtime(exp)) if exp else "?",
            "expired": time.time() > exp,
            "has_refresh": bool(sess.get("refresh_token")),
            "email": sess.get("email"),
            "keepalive": st.get(name, {"alive": False}),
        })
    return {"accounts": out, "current": cur}


@app.post("/api/accounts/auto-login")
def api_auto_login(req: AutoLoginReq):
    try:
        moclaw.auto_login(req.name.strip(), email=(req.email or None))
        log(req.name, "auto-login OK via dashboard")
        return {"ok": True}
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/api/accounts/browser-start")
def api_browser_start(req: BrowserStartReq):
    try:
        url = moclaw.login_browser_start(req.name.strip(), email=(req.email or None))
        log(req.name, "browser login URL generated")
        return {"ok": True, "url": url}
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/api/accounts/browser-finish")
def api_browser_finish(req: BrowserFinishReq):
    try:
        moclaw.login_browser_finish(req.name.strip(), req.code.strip(),
                                    email=(req.email or None))
        log(req.name, "browser login finished")
        return {"ok": True}
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/api/accounts/import")
def api_import(req: ImportReq):
    try:
        moclaw.import_from_json(req.name.strip(), req.json_str)
        return {"ok": True}
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/api/accounts/token")
def api_token(req: TokenReq):
    try:
        moclaw.add_account(req.name.strip(), req.token.strip())
        return {"ok": True}
    except Exception as e:
        raise HTTPException(400, str(e))


@app.delete("/api/accounts/{name}")
def api_remove(name: str):
    accounts = moclaw._load_accounts()
    if name not in accounts:
        raise HTTPException(404, "not found")
    try:
        ka_stop(name)
    except Exception:
        pass
    del accounts[name]
    moclaw._save_accounts(accounts)
    log(name, "account removed")
    return {"ok": True}


@app.post("/api/accounts/{name}/refresh")
def api_refresh(name: str):
    try:
        moclaw.refresh(name)
        return {"ok": True}
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/api/accounts/{name}/relogin")
def api_relogin(name: str):
    try:
        moclaw.relogin(name)
        return {"ok": True}
    except Exception as e:
        raise HTTPException(400, str(e))


@app.get("/api/accounts/{name}/status")
def api_status(name: str):
    try:
        return moclaw.environment_status(name)
    except HTTPError as e:
        raise HTTPException(e.code, f"upstream {e.code}")
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/api/accounts/{name}/initialize")
def api_init(name: str):
    try:
        return moclaw.environment_initialize(name=name)
    except Exception as e:
        raise HTTPException(400, str(e))


@app.get("/api/accounts/{name}/connect")
def api_connect(name: str):
    try:
        return moclaw.connect(name)
    except Exception as e:
        raise HTTPException(400, str(e))


@app.get("/api/health")
def api_health():
    accounts = moclaw._load_accounts()
    out = []
    for name, sess in accounts.items():
        left = sess.get("_expires_at", 0) - time.time()
        out.append({"name": name, "seconds_left": int(left),
                    "expired": left < 0,
                    "has_refresh": bool(sess.get("refresh_token")),
                    "email": sess.get("email")})
    return {"accounts": out}


# ---------- keepalive API: start/stop + status ----------
@app.get("/api/keepalive/status")
def api_ka_status():
    return {"running": ka_status()}


@app.post("/api/keepalive/{name}/start")
def api_ka_start(name: str, req: IntervalReq):
    try:
        started = ka_start(name, req.interval or 25.0)
        return {"ok": True, "started": started}
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/api/keepalive/{name}/stop")
def api_ka_stop(name: str):
    return {"ok": True, "stopped": ka_stop(name)}


@app.post("/api/keepalive/all/start")
def api_ka_all_start(req: IntervalReq):
    accounts = moclaw._load_accounts()
    res = {}
    for n in accounts:
        try:
            res[n] = ka_start(n, req.interval or 25.0)
        except Exception as e:
            res[n] = str(e)
    return {"ok": True, "result": res}


@app.post("/api/keepalive/all/stop")
def api_ka_all_stop():
    names = list(ka_status().keys())
    res = {n: ka_stop(n) for n in names}
    return {"ok": True, "result": res}


# ---------- logs tab ----------
@app.get("/api/logs")
def api_logs(account: str = "all", limit: int = 300):
    with LOG_LOCK:
        items = list(LOGS)[-max(min(limit, 1000), 1):]
    if account != "all":
        items = [e for e in items if e["account"] == account]
    return {"logs": items}
