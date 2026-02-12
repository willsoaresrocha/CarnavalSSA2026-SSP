
import os
import json
import time
import threading
import base64
import hmac
import hashlib
from datetime import datetime, date, timedelta
from typing import Dict, List, Optional, Tuple

from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy import text, create_engine
from sqlalchemy.engine import Engine

load_dotenv()

# =========================
# ENV / CONFIG
# =========================
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_NAME = os.getenv("DB_NAME", "")
DB_USER = os.getenv("DB_USER", "")
DB_PASS = os.getenv("DB_PASS", "")

POLL_SECONDS = int(os.getenv("POLL_SECONDS", "300"))  # 5 min
HALF_LIFE_MINUTES = float(os.getenv("HALF_LIFE_MINUTES", "20"))
HISTORY_FILE = os.getenv("HISTORY_FILE", "data/history-ssp.jsonl")

EVENT_START = os.getenv("EVENT_START", "2026-02-12")
EVENT_END = os.getenv("EVENT_END", "2026-02-17")
ALERT_THRESHOLD_5MIN = int(os.getenv("ALERT_THRESHOLD_5MIN", "900"))

# ===== Auth (DB-backed) =====
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
COOKIE_NAME = os.getenv("SESSION_COOKIE", "hive_session")
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "43200"))  # 12h
AUTH_DEBUG = os.getenv("AUTH_DEBUG", "0") == "1"

# If you know your schema, set these in .env (recommended)
AUTH_TABLE = os.getenv("AUTH_TABLE", "").strip()
AUTH_USER_COL = os.getenv("AUTH_USER_COL", "").strip()
AUTH_PASS_COL = os.getenv("AUTH_PASS_COL", "").strip()

# Candidates (auto-discovery)
USER_COL_CANDIDATES = [c.strip() for c in os.getenv("AUTH_USER_COL_CANDIDATES", "email,login,usuario,username,cpf").split(",") if c.strip()]
PASS_COL_CANDIDATES = [c.strip() for c in os.getenv("AUTH_PASS_COL_CANDIDATES", "senha,password,pass").split(",") if c.strip()]

# =========================
# PASSLIB (hash verify)
# =========================
# Your DB has "$1$..." hashes (MD5-crypt). We verify with passlib.
# Install:
#   pip install passlib
try:
    from passlib.context import CryptContext
except Exception as e:
    raise RuntimeError(
        "Dependência ausente: passlib. Instale com: pip install passlib\n"
        f"Detalhe: {e!r}"
    )

PWD_CTX = CryptContext(
    schemes=[
        "md5_crypt",     # $1$...
        "bcrypt",        # $2...
        "sha256_crypt",  # $5$...
        "sha512_crypt",  # $6$...
    ],
    deprecated="auto",
)

# =========================
# QUERIES (SSP)
# =========================
SQL_PORTALS_REF = """
SELECT
  p.idPortal,
  p.nomePortal,
  p.idCircuito,
  cir.nomeCircuito,
  camRef.idCamera   AS idCameraRef,
  camRef.latitude   AS latPortal,
  camRef.longitude  AS lngPortal
FROM tbPortais p
JOIN tbCircuitos cir ON cir.idCircuito = p.idCircuito
JOIN tbCameras camRef ON camRef.idPortal = p.idPortal
WHERE camRef.idCamera = (
  SELECT MIN(c2.idCamera) FROM tbCameras c2 WHERE c2.idPortal = p.idPortal
)
ORDER BY p.idPortal;
"""

SQL_INTERVAL_COUNTS = """
SELECT
  p.idPortal,
  SUM(a.quantidade) AS qtd_intervalo
FROM tbPassantesAgregado a
JOIN tbCameras cam ON cam.idCamera = a.idCamera
JOIN tbPortais p   ON p.idPortal   = cam.idPortal
WHERE a.sentido = 'IN'
  AND TIMESTAMP(a.dataEvento, a.hora) >= (NOW() - INTERVAL 5 MINUTE)
  AND TIMESTAMP(a.dataEvento, a.hora) <  NOW()
GROUP BY p.idPortal;
"""

def ensure_dir(filepath: str) -> None:
    d = os.path.dirname(filepath)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)

def make_engine() -> Engine:
    if not DB_NAME or not DB_USER:
        raise RuntimeError("Configure DB_NAME e DB_USER no .env (e DB_PASS/DB_HOST/DB_PORT se necessário).")
    uri = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
    return create_engine(uri, pool_pre_ping=True, pool_size=8, max_overflow=16, pool_recycle=1800)

engine = make_engine()

# =========================
# Session cookie helpers
# =========================
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))

def sign_session(username: str) -> str:
    secret = SESSION_SECRET if SESSION_SECRET else ("dev-" + str(os.getpid()))
    exp = int(time.time()) + SESSION_TTL_SECONDS
    payload = f"{username}|{exp}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
    return f"{_b64url(payload)}.{_b64url(sig)}"

def verify_session(token: str) -> Optional[str]:
    try:
        if "." not in token:
            return None
        p64, s64 = token.split(".", 1)
        payload = _b64url_decode(p64)
        sig = _b64url_decode(s64)

        secret = SESSION_SECRET if SESSION_SECRET else ("dev-" + str(os.getpid()))
        expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None

        raw = payload.decode("utf-8", errors="ignore")
        if "|" not in raw:
            return None
        username, exp_s = raw.split("|", 1)
        if int(exp_s) < int(time.time()):
            return None
        return username
    except Exception:
        return None

# =========================
# Auth: discovery utilities
# =========================
def _table_exists(table: str) -> bool:
    q = """
    SELECT 1
    FROM information_schema.tables
    WHERE table_schema = DATABASE() AND table_name = :t
    LIMIT 1
    """
    with engine.connect() as conn:
        return conn.execute(text(q), {"t": table}).first() is not None

def _table_columns(table: str) -> List[str]:
    q = """
    SELECT column_name
    FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = :t
    """
    with engine.connect() as conn:
        rows = conn.execute(text(q), {"t": table}).mappings().all()
    return [str(r["column_name"]) for r in rows]

def _discover_user_table_and_cols() -> Optional[Tuple[str, str, str]]:
    """
    Finds a table that contains (one of USER_COL_CANDIDATES) AND (one of PASS_COL_CANDIDATES).
    Returns (table, user_col, pass_col) or None.
    """
    q = """
    SELECT table_name, column_name
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND (column_name IN :user_cols OR column_name IN :pass_cols)
    """
    user_cols = tuple(USER_COL_CANDIDATES)
    pass_cols = tuple(PASS_COL_CANDIDATES)

    with engine.connect() as conn:
        rows = conn.execute(text(q), {"user_cols": user_cols, "pass_cols": pass_cols}).mappings().all()

    by_table: Dict[str, set] = {}
    for r in rows:
        t = str(r["table_name"])
        c = str(r["column_name"])
        by_table.setdefault(t, set()).add(c)

    preferred = sorted(
        by_table.keys(),
        key=lambda t: (0 if ("usu" in t.lower() or "user" in t.lower() or "adm" in t.lower()) else 1, t.lower()),
    )
    for t in preferred:
        cols = by_table[t]
        u = next((c for c in USER_COL_CANDIDATES if c in cols), None)
        p = next((c for c in PASS_COL_CANDIDATES if c in cols), None)
        if u and p:
            return (t, u, p)
    return None

def _decode_if_bytes(v):
    if isinstance(v, (bytes, bytearray)):
        for enc in ("utf-8", "latin-1"):
            try:
                return v.decode(enc)
            except Exception:
                pass
        return v.decode("utf-8", errors="ignore")
    return v

def verify_user_db(username: str, password: str) -> Tuple[bool, str]:
    """
    - Auto-discovers user table and tries multiple username columns in SAME table.
    - Verifies hash with passlib (supports $1$... md5_crypt).
    - Also supports plaintext fallback if stored is not a recognized hash.
    """
    global AUTH_TABLE, AUTH_USER_COL, AUTH_PASS_COL

    try:
        # Resolve schema
        if AUTH_TABLE and AUTH_USER_COL and AUTH_PASS_COL:
            if not _table_exists(AUTH_TABLE):
                return False, f"Tabela '{AUTH_TABLE}' não existe."
            tname, pcol = AUTH_TABLE, AUTH_PASS_COL
            user_cols_to_try = [AUTH_USER_COL]
        else:
            found = _discover_user_table_and_cols()
            if not found:
                return False, "Não encontrei tabela de usuários (defina AUTH_TABLE/AUTH_USER_COL/AUTH_PASS_COL)."
            tname, discovered_user_col, pcol = found
            cols = _table_columns(tname)
            present_user_cols = [c for c in USER_COL_CANDIDATES if c in cols]
            user_cols_to_try: List[str] = []
            if "email" in present_user_cols:
                user_cols_to_try.append("email")
            if discovered_user_col in present_user_cols and discovered_user_col not in user_cols_to_try:
                user_cols_to_try.append(discovered_user_col)
            for c in present_user_cols:
                if c not in user_cols_to_try:
                    user_cols_to_try.append(c)

            AUTH_TABLE, AUTH_USER_COL, AUTH_PASS_COL = tname, (user_cols_to_try[0] if user_cols_to_try else discovered_user_col), pcol
            if AUTH_DEBUG:
                print(f"[AUTH_DEBUG] Auto-discovery: table={tname} user_cols_try={user_cols_to_try} pass_col={pcol}")

        u = username.strip()
        p = password

        for ucol in user_cols_to_try:
            q = f"SELECT `{pcol}` AS pass FROM `{tname}` WHERE `{ucol}` = :u LIMIT 1"
            with engine.connect() as conn:
                row = conn.execute(text(q), {"u": u}).mappings().first()
            if not row:
                continue

            stored = _decode_if_bytes(row.get("pass"))
            if stored is None:
                return False, "Senha não cadastrada."

            stored_s = str(stored)

            # Hash verify (preferred)
            try:
                if stored_s.startswith("$"):
                    scheme = None
                    try:
                        scheme = PWD_CTX.identify(stored_s)
                    except Exception:
                        scheme = None
                    if AUTH_DEBUG:
                        def _safe_preview(s: str, n: int = 90) -> str:
                            return s if len(s) <= n else (s[:n] + "…")
                        print(f"[AUTH_DEBUG] Found user via '{ucol}'.")
                        print(f"[AUTH_DEBUG] Stored hash preview: {_safe_preview(stored_s)!r} (len={len(stored_s)}) scheme={scheme!r}")
                        print(f"[AUTH_DEBUG] Provided preview: {_safe_preview(p, 6)!r}... (len={len(p)})")
                    ok = False
                    try:
                        ok = PWD_CTX.verify(p, stored_s)
                    except Exception as e:
                        if AUTH_DEBUG:
                            print("[AUTH_DEBUG] Erro ao verificar hash:", repr(e))
                        ok = False
                    if AUTH_DEBUG:
                        print(f"[AUTH_DEBUG] passlib.verify result: {ok}")
                    if ok:
                        return True, "ok"

                    # Extra debug for $1$ (md5-crypt): compute candidate with same salt
                    if AUTH_DEBUG and stored_s.startswith("$1$"):
                        try:
                            from passlib.hash import md5_crypt
                            cand = md5_crypt.hash(p, salt=md5_crypt.from_string(stored_s).salt)
                            print(f"[AUTH_DEBUG] md5_crypt candidate preview: {_safe_preview(cand)!r}")
                        except Exception as e:
                            print(f"[AUTH_DEBUG] md5_crypt candidate error: {e!r}")

                    return False, "Senha incorreta."
            except Exception as e:
                if AUTH_DEBUG:
                    print("[AUTH_DEBUG] Erro ao verificar hash:", repr(e))

            # Plaintext fallback
            if stored_s == p:
                return True, "ok"

            if AUTH_DEBUG:
                print(f"[AUTH_DEBUG] Found user via '{ucol}'. Stored={stored_s!r} len={len(stored_s)}; Provided len={len(p)}")

            return False, "Senha incorreta."

        return False, "Usuário não encontrado."

    except Exception as e:
        if AUTH_DEBUG:
            print("[AUTH_DEBUG] Erro ao validar credenciais:", repr(e))
        return False, "Falha ao consultar usuário (AUTH_DEBUG)."

# =========================
# Aggregation / polling (same as before)
# =========================
agg_lock = threading.Lock()
agg_state: Dict[str, object] = {"by_day_circuit": {}, "by_day_total": {}, "total_carnaval": 0}

def parse_iso_date(s: str) -> date:
    y, m, d = s.split("-")
    return date(int(y), int(m), int(d))

def daterange(d0: date, d1: date):
    cur = d0
    while cur <= d1:
        yield cur
        cur += timedelta(days=1)

def canonical_circuit_name(name: Optional[str]) -> str:
    if not name:
        return "Desconhecido"
    n = name.strip().lower()
    if "osmar" in n:
        return "Osmar"
    if "dod" in n:
        return "Dodô"
    if "batat" in n:
        return "Batatinha"
    return name.strip()

def _agg_add(day_key: str, circuit: str, value: int) -> None:
    by_day_circuit: Dict[str, Dict[str, int]] = agg_state["by_day_circuit"]  # type: ignore
    by_day_total: Dict[str, int] = agg_state["by_day_total"]  # type: ignore
    if day_key not in by_day_circuit:
        by_day_circuit[day_key] = {}
    by_day_circuit[day_key][circuit] = int(by_day_circuit[day_key].get(circuit, 0) + value)
    by_day_total[day_key] = int(by_day_total.get(day_key, 0) + value)
    agg_state["total_carnaval"] = int(agg_state.get("total_carnaval", 0) + value)

def rebuild_aggregates_from_history() -> None:
    if not os.path.exists(HISTORY_FILE):
        return
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
    except Exception:
        return
    agg_state["by_day_circuit"] = {}
    agg_state["by_day_total"] = {}
    agg_state["total_carnaval"] = 0
    for ln in lines:
        try:
            snap = json.loads(ln)
        except Exception:
            continue
        ts = snap.get("ts")
        if not ts:
            continue
        dt = datetime.fromtimestamp(int(ts) / 1000.0)
        day_key = dt.date().isoformat()
        portals = snap.get("portals") or []
        portal_to_circuit: Dict[str, str] = {}
        for p in portals:
            pid = str(p.get("idPortal"))
            c = canonical_circuit_name(p.get("nomeCircuito"))
            portal_to_circuit[pid] = c
        interval = snap.get("intervalCounts") or {}
        for pid, v in interval.items():
            try:
                val = int(v or 0)
            except Exception:
                val = 0
            if val <= 0:
                continue
            circuit = portal_to_circuit.get(str(pid), "Desconhecido")
            _agg_add(day_key, circuit, val)

with agg_lock:
    rebuild_aggregates_from_history()

cache_lock = threading.Lock()
cache: Dict[str, object] = {
    "ts": int(time.time() * 1000),
    "portals": [],
    "intervalCounts": {},
    "meta": {
        "poll_seconds": POLL_SECONDS,
        "half_life_minutes": HALF_LIFE_MINUTES,
        "event_start": EVENT_START,
        "event_end": EVENT_END,
        "alert_threshold_5min": ALERT_THRESHOLD_5MIN,
    },
    "aggregates": {},
}

def compute_aggregates_for_response(portals: List[Dict], interval_counts: Dict[str, int], ts_ms: int) -> Dict:
    now_by_circuit: Dict[str, int] = {}
    portal_to_circuit: Dict[str, str] = {}
    for p in portals:
        pid = str(p["idPortal"])
        c = canonical_circuit_name(p.get("nomeCircuito"))
        portal_to_circuit[pid] = c
    for pid, v in interval_counts.items():
        c = portal_to_circuit.get(str(pid), "Desconhecido")
        now_by_circuit[c] = int(now_by_circuit.get(c, 0) + int(v or 0))
    return {"now_by_circuit": now_by_circuit}

def refresh_once() -> None:
    ts = int(time.time() * 1000)
    with engine.connect() as conn:
        portals_rows = conn.execute(text(SQL_PORTALS_REF)).mappings().all()
        counts_rows = conn.execute(text(SQL_INTERVAL_COUNTS)).mappings().all()
    portals: List[Dict] = []
    for r in portals_rows:
        portals.append({
            "idPortal": str(r["idPortal"]),
            "nomePortal": r.get("nomePortal"),
            "idCircuito": r.get("idCircuito"),
            "nomeCircuito": r.get("nomeCircuito"),
            "idCameraRef": r.get("idCameraRef"),
            "latPortal": float(r["latPortal"]) if r["latPortal"] is not None else None,
            "lngPortal": float(r["lngPortal"]) if r["lngPortal"] is not None else None
        })
    interval_counts: Dict[str, int] = {}
    for r in counts_rows:
        interval_counts[str(r["idPortal"])] = int(r["qtd_intervalo"] or 0)

    snapshot = {
        "ts": ts,
        "portals": portals,
        "intervalCounts": interval_counts,
        "meta": {"poll_seconds": POLL_SECONDS},
        "aggregates": compute_aggregates_for_response(portals, interval_counts, ts)
    }
    with cache_lock:
        cache.update(snapshot)
    ensure_dir(HISTORY_FILE)
    with open(HISTORY_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(snapshot, ensure_ascii=False) + "\n")

def polling_loop() -> None:
    try:
        refresh_once()
    except Exception as e:
        print("[SSP] Primeira carga falhou:", repr(e))
    while True:
        time.sleep(POLL_SECONDS)
        try:
            refresh_once()
        except Exception as e:
            print("[SSP] Atualização falhou:", repr(e))

# =========================
# FastAPI app + Auth middleware
# =========================
app = FastAPI(title="SSP Carnaval Dashboard")
app.mount("/static", StaticFiles(directory="public"), name="static")

ALLOW_PATH_PREFIXES = ("/login", "/api/login", "/logout", "/static/login.html", "/static/logos", "/static/favicon")

def _is_public_path(path: str) -> bool:
    if path == "/static/index.html":
        return False
    return any(path.startswith(p) for p in ALLOW_PATH_PREFIXES)

@app.middleware("http")
async def auth_gate(request: Request, call_next):
    path = request.url.path
    if _is_public_path(path):
        return await call_next(request)
    token = request.cookies.get(COOKIE_NAME, "")
    username = verify_session(token) if token else None
    if not username:
        if path.startswith("/api/"):
            return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
        return RedirectResponse(url="/login", status_code=302)
    return await call_next(request)

@app.get("/login")
def login_page():
    return FileResponse("public/login.html")

@app.get("/logout")
def logout():
    resp = RedirectResponse(url="/login", status_code=302)
    resp.delete_cookie(COOKIE_NAME)
    return resp

@app.get("/")
def index():
    return FileResponse("public/index.html")

class LoginPayload(BaseModel):
    username: str
    password: str

@app.post("/api/login")
def api_login(payload: LoginPayload, response: Response):
    username = (payload.username or "").strip()
    password = (payload.password or "")
    if not username or not password:
        raise HTTPException(status_code=400, detail="Informe usuário e senha.")
    ok, reason = verify_user_db(username, password)
    if not ok:
        raise HTTPException(status_code=401, detail=reason)
    token = sign_session(username)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=SESSION_TTL_SECONDS
    )
    return {"ok": True}

@app.get("/api/ssp/snapshot")
def get_snapshot():
    with cache_lock:
        return cache

t = threading.Thread(target=polling_loop, daemon=True)
t.start()
