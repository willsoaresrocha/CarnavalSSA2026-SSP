import os
import json
import time
import threading
from datetime import datetime, date, timedelta
from typing import Dict, List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
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

# Carnaval (p/ gráfico diário)
EVENT_START = os.getenv("EVENT_START", "2026-02-12")
EVENT_END = os.getenv("EVENT_END", "2026-02-17")

# Portal crítico no intervalo (5 min) — usado p/ alertas/contador
ALERT_THRESHOLD_5MIN = int(os.getenv("ALERT_THRESHOLD_5MIN", "900"))

# =========================
# QUERIES (SSP)
# =========================
# 1) Portal -> câmera referência (MIN(idCamera)) para lat/lng do portal
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

# 2) Total do portal no intervalo (soma de todas as câmeras do portal nos últimos 5 min)
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
    uri = f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
    return create_engine(
        uri,
        pool_pre_ping=True,
        pool_size=8,
        max_overflow=16,
        pool_recycle=1800,
    )

engine = make_engine()

# =========================
# AGG STATE (histórico -> dia/circuito)
# =========================
# Estrutura:
# agg_state = {
#   "by_day_circuit": { "YYYY-MM-DD": { "Osmar": 123, "Dodô": 456, ... } },
#   "by_day_total":   { "YYYY-MM-DD": 999 },
#   "total_carnaval": 1234567
# }
agg_lock = threading.Lock()
agg_state: Dict[str, object] = {
    "by_day_circuit": {},
    "by_day_total": {},
    "total_carnaval": 0,
}

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
    if "dod" in n:  # Dodô
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

# =========================
# CACHE (snapshot do momento)
# =========================
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

    active = 0
    inactive = 0
    critical = 0
    for p in portals:
        pid = str(p["idPortal"])
        has_coord = (p.get("latPortal") is not None and p.get("lngPortal") is not None)
        v = int(interval_counts.get(pid, 0) or 0)
        if has_coord and v > 0:
            active += 1
        else:
            inactive += 1
        if v >= ALERT_THRESHOLD_5MIN:
            critical += 1

    dt = datetime.fromtimestamp(int(ts_ms) / 1000.0)
    today_key = dt.date().isoformat()

    with agg_lock:
        by_day_total: Dict[str, int] = agg_state.get("by_day_total", {})  # type: ignore
        by_day_circuit: Dict[str, Dict[str, int]] = agg_state.get("by_day_circuit", {})  # type: ignore
        total_carnaval: int = int(agg_state.get("total_carnaval", 0))

        total_today = int(by_day_total.get(today_key, 0))

        d0 = parse_iso_date(EVENT_START)
        d1 = parse_iso_date(EVENT_END)

        daily = []
        for d in daterange(d0, d1):
            dk = d.isoformat()
            circuits = by_day_circuit.get(dk, {})
            daily.append({
                "date": dk,
                "Osmar": int(circuits.get("Osmar", 0)),
                "Dodô": int(circuits.get("Dodô", 0)),
                "Batatinha": int(circuits.get("Batatinha", 0)),
            })

        peaks = {}
        for circuit in ["Osmar", "Dodô", "Batatinha"]:
            best_val = 0
            best_date = None
            for row in daily:
                v = int(row.get(circuit, 0))
                if v > best_val:
                    best_val = v
                    best_date = row["date"]
            peaks[circuit] = {"value": best_val, "date": best_date}

    if critical > 0:
        alerts_summary = f"{critical} portal(is) acima do threshold ({ALERT_THRESHOLD_5MIN} / 5 min)."
    else:
        alerts_summary = "Sem alertas críticos no último ciclo."

    return {
        "now_by_circuit": now_by_circuit,
        "total_today": total_today,
        "total_carnaval": total_carnaval,
        "portals_active": active,
        "portals_inactive": inactive,
        "portals_critical": critical,
        "daily_by_circuit": daily,
        "peaks_by_circuit": peaks,
        "alerts_summary": alerts_summary,
    }

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
            "lngPortal": float(r["lngPortal"]) if r["lngPortal"] is not None else None,
        })

    interval_counts: Dict[str, int] = {}
    for r in counts_rows:
        interval_counts[str(r["idPortal"])] = int(r["qtd_intervalo"] or 0)

    dt = datetime.fromtimestamp(ts / 1000.0)
    day_key = dt.date().isoformat()

    portal_to_circuit = {p["idPortal"]: canonical_circuit_name(p.get("nomeCircuito")) for p in portals}

    with agg_lock:
        for pid, v in interval_counts.items():
            val = int(v or 0)
            if val <= 0:
                continue
            circuit = portal_to_circuit.get(str(pid), "Desconhecido")
            _agg_add(day_key, circuit, val)

    aggregates = compute_aggregates_for_response(portals, interval_counts, ts)

    snapshot = {
        "ts": ts,
        "portals": portals,
        "intervalCounts": interval_counts,
        "meta": {
            "poll_seconds": POLL_SECONDS,
            "half_life_minutes": HALF_LIFE_MINUTES,
            "event_start": EVENT_START,
            "event_end": EVENT_END,
            "alert_threshold_5min": ALERT_THRESHOLD_5MIN,
        },
        "aggregates": aggregates,
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

app = FastAPI(title="SSP Carnaval Dashboard")

app.mount("/static", StaticFiles(directory="public"), name="static")

@app.get("/")
def index():
    return FileResponse("public/novo.html")

@app.get("/api/ssp/snapshot")
def get_snapshot():
    with cache_lock:
        return cache

@app.get("/api/ssp/history")
def get_history():
    if not os.path.exists(HISTORY_FILE):
        return {"error": "Sem histórico ainda."}
    with open(HISTORY_FILE, "r", encoding="utf-8") as f:
        return {"history_jsonl": f.read()}

@app.get("/api/ssp/cameras")
def get_cameras():
    # MOCK inicial (depois você troca por query no banco)
    payload = {
        "zones": [
            {
                "zone_id": "entrada_barra",
                "zone_name": "Zona Entrada Barra",
                "cameras": [
                    {"camera_id": 101, "camera_name": "CAM 101 - Barra (Ref)", "last_image": "/static/mock/cam_101.jpg", "last_update": "2026-02-11 20:32:00"},
                    {"camera_id": 102, "camera_name": "CAM 102 - Barra (Aux)", "last_image": "/static/mock/cam_102.jpg", "last_update": "2026-02-11 20:32:00"},
                ],
            },
            {
                "zone_id": "entrada_ondina",
                "zone_name": "Zona Entrada Ondina",
                "cameras": [
                    {"camera_id": 201, "camera_name": "CAM 201 - Ondina (Ref)", "last_image": "/static/mock/cam_201.jpg", "last_update": "2026-02-11 20:32:00"},
                    {"camera_id": 202, "camera_name": "CAM 202 - Ondina (Aux)", "last_image": "/static/mock/cam_202.jpg", "last_update": "2026-02-11 20:32:00"},
                ],
            },
        ]
    }
    return payload

t = threading.Thread(target=polling_loop, daemon=True)
t.start()
