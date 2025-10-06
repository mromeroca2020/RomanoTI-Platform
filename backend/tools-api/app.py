from fastapi import FastAPI, HTTPException, Depends, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import jwt
from passlib.context import CryptContext

# NOC / externos
import requests  # <— para /noc/http-check
from dns import resolver, exception as dns_exc  # <— para /noc/dns-lookup
from urllib.parse import urlparse

import os, json, time, socket, platform, subprocess, psutil
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Respuestas vacías a OPTIONS preflight
from starlette.responses import Response

# =========================
# Configuración / Entorno
# =========================
JWT_SECRET = os.getenv("ROMANOTI_JWT_SECRET", "change-me")  # ⚠️ cámbialo en prod
JWT_ALG    = "HS256"
JWT_HOURS  = int(os.getenv("ROMANOTI_JWT_HOURS", "8"))

def _parse_origins(val: str) -> List[str]:
    try:
        j = json.loads(val)
        if isinstance(j, list):
            return j
    except Exception:
        pass
    if not val:
        return ["*"]
    return [x.strip() for x in val.split(",") if x.strip()]

ALLOWED_ORIGINS = _parse_origins(os.getenv("ROMANOTI_ALLOWED_ORIGINS", "*"))

PWD        = Path(__file__).resolve().parent
USERS_FILE = PWD / "users.json"

DATA_DIR     = (PWD / "data"); DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_FILE = DATA_DIR / "reports.jsonl"
LATEST_FILE  = DATA_DIR / "latest.json"

# API key de organización (misma que usas para /client/report)
ORG_API_KEY  = os.getenv("ROMANOTI_ORG_API_KEY", "MySecret123$")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# =========================
# App y CORS
# =========================
app = FastAPI(title="RomanoTI Tools API", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=86400,
)

@app.options("/{full_path:path}")
async def any_options(full_path: str, request: Request):
    return Response(status_code=204)

# =========================
# Modelos comunes
# =========================
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class User(BaseModel):
    username: str
    roles: List[str] = []

class PingRequest(BaseModel):
    host: str
    count: int = 4

class TraceRequest(BaseModel):
    host: str

class PortScanRequest(BaseModel):
    host: str
    start: int = 1
    end: int = 1024
    ports: Optional[List[int]] = None
    timeout_ms: int = 500

# =========================
# Usuarios / Auth helpers
# =========================
def load_users() -> Dict[str, Dict[str, Any]]:
    """
    Estructura esperada en users.json:
    {
      "users": [
        {"username": "eng1", "password": "$2b$....", "roles": ["engineer"] }
      ]
    }
    Si el password no es bcrypt, se compara en claro (dev).
    """
    if not USERS_FILE.exists():
        return {"users": [{"username": "eng1", "password": "eng1", "roles": ["engineer"]}]}
    with USERS_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)

def verify_password(plain: str, stored: str) -> bool:
    if stored.startswith(("$2a$", "$2b$", "$2y$")):
        return pwd_context.verify(plain, stored)
    return plain == stored

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    exp = datetime.utcnow() + (expires_delta or timedelta(hours=JWT_HOURS))
    to_encode.update({"exp": exp})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)

def authenticate_user(username: str, password: str) -> Optional[User]:
    data = load_users()
    for u in data.get("users", []):
        if u.get("username") == username and verify_password(password, u.get("password","")):
            return User(username=username, roles=u.get("roles") or [])
    return None

# =========================
# Auth
# =========================
@app.post("/auth/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    token = create_access_token({"sub": user.username, "roles": user.roles})
    return {"access_token": token, "token_type": "bearer"}

# =========================
# Salud / Info
# =========================
@app.get("/health")
def health():
    return {"status": "ok", "service": "romanoti-tools", "ts": datetime.utcnow().isoformat()+"Z"}

@app.get("/system/info")
def system_info():
    vm = psutil.virtual_memory()
    info = {
        "os": platform.platform(),
        "version": platform.version(),
        "arch": platform.machine(),
        "cpu_cores": psutil.cpu_count(logical=True),
        "ram_gb": round(vm.total / (1024**3), 2),
        "hostname": socket.gethostname(),
        "ts": datetime.utcnow().isoformat()+"Z",
    }
    return info

@app.get("/network/info")
def network_info():
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    interfaces = {}
    for ifname, lst in addrs.items():
        ips = []
        for a in lst:
            if a.family == socket.AF_INET:
                ips.append({"ip": a.address, "netmask": a.netmask})
            elif hasattr(socket, "AF_INET6") and a.family == socket.AF_INET6:
                ips.append({"ip6": a.address, "netmask": a.netmask})
        interfaces[ifname] = {
            "isup": stats.get(ifname).isup if ifname in stats else None,
            "speed": getattr(stats.get(ifname, None), "speed", None) if ifname in stats else None,
            "addrs": ips
        }
    return {"hostname": socket.gethostname(), "interfaces": interfaces}

# =========================
# Utilidades de red (CLI)
# =========================
def _run(cmd: List[str], timeout: int = 20) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode(errors="ignore")
    except subprocess.CalledProcessError as e:
        return e.output.decode(errors="ignore")
    except Exception as e:
        return f"error: {e}"

@app.post("/network/ping")
def ping(req: PingRequest):
    if platform.system().lower().startswith("win"):
        cmd = ["ping", "-n", str(req.count), req.host]
    else:
        cmd = ["ping", "-c", str(req.count), req.host]
    out = _run(cmd, timeout=30)
    return {"host": req.host, "count": req.count, "output": out}

@app.post("/network/traceroute")
def traceroute(req: TraceRequest):
    if platform.system().lower().startswith("win"):
        cmd = ["tracert", "-d", "-h", "20", req.host]
    else:
        cmd = ["traceroute", "-n", "-m", "20", req.host]
    out = _run(cmd, timeout=60)
    return {"host": req.host, "output": out}

def _check_port(host: str, port: int, timeout: float) -> Optional[int]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port
    except Exception:
        return None

@app.post("/network/portscan")
def portscan(req: PortScanRequest):
    ports: List[int]
    if req.ports and len(req.ports) > 0:
        ports = sorted(set([int(p) for p in req.ports if 1 <= int(p) <= 65535]))
    else:
        s = max(1, int(req.start)); e = min(65535, int(req.end))
        if e < s: s, e = e, s
        ports = list(range(s, e+1))

    timeout = max(0.05, req.timeout_ms / 1000.0)
    open_ports: List[int] = []
    with ThreadPoolExecutor(max_workers=200) as ex:
        futures = {ex.submit(_check_port, req.host, p, timeout): p for p in ports}
        for fu in as_completed(futures):
            res = fu.result()
            if res:
                open_ports.append(res)

    return {"host": req.host, "open": sorted(open_ports), "scanned": len(ports), "timeout_ms": req.timeout_ms}

# =========================
# Agente On-Prem (LAN)
# =========================
@app.post("/client/report")
async def client_report(
    request: Request,
    x_api_key: Optional[str] = Header(None),
    x_agent: Optional[str] = Header(None),
):
    if not x_api_key or x_api_key != ORG_API_KEY:
        raise HTTPException(status_code=401, detail="invalid x-api-key")
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON")

    record = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "agent": x_agent or payload.get("agent") or "unknown",
        "data": payload,
    }
    with REPORTS_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    with LATEST_FILE.open("w", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=False)
    return {"ok": True, "saved": True}

@app.get("/client/reports/latest")
def client_reports_latest(x_api_key: Optional[str] = Header(None)):
    if not x_api_key or x_api_key != ORG_API_KEY:
        raise HTTPException(status_code=401, detail="invalid x-api-key")
    if not LATEST_FILE.exists():
        return {"ok": True, "empty": True, "message": "no reports yet"}
    with LATEST_FILE.open("r", encoding="utf-8") as f:
        record = json.load(f)
    return record

# =========================
# NOC Endpoints (HTTP / DNS)
# =========================
class HttpCheckReq(BaseModel):
    url: str
    timeout_s: int = 8
    verify_tls: bool = True

@app.post("/noc/http-check")
def noc_http_check(req: HttpCheckReq, x_api_key: Optional[str] = Header(None)):
    """
    Chequeo HTTP(S) simple con requests.
    Devuelve: status code, latencia ms, URL final, headers básicos, bytes, IP resuelta.
    Protegido por x-api-key.
    """
    if not x_api_key or x_api_key != ORG_API_KEY:
        raise HTTPException(status_code=401, detail="invalid x-api-key")

    try:
        u = urlparse(req.url)
        if u.scheme not in ("http", "https"):
            raise ValueError("url must start with http:// or https://")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    host = u.hostname
    resolved_ip = None
    try:
        if host:
            resolved_ip = socket.gethostbyname(host)
    except Exception:
        pass

    t0 = time.time()
    try:
        r = requests.get(
            req.url,
            timeout=req.timeout_s,
            verify=req.verify_tls,
            allow_redirects=True,
            headers={"User-Agent":"Romanoti-NOC/1.0"}
        )
        elapsed_ms = int((time.time()-t0)*1000)
        keep = {"server","content-type","content-length","date","cache-control"}
        limited_headers = {k:v for k,v in r.headers.items() if k.lower() in keep}
        return {
            "ok": True,
            "status": r.status_code,
            "elapsed_ms": elapsed_ms,
            "resolved_ip": resolved_ip,
            "final_url": r.url,
            "headers": limited_headers,
            "bytes": len(r.content),
        }
    except requests.exceptions.SSLError as e:
        elapsed_ms = int((time.time()-t0)*1000)
        return {"ok": False, "ssl_error": True, "elapsed_ms": elapsed_ms, "resolved_ip": resolved_ip, "error": str(e)}
    except Exception as e:
        elapsed_ms = int((time.time()-t0)*1000)
        return {"ok": False, "elapsed_ms": elapsed_ms, "resolved_ip": resolved_ip, "error": str(e)}

class DnsLookupReq(BaseModel):
    domain: str
    type: str = "A"

@app.post("/noc/dns-lookup")
def noc_dns_lookup(req: DnsLookupReq, x_api_key: Optional[str] = Header(None)):
    """
    Consulta DNS (A/AAAA/MX/TXT/NS) usando dnspython.
    Protegido por x-api-key.
    """
    if not x_api_key or x_api_key != ORG_API_KEY:
        raise HTTPException(status_code=401, detail="invalid x-api-key")

    dom = req.domain.strip().rstrip(".")
    rtype = (req.type or "A").upper()
    out = {"domain": dom, "type": rtype}

    try:
        ans = resolver.resolve(dom, rtype)
        values = []
        for r in ans:
            try:
                values.append(r.to_text())
            except Exception:
                values.append(str(r))
        out["answers"] = values
        return out
    except (dns_exc.DNSException, Exception) as e:
        raise HTTPException(status_code=400, detail=f"dns error: {e}")

# =========================
# NOC Endpoint (NUEVO): TCP Port Check
# =========================
class TcpCheckReq(BaseModel):
    host: str
    port: int
    timeout_s: int = 5

@app.post("/noc/tcp-check")
def noc_tcp_check(req: TcpCheckReq, x_api_key: Optional[str] = Header(None)):
    """
    Verifica si un puerto TCP está accesible y mide latencia.
    Devuelve: ok, host, port, latency_ms y (si hay) un pequeño banner del servicio.
    Protegido por x-api-key.
    """
    if not x_api_key or x_api_key != ORG_API_KEY:
        raise HTTPException(status_code=401, detail="invalid x-api-key")

    host = req.host.strip()
    port = int(req.port)
    timeout = max(1, int(req.timeout_s))

    # IP resuelta (mejor esfuerzo)
    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(host)
    except Exception:
        pass

    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(0.5)  # lectura rápida opcional
            banner = b""
            try:
                banner = s.recv(64)  # algunos servicios envían banner inicial
            except Exception:
                pass
            latency_ms = round((time.perf_counter() - t0) * 1000, 1)
            return {
                "ok": True,
                "host": host,
                "port": port,
                "resolved_ip": resolved_ip,
                "latency_ms": latency_ms,
                "banner": banner.decode("latin1", errors="ignore") if banner else ""
            }
    except Exception as e:
        latency_ms = round((time.perf_counter() - t0) * 1000, 1)
        return {
            "ok": False,
            "host": host,
            "port": port,
            "resolved_ip": resolved_ip,
            "latency_ms": latency_ms,
            "error": str(e)
        }
        # =========================
# SOC Endpoints (NEW)
# =========================

# Archivo donde guardaremos alertas de demo
SOC_ALERTS_FILE = DATA_DIR / "soc_alerts.jsonl"

class SocAlertIn(BaseModel):
    source: str                  # ej: "edr", "wazuh", "firewall"
    severity: str                # "low" | "medium" | "high" | "critical"
    title: str
    details: Dict[str, Any] = {} # payload libre (host, user, hash, ip, etc.)

@app.post("/soc/alerts")
def soc_alerts_receive(alert: SocAlertIn, x_api_key: Optional[str] = Header(None)):
    """
    Recibe alertas desde agentes/EDR (mock). Protegido por x-api-key.
    Persiste cada alerta en data/soc_alerts.jsonl (1 línea JSON por alerta).
    """
    if not x_api_key or x_api_key != ORG_API_KEY:
        raise HTTPException(status_code=401, detail="invalid x-api-key")

    record = {
        "ts": datetime.utcnow().isoformat()+"Z",
        "alert": alert.dict(),
    }
    with SOC_ALERTS_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return {"ok": True, "saved": True}

def _tail_jsonl(path: Path, limit: int) -> List[Dict[str, Any]]:
    """
    Devuelve las últimas N líneas de un .jsonl como lista de dicts (best effort).
    """
    if not path.exists():
        return []
    out: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        lines = f.readlines()[-max(1, int(limit)):]
    for ln in lines:
        try:
            out.append(json.loads(ln.strip()))
        except Exception:
            pass
    return out

@app.get("/soc/alerts/recent")
def soc_alerts_recent(limit: int = 50, x_api_key: Optional[str] = Header(None)):
    """
    Lista las últimas N alertas guardadas (para dashboard/demo). Protegido por x-api-key.
    """
    if not x_api_key or x_api_key != ORG_API_KEY:
        raise HTTPException(status_code=401, detail="invalid x-api-key")
    return {"ok": True, "count": int(limit), "items": _tail_jsonl(SOC_ALERTS_FILE, limit)}

class PlaybookRunReq(BaseModel):
    playbook_id: str             # ej: "isolate-host" | "reset-user" | "block-ip"
    target: Optional[str] = None # hostname, usuario o IP (según playbook)

@app.post("/soc/playbooks/run")
def soc_playbook_run(req: PlaybookRunReq, x_api_key: Optional[str] = Header(None)):
    """
    Ejecuta un playbook simulado y devuelve pasos/resultado (mock).
    Ideal para botones en /it-soc.
    """
    if not x_api_key or x_api_key != ORG_API_KEY:
        raise HTTPException(status_code=401, detail="invalid x-api-key")

    steps: List[str]
    if req.playbook_id == "isolate-host":
        steps = [
            "Lookup endpoint in EDR",
            "Issue isolate command (EDR API)",
            "Notify NOC/SOC & create ticket",
        ]
    elif req.playbook_id == "reset-user":
        steps = [
            "Disable user sign-in (IdP)",
            "Force password reset",
            "Revoke refresh tokens / sessions",
        ]
    elif req.playbook_id == "block-ip":
        steps = [
            "Push IP to firewall blocklist",
            "Validate deny rule propagation",
        ]
    else:
        steps = ["Unknown playbook — no-op"]

    return {
        "ok": True,
        "playbook": req.playbook_id,
        "target": req.target,
        "steps": steps,
        "executed_at": datetime.utcnow().isoformat()+"Z",
        "result": "simulated-success"
    }
# ======== SOC: Métricas y Búsqueda (añadir al final del app.py) ========
from pydantic import BaseModel
from datetime import datetime, timedelta

# Archivos (si ya los definiste arriba, omite estas líneas)
DATA_DIR.mkdir(parents=True, exist_ok=True)
SOC_ALERTS_FILE = DATA_DIR / "soc_alerts.jsonl"   # donde guardas las alertas

# Util para parsear ISO8601 con 'Z'
def _parse_iso(ts: str) -> Optional[datetime]:
    try:
        # soporta '2025-10-01T01:23:45.123456Z' o sin microsegundos
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None

# -------- Modelo de búsqueda --------
class SocSearchQuery(BaseModel):
    # filtros opcionales
    severities: Optional[List[str]] = None     # ["low","medium","high","critical"]
    sources:    Optional[List[str]] = None     # ["edr","siem","email"...]
    query:      Optional[str] = None           # texto libre (title/details)
    since:      Optional[str] = None           # ISO8601 (ej: "2025-10-01T00:00:00Z")
    until:      Optional[str] = None           # ISO8601
    limit:      int = 100                      # tope de resultados

# -------- Stats rápidas en ventana (por defecto 24h) --------
@app.get("/soc/alerts/stats")
def soc_alerts_stats(window_h: int = 24, x_api_key: Optional[str] = Header(None)):
    if not x_api_key or x_api_key != ORG_API_KEY:
        raise HTTPException(status_code=401, detail="invalid x-api-key")

    if not SOC_ALERTS_FILE.exists():
        return {"total": 0, "by_severity": {}, "by_source": {}, "window_h": window_h}

    cutoff = datetime.utcnow() - timedelta(hours=window_h)
    total = 0
    by_sev: Dict[str, int] = {}
    by_src: Dict[str, int] = {}

    with SOC_ALERTS_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue

            ts = _parse_iso(rec.get("ts", ""))
            if ts is None or ts < cutoff:
                continue

            total += 1
            sev = (rec.get("severity") or "").lower() or "unknown"
            src = (rec.get("source") or "").lower() or "unknown"
            by_sev[sev] = by_sev.get(sev, 0) + 1
            by_src[src] = by_src.get(src, 0) + 1

    return {
        "total": total,
        "by_severity": by_sev,
        "by_source": by_src,
        "window_h": window_h,
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }

# -------- Búsqueda flexible --------
@app.post("/soc/alerts/search")
def soc_alerts_search(q: SocSearchQuery, x_api_key: Optional[str] = Header(None)):
    if not x_api_key or x_api_key != ORG_API_KEY:
        raise HTTPException(status_code=401, detail="invalid x-api-key")

    if not SOC_ALERTS_FILE.exists():
        return []

    severities = set([s.lower() for s in (q.severities or [])])
    sources    = set([s.lower() for s in (q.sources or [])])
    txt        = (q.query or "").lower().strip()
    since_dt   = _parse_iso(q.since) if q.since else None
    until_dt   = _parse_iso(q.until) if q.until else None

    out = []
    with SOC_ALERTS_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue

            ts = _parse_iso(rec.get("ts", ""))
            if since_dt and (ts is None or ts < since_dt): 
                continue
            if until_dt and (ts is None or ts > until_dt): 
                continue

            if severities and (rec.get("severity","").lower() not in severities):
                continue
            if sources and (rec.get("source","").lower() not in sources):
                continue

            if txt:
                haystack = (json.dumps(rec, ensure_ascii=False) or "").lower()
                if txt not in haystack:
                    continue

            out.append(rec)
            if len(out) >= max(1, min(1000, q.limit)):  # límites sanos
                break

    return out
# =========================
# EXT: Email & TLS posture + Field/SOC extras
# =========================
from pydantic import BaseModel
import ssl
from datetime import datetime
from typing import Optional, List, Dict, Any

# ---------- TLS Cert check ----------
class TLSCheckReq(BaseModel):
    host: str
    port: int = 443

def _parse_openssl_time(s: str) -> datetime:
    # ej: 'Oct  1 12:00:00 2027 GMT'
    return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z")

@app.post("/ext/tls")
def ext_tls(req: TLSCheckReq, x_api_key: Optional[str] = Header(None)):
    if not x_api_key or x_api_key != ORG_API_KEY:
        raise HTTPException(status_code=401, detail="invalid x-api-key")

    host, port = req.host.strip(), int(req.port or 443)

    # Primero intentamos verificación normal (cadena válida)
    ctx = ssl.create_default_context()
    verified = True
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except Exception as e:
        # Reintentamos sin verificación para al menos leer fechas/SAN
        verified = False
        ctx = ssl._create_unverified_context()
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
        except Exception as e2:
            raise HTTPException(status_code=400, detail=f"tls error: {e2}")

    not_after = cert.get("notAfter")
    not_before = cert.get("notBefore")
    san = [v for (k, v) in cert.get("subjectAltName", []) if k.lower() == "dns"]
    issuer = ", ".join("=".join(t) for t in cert.get("issuer", [("CN","?")])[-1])
    subject = ", ".join("=".join(t) for t in cert.get("subject", [("CN","?")])[-1])

    # Days left
    days_left = None
    try:
        na = _parse_openssl_time(not_after)
        days_left = (na - datetime.utcnow()).days
    except Exception:
        pass

    return {
        "ok": True,
        "verified_chain": verified,
        "host": host,
        "port": port,
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before,
        "not_after": not_after,
        "days_left": days_left,
        "san_dns": san,
    }

# ---------- Email posture (MX / SPF / DMARC) ----------
class EmailDNSReq(BaseModel):
    domain: str

@app.post("/ext/emaildns")
def ext_emaildns(req: EmailDNSReq, x_api_key: Optional[str] = Header(None)):
    if not x_api_key or x_api_key != ORG_API_KEY:
        raise HTTPException(status_code=401, detail="invalid x-api-key")

    dom = req.domain.strip().rstrip(".")

    out: Dict[str, Any] = {"domain": dom}

    def _res(rr, typ):
        try:
            ans = resolver.resolve(rr, typ)
            return [r.to_text() for r in ans]
        except Exception:
            return []

    mx = _res(dom, "MX")
    spf_txt = [t for t in _res(dom, "TXT") if t.lower().startswith('"v=spf1') or t.lower().startswith('v=spf1')]
    dmarc = _res(f"_dmarc.{dom}", "TXT")

    dmarc_pol = None
    if dmarc:
        try:
            txt = dmarc[0].strip('"').lower()
            import re
            m = re.search(r"p=(none|quarantine|reject)", txt)
            if m:
                dmarc_pol = m.group(1)
        except Exception:
            pass

    out.update({
        "mx": mx,
        "spf": spf_txt,
        "dmarc": dmarc,
        "summary": {
            "has_mx": len(mx) > 0,
            "has_spf": any(s.lower().startswith(('"v=spf1', 'v=spf1')) for s in spf_txt),
            "dmarc_policy": dmarc_pol or "missing",
        }
    })
    return out

# ---------- Service Check (agregador rápido para demos) ----------
class ServiceCheckReq(BaseModel):
    host: Optional[str] = None           # p.ej. 8.8.8.8
    url: Optional[str] = None            # p.ej. https://example.com
    ports: Optional[List[int]] = [22, 80, 443, 3389, 445, 25, 587]
    ping_count: int = 2
    timeout_ms: int = 500
    verify_tls: bool = True

@app.post("/noc/service-check")
def noc_service_check(req: ServiceCheckReq, x_api_key: Optional[str] = Header(None)):
    if not x_api_key or x_api_key != ORG_API_KEY:
        raise HTTPException(status_code=401, detail="invalid x-api-key")

    result: Dict[str, Any] = {"ok": True, "ts": datetime.utcnow().isoformat()+"Z", "host": req.host, "url": req.url}

    # Ping
    if req.host:
        try:
            if platform.system().lower().startswith("win"):
                cmd = ["ping", "-n", str(req.ping_count), req.host]
            else:
                cmd = ["ping", "-c", str(req.ping_count), req.host]
            out = _run(cmd, timeout=20)
            result["ping"] = {"ok": True, "output": out}
        except Exception as e:
            result["ping"] = {"ok": False, "error": str(e)}

    # Port quick scan
    if req.host and req.ports:
        try:
            open_ports: List[int] = []
            timeout = max(0.05, req.timeout_ms / 1000.0)
            with ThreadPoolExecutor(max_workers=min(100, len(req.ports))) as ex:
                futures = {ex.submit(_check_port, req.host, p, timeout): p for p in req.ports}
                for fu in as_completed(futures):
                    r = fu.result()
                    if r:
                        open_ports.append(r)
            result["ports"] = {"scanned": req.ports, "open": sorted(open_ports)}
        except Exception as e:
            result["ports"] = {"error": str(e)}

    # HTTP/TLS check
    if req.url:
        try:
            u = urlparse(req.url)
            if u.scheme not in ("http", "https"):
                raise ValueError("url must start with http:// or https://")
            t0 = time.time()
            r = requests.get(req.url, timeout=8, verify=req.verify_tls, allow_redirects=True, headers={"User-Agent":"Romanoti-NOC/1.0"})
            elapsed_ms = int((time.time()-t0)*1000)
            keep = {"server","content-type","content-length","date","cache-control"}
            result["http"] = {
                "status": r.status_code,
                "elapsed_ms": elapsed_ms,
                "final_url": r.url,
                "headers": {k:v for k,v in r.headers.items() if k.lower() in keep},
                "bytes": len(r.content),
            }
        except Exception as e:
            result["http"] = {"error": str(e)}

    return result

# ---------- SOC Telemetry ingest (demo) ----------
@app.post("/soc/telemetry/ingest")
def soc_telemetry_ingest(payload: Dict[str, Any], x_api_key: Optional[str] = Header(None)):
    if not x_api_key or x_api_key != ORG_API_KEY:
        raise HTTPException(status_code=401, detail="invalid x-api-key")

    # Guardamos el evento para demo/corr
    ev = {"ts": datetime.utcnow().isoformat()+"Z", **payload}
    with (DATA_DIR / "soc_events.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    # Reglas muy simples para demo (si coincide, creamos alerta)
    # 1) powershell sospechoso
    cmd = (payload.get("process_cmdline") or "").lower()
    if "powershell" in cmd and ("downloadstring" in cmd or "encodedcommand" in cmd):
        _ = _soc_save_alert({
            "source": "edr",
            "severity": "high",
            "title": "Suspicious PowerShell",
            "details": {"cmd": payload.get("process_cmdline"), "host": payload.get("host")}
        })

    # 2) demasiados fallos de login
    if payload.get("event") == "auth_fail" and int(payload.get("count", 0)) >= 5:
        _ = _soc_save_alert({
            "source": "auth",
            "severity": "medium",
            "title": "Multiple login failures",
            "details": {"user": payload.get("user"), "src": payload.get("src_ip")}
        })

    return {"ok": True}

# Helper: reutiliza el mismo “save” que uses en /soc/alerts
def _soc_save_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    rec = {"ts": datetime.utcnow().isoformat()+"Z", **alert}
    with (DATA_DIR / "soc_alerts.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return rec

# ---------- Playbooks: preview ----------
class PlaybookReq(BaseModel):
    playbook_id: str

@app.post("/soc/playbooks/preview")
def soc_playbook_preview(req: PlaybookReq, x_api_key: Optional[str] = Header(None)):
    if not x_api_key or x_api_key != ORG_API_KEY:
        raise HTTPException(status_code=401, detail="invalid x-api-key")

    catalog = {
        "isolate-host": [
            "Lookup endpoint in EDR",
            "Issue isolate command (EDR API)",
            "Notify NOC/SOC & create ticket"
        ],
        "block-ip": [
            "Push temp firewall rule to edge",
            "Validate no false positives",
            "Schedule rule cleanup"
        ],
        "reset-user": [
            "Force sign-out in IdP",
            "Reset password & revoke tokens",
            "Notify user and document"
        ]
    }
    steps = catalog.get(req.playbook_id)
    if not steps:
        raise HTTPException(status_code=400, detail="unknown playbook_id")
    return {"ok": True, "playbook": req.playbook_id, "steps": steps}
# =========================
# EASM Lite (External Attack Surface Monitor)
# =========================
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import ssl, ipaddress

class EasmScanReq(BaseModel):
    domain: str
    # subdominios sugeridos (puedes sobreescribir desde el body)
    subdomains: Optional[List[str]] = None
    # puertos a probar con TCP connect (rápido, respetuoso)
    check_ports: Optional[List[int]] = [80, 443, 22, 3389, 445, 25, 110, 143, 587, 993, 995]
    timeout_ms: int = 500
    tls_port: int = 443
    verify_tls: bool = True  # sólo afecta a la sonda HTTP si en el futuro la agregas

def _is_private_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except Exception:
        return False

def _dns_list(rr: str, typ: str) -> List[str]:
    try:
        ans = resolver.resolve(rr, typ)
        out = []
        for r in ans:
            try:
                out.append(r.to_text())
            except Exception:
                out.append(str(r))
        return out
    except Exception:
        return []

def _tls_probe_quick(host: str, port: int) -> Dict[str, Any]:
    """
    Handshake TLS para extraer fechas/SAN/issuer/subject, con reintento no verificado
    para al menos leer el cert aunque la cadena esté mala. No descarga contenido.
    """
    if not host:
        return {"ok": False, "error": "no host"}

    def _do_handshake(verify: bool):
        ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert()

    verified = True
    try:
        cert = _do_handshake(True)
    except Exception:
        verified = False
        try:
            cert = _do_handshake(False)
        except Exception as e2:
            return {"ok": False, "error": f"tls error: {e2}"}

    not_after = cert.get("notAfter")
    not_before = cert.get("notBefore")
    san = [v for (k, v) in cert.get("subjectAltName", []) if k.lower() == "dns"]
    issuer = ", ".join("=".join(t) for t in cert.get("issuer", [("CN","?")])[-1])
    subject = ", ".join("=".join(t) for t in cert.get("subject", [("CN","?")])[-1])

    days_left = None
    try:
        # formato típico 'Oct  1 12:00:00 2027 GMT'
        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (dt - datetime.utcnow()).days
    except Exception:
        pass

    return {
        "ok": True,
        "verified_chain": verified,
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before,
        "not_after": not_after,
        "days_left": days_left,
        "san_dns": san,
        "port": port,
        "host": host,
    }

def _email_posture(domain: str) -> Dict[str, Any]:
    # similar a /ext/emaildns pero local para no invocar rutas
    dom = domain.strip().rstrip(".")
    out: Dict[str, Any] = {"domain": dom}

    mx = _dns_list(dom, "MX")
    txt = _dns_list(dom, "TXT")
    spf = [t for t in txt if t.lower().startswith('"v=spf1') or t.lower().startswith('v=spf1')]
    dmarc = _dns_list(f"_dmarc.{dom}", "TXT")

    pol = "missing"
    if dmarc:
        try:
            low = dmarc[0].strip('"').lower()
            import re
            m = re.search(r"p=(none|quarantine|reject)", low)
            if m: pol = m.group(1)
        except Exception:
            pass

    out.update({
        "mx": mx,
        "spf": spf,
        "dmarc": dmarc,
        "summary": {
            "has_mx": len(mx) > 0,
            "has_spf": len(spf) > 0,
            "dmarc_policy": pol
        }
    })
    return out

@app.post("/easm/scan")
def easm_scan(req: EasmScanReq, x_api_key: Optional[str] = Header(None)):
    """
    EASM Lite:
      - DNS básicos (A/AAAA/MX/NS/TXT)
      - Postura de correo (SPF/DMARC)
      - TLS probe (expiración/emisor/SAN)
      - Descubrimiento corto de subdominios + ports
      - Findings + risk_score (0–100; 100 es mejor)
    Protegido por x-api-key.
    """
    if not x_api_key or x_api_key != ORG_API_KEY:
        raise HTTPException(status_code=401, detail="invalid x-api-key")

    domain = req.domain.strip().rstrip(".")
    if not domain:
        raise HTTPException(status_code=400, detail="domain required")

    # Subdominios default "seguros"
    subs = req.subdomains or [
        "www","mail","vpn","remote","portal","autodiscover","owa",
        "api","app","dev","staging","secure","git","jira","rdp","citrix"
    ]
    ports = list(dict.fromkeys(int(p) for p in (req.check_ports or [])))[:30]  # límite sano

    # DNS básicos
    dns_data = {
        "A": _dns_list(domain, "A"),
        "AAAA": _dns_list(domain, "AAAA"),
        "MX": _dns_list(domain, "MX"),
        "NS": _dns_list(domain, "NS"),
        "TXT": _dns_list(domain, "TXT"),
    }

    # Postura de correo
    email = _email_posture(domain)

    # TLS principal
    tls_info = _tls_probe_quick(domain, int(req.tls_port))

    # Descubrimiento + ports
    timeout = max(0.05, req.timeout_ms / 1000.0)
    sub_results: List[Dict[str, Any]] = []

    # Resolver subdominios (A)
    for s in subs:
        fqdn = f"{s}.{domain}"
        ips = _dns_list(fqdn, "A")
        if not ips:
            continue

        # Chequeo de puertos para el primer IP/hostname (rápido)
        open_ports: List[int] = []
        try:
            with ThreadPoolExecutor(max_workers=min(60, len(ports))) as ex:
                futs = {ex.submit(_check_port, fqdn, p, timeout): p for p in ports}
                for fu in as_completed(futs):
                    r = fu.result()
                    if r: open_ports.append(r)
        except Exception:
            pass

        sub_results.append({
            "host": fqdn,
            "ips": ips,
            "has_private_ip": any(_is_private_ip(ip) for ip in ips),
            "open_ports": sorted(open_ports),
        })

    # Findings & scoring
    findings: List[Dict[str, Any]] = []
    risk = 100  # base

    # Email posture findings
    if not email["summary"]["has_spf"]:
        findings.append({"sev": "medium", "id": "spf_missing", "msg": "SPF ausente"})
        risk -= 10
    pol = email["summary"]["dmarc_policy"]
    if pol == "missing" or pol == "none":
        findings.append({"sev": "medium", "id": "dmarc_weak", "msg": f"DMARC {pol}"})
        risk -= 10
    if email["mx"] and ('0 .' in [m.strip().lower() for m in email["mx"]]):
        findings.append({"sev": "low", "id": "null_mx", "msg": "Null MX detectado"})

    # TLS findings
    if tls_info.get("ok"):
        days_left = tls_info.get("days_left")
        if isinstance(days_left, int):
            if days_left < 7:
                findings.append({"sev": "high", "id": "tls_expiring", "msg": f"Certificado expira en {days_left} días"})
                risk -= 25
            elif days_left < 30:
                findings.append({"sev": "medium", "id": "tls_expiring_soon", "msg": f"Certificado expira en {days_left} días"})
                risk -= 10
    else:
        findings.append({"sev": "medium", "id": "tls_probe_failed", "msg": f"No se pudo leer TLS: {tls_info.get('error')}"})
        risk -= 5

    # Puertos “sensibles” expuestos
    risky_map = {3389: ("high","RDP abierto"), 445: ("high","SMB expuesto"), 22: ("medium","SSH expuesto")}
    for sub in sub_results:
        for p in sub.get("open_ports", []):
            if p in risky_map:
                sev, label = risky_map[p]
                findings.append({"sev": sev, "id": f"port_{p}", "host": sub["host"], "msg": label})
                risk -= (20 if sev == "high" else 10)

        if sub.get("has_private_ip"):
            findings.append({"sev":"low","id":"private_ip_dns","host":sub["host"],"msg":"Respuesta A hacia IP privada (posible filtración)"})
            risk -= 3

    # Normaliza score
    risk = max(0, min(100, risk))

    return {
        "ok": True,
        "ts": datetime.utcnow().isoformat()+"Z",
        "domain": domain,
        "dns": dns_data,
        "email_posture": email,
        "tls": tls_info,
        "subdomains": sub_results,
        "findings": findings,
        "risk_score": risk
    }

