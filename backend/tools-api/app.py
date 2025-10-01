from fastapi import FastAPI, HTTPException, Depends, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import jwt
from passlib.context import CryptContext

import os, json, socket, platform, subprocess, psutil, ssl
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# DNS / HTTP stdlib
from dns import resolver, exception as dns_exc  # pip install dnspython
from urllib.parse import urlparse
from urllib.request import Request as UrlRequest, urlopen

# Respuesta para OPTIONS
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

# Agente / Reports
DATA_DIR     = (PWD / "data"); DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_FILE = DATA_DIR / "reports.jsonl"
LATEST_FILE  = DATA_DIR / "latest.json"
ORG_API_KEY  = os.getenv("ROMANOTI_ORG_API_KEY", "MySecret123$")

# SOC data
SOC_ALERTS_FILE = DATA_DIR / "soc_alerts.jsonl"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="RomanoTI Tools API", version="1.2.0")

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
# Modelos
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

# NOC checks
class HttpCheck(BaseModel):
    url: str
    timeout_s: int = 6
    verify_tls: bool = True

class TcpCheck(BaseModel):
    host: str
    port: int
    timeout_ms: int = 800

class DnsCheck(BaseModel):
    domain: str
    rtype: str = "A"  # A, AAAA, MX, TXT, CNAME, NS

class IcmpCheck(BaseModel):
    host: str
    count: int = 2

# SOC ingest
class SocLog(BaseModel):
    source: str = "unknown"
    event_type: str = "generic"
    severity: str = "info"  # info|low|medium|high|critical
    message: str = ""
    meta: Optional[Dict[str, Any]] = None

# =========================
# Usuarios / Auth
# =========================
def load_users() -> Dict[str, Dict[str, Any]]:
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

@app.post("/auth/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    token = create_access_token({"sub": user.username, "roles": user.roles})
    return {"access_token": token, "token_type": "bearer"}

# =========================
# Salud
# =========================
@app.get("/health")
def health():
    return {"status": "ok", "service": "romanoti-tools", "ts": datetime.utcnow().isoformat()+"Z"}

# =========================
# Info de sistema / red
# =========================
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
# Utilidades de red (backend)
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
        s = max(1, int(req.start))
        e = min(65535, int(req.end))
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
# EXT checks (ya tenías emaildns/tls)
# =========================
class TlsReq(BaseModel):
    host: str
    port: int = 443

class EmailDNSReq(BaseModel):
    domain: str

def _tls_cert_expiry(host: str, port: int = 443, timeout: int = 5):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            exp_str = cert["notAfter"]
            exp = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
            days = (exp - datetime.utcnow()).days
            issuer = ""
            try:
                issuer = dict(x[0] for x in cert.get("issuer", [])) \
                           .get("organizationName", "")
            except Exception:
                pass
            subject = ""
            try:
                subject = dict(x[0] for x in cert.get("subject", [])) \
                           .get("commonName", "")
            except Exception:
                pass
            return {
                "host": host,
                "port": port,
                "subject": subject,
                "issuer": issuer,
                "not_after": exp.isoformat() + "Z",
                "days_remaining": days,
            }

@app.post("/ext/tls")
def ext_tls(req: TlsReq):
    try:
        return _tls_cert_expiry(req.host, req.port)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/ext/emaildns")
def email_dns(req: EmailDNSReq):
    dom = req.domain.strip()
    if not dom:
        raise HTTPException(status_code=400, detail="domain required")

    out = {"domain": dom}
    try:
        answers = resolver.resolve(dom, "MX")
        out["mx"] = [f"{r.preference} {r.exchange.to_text()}" for r in answers]
    except (dns_exc.DNSException, Exception) as e:
        out["mx_error"] = str(e)

    try:
        txt = [t.to_text().strip('"') for t in resolver.resolve(dom, "TXT")]
        out["spf"] = [t for t in txt if t.lower().startswith("v=spf1")]
    except (dns_exc.DNSException, Exception) as e:
        out["spf_error"] = str(e)

    try:
        dmarc_txt = [
            t.to_text().strip('"')
            for t in resolver.resolve(f"_dmarc.{dom}", "TXT")
        ]
        out["dmarc"] = [t for t in dmarc_txt if t.lower().startswith("v=dmarc1")]
    except (dns_exc.DNSException, Exception) as e:
        out["dmarc_error"] = str(e)

    return out

# =========================
# Helpers
# =========================
def _require_org_key(x_api_key: Optional[str]):
    if not x_api_key or x_api_key != ORG_API_KEY:
        raise HTTPException(status_code=401, detail="invalid x-api-key")

# =========================
# NOC Quick Checks (x-api-key)
# =========================
@app.post("/noc/http_check")
def noc_http_check(req: HttpCheck, x_api_key: Optional[str] = Header(None)):
    _require_org_key(x_api_key)
    parsed = urlparse(req.url)
    if not parsed.scheme or not parsed.netloc:
        raise HTTPException(status_code=400, detail="invalid url")
    headers = {"User-Agent": "RomanoTI-NOC/1.0"}
    # urllib no valida TLS hostname si verify_tls=False? => si verify=false, permitimos sin cert
    ctx = ssl.create_default_context()
    if not req.verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    start = datetime.utcnow()
    try:
        r = urlopen(Request(req.url, headers=headers), timeout=req.timeout_s, context=ctx)  # nosec - controlado
        code = r.getcode()
        body = r.read(256)  # primeros bytes
        ms = int((datetime.utcnow() - start).total_seconds()*1000)
        return {"url": req.url, "status": code, "latency_ms": ms, "snippet": body[:120].decode(errors="ignore")}
    except Exception as e:
        ms = int((datetime.utcnow() - start).total_seconds()*1000)
        raise HTTPException(status_code=502, detail=f"http_check error after {ms}ms: {e}")

@app.post("/noc/tcp_check")
def noc_tcp_check(req: TcpCheck, x_api_key: Optional[str] = Header(None)):
    _require_org_key(x_api_key)
    to = max(0.05, req.timeout_ms/1000.0)
    t0 = datetime.utcnow()
    try:
        with socket.create_connection((req.host, req.port), timeout=to):
            ms = int((datetime.utcnow()-t0).total_seconds()*1000)
            return {"host": req.host, "port": req.port, "reachable": True, "latency_ms": ms}
    except Exception as e:
        ms = int((datetime.utcnow()-t0).total_seconds()*1000)
        return {"host": req.host, "port": req.port, "reachable": False, "error": str(e), "latency_ms": ms}

@app.post("/noc/dns_check")
def noc_dns_check(req: DnsCheck, x_api_key: Optional[str] = Header(None)):
    _require_org_key(x_api_key)
    rtype = req.rtype.upper()
    try:
        answers = resolver.resolve(req.domain, rtype)
        values = [a.to_text() for a in answers]
        return {"domain": req.domain, "type": rtype, "answers": values}
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))

@app.post("/noc/icmp_check")
def noc_icmp_check(req: IcmpCheck, x_api_key: Optional[str] = Header(None)):
    _require_org_key(x_api_key)
    # Reutilizamos ping del sistema para 1-2 paquetes
    count = max(1, min(4, req.count))
    if platform.system().lower().startswith("win"):
        cmd = ["ping", "-n", str(count), req.host]
    else:
        cmd = ["ping", "-c", str(count), req.host]
    out = _run(cmd, timeout=20)
    return {"host": req.host, "count": count, "output": out}

# =========================
# SOC – ingest + alerts (x-api-key)
# =========================
@app.post("/soc/log/ingest")
async def soc_ingest(log: SocLog, x_api_key: Optional[str] = Header(None)):
    _require_org_key(x_api_key)
    rec = {
        "ts": datetime.utcnow().isoformat()+"Z",
        "source": log.source,
        "event_type": log.event_type,
        "severity": log.severity,
        "message": log.message,
        "meta": log.meta or {}
    }
    sev = (log.severity or "info").lower()
    is_alert = sev in ("high", "critical")

    # Persist alert if needed
    if is_alert:
        with SOC_ALERTS_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    return {"accepted": True, "alerted": is_alert}

@app.get("/soc/alerts")
def soc_alerts(limit: int = 50, x_api_key: Optional[str] = Header(None)):
    _require_org_key(x_api_key)
    if not SOC_ALERTS_FILE.exists():
        return {"alerts": []}
    alerts: List[Dict[str, Any]] = []
    with SOC_ALERTS_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                alerts.append(json.loads(line))
            except Exception:
                continue
    alerts = list(reversed(alerts))[:max(1, min(200, limit))]
    return {"alerts": alerts}
