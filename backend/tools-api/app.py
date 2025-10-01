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
# NOC Endpoints (NUEVOS)
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
