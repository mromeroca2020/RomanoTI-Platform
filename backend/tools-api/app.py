from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta
from typing import Dict
from jose import jwt, JWTError
from pydantic import BaseModel
from passlib.context import CryptContext
from passlib.exc import UnknownHashError, InvalidHash
import json, os, platform, psutil
=======
from typing import List
import time, concurrent.futures, socket
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import jwt, JWTError
from passlib.context import CryptContext
import os, json, platform, psutil, socket, subprocess, requests
from datetime import datetime, timedelta
>>>>>>> 9907876 (api: PBKDF2 users + deps + endpoints listos para deploy)

# ===== Config =====
JWT_SECRET = os.getenv("ROMANOTI_JWT_SECRET", "change-me")  # cambia en prod
JWT_ALG    = "HS256"
JWT_HOURS  = int(os.getenv("ROMANOTI_JWT_HOURS", "8"))
ALLOWED_ORIGINS = json.loads(os.getenv("ROMANOTI_ALLOWED_ORIGINS", '["*"]'))
<<<<<<< HEAD

# ===== Usuarios =====
PWD = os.path.dirname(__file__)
USERS_FILE = os.path.join(PWD, "users.json")
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")  # <- PBKDF2, no bcrypt

def load_users() -> Dict[str, Dict]:
    if not os.path.exists(USERS_FILE):
        raise RuntimeError("No existe users.json (crea uno con usuarios).")
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {u["username"]: u for u in data}

USERS = load_users()

# ===== App =====
app = FastAPI(title="RomanoTI Tools API", version="0.2")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

class LoginRequest(BaseModel):
    username: str
    password: str

def verify_password(plain: str, hashed: str) -> bool:
    if not hashed:
        return False
    try:
        if hashed.startswith("$"):  # hash estándar (pbkdf2_sha256)
            return pwd_context.verify(plain, hashed)
        if hashed.startswith("plaintext:"):  # modo DEV opcional
            return plain == hashed.split(":", 1)[1]
        return False
    except (UnknownHashError, InvalidHash):
        return False
    except Exception:
        return False

def create_token(username: str, role: str) -> str:
    payload = {
        "sub": username,
        "role": role,
        "iat": int(datetime.utcnow().timestamp()),
        "exp": int((datetime.utcnow() + timedelta(hours=JWT_HOURS)).timestamp())
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        username = payload.get("sub"); role = payload.get("role")
        if not username or not role:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = USERS.get(username)
        if not user or user.get("role") != role:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return {"username": username, "role": role}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid/expired token")

def require_engineer(user=Depends(get_current_user)):
    if user["role"] != "engineer":
        raise HTTPException(status_code=403, detail="Insufficient role")
    return user
=======
>>>>>>> 9907876 (api: PBKDF2 users + deps + endpoints listos para deploy)

# ===== Usuarios =====
PWD = os.path.dirname(__file__)
USERS_FILE = os.path.join(PWD, "users.json")
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")  # PBKDF2 (sin bcrypt)

def load_users():
    if not os.path.exists(USERS_FILE):
        raise RuntimeError("No existe users.json (crea uno).")
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {u["username"]: u for u in data}

USERS = load_users()

# ===== App =====
app = FastAPI(title="RomanoTI Tools API", version="0.4")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

# ===== Modelos =====
class LoginRequest(BaseModel):
    username: str
    password: str

class PingRequest(BaseModel):
    host: str = "8.8.8.8"
    count: int = 4

class TraceRequest(BaseModel):
    host: str = "8.8.8.8"

class PortScanRequest(BaseModel):
    host: str                               # IP o hostname destino
    ports: List[int] | None = None          # opcional: lista de puertos; si falta, usamos start-end
    start: int | None = 1                   # usados si 'ports' es None
    end: int | None = 1024                  # límite de seguridad
    timeout_ms: int = 800                   # tiempo por puerto (ms)
    max_workers: int = 200                  # concurrencia


# ===== Auth utils =====
def verify_password(plain: str, hashed: str) -> bool:
    if not hashed:
        return False
    try:
        if hashed.startswith("$"):              # hash PBKDF2
            return pwd_context.verify(plain, hashed)
        if hashed.startswith("plaintext:"):     # modo DEV
            return plain == hashed.split(":", 1)[1]
        return False
    except Exception:
        return False

def create_token(username: str, role: str) -> str:
    payload = {
        "sub": username,
        "role": role,
        "iat": int(datetime.utcnow().timestamp()),
        "exp": int((datetime.utcnow() + timedelta(hours=JWT_HOURS)).timestamp()),
        "iss": "romanoti-tools"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        username, role = payload.get("sub"), payload.get("role")
        if not username or not role:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = USERS.get(username)
        if not user or user.get("role") != role:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return {"username": username, "role": role}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid/expired token")

def require_engineer(user=Depends(get_current_user)):
    if user["role"] != "engineer":
        raise HTTPException(status_code=403, detail="Insufficient role")
    return user

# ===== Helper para comandos =====
def run_cmd(command: list, timeout: int = 30) -> dict:
    try:
        p = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return {"ok": p.returncode == 0, "stdout": p.stdout, "stderr": p.stderr}
    except FileNotFoundError as e:
        return {"ok": False, "stdout": "", "stderr": f"Comando no encontrado: {e}"}
    except Exception as e:
        return {"ok": False, "stdout": "", "stderr": str(e)}

# ===== Endpoints =====
@app.get("/health")
def health():
    return {"status": "ok", "service": "romanoti-tools", "ts": datetime.utcnow().isoformat()}

<<<<<<< HEAD
@app.post("/auth/login")
def auth_login(req: LoginRequest):
    user = USERS.get(req.username)
    if not user or not verify_password(req.password, user["password_hash"]):
=======
# JSON login (útil para scripts)
@app.post("/auth/login")
def auth_login(req: LoginRequest):
    user = USERS.get(req.username)
    if not user or not verify_password(req.password, user.get("password_hash", "")):
>>>>>>> 9907876 (api: PBKDF2 users + deps + endpoints listos para deploy)
        raise HTTPException(status_code=401, detail="Bad username or password")
    token = create_token(user["username"], user["role"])
    return {"access_token": token, "token_type": "bearer", "expires_in": JWT_HOURS * 3600}

<<<<<<< HEAD
=======
# OAuth2 Password (para botón Authorize de Swagger)
@app.post("/auth/token")
def auth_token(form: OAuth2PasswordRequestForm = Depends()):
    user = USERS.get(form.username)
    if not user or not verify_password(form.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Bad username or password")
    token = create_token(user["username"], user["role"])
    return {"access_token": token, "token_type": "bearer", "expires_in": JWT_HOURS * 3600}

# --- Protegidos ---
>>>>>>> 9907876 (api: PBKDF2 users + deps + endpoints listos para deploy)
@app.get("/auth/me")
def auth_me(user=Depends(require_engineer)):
    return user

<<<<<<< HEAD
# Ejemplo protegido
=======
>>>>>>> 9907876 (api: PBKDF2 users + deps + endpoints listos para deploy)
@app.get("/system/info")
def system_info(user=Depends(require_engineer)):
    return {
        "os": f"{platform.system()} {platform.release()}",
<<<<<<< HEAD
        "cpu_cores": psutil.cpu_count(),
        "ram_gb": psutil.virtual_memory().total // (1024**3),
        "ts": datetime.utcnow().isoformat()
    }
=======
        "version": platform.version(),
        "arch": platform.architecture()[0],
        "cpu_cores": psutil.cpu_count(),
        "ram_gb": psutil.virtual_memory().total // (1024**3),
        "ts": datetime.utcnow().isoformat(),
    }

# --- RED ---
@app.get("/network/info")
def network_info(user=Depends(require_engineer)):
    data = {"timestamp": datetime.utcnow().isoformat()}
    # público
    try:
        data["public_ip"] = requests.get("https://api.ipify.org", timeout=5).text
        data["internet"] = "CONNECTED"
    except Exception:
        data["public_ip"] = None
        data["internet"] = "OFFLINE"
    # hostname / IP local
    try:
        hostname = socket.gethostname()
        data["hostname"] = hostname
        data["local_ip"] = socket.gethostbyname(hostname)
    except Exception:
        data["hostname"] = None
        data["local_ip"] = None
    # interfaces
    try:
        ifaces = {}
        for name, addrs in psutil.net_if_addrs().items():
            ips = [a.address for a in addrs if getattr(a, "family", None) == socket.AF_INET]
            if ips:
                ifaces[name] = ips
        data["interfaces"] = ifaces
    except Exception:
        data["interfaces"] = {}
    return data

@app.post("/network/ping")
def network_ping(req: PingRequest, user=Depends(require_engineer)):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    count = str(max(1, min(req.count, 10)))  # límite 10
    return run_cmd(["ping", param, count, req.host], timeout=25)

@app.post("/network/traceroute")
def network_traceroute(req: TraceRequest, user=Depends(require_engineer)):
    tool = "tracert" if platform.system().lower() == "windows" else "traceroute"
    return run_cmd([tool, req.host], timeout=90)
def _port_is_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

@app.post("/network/portscan")
def network_portscan(req: PortScanRequest, user=Depends(require_engineer)):
    start = max(1, req.start or 1)
    end = min(max(start, req.end or 1024), 65535)
    timeout = max(0.1, (req.timeout_ms or 800) / 1000.0)
    workers = max(10, min(req.max_workers or 200, 1000))

    if req.ports and len(req.ports) > 5000:
        raise HTTPException(status_code=400, detail="Too many ports (max 5000).")

    ports_to_scan = req.ports if req.ports else list(range(start, end + 1))

    t0 = time.time()
    open_ports: List[int] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_port_is_open, req.host, p, timeout): p for p in ports_to_scan}
        for fut in concurrent.futures.as_completed(futures):
            p = futures[fut]
            try:
                if fut.result():
                    open_ports.append(p)
            except Exception:
                pass

    open_ports.sort()
    return {
        "target": req.host,
        "scanned": len(ports_to_scan),
        "open_ports": open_ports,
        "elapsed_s": round(time.time() - t0, 3),
        "ts": datetime.utcnow().isoformat(),
    }

