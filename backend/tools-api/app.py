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

# ===== Config =====
JWT_SECRET = os.getenv("ROMANOTI_JWT_SECRET", "change-me")  # cambia en prod
JWT_ALG    = "HS256"
JWT_HOURS  = int(os.getenv("ROMANOTI_JWT_HOURS", "8"))
ALLOWED_ORIGINS = json.loads(os.getenv("ROMANOTI_ALLOWED_ORIGINS", '["*"]'))

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

@app.get("/health")
def health():
    return {"status": "ok", "service": "romanoti-tools", "ts": datetime.utcnow().isoformat()}

@app.post("/auth/login")
def auth_login(req: LoginRequest):
    user = USERS.get(req.username)
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Bad username or password")
    token = create_token(user["username"], user["role"])
    return {"access_token": token, "token_type": "bearer", "expires_in": JWT_HOURS * 3600}

@app.get("/auth/me")
def auth_me(user=Depends(require_engineer)):
    return user

# Ejemplo protegido
@app.get("/system/info")
def system_info(user=Depends(require_engineer)):
    return {
        "os": f"{platform.system()} {platform.release()}",
        "cpu_cores": psutil.cpu_count(),
        "ram_gb": psutil.virtual_memory().total // (1024**3),
        "ts": datetime.utcnow().isoformat()
    }
