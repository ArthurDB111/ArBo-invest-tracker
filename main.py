from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import yfinance as yf
import jwt
import bcrypt
import os
import json
from datetime import datetime, timedelta
from typing import Optional
import httpx

app = FastAPI(title="Portfolio Tracker API")

# ── CORS — sta je GitHub Pages domein toe ───────────────────────────
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Config via omgevingsvariabelen ──────────────────────────────────
JWT_SECRET   = os.getenv("JWT_SECRET", "verander-dit-naar-een-geheime-sleutel")
JWT_EXPIRES  = int(os.getenv("JWT_EXPIRES_HOURS", "720"))  # 30 dagen

# Gebruikers — opgeslagen als JSON in omgevingsvariabele
# Formaat: [{"username":"arthur","password_hash":"...","role":"admin"}]
USERS_JSON   = os.getenv("USERS_JSON", "[]")

security = HTTPBearer(auto_error=False)


# ── Gebruikersbeheer ────────────────────────────────────────────────
def get_users() -> list:
    try:
        return json.loads(USERS_JSON)
    except Exception:
        return []


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_token(username: str, role: str = "user") -> str:
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Niet ingelogd")
    try:
        payload = jwt.decode(
            credentials.credentials, JWT_SECRET, algorithms=["HS256"]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Sessie verlopen")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Ongeldig token")


# ══════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ══════════════════════════════════════════════════════════════════════

@app.get("/")
def root():
    return {"status": "Portfolio Tracker API actief"}


# ── Login ────────────────────────────────────────────────────────────
@app.post("/auth/login")
def login(body: dict):
    username = body.get("username", "").strip()
    password = body.get("password", "")

    users = get_users()
    user = next((u for u in users if u["username"] == username), None)

    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Gebruikersnaam of wachtwoord onjuist")

    token = create_token(username, user.get("role", "user"))
    return {
        "token": token,
        "username": username,
        "role": user.get("role", "user"),
        "expires_hours": JWT_EXPIRES,
    }


# ── Controleer login status ──────────────────────────────────────────
@app.get("/auth/me")
def me(user=Depends(verify_token)):
    return {"username": user["sub"], "role": user["role"]}


# ── Live koers (enkelvoudig) ─────────────────────────────────────────
@app.get("/price/{ticker}")
def get_price(ticker: str, user=Depends(verify_token)):
    """
    Haal live koers op voor één ticker.
    Probeert automatisch Euronext suffixes (.AS, .BR) als nodig.
    """
    result = _fetch_price(ticker)
    if not result:
        raise HTTPException(status_code=404, detail=f"Koers niet gevonden voor {ticker}")
    return result


# ── Meerdere koersen tegelijk ────────────────────────────────────────
@app.post("/prices")
def get_prices(body: dict, user=Depends(verify_token)):
    """
    Haal koersen op voor meerdere tickers tegelijk.
    Body: {"tickers": ["AAPL", "IWDA.AS", "BTC-EUR"]}
    """
    tickers = body.get("tickers", [])
    if not tickers:
        return {}

    results = {}
    for ticker in tickers[:30]:  # max 30 per call
        data = _fetch_price(ticker)
        if data:
            results[ticker] = data

    return results


# ── Historische koersen (voor grafiek + benchmark) ───────────────────
@app.get("/history/{ticker}")
def get_history(
    ticker: str,
    period: str = "1y",
    interval: str = "1d",
    user=Depends(verify_token),
):
    """
    Historische dagkoersen voor grafiek of benchmark.
    period: 1d,5d,1mo,3mo,6mo,1y,2y,5y,10y,ytd,max
    interval: 1d,1wk,1mo
    """
    result = _fetch_history(ticker, period, interval)
    if not result:
        raise HTTPException(
            status_code=404, detail=f"Historische data niet gevonden voor {ticker}"
        )
    return result


# ── Admin: gebruiker aanmaken ────────────────────────────────────────
@app.post("/admin/hash-password")
def hash_password(body: dict, user=Depends(verify_token)):
    """
    Hulpendpoint om een wachtwoord te hashen voor in USERS_JSON.
    Alleen toegankelijk voor admins.
    """
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Geen toegang")
    password = body.get("password", "")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Wachtwoord te kort (min 6 tekens)")
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    return {"hash": hashed}


# ══════════════════════════════════════════════════════════════════════
# INTERNE HULPFUNCTIES
# ══════════════════════════════════════════════════════════════════════

def _fetch_price(ticker: str) -> Optional[dict]:
    """
    Probeer koers op te halen via yfinance.
    Probeert automatisch .AS en .BR suffixes voor Euronext.
    """
    candidates = [ticker]

    t = ticker.upper()
    # Voeg Euronext suffixes toe als er nog geen suffix is
    if "." not in t and "-" not in t:
        candidates += [t + ".AS", t + ".BR", t + ".L", t + ".PA"]

    for sym in candidates:
        try:
            tk = yf.Ticker(sym)
            info = tk.fast_info

            price = getattr(info, "last_price", None)
            prev  = getattr(info, "previous_close", None)

            if not price or price == 0:
                hist = tk.history(period="2d", interval="1m", auto_adjust=True)
                if hist.empty:
                    continue
                price = float(hist["Close"].iloc[-1])
                prev  = float(hist["Close"].iloc[0]) if len(hist) > 1 else price

            if not price or price == 0:
                continue

            price = round(float(price), 4)
            prev  = round(float(prev), 4) if prev else price
            chg   = round(price - prev, 4)
            chgP  = round((chg / prev * 100) if prev else 0, 2)

            return {
                "ticker": sym,
                "price": price,
                "previousClose": prev,
                "change": chg,
                "changePercent": chgP,
                "currency": getattr(info, "currency", "EUR"),
                "source": "yfinance",
                "timestamp": datetime.utcnow().isoformat(),
            }
        except Exception:
            continue

    return None


def _fetch_history(ticker: str, period: str, interval: str) -> Optional[dict]:
    """
    Historische OHLC data via yfinance.
    Probeert automatisch Euronext suffixes.
    """
    candidates = [ticker]
    t = ticker.upper()
    if "." not in t and "-" not in t:
        candidates += [t + ".AS", t + ".BR", t + ".L"]

    for sym in candidates:
        try:
            tk = yf.Ticker(sym)
            hist = tk.history(period=period, interval=interval, auto_adjust=True)

            if hist.empty:
                continue

            # Converteer naar JSON-vriendelijk formaat
            data = []
            for date, row in hist.iterrows():
                data.append({
                    "date": date.strftime("%Y-%m-%d"),
                    "close": round(float(row["Close"]), 4),
                    "open":  round(float(row["Open"]), 4),
                    "high":  round(float(row["High"]), 4),
                    "low":   round(float(row["Low"]), 4),
                })

            return {
                "ticker": sym,
                "period": period,
                "interval": interval,
                "data": data,
                "source": "yfinance",
            }
        except Exception:
            continue

    return None
