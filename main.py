from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
import bcrypt
import os
import json
import re
from datetime import datetime, timedelta
from typing import Optional
import httpx
from collections import defaultdict
import time

app = FastAPI(title="Portfolio Tracker API")

# ── Eenvoudige in-memory rate limiter ───────────────────────────────
_rate_store = defaultdict(list)

def rate_limit(request: Request, max_calls: int = 60, window: int = 60):
    """Max max_calls verzoeken per window seconden per IP."""
    # Haal echte IP op (ook achter proxy/Render)
    ip = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    if not ip:
        ip = request.client.host if request.client else "unknown"
    now = time.time()
    # Cleanup: verwijder IPs met lege lijsten (geheugen beheer)
    if len(_rate_store) > 10000:
        cutoff = now - window
        dead = [k for k, v in _rate_store.items() if not v or max(v) < cutoff]
        for k in dead:
            del _rate_store[k]
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < window]
    if len(_rate_store[ip]) >= max_calls:
        raise HTTPException(status_code=429, detail="Te veel verzoeken — even wachten")
    _rate_store[ip].append(now)

# ── Ticker validatie ────────────────────────────────────────────────
TICKER_RE = re.compile(r'^[A-Z0-9.\-]{1,20}$')

def validate_ticker(ticker: str) -> str:
    t = ticker.upper().strip()
    if not TICKER_RE.match(t):
        raise HTTPException(status_code=400, detail=f"Ongeldige ticker: {ticker}")
    return t

# ── CORS — sta je GitHub Pages domein toe ───────────────────────────
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],  # alleen wat nodig is
    allow_headers=["Authorization", "Content-Type"],
)

# ── Security headers op alle responses ─────────────────────────────
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# ── Config via omgevingsvariabelen ──────────────────────────────────
JWT_SECRET = os.getenv("JWT_SECRET", "")
if not JWT_SECRET or len(JWT_SECRET) < 32:
    import sys
    print("FATAL: JWT_SECRET is niet ingesteld of te kort (min 32 tekens). Stel in via Render env vars.", file=sys.stderr)
    # Genereer een tijdelijke secret zodat de server niet crasht, maar log een kritieke waarschuwing
    import secrets
    JWT_SECRET = secrets.token_hex(32)
    print("WAARSCHUWING: Tijdelijke JWT secret gegenereerd — tokens worden ongeldig na herstart!", file=sys.stderr)
JWT_EXPIRES_RAW = int(os.getenv("JWT_EXPIRES_HOURS", "24"))
JWT_EXPIRES = min(JWT_EXPIRES_RAW, 168)  # max 7 dagen, default 24u

# Gebruikers — opgeslagen als JSON in omgevingsvariabele
USERS_JSON   = os.getenv("USERS_JSON", "[]")

# Financial Modeling Prep API key
FMP_KEY      = os.getenv("FMP_API_KEY", "")

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
    return {"status": "ok"}


# ── Login ────────────────────────────────────────────────────────────
@app.post("/auth/login")
def login(body: dict, request: Request):
    rate_limit(request, max_calls=10, window=60)  # max 10 loginpogingen/min
    username = str(body.get("username", "")).strip()[:100]
    password = str(body.get("password", ""))[:200]

    # Basis sanitatie
    if not username or not password:
        raise HTTPException(status_code=401, detail="Gebruikersnaam of wachtwoord onjuist")

    users = get_users()
    user = next((u for u in users if u.get("username") == username), None)

    # Gebruik constante-tijd vergelijking via bcrypt (voorkomt timing attacks)
    dummy_hash = "$2b$12$dummy.hash.for.timing.prevention.xxxxx"
    if not user:
        bcrypt.checkpw(password.encode(), dummy_hash.encode() if len(dummy_hash) > 0 else b"$2b$12$x" * 3)
        raise HTTPException(status_code=401, detail="Gebruikersnaam of wachtwoord onjuist")
    if not verify_password(password, user["password_hash"]):
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
async def get_price(ticker: str, user=Depends(optional_token), request: Request = None):
    if request: rate_limit(request)
    ticker = validate_ticker(ticker)
    """
    Haal koers op voor één ticker.
    Probeert FMP eerst, dan yfinance als fallback.
    """
    # Probeer FMP eerst
    result = await _fetch_price_fmp(ticker)
    if not result:
        # Fallback naar yfinance
        result = _fetch_price(ticker)
    if not result:
        raise HTTPException(status_code=404, detail=f"Koers niet gevonden voor {ticker}")
    return result


# ── Meerdere koersen tegelijk ─────────────────────────────────────────
@app.post("/prices")
def get_prices(body: dict, user=Depends(optional_token), request: Request = None):
    if request: rate_limit(request, max_calls=30, window=60)
    """
    Haal koersen op voor meerdere tickers via Yahoo Finance.
    Body: {"tickers": ["AAPL", "IWDA.AS"]}
    """
    raw_tickers = body.get("tickers", [])
    if not raw_tickers or not isinstance(raw_tickers, list):
        return {}
    # Valideer en begrens: max 50 tickers per call, enkel geldige symbolen
    tickers = []
    for t in raw_tickers[:50]:
        if isinstance(t, str) and TICKER_RE.match(t.upper().strip()):
            tickers.append(t.upper().strip())

    results = {}
    stock_tickers = [t for t in tickers
                     if '-EUR' not in t and '-USD' not in t]

    for ticker in stock_tickers:
        data = _fetch_price(ticker)
        if data:
            results[ticker] = data

    return results


@app.get("/history/{ticker}")
async def get_history(
    ticker: str,
    period: str = "1y",
    interval: str = "1d",
    user=Depends(optional_token),
    request: Request = None,
):
    if request: rate_limit(request, max_calls=30, window=60)
    ticker = validate_ticker(ticker)
    # Valideer period parameter
    allowed_periods = {"1d","5d","1mo","3mo","6mo","1y","2y","5y","10y","ytd","max"}
    if period not in allowed_periods: period = "1y"
    """
    Historische dagkoersen voor grafiek of benchmark.
    Probeert FMP eerst, dan yfinance als fallback.
    """
    import httpx

    # Probeer FMP historische data
    if FMP_KEY:
        candidates = [ticker.upper()]
        t = ticker.upper()
        if "." not in t:
            candidates += [t + ".AS", t + ".BR"]

        for sym in candidates:
            try:
                url = f"https://financialmodelingprep.com/api/v3/historical-price-full/{sym}?apikey={FMP_KEY}"
                async with httpx.AsyncClient(timeout=15) as client:
                    r = await client.get(url)
                if not r.is_success:
                    continue
                data = r.json()
                hist = data.get("historical", [])
                if not hist:
                    continue
                # Filter op period
                from datetime import timedelta
                period_days = {
                    "1mo": 30, "3mo": 90, "6mo": 182, "1y": 365,
                    "2y": 730, "5y": 1825, "max": 99999
                }
                days = period_days.get(period, 365)
                cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
                filtered = [h for h in hist if h.get("date", "") >= cutoff]
                if not filtered:
                    filtered = hist  # geef alles als filter leeg is

                result_data = [{
                    "date": h["date"],
                    "close": round(float(h.get("close", 0)), 4),
                    "open":  round(float(h.get("open",  0)), 4),
                    "high":  round(float(h.get("high",  0)), 4),
                    "low":   round(float(h.get("low",   0)), 4),
                } for h in sorted(filtered, key=lambda x: x["date"])]

                return {
                    "ticker": sym,
                    "period": period,
                    "interval": interval,
                    "data": result_data,
                    "source": "FMP",
                }
            except Exception:
                continue

    # Fallback naar yfinance
    result = _fetch_history(ticker, period, interval)
    if not result:
        raise HTTPException(
            status_code=404, detail=f"Historische data niet gevonden voor {ticker}"
        )
    return result


# ── Ticker zoeken ────────────────────────────────────────────────────
@app.get("/search")
async def search_ticker(q: str, user=Depends(optional_token), request: Request = None):
    if request: rate_limit(request, max_calls=20, window=60)
    # Sanitize search query
    q = re.sub(r'[^a-zA-Z0-9 .&-]', '', q).strip()[:50]
    """
    Zoek naar tickers via naam of symbool via FMP.
    """
    import httpx

    if not q or len(q) < 1:
        return []

    if not FMP_KEY:
        raise HTTPException(status_code=503, detail="FMP API key niet ingesteld")

    results = []

    # Probeer beide FMP endpoints
    urls_to_try = [
        f"https://financialmodelingprep.com/stable/search-name?query={q}&limit=20&apikey={FMP_KEY}",
        f"https://financialmodelingprep.com/stable/search-symbol?query={q}&limit=20&apikey={FMP_KEY}",
        f"https://financialmodelingprep.com/api/v3/search?query={q}&limit=20&apikey={FMP_KEY}",
    ]

    async with httpx.AsyncClient(timeout=15) as client:
        for url in urls_to_try:
            try:
                r = await client.get(url)
                if not r.is_success:
                    continue
                data = r.json()
                # Normaliseer response - kan array zijn of object met array
                if isinstance(data, list) and len(data) > 0:
                    results = data
                    break
                elif isinstance(data, dict):
                    for key in ["data", "results", "stocks", "list"]:
                        if key in data and isinstance(data[key], list) and len(data[key]) > 0:
                            results = data[key]
                            break
                    if results:
                        break
            except Exception:
                continue

    if not results:
        return []

    # Filter en formatteer
    allowed = {"NASDAQ","NYSE","AMEX","EURONEXT","ENX","XETRA","LSE","AMS","BRU","PAR","CBOE","EURONEXT"}
    filtered = []
    seen = set()

    for item in results:
        sym = item.get("symbol","") or item.get("ticker","")
        name = item.get("name","") or item.get("companyName","")
        exch = item.get("exchangeShortName","") or item.get("exchange","") or item.get("stockExchange","")

        if not sym or sym in seen:
            continue
        seen.add(sym)

        # Accepteer als beurs bekend is of als symbool kort en zonder cijfers
        if exch.upper() not in allowed:
            if any(c.isdigit() for c in sym) or len(sym) > 7:
                continue

        filtered.append({
            "symbol": sym,
            "name": name,
            "exchange": exch,
            "exchangeShort": exch,
            "currency": item.get("currency",""),
        })

    return filtered[:15]


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
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Wachtwoord te kort (min 8 tekens)")
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    return {"hash": hashed}


# ══════════════════════════════════════════════════════════════════════
# INTERNE HULPFUNCTIES
# ══════════════════════════════════════════════════════════════════════

async def _fetch_price_fmp(ticker: str) -> Optional[dict]:
    """
    Haal koers op via Financial Modeling Prep API.
    Werkt voor Euronext (.AS, .BR), NYSE, NASDAQ, ETFs.
    Geeft altijd de laatste bekende prijs terug.
    """
    if not FMP_KEY:
        return None

    import httpx

    # Probeer ticker direct, dan met Euronext suffixes
    candidates = [ticker.upper()]
    t = ticker.upper()
    if "." not in t and "-" not in t:
        candidates += [t + ".AS", t + ".BR"]

    for sym in candidates:
        try:
            # FMP quote endpoint — geeft altijd laatste bekende prijs
            url = f"https://financialmodelingprep.com/api/v3/quote/{sym}?apikey={FMP_KEY}"
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url)
            if not r.is_success:
                continue
            data = r.json()
            if not data or not isinstance(data, list) or len(data) == 0:
                continue
            q = data[0]
            price = q.get("price") or q.get("previousClose")
            if not price or float(price) == 0:
                continue
            prev  = q.get("previousClose") or price
            chg   = q.get("change") or 0
            chgP  = q.get("changesPercentage") or 0
            return {
                "ticker": sym,
                "price": round(float(price), 4),
                "previousClose": round(float(prev), 4),
                "change": round(float(chg), 4),
                "changePercent": round(float(chgP), 2),
                "currency": q.get("currency", "EUR"),
                "source": "FMP",
                "timestamp": datetime.utcnow().isoformat(),
                "marketOpen": q.get("isActivelyTrading", False),
            }
        except Exception:
            continue
    return None


def _fetch_price(ticker: str) -> Optional[dict]:
    """
    Haal koers op via Yahoo Finance direct HTTP.
    Geen yfinance library nodig - directe API call.
    Werkt voor alle beurzen, ook buiten beurstijden.
    """
    import httpx

    t = ticker.upper().strip()

    # Bouw kandidatenlijst
    candidates = [t]
    if '.' not in t and '-' not in t and '=' not in t and len(t) <= 6:
        candidates += [t + '.AS', t + '.BR', t + '.DE', t + '.PA', t + '.L']

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json',
    }

    for sym in candidates:
        try:
            # Yahoo Finance v8 quote endpoint - gratis en betrouwbaar
            url = f'https://query1.finance.yahoo.com/v8/finance/chart/{sym}?interval=1d&range=5d'
            resp = httpx.get(url, headers=headers, timeout=15, follow_redirects=True)

            if resp.status_code != 200:
                continue

            data = resp.json()
            chart = data.get('chart', {})
            error = chart.get('error')
            if error:
                continue

            result_list = chart.get('result', [])
            if not result_list:
                continue

            r = result_list[0]
            meta = r.get('meta', {})
            closes = r.get('indicators', {}).get('quote', [{}])[0].get('close', [])

            # Gebruik regularMarketPrice als live prijs
            price = meta.get('regularMarketPrice') or meta.get('chartPreviousClose')
            prev  = meta.get('chartPreviousClose') or meta.get('previousClose') or price

            # Fallback: laatste waarde uit history
            if not price and closes:
                valid = [c for c in closes if c is not None]
                if valid:
                    price = valid[-1]
                    prev  = valid[-2] if len(valid) > 1 else price

            if not price or float(price) == 0:
                continue

            price = round(float(price), 4)
            prev  = round(float(prev or price), 4)
            chg   = round(price - prev, 4)
            chgP  = round((chg / prev * 100) if prev else 0, 2)
            curr  = meta.get('currency', 'EUR')
            open_market = meta.get('marketState', '') in ('REGULAR', 'PRE', 'POST')

            return {
                'ticker':        sym,
                'price':         price,
                'previousClose': prev,
                'change':        chg,
                'changePercent': chgP,
                'currency':      curr,
                'source':        'Yahoo Finance',
                'timestamp':     datetime.utcnow().isoformat(),
                'marketOpen':    open_market,
            }

        except Exception as e:
            print(f"Yahoo fout voor {sym}: {e}")
            continue

    return None


def _fetch_history(ticker: str, period: str, interval: str) -> Optional[dict]:
    """
    Historische dagkoersen via Yahoo Finance direct HTTP.
    """
    import httpx

    t = ticker.upper().strip()
    candidates = [t]
    if '.' not in t and '-' not in t:
        candidates += [t + '.AS', t + '.BR']

    # Zet period om naar Yahoo Finance range
    range_map = {
        '1d':'1d','5d':'5d','1mo':'1mo','3mo':'3mo',
        '6mo':'6mo','1y':'1y','2y':'2y','5y':'5y',
        '10y':'10y','ytd':'ytd','max':'max'
    }
    yf_range = range_map.get(period, '1y')

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json',
    }

    for sym in candidates:
        try:
            url = f'https://query1.finance.yahoo.com/v8/finance/chart/{sym}?interval={interval}&range={yf_range}'
            resp = httpx.get(url, headers=headers, timeout=15, follow_redirects=True)
            if resp.status_code != 200:
                continue

            data = resp.json()
            chart = data.get('chart', {})
            result_list = chart.get('result', [])
            if not result_list:
                continue

            r = result_list[0]
            timestamps = r.get('timestamp', [])
            closes = r.get('indicators', {}).get('quote', [{}])[0].get('close', [])

            if not timestamps or not closes:
                continue

            rows = []
            for ts, c in zip(timestamps, closes):
                if c is None:
                    continue
                rows.append({
                    'date': datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d'),
                    'close': round(float(c), 4),
                    'open': round(float(c), 4),
                    'high': round(float(c), 4),
                    'low': round(float(c), 4),
                })

            if not rows:
                continue

            return {
                'ticker': sym,
                'period': period,
                'interval': interval,
                'data': rows,
                'source': 'Yahoo Finance',
            }
        except Exception as e:
            print(f"History fout voor {sym}: {e}")
            continue

    return None


