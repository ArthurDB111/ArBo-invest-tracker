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
async def get_price(ticker: str, user=Depends(verify_token)):
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
def get_prices(body: dict, user=Depends(verify_token)):
    """
    Haal koersen op voor meerdere tickers via Yahoo Finance.
    Body: {"tickers": ["AAPL", "IWDA.AS"]}
    """
    tickers = body.get("tickers", [])
    if not tickers:
        return {}

    results = {}

    # Crypto wordt via CoinGecko gedaan in de browser, hier alleen aandelen/ETFs
    stock_tickers = [t for t in tickers
                     if '-EUR' not in t.upper() and '-USD' not in t.upper()]

    for ticker in stock_tickers:
        data = _fetch_price(ticker)
        if data:
            results[ticker] = data
        else:
            print(f"Geen prijs gevonden voor: {ticker}")

    return results


@app.get("/history/{ticker}")
async def get_history(
    ticker: str,
    period: str = "1y",
    interval: str = "1d",
    user=Depends(verify_token),
):
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
async def search_ticker(q: str, user=Depends(verify_token)):
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
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Wachtwoord te kort (min 6 tekens)")
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
